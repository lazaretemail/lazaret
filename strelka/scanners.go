// SPDX-License-Identifier: AGPL-3.0-only

package strelka

import (
	"context"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// beta.ocr, beta.scan_qr and beta.parse_exif, answered from the same scan that answers
// file.explode.
//
// These are not machine learning, despite living in the same corner of the function
// surface as ml.*: Strelka already runs tesseract, zbar and exiftool over every file it
// is given, so the results are sitting in the scan this package was fetching anyway. No
// new service, no model, no container.
//
// Each reads the *decoded* records rather than the wire, because the three wire-format
// divergences involved are absorbed in mdm/enrichment.go, where they are documented and
// unit-tested against captured output.

// enrichOCR answers beta.ocr.
//
// The published OCROutput.Text is a single string while Strelka emits an array of words,
// so this uses the reconstructed `raw`. Page results come from the child records: Strelka
// renders each page of a PDF to its own image and scans it separately, which is the same
// decomposition `page_results` describes.
func (c *Client) enrichOCR(ctx context.Context, args []mql.Value) (mql.Value, error) {
	records, err := c.scanArg(ctx, enrich.CapBetaOCR, args)
	if err != nil || records == nil {
		return mql.NullValue, err
	}

	out := &mdm.OCROutput{Success: mdm.Ptr(false)}
	for _, r := range records {
		if r.Scan == nil || r.Scan.Ocr == nil {
			continue
		}
		out.Success = mdm.Ptr(true)
		text := r.Scan.Ocr.Raw
		if text == nil {
			continue
		}
		if mdm.Deref(r.Depth) == 0 {
			out.Text = text
			continue
		}
		out.PageResults = append(out.PageResults, &mdm.OCRPage{Text: text})
	}

	// A single image has no depth-0 OCR distinct from its pages; fall back to the first
	// page so `.text` is not empty when `.page_results` is not.
	if out.Text == nil && len(out.PageResults) > 0 {
		out.Text = out.PageResults[0].Text
	}
	return mql.FromGo(out), nil
}

// enrichScanQR answers beta.scan_qr.
//
// Every record is searched, not just the top one: a QR code reaches a mailbox inside a
// PDF or an embedded image far more often than as a bare PNG attachment, and the whole
// point of the technique is to put the link somewhere a text scanner will not look.
func (c *Client) enrichScanQR(ctx context.Context, args []mql.Value) (mql.Value, error) {
	records, err := c.scanArg(ctx, enrich.CapBetaScanQR, args)
	if err != nil || records == nil {
		return mql.NullValue, err
	}

	out := &mdm.QRScanOutput{Found: mdm.Ptr(false)}
	seen := map[string]bool{}
	for _, r := range records {
		if r.Scan == nil || r.Scan.Qr == nil || r.Scan.Qr.Data == nil {
			continue
		}
		data := *r.Scan.Qr.Data
		if seen[data] {
			continue // the same code rendered on several pages is one code
		}
		seen[data] = true

		item := &mdm.QRItem{Data: mdm.Ptr(data), URL: r.Scan.Qr.URL}
		if r.Scan.Qr.Type != nil {
			item.Type = mdm.Ptr(string(*r.Scan.Qr.Type))
		}
		out.Items = append(out.Items, item)
		out.Found = mdm.Ptr(true)
	}
	return mql.FromGo(out), nil
}

// enrichParseExif answers beta.parse_exif, from the top-level file only — the corpus
// calls it on an attachment and means that attachment's own metadata, not that of
// whatever is embedded in it.
func (c *Client) enrichParseExif(ctx context.Context, args []mql.Value) (mql.Value, error) {
	records, err := c.scanArg(ctx, enrich.CapBetaParseExif, args)
	if err != nil || records == nil {
		return mql.NullValue, err
	}

	out := &mdm.ExifOutput{}
	for _, r := range records {
		if mdm.Deref(r.Depth) != 0 || r.Scan == nil || r.Scan.Exiftool == nil {
			continue
		}
		e := r.Scan.Exiftool
		out.Creator, out.Producer, out.Title = e.Creator, e.Producer, e.Title
		out.PageCount, out.ImageHeight, out.ImageWidth = e.PageCount, e.ImageHeight, e.ImageWidth
		for _, kv := range e.Fields {
			if kv.Key == nil {
				continue
			}
			out.Fields = append(out.Fields, &mdm.ExifField{Key: kv.Key, Value: kv.Value})
			// ExifOutput names an Author that StrelkaExifTool does not; images carry it
			// as Artist and documents as Author.
			if out.Author == nil && (*kv.Key == "Author" || *kv.Key == "Artist") {
				out.Author = kv.Value
			}
		}
	}
	if len(out.Fields) == 0 {
		return mql.NullValue, nil
	}
	return mql.FromGo(out), nil
}

// scanArg is the shared front half: pull the file out of the MQL argument, scan it, and
// turn a transport failure into an Unavailable naming the capability the rule asked for
// rather than the one this client happens to be built around.
func (c *Client) scanArg(ctx context.Context, cap enrich.Capability, args []mql.Value) ([]*mdm.FileExplodeOutput, error) {
	filename, data, ok := fileFrom(args)
	if !ok {
		return nil, nil
	}
	records, err := c.Explode(ctx, filename, data)
	if err != nil {
		return nil, &enrich.Unavailable{Capability: cap, Reason: "scan failed", Err: err}
	}
	return records, nil
}
