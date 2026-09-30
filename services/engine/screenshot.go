// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"net/http"
	"strconv"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Showing an analyst what the message looked like.
//
// The obvious implementation — put the message's HTML in the page — is the one thing
// this must not do. A mail body is attacker-authored markup: its remote images are
// tracking pixels that tell the sender their phishing landed and who opened it, its
// CSS can lift content out of the panel it was given, and its scripts run with the
// dashboard's origin and session. Sanitising it is a arms race nobody wins in a
// template.
//
// So the message is rendered where it can do no harm — headless Chromium in a
// container on a network marked internal, which has already been sitting there for
// file.message_screenshot — and what reaches the browser is a PNG. The analyst sees the
// real thing, pixel for pixel, and the message never executes anywhere that matters.

// messageScreenshot serves a picture of the message body.
func (a *API) messageScreenshot(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	id := r.PathValue("id")
	ctx := store.WithTenant(r.Context(), tenant)

	var msg mdm.MessageDataModel
	raw, err := a.store.MDMByID(ctx, tenant, id)
	if err != nil || len(raw) == 0 {
		fail(w, http.StatusNotFound, errors.New("no such message"))
		return
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	png, err := a.pipeline.screenshot(ctx, tenant, id, &msg, r.URL.Query().Get("rerender") != "")
	switch {
	case errors.Is(err, errNothingToRender):
		// A plain-text message with no HTML part has no picture in the same way it
		// has no attachments. The page shows the text instead, so this is a fact
		// rather than a failure.
		fail(w, http.StatusNoContent, err)
		return
	case err != nil:
		fail(w, http.StatusBadGateway, err)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	// Private: a message body is tenant data and must not sit in a shared proxy.
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Write(png)
}

// errNothingToRender means the message has no body a browser could lay out.
var errNothingToRender = errors.New("this message has no renderable body")

// screenshot renders the message body, reusing a cached picture when the body has not
// changed since one was made.
func (p *Pipeline) screenshot(ctx context.Context, tenant, id string, msg *mdm.MessageDataModel, fresh bool) ([]byte, error) {
	html := renderableBody(msg)
	if len(html) == 0 {
		return nil, errNothingToRender
	}
	digest := store.ScreenshotDigest(html)

	if !fresh {
		if png, err := p.store.Screenshot(ctx, tenant, id, digest); err == nil && len(png) > 0 {
			return png, nil
		}
	}

	if p.enricher == nil {
		return nil, errors.New("no renderer is configured")
	}
	v, err := p.enricher.Enrich(ctx, enrich.CapFileHTMLScreenshot,
		[]mql.Value{mql.BytesValue(html)}, nil)
	if err != nil {
		return nil, err
	}
	shot, ok := v.Field("raw").AsBytes()
	if !ok || len(shot) == 0 {
		return nil, errors.New("the renderer returned nothing")
	}
	shot = trimBlankBottom(shot)

	if err := p.store.SetScreenshot(ctx, tenant, id, digest, shot); err != nil {
		// Worth logging but not worth failing: the picture is correct, it just was
		// not kept, and the next view will make it again.
		log.Printf("caching screenshot for %s: %v", id, err)
	}
	return shot, nil
}

// renderableBody is the HTML a browser should lay out.
//
// A plain-text message is wrapped rather than skipped, because what the recipient saw
// is still a rendered thing — the line breaks and the monospace are part of how it
// read — and because a message with no HTML part is exactly the shape a text-only
// phishing attempt takes.
func renderableBody(msg *mdm.MessageDataModel) []byte {
	if msg.Body == nil {
		return nil
	}
	if msg.Body.HTML != nil {
		if raw := mdm.Deref(msg.Body.HTML.Raw); raw != "" {
			return []byte(raw)
		}
	}
	if msg.Body.Plain != nil {
		if raw := mdm.Deref(msg.Body.Plain.Raw); raw != "" {
			return []byte(`<!doctype html><meta charset="utf-8">` +
				`<body style="margin:0;padding:16px;background:#fff">` +
				`<pre style="font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;` +
				`white-space:pre-wrap;word-break:break-word;margin:0;color:#111">` +
				escapeHTML(raw) + `</pre>`)
		}
	}
	return nil
}

func escapeHTML(s string) string {
	r := make([]byte, 0, len(s)+16)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '&':
			r = append(r, "&amp;"...)
		case '<':
			r = append(r, "&lt;"...)
		case '>':
			r = append(r, "&gt;"...)
		default:
			r = append(r, s[i])
		}
	}
	return string(r)
}

// Trimming the empty page below a short message.
//
// Chromium screenshots the viewport, not the content, so a two-line email comes back as
// a thousand pixels of white with a sentence at the top. The renderer cannot know how
// tall the message is — that is a property of the laid-out document, which only exists
// inside the browser — so the blank part is cut off here, where the bytes are.
//
// Conservative by construction: it only removes rows identical to the page's own
// background colour, stops at the first row that is not, and keeps a margin. A message
// that fills the viewport is returned untouched, and so is anything it cannot decode.

// trimBlankBottom removes uniform background rows from the foot of a screenshot.
func trimBlankBottom(raw []byte) []byte {
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return raw
	}
	b := img.Bounds()
	if b.Dy() < 2 {
		return raw
	}

	// The background is whatever the bottom-left pixel is. Taken from the image
	// rather than assumed white, because a message can set its own page colour and
	// cutting on white would then trim nothing at all.
	bg := img.At(b.Min.X, b.Max.Y-1)

	last := b.Min.Y
	for y := b.Max.Y - 1; y >= b.Min.Y; y-- {
		if !uniformRow(img, y, bg) {
			last = y
			break
		}
	}

	const margin = 24
	height := last - b.Min.Y + 1 + margin
	if height < 80 {
		height = 80
	}
	if height >= b.Dy() {
		return raw
	}

	out := image.NewRGBA(image.Rect(0, 0, b.Dx(), height))
	draw.Draw(out, out.Bounds(), img, b.Min, draw.Src)

	var buf bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, out); err != nil {
		return raw
	}
	return buf.Bytes()
}

func uniformRow(img image.Image, y int, bg color.Color) bool {
	br, bgg, bb, ba := bg.RGBA()
	b := img.Bounds()
	for x := b.Min.X; x < b.Max.X; x++ {
		r, g, bl, a := img.At(x, y).RGBA()
		if r != br || g != bgg || bl != bb || a != ba {
			return false
		}
	}
	return true
}

// analyzerPayload is the analyze response: the verdict a caller already depended on,
// plus everything the message detail page shows.
//
// Additive rather than a replacement. The documented fields keep their names and
// meanings, so anything reading this endpoint today keeps working; the detail keys sit
// alongside them, and a caller that does not want them ignores them.
func (p *Pipeline) analyzerPayload(ctx context.Context, out *Analysis) map[string]any {
	payload := detailPayload(out.MessageID, out.Model, out.Detail, out.MDM)

	// The documented shape, layered on top.
	payload["verdict"] = out.Verdict
	payload["matched"] = out.Matched
	payload["missing_capabilities"] = out.Missing
	payload["rules_evaluated"] = out.Evaluated
	payload["elapsed_ms"] = out.ElapsedMS
	payload["enrichment_timing"] = out.Timing
	payload["timed_out"] = out.TimedOut
	if out.TimedOut {
		payload["timed_out_detail"] = map[string]any{
			"costliest_capability": out.CostliestCapability,
			"costliest_ms":         out.CostliestMS,
		}
	}

	// Nothing was stored, so the page cannot come back for a picture later. It is
	// rendered now and carried inline.
	if html := renderableBody(out.Model); len(html) > 0 && p.enricher != nil {
		if shot := p.renderNow(ctx, html); len(shot) > 0 {
			payload["screenshot"] = base64.StdEncoding.EncodeToString(shot)
		}
	}

	// There is no message to act on, and saying so is better than offering buttons
	// that cannot work.
	payload["held"] = false
	payload["transient"] = true
	return payload
}

// renderNow screenshots a body without caching it, for a message that has no identity
// to cache against.
func (p *Pipeline) renderNow(ctx context.Context, html []byte) []byte {
	v, err := p.enricher.Enrich(ctx, enrich.CapFileHTMLScreenshot,
		[]mql.Value{mql.BytesValue(html)}, nil)
	if err != nil {
		return nil
	}
	shot, ok := v.Field("raw").AsBytes()
	if !ok || len(shot) == 0 {
		return nil
	}
	return trimBlankBottom(shot)
}
