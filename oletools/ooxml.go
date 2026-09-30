// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"path"
	"strings"

	"github.com/lazaretemail/lazaret/mdm"
)

// OOXML: a zip of XML parts, plus relationship files that say how they connect.
//
// The relationships are the interesting part and the reason seven corpus rules want
// this. A relationship with TargetMode="External" makes the document fetch something
// when opened, and that is the whole mechanism behind remote template injection and
// CVE-2021-40444: a Word file whose settings relationship points at an http URL, or
// an embedded object whose target is an mhtml: URL that loads a scriptlet.
//
// Nothing here executes or renders anything. It reads the manifest and reports where
// the document says it will reach.

// relsXML is the shape of a .rels part.
type relsXML struct {
	XMLName       xml.Name          `xml:"Relationships"`
	Relationships []relationshipXML `xml:"Relationship"`
}

type relationshipXML struct {
	ID         string `xml:"Id,attr"`
	Type       string `xml:"Type,attr"`
	Target     string `xml:"Target,attr"`
	TargetMode string `xml:"TargetMode,attr"`
}

func (a *Analyzer) analyzeOOXML(raw []byte, out *mdm.OleToolsOutput) {
	lim := a.limits()

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		// A file that begins "PK" but is not a readable zip is not a document.
		// Reported as nothing rather than as a document with no macros.
		return
	}

	out.Indicators = &mdm.OleIndicators{
		FileFormat: &mdm.OleIndicator{Value: mdm.Ptr(formatName(formatOOXML))},
	}

	var (
		total    int64
		external int64
		vbaRaw   []byte
	)

	for i, f := range zr.File {
		if i >= lim.MaxEntries {
			break
		}
		name := path.Clean(f.Name)

		switch {
		case isRelsPart(name):
			data, n := readCapped(f, lim.MaxEntryBytes, lim.MaxTotalBytes-total)
			total += n
			external += a.collectRelationships(name, data, out)

		case isVBAProject(name):
			// Kept for the macro pass. Read here because the zip is open and
			// reading it twice is the only alternative.
			vbaRaw, _ = readCapped(f, lim.MaxEntryBytes, lim.MaxTotalBytes-total)
		}

		if total >= lim.MaxTotalBytes {
			break
		}
	}

	if external > 0 {
		out.Indicators.ExternalRelationships = &mdm.OleIndicatorCount{Count: mdm.Ptr(external)}
	}

	// An OOXML file is a plain zip; if it were encrypted it would be an OLE2
	// container instead, handled on the other path. Saying so explicitly matters:
	// a rule asking `indicators.encryption.exists` wants false here, not absent.
	out.Indicators.Encryption = &mdm.OleIndicator{Exists: mdm.Ptr(false)}

	a.analyzeVBA(vbaRaw, out)
}

// isRelsPart reports the relationship manifests. They live in a _rels directory
// beside the part they describe, at any depth: "_rels/.rels" for the package itself,
// "word/_rels/document.xml.rels" and "word/_rels/settings.xml.rels" for the parts.
func isRelsPart(name string) bool {
	return strings.HasSuffix(name, ".rels") && strings.Contains(name, "_rels/")
}

// isVBAProject finds the macro storage. Word, Excel and PowerPoint each put it under
// their own directory, so the base name is what identifies it.
func isVBAProject(name string) bool {
	return strings.EqualFold(path.Base(name), "vbaProject.bin")
}

// collectRelationships parses one .rels part and appends what it declares, returning
// how many were external.
func (a *Analyzer) collectRelationships(part string, data []byte, out *mdm.OleToolsOutput) int64 {
	if len(data) == 0 {
		return 0
	}
	var doc relsXML
	if err := xml.Unmarshal(data, &doc); err != nil {
		return 0
	}

	lim := a.limits()
	var external int64
	for _, r := range doc.Relationships {
		if len(out.Relationships) >= lim.MaxRelationships {
			break
		}
		if r.Target == "" {
			continue
		}
		isExternal := strings.EqualFold(r.TargetMode, "External")
		if isExternal {
			external++
		}

		rel := &mdm.OleRelationship{
			Target: mdm.Ptr(r.Target),
			Name:   mdm.Ptr(r.ID),
			Type:   mdm.Ptr(r.Type),
		}
		// target_url is what the corpus reads far more than target, because what
		// matters is where the document reaches. Only external targets are URLs;
		// an internal one is a path inside the package and parsing it as a URL
		// would invent a scheme that is not there.
		if isExternal {
			if u := mdm.ParseURL(r.Target, true); u != nil {
				rel.TargetURL = u
			}
		}
		out.Relationships = append(out.Relationships, rel)
	}
	return external
}

// readCapped reads a zip member, bounded twice: by what one member may be and by what
// is left of the document's total budget. A member's declared uncompressed size is
// attacker-controlled, so the limit is applied to the read rather than trusted from
// the header.
func readCapped(f *zip.File, maxEntry, remaining int64) ([]byte, int64) {
	if maxEntry <= 0 || remaining <= 0 {
		return nil, 0
	}
	cap := maxEntry
	if remaining < cap {
		cap = remaining
	}
	rc, err := f.Open()
	if err != nil {
		return nil, 0
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, cap))
	if err != nil {
		return nil, int64(len(data))
	}
	return data, int64(len(data))
}
