// SPDX-License-Identifier: AGPL-3.0-only

package strelka

import (
	"encoding/json"
	"path"
	"strings"

	"github.com/lazaretemail/lazaret/mdm"
)

// Translating Strelka's wire format into the shape MQL reads.
//
// # The published schema is not the wire format
//
// Sublime's FileExplodeOutput — from which mdm.FileExplodeOutput is generated — is a
// *flattened* view of Strelka's response, not the response itself. Strelka emits
//
//	{"file": {"depth":1, "name":"script.js", "size":36, "source":"ScanZip",
//	          "flavors":{"mime":["text/plain"], "yara":["javascript_file"]},
//	          "tree":{"node":"…", "parent":"…", "root":"…"}},
//	 "request": {…},
//	 "scan": {…}}
//
// while rules see `.file_name`, `.depth`, `.node_id`, `.parent_node_id` at the top level.
// So Sublime lifts file.* up a level and renames the tree fields, and anything consuming
// raw Strelka has to do the same.
//
// This was only discoverable by running a real Strelka: decoding the wire format straight
// into the generated struct compiles, produces no error, and silently yields records
// where every field except `scan` is empty. Rules would have kept evaluating and quietly
// matching nothing.
//
// The other mismatch is `flavors.mime`, which Strelka emits as an array and the schema
// declares as a single string.

// strelkaEvent is Strelka's actual response, as it appears on the wire.
type strelkaEvent struct {
	File struct {
		Depth   int64  `json:"depth"`
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		Source  string `json:"source"`
		Flavors struct {
			MIME     []string `json:"mime"`
			Yara     []string `json:"yara"`
			External []string `json:"external"`
		} `json:"flavors"`
		Tree struct {
			Node   string `json:"node"`
			Parent string `json:"parent"`
			Root   string `json:"root"`
		} `json:"tree"`
	} `json:"file"`

	Request struct {
		Attributes struct {
			Filename string `json:"filename"`
		} `json:"attributes"`
	} `json:"request"`

	// Scan matches the generated type directly: it is the one part of the response
	// Sublime passes through unchanged, which is why the 36-scanner tree under it —
	// yara, javascript, ocr, vba and the rest — decodes without any translation.
	Scan *mdm.FileScan `json:"scan"`
}

// decodeEvent converts one Strelka response into the model.
func decodeEvent(raw []byte) (*mdm.FileExplodeOutput, error) {
	var ev strelkaEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, err
	}

	out := &mdm.FileExplodeOutput{
		Depth: mdm.Ptr(ev.File.Depth),
		Size:  mdm.Ptr(ev.File.Size),
		Scan:  ev.Scan,
	}

	// The submitted file has no name of its own in the event — Strelka only knows the
	// filename the client supplied, which it echoes back under request.attributes. An
	// extracted file does have one.
	name := ev.File.Name
	if name == "" && ev.File.Depth == 0 {
		name = ev.Request.Attributes.Filename
	}
	if name != "" {
		out.FileName = mdm.Ptr(name)
		// Not in the wire format at all; rules read it constantly, and deriving it from
		// the name is what Sublime must do too.
		if ext := strings.TrimPrefix(strings.ToLower(path.Ext(name)), "."); ext != "" {
			out.FileExtension = mdm.Ptr(ext)
		}
	}

	// `source` names the scanner that produced this file — "ScanZip" for a zip member.
	// It is how a rule tells an extracted object from the thing that was submitted.
	if ev.File.Source != "" {
		out.Source = mdm.Ptr(ev.File.Source)
	}

	if ev.File.Tree.Node != "" {
		out.NodeID = mdm.Ptr(ev.File.Tree.Node)
	}
	if ev.File.Tree.Parent != "" {
		out.ParentNodeID = mdm.Ptr(ev.File.Tree.Parent)
	}

	if f := ev.File.Flavors; len(f.MIME) > 0 || len(f.Yara) > 0 || len(f.External) > 0 {
		flavors := &mdm.StrelkaFlavors{External: f.External}
		// The schema types flavour names as an enumeration, but Strelka's set grows with
		// its scanners, so unknown values are carried through rather than dropped.
		for _, y := range f.Yara {
			flavors.Yara = append(flavors.Yara, mdm.StrelkaFlavorsYara(y))
		}
		if len(f.MIME) > 0 {
			// The schema declares one MIME type where Strelka emits a list. Taking the
			// first matches what rules expect; the rest are alternates from libmagic and
			// are not carried, because the field has nowhere to put them.
			flavors.MIME = mdm.Ptr(f.MIME[0])
		}
		out.Flavors = flavors
	}

	return out, nil
}
