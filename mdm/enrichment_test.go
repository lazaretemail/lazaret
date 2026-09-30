// SPDX-License-Identifier: AGPL-3.0-only

package mdm_test

import (
	"encoding/json"
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
)

// Strelka and Sublime disagree about the shape of a YARA result, and rules are written
// against Sublime's. Both have to decode to the same thing.
//
// This is pinned here rather than only in the live test because it was found the hard
// way: every unit test passed while the fixture asserted the published shape against a
// fake that produced the published shape. Nothing failed until a signature matched
// against a real Strelka.
func TestStrelkaYARAAcceptsBothWireShapes(t *testing.T) {
	// What Strelka actually emits: rule names, with metadata in a parallel list.
	strelkaForm := `{
		"matches": ["lazaret_script_obfuscation", "lazaret_ole_auto_exec"],
		"meta": [
			{"rule": "lazaret_script_obfuscation", "identifier": "author", "value": "Lazaret"},
			{"rule": "lazaret_script_obfuscation", "identifier": "severity", "value": 7}
		],
		"tags": ["script"],
		"rules_loaded": 2
	}`

	// What Sublime's API returns, and what the corpus reads.
	publishedForm := `{
		"matches": [
			{"name": "lazaret_script_obfuscation", "meta": {"author": "Lazaret", "severity": "7"}},
			{"name": "lazaret_ole_auto_exec"}
		]
	}`

	for _, tc := range []struct{ name, in string }{
		{"strelka wire format", strelkaForm},
		{"published schema", publishedForm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var y mdm.StrelkaYARA
			if err := json.Unmarshal([]byte(tc.in), &y); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if len(y.Matches) != 2 {
				t.Fatalf("got %d matches, want 2", len(y.Matches))
			}
			if got := mdm.Deref(y.Matches[0].Name); got != "lazaret_script_obfuscation" {
				t.Errorf("first match name = %q", got)
			}
			if got := mdm.Deref(y.Matches[1].Name); got != "lazaret_ole_auto_exec" {
				t.Errorf("second match name = %q", got)
			}
			if got := y.Matches[0].Meta["author"]; got != "Lazaret" {
				t.Errorf("author meta = %q", got)
			}
			// YARA metadata is not limited to strings; the schema types it as one, so a
			// number is rendered rather than dropped.
			if got := y.Matches[0].Meta["severity"]; got != "7" {
				t.Errorf("severity meta = %q, want the rendered number", got)
			}
		})
	}
}

// Meta naming a rule that is not in matches still identifies a rule that fired, so it is
// kept rather than discarded.
func TestStrelkaYARAKeepsMetaForUnlistedRule(t *testing.T) {
	var y mdm.StrelkaYARA
	err := json.Unmarshal([]byte(`{"matches":[],
		"meta":[{"rule":"orphan","identifier":"author","value":"someone"}]}`), &y)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(y.Matches) != 1 || mdm.Deref(y.Matches[0].Name) != "orphan" {
		t.Fatalf("got %+v, want the orphaned rule kept", y.Matches)
	}
}

// A match that is neither shape is reported. An undetected match is a missed detection,
// so it must not be swallowed.
func TestStrelkaYARARejectsUnknownShape(t *testing.T) {
	var y mdm.StrelkaYARA
	if err := json.Unmarshal([]byte(`{"matches":[12345]}`), &y); err == nil {
		t.Fatal("want an error for a match that is neither a name nor an object")
	}
}

// The fixtures below are captured from a real Strelka scan of a real file, not
// transcribed from the published schema. That distinction is the whole point: a fixture
// written from the schema agrees with a decoder written from the schema, and the suite
// stays green over a format neither of them has ever seen.

// scan.qr, from scanning a PNG that is a QR code encoding a URL.
const wireQR = `{"data":["https://phish.lazaret.email/verify?id=42"],"elapsed":0.007663}`

// scan.ocr, from scanning a PNG carrying three lines of text.
const wireOCR = `{"elapsed":0.550348,"render":{"dpi":300,"format":"png","height":1625,
  "source":"pdf","width":5625},"text":["URGENT","PAYMENT","REQUIRED","Verify","your",
  "account","now","support@lazaretemail"]}`

// scan.exiftool, from scanning a three-page PDF. Note every key is lowercased, and the
// filesystem entries describe Strelka's temporary copy rather than the document.
const wireExif = `{"author":"A. Sender","createdate":"2026:09:19 01:50:42Z",
  "directory":"/tmp","elapsed":0.053425,"exiftoolversion":12.6,
  "filename":"tmpuw7vkgpn","filepermissions":"-rw-------","filesize":"171 kB",
  "filetype":"PDF","filetypeextension":"pdf","linearized":"No",
  "mimetype":"application/pdf","pagecount":3,"pdfversion":1.4,
  "producer":"LazaretFixtureTool","sourcefile":"/tmp/tmpuw7vkgpn",
  "title":"Quarterly Invoice"}`

func TestStrelkaQRAcceptsAnArrayOfPayloads(t *testing.T) {
	var q mdm.StrelkaQR
	if err := json.Unmarshal([]byte(wireQR), &q); err != nil {
		t.Fatalf("decoding the real wire shape: %v", err)
	}
	if q.Data == nil || *q.Data != "https://phish.lazaret.email/verify?id=42" {
		t.Fatalf("data = %v", q.Data)
	}
	if q.Type == nil || *q.Type != mdm.StrelkaQRTypeURL {
		t.Errorf("type = %v, want url", q.Type)
	}
	if q.URL == nil || q.URL.Domain == nil || q.URL.Domain.RootDomain == nil ||
		*q.URL.Domain.RootDomain != "lazaret.email" {
		t.Errorf("url was not derived: %+v", q.URL)
	}

	// The published shape, a bare string, must keep working.
	var single mdm.StrelkaQR
	if err := json.Unmarshal([]byte(`{"data":"mailto:a@b.test"}`), &single); err != nil {
		t.Fatalf("decoding the published shape: %v", err)
	}
	if single.Type == nil || *single.Type != mdm.StrelkaQRTypeEmail {
		t.Errorf("type = %v, want email", single.Type)
	}
}

func TestStrelkaOCRReconstructsRaw(t *testing.T) {
	var o mdm.StrelkaOCR
	if err := json.Unmarshal([]byte(wireOCR), &o); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(o.Text) != 8 {
		t.Errorf("words = %d, want 8", len(o.Text))
	}
	// 505 corpus rules read .scan.ocr.raw, and this build of Strelka never sends it.
	const want = "URGENT PAYMENT REQUIRED Verify your account now support@lazaretemail"
	if o.Raw == nil || *o.Raw != want {
		t.Errorf("raw = %v,\nwant %q", o.Raw, want)
	}

	// A build that does send raw must win over the reconstruction.
	var given mdm.StrelkaOCR
	if err := json.Unmarshal([]byte(`{"raw":"line one\nline two","text":["line","one"]}`), &given); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if given.Raw == nil || *given.Raw != "line one\nline two" {
		t.Errorf("raw = %v, want the wire's own value", given.Raw)
	}
}

func TestStrelkaExifToolFlattensAndRecasesKeys(t *testing.T) {
	var e mdm.StrelkaExifTool
	if err := json.Unmarshal([]byte(wireExif), &e); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	got := map[string]string{}
	for _, kv := range e.Fields {
		got[*kv.Key] = *kv.Value
	}
	// Canonical casing, because the corpus compares `.key == "Author"` literally.
	if got["Author"] != "A. Sender" {
		t.Errorf("Author = %q; a lowercase key matches no rule", got["Author"])
	}
	if got["PageCount"] != "3" {
		t.Errorf("PageCount = %q, want 3 — not 3.0, which no rule compares against", got["PageCount"])
	}
	// The scanner's own temporary paths are not document metadata.
	for _, k := range []string{"sourcefile", "directory", "filename", "elapsed", "SourceFile"} {
		if _, ok := got[k]; ok {
			t.Errorf("%q leaked into fields", k)
		}
	}
	// Named conveniences.
	if e.Title == nil || *e.Title != "Quarterly Invoice" {
		t.Errorf("title = %v", e.Title)
	}
	if e.Producer == nil || *e.Producer != "LazaretFixtureTool" {
		t.Errorf("producer = %v", e.Producer)
	}
	if e.PageCount == nil || *e.PageCount != 3 {
		t.Errorf("page_count = %v", e.PageCount)
	}
}
