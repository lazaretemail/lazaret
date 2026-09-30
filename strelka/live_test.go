// SPDX-License-Identifier: AGPL-3.0-only

package strelka_test

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/strelka"
)

// A smoke test against a real Strelka.
//
// Opt-in, because it needs a running deployment. It exists because the unit tests above
// were once green against a fake whose format was wrong in a way that would have made
// every rule quietly match nothing — a fake can only ever confirm what its author already
// believed. Run it against the deployment in third_party/strelka:
//
//	docker compose -f third_party/strelka/docker-compose.yml up -d
//	LAZARET_STRELKA=localhost:57314 go test ./strelka/ -run Live -v
func TestLiveStrelka(t *testing.T) {
	addr := os.Getenv("LAZARET_STRELKA")
	if addr == "" {
		t.Skip("set LAZARET_STRELKA to a Strelka frontend address to run this")
	}

	c, err := strelka.Dial(&strelka.Options{Address: addr, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	// An archive with two members, one of which is a script — so extraction, flavour
	// detection and a content scanner are all exercised.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"invoice.txt": "an urgent payment request",
		"script.js":   `var x = unescape("%41%42"); eval(x);`,
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := c.Explode(context.Background(), "invoice.zip", buf.Bytes())
	if err != nil {
		t.Fatalf("Explode: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d records, want 3 (the archive and two members)", len(out))
	}

	var root, script *mdm.FileExplodeOutput
	for _, r := range out {
		switch mdm.Deref(r.FileName) {
		case "invoice.zip":
			root = r
		case "script.js":
			script = r
		}
	}

	// The translation layer. Every one of these was empty before it existed, with no
	// error anywhere to say so.
	if root == nil {
		t.Fatal("the submitted archive was not in the results")
	}
	if got := mdm.Deref(root.Depth); got != 0 {
		t.Errorf("archive depth = %d, want 0", got)
	}
	if got := mdm.Deref(root.FileExtension); got != "zip" {
		t.Errorf("archive file_extension = %q", got)
	}
	if root.Flavors == nil || mdm.Deref(root.Flavors.MIME) != "application/zip" {
		t.Errorf("archive mime = %+v", root.Flavors)
	}

	if script == nil {
		t.Fatal("script.js was not extracted")
	}
	if got := mdm.Deref(script.Depth); got != 1 {
		t.Errorf("member depth = %d, want 1", got)
	}
	if mdm.Deref(script.ParentNodeID) != mdm.Deref(root.NodeID) {
		t.Error("the member does not point back at the archive")
	}
	if got := mdm.Deref(script.Source); got != "ScanZip" {
		t.Errorf("member source = %q, want ScanZip", got)
	}

	// And a real scanner result, of the kind rules actually match on.
	if script.Scan == nil || script.Scan.Javascript == nil {
		t.Fatal("the javascript scanner produced nothing")
	}
	if ids := script.Scan.Javascript.Identifiers; !slices.Contains(ids, "unescape") {
		t.Errorf("javascript identifiers = %v, want them to include unescape", ids)
	}

	// And a YARA hit from third_party/strelka/signatures, on a file that only exists
	// because the archive was exploded. This assertion is here because the wire format
	// of `scan.yara.matches` is a bare rule name where the published schema says it is
	// an object, and nothing revealed that until a signature matched for the first time
	// against a real Strelka — an empty match list decodes fine under either reading.
	if script.Scan.Yara == nil {
		t.Fatal("the yara scanner produced nothing")
	}
	var matched []string
	for _, m := range script.Scan.Yara.Matches {
		matched = append(matched, mdm.Deref(m.Name))
	}
	if !slices.Contains(matched, "lazaret_script_obfuscation") {
		t.Errorf("yara matches = %v, want lazaret_script_obfuscation", matched)
	}

	t.Logf("archive=%s member=%s identifiers=%v yara=%v",
		mdm.Deref(root.FileName), mdm.Deref(script.FileName),
		script.Scan.Javascript.Identifiers, matched)
}
