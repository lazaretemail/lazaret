// SPDX-License-Identifier: AGPL-3.0-only

package yara_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/yara"
)

const testSignature = `
rule SublimeStandardTestString {
  meta:
    author = "Sublime Security"
    severity = "low"
  strings:
    $s = "Sublime-Standard-Test-String"
  condition:
    $s
}
`

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("test.yar", testSignature)
	write("other.yara", "rule B { condition: false }")
	// A feed is a git repository, so it contains other things too.
	write("README.md", "not a signature")
	write("rule.yml", "name: an MQL rule")

	sources, err := yara.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(sources) != 2 {
		t.Errorf("loaded %d files, want 2: %v", len(sources), keysOf(sources))
	}
	if !strings.Contains(sources["test.yar"], "SublimeStandardTestString") {
		t.Error("the signature body was not read")
	}

	if _, err := yara.LoadDir(t.TempDir()); err == nil {
		t.Error("an empty directory loaded without complaint")
	}
}

func TestResultMapsToTheShapeMQLReads(t *testing.T) {
	// Rules reach for `.scan.yara.matches, .name == "..."` and `.meta['author']`. This is
	// the contract with the file-analysis module, so it is worth pinning independently of
	// whether a scanner is available.
	res := &yara.Result{
		Flags: []string{"timeout"},
		Matches: []yara.Match{{
			Name:      "SublimeStandardTestString",
			Namespace: "test.yar",
			Meta:      map[string]string{"author": "Sublime Security", "severity": "low"},
		}},
	}

	got := res.MDM()
	if len(got.Matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(got.Matches))
	}
	if name := mdm.Deref(got.Matches[0].Name); name != "SublimeStandardTestString" {
		t.Errorf("name = %q", name)
	}
	if got.Matches[0].Meta["author"] != "Sublime Security" {
		t.Errorf("meta = %v", got.Matches[0].Meta)
	}
	if len(got.Flags) != 1 || got.Flags[0] != "timeout" {
		t.Errorf("flags = %v", got.Flags)
	}
}

func TestUnsupportedIsDistinctFromNoMatch(t *testing.T) {
	// A build that cannot scan has not cleared a file. Callers must be able to tell that
	// apart from a clean scan, or they will eventually report the wrong thing.
	if yara.Available() {
		t.Skip("this build has YARA support")
	}

	_, err := yara.Compile(map[string]string{"t.yar": testSignature})
	if !errors.Is(err, yara.ErrUnsupported) {
		t.Errorf("Compile error = %v, want ErrUnsupported", err)
	}
	if _, err := yara.ScanAttachments(nil, &mdm.MessageDataModel{}); !errors.Is(err, yara.ErrUnsupported) {
		t.Errorf("ScanAttachments error = %v, want ErrUnsupported", err)
	}
	// And the message says what to do about it.
	if !strings.Contains(yara.ErrUnsupported.Error(), "-tags yara") {
		t.Errorf("the error does not say how to enable support: %v", yara.ErrUnsupported)
	}
}

func TestScanAttachments(t *testing.T) {
	if !yara.Available() {
		t.Skip("built without YARA support; run with -tags yara")
	}

	scanner, err := yara.Compile(map[string]string{"test.yar": testSignature})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	defer scanner.Close()

	if scanner.Count() != 1 {
		t.Errorf("Count() = %d, want 1", scanner.Count())
	}

	msg := &mdm.MessageDataModel{Attachments: []*mdm.Attachment{
		{FileName: mdm.Ptr("hit.txt"), Raw: []byte("xx Sublime-Standard-Test-String xx")},
		{FileName: mdm.Ptr("miss.txt"), Raw: []byte("nothing interesting")},
		{FileName: mdm.Ptr("empty.txt")}, // no bytes; nothing to scan
	}}

	results, err := yara.ScanAttachments(scanner, msg)
	if err != nil {
		t.Fatalf("ScanAttachments: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("scanned %d attachments, want 2 (the empty one has no bytes)", len(results))
	}
	if n := len(results["hit.txt"].Matches); n != 1 {
		t.Errorf("hit.txt produced %d matches, want 1", n)
	}
	if n := len(results["miss.txt"].Matches); n != 0 {
		t.Errorf("miss.txt produced %d matches, want 0", n)
	}
	if got := results["hit.txt"].Matches[0].Meta["author"]; got != "Sublime Security" {
		t.Errorf("metadata was not carried through: %v", results["hit.txt"].Matches[0].Meta)
	}
}

func TestCompileRejectsOnlyBrokenSignatures(t *testing.T) {
	if !yara.Available() {
		t.Skip("built without YARA support")
	}
	if _, err := yara.Compile(map[string]string{"bad.yar": "this is not a signature"}); err == nil {
		t.Error("a file of nonsense compiled")
	}
	// One broken file among good ones should not cost the deployment the good ones.
	s, err := yara.Compile(map[string]string{
		"good.yar": testSignature,
		"bad.yar":  "this is not a signature",
	})
	if err != nil {
		t.Fatalf("one broken file lost the whole set: %v", err)
	}
	defer s.Close()
	if s.Count() != 1 {
		t.Errorf("Count() = %d, want the good signature to survive", s.Count())
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
