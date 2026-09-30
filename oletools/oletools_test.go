// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// Fixtures are built by testdata/generate.py and every compound file among them is
// verified with olefile before being written. That matters: this package is a
// reimplementation, and fixtures built from the same understanding as the code would
// only prove the two agree with each other.
func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v (run: python3 testdata/generate.py)", err)
	}
	return b
}

func analyze(t *testing.T, name string) *mdm.OleToolsOutput {
	t.Helper()
	var a Analyzer
	return a.Analyze(load(t, name))
}

// Remote template injection: a document whose settings relationship points at an
// external URL. Seven corpus rules read relationships and this is why.
func TestExternalRelationshipIsReported(t *testing.T) {
	out := analyze(t, "remote_template.docx")

	if len(out.Relationships) == 0 {
		t.Fatal("no relationships found in a document that declares one")
	}
	var found *mdm.OleRelationship
	for _, r := range out.Relationships {
		if strings.Contains(mdm.Deref(r.Target), "198.51.100.9") {
			found = r
		}
	}
	if found == nil {
		t.Fatalf("the external target is missing; got %d relationships", len(out.Relationships))
	}
	if found.TargetURL == nil {
		t.Fatal("target_url is not set, and it is what the rules read")
	}
	if got := mdm.Deref(found.TargetURL.Scheme); got != "http" {
		t.Errorf("target_url.scheme = %q, want http", got)
	}
	if out.Indicators == nil || out.Indicators.ExternalRelationships == nil {
		t.Fatal("external_relationships count is not set")
	}
	if got := mdm.Deref(out.Indicators.ExternalRelationships.Count); got != 1 {
		t.Errorf("external relationship count = %d, want 1", got)
	}
}

// The file: scheme rule reads target_url.scheme and target_url.path, so a UNC-style
// target has to parse into both.
func TestFileSchemeRelationshipParses(t *testing.T) {
	out := analyze(t, "file_scheme.docx")

	for _, r := range out.Relationships {
		if r.TargetURL == nil {
			continue
		}
		if mdm.Deref(r.TargetURL.Scheme) != "file" {
			continue
		}
		if !strings.Contains(mdm.Deref(r.TargetURL.Path), "203.0.113.5") &&
			!strings.Contains(mdm.Deref(r.Target), "203.0.113.5") {
			t.Errorf("the address is in neither target nor target_url.path: %+v", r.TargetURL)
		}
		return
	}
	t.Fatal("no file-scheme relationship found")
}

// An internal relationship is a path inside the package, not somewhere the document
// reaches. Giving it a target_url would invent a scheme that is not there and make
// every ordinary document look like it phones home.
func TestInternalRelationshipGetsNoURL(t *testing.T) {
	out := analyze(t, "internal_only.docx")

	for _, r := range out.Relationships {
		if strings.Contains(mdm.Deref(r.Target), "styles.xml") {
			if r.TargetURL != nil {
				t.Errorf("an internal target was given a URL: %+v", r.TargetURL)
			}
			if out.Indicators != nil && out.Indicators.ExternalRelationships != nil {
				t.Error("an internal relationship was counted as external")
			}
			return
		}
	}
	t.Fatal("the internal relationship is missing entirely")
}

// The auto-exec rule keys on keywords[].type, and the high-risk rule on
// indicators.vba_macros.risk. Both need real VBA out of a real compound file.
func TestMacroDocumentYieldsAutoExecAndHighRisk(t *testing.T) {
	out := analyze(t, "macro.docm")

	if out.Indicators == nil || out.Indicators.VBAMacros == nil {
		t.Fatal("no vba_macros indicator")
	}
	if !mdm.Deref(out.Indicators.VBAMacros.Exists) {
		t.Fatal("vba_macros.exists is false for a document with a macro")
	}
	if got := mdm.Deref(out.Indicators.VBAMacros.Risk); got != riskHigh {
		t.Errorf("risk = %q, want high: this macro runs on open and starts a process", got)
	}

	var autoexec, shell bool
	for _, k := range out.Macros.Keywords {
		if strings.EqualFold(mdm.Deref(k.Type), "autoexec") {
			autoexec = true
		}
		if strings.EqualFold(mdm.Deref(k.Keyword), "shell") {
			shell = true
		}
	}
	if !autoexec {
		t.Error("no AutoExec keyword; the corpus rule tests .type =~ \"autoexec\"")
	}
	if !shell {
		t.Error("Shell was not detected")
	}
	if !strings.Contains(mdm.Deref(out.Macros.VBACodeAllModules), "AutoOpen") {
		t.Error("the decompressed source does not contain the macro")
	}
}

// A macro that does nothing unusual must not be graded high, or the high-risk rule
// fires on every document that formats a table.
func TestBenignMacroIsNotHighRisk(t *testing.T) {
	out := analyze(t, "benign_macro.docm")

	if out.Indicators == nil || out.Indicators.VBAMacros == nil {
		t.Fatal("no vba_macros indicator")
	}
	if !mdm.Deref(out.Indicators.VBAMacros.Exists) {
		t.Error("a macro is present and should be reported")
	}
	if got := mdm.Deref(out.Indicators.VBAMacros.Risk); got == riskHigh {
		t.Errorf("risk = high for a macro that only formats a table")
	}
}

// An encrypted document says so, and says nothing about macros it cannot read.
func TestEncryptedDocumentIsReportedAndNotGuessedAbout(t *testing.T) {
	out := analyze(t, "encrypted.doc")

	if out.Indicators == nil || out.Indicators.Encryption == nil {
		t.Fatal("no encryption indicator")
	}
	if !mdm.Deref(out.Indicators.Encryption.Exists) {
		t.Error("encryption.exists is false for a document with an EncryptedPackage stream")
	}
	if out.Indicators.VBAMacros != nil {
		t.Error("a claim was made about the macros of a document that could not be read")
	}
}

// A document with no macros must say so definitely — absent is not the same as false,
// and a rule asking "does this have macros" deserves an answer when one is knowable.
func TestNoMacrosIsADefiniteFalse(t *testing.T) {
	out := analyze(t, "remote_template.docx")

	if out.Indicators == nil || out.Indicators.VBAMacros == nil {
		t.Fatal("vba_macros indicator absent for a readable document with no macros")
	}
	if mdm.Deref(out.Indicators.VBAMacros.Exists) {
		t.Error("vba_macros.exists is true for a document with no VBA project")
	}
}

// Anything that is not an Office document yields nothing — and in particular does
// not assert that it has no macros, which would be a statement about a PNG.
func TestNonOfficeInputAssertsNothing(t *testing.T) {
	var a Analyzer
	for name, raw := range map[string][]byte{
		"png":    {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A},
		"text":   []byte("just a note"),
		"empty":  {},
		"nearly": {'P', 'K', 0x03, 0x04, 0x00},
	} {
		out := a.Analyze(raw)
		if out == nil {
			t.Fatalf("%s: nil output", name)
		}
		if out.Indicators != nil && out.Indicators.VBAMacros != nil {
			t.Errorf("%s: claimed to know about macros", name)
		}
		if len(out.Relationships) != 0 {
			t.Errorf("%s: invented relationships", name)
		}
	}
}

// The enricher answers through the MQL seam the way rules call it.
func TestEnrichAnswersFileOletools(t *testing.T) {
	c := New()
	file := mql.FromGo(&mdm.File{
		FileName: mdm.Ptr("invoice.docm"),
		Raw:      load(t, "macro.docm"),
	})

	v, err := c.Enrich(context.Background(), enrich.CapFileOletools, []mql.Value{file}, nil)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if v.IsNull() {
		t.Fatal("null result for a macro document")
	}
	exists, _ := v.Field("indicators").Field("vba_macros").Field("exists").AsBool()
	if !exists {
		t.Error("indicators.vba_macros.exists did not survive the MQL conversion")
	}
	if risk, _ := v.Field("indicators").Field("vba_macros").Field("risk").AsString(); risk != riskHigh {
		t.Errorf("risk through MQL = %q, want high", risk)
	}
}

// A call on something with no bytes is not a failure. It must not report the
// capability unavailable, which would make every message carrying a text file
// indeterminate.
func TestEmptyInputIsNullNotUnavailable(t *testing.T) {
	c := New()
	v, err := c.Enrich(context.Background(), enrich.CapFileOletools,
		[]mql.Value{mql.FromGo(&mdm.File{FileName: mdm.Ptr("note.txt")})}, nil)
	if err != nil {
		t.Errorf("empty input reported an error: %v", err)
	}
	if !v.IsNull() {
		t.Error("expected null for a file with no content")
	}
}

// The CVE-2021-40444 target shape, which the corpus matches with
// regex.icontains(.target, ".*html:http.*"). The rule reads .target rather than
// .target_url, so the raw string has to survive intact — an mhtml: URL that gets
// normalised or dropped takes the detection with it.
func TestMHTMLTargetSurvivesVerbatim(t *testing.T) {
	out := analyze(t, "cve_2021_40444.docx")

	for _, r := range out.Relationships {
		target := mdm.Deref(r.Target)
		if !strings.Contains(target, "mhtml:") {
			continue
		}
		if !strings.Contains(strings.ToLower(target), "html:http") {
			t.Errorf("target was altered to %q; the rule matches on html:http", target)
		}
		if !strings.Contains(target, "x-usc:") {
			t.Errorf("the x-usc fragment was lost from %q", target)
		}
		return
	}
	t.Fatal("no mhtml relationship found")
}
