// SPDX-License-Identifier: AGPL-3.0-only

package strelka_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/strelka"
)

// Live tests for beta.ocr, beta.scan_qr and beta.parse_exif against a real Strelka.
//
// Every assertion here is on a *non-empty* result. That is the rule this package learned
// twice over: an empty list decodes cleanly under a wrong reading of the wire format, so
// a test that only checks "no error" proves nothing about the shape. The QR case is the
// sharpest example — scanning a real QR code is what revealed that Strelka sends `data`
// as an array where the published schema declares a string, which had been failing every
// scan of a QR-bearing attachment and taking file.explode down with it.
//
//	docker compose -f third_party/strelka/docker-compose.yml up -d
//	LAZARET_STRELKA=localhost:57314 go test ./strelka/ -run Live -v
func liveClient(t *testing.T) *strelka.Client {
	t.Helper()
	addr := os.Getenv("LAZARET_STRELKA")
	if addr == "" {
		t.Skip("set LAZARET_STRELKA to a Strelka frontend address to run this")
	}
	c, err := strelka.Dial(&strelka.Options{Address: addr, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatalf("dialling Strelka: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// attachmentArg builds the MQL argument shape a rule passes: `any(attachments, beta.ocr(.))`.
func attachmentArg(t *testing.T, name string) []mql.Value {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return []mql.Value{mql.FromGo(&mdm.Attachment{
		FileName: mdm.Ptr(name),
		Raw:      data,
	})}
}

func TestLiveOCRReadsTextFromAnImage(t *testing.T) {
	c := liveClient(t)
	v, err := c.Enrich(context.Background(), enrich.CapBetaOCR, attachmentArg(t, "ocr.png"), nil)
	if err != nil {
		t.Fatalf("beta.ocr: %v", err)
	}
	text := v.Field("text")
	if text.IsNull() {
		t.Fatal("no text recognised; the fixture carries large high-contrast words")
	}
	got := text.String()
	// Tesseract is not perfect — it drops the dot in an address — so assert on the
	// phrase a rule would key on rather than on an exact transcription.
	for _, want := range []string{"URGENT", "PAYMENT", "REQUIRED"} {
		if !strings.Contains(strings.ToUpper(got), want) {
			t.Errorf("recognised text %q does not contain %q", got, want)
		}
	}
	if s := v.Field("success"); !s.Truthy() {
		t.Error("success is not true on a scan that recognised text")
	}
	t.Logf("beta.ocr text = %q", got)
}

func TestLiveScanQRFindsAURL(t *testing.T) {
	c := liveClient(t)
	v, err := c.Enrich(context.Background(), enrich.CapBetaScanQR, attachmentArg(t, "qr.png"), nil)
	if err != nil {
		t.Fatalf("beta.scan_qr: %v", err)
	}
	if !v.Field("found").Truthy() {
		t.Fatal("found is not true for an image that is a QR code")
	}
	items := v.Field("items").Elements()
	if len(items) == 0 {
		t.Fatal("no items decoded")
	}
	first := items[0]
	if got := first.Field("type").String(); got != "url" {
		t.Errorf("type = %q, want url — the corpus keys on `.type == \"url\"`", got)
	}
	const want = "https://phish.lazaret.email/verify?id=42"
	if got := first.Field("data").String(); got != want {
		t.Errorf("data = %q, want %q", got, want)
	}
	// The parsed URL is what rules actually read: `.url.domain.root_domain` and friends.
	if got := first.Field("url").Field("domain").Field("root_domain").String(); got != "lazaret.email" {
		t.Errorf("url.domain.root_domain = %q, want lazaret.email", got)
	}
	t.Logf("beta.scan_qr items = %d, first = %s", len(items), first.Field("data").String())
}

func TestLiveParseExifReadsDocumentMetadata(t *testing.T) {
	c := liveClient(t)
	v, err := c.Enrich(context.Background(), enrich.CapBetaParseExif, attachmentArg(t, "invoice.pdf"), nil)
	if err != nil {
		t.Fatalf("beta.parse_exif: %v", err)
	}
	if got := v.Field("title").String(); got != "Quarterly Invoice" {
		t.Errorf("title = %q, want Quarterly Invoice", got)
	}
	if got := v.Field("producer").String(); got != "LazaretFixtureTool" {
		t.Errorf("producer = %q, want LazaretFixtureTool", got)
	}
	if got := v.Field("page_count").String(); got != "2" {
		t.Errorf("page_count = %q, want 2", got)
	}
	if got := v.Field("author").String(); got != "A. Sender" {
		t.Errorf("author = %q, want A. Sender", got)
	}

	// The corpus compares tag names literally — `.key == "Author"` — so the canonical
	// casing exiftool uses has to survive Strelka lowercasing it.
	var keys []string
	for _, f := range v.Field("fields").Elements() {
		keys = append(keys, f.Field("key").String())
	}
	if len(keys) == 0 {
		t.Fatal("no fields")
	}
	found := false
	for _, k := range keys {
		if k == "Author" {
			found = true
		}
		if k == "sourcefile" || k == "directory" {
			t.Errorf("field %q is the scanner's own temporary path, not document metadata", k)
		}
	}
	if !found {
		t.Errorf("no Author key in %v; a lowercase key matches no rule", keys)
	}
	t.Logf("beta.parse_exif fields = %v", keys)
}

// TestLiveExplodeSurvivesAQRCode is the regression test for the decode failure that
// scanning a real QR code exposed: `cannot unmarshal array into ... StrelkaQR.scan.qr.data`
// made Explode return an error for the whole file, not just the QR section.
func TestLiveExplodeSurvivesAQRCode(t *testing.T) {
	c := liveClient(t)
	data, err := os.ReadFile("testdata/qr.png")
	if err != nil {
		t.Fatal(err)
	}
	records, err := c.Explode(context.Background(), "qr.png", data)
	if err != nil {
		t.Fatalf("exploding a QR-bearing file: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("no records")
	}
	qr := records[0].Scan.Qr
	if qr == nil || qr.Data == nil {
		t.Fatal("scan.qr.data is empty for an image that is a QR code")
	}
	if qr.URL == nil {
		t.Fatal("scan.qr.url was not derived; 86 corpus rules read .scan.qr.url.*")
	}
}
