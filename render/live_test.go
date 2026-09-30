// SPDX-License-Identifier: AGPL-3.0-only

package render_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/render"
	"github.com/lazaretemail/lazaret/strelka"
)

// Live tests against a real lazaret-render.
//
//	docker compose -f deploy/compose/docker-compose.yml up -d --build render
//	LAZARET_RENDER=http://localhost:8710 go test ./render/ -run Live -v
func liveClient(t *testing.T) *render.Client {
	t.Helper()
	addr := os.Getenv("LAZARET_RENDER")
	if addr == "" {
		t.Skip("set LAZARET_RENDER to a lazaret-render base URL to run this")
	}
	return render.New(&render.Options{Address: addr})
}

// messageWithHTML is the shape the evaluator hands a zero-argument capability: the
// message itself, because `file.message_screenshot()` names no input.
func messageWithHTML(html string) []mql.Value {
	return []mql.Value{mql.FromGo(&mdm.MessageDataModel{
		Subject: &mdm.Subject{Subject: mdm.Ptr("Invoice")},
		Body:    &mdm.Body{HTML: &mdm.BodyHTML{Raw: mdm.Ptr(html)}},
	})}
}

func TestLiveMessageScreenshot(t *testing.T) {
	c := liveClient(t)
	v, err := c.Enrich(context.Background(), enrich.CapFileMessageScreenshot,
		messageWithHTML(`<html><body><h1>Hello</h1></body></html>`), nil)
	if err != nil {
		t.Fatalf("file.message_screenshot: %v", err)
	}
	if v.IsNull() {
		t.Fatal("null screenshot for a message with an HTML body")
	}
	raw, ok := v.Field("raw").AsBytes()
	if !ok || len(raw) == 0 {
		t.Fatal("no image bytes")
	}
	if !strings.HasPrefix(string(raw[:4]), "\x89PNG") {
		t.Errorf("not a PNG: % x", raw[:8])
	}
	t.Logf("%s, %d bytes", v.Field("file_name").String(), len(raw))
}

// A plain-text message still has a screenshot — it is what the recipient sees.
func TestLivePlainTextStillRenders(t *testing.T) {
	c := liveClient(t)
	msg := []mql.Value{mql.FromGo(&mdm.MessageDataModel{
		Body: &mdm.Body{Plain: &mdm.Plain{Raw: mdm.Ptr("wire the funds today")}},
	})}
	v, err := c.Enrich(context.Background(), enrich.CapFileMessageScreenshot, msg, nil)
	if err != nil {
		t.Fatalf("file.message_screenshot: %v", err)
	}
	if v.IsNull() {
		t.Fatal("null for a plain-text message")
	}
}

// A message with no body at all is null, not unavailable: the service is fine, there is
// simply nothing to render, the same way a message can have no attachments.
func TestLiveEmptyMessageIsNullNotUnavailable(t *testing.T) {
	c := liveClient(t)
	v, err := c.Enrich(context.Background(), enrich.CapFileMessageScreenshot,
		[]mql.Value{mql.FromGo(&mdm.MessageDataModel{})}, nil)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !v.IsNull() {
		t.Error("a message with no body produced a screenshot")
	}
}

// The chain the corpus actually writes: `beta.ocr(file.message_screenshot()).text`, 161
// calls. Rendering exists so that an attack which puts its words inside an image is
// visible to a text engine, and this is the test that the whole path delivers that.
func TestLiveScreenshotFeedsOCR(t *testing.T) {
	c := liveClient(t)
	addr := os.Getenv("LAZARET_STRELKA")
	if addr == "" {
		t.Skip("set LAZARET_STRELKA as well to exercise the render -> OCR chain")
	}
	sc, err := strelka.Dial(&strelka.Options{Address: addr})
	if err != nil {
		t.Fatalf("dialling Strelka: %v", err)
	}
	defer sc.Close()

	shot, err := c.Enrich(context.Background(), enrich.CapFileMessageScreenshot,
		messageWithHTML(`<html><body style="font-family:sans-serif;font-size:40px">
			<h1>URGENT: VERIFY YOUR ACCOUNT</h1><p>Your payment is overdue.</p>
		</body></html>`), nil)
	if err != nil {
		t.Fatalf("screenshot: %v", err)
	}

	text, err := sc.Enrich(context.Background(), enrich.CapBetaOCR, []mql.Value{shot}, nil)
	if err != nil {
		t.Fatalf("ocr: %v", err)
	}
	got := strings.ToUpper(text.Field("text").String())
	for _, want := range []string{"URGENT", "VERIFY", "ACCOUNT"} {
		if !strings.Contains(got, want) {
			t.Errorf("OCR of the rendered message %q does not contain %q", got, want)
		}
	}
	t.Logf("rendered and read back: %q", text.Field("text").String())
}

// ml.link_analysis, which is mostly a browser's job rather than a model's.
//
//	docker compose ... up -d --build render   # with -fetch
//	LAZARET_RENDER_FETCH=http://localhost:8710 go test ./render/ -run Live -v
func TestLiveLinkAnalysis(t *testing.T) {
	addr := os.Getenv("LAZARET_RENDER_FETCH")
	if addr == "" {
		t.Skip("set LAZARET_RENDER_FETCH to a lazaret-render started with -fetch")
	}
	c := render.New(&render.Options{Address: addr}).EnableLinkAnalysis()

	link := mql.FromGo(&mdm.Link{HrefURL: mdm.ParseURL("http://example.com/", true)})
	v, err := c.Enrich(context.Background(), enrich.CapMLLinkAnalysis, []mql.Value{link}, nil)
	if err != nil {
		t.Fatalf("ml.link_analysis: %v", err)
	}
	if !v.Field("retrieved").Truthy() {
		t.Fatalf("not retrieved: %s", v.Field("final_dom").Field("raw").String())
	}
	if got := v.Field("effective_url").Field("url").String(); !strings.Contains(got, "example.com") {
		t.Errorf("effective_url = %q", got)
	}
	if got := v.Field("status_code").String(); got != "200" {
		t.Errorf("status_code = %q, want 200", got)
	}
	// The text forms are what rules read: a phishing page's give-away is often wording
	// that never appears in its markup as one contiguous string.
	if got := v.Field("final_dom").Field("inner_text").String(); !strings.Contains(got, "Example Domain") {
		t.Errorf("final_dom.inner_text = %q", got)
	}
	// analyzed means "assessed for credential phishing", and nothing classified this.
	// Reporting true because a fetch succeeded would make `.analyzed and not
	// .credphish...` read as a clean verdict from a service that never looked.
	if v.Field("analyzed").Truthy() {
		t.Error("analyzed is true although no classifier ran")
	}
	if !v.Field("credphish").IsNull() {
		t.Error("credphish is populated although no classifier ran")
	}
	t.Logf("fetched %s, dom %d bytes", v.Field("effective_url").Field("url").String(),
		len(v.Field("final_dom").Field("raw").String()))
}

// The guard that matters most: this service makes outbound requests to addresses an
// attacker chose, and a redirect to the cloud metadata endpoint is the whole technique.
func TestLiveLinkAnalysisRefusesInternalAddresses(t *testing.T) {
	addr := os.Getenv("LAZARET_RENDER_FETCH")
	if addr == "" {
		t.Skip("set LAZARET_RENDER_FETCH to a lazaret-render started with -fetch")
	}
	c := render.New(&render.Options{Address: addr}).EnableLinkAnalysis()

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:8710/v1/health",
		"http://10.0.0.1/",
	} {
		link := mql.FromGo(&mdm.Link{HrefURL: mdm.ParseURL(target, true)})
		v, err := c.Enrich(context.Background(), enrich.CapMLLinkAnalysis, []mql.Value{link}, nil)
		if err != nil {
			continue // refused before the request, which is also correct
		}
		if v.Field("retrieved").Truthy() {
			t.Errorf("%s was retrieved; the SSRF guard did not hold", target)
		}
	}
}
