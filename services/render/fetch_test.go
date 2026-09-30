// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsPublicRefusesInternalAddresses(t *testing.T) {
	for _, bad := range []string{
		"127.0.0.1", "::1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", // cloud metadata — the classic SSRF target
		"100.64.0.1",      // CGNAT, where a container's neighbours live
		"0.0.0.0", "224.0.0.1", "fe80::1", "fc00::1",
	} {
		if isPublic(net.ParseIP(bad)) {
			t.Errorf("%s accepted as public", bad)
		}
	}
	for _, good := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"} {
		if !isPublic(net.ParseIP(good)) {
			t.Errorf("%s refused although it is public", good)
		}
	}
}

// A page with a non-ASCII capital must not crash the heuristic.
//
// It did: strings.ToLower('İ') is two runes, so the lowercased copy of the DOM was
// longer than the DOM, and visibleTextLen walks both with one index. A single
// Turkish capital I in 400KB of markup panicked the whole request with
// "slice bounds out of range [401713:401712]", and because it happened inside an
// HTTP handler it took the connection with it.
func TestHeuristicsSurviveNonASCII(t *testing.T) {
	// Every rune whose lowercase form is a different number of bytes.
	for _, r := range []string{"İ", "İ", "ẞ", "Σ", "ǅ", "Ⅷ"} {
		dom := `<html><head><title>` + strings.Repeat(r, 500) +
			`</title></head><body><p>` + strings.Repeat("text "+r, 500) +
			`</p><script>var x=1</script><style>p{color:red}</style></body></html>`

		// Each of these walks the document; none may panic or run off the end.
		if n := visibleTextLen(dom); n <= 0 {
			t.Errorf("%q: visibleTextLen returned %d", r, n)
		}
		_ = browserReason(dom)
		_ = navigatesInInlineScript(dom)
	}
}

// asciiLower has to be length-preserving, which is the whole reason it exists.
func TestASCIILowerPreservesLength(t *testing.T) {
	for _, s := range []string{
		"", "plain", "<SCRIPT>", "İstanbul", "ẞ", "ΣΣΣ", "<DIV>Ünïcøde</DIV>",
	} {
		got := asciiLower(s)
		if len(got) != len(s) {
			t.Errorf("asciiLower(%q) is %d bytes, input is %d", s, len(got), len(s))
		}
	}
	if got := asciiLower("<SCRIPT SRC=x>"); got != "<script src=x>" {
		t.Errorf("asciiLower did not fold ASCII: %q", got)
	}
	// Non-ASCII is left exactly as it was, so nothing can fold *into* "script".
	if got := asciiLower("İ"); got != "İ" {
		t.Errorf("asciiLower changed a non-ASCII rune: %q", got)
	}
}

// A panic in a handler must become a 502, not a closed connection.
//
// The engine cannot tell a dropped connection from the renderer being down, so
// without this one malformed page reports the whole screenshot capability as
// unavailable and every rule needing it goes indeterminate.
func TestPanicBecomesBadGateway(t *testing.T) {
	boom := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("a page did something unexpected")
	})
	srv := httptest.NewServer(recoverPanics(boom))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("the connection was dropped rather than answered: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

// The link path does not announce itself as a robot.
//
// Cloaking is in every phishing kit worth the name: serve a benign page to anything that
// looks like a scanner, serve the credential form to everyone else. A visit that says
// HeadlessChrome gets the benign page, and the result is a clean verdict on a page the
// victim saw differently — which is the worst outcome this service can produce, because
// it looks like an answer.
func TestTheLinkPathDoesNotAnnounceItselfAsARobot(t *testing.T) {
	id := testIdentity()
	for _, s := range []string{id.UserAgent, id.SecCHUA} {
		for _, tell := range []string{"Headless", "headless", "bot", "Bot", "Lazaret", "scanner"} {
			if strings.Contains(s, tell) {
				t.Errorf("%q contains %q", s, tell)
			}
		}
	}
	// A browser string that is not one.
	if !strings.HasPrefix(id.UserAgent, "Mozilla/5.0") {
		t.Errorf("user agent does not look like a browser: %q", id.UserAgent)
	}
}

// The HTTP client and the browser present as the same client.
//
// They visit the same URL milliseconds apart. Presenting as two different clients is
// both a signal in itself and a way to get two different pages, where the one that
// reaches the rules is whichever answered second.
func TestBothHalvesOfAVisitAgreeOnWhoTheyAre(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Both halves are handed the same browserIdentity — the HTTP client through
	// Fetcher.Identity, the browser through chromedp.UserAgent and identify(). This
	// pins that they read the same fields rather than re-deriving them.
	id := testIdentity()
	req.Header.Set("User-Agent", id.UserAgent)

	if req.Header.Get("User-Agent") != id.UserAgent {
		t.Error("the HTTP client and the browser no longer share a user agent")
	}
	if !strings.Contains(id.SecCHUA, "Chromium") {
		t.Errorf("Sec-CH-UA does not match the claimed browser: %q", id.SecCHUA)
	}
}

// The browser is not allowed to throw away evidence we already had.
//
// It makes its own request, so it can be shown a different page from the one the HTTP
// client was shown — cloaked, challenged, or refused for what it says it is. Measured on
// a real link: 127,760 bytes of a genuine login page served, 28,500 back from the
// browser, and without this that fifth is what reached the rules.
func TestABrowserThatWasTurnedAwayDoesNotReplaceTheServedPage(t *testing.T) {
	served := strings.Repeat("<div>real login form</div>", 5000)

	cases := []struct {
		name     string
		rendered string
		want     string
	}{
		{"script built more, which is why the browser runs",
			served + strings.Repeat("<input type=password>", 100), served + strings.Repeat("<input type=password>", 100)},
		{"about the same, so the browser's is the fresher",
			strings.Repeat("<div>real login form</div>", 4800), strings.Repeat("<div>real login form</div>", 4800)},
		{"a fifth of it, which is what being cloaked looks like",
			strings.Repeat("<div>nothing here</div>", 200), served},
		{"nothing at all", "", served},
	}
	for _, c := range cases {
		got := keepBetterDOM(served, c.rendered, "https://example.test/login")
		if got != c.want {
			t.Errorf("%s: kept %d bytes, want %d", c.name, len(got), len(c.want))
		}
	}

	// With nothing served, whatever the browser found is all there is.
	if got := keepBetterDOM("", "<html>built</html>", "https://example.test/"); got != "<html>built</html>" {
		t.Errorf("with no served HTML the browser's result was discarded: %q", got)
	}
}
