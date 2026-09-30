// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// What a page actually sees when the link browser visits it.
//
// Asserted against a real browser rather than against the flags we pass it, because the
// two came apart in exactly the way that matters: --user-agent covers the User-Agent
// header and leaves Sec-CH-UA built from Chromium's own brand list, so a browser told to
// claim Chrome went on announcing "Chromium" in the hints. A cloaking check does not
// need to detect a headless browser, only an inconsistent one.
func TestWhatTheLinkBrowserTellsAPage(t *testing.T) {
	if _, err := exec.LookPath("chromium"); err != nil {
		t.Skip("no chromium on PATH")
	}

	var (
		mu      sync.Mutex
		ua      string
		chUA    string
		lang    string
		platfrm string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if ua == "" {
			ua, chUA = r.Header.Get("User-Agent"), r.Header.Get("Sec-CH-UA")
			lang, platfrm = r.Header.Get("Accept-Language"), r.Header.Get("Sec-CH-UA-Platform")
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	// A non-default identity on purpose: the point is that configuration reaches the
	// wire, and asserting the default would pass even if the plumbing were ignored.
	want, err := newIdentity(PlatformWindows, "es-ES,es,en")
	if err != nil {
		t.Fatalf("building identity: %v", err)
	}
	hosts, err := newBrowserHosts(2, true, want)
	if err != nil {
		t.Fatalf("starting browsers: %v", err)
	}
	defer hosts.Close()

	if _, err := hosts.web.DOM(t.Context(), 45*time.Second, srv.URL); err != nil {
		t.Fatalf("visiting: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// The headless tell, which is the whole reason this exists.
	if strings.Contains(ua, "Headless") {
		t.Errorf("the browser announced itself as headless: %q", ua)
	}
	if ua != want.UserAgent {
		t.Errorf("user agent is %q, want %q", ua, want.UserAgent)
	}
	if !strings.Contains(ua, "Windows") {
		t.Errorf("the configured platform did not reach the wire: %q", ua)
	}
	if !strings.HasPrefix(lang, "es-ES") {
		t.Errorf("the configured language did not reach the wire: %q", lang)
	}

	// The half the flag does not reach. Real Chrome names itself here; a user agent
	// claiming Chrome beside hints that only say Chromium is a mismatch, and a
	// mismatch is what a cloaking check is looking for.
	if chUA != "" {
		if !strings.Contains(chUA, "Google Chrome") {
			t.Errorf("Sec-CH-UA does not name Chrome, so it disagrees with the user agent: %q", chUA)
		}
		if !strings.Contains(chUA, chromeMajor) {
			t.Errorf("Sec-CH-UA version does not match the user agent: %q", chUA)
		}
	}
	if platfrm != "" && !strings.Contains(platfrm, want.PlatformName) {
		t.Errorf("Sec-CH-UA-Platform is %q, want %q", platfrm, want.PlatformName)
	}
	if lang == "" {
		t.Error("no Accept-Language, which every real browser sends")
	}
	// Chromium appends its own quality values, so supplying them produced
	// "en-US,en;q=0.9;q=0.9". A malformed header is a louder signal than the one it
	// was meant to quieten. More than one weight in the list is normal — more than
	// one on a single tag is the bug.
	for _, tag := range strings.Split(lang, ",") {
		if strings.Count(tag, "q=") > 1 {
			t.Errorf("Accept-Language tag %q has duplicated quality values (%q)", tag, lang)
		}
	}
	// And Chromium's own weighting should match what the HTTP client sends, or the
	// two halves disagree on something a server can compare.
	if lang != want.AcceptLanguageHeader() {
		t.Errorf("the browser sent %q, the HTTP client would send %q",
			lang, want.AcceptLanguageHeader())
	}
	t.Logf("page saw: UA=%q Sec-CH-UA=%q platform=%q lang=%q", ua, chUA, platfrm, lang)
}

// testIdentity is the default identity, for tests that only need a valid one.
func testIdentity() browserIdentity {
	id, err := newIdentity(PlatformLinux, "en-US,en")
	if err != nil {
		panic(err)
	}
	return id
}

// An operator can ask for the recipient's language and the recipient's platform.
//
// A page served in Spanish to a Spanish-speaking recipient is a different page, and a
// deployment protecting those recipients should be shown the one they were shown.
func TestTheIdentityIsConfigurable(t *testing.T) {
	id, err := newIdentity(PlatformWindows, "es-ES,es,en")
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	if !strings.Contains(id.UserAgent, "Windows NT 10.0") {
		t.Errorf("user agent is not Windows: %q", id.UserAgent)
	}
	if id.Platform != `"Windows"` {
		t.Errorf("Sec-CH-UA-Platform is %q", id.Platform)
	}
	if got := id.AcceptLanguageHeader(); got != "es-ES,es;q=0.9,en;q=0.8" {
		t.Errorf("Accept-Language is %q", got)
	}
	// The bare form is what Chromium is given, because it appends its own weights.
	if id.AcceptLanguage != "es-ES,es,en" {
		t.Errorf("the browser would be given %q", id.AcceptLanguage)
	}
}

// Every platform is internally consistent.
//
// This is the whole reason the setting is a platform name rather than three strings: an
// operator who could set them separately could ship a browser claiming Windows in one
// header and X11/Linux in another, and a cloaking check does not need to spot a headless
// browser, only an inconsistent one.
func TestEveryPlatformAgreesWithItself(t *testing.T) {
	want := map[string]string{
		PlatformLinux:   "Linux",
		PlatformWindows: "Windows",
		PlatformMacOS:   "Mac",
	}
	for platform, token := range want {
		id, err := newIdentity(platform, "en-US,en")
		if err != nil {
			t.Fatalf("%s: %v", platform, err)
		}
		if !strings.Contains(id.UserAgent, token) {
			t.Errorf("%s: user agent %q does not mention %q", platform, id.UserAgent, token)
		}
		// The quoted hint and the metadata name the same thing.
		if id.Platform != `"`+id.PlatformName+`"` {
			t.Errorf("%s: hint %q and metadata %q disagree", platform, id.Platform, id.PlatformName)
		}
		if !strings.Contains(strings.ToLower(id.PlatformName), strings.ToLower(token[:3])) {
			t.Errorf("%s: metadata platform is %q", platform, id.PlatformName)
		}
		if id.PlatformVersion == "" || id.Arch == "" {
			t.Errorf("%s: incomplete metadata", platform)
		}
	}
}

// A platform nobody implements is refused at start-up rather than ignored.
func TestAnUnknownPlatformIsRefused(t *testing.T) {
	_, err := newIdentity("freebsd", "en-US,en")
	if err == nil {
		t.Fatal("an unimplemented platform was accepted")
	}
	// The message names the choices, because the alternative is reading the source.
	for _, p := range []string{"linux", "windows", "macos"} {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("the refusal does not mention %q: %v", p, err)
		}
	}
}

// The language list is checked, because it goes into a header verbatim.
func TestTheLanguageListIsChecked(t *testing.T) {
	for _, bad := range []string{
		"en-US\r\nX-Injected: 1", // header injection
		"en US",                  // a space is not a tag separator
		"en;q=x, <script>",
		"-en",
		"en-",
	} {
		if _, err := newIdentity(PlatformLinux, bad); err == nil {
			t.Errorf("%q was accepted as a language list", bad)
		}
	}

	// Quality values supplied by an operator are stripped rather than refused: they
	// are a reasonable thing to write, and both consumers need a different form.
	id, err := newIdentity(PlatformLinux, "fr-FR;q=1.0, fr;q=0.9, en;q=0.5")
	if err != nil {
		t.Fatalf("a list with weights was refused: %v", err)
	}
	if id.AcceptLanguage != "fr-FR,fr,en" {
		t.Errorf("weights were not stripped: %q", id.AcceptLanguage)
	}
	if got := id.AcceptLanguageHeader(); got != "fr-FR,fr;q=0.9,en;q=0.8" {
		t.Errorf("header form is %q", got)
	}
}
