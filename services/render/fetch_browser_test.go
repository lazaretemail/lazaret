// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"
)

// The browser is ~9x the cost of the fetch it follows, so the decision to launch
// one has to mean something. The old test — "does the DOM contain <script>" —
// measured out at 93% of real links, which is not a decision.
func TestOrdinaryPagesDoNotNeedTheBrowser(t *testing.T) {
	// A real article: plenty of text, and script for analytics that changes nothing.
	page := `<html><head><title>Quarterly update</title>
<script src="https://cdn.example/analytics.js"></script>
<script>window.dataLayer=window.dataLayer||[];</script></head>
<body><h1>Quarterly update</h1>` +
		strings.Repeat("<p>The board met on Tuesday and agreed the revised figures for the quarter.</p>", 6) +
		`</body></html>`

	if rewritesItself(page) {
		t.Error("a text page with analytics was sent to the browser; that is the 93% case")
	}
}

// What the browser is actually for.
func TestPagesThatRewriteThemselvesNeedTheBrowser(t *testing.T) {
	body := strings.Repeat("<p>Please wait while we redirect you to your document.</p>", 8)

	cases := map[string]string{
		"meta refresh":     `<html><head><meta http-equiv="refresh" content="0;url=https://elsewhere.test/"></head><body>` + body + `</body></html>`,
		"location.href":    `<html><body>` + body + `<script>location.href="https://elsewhere.test/"</script></body></html>`,
		"location.replace": `<html><body>` + body + `<script>window.location.replace("https://elsewhere.test/")</script></body></html>`,
	}
	for name, page := range cases {
		if !rewritesItself(page) {
			t.Errorf("%s: a page that navigates itself must be run; that is how a kit hides its destination", name)
		}
	}
}

// An SPA shell says nothing until something runs it.
func TestEmptyShellNeedsTheBrowser(t *testing.T) {
	shell := `<html><head><title>App</title><script src="/static/bundle.js"></script></head>` +
		`<body><div id="root"></div></body></html>`
	if !rewritesItself(shell) {
		t.Error("a shell with no readable text was not sent to the browser")
	}

	// Padding the shell with script must not make it look like a document: script
	// contents are not text a reader sees.
	padded := `<html><body><div id="root"></div><script>` +
		strings.Repeat("var x=1;/* filler filler filler */", 200) + `</script></body></html>`
	if !rewritesItself(padded) {
		t.Error("script contents were counted as readable text")
	}
}

// A page with no markup at all is still a document if it says something.
func TestPlainTextishPageIsNotRun(t *testing.T) {
	page := "<html><body>" + strings.Repeat("Thank you for your order. Your receipt is below. ", 12) + "</body></html>"
	if rewritesItself(page) {
		t.Error("a plain page with real text was sent to the browser")
	}
}

// The first attempt at this failed in a way worth pinning down: it searched the
// whole document, so any page carrying a bundled framework matched `window.location`
// and went to the browser anyway. Browser usage moved 93% -> 91%.
func TestBundledFrameworkIsNotMistakenForARedirect(t *testing.T) {
	bundle := strings.Repeat("function n(e){return window.location.pathname+e}var q=1;", 80)
	page := `<html><head><script src="/static/app.bundle.js"></script>` +
		`<script>` + bundle + `</script></head><body>` +
		strings.Repeat("<p>Your invoice for September is attached and due on the first.</p>", 8) +
		`</body></html>`

	if rewritesItself(page) {
		t.Error("a page with a framework bundle was treated as a redirect; this is the 91% case")
	}
}

// And the stub it must still catch.
func TestShortInlineRedirectStubIsCaught(t *testing.T) {
	page := `<html><body>` +
		strings.Repeat("<p>One moment while we take you to the secure document portal.</p>", 8) +
		`<script>setTimeout(function(){window.location.href="https://elsewhere.test/login"},1200)</script>` +
		`</body></html>`
	if !rewritesItself(page) {
		t.Error("a short inline redirect stub was not caught; that is what the browser is for")
	}
}
