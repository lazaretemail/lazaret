// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"go.opentelemetry.io/otel/trace"
	"log"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Page fetching, for ml.link_analysis.
//
// Most of what that function returns is not a model's opinion. final_dom (133 corpus
// uses), effective_url (60), redirect_history (28), unique_urls_accessed (16),
// files_downloaded (17) and screenshot (15) are all observations: follow the link and
// report what happened. Only credphish (66) needs a classifier, and it stays unavailable
// until one is configured.
//
// The split below is deliberate. Redirects, status codes and content types come from an
// ordinary HTTP client, because that is where the guards belong and a browser makes them
// hard to enforce. The final DOM and the screenshot come from Chromium, because a
// credential-harvesting page is frequently assembled by script and its served HTML shows
// nothing.
//
// # This one needs egress, and that changes the posture
//
// Screenshotting a message needs no network at all, and lazaret-render is deployed
// egress-free precisely so that analysing a message cannot tell its sender it was read.
// Following a link is the opposite: the whole point is to visit somewhere. So fetching
// is off unless -fetch is passed, and an operator turning it on is accepting that this
// container reaches the internet at addresses an attacker chose.
//
// Given that, the guards here are the load-bearing part:
//
//   - Only http and https. No file://, no data:, no gopher://.
//   - Every hop is re-resolved and checked: loopback, link-local, private, multicast,
//     unspecified and CGNAT ranges are refused. Checking only the first URL is useless
//     against a redirect to 169.254.169.254, which is the whole SSRF technique.
//   - Redirects are capped and counted, bodies are size-capped, everything is
//     time-bounded.

// maxRedirects bounds a chain. Real shorteners chain two or three times; a hundred is
// someone wasting the fetcher's time.
const maxRedirects = 10

// maxBodyBytes caps one page.
const maxBodyBytes = 16 << 20

// FetchResult is what one visit observed, shaped to fill mdm.LinkAnalysisOutput.
type FetchResult struct {
	OriginalURL     string   `json:"original_url"`
	EffectiveURL    string   `json:"effective_url"`
	RedirectHistory []string `json:"redirect_history"`
	StatusCode      int      `json:"status_code"`
	ContentType     string   `json:"content_type"`
	Retrieved       bool     `json:"retrieved"`
	FinalDOM        string   `json:"final_dom"`
	Screenshot      []byte   `json:"screenshot,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// Fetcher visits a URL and reports what it saw.
type Fetcher struct {
	Renderer *Renderer

	// Cache, when set, serves a recent identical request without refetching.
	Cache *urlCache

	// Timeout bounds the whole visit, including rendering.
	Timeout time.Duration

	// Screenshot renders the page as well as reading it. Slower, and what
	// ml.link_analysis(...).screenshot needs.
	Screenshot bool

	// Identity is what this client says it is. Zero means the default, which keeps
	// a Fetcher built in a test from having to know about any of this.
	Identity browserIdentity
}

// identity returns the configured identity, or the default one.
func (f *Fetcher) identity() browserIdentity {
	if f.Identity.UserAgent != "" {
		return f.Identity
	}
	id, _ := newIdentity(PlatformLinux, "")
	return id
}

func (f *Fetcher) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	// Ten seconds, not forty-five.
	//
	// Every link in a message is fetched separately, so this multiplies: the old
	// default meant a message with three dead links took over two minutes, and four
	// of the six real phishing samples in the rule corpus timed out entirely. A
	// credential-harvesting page that has not answered in ten seconds is not going
	// to, and "did not retrieve" is a finding the rules can read.
	return 10 * time.Second
}

// Fetch follows a URL and reports the result. A failure to retrieve is part of the
// result rather than an error: "this link did not resolve" is a finding about the
// message, and rules read `.retrieved`.
// Fetch retrieves a link, serving a recent identical request from the cache.
func (f *Fetcher) Fetch(ctx context.Context, raw string) (*FetchResult, error) {
	ctx, span := renderTracer.Start(ctx, "fetch.link")
	defer span.End()
	started := time.Now()

	if f.Cache == nil {
		res, err := f.fetchUncached(ctx, raw, span)
		recordFetch(ctx, span, started, false)
		return res, err
	}

	var inner error
	res, err, hit := f.Cache.Do(raw, func() (*FetchResult, error) {
		out, e := f.fetchUncached(ctx, raw, span)
		inner = e
		return out, e
	})
	_ = inner
	recordFetch(ctx, span, started, hit)
	return res, err
}

// FetchFresh retrieves a link without consulting any cache, and without populating
// one.
//
// For the caller asking "has this changed since we last looked" — a re-visit of a link
// that was in mail delivered hours ago. A cached answer would make that question
// unanswerable: the cache exists precisely to return what was seen before, which is the
// one thing a re-visit must not do. Nor is the result stored, because a re-visit is not
// evidence about what the message carried at the time.
func (f *Fetcher) FetchFresh(ctx context.Context, raw string) (*FetchResult, error) {
	ctx, span := renderTracer.Start(ctx, "fetch.link.fresh")
	defer span.End()
	started := time.Now()
	res, err := f.fetchUncached(ctx, raw, span)
	recordFetch(ctx, span, started, false)
	return res, err
}

// recordFetch puts the outcome on the span and into the metrics.
func recordFetch(ctx context.Context, span trace.Span, started time.Time, hit bool) {
	span.SetAttributes(
		attribute.Bool("lazaret.fetch.cached", hit),
		attribute.Int64("lazaret.fetch.total_ms", time.Since(started).Milliseconds()),
	)
	attrs := metric.WithAttributes(attribute.Bool("lazaret.fetch.cached", hit))
	metricFetches.Add(ctx, 1, attrs)
	metricFetchDuration.Record(ctx, time.Since(started).Seconds(), attrs)
}

// fetchUncached does the work: the HTTP request, and the browser when the served
// bytes cannot answer on their own.
func (f *Fetcher) fetchUncached(ctx context.Context, raw string, span trace.Span) (*FetchResult, error) {
	httpStart := time.Now()
	var httpDone time.Duration
	usedBrowser := false
	reason := ""
	defer func() {
		span.SetAttributes(
			attribute.Bool("lazaret.fetch.browser", usedBrowser),
			attribute.String("lazaret.fetch.browser_reason", reason),
			attribute.Int64("lazaret.fetch.http_ms", httpDone.Milliseconds()),
		)
	}()

	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("fetch: unparsable url: %w", err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("fetch: refusing scheme %q", target.Scheme)
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	out := &FetchResult{OriginalURL: target.String(), EffectiveURL: target.String()}

	client := &http.Client{
		Transport: guardedTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			out.RedirectHistory = append(out.RedirectHistory, req.URL.String())
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	// The same thing the browser presents, for the reason in identity.go: the two
	// halves visit the same URL milliseconds apart, and presenting as two different
	// clients is both a signal and a way to be shown two different pages.
	id := f.identity()
	req.Header.Set("User-Agent", id.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	// Real Chrome sends these, and a client claiming to be Chrome without them is
	// answering the question it was trying not to raise.
	req.Header.Set("Sec-CH-UA", id.SecCHUA)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", id.Platform)
	req.Header.Set("Accept-Language", id.AcceptLanguageHeader())

	resp, err := client.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out, nil
	}
	defer resp.Body.Close()

	out.Retrieved = true
	out.StatusCode = resp.StatusCode
	out.ContentType = resp.Header.Get("Content-Type")
	out.EffectiveURL = resp.Request.URL.String()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		out.Error = err.Error()
		return out, nil
	}
	out.FinalDOM = string(body)

	// Chromium re-fetches and runs the page, and its DOM replaces the served HTML,
	// because a phishing kit that builds its form in script serves a page with no
	// form in it.
	//
	// It is also, by a wide margin, the most expensive thing here: a browser launch
	// costs one to ten seconds where the HTTP request above costs two hundred
	// milliseconds. A message with nine links was paying for eighteen launches — one
	// to dump the DOM and one to screenshot, for every link — and spending a minute
	// and a half doing it. So the browser runs when it can change the answer, and
	// only then, and when it runs it runs once.
	httpDone = time.Since(httpStart)
	if f.Renderer != nil && f.needsBrowser(out) {
		usedBrowser = true
		reason = f.browserReasonFor(out)
		f.Renderer.visit(ctx, out, f.Screenshot)
	}
	return out, nil
}

// needsBrowser reports whether running the page can tell us anything the response
// already has.
//
// Two cases where it cannot, and both are common. A response that is not HTML has no
// DOM to build — a tracking link redirecting to a PDF, an image, a JSON endpoint or a
// 404 body. And HTML with no script in it cannot construct anything: what was served
// is what a browser would show, so parsing the served bytes gives the same answer for
// a thousandth of the cost.
//
// Deliberately conservative. Anything uncertain — an unreadable content type, an empty
// body, a page with a single inline script — goes to the browser.
func (f *Fetcher) needsBrowser(res *FetchResult) bool {
	if f.Screenshot {
		// A picture is of the rendered page by definition, so there is no
		// shortcut when one was asked for.
		return true
	}
	if !res.Retrieved || res.FinalDOM == "" {
		return false
	}
	if ct := res.ContentType; ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err == nil && mt != "text/html" && mt != "application/xhtml+xml" {
			return false
		}
	}
	return rewritesItself(res.FinalDOM)
}

// rewritesItself reports whether running the page could plausibly show something
// the served bytes do not already show.
//
// This used to be `contains "<script>"`, which measured out at 93% of real links
// and made the browser ~9x the cost of the fetch it was meant to only sometimes
// follow. Practically every page on the web carries script — analytics, a cookie
// banner, a framework bundle — and none of that changes what the page says. The
// question is not whether a page *has* script; it is whether the page *is* script.
//
// Three things justify the browser, and the first two are what phishing actually
// uses:
//
//   - a redirect performed by the page rather than by HTTP, which is how a kit
//     keeps the real destination out of the headers;
//   - a body that is mostly markup and barely any text, the shape of an SPA shell
//     or a loader that paints its content in afterwards;
//   - a document with no readable text at all, where there is nothing to analyse
//     unless something runs.
//
// Anything uncertain still goes to the browser. Being wrong in the cheap direction
// means missing a cloaked page; the guard is that the cases below are the ones
// cloaking needs.
func rewritesItself(dom string) bool { return browserReason(dom) != "" }

// browserReason names why a page needs running, or "" when it does not.
func browserReason(dom string) string {
	lower := asciiLower(dom)

	// A meta refresh is unambiguous: the document asks to be replaced.
	for _, marker := range []string{
		"http-equiv=\"refresh\"", "http-equiv='refresh'", "http-equiv=refresh",
	} {
		if strings.Contains(lower, marker) {
			return "meta-refresh"
		}
	}

	// Navigation from script, but only where a redirect actually lives.
	//
	// Searching the whole document for `location.href` matched almost everything,
	// because every bundled framework contains it — the first version of this
	// check moved browser usage from 93% to 91%, which is to say it did nothing.
	// A redirect kit is a short inline stub; a React bundle is neither short nor
	// inline. Looking only inside small inline scripts is what separates them.
	if navigatesInInlineScript(dom) {
		return "inline-navigation"
	}

	// A shell rather than a document: lots of markup, almost no words.
	text := visibleTextLen(dom)
	if text < minServedText {
		return "no-text"
	}
	if len(dom) > 0 && float64(text)/float64(len(dom)) < minTextRatio {
		return "thin-text"
	}
	return ""
}

// navigatesInInlineScript looks for a self-navigation inside a short inline script.
func navigatesInInlineScript(dom string) bool {
	lower := asciiLower(dom)
	i := 0
	for {
		open := strings.Index(lower[i:], "<script")
		if open < 0 {
			return false
		}
		open += i
		gt := strings.IndexByte(lower[open:], '>')
		if gt < 0 {
			return false
		}
		tag := lower[open : open+gt]
		bodyStart := open + gt + 1
		end := strings.Index(lower[bodyStart:], "</script>")
		if end < 0 {
			return false
		}
		body := lower[bodyStart : bodyStart+end]
		i = bodyStart + end + len("</script>")

		// An external script is the framework, not the stub.
		if strings.Contains(tag, "src=") {
			continue
		}
		if len(body) > maxStubScript {
			continue
		}
		for _, marker := range []string{
			"location.href", "location.replace", "location.assign",
			"window.location", "document.location", "location=",
		} {
			if strings.Contains(body, marker) {
				return true
			}
		}
	}
}

const (
	// maxStubScript is how long an inline script can be and still look like a
	// redirect stub rather than application code.
	maxStubScript = 2048

	// minServedText is how little readable text makes a page suspicious on its own.
	// A real page that says anything says more than this.
	minServedText = 200

	// minTextRatio is text as a fraction of served bytes. An SPA shell is almost
	// all scaffolding; a document that anyone reads is not.
	minTextRatio = 0.02
)

// visibleTextLen approximates how much readable text the served bytes contain,
// ignoring the contents of script and style elements.
func visibleTextLen(dom string) int {
	lower := asciiLower(dom)
	var n, i int
	for i < len(dom) {
		switch {
		case strings.HasPrefix(lower[i:], "<script"):
			i = skipElement(lower, i, "</script>")
		case strings.HasPrefix(lower[i:], "<style"):
			i = skipElement(lower, i, "</style>")
		case dom[i] == '<':
			if end := strings.IndexByte(dom[i:], '>'); end >= 0 {
				i += end + 1
			} else {
				i = len(dom)
			}
		default:
			if !isSpace(dom[i]) {
				n++
			}
			i++
		}
	}
	return n
}

// asciiLower folds A-Z and nothing else, so the result is byte-for-byte the same
// length as its input.
//
// strings.ToLower is not, and that cost a panic in production: 'İ' (U+0130) folds
// to two runes, so on a page containing one the lowercased copy was longer than
// the original, and visibleTextLen — which walks both with the same index —
// indexed past the end. "slice bounds out of range [401713:401712]", from a single
// Turkish capital I somewhere in 400KB of markup.
//
// Folding only ASCII is also the more correct reading. Every tag name being looked
// for here is ASCII by definition, and Unicode folding can only add ways for a
// non-ASCII byte sequence to turn into the letters "script".
func asciiLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

func skipElement(lower string, from int, closing string) int {
	if end := strings.Index(lower[from:], closing); end >= 0 {
		return from + end + len(closing)
	}
	return len(lower)
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// visit runs the page once, taking the DOM and optionally a picture from the same
// browser rather than starting a second one for the second answer.
func (r *Renderer) visit(ctx context.Context, res *FetchResult, wantShot bool) {
	if !wantShot {
		if dom, err := r.DumpDOM(ctx, res.EffectiveURL); err == nil && dom != "" {
			res.FinalDOM = keepBetterDOM(res.FinalDOM, dom, res.EffectiveURL)
		}
		return
	}

	dir, err := tempDir()
	if err != nil {
		return
	}
	defer removeAll(dir)

	shot := filepath.Join(dir, "shot.png")
	dom, err := r.run(ctx, res.EffectiveURL, "--dump-dom", "--screenshot="+shot)
	if err != nil {
		return
	}
	if len(dom) > 0 {
		res.FinalDOM = keepBetterDOM(res.FinalDOM, string(dom), res.EffectiveURL)
	}
	if png, err := readFile(shot); err == nil && len(png) > 0 {
		res.Screenshot = png
	}
}

// keepBetterDOM decides whether the browser's document replaces the served one.
//
// The browser normally wins, and that is the whole reason it runs: a phishing kit that
// builds its form in script serves a page with no form in it, so what script produced is
// the thing worth reading.
//
// But it can lose, and quietly. The browser makes its own request, so it can be shown a
// different page from the one the HTTP client was shown — cloaked, challenged, or simply
// refused because of what it says it is. Measured on a real link: the HTTP client
// received 127,760 bytes of a genuine login page and the browser came back with 28,500,
// and without this that fifth is what reached the rules. Evidence already in hand was
// being thrown away for less.
//
// So a browser result that is substantially smaller than what was served is treated as
// the browser having been turned away rather than as the truth about the page. It is a
// crude test and deliberately so: the alternative is trusting whichever answered second.
func keepBetterDOM(served, rendered, url string) string {
	if rendered == "" {
		return served
	}
	if len(served) > 0 && len(rendered)*2 < len(served) {
		log.Printf("lazaret-render: keeping the served HTML for %s — the browser returned "+
			"%d bytes against %d served, which is what being cloaked or refused looks "+
			"like rather than what the page says",
			url, len(rendered), len(served))
		return served
	}
	return rendered
}

// guardedTransport refuses to connect to anything that is not a public address.
//
// The check is in DialContext rather than on the URL, so it applies to every hop of a
// redirect chain and to the address actually connected to. A hostname that resolves to
// 127.0.0.1, or a redirect to the cloud metadata service at 169.254.169.254, is the
// whole SSRF technique, and checking only the URL the caller passed catches neither.
func guardedTransport() http.RoundTripper {
	// Each phase has to fit inside the per-fetch budget above, or the budget is
	// decorative: 10 + 15 + 20 could spend 45 seconds on one unresponsive host.
	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 4 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !isPublic(ip.IP) {
					return nil, fmt.Errorf("refusing to connect to non-public address %s", ip.IP)
				}
			}
			// Dial the address that was checked, not the name, so nothing can change
			// between the check and the connection.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		DisableKeepAlives:     true,
		MaxIdleConns:          10,
	}
}

// isPublic reports whether an address is one the internet routes to someone else.
func isPublic(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	// 100.64.0.0/10, carrier-grade NAT. Not covered by IsPrivate and routinely where a
	// container's neighbours live.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	return true
}

// DumpDOM renders a URL and returns the DOM after script has run.
func (r *Renderer) DumpDOM(ctx context.Context, target string) (string, error) {
	out, err := r.run(ctx, target, "--dump-dom")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ScreenshotURL renders a URL to a PNG.
func (r *Renderer) ScreenshotURL(ctx context.Context, target string) ([]byte, error) {
	dir, err := tempDir()
	if err != nil {
		return nil, err
	}
	defer removeAll(dir)

	shot := filepath.Join(dir, "shot.png")
	if _, err := r.run(ctx, target, "--screenshot="+shot); err != nil {
		return nil, err
	}
	return readFile(shot)
}

// run invokes Chromium against a URL with the same hardening as a local render.
// settleBudget is how long a fetched page is given to finish building itself.
//
// Chromium's --virtual-time-budget is a hard wait: the browser sits there until the
// budget is spent, whether or not the page finished in the first two hundred
// milliseconds. At the eight seconds this used to be, every link in every message
// cost eight seconds of doing nothing — 66 of the 20 seconds one real message took,
// across nine links.
//
// Two seconds is enough for a page to run its scripts and settle. What it gives up is
// a page that deliberately stalls, and a phishing kit that waits two seconds before
// building its form is a page whose served HTML already looks suspicious for other
// reasons.
var settleBudget = 2000

func (r *Renderer) run(ctx context.Context, target string, extra ...string) ([]byte, error) {
	// A tab in the running link browser, when there is one and the job is a plain
	// DOM dump. This is the hot path: about thirty-eight of these per message, and
	// each used to be a whole process.
	if r.Hosts != nil && r.Hosts.web != nil && !wantsScreenshot(extra) {
		dom, err := r.domInTab(ctx, target)
		if err == nil {
			return []byte(dom), nil
		}
		if pageFault(err) {
			return nil, err
		}
		log.Printf("render: tab fetch of %s failed (%v); falling back to a process", target, err)
	}

	// The same bound as a screenshot: this launches a browser too.
	release, err := r.Browsers.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	bin, err := r.binary()
	if err != nil {
		return nil, err
	}
	dir, err := tempDir()
	if err != nil {
		return nil, err
	}
	defer removeAll(dir)

	w, h := r.size()
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	args := []string{
		"--headless", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
		"--hide-scrollbars", "--no-first-run", "--no-default-browser-check",
		"--disable-extensions", "--disable-sync", "--disable-default-apps",
		"--disable-client-side-phishing-detection", "--disable-component-update",
		"--safebrowsing-disable-auto-update", "--metrics-recording-only", "--mute-audio",
		"--user-data-dir=" + filepath.Join(dir, "profile"),
		"--crash-dumps-dir=" + filepath.Join(dir, "crash"),
		"--window-size=" + strconv.Itoa(w) + "," + strconv.Itoa(h),
		"--virtual-time-budget=" + strconv.Itoa(settleBudget),
	}
	args = append(args, extra...)
	args = append(args, target)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"HOME=" + dir, "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("render: timed out")
		}
		return nil, fmt.Errorf("render: chromium: %w", err)
	}
	return out, nil
}

// browserReasonFor names why this response needed the browser, for telemetry.
func (f *Fetcher) browserReasonFor(res *FetchResult) string {
	if f.Screenshot {
		return "screenshot-requested"
	}
	if !res.Retrieved || res.FinalDOM == "" {
		return "no-body"
	}
	if ct := res.ContentType; ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err == nil && mt != "text/html" && mt != "application/xhtml+xml" {
			return "not-html"
		}
	}
	return browserReason(res.FinalDOM)
}

// wantsScreenshot reports whether these arguments ask for an image, which the tab
// path does not serve — the caller wants a file written by the process.
func wantsScreenshot(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "--screenshot") {
			return true
		}
	}
	return false
}

// domInTab loads a page in the link browser and returns the rendered DOM.
func (r *Renderer) domInTab(ctx context.Context, target string) (string, error) {
	return r.Hosts.web.DOM(ctx, r.timeout(), target)
}

// Waiting on readyState instead of the load event was tried here and reverted.
//
// The hypothesis was that an external engine which never fires load would hang this
// path until the render timeout, which is exactly what obscura did on five of the ten
// links in one real marketing email — 155 seconds against Chromium's 12. Polling
// readyState fixed none of it, because the cause is not the load event: chromedp and
// obscura disagree about session bookkeeping, and the run never gets as far as
// navigating. It also cost Chromium four seconds over the same ten links. Recorded so
// the next person does not spend the afternoon on it twice.

// settleFor is how long a page gets to finish painting before its DOM is taken.
const settleFor = 1500 * time.Millisecond
