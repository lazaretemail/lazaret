// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Visiting links with something other than Chromium.
//
// # Why this is possible at all, and only here
//
// Screenshotting a message needs a browser that lays out and paints correctly, because
// the picture is fed to OCR, logo detection and a QR reader. A renderer that gets it
// wrong still produces a valid PNG, so "nothing found" comes back from a rule that
// should have said "I could not see" — the one collapse this engine refuses everywhere.
// That path stays on Chromium, and obscura fails it concretely: CJK text rasterises to
// tofu even with the fonts present.
//
// The link path is a different job wearing the same clothes. Redirects, status codes and
// content types come from an ordinary HTTP client, where the SSRF guards live. Of the
// browser, exactly one thing is asked: the document after its script has run. From that
// string, `.inner_text`, `.display_text` and `.links` are derived in Go — see
// render/linkanalysis.go. The browser is never asked what is visible, never asked for a
// picture, and its fonts are never used.
//
// So the second Chromium — the one this service starts purely to visit links — can be
// replaced by something an order of magnitude smaller without touching the part of the
// platform that depends on rendering being right.
//
// # The client, not the engine, was the hard part
//
// The first attempt drove the external engine with chromedp and was unusable: five of
// ten real links never completed and each cost the full render timeout, 155 seconds
// against Chromium's 12. The cause was chromedp's model of the browser's targets and
// sessions desynchronising, not the engine — where it completed, its DOM was identical
// to Chromium's and it was the faster of the two. So this speaks CDP directly. See
// cdp.go.
type remoteBrowser struct {
	name     string
	endpoint string

	client *cdpClient

	// tabs bounds concurrency, the same way a local host does. A lightweight engine
	// is cheap per page but not free, and link analysis fans out across every link
	// in a message.
	tabs chan struct{}

	mu sync.Mutex

	// down is when the endpoint was last found unreachable, so a dead engine costs
	// one dial per window rather than one per link. A visit that cannot reach the
	// browser is not a failure of the analysis: the served HTML is already in hand
	// from the HTTP client, and that is what the result keeps.
	down time.Time
}

// remoteDownFor is how long a failed endpoint stays out of the path.
const remoteDownFor = 30 * time.Second

// newRemoteBrowser returns a link browser backed by an external CDP endpoint.
//
// The endpoint may be the websocket URL, or the HTTP base of a CDP server — in which
// case /json/version is asked for the websocket URL, which is how every one of these
// advertises it.
//
// token, when set, is presented as `Authorization: Bearer`. Obscura requires one on any
// non-loopback bind and refuses to start without it, which is the right default for a
// port that is a remote control for a browser.
func newRemoteBrowser(name, endpoint, token string, maxTabs int) (*remoteBrowser, error) {
	if maxTabs < 1 {
		maxTabs = 1
	}
	header := http.Header{}
	if token != "" {
		header.Set("Authorization", "Bearer "+token)
	}

	ws, err := resolveCDPEndpoint(endpoint, header)
	if err != nil {
		return nil, err
	}
	return &remoteBrowser{
		name:     name,
		endpoint: ws,
		client:   newCDPClient(ws, header),
		tabs:     make(chan struct{}, maxTabs),
	}, nil
}

// resolveCDPEndpoint turns whatever an operator wrote into a websocket URL.
func resolveCDPEndpoint(endpoint string, header http.Header) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("no link browser endpoint given")
	}
	if strings.HasPrefix(endpoint, "ws://") || strings.HasPrefix(endpoint, "wss://") {
		return endpoint, nil
	}
	if !strings.Contains(endpoint, "://") {
		endpoint = "http://" + endpoint
	}

	// Asked once, at start-up, so a typo is a start-up failure rather than a
	// surprise on the first message with a link in it.
	base := strings.TrimSuffix(endpoint, "/")
	req, err := http.NewRequest(http.MethodGet, base+"/json/version", nil)
	if err != nil {
		return "", err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("asking %s for its CDP endpoint: %w", base, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s/json/version returned %s", base, resp.Status)
	}
	var v struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
		Browser              string `json:"Browser"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.WebSocketDebuggerURL == "" {
		return "", fmt.Errorf("%s/json/version did not name a websocket endpoint", base)
	}
	log.Printf("lazaret-render: link browser at %s reports itself as %q", base, v.Browser)
	return v.WebSocketDebuggerURL, nil
}

// DOM visits a URL on the remote engine and returns the document after script has run.
func (r *remoteBrowser) DOM(ctx context.Context, timeout time.Duration, url string) (string, error) {
	if r == nil {
		return "", fmt.Errorf("no link browser is configured")
	}
	select {
	case r.tabs <- struct{}{}:
		defer func() { <-r.tabs }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	if r.backingOff() {
		return "", fmt.Errorf("the link browser at %s was unreachable a moment ago", r.endpoint)
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dom, err := r.client.DOM(runCtx, url)
	if err != nil {
		// A transport failure means the engine is gone; a page-level one does not.
		// Only the first should take the endpoint out of the path, or one hostile
		// page that hangs would stop every other link being visited — a denial of
		// service an attacker triggers by putting a slow page in an email.
		if runCtx.Err() == nil && isTransportFailure(err) {
			r.failed(err)
		}
		return "", err
	}
	return dom, nil
}

// isTransportFailure distinguishes "the browser is not there" from "the page misbehaved".
func isTransportFailure(err error) bool {
	s := err.Error()
	for _, frag := range []string{
		"connection refused", "connection reset", "broken pipe", "EOF",
		"no such host", "connection lost", "use of closed network connection",
		"dialling the link browser", "websocket: close", "unexpected EOF",
	} {
		if strings.Contains(s, frag) {
			return true
		}
	}
	return false
}

func (r *remoteBrowser) backingOff() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.down.IsZero() && time.Since(r.down) < remoteDownFor
}

// failed records an unreachable endpoint and drops the connection, so the next attempt
// after the window dials again rather than reusing a dead socket.
func (r *remoteBrowser) failed(err error) {
	r.mu.Lock()
	first := r.down.IsZero() || time.Since(r.down) >= remoteDownFor
	r.down = time.Now()
	r.mu.Unlock()

	r.client.Close()

	if first {
		// Said once per window, and said plainly: this degrades link analysis, it
		// does not break it. The served HTML is already in hand from the HTTP
		// client, so what is lost is what script would have built.
		log.Printf("lazaret-render: the link browser at %s is not answering (%v); links "+
			"will be reported from their served HTML until it returns, so a page that "+
			"builds itself in script will read as empty", r.endpoint, err)
	}
}

// Close releases the connection.
func (r *remoteBrowser) Close() {
	if r == nil {
		return
	}
	r.client.Close()
}

// Tabs is the concurrency this browser allows, for the start-up log.
func (r *remoteBrowser) Tabs() int { return cap(r.tabs) }
