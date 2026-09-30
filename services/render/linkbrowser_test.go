// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An operator may give the HTTP base of a CDP server, not only the websocket URL.
//
// Every one of these engines advertises its websocket endpoint at /json/version and
// prints an http:// address in its own start-up log, so that is what an operator will
// paste. Requiring them to find the ws:// form by hand would be a needless way to fail.
func TestTheLinkBrowserEndpointCanBeAnHTTPBase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/json/version" {
			t.Errorf("asked for %s, want /json/version", r.URL.Path)
		}
		fmt.Fprint(w, `{"Browser":"Obscura/0.2.3","webSocketDebuggerUrl":"ws://example.test/devtools/browser/abc"}`)
	}))
	defer srv.Close()

	got, err := resolveCDPEndpoint(srv.URL, nil)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if got != "ws://example.test/devtools/browser/abc" {
		t.Errorf("resolved to %q", got)
	}
}

// A websocket URL is taken as given, without a round trip.
func TestAWebsocketEndpointIsUsedDirectly(t *testing.T) {
	for _, in := range []string{
		"ws://obscura:9222/devtools/browser/x",
		"wss://elsewhere.test/devtools/browser/y",
	} {
		got, err := resolveCDPEndpoint(in, nil)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != in {
			t.Errorf("%s was rewritten to %s", in, got)
		}
	}
}

// A misconfigured endpoint fails at start-up, not on the first message.
//
// The engine calls this once when the flag is parsed, and main treats a failure as
// fatal. Quietly falling back to starting a local Chromium would give a deployment
// twice the memory it budgeted for with nothing saying why.
func TestABadLinkBrowserEndpointIsRefused(t *testing.T) {
	if _, err := resolveCDPEndpoint("", nil); err == nil {
		t.Error("an empty endpoint was accepted")
	}

	// Answers, but not with a CDP endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"Browser":"something else"}`)
	}))
	defer srv.Close()
	if _, err := resolveCDPEndpoint(srv.URL, nil); err == nil {
		t.Error("a server with no websocketDebuggerUrl was accepted")
	}

	// Refuses outright.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer down.Close()
	if _, err := resolveCDPEndpoint(down.URL, nil); err == nil {
		t.Error("a 500 from /json/version was accepted")
	}
}

// A page that misbehaves must not take the whole browser out of the path.
//
// The two failures look alike from a caller and mean opposite things. If a hostile page
// that hangs were treated as "the engine is gone", one such link would stop every other
// link in the deployment being visited for the backoff window — which is a denial of
// service an attacker can trigger by putting a slow page in an email.
func TestOnlyATransportFailureTakesTheBrowserDown(t *testing.T) {
	transport := []string{
		"dial tcp 10.0.0.5:9222: connect: connection refused",
		"read tcp: connection reset by peer",
		"websocket: close 1006 (abnormal closure)",
		"lookup obscura: no such host",
		"unexpected EOF",
	}
	for _, e := range transport {
		if !isTransportFailure(fmt.Errorf("%s", e)) {
			t.Errorf("%q was not recognised as the browser being gone", e)
		}
	}

	page := []string{
		"context deadline exceeded",
		"could not navigate to page: net::ERR_NAME_NOT_RESOLVED",
		"encountered an exception evaluating script",
		"Page.navigate: timeout waiting for initial target",
	}
	for _, e := range page {
		if isTransportFailure(fmt.Errorf("%s", e)) {
			t.Errorf("%q would take the browser out of the path for every other link", e)
		}
	}
}

// Concurrency is bounded, the same as it is for a local browser.
//
// A lightweight engine is cheap per page, not free. Link analysis fans out across every
// link in a message, so without a bound one message can put thirty pages into one
// process at once.
func TestTheRemoteBrowserBoundsConcurrency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"webSocketDebuggerUrl":"ws://example.test/devtools/browser/abc"}`)
	}))
	defer srv.Close()

	rb, err := newRemoteBrowser("link", srv.URL, "", 4)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	if rb.Tabs() != 4 {
		t.Errorf("bound is %d, want 4", rb.Tabs())
	}

	// Zero would mean an unbuffered channel, which is not "unbounded" but
	// "deadlocked on the first visit".
	rb0, err := newRemoteBrowser("link", srv.URL, "", 0)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	if rb0.Tabs() < 1 {
		t.Errorf("a bound of %d would never admit a visit", rb0.Tabs())
	}
}

// While the endpoint is known to be down, visits fail fast instead of dialling.
//
// A deployment whose link browser has gone away should pay one dial per window, not one
// per link. Thirty links in a message against a dead endpoint is thirty connection
// timeouts inside the analysis budget, which turns one missing container into every
// message timing out.
func TestADeadLinkBrowserFailsFastRatherThanPerLink(t *testing.T) {
	rb := &remoteBrowser{
		endpoint: "ws://gone.test/x",
		client:   newCDPClient("ws://gone.test/x", nil),
		tabs:     make(chan struct{}, 2),
	}
	rb.failed(fmt.Errorf("connection refused"))

	if !rb.backingOff() {
		t.Fatal("a failed endpoint is dialled again immediately")
	}
	_, err := rb.DOM(t.Context(), time.Second, "https://example.test/")
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("a visit during the backoff window returned %v", err)
	}
}
