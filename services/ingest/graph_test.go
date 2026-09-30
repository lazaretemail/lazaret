// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Graph cannot be tested against Microsoft from here, but the parts that actually break
// in deployments are all local: the validation handshake, the clientState check, and
// the decision to stop trusting a subscription. Those are tested; the wire format of a
// Graph response is not, because a fixture written from Microsoft's documentation would
// only confirm what the documentation says — the same trap this project has hit four
// times with Strelka.

// The validation handshake is the single most common reason a subscription cannot be
// created: Graph calls the endpoint *during* the create, before any subscription
// exists, and expects the token echoed back as text/plain.
func TestGraphValidationHandshake(t *testing.T) {
	g := &GraphSource{Addr: freePort(t), ClientState: "secret", NotificationURL: "https://example.test/graph/notify"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.serve(ctx, func(context.Context, RawMessage) (*Verdict, error) { return nil, nil })
	waitFor(t, "http://"+g.Addr+"/graph/notify")

	resp, err := http.Post("http://"+g.Addr+"/graph/notify?validationToken=abc123", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}
	if string(body) != "abc123" {
		t.Errorf("echoed %q, want abc123", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type %q, want text/plain", ct)
	}
}

// clientState is the only thing distinguishing a real notification from anyone on the
// internet who has found the endpoint.
func TestGraphRejectsAWrongClientState(t *testing.T) {
	g := &GraphSource{Addr: freePort(t), ClientState: "correct"}

	var fetched atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.serve(ctx, func(context.Context, RawMessage) (*Verdict, error) {
		fetched.Add(1)
		return &Verdict{Verdict: "clean"}, nil
	})
	waitFor(t, "http://"+g.Addr+"/graph/notify")

	payload, _ := json.Marshal(map[string]any{
		"value": []map[string]any{{
			"subscriptionId": "s1",
			"clientState":    "wrong",
			"changeType":     "created",
			"resource":       "Users/watch@lazaret.test/Messages/AAA",
			"resourceData":   map[string]string{"id": "AAA"},
		}},
	})
	resp, err := http.Post("http://"+g.Addr+"/graph/notify", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Accepted — never retried by telling Graph it failed — but not acted on.
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status %d, want 202", resp.StatusCode)
	}
	time.Sleep(300 * time.Millisecond)
	if n := fetched.Load(); n != 0 {
		t.Errorf("a notification with the wrong clientState caused %d fetches", n)
	}
}

// Graph gives seconds before it retries and then drops a subscription, and a full rule
// evaluation takes longer than that. The handler must acknowledge first and work after.
func TestGraphAcknowledgesBeforeWorking(t *testing.T) {
	g := &GraphSource{Addr: freePort(t), ClientState: "s"}

	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.serve(ctx, func(context.Context, RawMessage) (*Verdict, error) {
		<-release // a slow analysis
		return &Verdict{Verdict: "clean"}, nil
	})
	waitFor(t, "http://"+g.Addr+"/graph/notify")

	payload, _ := json.Marshal(map[string]any{
		"value": []map[string]any{{
			"clientState":  "s",
			"resource":     "Users/watch@lazaret.test/Messages/AAA",
			"resourceData": map[string]string{"id": "AAA"},
		}},
	})

	start := time.Now()
	resp, err := http.Post("http://"+g.Addr+"/graph/notify", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	elapsed := time.Since(start)
	close(release)

	if elapsed > 2*time.Second {
		t.Errorf("acknowledged after %s; Graph would have retried and then dropped the subscription", elapsed)
	}
}

// A notification updates the watchdog, which is what keeps the fallback asleep.
func TestGraphNotificationResetsTheWatchdog(t *testing.T) {
	g := &GraphSource{Addr: freePort(t), ClientState: "s"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go g.serve(ctx, func(context.Context, RawMessage) (*Verdict, error) { return nil, nil })
	waitFor(t, "http://"+g.Addr+"/graph/notify")

	before := time.Now().Add(-time.Hour)
	g.mu.Lock()
	g.lastNotif = before
	g.mu.Unlock()

	payload, _ := json.Marshal(map[string]any{"value": []map[string]any{{"clientState": "s"}}})
	resp, _ := http.Post("http://"+g.Addr+"/graph/notify", "application/json", strings.NewReader(string(payload)))
	if resp != nil {
		resp.Body.Close()
	}

	g.mu.Lock()
	after := g.lastNotif
	g.mu.Unlock()
	if !after.After(before) {
		t.Error("a notification did not reset the watchdog; the fallback would start for no reason")
	}
}

// With no notification URL there is nothing inbound to try, so polling starts straight
// away rather than after a failed subscription attempt.
func TestGraphWithoutANotificationURLPollsImmediately(t *testing.T) {
	fake := fakeGraph(t)
	defer fake.Close()

	var polled atomic.Int32
	g := &GraphSource{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		Mailboxes: []string{"watch@lazaret.test"},
		// No NotificationURL, so there is nothing inbound to try.
		PollInterval: 50 * time.Millisecond,
		GraphBase:    fake.URL,
		LoginBase:    fake.URL,
	}
	graphPolls = &polled

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go g.Run(ctx, func(context.Context, RawMessage) (*Verdict, error) { return &Verdict{Verdict: "clean"}, nil })

	time.Sleep(400 * time.Millisecond)
	if !g.isPolling() {
		t.Fatal("polling did not start although there is no notification URL")
	}
	// And it actually asked, rather than merely setting a flag.
	if polled.Load() == 0 {
		t.Error("no delta query was issued")
	}
}

// graphPolls lets the stub count delta queries for the test above.
var graphPolls *atomic.Int32

// fakeGraph answers the token endpoint and the Graph API, so the polling path can be
// exercised without Microsoft. It deliberately does not pretend to be a faithful Graph:
// it answers the two shapes this client actually parses.
func fakeGraph(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/v2.0/token"):
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fake-token", "expires_in": 3600,
			})
		case strings.Contains(r.URL.Path, "/delta"):
			if graphPolls != nil {
				graphPolls.Add(1)
			}
			json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return httptest.NewServer(mux)
}

func waitFor(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Post(url+"?validationToken=ping", "text/plain", nil)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the endpoint never started listening")
}

// Every Graph request carries a bearer token, and nextLink/deltaLink are absolute URLs
// chosen by the server. Following one to another host would hand that token to whoever
// the response named. Against real Graph this never happens; the guard exists because
// "the server told us to" is not a reason to hand out a credential.
func TestGraphRefusesAContinuationLinkToAnotherHost(t *testing.T) {
	var leaked atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
	}))
	defer attacker.Close()

	// A Graph stub whose delta response redirects the client elsewhere.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/v2.0/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "secret-token", "expires_in": 3600})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"value":           []any{},
				"@odata.nextLink": attacker.URL + "/v1.0/next",
			})
		}
	})
	hostile := httptest.NewServer(mux)
	defer hostile.Close()

	g := &GraphSource{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		Mailboxes: []string{"watch@lazaret.test"},
		GraphBase: hostile.URL, LoginBase: hostile.URL,
	}
	g.deltaLinks = map[string]string{}

	err := g.pollOnce(context.Background(), "watch@lazaret.test",
		func(context.Context, RawMessage) (*Verdict, error) { return nil, nil })
	if err == nil {
		t.Error("a continuation link to another host was accepted")
	}
	if n := leaked.Load(); n != 0 {
		t.Errorf("the bearer token was sent to another host %d times", n)
	}
}

// Removal must be a permanent delete where Graph offers one.
//
// The distinction is the whole of custody on Microsoft. A plain DELETE is a soft
// delete: the message lands in Deleted Items and the recipient pulls it straight back
// out, which means "quarantined" would be filing with extra steps. permanentDelete
// puts it in Purges, where the client cannot reach it.
func TestGraphRemovalIsPermanent(t *testing.T) {
	var permanent, soft atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/v2.0/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, "/permanentDelete") && r.Method == http.MethodPost:
			permanent.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			soft.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g := &GraphSource{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		Mailboxes: []string{"watch@example.test"},
		GraphBase: srv.URL, LoginBase: srv.URL,
	}
	if err := g.removeMessage(context.Background(), "watch@example.test", "AAMk"); err != nil {
		t.Fatalf("removing: %v", err)
	}
	if permanent.Load() != 1 {
		t.Errorf("permanentDelete called %d times, want 1", permanent.Load())
	}
	if soft.Load() != 0 {
		t.Errorf("fell back to a soft DELETE %d times when permanentDelete worked", soft.Load())
	}
}

// The sovereign clouds do not offer permanentDelete. Falling back is better than a
// connector that cannot remediate there at all — but it must be a fallback, not the
// default, and it must be announced.
func TestGraphFallsBackWherePermanentDeleteIsAbsent(t *testing.T) {
	var soft atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/v2.0/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, "/permanentDelete"):
			// What a cloud without the action returns.
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":{"code":"ResourceNotFound","message":"Resource not found"}}`))
		case r.Method == http.MethodDelete:
			soft.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g := &GraphSource{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		Mailboxes: []string{"watch@example.test"},
		GraphBase: srv.URL, LoginBase: srv.URL,
	}
	if err := g.removeMessage(context.Background(), "watch@example.test", "AAMk"); err != nil {
		t.Fatalf("removing: %v", err)
	}
	if soft.Load() != 1 {
		t.Errorf("soft DELETE called %d times, want 1", soft.Load())
	}
}

// A permissions failure must not be mistaken for an absent action.
//
// Retrying a 403 as a soft delete would silently downgrade every removal in a
// deployment whose app registration is missing Mail.ReadWrite — the connector would
// appear to work while leaving recoverable copies in every mailbox.
func TestGraphDoesNotDowngradeOnPermissionDenied(t *testing.T) {
	var soft atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/v2.0/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "t", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, "/permanentDelete"):
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}`))
		case r.Method == http.MethodDelete:
			soft.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	g := &GraphSource{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		Mailboxes: []string{"watch@example.test"},
		GraphBase: srv.URL, LoginBase: srv.URL,
	}
	err := g.removeMessage(context.Background(), "watch@example.test", "AAMk")
	if err == nil {
		t.Fatal("a permissions failure was swallowed")
	}
	if soft.Load() != 0 {
		t.Errorf("fell back to a soft DELETE after a 403: removal would be silently downgraded")
	}
}
