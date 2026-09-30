// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The scoring map is the whole contract with Rspamd, so it is tested directly rather
// than only through the endpoint.
func TestRspamdScoring(t *testing.T) {
	s := &RspamdSource{Score: DefaultRspamdScores}

	for _, tc := range []struct {
		name      string
		verdict   *Verdict
		wantSym   string
		wantScore float64
	}{
		{
			name: "critical rejects on its own",
			verdict: &Verdict{Verdict: "malicious", Matched: []Rule{
				{Name: "Credential phishing", Severity: "critical"}}},
			wantSym: "LAZARET_MALICIOUS", wantScore: 15,
		},
		{
			name: "medium adds a header",
			verdict: &Verdict{Verdict: "malicious", Matched: []Rule{
				{Name: "Suspicious subject", Severity: "medium"}}},
			wantSym: "LAZARET_MALICIOUS", wantScore: 6,
		},
		{
			name: "the highest severity wins",
			verdict: &Verdict{Verdict: "malicious", Matched: []Rule{
				{Name: "a", Severity: "low"}, {Name: "b", Severity: "high"}}},
			wantSym: "LAZARET_MALICIOUS", wantScore: 10,
		},
		{
			name:    "clean scores nothing",
			verdict: &Verdict{Verdict: "clean"},
			wantSym: "LAZARET_CLEAN", wantScore: 0,
		},
		{
			// Neither clean nor malicious. Scoring it zero would say the message was
			// cleared when nothing cleared it; scoring it like a detection would turn
			// an ML outage into a mail outage.
			name:    "indeterminate nudges and says why",
			verdict: &Verdict{Verdict: "indeterminate", Missing: []string{"ml.nlu_classifier"}},
			wantSym: "LAZARET_INDETERMINATE", wantScore: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.reply(tc.verdict)
			if got.Symbol != tc.wantSym {
				t.Errorf("symbol = %q, want %q", got.Symbol, tc.wantSym)
			}
			if got.Score != tc.wantScore {
				t.Errorf("score = %v, want %v", got.Score, tc.wantScore)
			}
			if got.Description == "" {
				t.Error("no description; it lands in the Rspamd report and should say something")
			}
		})
	}
}

// An indeterminate reply must name what was missing, so an operator reading Rspamd's
// log can tell "we found nothing" from "we could not look".
func TestRspamdIndeterminateNamesTheGap(t *testing.T) {
	s := &RspamdSource{Score: DefaultRspamdScores}
	got := s.reply(&Verdict{Verdict: "indeterminate", Missing: []string{"ml.nlu_classifier", "file.explode"}})
	if !strings.Contains(got.Description, "ml.nlu_classifier") {
		t.Errorf("description %q does not name the missing capability", got.Description)
	}
}

func TestRspamdEndpointRequiresTheSecret(t *testing.T) {
	src := &RspamdSource{Addr: freePort(t), Secret: "correct-horse", Score: DefaultRspamdScores}
	base := serve(t, src, func(context.Context, RawMessage) (*Verdict, error) {
		return &Verdict{Verdict: "clean"}, nil
	})

	for _, tc := range []struct {
		secret string
		want   int
	}{
		{"", http.StatusUnauthorized},
		{"wrong", http.StatusUnauthorized},
		{"correct-horse", http.StatusOK},
	} {
		req, _ := http.NewRequest(http.MethodPost, base+"/rspamd/check", strings.NewReader("From: a@b\r\n\r\nhi"))
		if tc.secret != "" {
			req.Header.Set("Password", tc.secret)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("secret %q: status %d, want %d", tc.secret, resp.StatusCode, tc.want)
		}
	}
}

// When the engine is unreachable the endpoint must return an error the plugin can see,
// not a clean verdict. The plugin fails open on its side; this side must never
// manufacture a pass.
func TestRspamdEngineFailureIsNotAPass(t *testing.T) {
	src := &RspamdSource{Addr: freePort(t), Score: DefaultRspamdScores}
	base := serve(t, src, func(context.Context, RawMessage) (*Verdict, error) {
		return nil, context.DeadlineExceeded
	})

	resp, err := http.Post(base+"/rspamd/check", "message/rfc822", strings.NewReader("From: a@b\r\n\r\nhi"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d, want 502", resp.StatusCode)
	}

	var reply rspamdReply
	json.NewDecoder(resp.Body).Decode(&reply)
	if reply.Symbol != "LAZARET_FAIL" {
		t.Errorf("symbol = %q, want LAZARET_FAIL", reply.Symbol)
	}
	if reply.Score != 0 {
		t.Errorf("score = %v; a failure must not score as a detection", reply.Score)
	}
	if reply.Verdict == "clean" {
		t.Error("a failure reported itself as clean")
	}
}

// The recipient travels in a header, so the engine can attribute the message.
func TestRspamdPassesTheRecipient(t *testing.T) {
	src := &RspamdSource{Addr: freePort(t), Score: DefaultRspamdScores}
	got := make(chan string, 1)
	base := serve(t, src, func(_ context.Context, m RawMessage) (*Verdict, error) {
		got <- m.Mailbox
		return &Verdict{Verdict: "clean"}, nil
	})

	req, _ := http.NewRequest(http.MethodPost, base+"/rspamd/check", strings.NewReader("From: a@b\r\n\r\nhi"))
	req.Header.Set("Rcpt", "victim@example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case mbox := <-got:
		if mbox != "victim@example.com" {
			t.Errorf("mailbox = %q", mbox)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the engine was never called")
	}
}

// serve starts a source and returns its base URL.
func serve(t *testing.T, src *RspamdSource, deliver Deliver) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go src.Run(ctx, deliver)

	base := "http://" + src.Addr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(base + "/rspamd/ping"); err == nil {
			resp.Body.Close()
			return base
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the source never started listening")
	return ""
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// shortClient is for tests that point an Engine at a dead address on purpose: the
// action call is expected to fail and must not hold the test open for two minutes.
func shortClient() *http.Client { return &http.Client{Timeout: 200 * time.Millisecond} }
