// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"
)

// The Rspamd source: Lazaret, inline, before delivery.
//
// This is the only placement where a verdict can stop a message reaching a mailbox at
// all. Every other source sees mail that has already been delivered and can at best
// move it afterwards, during which a recipient can read it.
//
// Rspamd calls this endpoint from a Lua plugin (lua/lazaret.lua) while it is scanning.
// The response is a score and a set of symbols, which Rspamd folds into its own
// decision alongside SPF, DKIM, DMARC, Bayes and the rest. Deliberately a contribution
// rather than an override: an operator who has tuned Rspamd should not have this
// silently outrank everything they configured.
//
// # Failure has to be a decision, not an accident
//
// An inline scanner sits in the delivery path, so what it does when it breaks is part
// of its design rather than an afterthought.
//
//   - **Unreachable, or timed out.** The Lua plugin fails *open* — the message is
//     delivered — and emits LAZARET_FAIL so the failure is visible in Rspamd's own
//     logs and can be alerted on. Failing closed would mean an engine restart stops
//     all mail, which is a worse outage than a missed detection and the kind that gets
//     the whole system removed.
//   - **Indeterminate.** The engine ran but could not decide, because a capability it
//     needed was unavailable. That is neither clean nor malicious, so it scores a
//     little and says why. Treating it as clean converts an outage into delivered
//     phishing; treating it as malicious converts an outage into a mail outage.
//
// Both are visible as distinct symbols precisely so an operator can tell "Lazaret said
// this is fine" from "Lazaret could not say", which is the distinction the whole engine
// is built around.

// RspamdSource serves the endpoint the Lua plugin calls.
type RspamdSource struct {
	Addr   string
	Engine *Engine

	// Secret is checked against the Password header the plugin sends. Rspamd and this
	// service are usually on the same host or the same private network, but "usually"
	// is not a security model: without it anyone who can reach the port can submit mail
	// for scoring and learn what the rules do.
	Secret string

	// MaxBody caps a submission.
	MaxBody int64

	// Score is what a malicious verdict contributes, per severity. Rspamd's default
	// reject threshold is 15 and its add-header threshold 6, so a critical finding
	// rejects on its own and a low one only nudges.
	Score map[string]float64
}

// DefaultRspamdScores maps severity to an Rspamd score.
//
// Chosen against Rspamd's stock thresholds (greylist 4, add_header 6, reject 15) so
// that the defaults do something sensible before anyone tunes them: critical rejects,
// high is close, medium adds a header, low is advisory.
var DefaultRspamdScores = map[string]float64{
	"critical": 15,
	"high":     10,
	"medium":   6,
	"low":      2,
	"":         5,
}

func (s *RspamdSource) Name() string { return "rspamd" }

// rspamdReply is what the Lua plugin expects back.
type rspamdReply struct {
	// Score is added to Rspamd's running total.
	Score float64 `json:"score"`

	// Symbol names the finding in Rspamd's report, so it appears in the headers an
	// operator already reads.
	Symbol string `json:"symbol"`

	// Description is the one-line reason, usually the rule that fired.
	Description string `json:"description"`

	// Verdict, MessageID and Rules are passed through for logging rather than scoring.
	Verdict   string   `json:"verdict"`
	MessageID string   `json:"message_id,omitempty"`
	Rules     []string `json:"rules,omitempty"`
}

// Run serves the scoring endpoint until the context is cancelled.
func (s *RspamdSource) Run(ctx context.Context, deliver Deliver) error {
	if s.MaxBody <= 0 {
		s.MaxBody = 64 << 20
	}
	if s.Score == nil {
		s.Score = DefaultRspamdScores
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /rspamd/check", func(w http.ResponseWriter, r *http.Request) {
		if s.Secret != "" && r.Header.Get("Password") != s.Secret {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}

		raw, err := io.ReadAll(io.LimitReader(r.Body, s.MaxBody))
		if err != nil || len(raw) == 0 {
			http.Error(w, "empty body", http.StatusBadRequest)
			return
		}

		msg := RawMessage{
			Raw:        raw,
			Source:     "rspamd",
			Mailbox:    r.Header.Get("Rcpt"),
			ReceivedAt: time.Now().UTC(),
		}

		verdict, err := deliver(r.Context(), msg)
		if err != nil {
			// 502, and the plugin fails open. The error is reported rather than
			// swallowed so it lands in Rspamd's log next to the message it affected.
			log.Printf("rspamd: analysing a message: %v", err)
			writeJSON(w, http.StatusBadGateway, rspamdReply{
				Symbol: "LAZARET_FAIL", Verdict: "error", Description: err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, s.reply(verdict))
	})

	mux.HandleFunc("GET /rspamd/ping", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	srv := &http.Server{
		Addr:              s.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// Inline means a real MTA is waiting on this. Generous enough for a full scan
		// with file explosion, short enough that a wedged engine does not hold an SMTP
		// transaction open indefinitely.
		ReadTimeout:  3 * time.Minute,
		WriteTimeout: 3 * time.Minute,
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Printf("rspamd: listening on %s", s.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// reply turns a verdict into a score and a symbol.
func (s *RspamdSource) reply(v *Verdict) rspamdReply {
	out := rspamdReply{Verdict: v.Verdict, MessageID: v.MessageID}
	for _, r := range v.Matched {
		out.Rules = append(out.Rules, r.Name)
	}

	switch {
	case v.Malicious():
		sev := v.Severity()
		out.Score = s.Score[sev]
		if out.Score == 0 {
			out.Score = s.Score[""]
		}
		out.Symbol = "LAZARET_MALICIOUS"
		out.Description = describe(v)

	case v.Indeterminate():
		// A small positive score, not zero and not a rejection. The message has not
		// been cleared — some rule could not run — and that is worth a nudge and a
		// distinct symbol, not a verdict.
		out.Score = 1
		out.Symbol = "LAZARET_INDETERMINATE"
		out.Description = "not fully evaluated: missing " + join(v.Missing, 3)

	default:
		out.Score = 0
		out.Symbol = "LAZARET_CLEAN"
		out.Description = "no rules matched"
	}
	return out
}

func describe(v *Verdict) string {
	if len(v.Matched) == 0 {
		return "flagged"
	}
	names := make([]string, 0, len(v.Matched))
	for _, r := range v.Matched {
		names = append(names, r.Name)
	}
	return join(names, 3)
}

func join(vs []string, max int) string {
	if len(vs) == 0 {
		return "none"
	}
	out := ""
	for i, v := range vs {
		if i >= max {
			out += ", and " + itoa(len(vs)-max) + " more"
			break
		}
		if i > 0 {
			out += "; "
		}
		out += v
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
