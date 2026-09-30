// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"github.com/lazaretemail/lazaret/telemetry"

	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// A Source produces messages. Everything upstream of the engine is one of these.
//
// Four are implemented, and they sit at genuinely different points in a mail system,
// which is the reason for all four rather than a preference between them:
//
//   - **rspamd** is inline, before delivery. A verdict can stop a message reaching a
//     mailbox at all, which is the only placement where that is possible.
//   - **imap** is after delivery, works against anything that speaks IMAP, and needs no
//     cooperation from the mail provider beyond an account.
//   - **graph-webhook** is Microsoft 365, push. Near-real-time, and needs an endpoint
//     Microsoft can reach.
//   - **graph-poll** is Microsoft 365, pull. Slower, and needs nothing inbound — which
//     is why it is the fallback rather than an alternative.
type Source interface {
	// Name identifies the source in logs and metrics.
	Name() string

	// Run delivers messages until the context is cancelled. It returns nil on a clean
	// shutdown and an error only when the source cannot continue.
	Run(ctx context.Context, deliver Deliver) error
}

// Deliver hands one raw message to the engine and returns what it concluded.
type Deliver func(ctx context.Context, msg RawMessage) (*Verdict, error)

// RawMessage is a message as received, plus where it came from.
type RawMessage struct {
	// Raw is the RFC 5322 bytes.
	Raw []byte

	// Source names the connector.
	Source string

	// Mailbox is whose mailbox it arrived in, where that is known. Empty for inline
	// sources, which see a message in transit rather than in a mailbox.
	Mailbox string

	// MailboxID is the engine's identifier for that mailbox, when this connector was
	// configured by the engine rather than from flags.
	//
	// It is what lets remediation be aimed. Without it the engine has to queue a
	// removal against every mailbox it knows about and let most of them find
	// nothing, which is correct but wasteful — and gets worse with every mailbox
	// added.
	MailboxID string

	// ProviderID is the provider's own identifier, needed to act on the message later.
	// An IMAP UID, a Graph message id. Without it a verdict can be recorded but not
	// enforced.
	ProviderID string

	ReceivedAt time.Time
}

// Verdict is what the engine concluded.
type Verdict struct {
	MessageID string   `json:"message_id"`
	Verdict   string   `json:"verdict"`
	Matched   []Rule   `json:"matched"`
	Missing   []string `json:"missing_capabilities"`
	Recorded  bool     `json:"recorded"`
	Duplicate bool     `json:"duplicate"`

	// Released says a person has overridden this verdict. The rules still fired —
	// the verdict is unchanged and still reported — but the message must be left
	// where it is.
	Released bool `json:"released"`
}

// Rule is one rule that fired.
type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// Malicious reports whether the engine flagged the message.
func (v *Verdict) Malicious() bool { return v != nil && v.Verdict == "malicious" }

// Actionable reports whether this connector should remove the message.
//
// Malicious and not already released. The second half is what stops the two halves
// of custody fighting: a released message put back in the inbox is unread, so the
// connector analyses it, gets the same malicious verdict, and would remove it again
// — undoing the analyst's decision within seconds, over and over.
func (v *Verdict) Actionable() bool { return v.Malicious() && !v.Released }

// Indeterminate reports whether the engine could not decide.
//
// Worth its own method, and worth callers distinguishing: a message the engine could
// not fully evaluate has not been cleared. An inline source that treats this as clean
// converts an outage into delivered phishing, and one that treats it as malicious
// converts an outage into a mail outage. Neither is right; it is a third answer.
func (v *Verdict) Indeterminate() bool { return v != nil && v.Verdict == "indeterminate" }

// Severity returns the highest severity among the rules that fired.
func (v *Verdict) Severity() string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	best, name := 0, ""
	for _, r := range v.Matched {
		if rank[r.Severity] > best {
			best, name = rank[r.Severity], r.Severity
		}
	}
	return name
}

// Engine is a client for lazaret-engine.
type Engine struct {
	Address string
	Tenant  string
	Client  *http.Client

	// Token authenticates this connector to the engine. An API token rather than a
	// session, which is also what lets it read mailbox credentials — see the
	// engine's /v0/mailboxes/secrets. Empty only where the engine runs with -no-auth.
	Token string
}

// NewEngine returns a client.
func NewEngine(addr, tenant string, timeout time.Duration) *Engine {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return &Engine{Address: addr, Tenant: tenant, Client: telemetry.Client(&http.Client{Timeout: timeout})}
}

// authorize attaches the connector's credential, if it has one.
func (e *Engine) authorize(req *http.Request) {
	if e.Token != "" {
		req.Header.Set("Authorization", "Bearer "+e.Token)
	}
}

// Ingest analyses and records a message: the delivery path.
func (e *Engine) Ingest(ctx context.Context, msg RawMessage) (*Verdict, error) {
	return e.post(ctx, "/v0/messages/ingest", msg.Raw, msg.MailboxID)
}

// Analyze analyses without recording.
//
// Used by the inline source. A message Rspamd is about to reject was never delivered,
// and recording it would build sender history for mail nobody received — which is the
// same reasoning that keeps the engine's own analyze endpoint read-only.
func (e *Engine) Analyze(ctx context.Context, msg RawMessage) (*Verdict, error) {
	return e.post(ctx, "/v0/messages/analyze", msg.Raw, "")
}

func (e *Engine) post(ctx context.Context, path string, raw []byte, mailboxID string) (*Verdict, error) {
	body, err := json.Marshal(map[string]string{
		"raw_message": base64.StdEncoding.EncodeToString(raw),
		"tenant_id":   e.Tenant,
		"mailbox_id":  mailboxID,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Address+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	e.authorize(req)

	resp, err := e.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(payload, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, fmt.Errorf("engine: %s", e.Error)
	}

	var v Verdict
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, fmt.Errorf("engine: decoding the verdict: %w", err)
	}
	return &v, nil
}

// RecordAction tells the engine what was done, for the audit trail.
func (e *Engine) RecordAction(ctx context.Context, messageID, action, reason, actor string) error {
	body, _ := json.Marshal(map[string]string{
		"action": action, "reason": reason, "actor": actor, "tenant_id": e.Tenant,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.Address+"/v0/messages/"+url.PathEscape(messageID)+"/actions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	e.authorize(req)

	resp, err := e.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("engine: recording action: %s", resp.Status)
	}
	return nil
}

// ReportHealth tells the engine whether this connector can reach a mailbox.
//
// Called on every connection attempt rather than only on failure: a mailbox that
// stopped working needs to stop looking like it works, and a mailbox that started
// working after a password was fixed needs to say so without waiting for mail to
// arrive. A report that cannot be delivered is logged and dropped — the engine being
// briefly unreachable is not a reason to stop collecting mail.
func (e *Engine) ReportHealth(ctx context.Context, mailboxID string, seen int64, reported error) {
	if mailboxID == "" {
		return // an unmanaged connector, configured from flags; nothing to report to
	}
	msg := ""
	if reported != nil {
		msg = reported.Error()
	}
	body, err := json.Marshal(map[string]any{"seen": seen, "error": msg})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.Address+"/v0/mailboxes/"+mailboxID+"/health", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	e.authorize(req)

	resp, err := e.Client.Do(req)
	if err != nil {
		log.Printf("health: reporting %s: %v", mailboxID, err)
		return
	}
	resp.Body.Close()
}
