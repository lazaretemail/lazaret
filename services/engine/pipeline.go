// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lazaretemail/lazaret/eml"
	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/ml"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/orgconfig"
	"github.com/lazaretemail/lazaret/profile"
	"github.com/lazaretemail/lazaret/rules"
	"github.com/lazaretemail/lazaret/services/engine/store"
	"github.com/lazaretemail/lazaret/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// The analysis pipeline: parse, evaluate, persist.
//
// One function, because the three steps are one transaction of meaning. A message that
// is evaluated but not persisted leaves no history, and profile.* is 898 corpus calls
// answered from history — so an engine that analyses without recording degrades every
// subsequent message it sees.

// Pipeline analyses messages against a rule set.
type Pipeline struct {
	store *store.Store
	// engine is swapped wholesale when rule content changes — a feed sync, or an
	// operator editing the local rules directory. Atomic rather than mutex-guarded
	// because it is read on every message and written a few times a day.
	engine atomic.Pointer[rules.Engine]
	org    *orgconfig.Config

	// enricher is the shared provider set. Each analysis wraps it in a per-message
	// cache: ~500 corpus rules each write file.explode(.) for themselves, and uncached
	// that is a thousand identical scans of one attachment.
	enricher mql.Enricher

	// lists resolves $named lists, including the history-backed ones.
	lists mql.ListResolver

	// The capability probe's last answer. Cached because two pages ask for it and
	// each probe is a real call to a real service.
	healthMu sync.Mutex
	health   []CapabilityState
	healthAt time.Time

	// model is what this deployment has learned from its own analysts' reviews.
	//
	// Advisory: it scores a message alongside the rules and never instead of them.
	// It is trained on which detections analysts agreed with, so letting it
	// suppress detections would close a loop in which the system learns to stop
	// reporting whatever nobody has got round to reviewing.
	model modelCache

	// timeout bounds one message's analysis.
	//
	// Needed because enrichment multiplies: every link in a message is visited
	// separately, so a message with a dozen dead links spends a dozen fetch budgets
	// in a row. Without a ceiling, one message can occupy the delivery path for
	// minutes — and the inline placement has Rspamd waiting on the other end with a
	// twenty-second budget of its own.
	//
	// Overrunning is not a failure. Enrichment past the deadline reports
	// unavailable, its rules report indeterminate, and everything that did finish
	// still counts: a partial verdict on a slow message beats no verdict.
	timeout time.Duration

	// mu guards org, which an admin can change while messages are being processed.
	mu sync.RWMutex

	// ml is kept so the platform can report what inference is running on. Not used
	// for enrichment — that goes through the mux like everything else — but the
	// provider in use is the difference between a message taking one second and
	// taking eight, and nothing in a result says which happened.
	ml *ml.Client

	// providerNames is what enrichment is attached, for the capabilities endpoint. An
	// operator should be able to see what a deployment can answer without sending a
	// message through it.
	providerNames []string

	// links, when set, schedules the message's links to be looked at again over the
	// following day. Nil in a deployment with no renderer, which is the honest
	// outcome: there is nothing to re-visit with.
	links *LinkWatcher
}

// WatchLinks attaches the re-detonation schedule.
func (p *Pipeline) WatchLinks(w *LinkWatcher) { p.links = w }

// Analysis is the result of running the pipeline over one message.
type Analysis struct {
	MessageID     string          `json:"message_id"`
	Verdict       string          `json:"verdict"`
	Matched       []RuleResult    `json:"matched"`
	Indeterminate []RuleResult    `json:"indeterminate,omitempty"`
	Missing       []string        `json:"missing_capabilities,omitempty"`
	MDM           json.RawMessage `json:"message_data_model,omitempty"`
	Evaluated     int             `json:"rules_evaluated"`
	ElapsedMS     int64           `json:"elapsed_ms"`
	Recorded      bool            `json:"recorded,omitempty"`
	Duplicate     bool            `json:"duplicate,omitempty"`
	// Released says a person has overridden the verdict for this message, and a
	// connector must leave it where it is.
	//
	// Without this the two halves of custody fight each other. Releasing puts the
	// message back in the inbox; the connector sees an unread message, analyses it,
	// gets the same malicious verdict it got the first time, and removes it again —
	// a loop in which the analyst's decision is undone within seconds and the only
	// visible symptom is a message that will not stay released.
	//
	// The verdict itself is left alone. The rules did fire, and saying otherwise
	// would hide a real detection from every report. What changes is what may be
	// done about it.
	Released bool `json:"released,omitempty"`

	// EvidenceKept is how many enrichment answers were frozen with the message, so
	// an operator can see that a hunt over this message has something to work from.
	EvidenceKept int `json:"evidence_kept,omitempty"`

	// detail is the stored detail-view analysis, carried to persist. Unexported:
	// it is several kilobytes of page content and has no business in the ingest
	// response, which a connector reads on every message.
	detail []byte

	// evidence is what enrichment answered, frozen, carried to persist. Unexported
	// for the same reason as detail and more so: it is the largest thing the
	// analysis produces.
	evidence []byte

	// Detail and Model are the same answer, kept live rather than marshalled, for
	// the analyzer — which wants everything the message page shows and has nowhere
	// to read it back from, the whole point of that endpoint being that it stores
	// nothing.
	Detail *StoredAnalysis       `json:"-"`
	Model  *mdm.MessageDataModel `json:"-"`

	// Timing is what each capability cost on this message. Carried so an operator
	// can answer "why was that slow" without reaching for a profiler.
	Timing []CapTiming `json:"-"`

	// Actions names what the matched rules caused to happen. Reported back to
	// the connector that handed the message over: it has just been told the
	// verdict, and it should also be told that the platform is about to change
	// the mailbox it came from.
	Actions []string `json:"actions,omitempty"`

	// TimedOut says the analysis hit its deadline. When it is set, the missing
	// capabilities below describe this message's budget rather than the
	// deployment's abilities, and anything reading them has to say so.
	TimedOut            bool   `json:"timed_out,omitempty"`
	CostliestCapability string `json:"costliest_capability,omitempty"`
	CostliestMS         int64  `json:"costliest_ms,omitempty"`
}

// RuleResult names one rule and why it is in the list it is in.
type RuleResult struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name"`
	Severity string   `json:"severity,omitempty"`
	Missing  []string `json:"missing,omitempty"`
}

// Analyze parses a raw message, evaluates the rule set, and persists the result.
//
// persist is false for the stateless /v0/messages/analyze path, where a caller is
// checking a message they hold rather than feeding the pipeline. Recording those would
// let anyone with API access poison every sender profile in the tenant by submitting
// messages that were never delivered.
func (p *Pipeline) Analyze(ctx context.Context, tenant string, raw []byte, persist bool) (*Analysis, error) {
	return p.AnalyzeFrom(ctx, tenant, raw, persist, "")
}

// AnalyzeFrom is Analyze, told which mailbox the message arrived in.
//
// Separate entry point rather than a wider signature everywhere, because only the
// ingest path knows this and only remediation uses it.
func (p *Pipeline) AnalyzeFrom(ctx context.Context, tenant string, raw []byte, persist bool, mailboxID string) (*Analysis, error) {
	return p.AnalyzeWith(ctx, tenant, raw, persist, IngestOptions{MailboxID: mailboxID})
}

// IngestOptions are the things about an ingest that are not the message.
type IngestOptions struct {
	// MailboxID is which mailbox this arrived in, so a later removal can be aimed.
	MailboxID string

	// BackfillID marks a message found by a retrospective scan rather than seen on
	// arrival. Recorded as provenance, because a verdict reached weeks after
	// delivery is a different claim from one reached at the door.
	BackfillID string

	// SkipCustody declines to keep the original bytes.
	//
	// Custody exists to make quarantine reversible, and a retrospective scan does
	// not quarantine — so for a ninety-day backfill, holding a copy of every
	// message is a large amount of storage bought for a capability the scan will
	// never use. Opt in per job when the mail is worth keeping anyway.
	SkipCustody bool
}

// AnalyzeWith is AnalyzeFrom with the whole set of ingest options.
func (p *Pipeline) AnalyzeWith(ctx context.Context, tenant string, raw []byte, persist bool, opts IngestOptions) (*Analysis, error) {
	start := time.Now()

	ctx, span := engineTracer.Start(ctx, "pipeline.analyze", trace.WithAttributes(
		attrTenant.String(tenant),
		attribute.Bool("lazaret.backfill", opts.BackfillID != ""),
		attribute.String("lazaret.mailbox_id", opts.MailboxID),
		attribute.Int("lazaret.message.bytes", len(raw)),
		attribute.Bool("lazaret.persist", persist),
	))
	defer span.End()

	// The deadline covers evaluation, not persistence: a message that ran out of
	// time to enrich still has a verdict worth recording, and writing it under the
	// expired deadline would lose exactly the result the deadline existed to
	// salvage. So the caller's context is kept for the write.
	parent := ctx
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	parseCtx, parseSpan := engineTracer.Start(ctx, "eml.parse")
	msg, err := eml.Parse(raw, &eml.Options{Org: p.orgConfig()})
	if err != nil {
		telemetry.Error(parseSpan, err)
		parseSpan.End()
		return nil, telemetry.Error(span, fmt.Errorf("parsing message: %w", err))
	}
	parseSpan.End()
	_ = parseCtx

	// One cache per message, never shared between them: within a single analysis an
	// enrichment is a pure function of its arguments, so there is nothing to
	// invalidate, and nothing leaks from one message to the next.
	// Timing wraps the cache, not the other way round: a cache hit costs nothing
	// and should not be counted as work.
	timing := newTimingEnricher(p.enricher)
	enricher := mql.NewCache(timing)

	// Visit the links first, together, so the rules find them already answered
	// rather than waiting for each in turn.
	warmCtx, warmSpan := engineTracer.Start(ctx, "linkanalysis.prefetch")
	p.warmLinkAnalysis(warmCtx, msg, enricher)
	warmSpan.End()

	// One span for the whole rule set, not one per rule. Fifteen hundred rules
	// against one message would make the span the most expensive thing in the
	// analysis and the trace unreadable; the per-rule detail that is worth keeping
	// is already in the report, and the slow part is enrichment, which is traced
	// at its own boundary.
	runCtx, runSpan := engineTracer.Start(ctx, "rules.run",
		trace.WithAttributes(attribute.Int("lazaret.rules.loaded", p.rules().Len())))
	report := p.rules().RunWith(runCtx, msg, &rules.RunOptions{Enricher: enricher, Lists: p.lists})
	runSpan.SetAttributes(
		attribute.Int("lazaret.rules.matched", len(report.Flagged)),
		attribute.Int("lazaret.rules.indeterminate", len(report.Indeterminate)),
	)
	runSpan.End()

	out := &Analysis{
		MessageID: messageID(msg, raw),
		Evaluated: p.rules().Len(),
		ElapsedMS: time.Since(start).Milliseconds(),
	}

	// Freeze what enrichment answered, now the rules have finished asking.
	//
	// After the run rather than during it: a snapshot taken mid-flight records
	// whatever has resolved so far, which is a partial record rather than a wrong
	// one, but partial is not what a later hunt should be given. Marshalling
	// failures are logged and dropped — a message with no evidence is one a hunt
	// reports as undecidable, which is true, rather than one it answers wrongly.
	if snap := enricher.Snapshot(); snap.Len() > 0 {
		if b, err := json.Marshal(snap); err != nil {
			log.Printf("freezing evidence for %s: %v", out.MessageID, err)
		} else {
			out.evidence = b
			out.EvidenceKept = snap.Len()
		}
	}

	// Running out of time is not the same as lacking a capability, and until now
	// they were reported identically. Once the deadline passes, every enrichment
	// the evaluator happens to reach next fails and is recorded as unavailable —
	// so one slow link fetch could make fifteen working services look broken, which
	// is a worse lie than the slow analysis itself.
	if ctx.Err() != nil {
		out.TimedOut = true
		out.CostliestCapability, out.CostliestMS = timing.Costliest()
		log.Printf("analysis of %s ran out of time after %s; %s alone took %dms — "+
			"capabilities reported missing on this message may be fine",
			out.MessageID, p.timeout, out.CostliestCapability, out.CostliestMS)
	}

	// The detail view's answer, built here from the run that just happened rather
	// than by running everything again when somebody opens the page. The enricher
	// cache is already warm, so the insights and the sender panel cost a few
	// map lookups instead of a second round of RDAP and inference.
	detail := &StoredAnalysis{
		Schema:        analysisSchema,
		At:            time.Now().UTC().Format(time.RFC3339),
		Detections:    detections(report.Flagged),
		Indeterminate: detections(report.Indeterminate),
		Excluded:      detections(report.Excluded),
		Queries:       queryValues(report.Queries),
		Missing:       capList(report.Missing),
	}
	detail.Insights = p.messageInsights(ctx, msg, enricher)
	detail.Signals = attackSignals(detail.Detections, detail.Insights)
	detail.Sender = p.senderDetails(ctx, msg, enricher)
	detail.Links = p.linkDetails(ctx, msg, enricher)
	detail.Origin = p.originDetails(ctx, msg, enricher)
	detail.Learned = scoreWith(p.model.get(), detail, messageSummary(msg), detail.Sender)
	if blob, err := json.Marshal(detail); err == nil {
		out.detail = blob
	}
	out.Detail, out.Model = detail, msg
	out.Timing = timing.Report()
	for _, d := range report.Flagged {
		out.Matched = append(out.Matched, result(d))
	}
	for _, d := range report.Indeterminate {
		out.Indeterminate = append(out.Indeterminate, result(d))
	}
	// An excluded message is not flagged, however many detections fired. Reporting the
	// matches anyway would make a suppressed message look dangerous in every list that
	// reads Matched.
	if len(report.Excluded) > 0 {
		out.Matched = nil
	}
	out.Missing = capNames(report.Missing)
	out.Verdict = verdictOf(out)

	if body, err := json.Marshal(msg); err == nil {
		out.MDM = body
	}

	// A decision someone already made about this message outranks the verdict just
	// computed for it. Checked on every analysis, not only on a duplicate: a
	// released message that is re-delivered is still one a person has judged.
	if last, err := p.store.LastActions(ctx, tenant, []string{out.MessageID}); err == nil {
		switch last[out.MessageID] {
		case "release", "restore", "unflag":
			out.Released = true
		}
	}

	if persist {
		// Where it came from, so a later removal can be aimed at one connector
		// rather than fanned out across every mailbox in the tenant. Recorded even
		// for a duplicate: the second delivery may be to a different mailbox.
		if opts.MailboxID != "" {
			if err := p.store.RecordOriginFrom(parent, tenant, out.MessageID,
				opts.MailboxID, opts.BackfillID); err != nil {
				log.Printf("origin: %s: %v", out.MessageID, err)
			}
		}

		switch err := p.persistWith(parent, tenant, msg, out, raw, opts); {
		case err == nil:
			out.Recorded = true
		case errors.Is(err, store.ErrDuplicate):
			// Already held. The analysis is still valid and is still returned; what is
			// refused is a second sender event, because a retried delivery must not
			// count twice towards a profile.
			out.Duplicate = true
		default:
			return out, fmt.Errorf("persisting analysis: %w", err)
		}

		// What the matched rules call for, if anything.
		//
		// After persistence, and the order is load-bearing: a destructive action
		// is refused unless the original is held, so custody has to exist before
		// the question is asked. Running this first would refuse every
		// quarantine on the grounds that the copy it just failed to check for
		// had not been written yet.
		//
		// Not for a duplicate. The message has been seen and acted on already;
		// doing it again on a redelivery would re-quarantine something an
		// analyst may have released in between.
		if !out.Duplicate {
			out.Actions = p.autoAct(parent, tenant, out, opts)
		}
	}

	p.recordAnalysis(ctx, span, tenant, msg, out, start)
	return out, nil
}

// recordAnalysis puts the result on the span and into the metrics.
//
// Everything with unbounded values — the message id, the sender, which rules fired
// — goes on the span. Only the fixed vocabulary becomes a metric label, because a
// label is a time series and a message id is not a category.
func (p *Pipeline) recordAnalysis(ctx context.Context, span trace.Span, tenant string,
	msg *mdm.MessageDataModel, out *Analysis, start time.Time) {

	verdict := verdictOf(out)
	direction := directionOf(msg)

	span.SetAttributes(
		attrVerdict.String(verdict),
		attrDirection.String(direction),
		attribute.String("lazaret.message.id", out.MessageID),
		attribute.Int("lazaret.detections", len(out.Matched)),
		attribute.Int("lazaret.indeterminate", len(out.Indeterminate)),
		attribute.StringSlice("lazaret.missing_capabilities", out.Missing),
		attribute.Bool("lazaret.timed_out", out.TimedOut),
		attribute.Bool("lazaret.duplicate", out.Duplicate),
		attribute.Bool("lazaret.recorded", out.Recorded),
	)

	common := metric.WithAttributes(
		attrTenant.String(tenant),
		attrVerdict.String(verdict),
		attrDirection.String(direction),
		attribute.Bool("lazaret.timed_out", out.TimedOut),
	)
	metricAnalyzed.Add(ctx, 1, common)
	metricAnalysisDuration.Record(ctx, time.Since(start).Seconds(), common)

	for _, d := range out.Matched {
		metricRuleMatched.Add(ctx, 1, metric.WithAttributes(
			attrTenant.String(tenant),
			attrRule.String(d.Name),
			attrSeverity.String(d.Severity),
		))
	}
}

// verdictOf collapses a report into one word.
//
// `indeterminate` is a verdict in its own right rather than being folded into clean. A
// message whose rules could not all run has not been cleared, and the distinction is
// the whole reason the engine tracks missing capabilities.
func verdictOf(a *Analysis) string {
	switch {
	case len(a.Matched) > 0:
		return "malicious"
	case len(a.Indeterminate) > 0:
		return "indeterminate"
	default:
		return "clean"
	}
}

func (p *Pipeline) persist(ctx context.Context, tenant string, msg *mdm.MessageDataModel, a *Analysis, raw []byte) error {
	return p.persistWith(ctx, tenant, msg, a, raw, IngestOptions{})
}

func (p *Pipeline) persistWith(ctx context.Context, tenant string, msg *mdm.MessageDataModel, a *Analysis, raw []byte, opts IngestOptions) error {
	at := receivedAt(msg)

	// The original bytes, before anything else. Quarantine removes a message from the
	// mailbox entirely rather than moving it to a folder, so this copy is what makes
	// that reversible — and it has to exist before the verdict does, because the
	// verdict is what someone will act on.
	//
	// A failure here is logged and not fatal. Recording the analysis is still worth
	// doing without it; what it costs is the ability to quarantine this one message,
	// and the action endpoint refuses rather than deleting something it cannot
	// restore.
	// Skipped for a retrospective scan that asked to skip it. Custody exists to
	// make quarantine reversible; a scan does not quarantine, so keeping ninety
	// days of message bodies buys a capability this job will never use. The
	// consequence is stated where it matters: a message with no custody cannot be
	// quarantined later, and the action endpoint refuses rather than deleting
	// something it cannot restore.
	if !opts.SkipCustody {
		if err := p.store.PutRaw(ctx, tenant, a.MessageID, raw); err != nil {
			log.Printf("custody: %s: %v", a.MessageID, err)
		}
	}

	m := store.Message{
		TenantID:   tenant,
		MessageID:  a.MessageID,
		ReceivedAt: at,
		Subject:    strOf(msg.Subject, func(s *mdm.Subject) *string { return s.Subject }),
		Direction:  directionOf(msg),
		Verdict:    a.Verdict,
		MDM:        a.MDM,
		RawKey:     rawKey(tenant, a.MessageID),
		Analysis:   a.detail,
		Evidence:   a.evidence,

		// Computed here rather than in a later pass over the corpus: it needs the
		// parsed model, which is in hand exactly once, and it costs microseconds.
		Fingerprint: Fingerprint(msg),
	}
	if s := msg.Sender; s != nil && s.Email != nil {
		m.SenderEmail = mdm.Deref(s.Email.Email)
		if s.Email.Domain != nil {
			m.SenderDomain = s.Email.Domain.Domain
		}
	}
	m.Recipients = recipientsOf(msg)

	v := store.Verdict{
		TenantID:      tenant,
		MessageID:     a.MessageID,
		At:            time.Now().UTC(),
		Verdict:       a.Verdict,
		Matched:       names(a.Matched),
		Indeterminate: names(a.Indeterminate),
		Missing:       a.Missing,
	}

	e := store.SenderEvent{
		TenantID:     tenant,
		At:           at,
		SenderEmail:  m.SenderEmail,
		SenderDomain: m.SenderDomain,
		Direction:    m.Direction,
		Verdict:      profileVerdict(a.Verdict),
		AuthFailed:   authFailed(msg),
	}
	if h := msg.Headers; h != nil {
		for _, rt := range h.ReplyTo {
			if rt != nil && rt.Email != nil {
				e.ReplyTo = mdm.Deref(rt.Email.Email)
				break
			}
		}
	}

	if err := p.store.PutMessage(ctx, m, v, e); err != nil {
		return err
	}

	// Scheduled after the message is recorded, not before: a finding points at a
	// message, and one that arrives before the message it names has nothing to show.
	p.links.Schedule(ctx, a.MessageID, a.evidence)
	return nil
}

// profileVerdict maps a run's verdict onto the vocabulary a profile records.
//
// An indeterminate message contributes no verdict at all rather than a benign one:
// recording "we could not tell" as "this was fine" would let an outage quietly build a
// reputation for a sender nobody actually cleared.
func profileVerdict(v string) string {
	switch v {
	case "malicious":
		return string(profile.VerdictMalicious)
	case "clean":
		return string(profile.VerdictBenign)
	default:
		return string(profile.VerdictUnknown)
	}
}

// messageID prefers the message's own Message-ID and falls back to a content hash.
//
// A hash rather than a random id, so that submitting the same message twice addresses
// the same record instead of silently duplicating it — which matters for a
// re-evaluation path that is supposed to update a verdict, not add a second one.
func messageID(msg *mdm.MessageDataModel, raw []byte) string {
	if h := msg.Headers; h != nil {
		if id := mdm.Deref(h.MessageID); id != "" {
			return id
		}
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func rawKey(tenant, messageID string) string {
	sum := sha256.Sum256([]byte(messageID))
	return tenant + "/raw/" + hex.EncodeToString(sum[:])
}

func receivedAt(msg *mdm.MessageDataModel) time.Time {
	if h := msg.Headers; h != nil && h.Date != nil {
		return h.Date.UTC()
	}
	return time.Now().UTC()
}

func directionOf(msg *mdm.MessageDataModel) string {
	t := msg.Type
	if t == nil {
		return "unknown"
	}
	switch {
	case mdm.Deref(t.Outbound):
		return "outbound"
	case mdm.Deref(t.Internal):
		return "internal"
	case mdm.Deref(t.Inbound):
		return "inbound"
	}
	return "unknown"
}

func authFailed(msg *mdm.MessageDataModel) bool {
	h := msg.Headers
	if h == nil || h.AuthSummary == nil || h.AuthSummary.DMARC == nil {
		return true
	}
	return !mdm.Deref(h.AuthSummary.DMARC.Pass)
}

func names(rs []RuleResult) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

func capNames(caps []enrich.Capability) []string {
	out := make([]string, len(caps))
	for i, c := range caps {
		out[i] = string(c)
	}
	return out
}

func strOf[T any](v *T, get func(*T) *string) string {
	if v == nil {
		return ""
	}
	return mdm.Deref(get(v))
}

// setOrg replaces the organisation configuration used to parse messages.
//
// Guarded, because a message may be mid-parse when an admin saves a change.
func (p *Pipeline) setOrg(org *orgconfig.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.org = org
}

func (p *Pipeline) orgConfig() *orgconfig.Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.org
}

// listSample returns a few entries and the total, for a settings page. tranco_1m has
// a million entries and nobody is reading them in a browser.
func (p *Pipeline) listSample(name string, n int) ([]string, int) {
	type elements interface {
		Elements(ctx context.Context, name string) ([]mql.Value, bool)
	}
	e, ok := p.lists.(elements)
	if !ok {
		return nil, 0
	}
	vals, known := e.Elements(context.Background(), name)
	if !known {
		return nil, 0
	}
	out := make([]string, 0, n)
	for i, v := range vals {
		if i >= n {
			break
		}
		if s, ok := v.AsString(); ok {
			out = append(out, s)
		}
	}
	return out, len(vals)
}

// listsKnown reports whether a named list can be resolved.
//
// Used by the coverage view: a rule gated on a list nobody configured is as blocked as
// one gated on a model nobody deployed, and reporting only the second would understate
// the gap.
func (p *Pipeline) listsKnown(name string) bool {
	type known interface{ Known(string) bool }
	if k, ok := p.lists.(known); ok {
		return k.Known(name)
	}
	return true
}

// result shapes one detection for the API.
func result(d *rules.Detection) RuleResult {
	return RuleResult{
		ID:       d.Entity.ID,
		Name:     d.Entity.Name,
		Severity: string(d.Entity.Severity),
		Missing:  capNames(d.Missing),
	}
}

// recipientsOf collects every addressee, which is what $recipient_emails is built
// from. To, Cc and Bcc alike: a message blind-copied to a mailbox was still received
// by it, and a rule asking "is this one of ours" means the mailbox rather than the
// visible header.
func recipientsOf(msg *mdm.MessageDataModel) []string {
	r := msg.Recipients
	if r == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, group := range [][]*mdm.Mailbox{r.To, r.CC, r.BCC} {
		for _, mb := range group {
			if mb == nil || mb.Email == nil {
				continue
			}
			addr := strings.ToLower(mdm.Deref(mb.Email.Email))
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

// Registry is the function set rules are compiled against, including any extensions
// this deployment enabled. Used by the API so validation agrees with evaluation.
func (p *Pipeline) Registry() *mql.Registry { return p.rules().Registry() }

// rules is the current rule set. Never nil once the pipeline is built.
func (p *Pipeline) rules() *rules.Engine { return p.engine.Load() }

// setRules swaps in a newly loaded rule set.
//
// Messages already being analysed finish against the set they started with, which
// is the honest behaviour: a verdict should come from one coherent rule set rather
// than half of each.
func (p *Pipeline) setRules(e *rules.Engine) { p.engine.Store(e) }
