// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Message is one analysed message, as persisted.
type Message struct {
	TenantID     string
	MessageID    string
	ReceivedAt   time.Time
	SenderEmail  string
	SenderDomain string
	Subject      string
	Direction    string
	Verdict      string

	// MDM is the parsed model, serialised. Stored whole rather than shredded into
	// columns because rules reach 54,740 distinct field paths across the corpus: any
	// column set narrow enough to be worth having is one a rule reads past.
	MDM []byte

	// RawKey locates the original message bytes in the blob store. The corpus holds the
	// model; the blob store holds the evidence.
	RawKey string

	// Analysis is the detail view's stored answer: the detections, the insights and
	// the sender panel as they were when the message was ingested. Opaque here —
	// the store keeps it, the API shapes it.
	Analysis []byte

	// Evidence is what enrichment answered, frozen — a serialised mql.Snapshot.
	//
	// The conclusions are in Analysis; this is what they were reached from. Without
	// it a rule cannot be run again over old mail: the link is dead, the WHOIS record
	// has changed, and re-fetching would answer a question about March with October's
	// facts. With it, a hunt covers every rule rather than the 545 of 1,513 that need
	// no enrichment, and a new rule can be measured against what actually arrived.
	//
	// Large, and compresses well: it is mostly the JSON the enrichers returned, and
	// DuckLake writes Parquet with zstd.
	Evidence []byte

	// Fingerprint is a SimHash of the message's structure, for grouping one attack
	// that arrived many times. Zero means none was computed.
	Fingerprint uint64

	// Recipients is who it was addressed to, which is where $recipient_emails comes
	// from. Stored on the message rather than derived from the model at read time,
	// so building the list is a column scan rather than a parse of every MDM.
	Recipients []string
}

// Verdict is the outcome of evaluating a rule set against a message.
type Verdict struct {
	TenantID      string
	MessageID     string
	At            time.Time
	Verdict       string
	Matched       []string
	Indeterminate []string

	// Missing is which capabilities were unavailable. Stored because it is what makes a
	// message re-runnable: when a downed service returns, the messages worth
	// re-evaluating are exactly the ones that named it.
	Missing []string
}

// SenderEvent is one entry in the append-only profile history.
type SenderEvent struct {
	TenantID     string
	At           time.Time
	SenderEmail  string
	SenderDomain string
	ReplyTo      string
	Direction    string
	Verdict      string
	AuthFailed   bool
}

// PutMessage writes a message, its verdict and its sender event as one unit.
//
// One transaction, because the three are one fact. A message in the corpus with no
// sender event would be invisible to every future profile query, and a profile counting
// a message the corpus does not hold could never be rebuilt.
func (s *Store) PutMessage(ctx context.Context, m Message, v Verdict, e SenderEvent) error {
	m.sanitise()
	v.sanitise()
	e.sanitise()

	// Idempotent by (tenant, message_id). DuckLake has no unique constraints, so this is
	// a read before the write, and it earns its cost: a retried delivery that appends a
	// second row inflates the sender's message count, which moves prevalence from "new"
	// to "outlier" and silently stops every first-contact rule from firing. A duplicate
	// here is a worse failure than a slightly slower ingest.
	dup, err := s.hasMessage(ctx, m.TenantID, m.MessageID)
	if err != nil {
		return fmt.Errorf("store: checking for a duplicate: %w", err)
	}
	if dup {
		return ErrDuplicate
	}

	tx, err := s.duck.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: beginning corpus write: %w", err)
	}
	defer tx.Rollback()

	day := m.ReceivedAt.UTC().Format("2006-01-02")

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO corpus.messages
		  (tenant_id, message_id, received_at, day, sender_email, sender_domain,
		   subject, direction, verdict, mdm, raw_key, recipients, analysis, evidence,
		   fingerprint)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.TenantID, m.MessageID, m.ReceivedAt.UTC(), day, m.SenderEmail, m.SenderDomain,
		m.Subject, m.Direction, m.Verdict, string(m.MDM), m.RawKey,
		strs(m.Recipients), string(m.Analysis), string(m.Evidence),
		int64(m.Fingerprint)); err != nil {
		return fmt.Errorf("store: writing message: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO corpus.verdicts
		  (tenant_id, message_id, day, verdict, matched, indeterminate, missing, evaluated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.TenantID, v.MessageID, day, v.Verdict,
		strs(v.Matched), strs(v.Indeterminate), strs(v.Missing), v.At.UTC()); err != nil {
		return fmt.Errorf("store: writing verdict: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO corpus.sender_events
		  (tenant_id, occurred_at, day, sender_email, sender_domain, reply_to, direction, verdict, auth_failed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TenantID, e.At.UTC(), e.At.UTC().Format("2006-01-02"),
		e.SenderEmail, e.SenderDomain, e.ReplyTo, e.Direction, e.Verdict, e.AuthFailed); err != nil {
		return fmt.Errorf("store: writing sender event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing corpus write: %w", err)
	}
	return s.refreshProfile(ctx, e)
}

// ErrDuplicate reports that a message with this id is already stored for this tenant.
//
// Not an error in the usual sense: the caller has the analysis and the corpus already
// holds the message, so the right response is 200 with a note rather than a failure.
var ErrDuplicate = errors.New("store: message already recorded")

func (s *Store) hasMessage(ctx context.Context, tenant, messageID string) (bool, error) {
	var n int
	err := s.duck.QueryRowContext(ctx,
		`SELECT count(*) FROM corpus.messages WHERE tenant_id = ? AND message_id = ?`,
		tenant, messageID).Scan(&n)
	return n > 0, err
}

// NUL bytes are removed from every string before it reaches DuckLake, because a
// DuckLake catalog is a Postgres database and Postgres cannot store a NUL in a text
// column at all — but the failure does not arrive as a clean rejection. DuckLake
// composes its catalog statements as SQL text and hands them to postgres_execute, so
// a NUL terminates the statement early and the whole transaction fails with a syntax
// error naming a fragment of some other row. Observed both ways: a NUL in a list
// element fails the commit, and a NUL in a value used as a query parameter fails the
// *read*, because the catalog pushdown concatenates it too.
//
// This is a write-path denial of service reachable from a message header, which is to
// say from whoever sent the mail: one crafted address and the corpus stops accepting
// anything. It is not an injection — the quoting around the truncation is correct, and
// truncating discards the attacker's text rather than executing it — but a sender who
// can stop a security platform recording mail has achieved most of what they wanted.
//
// Stripping rather than rejecting, because a NUL cannot be legitimate here. RFC 5322
// excludes it from every header production, so its presence is either a parser artefact
// or deliberate, and dropping the whole message would hand the same sender a way to
// make mail disappear instead.
func withoutNUL(v string) string {
	if !strings.ContainsRune(v, 0) {
		return v
	}
	return strings.ReplaceAll(v, "\x00", "")
}

func cleanAll(vs []string) []string {
	for i, v := range vs {
		vs[i] = withoutNUL(v)
	}
	return vs
}

func (m *Message) sanitise() {
	m.TenantID = withoutNUL(m.TenantID)
	m.MessageID = withoutNUL(m.MessageID)
	m.SenderEmail = withoutNUL(m.SenderEmail)
	m.SenderDomain = withoutNUL(m.SenderDomain)
	m.Subject = withoutNUL(m.Subject)
	m.Direction = withoutNUL(m.Direction)
	m.Verdict = withoutNUL(m.Verdict)
	m.RawKey = withoutNUL(m.RawKey)
	if bytes.IndexByte(m.Analysis, 0) >= 0 {
		m.Analysis = bytes.ReplaceAll(m.Analysis, []byte{0}, nil)
	}
	m.Recipients = cleanAll(m.Recipients)
	if bytes.IndexByte(m.MDM, 0) >= 0 {
		m.MDM = bytes.ReplaceAll(m.MDM, []byte{0}, nil)
	}
}

func (v *Verdict) sanitise() {
	v.TenantID = withoutNUL(v.TenantID)
	v.MessageID = withoutNUL(v.MessageID)
	v.Verdict = withoutNUL(v.Verdict)
	v.Matched = cleanAll(v.Matched)
	v.Indeterminate = cleanAll(v.Indeterminate)
	v.Missing = cleanAll(v.Missing)
}

func (e *SenderEvent) sanitise() {
	e.TenantID = withoutNUL(e.TenantID)
	e.SenderEmail = withoutNUL(e.SenderEmail)
	e.SenderDomain = withoutNUL(e.SenderDomain)
	e.ReplyTo = withoutNUL(e.ReplyTo)
	e.Direction = withoutNUL(e.Direction)
	e.Verdict = withoutNUL(e.Verdict)
}

// strs binds a Go slice as a DuckDB VARCHAR[] parameter.
//
// The driver binds []string natively; the only thing this adds is a non-nil empty
// slice, because a nil one binds as NULL and a message with no recipients has an
// empty recipient list rather than an unknown one.
//
// It exists at all because the first version of this file built the list as a SQL
// literal with quotes doubled. That is escaping rather than binding, and recipients
// come from message headers — i.e. from whoever sent the mail. Escaping message
// content into SQL text is the wrong shape even when the escaping is correct, because
// its correctness then has to be re-argued every time the code around it moves.
func strs(vs []string) []string {
	if vs == nil {
		return []string{}
	}
	return vs
}

// AnalysisByID returns the stored analysis for a message, or nil if none was kept.
//
// nil is an ordinary answer, not an error: messages ingested before the column
// existed have none, and the caller falls back to evaluating on demand.
func (s *Store) AnalysisByID(ctx context.Context, tenant, messageID string) ([]byte, error) {
	var raw *string
	err := s.duck.QueryRowContext(ctx,
		`SELECT analysis FROM corpus.messages WHERE tenant_id = ? AND message_id = ?
		 ORDER BY received_at DESC LIMIT 1`, tenant, messageID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	if raw == nil || *raw == "" {
		return nil, nil
	}
	return []byte(*raw), nil
}

// MDMByID returns one message's model.
func (s *Store) MDMByID(ctx context.Context, tenant, messageID string) ([]byte, error) {
	var raw string
	err := s.duck.QueryRowContext(ctx,
		`SELECT mdm FROM corpus.messages WHERE tenant_id = ? AND message_id = ?
		 ORDER BY received_at DESC LIMIT 1`, tenant, messageID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

// Scan walks the corpus for a tenant and window, yielding each message's model.
//
// This is what hunt runs over. The window is a partition predicate rather than a filter:
// DuckLake prunes by `day`, so a 30-day hunt over a year of mail reads a thirtieth of
// the files rather than all of them and discards the rest.
//
// The models come back whole, and MQL is evaluated over them in Go. Compiling MQL to
// SQL would be faster and would be a second implementation of the language's semantics —
// which, in an engine whose central claim is that its semantics match, is the one
// optimisation worth refusing. A hunt that disagrees with live evaluation is worse than
// a hunt that is slow.
func (s *Store) Scan(ctx context.Context, tenant string, from, to time.Time, fn func(messageID string, mdm []byte) error) (int, error) {
	return s.ScanWithEvidence(ctx, tenant, from, to,
		func(id string, mdm, _ []byte) error { return fn(id, mdm) })
}

// ScanWithEvidence is Scan, and also hands back what enrichment answered.
//
// The evidence is what turns a hunt from "the 545 rules that need nothing" into all of
// them. It comes back beside the model rather than being fetched per message, because
// the alternative is a query per row against a columnar store, which is the slowest
// possible way to read a column.
//
// Evidence is empty for anything ingested before it was kept, and for a message the
// enrichers never answered anything about. A caller must treat empty as "cannot decide"
// rather than "nothing was found" — see mql.NewReplay, which turns a missing answer into
// unavailable rather than null.
func (s *Store) ScanWithEvidence(ctx context.Context, tenant string, from, to time.Time,
	fn func(messageID string, mdm, evidence []byte) error) (int, error) {

	rows, err := s.duck.QueryContext(ctx, `
		SELECT message_id, mdm, coalesce(evidence, '') FROM corpus.messages
		WHERE tenant_id = ? AND day >= ? AND day <= ?
		ORDER BY received_at`,
		tenant, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02"))
	if err != nil {
		return 0, fmt.Errorf("store: scanning corpus: %w", err)
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id, mdm, evidence string
		if err := rows.Scan(&id, &mdm, &evidence); err != nil {
			return n, err
		}
		n++
		if err := fn(id, []byte(mdm), []byte(evidence)); err != nil {
			return n, err
		}
	}
	return n, rows.Err()
}

// ScannedMessage is one row of a corpus walk, with enough beside the model to render
// a result without a second query per message.
type ScannedMessage struct {
	MessageID   string
	ReceivedAt  time.Time
	Subject     string
	SenderEmail string
	Verdict     string

	// MDM is the parsed model, serialised.
	MDM []byte

	// Evidence is what enrichment answered, or empty for a message ingested before
	// it was kept. Empty means undecidable, never clean — see mql.NewReplay.
	Evidence []byte
}

// ScanMessagesWithEvidence walks the corpus yielding whole rows.
//
// Scan and ScanWithEvidence hand back the model alone, which is all a hunt needs
// because a hunt only reports message ids. A backtest has to show a person what a rule
// would have caught, and fetching the subject and sender per hit afterwards is a query
// per row against a columnar store — the slowest way there is to read two columns.
func (s *Store) ScanMessagesWithEvidence(ctx context.Context, tenant string, from, to time.Time,
	fn func(ScannedMessage) error) (int, error) {

	rows, err := s.duck.QueryContext(ctx, `
		SELECT message_id, received_at, coalesce(subject, ''), coalesce(sender_email, ''),
		       coalesce(verdict, ''), mdm, coalesce(evidence, '')
		FROM corpus.messages
		WHERE tenant_id = ? AND day >= ? AND day <= ?
		ORDER BY received_at`,
		tenant, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02"))
	if err != nil {
		return 0, fmt.Errorf("store: scanning corpus: %w", err)
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var m ScannedMessage
		var mdmText, evidence string
		if err := rows.Scan(&m.MessageID, &m.ReceivedAt, &m.Subject, &m.SenderEmail,
			&m.Verdict, &mdmText, &evidence); err != nil {
			return n, err
		}
		m.MDM = []byte(mdmText)
		m.Evidence = []byte(evidence)
		n++
		if err := fn(m); err != nil {
			return n, err
		}
	}
	return n, rows.Err()
}

// EvidenceByID returns the frozen enrichment for one message, or nil.
func (s *Store) EvidenceByID(ctx context.Context, tenant, id string) ([]byte, error) {
	var evidence string
	err := s.duck.QueryRowContext(ctx,
		`SELECT coalesce(evidence, '') FROM corpus.messages
		 WHERE tenant_id = ? AND message_id = ?
		 ORDER BY received_at DESC LIMIT 1`, tenant, id).Scan(&evidence)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if evidence == "" {
		return nil, nil
	}
	return []byte(evidence), nil
}

// MessagesMissing lists messages whose evaluation needed a capability that was
// unavailable, so they can be re-run once it returns.
//
// This is the operational payoff of recording the missing set rather than collapsing
// indeterminate into no-match. When the ML container comes back, the messages worth
// re-evaluating are exactly the ones that said they needed it.
func (s *Store) MessagesMissing(ctx context.Context, tenant, capability string, from, to time.Time) ([]string, error) {
	rows, err := s.duck.QueryContext(ctx, `
		SELECT message_id FROM corpus.verdicts
		WHERE tenant_id = ? AND day >= ? AND day <= ? AND list_contains(missing, ?)
		ORDER BY evaluated_at`,
		tenant, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02"), capability)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Stats summarises what a tenant holds, for the health endpoint.
type Stats struct {
	Messages      int64     `json:"messages"`
	Verdicts      int64     `json:"verdicts"`
	SenderEvents  int64     `json:"sender_events"`
	OldestMessage time.Time `json:"oldest_message,omitempty"`
	NewestMessage time.Time `json:"newest_message,omitempty"`
}

// Stats counts what is stored for a tenant.
func (s *Store) Stats(ctx context.Context, tenant string) (Stats, error) {
	var st Stats
	var oldest, newest *time.Time
	err := s.duck.QueryRowContext(ctx, `
		SELECT count(*),
		       min(received_at),
		       max(received_at)
		FROM corpus.messages WHERE tenant_id = ?`, tenant).Scan(&st.Messages, &oldest, &newest)
	if err != nil {
		return st, err
	}
	if oldest != nil {
		st.OldestMessage = *oldest
	}
	if newest != nil {
		st.NewestMessage = *newest
	}
	_ = s.duck.QueryRowContext(ctx, `SELECT count(*) FROM corpus.verdicts WHERE tenant_id = ?`, tenant).Scan(&st.Verdicts)
	_ = s.duck.QueryRowContext(ctx, `SELECT count(*) FROM corpus.sender_events WHERE tenant_id = ?`, tenant).Scan(&st.SenderEvents)
	return st, nil
}

// Compact flushes inlined writes to Parquet and merges the result.
//
// The order matters, and the first call is the one that is easy to omit. DuckLake
// *inlines* small writes into the catalog database — that is the feature that makes
// message-at-a-time ingest viable, since a Parquet file per message would be
// unusable — but inlined data lives in Postgres until it is flushed. Without
// ducklake_flush_inlined_data the corpus never reaches the blob store at all, and the
// storage design inverts itself: Postgres ends up holding the message bodies it was
// specifically chosen not to hold. Merging alone does not do it, because there are no
// files yet to merge.
//
// Then: merge the many small Parquet files a flush produces, expire old snapshots, and
// delete the files nothing references any more.
//
// Scheduled by the engine rather than left to an operator to remember, and exposed so
// it can be run out of hours.
func (s *Store) Compact(ctx context.Context) error {
	for _, stmt := range []string{
		"CALL ducklake_flush_inlined_data('corpus')",
		"CALL ducklake_merge_adjacent_files('corpus')",
		"CALL ducklake_expire_snapshots('corpus', older_than => now() - INTERVAL 7 DAY)",
		"CALL ducklake_cleanup_old_files('corpus', cleanup_all => true)",
	} {
		if _, err := s.duck.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: %s: %w", stmt, err)
		}
	}
	return nil
}

// mdmJSON is a convenience for callers holding a model rather than bytes.
func mdmJSON(v any) ([]byte, error) { return json.Marshal(v) }

// Listing and aggregating, for the triage and insight views.
//
// These are the queries a dashboard makes, and they are the reason the corpus is
// columnar rather than a row store: a verdict count by day over a year of mail reads
// two columns, and DuckLake prunes to the partitions in range before reading anything.

// Summary is one row in the triage list. Deliberately not the whole model — a list of
// two hundred messages does not need two hundred parsed MDMs, and sending them would
// make the page slow in a way no amount of front-end work fixes.
type Summary struct {
	MessageID  string    `json:"message_id"`
	ReceivedAt time.Time `json:"received_at"`
	Sender     string    `json:"sender"`
	Subject    string    `json:"subject"`
	Direction  string    `json:"direction"`
	Verdict    string    `json:"verdict"`
	Matched    []string  `json:"matched"`
	Missing    []string  `json:"missing,omitempty"`
	LastAction string    `json:"last_action,omitempty"`

	// TriageState travels with the list so the queues are one request rather than one
	// per row. Absence means unreviewed: nobody has looked, which is itself a state.
	TriageState string `json:"triage_state,omitempty"`
}

// ListOptions filter the triage list.
type ListOptions struct {
	Verdict string
	Sender  string
	Search  string
	From    time.Time
	To      time.Time
	Limit   int
	Offset  int
}

// List returns messages newest first.
func (s *Store) List(ctx context.Context, tenant string, opts ListOptions) ([]Summary, error) {
	if opts.Limit <= 0 || opts.Limit > 500 {
		opts.Limit = 100
	}
	if opts.To.IsZero() {
		opts.To = time.Now().UTC().AddDate(0, 0, 1)
	}
	if opts.From.IsZero() {
		opts.From = opts.To.AddDate(0, 0, -30)
	}

	// A left join, because a message is written with its verdict in one transaction but
	// the two are separate tables: an inner join would hide anything mid-write.
	query := `
		SELECT m.message_id, m.received_at, coalesce(m.sender_email, ''),
		       coalesce(m.subject, ''), coalesce(m.direction, ''), m.verdict,
		       coalesce(v.matched, []), coalesce(v.missing, [])
		FROM corpus.messages m
		LEFT JOIN corpus.verdicts v
		  ON v.tenant_id = m.tenant_id AND v.message_id = m.message_id
		WHERE m.tenant_id = ? AND m.day >= ? AND m.day <= ?`

	args := []any{tenant, opts.From.UTC().Format("2006-01-02"), opts.To.UTC().Format("2006-01-02")}
	if opts.Verdict != "" {
		query += " AND m.verdict = ?"
		args = append(args, opts.Verdict)
	}
	if opts.Sender != "" {
		query += " AND lower(m.sender_email) LIKE lower(?)"
		args = append(args, "%"+opts.Sender+"%")
	}
	if opts.Search != "" {
		query += " AND lower(m.subject) LIKE lower(?)"
		args = append(args, "%"+opts.Search+"%")
	}
	query += " ORDER BY m.received_at DESC LIMIT ? OFFSET ?"
	args = append(args, opts.Limit, opts.Offset)

	rows, err := s.duck.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listing messages: %w", err)
	}
	defer rows.Close()

	var out []Summary
	for rows.Next() {
		var m Summary
		var matched, missing any
		if err := rows.Scan(&m.MessageID, &m.ReceivedAt, &m.Sender, &m.Subject,
			&m.Direction, &m.Verdict, &matched, &missing); err != nil {
			return nil, err
		}
		m.Matched, m.Missing = toStrings(matched), toStrings(missing)
		out = append(out, m)
	}
	return out, rows.Err()
}

// toStrings unpacks a DuckDB list column, which the driver hands back as []any.
func toStrings(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Insights are the aggregate views a dashboard opens with.
type Insights struct {
	ByDay      []DayCount       `json:"by_day"`
	TopRules   []NameCount      `json:"top_rules"`
	TopSenders []NameCount      `json:"top_senders"`
	Missing    []NameCount      `json:"missing_capabilities"`
	Totals     map[string]int64 `json:"totals"`
}

// DayCount is one day's verdict counts.
type DayCount struct {
	Day           string `json:"day"`
	Malicious     int64  `json:"malicious"`
	Indeterminate int64  `json:"indeterminate"`
	Clean         int64  `json:"clean"`
}

// NameCount is a ranked pair.
type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// Insights computes the aggregate views over a window.
func (s *Store) Insights(ctx context.Context, tenant string, from, to time.Time) (*Insights, error) {
	f, t := from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02")
	out := &Insights{Totals: map[string]int64{}}

	byDay, err := s.duck.QueryContext(ctx, `
		SELECT strftime(day, '%Y-%m-%d') AS d,
		       count(*) FILTER (verdict = 'malicious'),
		       count(*) FILTER (verdict = 'indeterminate'),
		       count(*) FILTER (verdict = 'clean')
		FROM corpus.messages
		WHERE tenant_id = ? AND day >= ? AND day <= ?
		GROUP BY d ORDER BY d`, tenant, f, t)
	if err != nil {
		return nil, fmt.Errorf("store: insights by day: %w", err)
	}
	for byDay.Next() {
		var d DayCount
		if err := byDay.Scan(&d.Day, &d.Malicious, &d.Indeterminate, &d.Clean); err != nil {
			byDay.Close()
			return nil, err
		}
		out.ByDay = append(out.ByDay, d)
		out.Totals["malicious"] += d.Malicious
		out.Totals["indeterminate"] += d.Indeterminate
		out.Totals["clean"] += d.Clean
	}
	byDay.Close()

	// unnest turns the matched-rule list back into rows. Storing the list rather than a
	// row per (message, rule) is what keeps the corpus from being 228 million rows a
	// day; unnesting at read time is the price, and it is paid by one query rather than
	// by every write.
	out.TopRules, err = s.ranked(ctx, `
		SELECT r, count(*) FROM (
			SELECT unnest(matched) AS r FROM corpus.verdicts
			WHERE tenant_id = ? AND day >= ? AND day <= ?
		) WHERE r IS NOT NULL AND r <> '' GROUP BY r ORDER BY 2 DESC LIMIT 10`, tenant, f, t)
	if err != nil {
		return nil, fmt.Errorf("store: insights top rules: %w", err)
	}

	out.TopSenders, err = s.ranked(ctx, `
		SELECT lower(sender_email), count(*) FROM corpus.messages
		WHERE tenant_id = ? AND day >= ? AND day <= ?
		  AND verdict = 'malicious' AND sender_email IS NOT NULL AND sender_email <> ''
		GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, tenant, f, t)
	if err != nil {
		return nil, fmt.Errorf("store: insights top senders: %w", err)
	}

	// What the deployment could not answer, ranked. This is the honest counterpart to
	// the detection numbers: a dashboard that shows only what fired, and not what could
	// not be evaluated, is the kind of report that makes a partial system look complete.
	out.Missing, err = s.ranked(ctx, `
		SELECT c, count(*) FROM (
			SELECT unnest(missing) AS c FROM corpus.verdicts
			WHERE tenant_id = ? AND day >= ? AND day <= ?
		) WHERE c IS NOT NULL AND c <> '' GROUP BY c ORDER BY 2 DESC LIMIT 10`, tenant, f, t)
	if err != nil {
		return nil, fmt.Errorf("store: insights missing: %w", err)
	}

	return out, nil
}

func (s *Store) ranked(ctx context.Context, query string, args ...any) ([]NameCount, error) {
	rows, err := s.duck.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []NameCount
	for rows.Next() {
		var n NameCount
		if err := rows.Scan(&n.Name, &n.Count); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// LastActions returns the most recent action per message, for the triage list.
func (s *Store) LastActions(ctx context.Context, tenant string, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pg.Query(ctx, `
		SELECT DISTINCT ON (message_id) message_id, action
		FROM actions WHERE tenant_id = $1 AND message_id = ANY($2)
		ORDER BY message_id, at DESC`, tenant, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, action string
		if err := rows.Scan(&id, &action); err != nil {
			return nil, err
		}
		out[id] = action
	}
	return out, rows.Err()
}

// RuleStat is one rule's record over a window.
type RuleStat struct {
	Rule       string `json:"rule"`
	Fired      int64  `json:"fired"`
	Confirmed  int64  `json:"confirmed"`
	Benign     int64  `json:"benign"`
	Ignored    int64  `json:"ignored"`
	Unreviewed int64  `json:"unreviewed"`

	// FalsePositive is an analyst saying the rule was wrong. This is the number that
	// should make someone look at the rule.
	FalsePositive int64 `json:"false_positive"`

	// AcceptedRisk is an analyst saying the rule was right and the message was
	// wanted anyway. Counted apart from FalsePositive precisely so it does not look
	// like evidence against the rule.
	AcceptedRisk int64 `json:"accepted_risk"`
}

// PrecisionKnown reports whether enough of this rule's hits have been reviewed to say
// anything about it. A rule with two reviews and both benign is not a bad rule, it is
// an unmeasured one, and presenting 0% precision for it would be a lie told with
// arithmetic.
func (r RuleStat) PrecisionKnown() bool { return r.reviewed() >= 5 }

// Precision is confirmed over reviewed. Meaningless unless PrecisionKnown.
//
// An accepted risk counts as *confirmed*, not as a miss. The analyst agreed the rule
// was right and let the message through anyway; a rule that correctly identifies a
// phishing simulation every month should not be scored as wrong every month.
func (r RuleStat) Precision() float64 {
	reviewed := r.reviewed()
	if reviewed == 0 {
		return 0
	}
	return float64(r.Confirmed+r.AcceptedRisk) / float64(reviewed)
}

func (r RuleStat) reviewed() int64 {
	return r.Confirmed + r.Benign + r.FalsePositive + r.AcceptedRisk
}

// RuleEffectiveness joins what fired to what an analyst then concluded.
//
// This is the only view in the product that can tell a rule generating detections from
// a rule generating work. Neither half is enough on its own: the corpus knows what
// fired and Postgres knows what a human decided, and the answer needs both.
func (s *Store) RuleEffectiveness(ctx context.Context, tenant string, from, to time.Time) ([]RuleStat, error) {
	rows, err := s.duck.QueryContext(ctx, `
		SELECT r, message_id FROM (
			SELECT unnest(matched) AS r, message_id FROM corpus.verdicts
			WHERE tenant_id = ? AND day >= ? AND day <= ?
		) WHERE r IS NOT NULL AND r <> ''`,
		tenant, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02"))
	if err != nil {
		return nil, fmt.Errorf("store: rule effectiveness: %w", err)
	}

	byRule := map[string][]string{}
	seen := map[string]bool{}
	var ids []string
	for rows.Next() {
		var rule, id string
		if err := rows.Scan(&rule, &id); err != nil {
			rows.Close()
			return nil, err
		}
		byRule[rule] = append(byRule[rule], id)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	states, err := s.TriageFor(ctx, tenant, ids)
	if err != nil {
		return nil, err
	}

	// What an analyst said when they released the message, which is a different
	// question from how they triaged it. "Accepted risk" means the rule was right
	// and the message was wanted anyway — a phishing simulation, a pen test, a
	// newsletter finance insists on — and counting that against the rule teaches
	// operators to tune away a detection that works.
	dispositions, err := s.Dispositions(ctx, tenant, ids)
	if err != nil {
		return nil, err
	}

	out := make([]RuleStat, 0, len(byRule))
	for rule, msgs := range byRule {
		st := RuleStat{Rule: rule, Fired: int64(len(msgs))}
		for _, id := range msgs {
			switch dispositions[id] {
			case DispositionFalsePositive:
				st.FalsePositive++
				continue
			case DispositionAcceptedRisk:
				st.AcceptedRisk++
				continue
			}
			switch states[id].State {
			case StateNeedsRemediation, StateRemediated:
				st.Confirmed++
			case StateBenign:
				st.Benign++
			case StateIgnored:
				st.Ignored++
			default:
				st.Unreviewed++
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fired > out[j].Fired })
	return out, nil
}

// RecipientList returns the addresses or domains this deployment receives mail for.
//
// $recipient_emails and $recipient_domains mean "is this one of ours", and 63 rules
// ask it — most often to catch a message that claims to be internal but was addressed
// from outside. Learned from delivered inbound mail rather than configured, so it
// stays correct as mailboxes are added and removed without anyone maintaining a list.
//
// Inbound and internal only. An address this organisation has written *to* is a
// correspondent, not a recipient of ours, and counting it would make every external
// party look like an internal mailbox — which is precisely backwards for the rules
// that use it.
func (s *Store) RecipientList(ctx context.Context, tenant, kind string) ([]string, error) {
	expr := "lower(r)"
	if kind == "domain" {
		expr = "lower(split_part(r, '@', 2))"
	}
	rows, err := s.duck.QueryContext(ctx, fmt.Sprintf(`
		SELECT DISTINCT %s FROM (
			SELECT unnest(recipients) AS r FROM corpus.messages
			WHERE tenant_id = ? AND direction <> 'outbound' AND recipients IS NOT NULL
		) WHERE r IS NOT NULL AND r <> '' AND (%s) <> ''
		ORDER BY 1`, expr, expr), tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetAnalysis replaces the stored detail-view analysis for a message.
//
// An UPDATE rather than an append: DuckLake has no unique constraint, so inserting a
// second row would leave two versions of the same message and every read would have
// to pick one. The analysis is a cache of a derivation, not a fact about the past —
// unlike the verdict, which is history and is never rewritten.
func (s *Store) SetAnalysis(ctx context.Context, tenant, messageID string, analysis []byte) error {
	_, err := s.duck.ExecContext(ctx,
		`UPDATE corpus.messages SET analysis = ? WHERE tenant_id = ? AND message_id = ?`,
		string(withoutNULBytes(analysis)), tenant, messageID)
	return err
}

func withoutNULBytes(b []byte) []byte {
	if bytes.IndexByte(b, 0) < 0 {
		return b
	}
	return bytes.ReplaceAll(b, []byte{0}, nil)
}

// MessageHead is the little a list view needs about a message it is referring to.
type MessageHead struct {
	Subject     string    `json:"subject,omitempty"`
	SenderEmail string    `json:"sender,omitempty"`
	ReceivedAt  time.Time `json:"received_at,omitempty"`
	Verdict     string    `json:"verdict,omitempty"`
}

// MessageHeads looks up several messages' headline fields at once.
//
// For a page that lists things pointing at messages — findings, for one — and has to
// show what each one is about. One query for the page rather than one per row, which is
// the difference between a page load and two hundred columnar scans.
func (s *Store) MessageHeads(ctx context.Context, tenant string, ids []string) (map[string]MessageHead, error) {
	out := map[string]MessageHead{}
	if len(ids) == 0 {
		return out, nil
	}
	// Built rather than passed as an array: the DuckDB driver has no array binding,
	// and every element is a placeholder, so nothing is interpolated.
	args := make([]any, 0, len(ids)+1)
	args = append(args, tenant)
	ph := make([]string, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args = append(args, id)
	}

	rows, err := s.duck.QueryContext(ctx, `
		SELECT DISTINCT ON (message_id) message_id, coalesce(subject,''),
		       coalesce(sender_email,''), received_at, coalesce(verdict,'')
		FROM corpus.messages
		WHERE tenant_id = ? AND message_id IN (`+strings.Join(ph, ",")+`)
		ORDER BY message_id, received_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var h MessageHead
		if err := rows.Scan(&id, &h.Subject, &h.SenderEmail, &h.ReceivedAt, &h.Verdict); err != nil {
			return nil, err
		}
		out[id] = h
	}
	return out, rows.Err()
}

// CampaignMember is one message as a campaign view needs it.
//
// Deliberately thin. Clustering reads every message in the window, and pulling each
// one's model to find its links would turn a columnar scan of five columns into a
// megabyte per row.
type CampaignMember struct {
	MessageID   string    `json:"message_id"`
	ReceivedAt  time.Time `json:"received_at"`
	Subject     string    `json:"subject,omitempty"`
	SenderEmail string    `json:"sender,omitempty"`
	Verdict     string    `json:"verdict,omitempty"`
	Triage      string    `json:"triage,omitempty"`

	// LinkDomains is what the message pointed at, for the "all of these reach the
	// same host" summary. Extracted at read time from the stored model's links.
	LinkDomains []string `json:"link_domains,omitempty"`

	// Fingerprint is what the grouping is done on, and is not shown.
	Fingerprint uint64 `json:"-"`
}

// CampaignCandidates reads the fingerprinted messages in a window.
//
// Only fingerprinted ones: a message ingested before fingerprints existed has nothing
// to cluster on, and including it as a zero would put every such message in one group.
func (s *Store) CampaignCandidates(ctx context.Context, tenant string, from, to time.Time, limit int) ([]CampaignMember, error) {
	if limit <= 0 || limit > 200000 {
		limit = 50000
	}
	rows, err := s.duck.QueryContext(ctx, `
		SELECT message_id, received_at, coalesce(subject,''), coalesce(sender_email,''),
		       coalesce(verdict,''), fingerprint,
		       -- json_extract, cast to text. A wildcard path yields a LIST, and
		       -- json_extract_string would hand the driver a list of values it
		       -- cannot scan into a string. Casting the JSON form gives one text
		       -- value, a JSON array, which uniqueStrings parses.
		       coalesce(CAST(json_extract(mdm, '$.body.links[*].href_url.domain.root_domain') AS VARCHAR), '')
		FROM corpus.messages
		WHERE tenant_id = ? AND day >= ? AND day <= ?
		  AND fingerprint IS NOT NULL AND fingerprint != 0
		ORDER BY received_at DESC
		LIMIT ?`,
		tenant, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02"), limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading campaign candidates: %w", err)
	}
	defer rows.Close()

	out := []CampaignMember{}
	for rows.Next() {
		var m CampaignMember
		var fp int64
		var domains string
		if err := rows.Scan(&m.MessageID, &m.ReceivedAt, &m.Subject, &m.SenderEmail,
			&m.Verdict, &fp, &domains); err != nil {
			return nil, err
		}
		m.Fingerprint = uint64(fp)
		m.LinkDomains = uniqueStrings(domains)
		out = append(out, m)
	}
	return out, rows.Err()
}

// uniqueStrings reads the JSON array json_extract_string returns for a wildcard path,
// which is a string like `["a","b","a"]` — or an empty string when nothing matched.
func uniqueStrings(raw string) []string {
	if raw == "" || raw == "[]" {
		return nil
	}
	var all []string
	if err := json.Unmarshal([]byte(raw), &all); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range all {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
