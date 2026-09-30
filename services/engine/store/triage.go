// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"fmt"
	"time"
)

// Triage state: where a message is in an investigation.
//
// Kept in Postgres rather than the corpus, and that is the whole reason it exists as a
// separate table. The corpus is append-only and immutable — it records what arrived and
// what the rules concluded — while "has anyone looked at this yet" changes repeatedly.
// Storing it alongside the message would mean rewriting an immutable record every time
// an analyst clicked something.

// TriageState is where a message sits in the queue.
type TriageState string

const (
	// StateUnreviewed is the default: a rule fired and nobody has looked.
	StateUnreviewed TriageState = "unreviewed"

	// StateNeedsRemediation is reviewed, confirmed bad, and still in the mailbox.
	// The most urgent queue, because the message is live.
	StateNeedsRemediation TriageState = "needs_remediation"

	// StateRemediated is confirmed bad and dealt with.
	StateRemediated TriageState = "remediated"

	// StateBenign is reviewed and judged harmless: a false positive.
	StateBenign TriageState = "benign"

	// StateIgnored is reviewed and deliberately not acted on — graymail, a marketing
	// blast, something noisy but harmless. Distinct from benign because it means "do
	// not show me these" rather than "the rule was wrong".
	StateIgnored TriageState = "ignored"
)

// ValidTriageState reports whether a string is a state.
func ValidTriageState(s string) bool {
	switch TriageState(s) {
	case StateUnreviewed, StateNeedsRemediation, StateRemediated, StateBenign, StateIgnored:
		return true
	}
	return false
}

// Triage is one message's investigation state.
type Triage struct {
	MessageID  string      `json:"message_id"`
	State      TriageState `json:"state"`
	Assignee   string      `json:"assignee,omitempty"`
	ReviewedBy string      `json:"reviewed_by,omitempty"`
	ReviewedAt *time.Time  `json:"reviewed_at,omitempty"`
	Note       string      `json:"note,omitempty"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// SetTriage records a review.
func (s *Store) SetTriage(ctx context.Context, tenant, messageID string, t Triage, by string) error {
	if !ValidTriageState(string(t.State)) {
		return fmt.Errorf("store: %q is not a triage state", t.State)
	}
	// reviewed_by and reviewed_at are set only when the state leaves unreviewed, so
	// "who reviewed this" means what it says rather than "who last touched the row".
	var reviewedBy *string
	var reviewedAt *time.Time
	if t.State != StateUnreviewed {
		now := time.Now().UTC()
		reviewedBy, reviewedAt = &by, &now
	}

	_, err := s.pg.Exec(ctx, `
		INSERT INTO triage (tenant_id, message_id, state, assignee, reviewed_by, reviewed_at, note, updated_at)
		VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,NULLIF($7,''),now())
		ON CONFLICT (tenant_id, message_id) DO UPDATE SET
		  state = EXCLUDED.state,
		  assignee = coalesce(EXCLUDED.assignee, triage.assignee),
		  reviewed_by = coalesce(EXCLUDED.reviewed_by, triage.reviewed_by),
		  reviewed_at = coalesce(EXCLUDED.reviewed_at, triage.reviewed_at),
		  note = coalesce(EXCLUDED.note, triage.note),
		  updated_at = now()`,
		tenant, messageID, string(t.State), t.Assignee, reviewedBy, reviewedAt, t.Note)
	return err
}

// TriageFor returns the state of specific messages.
func (s *Store) TriageFor(ctx context.Context, tenant string, ids []string) (map[string]Triage, error) {
	out := map[string]Triage{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pg.Query(ctx, `
		SELECT message_id, state, coalesce(assignee,''), coalesce(reviewed_by,''),
		       reviewed_at, coalesce(note,''), updated_at
		FROM triage WHERE tenant_id = $1 AND message_id = ANY($2)`, tenant, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var t Triage
		if err := rows.Scan(&t.MessageID, &t.State, &t.Assignee, &t.ReviewedBy,
			&t.ReviewedAt, &t.Note, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out[t.MessageID] = t
	}
	return out, rows.Err()
}

// TriageCounts is the queue depth per state, for the navigation badges.
//
// Only messages a rule actually fired on are counted. A queue that includes every
// clean message is not a queue.
func (s *Store) TriageCounts(ctx context.Context, tenant string, flagged []string) (map[string]int, error) {
	out := map[string]int{}
	if len(flagged) == 0 {
		return out, nil
	}

	states, err := s.TriageFor(ctx, tenant, flagged)
	if err != nil {
		return nil, err
	}
	for _, id := range flagged {
		if t, ok := states[id]; ok {
			out[string(t.State)]++
		} else {
			out[string(StateUnreviewed)]++
		}
	}
	return out, nil
}

// FlaggedIDs returns the messages a rule fired on, which is the population triage
// works over.
func (s *Store) FlaggedIDs(ctx context.Context, tenant string, from, to time.Time) ([]string, error) {
	rows, err := s.duck.QueryContext(ctx, `
		SELECT message_id FROM corpus.messages
		WHERE tenant_id = ? AND day >= ? AND day <= ? AND verdict IN ('malicious', 'indeterminate')
		ORDER BY received_at DESC LIMIT 5000`,
		tenant, from.UTC().Format("2006-01-02"), to.UTC().Format("2006-01-02"))
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

// Disposition records why a flagged message was released.
//
// Two answers, and they say different things about the rule. "false_positive" means
// the rule was wrong and its effectiveness number should suffer. "accepted_risk"
// means the rule was right and someone wanted the message anyway — a phishing
// simulation, a penetration test, a newsletter the finance team insists on — and
// counting that against the rule would train an operator to tune away a working
// detection.
//
// Kept separate from the action log, which is append-only history. This is the
// current judgement about one message, and it can be revised.
const (
	DispositionFalsePositive = "false_positive"
	DispositionAcceptedRisk  = "accepted_risk"
)

// SetDisposition records an analyst's judgement about a released message.
func (s *Store) SetDisposition(ctx context.Context, tenant, messageID, disposition string) error {
	switch disposition {
	case DispositionFalsePositive, DispositionAcceptedRisk, "":
	default:
		return fmt.Errorf("store: unknown disposition %q", disposition)
	}
	_, err := s.pg.Exec(ctx, `
		INSERT INTO dispositions (tenant_id, message_id, disposition)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, message_id) DO UPDATE
		  SET disposition = EXCLUDED.disposition, at = now()`,
		tenant, messageID, disposition)
	return err
}

// Dispositions returns the judgement for each of the given messages.
func (s *Store) Dispositions(ctx context.Context, tenant string, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pg.Query(ctx,
		`SELECT message_id, disposition FROM dispositions WHERE tenant_id = $1 AND message_id = ANY($2)`,
		tenant, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, d string
		if err := rows.Scan(&id, &d); err != nil {
			return nil, err
		}
		out[id] = d
	}
	return out, rows.Err()
}

// FalsePositives returns the message ids an analyst judged wrongly flagged, for the
// effectiveness view.
func (s *Store) FalsePositives(ctx context.Context, tenant string) (map[string]bool, error) {
	rows, err := s.pg.Query(ctx,
		`SELECT message_id FROM dispositions WHERE tenant_id = $1 AND disposition = $2`,
		tenant, DispositionFalsePositive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
