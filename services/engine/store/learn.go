// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"time"
)

// Storage for the model learned from analyst reviews, and for the reviews it learns
// from.
//
// The model lives in Postgres rather than the corpus: it is a few kilobytes of
// weights, rewritten whole on every training run, and read on every ingest. DuckLake
// is built for appending columns of messages and scanning them, which is the
// opposite access pattern.

// LearnedModel is a stored model and enough about it to decide whether to believe it.
type LearnedModel struct {
	TenantID  string    `json:"tenant_id"`
	Version   int       `json:"version"`
	Weights   []byte    `json:"-"`
	TrainedAt time.Time `json:"trained_at"`
}

// NextModelVersion reserves the number the next model will carry.
//
// Separate from SaveModel because the version has to be inside the stored weights,
// not only in the row: the blob is what gets loaded at startup and reported on the
// page, and a model that knows its own version only while the process that trained
// it is alive will call itself version zero forever afterwards.
func (s *Store) NextModelVersion(ctx context.Context, tenant string) (int, error) {
	var next int
	err := s.pg.QueryRow(ctx,
		`SELECT coalesce(max(version), 0) + 1 FROM learned_models WHERE tenant_id = $1`,
		tenant).Scan(&next)
	return next, err
}

// SaveModel writes a version.
//
// Versioned rather than overwritten, so a model that turns out to be worse can be
// compared with what preceded it, and so an audit can answer "what was the system
// using on the day it made that decision".
func (s *Store) SaveModel(ctx context.Context, tenant string, version int, weights []byte) error {
	_, err := s.pg.Exec(ctx, `
		INSERT INTO learned_models (tenant_id, version, weights) VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, version) DO UPDATE SET weights = EXCLUDED.weights,
		                                               trained_at = now()`,
		tenant, version, weights)
	return err
}

// LatestModel returns the current model, or nil when none has been trained.
func (s *Store) LatestModel(ctx context.Context, tenant string) ([]byte, error) {
	var raw []byte
	err := s.pg.QueryRow(ctx,
		`SELECT weights FROM learned_models WHERE tenant_id = $1 ORDER BY version DESC LIMIT 1`,
		tenant).Scan(&raw)
	if err != nil {
		return nil, nil // no model yet is an ordinary state, not an error
	}
	return raw, nil
}

// ReviewedMessage is one analyst decision, as the trainer needs it.
type ReviewedMessage struct {
	MessageID string
	Analysis  []byte
	Bad       bool
}

// ReviewedMessages returns every message an analyst has judged, with the stored
// analysis that was in front of them.
//
// The join is the point: the label is the analyst's conclusion and the features come
// from what the system believed *at the time*. Recomputing the features now would
// train the model on today's rules against yesterday's decisions, and quietly teach
// it that a rule which has since been fixed used to be wrong.
func (s *Store) ReviewedMessages(ctx context.Context, tenant string, limit int) ([]ReviewedMessage, error) {
	if limit <= 0 {
		limit = 20000
	}

	// The labels, from Postgres: triage state, overridden by an explicit
	// disposition where one exists. A disposition is the more considered answer —
	// it is recorded at the moment of releasing a message, with a reason.
	rows, err := s.pg.Query(ctx, `
		SELECT t.message_id,
		       coalesce(d.disposition, ''),
		       t.state
		FROM triage t
		LEFT JOIN dispositions d ON d.tenant_id = t.tenant_id AND d.message_id = t.message_id
		WHERE t.tenant_id = $1 AND t.state <> 'unreviewed'
		LIMIT $2`, tenant, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type label struct{ bad bool }
	labels := map[string]label{}
	var ids []string
	for rows.Next() {
		var id, disposition, state string
		if err := rows.Scan(&id, &disposition, &state); err != nil {
			return nil, err
		}
		bad, ok := labelFor(state, disposition)
		if !ok {
			continue
		}
		labels[id] = label{bad: bad}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	// The features, from the corpus, where the stored analysis lives.
	out := make([]ReviewedMessage, 0, len(ids))
	for _, id := range ids {
		blob, err := s.AnalysisByID(ctx, tenant, id)
		if err != nil || len(blob) == 0 {
			// A reviewed message with no stored analysis predates the column.
			// Skipped rather than recomputed: recomputing would produce today's
			// features for yesterday's judgement.
			continue
		}
		out = append(out, ReviewedMessage{MessageID: id, Analysis: blob, Bad: labels[id].bad})
	}
	return out, nil
}

// labelFor turns a review into a label, and reports whether it is usable at all.
func labelFor(state, disposition string) (bad bool, ok bool) {
	// The disposition wins where there is one: it was recorded deliberately, with a
	// reason, at the moment of overriding the system.
	switch disposition {
	case DispositionFalsePositive:
		return false, true
	case DispositionAcceptedRisk:
		// The rule was right and the message was allowed anyway. A positive
		// example, and the distinction that makes this worth storing separately —
		// counting it as a false positive would teach the model to stop flagging
		// the phishing simulation it correctly caught.
		return true, true
	}

	switch TriageState(state) {
	case StateNeedsRemediation, StateRemediated:
		return true, true
	case StateBenign:
		return false, true
	case StateIgnored:
		// Noisy but harmless: not a false positive exactly, but not something this
		// deployment wants surfaced. For a model whose job is predicting analyst
		// agreement, that is a negative.
		return false, true
	}
	return false, false
}

// ForgetModels removes every learned model for a tenant.
func (s *Store) ForgetModels(ctx context.Context, tenant string) error {
	_, err := s.pg.Exec(ctx, `DELETE FROM learned_models WHERE tenant_id = $1`, tenant)
	return err
}
