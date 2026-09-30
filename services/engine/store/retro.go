// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Findings: what we learned about mail that had already been delivered.
//
// See the table comment in schema.sql for why this exists. The short version is that
// attribution lags delivery, so a pipeline that judges mail only on the way in is
// permanently one feed update and one re-registered link behind.
//
// Nothing here acts. A finding is surfaced and a person decides, on the same footing as
// a retrospective scan, which records verdicts and deliberately has no branch that
// removes anything.

// RetroFinding is one thing learned late about one message.
type RetroFinding struct {
	ID        string    `json:"id"`
	MessageID string    `json:"message_id"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Detail    string    `json:"detail,omitempty"`
	State     string    `json:"state"`
	FoundAt   time.Time `json:"found_at"`

	ReviewedBy string     `json:"reviewed_by,omitempty"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`

	// Subject and Sender are joined in for the list view, so a person can judge a
	// finding without opening every message.
	Subject string `json:"subject,omitempty"`
	Sender  string `json:"sender,omitempty"`
}

// Finding kinds.
const (
	FindingRule = "rule"
	FindingLink = "link"
)

// Finding states.
const (
	FindingNew       = "new"
	FindingDismissed = "dismissed"
	FindingActioned  = "actioned"
)

// RecordFinding files one, or leaves an existing one alone.
//
// Idempotent on (message, kind, source), because a sweep runs on a schedule and a link
// is checked more than once. Filing the same discovery nightly would bury the new ones
// under repeats of the old, which is the failure mode of every alerting system that
// does not do this.
//
// An existing finding is not revived: once somebody has dismissed a finding, a later
// sweep re-observing the same fact must not put it back in front of them.
func (s *Store) RecordFinding(ctx context.Context, tenant string, f RetroFinding) (bool, error) {
	if f.MessageID == "" || f.Kind == "" || f.Source == "" {
		return false, errors.New("store: a finding needs a message, a kind and a source")
	}
	id := findingID(tenant, f.MessageID, f.Kind, f.Source)
	tag, err := s.pg.Exec(ctx, `
		INSERT INTO retro_findings (id, tenant_id, message_id, kind, source, detail, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'new')
		ON CONFLICT (tenant_id, message_id, kind, source) DO NOTHING`,
		id, tenant, f.MessageID, f.Kind, f.Source, f.Detail)
	if err != nil {
		return false, fmt.Errorf("store: recording finding: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// findingID is derived rather than random, so the same discovery has the same id
// wherever it is filed from and a retry does not create a second row.
func findingID(tenant, message, kind, source string) string {
	h := sha256.Sum256([]byte(tenant + "\x00" + message + "\x00" + kind + "\x00" + source))
	return "rf_" + hex.EncodeToString(h[:8])
}

// Findings lists them, newest first.
func (s *Store) Findings(ctx context.Context, tenant, state string, limit int) ([]RetroFinding, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `SELECT id, message_id, kind, source, coalesce(detail,''), state, found_at,
	             coalesce(reviewed_by,''), reviewed_at
	      FROM retro_findings WHERE tenant_id = $1`
	args := []any{tenant}
	if state != "" {
		q += ` AND state = $2`
		args = append(args, state)
	}
	q += fmt.Sprintf(` ORDER BY found_at DESC LIMIT %d`, limit)

	rows, err := s.pg.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []RetroFinding{}
	for rows.Next() {
		var f RetroFinding
		if err := rows.Scan(&f.ID, &f.MessageID, &f.Kind, &f.Source, &f.Detail,
			&f.State, &f.FoundAt, &f.ReviewedBy, &f.ReviewedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// OpenFindings counts the ones nobody has dealt with, for the console's badge.
func (s *Store) OpenFindings(ctx context.Context, tenant string) (int, error) {
	var n int
	err := s.pg.QueryRow(ctx,
		`SELECT count(*) FROM retro_findings WHERE tenant_id = $1 AND state = 'new'`,
		tenant).Scan(&n)
	return n, err
}

// ResolveFinding records what a person decided about one.
func (s *Store) ResolveFinding(ctx context.Context, tenant, id, state, by string) error {
	switch state {
	case FindingDismissed, FindingActioned:
	default:
		return fmt.Errorf("store: %q is not a way to resolve a finding", state)
	}
	tag, err := s.pg.Exec(ctx, `
		UPDATE retro_findings SET state = $3, reviewed_by = NULLIF($4,''), reviewed_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenant, id, state, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("store: no such finding")
	}
	return nil
}

// WatchLink schedules a link to be looked at again.
//
// The digest is what it looked like when the message was judged. Keeping a digest
// rather than the page is deliberate: the question a later visit asks is "is this the
// same as it was", and storing every fetched page for every link in every message to
// answer it would be a corpus of its own.
func (s *Store) WatchLink(ctx context.Context, tenant, url, messageID, digest string, due time.Time) error {
	_, err := s.pg.Exec(ctx, `
		INSERT INTO link_watch (tenant_id, url, message_id, digest, due_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, url, message_id) DO NOTHING`,
		tenant, url, messageID, digest, due.UTC())
	return err
}

// WatchedLink is one due re-visit.
type WatchedLink struct {
	URL       string
	MessageID string
	Digest    string
	Attempts  int
}

// DueLinks claims links whose next visit is due.
//
// Claimed by pushing due_at forward before returning them, so two workers — or the
// same worker on an overlapping tick — do not both fetch the same URL. A crash between
// claiming and fetching loses one round of checking for that link, which is the right
// way round: the alternative is a lock somebody has to clean up.
func (s *Store) DueLinks(ctx context.Context, tenant string, limit int, retryIn time.Duration) ([]WatchedLink, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pg.Query(ctx, `
		UPDATE link_watch SET due_at = now() + $3::interval, attempts = attempts + 1
		WHERE (tenant_id, url, message_id) IN (
			SELECT tenant_id, url, message_id FROM link_watch
			WHERE tenant_id = $1 AND due_at <= now()
			ORDER BY due_at LIMIT $2
		)
		RETURNING url, message_id, digest, attempts`,
		tenant, limit, fmt.Sprintf("%d seconds", int(retryIn.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("store: claiming due links: %w", err)
	}
	defer rows.Close()

	out := []WatchedLink{}
	for rows.Next() {
		var w WatchedLink
		if err := rows.Scan(&w.URL, &w.MessageID, &w.Digest, &w.Attempts); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// StopWatching removes a link from the schedule, once it has been checked enough times
// or has already told us what we wanted to know.
func (s *Store) StopWatching(ctx context.Context, tenant, url, messageID string) error {
	_, err := s.pg.Exec(ctx,
		`DELETE FROM link_watch WHERE tenant_id = $1 AND url = $2 AND message_id = $3`,
		tenant, url, messageID)
	return err
}

// WatchedCount is how many links are currently scheduled, for the console.
func (s *Store) WatchedCount(ctx context.Context, tenant string) (int, error) {
	var n int
	err := s.pg.QueryRow(ctx,
		`SELECT count(*) FROM link_watch WHERE tenant_id = $1`, tenant).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return n, err
}
