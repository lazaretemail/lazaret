// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Retrospective scans.
//
// See the table comment in schema.sql for why the state lives here and why the walk
// is oldest-first. In short: a connector is replaceable and a ninety-day scan is not,
// and sender profiles answer from events strictly before the message being judged, so
// the order the history is rebuilt in is the order it is believed in.

// Backfill states.
const (
	BackfillPending   = "pending"
	BackfillRunning   = "running"
	BackfillPaused    = "paused"
	BackfillDone      = "done"
	BackfillFailed    = "failed"
	BackfillCancelled = "cancelled"
)

// ErrBackfillExists reports an active scan already running for a mailbox.
var ErrBackfillExists = errors.New("store: a scan of this mailbox is already running")

// Backfill is one retrospective scan.
type Backfill struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	MailboxID string    `json:"mailbox_id"`
	Since     time.Time `json:"since"`
	Until     time.Time `json:"until"`
	State     string    `json:"state"`

	// Cursor is how far the walk has reached, in the mailbox's own time.
	Cursor *time.Time `json:"cursor,omitempty"`

	Examined   int64 `json:"examined"`
	Ingested   int64 `json:"ingested"`
	Duplicates int64 `json:"duplicates"`
	Flagged    int64 `json:"flagged"`
	Failures   int64 `json:"failures"`

	KeepRaw bool `json:"keep_raw"`

	LastError string `json:"last_error,omitempty"`

	// When LastError happened. The error text survives every later batch, and the
	// count of Failures is what gives it scale, so without this a single failure
	// from hours ago is indistinguishable from a scan that is failing right now.
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`

	ClaimedBy  string     `json:"claimed_by,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Active reports whether this scan is still going to do work.
func (b Backfill) Active() bool {
	switch b.State {
	case BackfillPending, BackfillRunning, BackfillPaused:
		return true
	}
	return false
}

// Progress is how far through the window the cursor has reached, 0 to 1.
//
// By time rather than by message count, because the count is unknown until the walk
// finishes. It is an honest approximation: mail is not evenly distributed through a
// window, so this moves unevenly.
func (b Backfill) Progress() float64 {
	if b.Cursor == nil {
		return 0
	}
	span := b.Until.Sub(b.Since)
	if span <= 0 {
		return 1
	}
	done := b.Cursor.Sub(b.Since)
	switch {
	case done <= 0:
		return 0
	case done >= span:
		return 1
	default:
		return float64(done) / float64(span)
	}
}

// CreateBackfill records a new scan.
//
// Refuses a second active scan of the same mailbox: two walking the same window would
// deliver every message twice and overwrite each other's cursor.
func (s *Store) CreateBackfill(ctx context.Context, b Backfill) (*Backfill, error) {
	if b.MailboxID == "" {
		return nil, errors.New("store: a scan needs a mailbox")
	}
	if !b.Until.After(b.Since) {
		return nil, errors.New("store: the scan window ends before it starts")
	}

	id, err := randomID("bf")
	if err != nil {
		return nil, err
	}
	_, err = s.pg.Exec(ctx, `
		INSERT INTO backfills (id, tenant_id, mailbox_id, since, until, keep_raw, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''))`,
		id, b.TenantID, b.MailboxID, b.Since.UTC(), b.Until.UTC(), b.KeepRaw, b.CreatedBy)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrBackfillExists
		}
		return nil, err
	}
	return s.BackfillByID(ctx, b.TenantID, id)
}

const backfillColumns = `id, tenant_id, mailbox_id, since, until, state, cursor,
	examined, ingested, duplicates, flagged, failures, keep_raw,
	coalesce(last_error,''), last_error_at, coalesce(claimed_by,''), coalesce(created_by,''),
	created_at, updated_at, finished_at`

func scanBackfill(row pgx.Row) (*Backfill, error) {
	var b Backfill
	err := row.Scan(&b.ID, &b.TenantID, &b.MailboxID, &b.Since, &b.Until, &b.State,
		&b.Cursor, &b.Examined, &b.Ingested, &b.Duplicates, &b.Flagged, &b.Failures,
		&b.KeepRaw, &b.LastError, &b.LastErrorAt, &b.ClaimedBy, &b.CreatedBy,
		&b.CreatedAt, &b.UpdatedAt, &b.FinishedAt)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// BackfillByID returns one scan.
func (s *Store) BackfillByID(ctx context.Context, tenant, id string) (*Backfill, error) {
	return scanBackfill(s.pg.QueryRow(ctx,
		`SELECT `+backfillColumns+` FROM backfills WHERE tenant_id = $1 AND id = $2`, tenant, id))
}

// Backfills lists scans, newest first.
func (s *Store) Backfills(ctx context.Context, tenant string) ([]Backfill, error) {
	rows, err := s.pg.Query(ctx,
		`SELECT `+backfillColumns+` FROM backfills WHERE tenant_id = $1
		 ORDER BY created_at DESC LIMIT 100`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Backfill
	for rows.Next() {
		b, err := scanBackfill(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// ClaimBackfill hands a connector the pending scan for a mailbox, if there is one.
//
// Claiming is a state change, so a second connector asking gets nothing. A scan that
// was already running and whose claimant has gone quiet is reclaimable after the
// stale window — otherwise a connector that died mid-scan would strand its job
// forever, and the operator's only recourse would be to cancel and start again from
// the beginning.
func (s *Store) ClaimBackfill(ctx context.Context, tenant, mailboxID, by string, stale time.Duration) (*Backfill, error) {
	row := s.pg.QueryRow(ctx, `
		UPDATE backfills SET
		  state = 'running',
		  claimed_by = $3,
		  claimed_at = now(),
		  updated_at = now()
		WHERE id = (
		  SELECT id FROM backfills
		  WHERE tenant_id = $1 AND mailbox_id = $2
		    AND (state = 'pending'
		         OR (state = 'running' AND claimed_at < now() - $4::interval))
		  ORDER BY created_at
		  LIMIT 1
		  FOR UPDATE SKIP LOCKED
		)
		RETURNING `+backfillColumns,
		tenant, mailboxID, by, stale.String())

	b, err := scanBackfill(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return b, err
}

// BackfillProgress records what a connector has done and how far it has reached.
//
// The counts are deltas and the cursor is absolute, because that is how the caller
// knows them: it has just processed a batch and knows where the batch ended. The
// cursor only moves forward — a connector that restarts and re-reports an earlier
// position must not rewind a scan that another pass already took further.
func (s *Store) BackfillProgress(ctx context.Context, tenant, id string, d BackfillDelta) error {
	_, err := s.pg.Exec(ctx, `
		UPDATE backfills SET
		  examined   = examined   + $3,
		  ingested   = ingested   + $4,
		  duplicates = duplicates + $5,
		  flagged    = flagged    + $6,
		  failures   = failures   + $7,
		  cursor     = GREATEST(coalesce(cursor, $8), $8),
		  last_error = CASE WHEN $9 = '' THEN last_error ELSE $9 END,
		  last_error_at = CASE WHEN $9 = '' THEN last_error_at ELSE now() END,
		  updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND state = 'running'`,
		tenant, id, d.Examined, d.Ingested, d.Duplicates, d.Flagged, d.Failures,
		d.Cursor.UTC(), d.LastError)
	return err
}

// BackfillDelta is one batch's worth of progress.
type BackfillDelta struct {
	Examined   int64
	Ingested   int64
	Duplicates int64
	Flagged    int64
	Failures   int64
	Cursor     time.Time
	LastError  string
}

// FinishBackfill moves a scan to a terminal state.
func (s *Store) FinishBackfill(ctx context.Context, tenant, id, state, failure string) error {
	switch state {
	case BackfillDone, BackfillFailed, BackfillCancelled, BackfillPaused:
	default:
		return fmt.Errorf("store: %q is not an end state for a scan", state)
	}
	finished := "now()"
	if state == BackfillPaused {
		finished = "NULL"
	}
	// An empty failure means the scan ended cleanly, not that it never had one.
	// This used to write NULLIF($4,'') unconditionally, so finishing a scan
	// discarded whatever a message had failed with along the way — the failures
	// count survived and the reason did not, which is the wrong half to keep. A
	// finish replaces the error only when the finish itself is the failure.
	_, err := s.pg.Exec(ctx, `
		UPDATE backfills SET state = $3,
		  last_error    = CASE WHEN $4 = '' THEN last_error    ELSE $4     END,
		  last_error_at = CASE WHEN $4 = '' THEN last_error_at ELSE now()  END,
		  finished_at = `+finished+`, claimed_by = NULL, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenant, id, state, failure)
	return err
}

func randomID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}

// isUniqueViolation reports a Postgres unique-constraint failure, which is how the
// "one active scan per mailbox" index refuses a second one.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
