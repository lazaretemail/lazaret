// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Custody: holding the only copy of a message.
//
// Quarantine here does not mean moving a message to a folder the recipient can still
// open. It means taking it out of the mailbox entirely and keeping it, so that the
// only remaining copy is the one this system holds. Releasing puts it back; agreeing
// with the verdict leaves it gone.
//
// That makes the raw bytes load-bearing in a way they were not before. A folder move
// needs no copy — the message is still in the mailbox, and the worst case is that it
// is in the wrong place. Deleting it means a lost copy is a lost message, so the raw
// store is written *before* anything is deleted, and a release reads back exactly
// what was taken.

// ErrNoRaw reports that the original bytes are not held.
//
// Distinct from any other failure, because it is the one that must stop a delete:
// quarantining a message this system cannot reproduce would destroy it.
var ErrNoRaw = errors.New("store: the original message bytes are not held")

// custody is where held messages live. One of two backends, chosen by the shape of
// the configured path.
type custody interface {
	put(ctx context.Context, tenant, messageID string, raw []byte) error
	get(ctx context.Context, tenant, messageID string) ([]byte, error)
	has(ctx context.Context, tenant, messageID string) bool
	purge(ctx context.Context, tenant, messageID string) error
}

// openCustody builds the backend for a raw path.
//
// A local directory is the single-node answer and needs nothing. Anything with two
// engines, or anything expected to survive the loss of a machine, needs the s3:// form
// — the held copies are the only remaining version of every quarantined message, so
// leaving them on one node's disk makes that node's failure a data loss rather than an
// outage.
func openCustody(ctx context.Context, raw string, o Options) (custody, error) {
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(raw, "s3://") {
		c, err := newS3Custody(ctx, raw, o)
		if err != nil {
			return nil, err
		}
		// A blob store that is not reachable yet is reported and not fatal.
		//
		// Refusing to start would make a slow Garage during a rolling restart into an
		// engine outage, and starting without custody is safe rather than dangerous:
		// HasRaw answers "no" on any error, and every destructive path is gated on it,
		// so quarantine is refused instead of deleting mail nobody could release.
		// The client is kept, so custody starts working when the store comes back.
		if err := c.ensureBucket(ctx); err != nil {
			log.Printf("custody: %v", err)
			log.Printf("custody: quarantine will be refused until the blob store answers, " +
				"because a message that cannot be held cannot be released")
		}
		return c, nil
	}
	if strings.Contains(raw, "://") {
		return nil, fmt.Errorf("store: %q is not a raw custody path: use a local directory or s3://bucket/prefix", raw)
	}
	return &fsCustody{root: raw}, nil
}

// PutRaw stores a message's bytes.
func (s *Store) PutRaw(ctx context.Context, tenant, messageID string, raw []byte) error {
	if len(raw) == 0 {
		return ErrNoRaw
	}
	if s.custody == nil {
		return ErrNoCustody
	}
	return s.custody.put(ctx, tenant, messageID, raw)
}

// Raw returns a message's stored bytes.
func (s *Store) Raw(ctx context.Context, tenant, messageID string) ([]byte, error) {
	if s.custody == nil {
		return nil, ErrNoCustody
	}
	return s.custody.get(ctx, tenant, messageID)
}

// HasRaw reports whether the bytes are held, without reading them.
//
// A definite yes only. Every caller uses this to decide whether deleting a message
// from a mailbox is safe, so an unreachable blob store must read as "not held" and
// stop the deletion, never as "probably fine".
func (s *Store) HasRaw(ctx context.Context, tenant, messageID string) bool {
	return s.custody != nil && s.custody.has(ctx, tenant, messageID)
}

// PurgeRaw deletes the held copy. Used when an operator confirms a verdict and wants
// the message gone rather than merely out of the mailbox.
func (s *Store) PurgeRaw(ctx context.Context, tenant, messageID string) error {
	if s.custody == nil {
		return ErrNoCustody
	}
	return s.custody.purge(ctx, tenant, messageID)
}

// ErrNoCustody reports that no raw path is configured, so nothing can be held.
var ErrNoCustody = errors.New("store: no raw custody path is configured, so messages cannot be held")

// custodyName is the storage name for a message, shared by both backends.
//
// The message id is hashed rather than used as a name. It comes from the message
// headers, which is to say from the sender: a literal one could contain a slash, a
// leading dot, a NUL, or two thousand characters, and every one of those is a way to
// write outside the intended location or to fail in a way that looks like a bug rather
// than an attack. A hash has none of those properties and is still stable.
func custodyName(tenant, messageID string) string {
	sum := sha256.Sum256([]byte(tenant + "\x00" + messageID))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Custody on a local filesystem
// ---------------------------------------------------------------------------

type fsCustody struct{ root string }

func (c *fsCustody) path(tenant, messageID string) string {
	h := custodyName(tenant, messageID)
	// Two levels of fan-out: a flat directory of a million files is slow to list and
	// slow on some filesystems to open.
	return filepath.Join(c.root, h[:2], h[2:4], h+".eml")
}

func (c *fsCustody) put(ctx context.Context, tenant, messageID string, raw []byte) error {
	path := c.path(tenant, messageID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Written to a temporary name and renamed, so a crash halfway leaves no truncated
	// file that a later release would restore as a broken message.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".raw-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (c *fsCustody) get(ctx context.Context, tenant, messageID string) ([]byte, error) {
	f, err := os.Open(c.path(tenant, messageID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoRaw
		}
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func (c *fsCustody) has(ctx context.Context, tenant, messageID string) bool {
	st, err := os.Stat(c.path(tenant, messageID))
	return err == nil && st.Size() > 0
}

func (c *fsCustody) purge(ctx context.Context, tenant, messageID string) error {
	if err := os.Remove(c.path(tenant, messageID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// The remediation queue
// ---------------------------------------------------------------------------

// A remediation is work for a connector: something to do to a mailbox.
//
// It exists because the decision and the act are separated in time and in process.
// An analyst releases a message in the dashboard, which talks to the engine; the
// mailbox is reachable only from the connector, which may be on another machine and
// may be restarting at that moment. Recording the intent and letting the connector
// collect it is what makes the action survive that gap — and what makes it visible
// afterwards that it was carried out, or was not.
type Remediation struct {
	ID        int64      `json:"id"`
	TenantID  string     `json:"tenant_id"`
	MessageID string     `json:"message_id"`
	MailboxID string     `json:"mailbox_id"`
	Op        string     `json:"op"` // remove | restore
	State     string     `json:"state"`
	Attempts  int        `json:"attempts"`
	LastError string     `json:"last_error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	DoneAt    *time.Time `json:"done_at,omitempty"`

	// Raw is filled only when a connector claims a restore. It is not stored in this
	// row; the row points at the custody copy.
	Raw []byte `json:"raw,omitempty"`
}

const (
	OpRemove  = "remove"
	OpRestore = "restore"

	RemediationPending = "pending"
	RemediationDone    = "done"
	RemediationFailed  = "failed"
)

// Enqueue adds work for the mailboxes that hold the message.
//
// The mailboxes it actually arrived in, where that was recorded — which is every
// managed connector since message_origin existed. A message addressed to two watched
// mailboxes has two rows and gets two jobs, because removing it from one is a
// half-done quarantine.
//
// Falling back to every enabled mailbox when the origin is unknown, which covers mail
// seen in transit by the inline path and anything ingested before origins were
// recorded. A connector that does not find the message reports success with nothing
// to do, so the fan-out is wasteful rather than wrong — but it is wasteful in
// proportion to the number of mailboxes, which is why it is the fallback and not the
// rule.
func (s *Store) Enqueue(ctx context.Context, tenant, messageID, op string) (int, error) {
	if op != OpRemove && op != OpRestore {
		return 0, fmt.Errorf("store: unknown remediation %q", op)
	}

	tag, err := s.pg.Exec(ctx, `
		INSERT INTO remediations (tenant_id, message_id, mailbox_id, op)
		SELECT $1, $2, o.mailbox_id, $3
		FROM message_origin o
		JOIN mailboxes m ON m.id = o.mailbox_id AND m.tenant_id = o.tenant_id
		WHERE o.tenant_id = $1 AND o.message_id = $2 AND m.enabled
		ON CONFLICT (tenant_id, message_id, mailbox_id, op) WHERE state = 'pending'
		DO NOTHING`,
		tenant, messageID, op)
	if err != nil {
		return 0, err
	}
	if n := int(tag.RowsAffected()); n > 0 {
		return n, nil
	}

	tag, err = s.pg.Exec(ctx, `
		INSERT INTO remediations (tenant_id, message_id, mailbox_id, op)
		SELECT $1, $2, id, $3 FROM mailboxes WHERE tenant_id = $1 AND enabled
		ON CONFLICT (tenant_id, message_id, mailbox_id, op) WHERE state = 'pending'
		DO NOTHING`,
		tenant, messageID, op)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// Claim returns the pending work for one mailbox and marks it in flight.
func (s *Store) Claim(ctx context.Context, tenant, mailboxID string, limit int) ([]Remediation, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pg.Query(ctx, `
		UPDATE remediations SET attempts = attempts + 1
		WHERE id IN (
			SELECT id FROM remediations
			WHERE tenant_id = $1 AND mailbox_id = $2 AND state = 'pending'
			  AND attempts < 10
			ORDER BY id LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, tenant_id, message_id, mailbox_id, op, state, attempts,
		          last_error, created_at, done_at`,
		tenant, mailboxID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Remediation
	for rows.Next() {
		var r Remediation
		if err := rows.Scan(&r.ID, &r.TenantID, &r.MessageID, &r.MailboxID, &r.Op,
			&r.State, &r.Attempts, &r.LastError, &r.CreatedAt, &r.DoneAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Finish records the outcome of one remediation.
func (s *Store) Finish(ctx context.Context, tenant string, id int64, failure string) error {
	// A failure is left pending so it is retried, until the attempt limit turns it
	// into a failure a person has to look at. A remediation that silently gave up is
	// a message someone believes was removed and which is still sitting in an inbox.
	_, err := s.pg.Exec(ctx, `
		UPDATE remediations
		SET state = CASE WHEN $3 = '' THEN 'done'
		                 WHEN attempts >= 10 THEN 'failed'
		                 ELSE 'pending' END,
		    last_error = $3,
		    done_at = CASE WHEN $3 = '' THEN now() ELSE NULL END
		WHERE tenant_id = $1 AND id = $2`,
		tenant, id, failure)
	return err
}

// PendingRemediations reports outstanding work, for the dashboard.
func (s *Store) PendingRemediations(ctx context.Context, tenant string) ([]Remediation, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT id, tenant_id, message_id, mailbox_id, op, state, attempts,
		       last_error, created_at, done_at
		FROM remediations
		WHERE tenant_id = $1 AND state <> 'done'
		ORDER BY id DESC LIMIT 200`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Remediation
	for rows.Next() {
		var r Remediation
		if err := rows.Scan(&r.ID, &r.TenantID, &r.MessageID, &r.MailboxID, &r.Op,
			&r.State, &r.Attempts, &r.LastError, &r.CreatedAt, &r.DoneAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CustodyStatus describes whether messages can be held, for the health endpoint.
//
// Worth surfacing rather than leaving in a log line: an operator whose blob store is
// misconfigured finds out either here, or the first time an analyst tries to
// quarantine something and is refused with no obvious cause.
type CustodyStatus struct {
	Backend    string `json:"backend,omitempty"` // filesystem | s3
	Error      string `json:"error,omitempty"`
	Configured bool   `json:"configured"`
	Writable   bool   `json:"writable"`
}

// Custody reports whether a message could be held right now.
//
// Actually tries it, rather than reporting what was configured: the useful question
// is not "is a path set" but "if a verdict came in now, could the message be
// quarantined". A probe object is written and deleted under a reserved id.
func (s *Store) Custody(ctx context.Context) CustodyStatus {
	if s.custody == nil {
		return CustodyStatus{Error: "no raw path is configured, so quarantine is refused"}
	}
	st := CustodyStatus{Configured: true, Backend: "filesystem"}
	if _, ok := s.custody.(*s3Custody); ok {
		st.Backend = "s3"
	}
	const probe = "\x00lazaret-custody-probe"
	if err := s.custody.put(ctx, "\x00probe", probe, []byte("probe")); err != nil {
		st.Error = err.Error()
		return st
	}
	_ = s.custody.purge(ctx, "\x00probe", probe)
	st.Writable = true
	return st
}

// RecordOrigin notes which mailbox a message arrived in.
//
// Several rows per message are expected and correct: a message addressed to two
// watched mailboxes was delivered to both, and removing it from one is a half-done
// quarantine.
func (s *Store) RecordOrigin(ctx context.Context, tenant, messageID, mailboxID string) error {
	return s.RecordOriginFrom(ctx, tenant, messageID, mailboxID, "")
}

// RecordOriginFrom notes the mailbox and, when a retrospective scan found the
// message rather than a live connector, which scan.
//
// Kept because the two are read differently. A message flagged on arrival is the
// platform working; the same message found three weeks later by a backfill is the
// platform saying it was not there at the time. Counting them together overstates
// effectiveness precisely when someone is deciding whether to believe the numbers.
func (s *Store) RecordOriginFrom(ctx context.Context, tenant, messageID, mailboxID, backfillID string) error {
	if mailboxID == "" && backfillID == "" {
		return nil
	}
	_, err := s.pg.Exec(ctx, `
		INSERT INTO message_origin (tenant_id, message_id, mailbox_id, backfill_id)
		VALUES ($1, $2, $3, NULLIF($4,''))
		ON CONFLICT (tenant_id, message_id, mailbox_id) DO UPDATE
		  SET backfill_id = coalesce(message_origin.backfill_id, EXCLUDED.backfill_id)`,
		tenant, messageID, mailboxID, backfillID)
	return err
}

// HistoricalIDs returns the messages a retrospective scan found, so reports can
// separate them from what was caught on arrival.
func (s *Store) HistoricalIDs(ctx context.Context, tenant string) (map[string]string, error) {
	rows, err := s.pg.Query(ctx,
		`SELECT message_id, backfill_id FROM message_origin
		 WHERE tenant_id = $1 AND backfill_id IS NOT NULL`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, bf string
		if err := rows.Scan(&id, &bf); err != nil {
			return nil, err
		}
		out[id] = bf
	}
	return out, rows.Err()
}

// EnqueueAction queues any action kind against the mailbox a message arrived in.
//
// The generalisation of Enqueue, which knew only about removal and restoration.
// The op vocabulary grew when rules gained actions; the queue, the claim and the
// retry behaviour did not change, because they were never about what the action
// was.
//
// Config travels with the row because a "move" needs to know where to: the folder
// is a property of the configured action, and looking it up again at execution
// time would let an edit made after queueing change what a queued action does.
func (s *Store) EnqueueAction(ctx context.Context, tenant, messageID, mailboxID, op string, config map[string]string) error {
	if !validOp(op) {
		return fmt.Errorf("store: unknown remediation %q", op)
	}
	cfg, err := json.Marshal(config)
	if err != nil {
		return err
	}
	_, err = s.pg.Exec(ctx, `
		INSERT INTO remediations (tenant_id, message_id, mailbox_id, op, config)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (tenant_id, message_id, mailbox_id, op) WHERE state = 'pending'
		DO NOTHING`, tenant, messageID, mailboxID, op, cfg)
	return err
}

// validOp is the vocabulary a connector understands.
//
// "remove" rather than "quarantine" for the destructive one: that is what the
// column said before actions existed, and renaming it would have meant rewriting a
// queue somebody is waiting on for the sake of a tidier word.
func validOp(op string) bool {
	switch op {
	case OpRemove, OpRestore, "trash", "spam", "move", "flag", "mark_read":
		return true
	}
	return false
}
