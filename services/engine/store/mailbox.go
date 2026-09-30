// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Mailboxes to collect from.
//
// Configuration rather than command-line flags, because adding a mailbox is a routine
// operational act — a new shared inbox, a department, someone's account after an
// incident — and restarting a connector to do it is not. The ingest service reads this
// table and reconciles.
//
// # About the secrets
//
// IMAP passwords are encrypted at rest with AES-GCM under a key the operator supplies.
// What that protects against is narrow and worth stating plainly: a database dump, a
// backup, a replica, a stray pg_dump in someone's home directory. It does **not**
// protect against an attacker who has the engine's process memory or its environment,
// because the engine must be able to decrypt in order to log in.
//
// If that is not good enough — and for a mailbox with access to everything, it may not
// be — use OAuth against Microsoft rather than an IMAP password, or give the connector
// an app password scoped to one mailbox.

// Mailbox is one configured source.
type Mailbox struct {
	CreatedAt time.Time  `json:"created_at"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Kind      string     `json:"kind"` // imap | graph
	Address   string     `json:"address"`
	Host      string     `json:"host,omitempty"`
	Username  string     `json:"username,omitempty"`
	TLSMode   string     `json:"tls_mode,omitempty"`
	Folder    string     `json:"folder,omitempty"`
	GraphUser string     `json:"graph_user,omitempty"`
	// Secret is only ever populated on the way in. It is never read back out.
	Secret    string `json:"secret,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Messages  int64  `json:"messages"`
	Enabled   bool   `json:"enabled"`
	// Remediate allows a connector to remove mail from this mailbox.
	//
	// Off by default. Quarantine deletes the message rather than filing it, so
	// turning this on is the decision to let an automated verdict take a message
	// away from its recipient — not something to arrive at by leaving a field blank.
	Remediate bool `json:"remediate"`
	HasSecret bool `json:"has_secret"`
}

// SecretBox encrypts mailbox credentials at rest.
type SecretBox struct{ aead cipher.AEAD }

// NewSecretBox builds one from a 32-byte key.
func NewSecretBox(key []byte) (*SecretBox, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("store: the secret key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretBox{aead: aead}, nil
}

// Seal encrypts, prefixing the nonce.
func (b *SecretBox) Seal(plaintext string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// Open decrypts.
func (b *SecretBox) Open(sealed []byte) (string, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return "", errors.New("store: the stored secret is truncated")
	}
	out, err := b.aead.Open(nil, sealed[:n], sealed[n:], nil)
	if err != nil {
		// Almost always a changed key rather than tampering, and saying so saves an
		// operator a long hunt for a corrupted row.
		return "", fmt.Errorf("store: could not decrypt; has the secret key changed? %w", err)
	}
	return string(out), nil
}

// SetSecretBox attaches the key used for mailbox credentials.
func (s *Store) SetSecretBox(b *SecretBox) { s.secrets = b }

// SaveMailbox creates or updates one.
func (s *Store) SaveMailbox(ctx context.Context, m Mailbox) (*Mailbox, error) {
	if m.Kind != "imap" && m.Kind != "graph" {
		return nil, fmt.Errorf("store: %q is not a mailbox kind", m.Kind)
	}
	if m.Address == "" {
		return nil, errors.New("store: an address is required")
	}
	if m.ID == "" {
		m.ID = newID("mbx")
	}
	if m.Folder == "" {
		m.Folder = "INBOX"
	}
	if m.TLSMode == "" {
		m.TLSMode = "tls"
	}

	var sealed []byte
	if m.Secret != "" {
		if s.secrets == nil {
			return nil, errors.New("store: no secret key is configured, so a credential cannot be stored " +
				"(start the engine with -secret-key)")
		}
		var err error
		if sealed, err = s.secrets.Seal(m.Secret); err != nil {
			return nil, err
		}
	}

	// A null secret on update leaves the stored one alone, so editing a folder does
	// not silently clear the password.
	_, err := s.pg.Exec(ctx, `
		INSERT INTO mailboxes (id, tenant_id, kind, address, enabled, host, username,
		                       secret_enc, tls_mode, folder, remediate, graph_user)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,NULLIF($12,''))
		ON CONFLICT (id) DO UPDATE SET
		  address = EXCLUDED.address, enabled = EXCLUDED.enabled,
		  host = EXCLUDED.host, username = EXCLUDED.username,
		  secret_enc = coalesce(EXCLUDED.secret_enc, mailboxes.secret_enc),
		  tls_mode = EXCLUDED.tls_mode, folder = EXCLUDED.folder,
		  remediate = EXCLUDED.remediate, graph_user = EXCLUDED.graph_user`,
		m.ID, m.TenantID, m.Kind, m.Address, m.Enabled, m.Host, m.Username,
		sealed, m.TLSMode, m.Folder, m.Remediate, m.GraphUser)
	if err != nil {
		return nil, fmt.Errorf("store: saving mailbox: %w", err)
	}
	m.Secret, m.HasSecret = "", sealed != nil
	return &m, nil
}

// Mailboxes lists them. Credentials are not included.
func (s *Store) Mailboxes(ctx context.Context, tenant string, withSecrets bool) ([]Mailbox, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT id, tenant_id, kind, address, enabled, coalesce(host,''), coalesce(username,''),
		       secret_enc, tls_mode, folder, coalesce(remediate,false), coalesce(graph_user,''),
		       last_seen, coalesce(last_error,''), messages, created_at
		FROM mailboxes WHERE tenant_id = $1 ORDER BY kind, address`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Mailbox
	for rows.Next() {
		var m Mailbox
		var sealed []byte
		if err := rows.Scan(&m.ID, &m.TenantID, &m.Kind, &m.Address, &m.Enabled, &m.Host,
			&m.Username, &sealed, &m.TLSMode, &m.Folder, &m.Remediate, &m.GraphUser,
			&m.LastSeen, &m.LastError, &m.Messages, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.HasSecret = len(sealed) > 0
		if withSecrets && m.HasSecret && s.secrets != nil {
			// Only for the connector, never for the API. A credential that can be
			// read back through an HTTP endpoint is a credential one XSS away from
			// being taken.
			if plain, err := s.secrets.Open(sealed); err == nil {
				m.Secret = plain
			} else {
				m.LastError = err.Error()
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteMailbox removes one.
func (s *Store) DeleteMailbox(ctx context.Context, tenant, id string) error {
	_, err := s.pg.Exec(ctx, `DELETE FROM mailboxes WHERE tenant_id=$1 AND id=$2`, tenant, id)
	return err
}

// ErrNoMailbox reports that no mailbox with that id exists in this tenant.
var ErrNoMailbox = errors.New("store: no such mailbox")

// NoteMailbox records a connector's progress, so the settings page can show whether a
// mailbox is actually working rather than only that it is configured.
//
// Scoped by tenant, and the id alone is not enough. The id arrives from a connector
// over the network, in the path of a request — so without the tenant in the WHERE
// clause a token in one tenant could write to a mailbox row in another. What that
// buys an attacker is not a credential but something subtler and quite effective:
// last_error is free text that appears on another tenant's settings page as the
// reason their mailbox is failing. "Authentication failed" written onto a mailbox
// that is working perfectly is a good way to get an administrator to rotate a
// password, or to stop trusting the page.
//
// Returns ErrNoMailbox rather than succeeding silently when the pair does not match,
// so a caller can tell "recorded" from "wrote nothing".
func (s *Store) NoteMailbox(ctx context.Context, tenant, id string, seen int64, err error) error {
	var msg *string
	if err != nil {
		m := err.Error()
		msg = &m
	}
	tag, e := s.pg.Exec(ctx, `
		UPDATE mailboxes SET last_seen = now(), messages = messages + $3, last_error = $4
		WHERE tenant_id = $1 AND id = $2`, tenant, id, seen, msg)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		return ErrNoMailbox
	}
	return nil
}

// RecipientAddresses returns the configured mailbox addresses.
//
// These seed $recipient_emails before any mail has been seen: a fresh deployment
// knows which mailboxes it collects from, and waiting for delivery to learn that
// leaves the rules that use it blind on day one.
func (s *Store) RecipientAddresses(ctx context.Context, tenant string) ([]string, error) {
	rows, err := s.pg.Query(ctx,
		`SELECT lower(address) FROM mailboxes WHERE tenant_id=$1 AND enabled`, tenant)
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

// ClearMailboxHealth forgets what was last known about a mailbox's connection.
//
// So that the settings page shows "checking" rather than a stale "connected" from
// before someone changed a password. The next report from the connector fills it in
// again, which for a running connector is one poll interval away.
func (s *Store) ClearMailboxHealth(ctx context.Context, tenant, id string) error {
	_, err := s.pg.Exec(ctx,
		`UPDATE mailboxes SET last_seen = NULL, last_error = NULL
		 WHERE tenant_id = $1 AND id = $2`, tenant, id)
	return err
}

// SetMailboxEnabled pauses or resumes collection from one mailbox.
//
// A narrow update rather than a round trip through SaveMailbox, and the narrowness is
// the point. SaveMailbox writes every column, so a toggle built on it would have to
// read the row back first, and anything the caller failed to carry across — the folder,
// the remediate flag, the TLS mode — would be silently reset to whatever the form
// happened to hold. This can only change one boolean.
//
// Pausing is deliberately not deleting. The credential stays, the message count stays,
// and resuming is one click: an administrator investigating a noisy mailbox, or taking
// a departed employee's account out of collection, should not have to destroy the
// configuration and re-enter a password to do it.
func (s *Store) SetMailboxEnabled(ctx context.Context, tenant, id string, enabled bool) error {
	tag, err := s.pg.Exec(ctx,
		`UPDATE mailboxes SET enabled = $3 WHERE tenant_id = $1 AND id = $2`,
		tenant, id, enabled)
	if err != nil {
		return fmt.Errorf("store: setting mailbox state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoMailbox
	}
	return nil
}

// AddMailboxes creates several at once, skipping addresses already configured.
//
// For onboarding an estate from the directory. It returns what it added and what it
// skipped, because "we added 412 of your 460 accounts" is only a useful sentence with
// the other 48 accounted for.
//
// Existing addresses are skipped rather than updated. A second walk after adding forty
// people must not quietly reset the settings of the four hundred already there — and an
// administrator who wants to change one has the mailbox form for that.
//
// There is no unique index behind this, so two administrators bulk-adding at the same
// instant could both insert the same address. That race is left open on purpose: the
// index would have to be added to deployments that may already hold duplicates, where
// the migration would fail on start-up, and the consequence of losing the race is one
// duplicate row collecting the same mail twice — which ingest discards, because it is
// idempotent on (tenant, message_id).
func (s *Store) AddMailboxes(ctx context.Context, tenant string, boxes []Mailbox) (added []Mailbox, skipped []string, err error) {
	existing, err := s.mailboxAddresses(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}

	added = []Mailbox{}
	skipped = []string{}
	for _, m := range boxes {
		key := strings.ToLower(strings.TrimSpace(m.Address))
		if key == "" {
			continue
		}
		if existing[key] {
			skipped = append(skipped, m.Address)
			continue
		}
		m.TenantID = tenant
		saved, err := s.SaveMailbox(ctx, m)
		if err != nil {
			// Partial rather than all-or-nothing, and it says so. One malformed
			// address out of four hundred should not discard the other 399 — the
			// administrator would have no way to find which one it was.
			return added, skipped, fmt.Errorf("added %d mailbox(es), then %s failed: %w",
				len(added), m.Address, err)
		}
		existing[key] = true
		added = append(added, *saved)
	}
	return added, skipped, nil
}

// mailboxAddresses is the set of addresses already configured, lowercased.
//
// Lowercased because SMTP addresses are compared case-insensitively in practice and
// Microsoft will happily report one whose case differs from what somebody typed. Two
// rows differing only in case are two connectors collecting the same mailbox.
func (s *Store) mailboxAddresses(ctx context.Context, tenant string) (map[string]bool, error) {
	rows, err := s.pg.Query(ctx, `SELECT address FROM mailboxes WHERE tenant_id = $1`, tenant)
	if err != nil {
		return nil, fmt.Errorf("store: reading configured mailboxes: %w", err)
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out[strings.ToLower(strings.TrimSpace(a))] = true
	}
	return out, rows.Err()
}
