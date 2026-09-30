// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Rule feeds: where detection content comes from.
//
// A fresh install ships no rules. The Sublime corpus is a large MIT repository that
// belongs to somebody else and is not vendored here, so without this a new
// deployment starts with an empty rule set and detects nothing — which looks like a
// broken install rather than an unconfigured one. Seeding the Sublime feed on first
// start is what makes "docker compose up" produce a working system.

// A feed supplies content, never behaviour. Nothing it brings can touch a mailbox
// until an admin attaches an action to it, which is a separate, local decision.

// RuleFeed is a git repository of detection content.
type RuleFeed struct {
	ID       string `json:"id"`
	TenantID string `json:"-"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Branch   string `json:"branch,omitempty"`
	Subdir   string `json:"subdir,omitempty"`

	Enabled   bool `json:"enabled"`
	EverySecs int  `json:"every_seconds"`

	// Secret is an access token for a private repository. Set on write; on read it
	// is populated only when the caller asked for secrets, which the browser-facing
	// API never does.
	Secret string `json:"-"`

	// HasSecret is what a browser is told instead: whether one is stored.
	HasSecret bool `json:"has_secret"`

	LastSync   *time.Time `json:"last_sync,omitempty"`
	LastCommit string     `json:"last_commit,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	RuleCount  int        `json:"rule_count"`

	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ErrNoFeed is returned when a feed does not exist in this tenant.
var ErrNoFeed = errors.New("store: no such rule feed")

// The feeds seeded into a new deployment.
//
// Enabled, because the alternative is a fresh install that detects nothing until
// somebody finds a settings page they do not yet know exists.
var (
	// SublimeFeed is the MIT rule corpus this engine exists to run.
	SublimeFeed = RuleFeed{
		Name:      "Sublime core detections",
		URL:       "https://github.com/sublime-security/sublime-rules",
		Subdir:    "detection-rules",
		Enabled:   true,
		EverySecs: 21600, // six hours; the corpus changes most days, not most minutes
	}

	// CommunityFeed is Lazaret's own content: rules that use the extensions MQL
	// does not have, and so cannot live upstream.
	//
	// Its own repository rather than a directory in this one, for the same reason
	// Sublime's is: rules change on a different clock from the engine, and an
	// operator should be able to take a new detection without taking a new binary.
	// It also means a contributor can send a rule without touching the platform.
	CommunityFeed = RuleFeed{
		Name:      "Lazaret community detections",
		URL:       "https://github.com/lazaretemail/rules",
		Subdir:    "detection-rules",
		Enabled:   true,
		EverySecs: 21600,
	}
)

// SeededFeeds is what a fresh deployment starts with.
func SeededFeeds() []RuleFeed { return []RuleFeed{SublimeFeed, CommunityFeed} }

// checkFeedURL refuses a URL this engine should not be cloning.
//
// Only https and ssh. A file:// or a bare local path would let an admin — or
// anyone who reached the admin API — read the engine's own filesystem into a rule
// set, and git:// is unauthenticated and unencrypted, which is no way to fetch
// content that decides whether mail gets quarantined.
func checkFeedURL(raw string) error {
	if raw == "" {
		return errors.New("store: a feed needs a URL")
	}
	if strings.HasPrefix(raw, "git@") {
		return nil // scp-style ssh, e.g. git@github.com:org/repo.git
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("store: %q is not a URL: %w", raw, err)
	}
	switch u.Scheme {
	case "https", "ssh":
		if u.Host == "" {
			return fmt.Errorf("store: %q has no host", raw)
		}
		return nil
	case "http":
		return errors.New("store: refusing http for a rule feed; content that decides " +
			"whether mail is quarantined must not arrive over a connection anyone can rewrite")
	default:
		return fmt.Errorf("store: %q is not a scheme this engine will clone (https or ssh)", u.Scheme)
	}
}

// SaveRuleFeed creates or updates one. An empty Secret on update leaves the stored
// token alone, so editing a schedule does not silently clear credentials.
func (s *Store) SaveRuleFeed(ctx context.Context, f RuleFeed) (*RuleFeed, error) {
	if f.Name == "" {
		return nil, errors.New("store: a feed needs a name")
	}
	if err := checkFeedURL(f.URL); err != nil {
		return nil, err
	}
	if f.ID == "" {
		f.ID = newID("feed")
	}
	if f.EverySecs <= 0 {
		f.EverySecs = 21600
	}
	if f.EverySecs < 300 {
		// A repository polled every few seconds is a way to get rate limited off a
		// forge, and detection content does not change that fast.
		f.EverySecs = 300
	}

	var sealed []byte
	if f.Secret != "" {
		if s.secrets == nil {
			return nil, errors.New("store: no secret key is configured, so a feed token cannot be " +
				"stored (start the engine with -secret-key)")
		}
		var err error
		if sealed, err = s.secrets.Seal(f.Secret); err != nil {
			return nil, err
		}
	}

	_, err := s.pg.Exec(ctx, `
		INSERT INTO rule_feeds (id, tenant_id, name, url, branch, subdir, enabled,
		                        every_secs, secret_enc, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO UPDATE SET
			name       = EXCLUDED.name,
			url        = EXCLUDED.url,
			branch     = EXCLUDED.branch,
			subdir     = EXCLUDED.subdir,
			enabled    = EXCLUDED.enabled,
			every_secs = EXCLUDED.every_secs,
			secret_enc = COALESCE(EXCLUDED.secret_enc, rule_feeds.secret_enc)`,
		f.ID, f.TenantID, f.Name, f.URL, f.Branch, f.Subdir, f.Enabled, f.EverySecs,
		sealed, f.CreatedBy)
	if err != nil {
		return nil, err
	}
	return s.RuleFeed(ctx, f.TenantID, f.ID, false)
}

// RuleFeeds lists them. withSecrets is honoured only for a service token; the
// console's API never asks.
func (s *Store) RuleFeeds(ctx context.Context, tenant string, withSecrets bool) ([]RuleFeed, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT id, name, url, branch, subdir, enabled, every_secs, secret_enc,
		       last_sync, last_commit, last_error, rule_count, created_by, created_at
		FROM rule_feeds WHERE tenant_id = $1 ORDER BY name`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RuleFeed
	for rows.Next() {
		f, err := s.scanFeed(rows, tenant, withSecrets)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// RuleFeed is one, scoped to its tenant so an id from another one is a miss rather
// than a read.
func (s *Store) RuleFeed(ctx context.Context, tenant, id string, withSecrets bool) (*RuleFeed, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT id, name, url, branch, subdir, enabled, every_secs, secret_enc,
		       last_sync, last_commit, last_error, rule_count, created_by, created_at
		FROM rule_feeds WHERE tenant_id = $1 AND id = $2`, tenant, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNoFeed
	}
	return s.scanFeed(rows, tenant, withSecrets)
}

type scanner interface{ Scan(dest ...any) error }

func (s *Store) scanFeed(row scanner, tenant string, withSecrets bool) (*RuleFeed, error) {
	var f RuleFeed
	var sealed []byte
	if err := row.Scan(&f.ID, &f.Name, &f.URL, &f.Branch, &f.Subdir, &f.Enabled,
		&f.EverySecs, &sealed, &f.LastSync, &f.LastCommit, &f.LastError, &f.RuleCount,
		&f.CreatedBy, &f.CreatedAt); err != nil {
		return nil, err
	}
	f.TenantID = tenant
	f.HasSecret = len(sealed) > 0
	if withSecrets && len(sealed) > 0 && s.secrets != nil {
		secret, err := s.secrets.Open(sealed)
		if err != nil {
			return nil, err
		}
		f.Secret = secret
	}
	return &f, nil
}

// DeleteRuleFeed removes one. The cloned copy on disk is the caller's to clean up:
// the store does not know where it put it.
func (s *Store) DeleteRuleFeed(ctx context.Context, tenant, id string) error {
	tag, err := s.pg.Exec(ctx, `DELETE FROM rule_feeds WHERE tenant_id = $1 AND id = $2`, tenant, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoFeed
	}
	return nil
}

// RecordFeedSync stores the outcome of one sync attempt.
//
// A failure keeps the previous commit and rule count: the rules from the last good
// pull are still on disk and still loaded, and reporting zero would say the feed is
// empty when it is merely stale.
func (s *Store) RecordFeedSync(ctx context.Context, tenant, id, commit string, rules int, syncErr error) error {
	msg := ""
	if syncErr != nil {
		msg = syncErr.Error()
	}
	if syncErr != nil {
		_, err := s.pg.Exec(ctx, `
			UPDATE rule_feeds SET last_sync = now(), last_error = $3
			WHERE tenant_id = $1 AND id = $2`, tenant, id, msg)
		return err
	}
	_, err := s.pg.Exec(ctx, `
		UPDATE rule_feeds SET last_sync = now(), last_commit = $3, rule_count = $4, last_error = ''
		WHERE tenant_id = $1 AND id = $2`, tenant, id, commit, rules)
	return err
}

// SeedRuleFeeds inserts the defaults if this tenant has none at all.
//
// Only when the table is empty for the tenant, so an operator who deliberately
// removed the Sublime feed does not find it back after a restart.
func (s *Store) SeedRuleFeeds(ctx context.Context, tenant string) (bool, error) {
	var n int
	if err := s.pg.QueryRow(ctx,
		`SELECT count(*) FROM rule_feeds WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	for _, f := range SeededFeeds() {
		f.TenantID = tenant
		f.CreatedBy = "seed"
		if _, err := s.SaveRuleFeed(ctx, f); err != nil {
			return false, err
		}
	}
	return true, nil
}
