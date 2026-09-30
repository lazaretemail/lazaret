// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Named list configuration.
//
// The corpus references 32 distinct lists, and they need four genuinely different
// mechanisms to fill:
//
//	embedded  18 lists shipped in the binary from sublime-security/static-files
//	fetch     4 ranked domain tables too large to embed (tranco, umbrella, alexa)
//	feed      2 abuse.ch threat-intel feeds, which change hourly
//	org       5 lists that are facts about the organisation, not the internet
//	history   4 derived from what this deployment has seen
//
// A rule cannot tell them apart and should not have to. What this table adds is
// *configuration*: whether a list is on, where it comes from, and what an operator has
// added to or taken out of it.
//
// # Overrides survive a refresh
//
// Operator additions and exclusions live in their own table, never mixed into the
// cached contents. An exclusion added because a list wrongly contains the
// organisation's own domain has to survive the next download — losing it would
// silently re-break the thing someone fixed, at whatever hour the refresh runs.

// ListSource says what fills a list.
type ListSource string

const (
	SourceEmbedded ListSource = "embedded"
	SourceFetch    ListSource = "fetch"
	// SourceRadar is Cloudflare Radar, which needs two API calls rather than one
	// download: list the ranking datasets, then ask for a signed URL.
	SourceRadar ListSource = "radar"

	SourceFeed    ListSource = "feed"
	SourceOrg     ListSource = "org"
	SourceHistory ListSource = "history"
	SourceManual  ListSource = "manual"
)

// ListConfig is one list's configuration and state.
type ListConfig struct {
	LastRefresh *time.Time `json:"last_refresh,omitempty"`
	Name        string     `json:"name"`
	Source      ListSource `json:"source"`
	URL         string     `json:"url,omitempty"`
	AuthHeader  string     `json:"-"` // never serialised: it is a credential
	Format      string     `json:"format"`
	// Filter narrows a downloaded list to the lines that match, as a regular
	// expression over the whole line before the value is extracted.
	//
	// It exists for the feeds whose published export is broader than the list the
	// rules name. The corpus asks for abuse.ch's "trusted reporters" — a filter
	// Sublime's platform applies and abuse.ch's public export does not expose — so
	// the choice is between a broader feed than the rule intended and no feed at
	// all. This makes that an operator's decision instead of ours.
	Filter string `json:"filter,omitempty"`
	// FallbackTo names another list to use when this one resolves to nothing.
	//
	// For a list whose upstream no longer exists: $alexa_1m is read by two rules and
	// the ranking was discontinued in 2022, so the choice is a stale answer, no
	// answer, or an equivalent one. A chain makes that explicit and visible on the
	// settings page rather than being a silent substitution in code.
	FallbackTo  string `json:"fallback_to,omitempty"`
	Description string `json:"description"`
	LastError   string `json:"last_error,omitempty"`
	// Marshalled by the handlers, which convert to whole seconds: a time.Duration
	// encodes as nanoseconds, and a field named _seconds holding 3600000000000 is
	// the kind of thing an API consumer only notices after building on it.
	RefreshEvery time.Duration `json:"-"`
	EntryCount   int64         `json:"entry_count"`
	Includes     int64         `json:"includes"`
	Excludes     int64         `json:"excludes"`
	HasAuth      bool          `json:"has_auth"`
	Enabled      bool          `json:"enabled"`
}

// ListOverride is one operator addition or removal.
type ListOverride struct {
	Value   string    `json:"value"`
	Kind    string    `json:"kind"`
	Note    string    `json:"note,omitempty"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// EnsureList creates a list's configuration if it does not exist, leaving an existing
// one alone.
//
// Idempotent on purpose: it runs at every start-up to seed the defaults, and must not
// overwrite what an operator has since changed.
func (s *Store) EnsureList(ctx context.Context, tenant string, c ListConfig) error {
	if c.Format == "" {
		c.Format = "lines"
	}
	if c.RefreshEvery == 0 {
		c.RefreshEvery = 24 * time.Hour
	}
	_, err := s.pg.Exec(ctx, `
		INSERT INTO lists (tenant_id, name, source, url, auth_header, format, enabled,
		                   description, refresh_every, filter, fallback_to)
		VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,$7,$8, make_interval(secs => $9),
		        NULLIF($10,''), NULLIF($11,''))
		ON CONFLICT (tenant_id, name) DO NOTHING`,
		tenant, c.Name, string(c.Source), c.URL, c.AuthHeader, c.Format,
		c.Enabled, c.Description, c.RefreshEvery.Seconds(), c.Filter, c.FallbackTo)
	return err
}

// Lists returns every configured list with its state.
func (s *Store) Lists(ctx context.Context, tenant string) ([]ListConfig, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT l.name, l.source, coalesce(l.url,''), l.auth_header IS NOT NULL,
		       l.format, l.enabled, l.description,
		       extract(epoch from l.refresh_every), l.last_refresh,
		       coalesce(l.last_error,''), l.entry_count,
		       (SELECT count(*) FROM list_overrides o
		         WHERE o.tenant_id = l.tenant_id AND o.name = l.name AND o.kind = 'include'),
		       (SELECT count(*) FROM list_overrides o
		         WHERE o.tenant_id = l.tenant_id AND o.name = l.name AND o.kind = 'exclude'),
		       coalesce(l.filter,''), coalesce(l.fallback_to,'')
		FROM lists l WHERE l.tenant_id = $1 ORDER BY l.name`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ListConfig
	for rows.Next() {
		var c ListConfig
		var secs float64
		if err := rows.Scan(&c.Name, &c.Source, &c.URL, &c.HasAuth, &c.Format, &c.Enabled,
			&c.Description, &secs, &c.LastRefresh, &c.LastError, &c.EntryCount,
			&c.Includes, &c.Excludes, &c.Filter, &c.FallbackTo); err != nil {
			return nil, err
		}
		c.RefreshEvery = time.Duration(secs) * time.Second
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListByName returns one list's configuration, including its credential.
func (s *Store) ListByName(ctx context.Context, tenant, name string) (*ListConfig, error) {
	var c ListConfig
	var secs float64
	var auth *string
	err := s.pg.QueryRow(ctx, `
		SELECT name, source, coalesce(url,''), auth_header, format, enabled, description,
		       extract(epoch from refresh_every), last_refresh, coalesce(last_error,''), entry_count,
		       coalesce(filter,''), coalesce(fallback_to,'')
		FROM lists WHERE tenant_id = $1 AND name = $2`, tenant, name).
		Scan(&c.Name, &c.Source, &c.URL, &auth, &c.Format, &c.Enabled, &c.Description,
			&secs, &c.LastRefresh, &c.LastError, &c.EntryCount, &c.Filter, &c.FallbackTo)
	if err != nil {
		return nil, err
	}
	if auth != nil {
		c.AuthHeader, c.HasAuth = *auth, true
	}
	c.RefreshEvery = time.Duration(secs) * time.Second
	return &c, nil
}

// UpdateList changes a list's configuration.
func (s *Store) UpdateList(ctx context.Context, tenant, name string, enabled *bool, url, auth *string, every *time.Duration) error {
	if enabled != nil {
		if _, err := s.pg.Exec(ctx, `UPDATE lists SET enabled=$3, updated_at=now() WHERE tenant_id=$1 AND name=$2`,
			tenant, name, *enabled); err != nil {
			return err
		}
	}
	if url != nil {
		if _, err := s.pg.Exec(ctx, `UPDATE lists SET url=NULLIF($3,''), updated_at=now() WHERE tenant_id=$1 AND name=$2`,
			tenant, name, *url); err != nil {
			return err
		}
	}
	if auth != nil {
		if _, err := s.pg.Exec(ctx, `UPDATE lists SET auth_header=NULLIF($3,''), updated_at=now() WHERE tenant_id=$1 AND name=$2`,
			tenant, name, *auth); err != nil {
			return err
		}
	}
	if every != nil {
		if _, err := s.pg.Exec(ctx, `UPDATE lists SET refresh_every=make_interval(secs => $3), updated_at=now() WHERE tenant_id=$1 AND name=$2`,
			tenant, name, every.Seconds()); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceCache swaps a fetched or feed list's contents in one transaction.
//
// All-or-nothing, because the alternative is a window during which the list is half
// empty. A membership test against a half-loaded list does not fail, it answers
// "no" — and for a list of trusted senders that turns every one of them into a
// stranger for as long as the load takes.
func (s *Store) ReplaceCache(ctx context.Context, tenant, name string, values []string) error {
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM list_cache WHERE tenant_id=$1 AND name=$2`, tenant, name); err != nil {
		return err
	}

	const chunk = 5000
	for i := 0; i < len(values); i += chunk {
		end := min(i+chunk, len(values))
		batch := values[i:end]
		if _, err := tx.Exec(ctx, `
			INSERT INTO list_cache (tenant_id, name, value)
			SELECT $1, $2, unnest($3::text[]) ON CONFLICT DO NOTHING`,
			tenant, name, batch); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE lists SET last_refresh=now(), last_error=NULL, entry_count=$3, updated_at=now()
		WHERE tenant_id=$1 AND name=$2`, tenant, name, len(values)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// NoteListError records a failed refresh without discarding what is cached.
//
// The previous contents stay. An upstream outage should degrade to stale data rather
// than to an empty list, because an empty list is not "no data" to a rule — it is a
// confident "not a member".
func (s *Store) NoteListError(ctx context.Context, tenant, name string, err error) error {
	_, e := s.pg.Exec(ctx,
		`UPDATE lists SET last_error=$3, updated_at=now() WHERE tenant_id=$1 AND name=$2`,
		tenant, name, err.Error())
	return e
}

// CachedList returns a fetched or feed list's contents.
func (s *Store) CachedList(ctx context.Context, tenant, name string) ([]string, error) {
	rows, err := s.pg.Query(ctx, `SELECT value FROM list_cache WHERE tenant_id=$1 AND name=$2`, tenant, name)
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

// AddOverride records an operator addition or exclusion.
func (s *Store) AddOverride(ctx context.Context, tenant, name, value, kind, note, by string) error {
	if kind != "include" && kind != "exclude" {
		return fmt.Errorf("store: %q is not include or exclude", kind)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("store: an empty value cannot be added to a list")
	}
	_, err := s.pg.Exec(ctx, `
		INSERT INTO list_overrides (tenant_id, name, value, kind, note, added_by)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (tenant_id, name, lower(value), kind)
		DO UPDATE SET note = EXCLUDED.note, added_by = EXCLUDED.added_by, added_at = now()`,
		tenant, name, value, kind, note, by)
	return err
}

// RemoveOverride deletes one.
func (s *Store) RemoveOverride(ctx context.Context, tenant, name, value, kind string) error {
	_, err := s.pg.Exec(ctx,
		`DELETE FROM list_overrides WHERE tenant_id=$1 AND name=$2 AND lower(value)=lower($3) AND kind=$4`,
		tenant, name, value, kind)
	return err
}

// Overrides returns what an operator has changed about a list.
func (s *Store) Overrides(ctx context.Context, tenant, name string) ([]ListOverride, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT value, kind, note, added_by, added_at FROM list_overrides
		WHERE tenant_id=$1 AND name=$2 ORDER BY kind, lower(value)`, tenant, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ListOverride
	for rows.Next() {
		var o ListOverride
		if err := rows.Scan(&o.Value, &o.Kind, &o.Note, &o.AddedBy, &o.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// AllOverrides returns every override for a tenant, keyed by list.
func (s *Store) AllOverrides(ctx context.Context, tenant string) (map[string][]ListOverride, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT name, value, kind, note, added_by, added_at FROM list_overrides
		WHERE tenant_id=$1`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string][]ListOverride{}
	for rows.Next() {
		var name string
		var o ListOverride
		if err := rows.Scan(&name, &o.Value, &o.Kind, &o.Note, &o.AddedBy, &o.AddedAt); err != nil {
			return nil, err
		}
		out[name] = append(out[name], o)
	}
	return out, rows.Err()
}

// DueForRefresh returns the fetch and feed lists whose contents are stale.
func (s *Store) DueForRefresh(ctx context.Context, tenant string) ([]ListConfig, error) {
	all, err := s.Lists(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var out []ListConfig
	for _, c := range all {
		if !c.Enabled || !c.Downloadable() || (c.URL == "" && c.Source != SourceRadar) {
			continue
		}
		if c.LastRefresh == nil || time.Since(*c.LastRefresh) >= c.RefreshEvery {
			full, err := s.ListByName(ctx, tenant, c.Name)
			if err != nil {
				continue
			}
			out = append(out, *full)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Downloadable reports a list whose contents come from the network.
func (c ListConfig) Downloadable() bool {
	switch c.Source {
	case SourceFetch, SourceFeed, SourceRadar:
		return true
	}
	return false
}
