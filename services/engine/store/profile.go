// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/lazaretemail/lazaret/profile"
)

// The profile store is two stores, and the ADR is explicit about why.
//
// DuckLake holds corpus.sender_events, append-only, and answers "as of" for any moment.
// Postgres holds sender_profiles, one mutable row per sender, and answers "now" in a
// single indexed lookup during delivery.
//
// A single mutable table would be faster and would be wrong: it cannot answer "as of
// last March" at all, so every backtest reading it would silently see the future and
// score better than the rules ever did in production. A single event log would be
// correct and too slow for the delivery path, where profile.* is consulted 898 times
// per message across the corpus.
//
// So: the log is the source of truth, the table is a derived cache of its present
// state, and Rebuild regenerates one from the other.

// Events implements profile.Store against the append-only log.
//
// Strictly before `at`, so a message never profiles itself and two messages in the same
// second do not see each other — which is what keeps a replay independent of the order
// a batch happened to be loaded in.
func (s *Store) Events(ctx context.Context, key profile.Key, at time.Time) ([]profile.Event, error) {
	column := map[profile.Kind]string{
		profile.ByEmail:   "sender_email",
		profile.ByDomain:  "sender_domain",
		profile.ByReplyTo: "reply_to",
	}[key.Kind]
	if column == "" {
		return nil, fmt.Errorf("store: unknown profile key kind %q", key.Kind)
	}

	rows, err := s.duck.QueryContext(ctx, fmt.Sprintf(`
		SELECT occurred_at, sender_email, sender_domain, reply_to, direction, verdict, auth_failed
		FROM corpus.sender_events
		WHERE tenant_id = ? AND lower(%s) = lower(?) AND occurred_at < ?`, column),
		s.tenant(ctx), key.Value, at.UTC())
	if err != nil {
		// An error here must reach the caller rather than becoming an empty slice: an
		// empty history profiles as "nobody has ever heard from this sender", which is
		// the most suspicious answer there is, asserted on no evidence.
		return nil, fmt.Errorf("store: reading sender history: %w", err)
	}
	defer rows.Close()

	var out []profile.Event
	for rows.Next() {
		var e profile.Event
		var email, domain, replyTo, direction, verdict *string
		if err := rows.Scan(&e.At, &email, &domain, &replyTo, &direction, &verdict, &e.AuthFailed); err != nil {
			return nil, err
		}
		e.SenderEmail, e.SenderDomain, e.ReplyTo = deref(email), deref(domain), deref(replyTo)
		e.Direction = profile.Direction(deref(direction))
		e.Verdict = profile.Verdict(deref(verdict))
		out = append(out, e)
	}
	return out, rows.Err()
}

// tenantKey is how a tenant travels to the Store's query methods.
//
// profile.Store's signature is fixed by the root module, which knows nothing about
// tenants — correctly, since the library is single-tenant by construction and it is this
// service that adds the dimension. The context carries it rather than the interface.
type tenantKey struct{}

// WithTenant scopes a context to a tenant.
func WithTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

// TenantFrom returns the tenant a context is scoped to.
func TenantFrom(ctx context.Context) string {
	t, _ := ctx.Value(tenantKey{}).(string)
	return t
}

func (s *Store) tenant(ctx context.Context) string {
	if t := TenantFrom(ctx); t != "" {
		return t
	}
	return "default"
}

// refreshProfile folds one event into the materialised current profile.
//
// An upsert per key rather than a recount: the table is a running aggregate, and
// recomputing it from the log on every message would make delivery cost grow with
// history. It is exactly rebuildable, which is what makes that safe — see Rebuild.
func (s *Store) refreshProfile(ctx context.Context, e SenderEvent) error {
	keys := []struct{ kind, value string }{
		{"email", e.SenderEmail},
		{"domain", e.SenderDomain},
		{"reply_to", e.ReplyTo},
	}
	for _, k := range keys {
		if k.value == "" {
			continue
		}
		inbound, outbound := e.Direction == "inbound", e.Direction == "outbound"
		_, err := s.pg.Exec(ctx, `
			INSERT INTO sender_profiles
			  (tenant_id, kind, key, messages, first_contact, last_contact,
			   last_inbound, last_outbound, solicited, any_benign, any_malicious,
			   any_false_pos, all_auth_failed)
			VALUES ($1, $2, lower($3), 1, $4::timestamptz, $4::timestamptz,
			        CASE WHEN $5::boolean THEN $4::timestamptz END,
			        CASE WHEN $6::boolean THEN $4::timestamptz END,
			        $6::boolean, $7::boolean, $8::boolean, $9::boolean, $10::boolean)
			ON CONFLICT (tenant_id, kind, key) DO UPDATE SET
			  messages        = sender_profiles.messages + 1,
			  first_contact   = least(sender_profiles.first_contact, EXCLUDED.first_contact),
			  last_contact    = greatest(sender_profiles.last_contact, EXCLUDED.last_contact),
			  last_inbound    = greatest(sender_profiles.last_inbound, EXCLUDED.last_inbound),
			  last_outbound   = greatest(sender_profiles.last_outbound, EXCLUDED.last_outbound),
			  solicited       = sender_profiles.solicited OR EXCLUDED.solicited,
			  any_benign      = sender_profiles.any_benign OR EXCLUDED.any_benign,
			  any_malicious   = sender_profiles.any_malicious OR EXCLUDED.any_malicious,
			  any_false_pos   = sender_profiles.any_false_pos OR EXCLUDED.any_false_pos,
			  all_auth_failed = sender_profiles.all_auth_failed AND EXCLUDED.all_auth_failed`,
			e.TenantID, k.kind, k.value, e.At.UTC(), inbound, outbound,
			e.Verdict == "benign" || e.Verdict == "false_positive",
			e.Verdict == "malicious" || e.Verdict == "spam",
			e.Verdict == "false_positive",
			e.AuthFailed)
		if err != nil {
			return fmt.Errorf("store: refreshing profile: %w", err)
		}
	}
	return nil
}

// Rebuild regenerates the materialised profiles from the event log.
//
// The property that makes the cache safe to keep: it is derived, so it can be thrown
// away. Needed after a bulk import, after a retention deletion, and any time the two
// are suspected of having drifted.
func (s *Store) Rebuild(ctx context.Context, tenant string) error {
	if _, err := s.pg.Exec(ctx, `DELETE FROM sender_profiles WHERE tenant_id = $1`, tenant); err != nil {
		return err
	}

	rows, err := s.duck.QueryContext(ctx, `
		SELECT occurred_at, sender_email, sender_domain, reply_to, direction, verdict, auth_failed
		FROM corpus.sender_events WHERE tenant_id = ? ORDER BY occurred_at`, tenant)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var e SenderEvent
		var email, domain, replyTo, verdict *string
		if err := rows.Scan(&e.At, &email, &domain, &replyTo, &e.Direction, &verdict, &e.AuthFailed); err != nil {
			return err
		}
		e.TenantID = tenant
		e.SenderEmail, e.SenderDomain, e.ReplyTo, e.Verdict = deref(email), deref(domain), deref(replyTo), deref(verdict)
		if err := s.refreshProfile(ctx, e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// SenderList returns the addresses or domains a tenant has heard from, for
// $sender_emails and $sender_domains.
//
// Inbound and internal only: an address the organisation has written *to* has sent
// nothing, and counting it would make every outbound correspondent look established.
func (s *Store) SenderList(ctx context.Context, tenant, kind string) ([]string, error) {
	column := "sender_email"
	if kind == "domain" {
		column = "sender_domain"
	}
	rows, err := s.duck.QueryContext(ctx, fmt.Sprintf(`
		SELECT DISTINCT lower(%s) FROM corpus.sender_events
		WHERE tenant_id = ? AND direction <> 'outbound' AND %s IS NOT NULL AND %s <> ''
		ORDER BY 1`, column, column, column), tenant)
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

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
