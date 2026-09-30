// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lazaretemail/lazaret/orgconfig"
	"github.com/lazaretemail/lazaret/profile"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Integration tests against a real Postgres and a real DuckLake.
//
// Opt-in, because they need a database. Not mocked, deliberately: the things worth
// testing here are whether DuckLake actually attaches with a Postgres catalog, whether
// an inlined write reaches Parquet, and whether an as-of query respects its boundary —
// none of which a fake can tell you anything about. The same reasoning as the Strelka
// live tests, and for the same reason: a fake only ever confirms what its author
// already believed.
//
//	docker run -d --name lazaret-pg -e POSTGRES_PASSWORD=lazaret -e POSTGRES_USER=lazaret \
//	  -e POSTGRES_DB=lazaret -p 5433:5432 postgres:17-alpine
//	LAZARET_TEST_POSTGRES='postgres://lazaret:lazaret@localhost:5433/lazaret?sslmode=disable' \
//	  go test ./store/ -v
func openStore(t *testing.T) *store.Store {
	t.Helper()
	dsn, dir := isolated(t)
	s, err := store.Open(context.Background(), store.Options{Postgres: dsn, DataPath: dir, RawPath: filepath.Join(dir, "raw")})
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// isolated gives a test its own Postgres database and its own data directory.
//
// A database rather than a schema, because a DuckLake catalog is *bound to its data
// path*: attaching with a different DATA_PATH than the catalog was created with is a
// configuration error, not a migration. That is worth knowing operationally — the data
// path cannot be changed after the fact without rebuilding the catalog — and it means
// tests cannot share one database however carefully they name their tables.
func isolated(t *testing.T) (dsn, dir string) {
	t.Helper()
	admin := os.Getenv("LAZARET_TEST_POSTGRES")
	if admin == "" {
		t.Skip("set LAZARET_TEST_POSTGRES to run the storage tests")
	}

	name := "lazaret_test_" + strings.ToLower(strings.NewReplacer("/", "_", "-", "_").Replace(t.Name()))
	if len(name) > 60 {
		name = name[:60]
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatalf("connecting to postgres: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
		t.Fatalf("dropping %s: %v", name, err)
	}
	if _, err := pool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parsing the connection string: %v", err)
	}
	u.Path = "/" + name
	return u.String(), t.TempDir()
}

func day(n int) time.Time { return time.Date(2026, 3, n, 12, 0, 0, 0, time.UTC) }

func seed(t *testing.T, s *store.Store, tenant string) {
	t.Helper()
	ctx := context.Background()
	if err := s.EnsureTenant(ctx, tenant, tenant, nil); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	for i, e := range []struct {
		n         int
		email     string
		direction string
		verdict   string
	}{
		{1, "cfo@partner.test", "outbound", "benign"},
		{3, "cfo@partner.test", "inbound", "benign"},
		{5, "cfo@partner.test", "inbound", ""},
		{7, "attacker@evil.test", "inbound", "malicious"},
	} {
		at := day(e.n)
		m := store.Message{
			TenantID: tenant, MessageID: id(tenant, i), ReceivedAt: at,
			SenderEmail: e.email, SenderDomain: domainOf(e.email),
			Direction: e.direction, Verdict: e.verdict, MDM: []byte(`{"subject":{"subject":"x"}}`),
		}
		v := store.Verdict{TenantID: tenant, MessageID: m.MessageID, At: at, Verdict: "clean",
			Missing: []string{"ml.nlu_classifier"}}
		ev := store.SenderEvent{TenantID: tenant, At: at, SenderEmail: e.email,
			SenderDomain: domainOf(e.email), Direction: e.direction, Verdict: e.verdict,
			AuthFailed: e.email == "attacker@evil.test"}
		if err := s.PutMessage(ctx, m, v, ev); err != nil {
			t.Fatalf("writing message %d: %v", i, err)
		}
	}
}

func id(tenant string, i int) string { return tenant + "-msg-" + string(rune('a'+i)) }

func domainOf(email string) string {
	for i := range email {
		if email[i] == '@' {
			return email[i+1:]
		}
	}
	return ""
}

// The property the whole two-store design exists for. A query from day 4 must not see
// day 5, or every backtest scores against knowledge the rules did not have.
func TestProfileEventsAreTimeRelative(t *testing.T) {
	s := openStore(t)
	tenant := "asof"
	seed(t, s, tenant)

	ctx := store.WithTenant(context.Background(), tenant)
	key := profile.Key{Kind: profile.ByEmail, Value: "cfo@partner.test"}

	for _, tc := range []struct{ at, want int }{{2, 1}, {4, 2}, {6, 3}, {100, 3}} {
		got, err := s.Events(ctx, key, day(tc.at))
		if err != nil {
			t.Fatalf("as of day %d: %v", tc.at, err)
		}
		if len(got) != tc.want {
			t.Errorf("as of day %d: %d events, want %d", tc.at, len(got), tc.want)
		}
	}

	// Strictly before: a message never profiles itself, and two in the same instant do
	// not see each other, which keeps a replay independent of load order.
	got, err := s.Events(ctx, key, day(3))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("at the instant of an event: %d, want 1", len(got))
	}
}

func TestSummaryFromRealHistory(t *testing.T) {
	s := openStore(t)
	tenant := "summary"
	seed(t, s, tenant)

	ctx := store.WithTenant(context.Background(), tenant)
	events, err := s.Events(ctx, profile.Key{Kind: profile.ByEmail, Value: "cfo@partner.test"}, day(10))
	if err != nil {
		t.Fatal(err)
	}
	sum := profile.Summarise(events, day(10))
	if !sum.Solicited {
		t.Error("solicited is false although the organisation wrote first")
	}
	if !sum.AnyBenign {
		t.Error("any_benign is false after a benign verdict")
	}
	if sum.AnyMalicious {
		t.Error("any_malicious is true with no such verdict")
	}
	if got := profile.Prevalence(sum); got != "common" {
		t.Errorf("prevalence = %q, want common", got)
	}
}

// A retried delivery must not count twice: an inflated message count moves prevalence
// from "new" to "outlier" and silently stops first-contact rules firing.
func TestIngestIsIdempotent(t *testing.T) {
	s := openStore(t)
	tenant := "dup"
	ctx := context.Background()
	if err := s.EnsureTenant(ctx, tenant, tenant, nil); err != nil {
		t.Fatal(err)
	}

	m := store.Message{TenantID: tenant, MessageID: "same", ReceivedAt: day(1),
		SenderEmail: "a@b.test", SenderDomain: "b.test", Direction: "inbound", MDM: []byte(`{}`)}
	v := store.Verdict{TenantID: tenant, MessageID: "same", At: day(1), Verdict: "clean"}
	e := store.SenderEvent{TenantID: tenant, At: day(1), SenderEmail: "a@b.test",
		SenderDomain: "b.test", Direction: "inbound"}

	if err := s.PutMessage(ctx, m, v, e); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := s.PutMessage(ctx, m, v, e); err != store.ErrDuplicate {
		t.Fatalf("second write returned %v, want ErrDuplicate", err)
	}

	st, err := s.Stats(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if st.Messages != 1 {
		t.Errorf("%d messages stored, want 1", st.Messages)
	}
}

// The materialised profile must be exactly rebuildable from the event log. That is what
// makes keeping a mutable cache safe: if it drifts, it can be thrown away.
func TestRebuildMatchesTheEventLog(t *testing.T) {
	s := openStore(t)
	tenant := "rebuild"
	seed(t, s, tenant)
	ctx := context.Background()

	before := profiles(t, s, tenant)
	if len(before) == 0 {
		t.Fatal("no profiles were materialised")
	}
	if err := s.Rebuild(ctx, tenant); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	after := profiles(t, s, tenant)

	if len(before) != len(after) {
		t.Fatalf("%d profiles before, %d after", len(before), len(after))
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s: %d before, %d after", k, v, after[k])
		}
	}
}

func profiles(t *testing.T, s *store.Store, tenant string) map[string]int64 {
	t.Helper()
	rows, err := s.PG().Query(context.Background(),
		`SELECT kind || ':' || key, messages FROM sender_profiles WHERE tenant_id = $1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		out[k] = n
	}
	return out
}

// Recording which capabilities were missing is what makes a message re-runnable when a
// downed service returns.
func TestMessagesMissingFindsRerunnableMessages(t *testing.T) {
	s := openStore(t)
	tenant := "rerun"
	seed(t, s, tenant)

	ids, err := s.MessagesMissing(context.Background(), tenant, "ml.nlu_classifier", day(1), day(30))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 4 {
		t.Errorf("%d messages await ml.nlu_classifier, want 4", len(ids))
	}
	none, err := s.MessagesMissing(context.Background(), tenant, "ml.logo_detect", day(1), day(30))
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("%d messages await a capability nothing asked for", len(none))
	}
}

// Inlined writes must reach Parquet. Without the flush the corpus lives in Postgres
// forever and the storage design inverts itself.
func TestCompactFlushesInlinedDataToParquet(t *testing.T) {
	dsn, dir := isolated(t)
	s, err := store.Open(context.Background(), store.Options{Postgres: dsn, DataPath: dir, RawPath: filepath.Join(dir, "raw")})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	seed(t, s, "parquet")

	if n := countParquet(t, dir); n != 0 {
		t.Fatalf("%d parquet files before compaction; writes should still be inlined", n)
	}
	if err := s.Compact(context.Background()); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if n := countParquet(t, dir); n == 0 {
		t.Fatal("no parquet after compaction: inlined data never left the catalog")
	}

	// And the data is still readable through the same queries.
	st, err := s.Stats(context.Background(), "parquet")
	if err != nil {
		t.Fatal(err)
	}
	if st.Messages != 4 {
		t.Errorf("%d messages readable after the flush, want 4", st.Messages)
	}
}

func countParquet(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepathWalk(dir, func(path string) {
		if len(path) > 8 && path[len(path)-8:] == ".parquet" {
			n++
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHostileRecipientsAreBound checks that message-derived strings reach DuckDB as
// bound parameters rather than as SQL text.
//
// The first version of the corpus writer rendered the recipient array as a list
// literal with quotes doubled. Recipients come from the message headers, which is to
// say from whoever sent the mail, so that put sender-controlled text into a statement
// body. The escaping was correct as written, which is exactly why it is worth a test:
// the next edit near it would not have known it was load-bearing.
func TestHostileRecipientsAreBound(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	tenant := "hostile"
	if err := s.EnsureTenant(ctx, tenant, tenant, nil); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}

	hostile := []string{
		`a'); DROP TABLE corpus.messages; --@evil.test`,
		`b''@evil.test`,
		"c\\'@evil.test",
		"d\x00e@evil.test",
		"f\n'@evil.test",
	}
	at := day(2)
	m := store.Message{
		TenantID: tenant, MessageID: "hostile-1", ReceivedAt: at,
		SenderEmail: "attacker@evil.test", SenderDomain: "evil.test",
		Subject: `'); DROP TABLE corpus.messages; --`, Direction: "inbound",
		Verdict: "malicious", MDM: []byte(`{}`), Recipients: hostile,
	}
	v := store.Verdict{
		TenantID: tenant, MessageID: m.MessageID, At: at, Verdict: "malicious",
		Matched: []string{`rule'); DROP TABLE corpus.verdicts; --`},
	}
	e := store.SenderEvent{
		TenantID: tenant, At: at, SenderEmail: m.SenderEmail,
		SenderDomain: m.SenderDomain, Direction: "inbound", Verdict: "malicious",
	}
	if err := s.PutMessage(ctx, m, v, e); err != nil {
		t.Fatalf("recording a message with hostile recipients: %v", err)
	}

	// The table still exists, and the values came back byte-for-byte rather than
	// half-interpreted.
	got, err := s.RecipientList(ctx, tenant, "email")
	if err != nil {
		t.Fatalf("reading recipients back: %v", err)
	}
	have := map[string]bool{}
	for _, g := range got {
		have[g] = true
	}
	for _, want := range hostile {
		// NUL is the one character deliberately not preserved; see withoutNUL.
		want = strings.ReplaceAll(want, "\x00", "")
		if !have[strings.ToLower(want)] && !have[want] {
			t.Errorf("recipient %q did not survive the round trip; got %q", want, got)
		}
	}
}

// TestEnsureTenantDoesNotWipeOrgConfig covers silent data loss on restart.
//
// EnsureTenant runs on every startup to make sure the tenant row exists. Its upsert
// originally set org_config unconditionally, so each restart replaced an admin's
// configured domains with {}. Nothing failed and nothing was logged; the only symptom
// was that the 138 rules gated on $org_domains started reporting indeterminate.
func TestEnsureTenantDoesNotWipeOrgConfig(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	if err := s.EnsureTenant(ctx, "t", "t", []byte(`{"domains":["example.test"]}`)); err != nil {
		t.Fatal(err)
	}
	// The startup call: no configuration to offer, and none of its business.
	if err := s.EnsureTenant(ctx, "t", "t", nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.OrgConfig(ctx, "t")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "example.test") {
		t.Fatalf("org config lost on the second EnsureTenant: %s", got)
	}
}

// TestOrgConfigSurvivesTheStore checks the jsonb round trip.
//
// orgconfig.Config is written with encoding/json and read back by a parser that looks
// for the yaml spellings. Without json tags Go marshals Domains/VIPs/DisplayNames, the
// read finds no lowercase keys, and an empty configuration comes back with no error
// anywhere.
func TestOrgConfigSurvivesTheStore(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	in := orgconfig.Config{
		Domains:      []string{"example.test", "example.invalid"},
		VIPs:         []orgconfig.VIP{{Email: "ceo@example.test", DisplayName: "Dana Reyes"}},
		DisplayNames: []string{"Finance Team"},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureTenant(ctx, "t", "t", raw); err != nil {
		t.Fatal(err)
	}
	stored, err := s.OrgConfig(ctx, "t")
	if err != nil {
		t.Fatal(err)
	}
	var out orgconfig.Config
	if err := json.Unmarshal(stored, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Domains) != 2 || out.Domains[0] != "example.test" {
		t.Errorf("domains did not survive: %#v", out.Domains)
	}
	if len(out.VIPs) != 1 || out.VIPs[0].Email != "ceo@example.test" || out.VIPs[0].DisplayName != "Dana Reyes" {
		t.Errorf("vips did not survive: %#v", out.VIPs)
	}
	if len(out.DisplayNames) != 1 {
		t.Errorf("display names did not survive: %#v", out.DisplayNames)
	}
}
