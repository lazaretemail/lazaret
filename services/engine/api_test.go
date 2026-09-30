// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lazaretemail/lazaret/lists"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/orgconfig"
	"github.com/lazaretemail/lazaret/profile"
	"github.com/lazaretemail/lazaret/rules"
	"github.com/lazaretemail/lazaret/sensitive"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// End-to-end tests of the service, against a real Postgres and DuckLake.
//
//	LAZARET_TEST_POSTGRES='postgres://lazaret:lazaret@localhost:5433/lazaret?sslmode=disable' \
//	  go test . -v

const testRule = `
name: "Test: urgent wire request"
type: "rule"
severity: "high"
source: |
  strings.icontains(subject.subject, "urgent")
  and strings.icontains(body.current_thread.text, "wire")
id: "test-urgent-wire"
`

const testProfileRule = `
name: "Test: first contact"
type: "rule"
severity: "medium"
source: |
  profile.by_sender().prevalence == "new"
id: "test-first-contact"
`

// apiToken is the credential the tests authenticate with. Created per test alongside
// the tenant, because the API now requires one — which is the point: an endpoint that
// can quarantine mail should not be reachable without a credential, and a test suite
// that bypassed auth would stop noticing if that changed.
func newAPI(t *testing.T) (*API, *store.Store) {
	t.Helper()
	dsn, dir := isolatedDB(t)

	st, err := store.Open(context.Background(), store.Options{Postgres: dsn, DataPath: dir, RawPath: filepath.Join(dir, "raw")})
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.EnsureTenant(context.Background(), "default", "default", nil); err != nil {
		t.Fatal(err)
	}

	rulesDir := t.TempDir()
	for name, body := range map[string]string{"urgent.yml": testRule, "firstcontact.yml": testProfileRule} {
		if err := os.WriteFile(rulesDir+"/"+name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	org := &orgconfig.Config{Domains: []string{"example.com"}}
	org.Normalize()

	resolver := lists.MustEmbedded()
	resolver.AddOrgLists(org)

	mux := mql.NewMux()
	mux.Handle(sensitive.New(), sensitive.Capabilities()...)
	mux.Handle(profile.New(st), profile.Capabilities()...)

	engine, failures, err := loadRules(rulesDir, &rules.Options{Lists: resolver, SkipDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range failures {
		t.Fatalf("rule failed to load: %v", f)
	}

	token, err := st.NewAPIToken(context.Background(), "default", "test", store.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	testToken = token

	pipeline := &Pipeline{
		store: st, org: org, enricher: mux, lists: resolver,
		providerNames: []string{"sensitive", "profile"},
	}
	pipeline.setRules(engine)

	return &API{
		store:         st,
		pipeline:      pipeline,
		hunter:        NewHunter(st, resolver),
		defaultTenant: "default",
		maxBody:       16 << 20,
	}, st
}

func isolatedDB(t *testing.T) (dsn, dir string) {
	t.Helper()
	admin := os.Getenv("LAZARET_TEST_POSTGRES")
	if admin == "" {
		t.Skip("set LAZARET_TEST_POSTGRES to run the API tests")
	}
	name := "lazaret_api_" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "_"))
	if len(name) > 60 {
		name = name[:60]
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	pool.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	if _, err := pool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(admin)
	u.Path = "/" + name
	return u.String(), t.TempDir()
}

func message(subject, body, from string) []byte {
	return []byte("From: Sender <" + from + ">\r\n" +
		"To: victim@example.com\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: Mon, 02 Mar 2026 10:00:00 +0000\r\n" +
		"Message-ID: <" + subject + "@" + from + ">\r\n\r\n" + body + "\r\n")
}

// testToken is set by newAPI. A package-level variable rather than a parameter on
// every call, because threading a credential through forty call sites would obscure
// what each test is actually asserting.
var testToken string

func post(t *testing.T, a *API, path string, body any) (int, map[string]any) {
	t.Helper()
	buf, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(buf))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func get(t *testing.T, a *API, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestIngestEvaluatesAndPersists(t *testing.T) {
	a, st := newAPI(t)

	raw := message("URGENT payment", "please wire the funds today", "attacker@evil.test")
	code, out := post(t, a, "/v0/messages/ingest", map[string]string{
		"raw_message": base64.StdEncoding.EncodeToString(raw),
	})
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, out)
	}
	if out["verdict"] != "malicious" {
		t.Errorf("verdict = %v, want malicious", out["verdict"])
	}
	if out["recorded"] != true {
		t.Errorf("recorded = %v, want true", out["recorded"])
	}

	stats, err := st.Stats(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Messages != 1 {
		t.Errorf("%d messages stored, want 1", stats.Messages)
	}
}

// analyze must not write. Otherwise anyone with API access can build a sender a
// reputation by submitting mail that was never delivered.
func TestAnalyzeDoesNotPersist(t *testing.T) {
	a, st := newAPI(t)

	raw := message("URGENT payment", "please wire the funds today", "attacker@evil.test")
	code, out := post(t, a, "/v0/messages/analyze", map[string]string{
		"raw_message": base64.StdEncoding.EncodeToString(raw),
	})
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, out)
	}
	if out["recorded"] == true {
		t.Error("analyze recorded the message")
	}

	stats, _ := st.Stats(context.Background(), "default")
	if stats.Messages != 0 {
		t.Errorf("%d messages stored by analyze, want 0", stats.Messages)
	}
}

// The payoff of module 2: a profile rule that could only ever report indeterminate in
// the CLI now reaches a real verdict, and the verdict changes as history accumulates.
func TestProfilesAccumulateAcrossIngests(t *testing.T) {
	a, _ := newAPI(t)

	first := message("Hello", "just checking in", "new@partner.test")
	_, out := post(t, a, "/v0/messages/ingest", map[string]string{
		"raw_message": base64.StdEncoding.EncodeToString(first),
	})
	if !matched(out, "Test: first contact") {
		t.Fatalf("first message did not match the first-contact rule: %v", out["matched"])
	}

	// A second message from the same sender, later. The sender is no longer new, so the
	// rule must stop firing — which is only possible because the first was recorded.
	second := []byte(strings.Replace(string(first), "Subject: Hello", "Subject: Hello again", 1))
	second = []byte(strings.Replace(string(second), "<Hello@", "<Hello2@", 1))
	second = []byte(strings.Replace(string(second), "02 Mar 2026", "09 Mar 2026", 1))

	_, out2 := post(t, a, "/v0/messages/ingest", map[string]string{
		"raw_message": base64.StdEncoding.EncodeToString(second),
	})
	if matched(out2, "Test: first contact") {
		t.Error("the second message from a known sender still matched first contact")
	}
}

func matched(out map[string]any, name string) bool {
	list, _ := out["matched"].([]any)
	for _, m := range list {
		if mm, ok := m.(map[string]any); ok && mm["name"] == name {
			return true
		}
	}
	return false
}

func TestValidateReportsDiagnostics(t *testing.T) {
	a, _ := newAPI(t)

	code, out := post(t, a, "/v0/rules/validate", map[string]string{"source": "sender.emial == \"x\""})
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if out["success"] != false {
		t.Error("a misspelled field validated")
	}
	if d, _ := out["diagnostics"].(string); !strings.Contains(d, "did you mean") {
		t.Errorf("diagnostics did not suggest a correction: %v", out["diagnostics"])
	}

	_, ok := post(t, a, "/v0/rules/validate", map[string]string{"source": "type.inbound", "type": "rule"})
	if ok["success"] != true {
		t.Errorf("a valid rule failed to validate: %v", ok)
	}
}

func TestHuntFindsStoredMessages(t *testing.T) {
	a, _ := newAPI(t)

	for i, subj := range []string{"URGENT one", "Quiet two", "URGENT three"} {
		raw := message(subj, "please wire the funds", "s"+string(rune('a'+i))+"@evil.test")
		post(t, a, "/v0/messages/ingest", map[string]string{
			"raw_message": base64.StdEncoding.EncodeToString(raw),
		})
	}

	code, out := post(t, a, "/v0/hunt-jobs", map[string]string{
		"source": `strings.icontains(subject.subject, "urgent")`,
		"from":   "2026-01-01T00:00:00Z",
		"to":     "2026-12-31T00:00:00Z",
	})
	if code != http.StatusAccepted {
		t.Fatalf("status %d: %v", code, out)
	}
	id, _ := out["id"].(string)

	var job map[string]any
	for range 50 {
		_, job = get(t, a, "/v0/hunt-jobs/"+id)
		if job["state"] == "finished" || job["state"] == "failed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if job["state"] != "finished" {
		t.Fatalf("job state %v: %v", job["state"], job["error"])
	}
	if n, _ := job["messages_scanned"].(float64); n != 3 {
		t.Errorf("scanned %v, want 3", job["messages_scanned"])
	}
	if n, _ := job["messages_matched"].(float64); n != 2 {
		t.Errorf("matched %v, want 2", job["messages_matched"])
	}
}

// The disposition path the project is named for.
func TestActionsAreAppendOnlyAndAttributed(t *testing.T) {
	a, st := newAPI(t)

	// Quarantine removes the message from the mailbox, so it is refused unless the
	// original bytes are held: deleting something that cannot be put back is not a
	// reversible decision, and a verdict may be overturned.
	if err := st.PutRaw(context.Background(), "default", "m1",
		[]byte("Message-ID: <m1>\r\nSubject: held\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}

	code, _ := post(t, a, "/v0/messages/m1/actions", map[string]string{
		"action": "quarantine", "reason": "impersonation",
	})
	if code != http.StatusCreated {
		t.Fatalf("status %d", code)
	}
	post(t, a, "/v0/messages/m1/actions", map[string]string{
		"action": "release", "reason": "false positive",
	})

	// An action nobody defined is refused rather than recorded as free text.
	if code, _ := post(t, a, "/v0/messages/m1/actions", map[string]string{"action": "delete_everything"}); code != http.StatusBadRequest {
		t.Errorf("an unknown action returned %d", code)
	}

	// And a message whose bytes are not held cannot be quarantined at all.
	code, body := post(t, a, "/v0/messages/never-seen/actions", map[string]string{
		"action": "quarantine", "reason": "test",
	})
	if code != http.StatusConflict {
		t.Errorf("quarantining an unheld message returned %d, want 409: it would be deleted "+
			"from the mailbox with no copy to release", code)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "not held") {
		t.Errorf("the refusal does not say why: %q", msg)
	}

	_, log := get(t, a, "/v0/messages/m1/actions")
	acts, _ := log["actions"].([]any)
	if len(acts) != 2 {
		t.Fatalf("%d actions logged, want 2", len(acts))
	}
	first, _ := acts[0].(map[string]any)
	if first["action"] != "quarantine" {
		t.Errorf("first action = %v", first)
	}
	// The actor comes from the authenticated caller, never from the request body. A
	// client that can name its own actor can forge an audit trail, which is the one
	// thing an audit trail must not permit.
	if actor, _ := first["actor"].(string); actor != "service:test" {
		t.Errorf("actor = %q, want the authenticated caller", actor)
	}
}

// The API must not be reachable without a credential. It can quarantine mail, read
// every message, and enumerate an organisation's correspondents.
func TestAPIRequiresAuthentication(t *testing.T) {
	a, _ := newAPI(t)

	for _, path := range []string{"/v0/messages", "/v0/insights", "/v0/rules", "/v0/stats"} {
		req := httptest.NewRequest(http.MethodGet, path, nil) // no Authorization
		rec := httptest.NewRecorder()
		a.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without credentials: status %d, want 401", path, rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: no WWW-Authenticate header", path)
		}
	}

	// Health stays open, because a load balancer needs it and it reveals nothing.
	req := httptest.NewRequest(http.MethodGet, "/v0/health", nil)
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("health needs credentials: %d", rec.Code)
	}
}

// A viewer may read and must not act.
func TestRolesAreEnforcedOnTheAPI(t *testing.T) {
	a, st := newAPI(t)

	viewer, err := st.NewAPIToken(context.Background(), "default", "readonly", store.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}

	call := func(method, path string, body []byte) int {
		var rdr *bytes.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Authorization", "Bearer "+viewer)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.Routes().ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call(http.MethodGet, "/v0/messages", nil); code != http.StatusOK {
		t.Errorf("a viewer could not read: %d", code)
	}
	if code := call(http.MethodPost, "/v0/messages/m1/actions",
		[]byte(`{"action":"quarantine"}`)); code != http.StatusForbidden {
		t.Errorf("a viewer could act: %d", code)
	}
	if code := call(http.MethodGet, "/v0/users", nil); code != http.StatusForbidden {
		t.Errorf("a viewer could list accounts: %d", code)
	}
}

func TestMessageDataModelRoundTrips(t *testing.T) {
	a, _ := newAPI(t)

	raw := message("Roundtrip", "hello", "someone@partner.test")
	post(t, a, "/v0/messages/ingest", map[string]string{
		"raw_message": base64.StdEncoding.EncodeToString(raw),
	})

	id := url.PathEscape("Roundtrip@someone@partner.test")
	code, out := get(t, a, "/v0/messages/"+id+"/message_data_model")
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, out)
	}
	sender, _ := out["sender"].(map[string]any)
	email, _ := sender["email"].(map[string]any)
	if email["email"] != "someone@partner.test" {
		t.Errorf("sender = %v", email["email"])
	}
}
