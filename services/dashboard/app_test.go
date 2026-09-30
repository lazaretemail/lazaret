// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// The dashboard speaks only to the engine's HTTP API, so a stub engine is a faithful
// double here: there is no hidden coupling for it to hide.

type stub struct {
	mux      *http.ServeMux
	role     string
	lastAuth string
	payloads map[string]any
}

func newStub(role string) *stub {
	s := &stub{mux: http.NewServeMux(), role: role, payloads: map[string]any{}}
	s.mux.HandleFunc("GET /v0/auth/whoami", func(w http.ResponseWriter, r *http.Request) {
		s.lastAuth = r.Header.Get("Authorization")
		if s.lastAuth == "" {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(WhoAmI{UserID: "usr_1", Email: "a@example.com", TenantID: "default", Role: s.role})
	})
	s.mux.HandleFunc("POST /v0/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		if in["password"] != "correct-horse-battery" {
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"token": "session-token", "expires_at": time.Now().Add(time.Hour)})
	})
	s.handle("/v0/messages", map[string]any{"messages": []Message{}})
	s.handle("/v0/triage/counts", map[string]any{"counts": map[string]int{}, "flagged": 0})
	s.handle("/v0/insights", Insights{Totals: map[string]int64{}})
	s.handle("/v0/coverage", Coverage{})
	s.handle("/v0/rules", map[string]any{"rules": []Rule{}})
	s.handle("/v0/capabilities", Capabilities{})
	s.handle("/v0/mailboxes", map[string]any{"mailboxes": []Mailbox{}})
	s.handle("/v0/graph-app", GraphApp{DirectoryID: "dir", ClientID: "cli", HasSecret: true})
	return s
}

func (s *stub) handle(path string, payload any) {
	if _, seen := s.payloads[path]; !seen {
		s.mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(s.payloads[r.URL.Path])
		})
	}
	s.payloads[path] = payload
}

// A built console is not present in a unit test, so stand in a minimal one. The SPA
// handler only needs index.html to exist.
func testDist() fs.FS {
	return fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<!doctype html><div id=app></div>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("export default 1")},
	}
}

func newApp(t *testing.T, st *stub) *App {
	t.Helper()
	srv := httptest.NewServer(st.mux)
	t.Cleanup(srv.Close)
	engine := &EngineClient{Base: srv.URL, Tenant: "default", HTTP: srv.Client()}
	return &App{engine: engine, auth: &Auth{Engine: engine, Secure: false, DefaultRole: "viewer"}}
}

func do(t *testing.T, a *App, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := a.Routes(testDist())
	if err != nil {
		t.Fatalf("routes: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func withSession(req *http.Request) *http.Request {
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session-token"})
	return req
}

// withCSRF adds the session and the matching synchroniser token.
func withCSRF(req *http.Request) *http.Request {
	withSession(req)
	req.Header.Set("X-CSRF-Token", csrfFor("session-token"))
	return req
}

func jsonReq(method, path string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// ---------------------------------------------------------------------------
// Authentication and authorisation
// ---------------------------------------------------------------------------

// An unauthenticated API call gets a status, not a redirect.
//
// fetch() follows a 303 transparently, so redirecting would hand the console a lump
// of HTML with a 200 on it, which then fails to parse a long way from the cause.
func TestUnauthenticatedAPIIs401NotARedirect(t *testing.T) {
	a := newApp(t, newStub("admin"))

	for _, path := range []string{"/api/session", "/api/triage", "/api/overview",
		"/api/detections", "/api/settings/users", "/api/settings/mailboxes"} {
		rec := do(t, a, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: content type %q, want JSON", path, ct)
		}
	}
}

// A deep link into the console still serves the app, which then asks for the session
// itself. Only the API is status-gated.
func TestDeepLinkServesTheConsole(t *testing.T) {
	a := newApp(t, newStub("admin"))
	for _, path := range []string{"/", "/triage", "/messages/abc%40example.com", "/settings/users"} {
		rec := do(t, a, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `id=app`) {
			t.Errorf("%s: did not serve the app shell", path)
		}
	}
}

// A role that is not enough is a 403, not a 200 with an apologetic body. A denied
// request that reports success is indistinguishable from an allowed one to anything
// that checks the status rather than reading the page.
func TestInsufficientRoleIsForbidden(t *testing.T) {
	a := newApp(t, newStub("viewer"))
	rec := do(t, a, withSession(httptest.NewRequest(http.MethodGet, "/api/settings/users", nil)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "admin") {
		t.Errorf("the refusal does not say which role is needed: %s", rec.Body.String())
	}
}

// The browser's session is what reaches the engine, so the engine applies the same
// identity and the dashboard cannot act with more authority than its caller.
func TestTheCallersSessionReachesTheEngine(t *testing.T) {
	st := newStub("admin")
	a := newApp(t, st)
	do(t, a, withSession(httptest.NewRequest(http.MethodGet, "/api/triage", nil)))
	if st.lastAuth != "Bearer session-token" {
		t.Errorf("engine saw %q, want the caller's session", st.lastAuth)
	}
}

func TestSignInSetsAnHttpOnlySessionCookie(t *testing.T) {
	a := newApp(t, newStub("admin"))
	rec := do(t, a, jsonReq(http.MethodPost, "/api/auth/login",
		map[string]string{"email": "a@example.com", "password": "correct-horse-battery"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var session, csrf *http.Cookie
	for _, c := range rec.Result().Cookies() {
		switch c.Name {
		case sessionCookie:
			session = c
		case csrfCookie:
			csrf = c
		}
	}
	if session == nil || !session.HttpOnly {
		t.Error("the session cookie must be HttpOnly so script cannot read it")
	}
	// The CSRF token is deliberately readable: it is not a secret from this page, it
	// is a value a cross-site attacker cannot read because of the same-origin policy.
	if csrf == nil || csrf.HttpOnly {
		t.Error("the CSRF cookie must be readable by the console")
	}
}

func TestSignInRejectsBadCredentials(t *testing.T) {
	a := newApp(t, newStub("admin"))
	rec := do(t, a, jsonReq(http.MethodPost, "/api/auth/login",
		map[string]string{"email": "a@example.com", "password": "wrong"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
	// One message whatever went wrong: distinguishing "no such account" from "wrong
	// password" lets anyone enumerate who works here.
	if strings.Contains(strings.ToLower(rec.Body.String()), "no such") {
		t.Errorf("the refusal distinguishes the two failures: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

func TestStateChangeWithoutCSRFIsRefused(t *testing.T) {
	a := newApp(t, newStub("admin"))
	rec := do(t, a, withSession(jsonReq(http.MethodPost, "/api/messages/m1/triage",
		map[string]string{"state": "benign"})))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestCSRFIsBoundToTheSession(t *testing.T) {
	a := newApp(t, newStub("admin"))
	req := withSession(jsonReq(http.MethodPost, "/api/messages/m1/triage", map[string]string{"state": "benign"}))
	req.Header.Set("X-CSRF-Token", csrfFor("a-different-session"))
	if rec := do(t, a, req); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 for a token minted from another session", rec.Code)
	}
}

func TestCSRFAcceptsTheIssuedToken(t *testing.T) {
	st := newStub("admin")
	st.mux.HandleFunc("POST /v0/messages/{id}/triage", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	a := newApp(t, st)
	rec := do(t, a, withCSRF(jsonReq(http.MethodPost, "/api/messages/m1/triage", map[string]string{"state": "benign"})))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

// An .eml upload is multipart, and multipart is where the CSRF check used to break:
// ParseForm sets r.Form non-nil without reading a multipart body, so FormValue then
// skipped the parse it would otherwise have done and the token was never found.
func TestEMLUploadPassesTheCSRFCheck(t *testing.T) {
	st := newStub("admin")
	st.mux.HandleFunc("POST /v0/messages/analyze", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(MessageDetail{MessageID: "m1"})
	})
	a := newApp(t, st)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "sample.eml")
	fw.Write([]byte("Subject: hi\r\n\r\nbody"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/analyze", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	withCSRF(req)

	if rec := do(t, a, req); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEMLUploadWithoutATokenIsRefused(t *testing.T) {
	a := newApp(t, newStub("admin"))
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "sample.eml")
	fw.Write([]byte("Subject: hi\r\n\r\nbody"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/analyze", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	withSession(req)

	if rec := do(t, a, req); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestReadOnlyRefusesStateChanges(t *testing.T) {
	a := newApp(t, newStub("admin"))
	a.readOnly = true
	rec := do(t, a, withCSRF(jsonReq(http.MethodPost, "/api/messages/m1/triage", map[string]string{"state": "benign"})))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "read-only") {
		t.Errorf("the refusal does not say why: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// The credential boundary
// ---------------------------------------------------------------------------

// Mailbox and Graph secrets are reachable by a connector's service token and by
// nothing else. This is the reason the console's API is written out by hand instead
// of proxying /v0 behind a path allowlist: the engine serves both
// GET /v0/mailboxes/{id}/remediations and GET /v0/mailboxes/secrets, so any
// pattern-shaped allowlist ("/v0/mailboxes/*") would hand credentials to a browser.
func TestSecretEndpointsAreNotReachableFromABrowser(t *testing.T) {
	st := newStub("admin")
	leaked := false
	for _, p := range []string{"/v0/mailboxes/secrets", "/v0/graph-app/secrets"} {
		st.mux.HandleFunc("GET "+p, func(w http.ResponseWriter, _ *http.Request) {
			leaked = true
			json.NewEncoder(w).Encode(map[string]string{"password": "hunter2"})
		})
	}
	a := newApp(t, st)

	for _, path := range []string{
		"/api/settings/mailboxes/secrets",
		"/api/settings/mailboxes/{id}/secrets",
		"/api/settings/microsoft/secrets",
		"/api/v0/mailboxes/secrets",
		"/api/settings/mailboxes/../mailboxes/secrets",
	} {
		rec := do(t, a, withSession(httptest.NewRequest(http.MethodGet, path, nil)))
		if rec.Code == http.StatusOK {
			t.Errorf("%s: answered 200 — the console must not expose this", path)
		}
		if strings.Contains(rec.Body.String(), "hunter2") {
			t.Errorf("%s: a credential reached the browser", path)
		}
	}
	if leaked {
		t.Error("the dashboard called a secrets endpoint on the engine")
	}
}

// The configured Graph application is shown, but its secret is never echoed back —
// only whether one is stored.
func TestGraphAppSecretIsNeverReturned(t *testing.T) {
	st := newStub("admin")
	st.handle("/v0/graph-app", map[string]any{
		"directory_id": "dir", "client_id": "cli", "has_secret": true, "secret": "should-not-travel",
	})
	a := newApp(t, st)
	rec := do(t, a, withSession(httptest.NewRequest(http.MethodGet, "/api/settings/microsoft", nil)))
	if strings.Contains(rec.Body.String(), "should-not-travel") {
		t.Errorf("the client secret reached the browser: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Shell and API surface
// ---------------------------------------------------------------------------

func TestConsoleSecurityHeaders(t *testing.T) {
	a := newApp(t, newStub("admin"))
	rec := do(t, a, httptest.NewRequest(http.MethodGet, "/triage", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	// The bundle is same-origin and nothing is inlined, so neither escape hatch is
	// needed. If one appears here, something started injecting script or style at
	// runtime and the policy was weakened to match instead of the cause being fixed.
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval"} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("CSP contains %s: %s", forbidden, csp)
		}
	}
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %s", want, csp)
		}
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	// The shell names the current asset hashes, so caching it is how a browser ends
	// up asking for a bundle that no longer exists after a deploy.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// An unmatched /api path must not fall through to the app shell, which would reach
// fetch() as HTML and surface as a JSON parse error far from the cause.
func TestUnknownAPIPathIsJSON(t *testing.T) {
	a := newApp(t, newStub("admin"))
	rec := do(t, a, withSession(httptest.NewRequest(http.MethodGet, "/api/nope", nil)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<!doctype") {
		t.Error("an unknown API path was answered with the app shell")
	}
}

// ---------------------------------------------------------------------------
// Behaviour the console depends on
// ---------------------------------------------------------------------------

// A 404 from the engine is a normal thing to say plainly; a 502 means the engine is
// down and the page should offer a retry. Flattening both to one status made every
// failure look like the same failure.
func TestEngineStatusIsCarriedThrough(t *testing.T) {
	st := newStub("analyst")
	st.mux.HandleFunc("GET /v0/messages/{id}", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"no such message"}`, http.StatusNotFound)
	})
	a := newApp(t, st)
	rec := do(t, a, withSession(httptest.NewRequest(http.MethodGet, "/api/messages/gone", nil)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 rather than a generic upstream failure", rec.Code)
	}
}

// A bulk judgement reports what actually landed. Claiming the whole batch worked
// when some of it did not is how a queue quietly keeps messages nobody rechecks.
func TestBulkTriageReportsPartialFailure(t *testing.T) {
	st := newStub("analyst")
	st.mux.HandleFunc("POST /v0/messages/{id}/triage", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") == "bad" {
			http.Error(w, `{"error":"refused"}`, http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	a := newApp(t, st)

	rec := do(t, a, withCSRF(jsonReq(http.MethodPost, "/api/triage/bulk", map[string]any{
		"ids": []string{"ok1", "bad", "ok2"}, "state": "benign",
	})))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out bulkResult
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Done != 2 {
		t.Errorf("done = %d, want 2", out.Done)
	}
	if _, named := out.Failed["bad"]; !named || len(out.Failed) != 1 {
		t.Errorf("failures = %v, want exactly the one that was refused", out.Failed)
	}
}

// The screenshot for a transient analysis is inlined, and its bytes came from an
// untrusted message. Decoding and re-encoding is what makes the data: URL safe —
// the result is base64 alphabet and nothing else, under a media type this code
// chose rather than one the engine claimed.
func TestScreenshotSourceIsSanitised(t *testing.T) {
	png := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\n"))
	got := screenshotSrcFor("", &MessageDetail{Renderable: true, Screenshot: png})
	if !strings.HasPrefix(got, "data:image/png;base64,") {
		t.Fatalf("src = %q", got)
	}

	// A payload claiming to be something else cannot smuggle a media type through.
	hostile := screenshotSrcFor("", &MessageDetail{
		Renderable: true,
		Screenshot: "data:image/svg+xml,<svg onload=alert(1)>",
	})
	if hostile != "" {
		t.Errorf("a non-base64 payload produced %q, want it refused", hostile)
	}

	// A stored message is fetched from its endpoint instead, with the id escaped.
	stored := screenshotSrcFor("a b@example.com", &MessageDetail{Renderable: true})
	if strings.Contains(stored, " ") {
		t.Errorf("the message id was not escaped into the path: %q", stored)
	}

	if screenshotSrcFor("m1", &MessageDetail{Renderable: false}) != "" {
		t.Error("a message with no renderable body should offer no picture")
	}
}

func TestVerdictFollowsTheDetectionsShown(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   MessageDetail
		want string
	}{
		{"a match is malicious", MessageDetail{Detections: []Detection{{ID: "r1"}}}, "malicious"},
		{"only unanswerable rules is indeterminate", MessageDetail{Indeterminate: []Detection{{ID: "r1"}}}, "indeterminate"},
		{"nothing matched is clean", MessageDetail{}, "clean"},
	} {
		if got := verdictOf(&tc.in); got != tc.want {
			t.Errorf("%s: verdictOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Absence of a triage row means nobody has looked, which is unreviewed rather than
// unknown — otherwise new mail never appears in the queue that exists to catch it.
func TestUnsetTriageStateIsUnreviewed(t *testing.T) {
	if got := triageStateOf(Message{}); got != "unreviewed" {
		t.Errorf("triageStateOf = %q, want unreviewed", got)
	}
	if got := triageStateOf(Message{TriageState: "benign"}); got != "benign" {
		t.Errorf("triageStateOf = %q, want benign", got)
	}
}

func TestWindowRange(t *testing.T) {
	// "all" has to reach back further than any archive, because a page that silently
	// shows nothing looks identical to one with no data.
	from, _ := windowRange("all")
	if from.Year() > 1990 {
		t.Errorf("all starts at %v, too recent for an imported archive", from)
	}
	from7, to7 := windowRange("7")
	if d := to7.Sub(from7).Hours() / 24; d < 7 || d > 10 {
		t.Errorf("7-day window spans %.1f days", d)
	}
}
