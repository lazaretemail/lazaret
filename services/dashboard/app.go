// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// App serves the views.
type App struct {
	engine   *EngineClient
	auth     *Auth
	readOnly bool
}

// The information architecture.
//
// Grouped by the question being asked rather than by what the data happens to be,
// which is what makes a console navigable when something is on fire:
//
//	Overview      what is the state of things
//	Triage        what needs a decision from me
//	Investigate   I have a question about a message, a pattern, or a file
//	Detections    is the rule set doing its job, and what can it not see
//	Settings      who can use this
//
// Triage is the default landing page rather than the overview, because the reason
// someone opens a security console is almost always a queue rather than a chart.
func (a *App) Routes(dist fs.FS) (http.Handler, error) {
	console, err := newSPA(dist)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })

	// The OIDC handshake stays server-side: it is a pair of redirects with state in
	// a cookie, and nothing a single-page app can usefully take part in.
	mux.HandleFunc("GET /auth/sso", a.auth.StartOIDC)
	mux.HandleFunc("GET /auth/callback", a.ssoCallback)

	// Role gates. The JSON variants answer with a status the console can act on
	// rather than a redirect, which fetch() would follow into an HTML login page and
	// then fail to parse.
	view := func(h http.HandlerFunc) http.HandlerFunc { return a.apiAuthed("viewer", h) }
	act := func(h http.HandlerFunc) http.HandlerFunc { return a.apiAuthed("analyst", a.apiCSRF(h)) }
	admin := func(h http.HandlerFunc) http.HandlerFunc { return a.apiAuthed("admin", h) }
	adminAct := func(h http.HandlerFunc) http.HandlerFunc { return a.apiAuthed("admin", a.apiCSRF(h)) }

	// Unauthenticated, because they are how a session begins.
	mux.HandleFunc("POST /api/auth/login", a.apiLogin)
	mux.HandleFunc("POST /api/auth/logout", a.apiLogout)
	mux.HandleFunc("GET /api/auth/config", a.apiAuthConfig)

	mux.HandleFunc("GET /api/session", view(a.apiSession))

	mux.HandleFunc("GET /api/triage", view(a.apiTriage))
	mux.HandleFunc("POST /api/triage/bulk", act(a.apiBulkTriage))
	mux.HandleFunc("GET /api/search", view(a.apiSearch))

	mux.HandleFunc("GET /api/messages/{id}", view(a.apiMessage))
	mux.HandleFunc("POST /api/messages/{id}/act", act(a.apiAct))
	mux.HandleFunc("POST /api/messages/{id}/triage", act(a.apiSetTriage))

	mux.HandleFunc("GET /api/overview", view(a.apiOverview))
	mux.HandleFunc("GET /api/remediations", view(a.apiRemediations))

	mux.HandleFunc("GET /api/detections", view(a.apiRules))
	mux.HandleFunc("GET /api/detections/effectiveness", view(a.apiEffectiveness))
	mux.HandleFunc("GET /api/detections/coverage", view(a.apiCoverage))
	mux.HandleFunc("GET /api/detections/{id}", view(a.apiRule))

	mux.HandleFunc("GET /api/mql/schema", view(a.apiMQLSchema))
	mux.HandleFunc("POST /api/validate", act(a.apiValidateRule))
	mux.HandleFunc("POST /api/hunt", act(a.apiHuntStart))
	mux.HandleFunc("GET /api/hunt/{id}", view(a.apiHuntJob))
	mux.HandleFunc("POST /api/backtest", act(a.apiBacktestStart))
	mux.HandleFunc("GET /api/backtest/{id}", view(a.apiBacktest))

	// What we learned about mail after it was delivered, and the attacks that
	// arrived more than once.
	mux.HandleFunc("GET /api/findings", view(a.apiFindings))
	mux.HandleFunc("POST /api/findings/{id}/resolve", act(a.apiResolveFinding))
	mux.HandleFunc("GET /api/campaigns", view(a.apiCampaigns))
	mux.HandleFunc("POST /api/analyze", act(a.apiAnalyze))

	mux.HandleFunc("GET /api/settings/org", admin(a.apiOrg))
	mux.HandleFunc("PUT /api/settings/org", adminAct(a.apiSaveOrg))

	mux.HandleFunc("GET /api/settings/mailboxes", admin(a.apiMailboxes))
	mux.HandleFunc("POST /api/settings/mailboxes", adminAct(a.apiSaveMailbox))
	mux.HandleFunc("DELETE /api/settings/mailboxes/{id}", adminAct(a.apiDeleteMailbox))
	mux.HandleFunc("POST /api/settings/mailboxes/{id}/recheck", adminAct(a.apiRecheckMailbox))
	mux.HandleFunc("POST /api/settings/mailboxes/{id}/enabled", adminAct(a.apiSetMailboxEnabled))
	// Onboarding a whole estate: read the Microsoft directory, add what was chosen.
	mux.HandleFunc("GET /api/settings/directory", admin(a.apiGraphDirectory))
	mux.HandleFunc("POST /api/settings/mailboxes/bulk", adminAct(a.apiAddMailboxes))

	mux.HandleFunc("GET /api/settings/actions", admin(a.apiActions))
	mux.HandleFunc("POST /api/settings/actions", adminAct(a.apiSaveAction))
	mux.HandleFunc("DELETE /api/settings/actions/{id}", adminAct(a.apiDeleteAction))
	mux.HandleFunc("POST /api/settings/actions/attach", adminAct(a.apiAttachActions))

	mux.HandleFunc("GET /api/settings/microsoft", admin(a.apiGraphApp))
	mux.HandleFunc("PUT /api/settings/microsoft", adminAct(a.apiSaveGraphApp))
	mux.HandleFunc("DELETE /api/settings/microsoft", adminAct(a.apiDeleteGraphApp))

	mux.HandleFunc("GET /api/settings/history", admin(a.apiBackfills))
	mux.HandleFunc("POST /api/settings/history", adminAct(a.apiStartBackfill))
	mux.HandleFunc("POST /api/settings/history/{id}/cancel", adminAct(a.apiCancelBackfill))

	mux.HandleFunc("GET /api/settings/feeds", admin(a.apiRuleFeeds))
	mux.HandleFunc("POST /api/settings/feeds", adminAct(a.apiSaveRuleFeed))
	mux.HandleFunc("DELETE /api/settings/feeds/{id}", adminAct(a.apiDeleteRuleFeed))
	mux.HandleFunc("POST /api/settings/feeds/{id}/sync", adminAct(a.apiSyncRuleFeed))

	mux.HandleFunc("GET /api/settings/lists", admin(a.apiLists))
	mux.HandleFunc("GET /api/settings/lists/{name}", admin(a.apiList))
	mux.HandleFunc("PATCH /api/settings/lists/{name}", adminAct(a.apiUpdateList))
	mux.HandleFunc("POST /api/settings/lists/{name}/entries", adminAct(a.apiAddListEntry))
	mux.HandleFunc("DELETE /api/settings/lists/{name}/entries", adminAct(a.apiRemoveListEntry))
	mux.HandleFunc("POST /api/settings/lists/{name}/refresh", adminAct(a.apiRefreshList))

	mux.HandleFunc("GET /api/settings/learning", admin(a.apiModel))
	mux.HandleFunc("POST /api/settings/learning/train", adminAct(a.apiTrainModel))
	mux.HandleFunc("DELETE /api/settings/learning", adminAct(a.apiForgetModel))

	mux.HandleFunc("GET /api/settings/users", admin(a.apiUsers))
	mux.HandleFunc("POST /api/settings/users", adminAct(a.apiCreateUser))
	mux.HandleFunc("PATCH /api/settings/users/{id}", adminAct(a.apiUpdateUser))
	mux.HandleFunc("POST /api/settings/tokens", adminAct(a.apiCreateToken))

	// Anything else under /api is a mistake on this side, and should say so in the
	// shape the caller is parsing.
	mux.HandleFunc("/api/", jsonAPINotFound)

	// Binary reads that a browser fetches directly rather than through JSON: the
	// Rendered tab's <img> and the raw .eml download.
	mux.HandleFunc("GET /messages/{id}/screenshot", a.pageAuthed("viewer", a.messageScreenshot))
	mux.HandleFunc("GET /messages/{id}/raw", a.pageAuthed("analyst", a.messageRaw))

	// Everything else is the console itself.
	//
	// Registered for every method rather than GET alone: ServeMux refuses a pattern
	// that is broader in path but narrower in method than one already registered
	// ("GET /" against "/api/"), and the handler turns away anything but a read
	// itself.
	mux.Handle("/", console)

	return mux, nil
}

// apiAuthConfig says what sign-in methods exist, so the login page can offer the SSO
// button only when one is configured. Deliberately readable without a session: it is
// a property of the deployment, not of an account.
func (a *App) apiAuthConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"sso": a.auth.SSOEnabled()})
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

type sessionKey struct{}

func sessionFrom(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionKey{}).(*Session)
	return s
}

// resolve turns the session cookie into an identity, or reports why it could not.
//
// Shared by the JSON and page gates so there is exactly one place that decides what a
// cookie means. The two differ only in how they say no.
func (a *App) resolve(w http.ResponseWriter, r *http.Request) (*Session, *http.Request, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, r, errNoSession
	}
	ctx := WithToken(r.Context(), c.Value)
	who, err := a.engine.WhoAmI(ctx)
	if err != nil {
		// The engine rejected the session: expired, signed out elsewhere, or the
		// account was disabled. Clear the cookie rather than leaving the browser to
		// retry a dead token on every request.
		a.auth.clearSession(w)
		return nil, r, errNoSession
	}
	sess := &Session{Token: c.Value, User: *who}
	return sess, r.WithContext(context.WithValue(ctx, sessionKey{}, sess)), nil
}

var errNoSession = errors.New("not signed in")

// apiAuthed is the JSON gate: a status, never a redirect.
//
// fetch() follows a 303 transparently, so redirecting an unauthenticated API call to
// the login page hands the caller a lump of HTML with a 200 on it. The console then
// fails to parse it, a long way from the actual cause. A 401 lets the client do the
// one correct thing — send the person to sign in.
func (a *App) apiAuthed(need string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, r, err := a.resolve(w, r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		if !sess.User.Can(need) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "this needs the " + need + " role; your account has " + sess.User.Role,
			})
			return
		}
		next(w, r)
	}
}

// apiCSRF is withCSRF with a JSON refusal.
func (a *App) apiCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		if sess == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		// Only multipart needs parsing here; a JSON caller sends the token in a
		// header and decodes its own body.
		if mediaType(r) == "multipart/form-data" {
			if err := r.ParseMultipartForm(maxUploadMemory); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		}
		if err := a.auth.checkCSRF(r, sess.Token); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "this request did not come from a page on this site (" + err.Error() + ")",
			})
			return
		}
		if a.readOnly {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this dashboard is read-only"})
			return
		}
		next(w, r)
	}
}

// pageAuthed guards the two endpoints a browser loads directly rather than through
// the JSON client — the screenshot <img> and the raw .eml download — where a redirect
// to the sign-in page is the useful answer.
func (a *App) pageAuthed(need string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, r, err := a.resolve(w, r)
		if err != nil {
			a.redirectToLogin(w, r)
			return
		}
		if !sess.User.Can(need) {
			http.Error(w, "this needs the "+need+" role; your account has "+sess.User.Role, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// withCSRF rejects a state-changing request without a valid token.
//
// A synchroniser token as well as SameSite=Lax. SameSite is a browser behaviour rather
// than a server-enforced invariant, and a same-site subdomain can still post; this is
// the check that does not depend on the client behaving.
func (a *App) withCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		if sess == nil {
			a.redirectToLogin(w, r)
			return
		}
		// The body has to be parsed here, before the token is looked for, and how
		// depends on the encoding.
		//
		// ParseForm does not read a multipart body — it only decodes a urlencoded
		// one — but it does set r.Form to a non-nil empty map. FormValue then sees
		// a parsed form and skips the ParseMultipartForm it would otherwise do for
		// itself, so the token in an upload's hidden field was never found and
		// every .eml upload was rejected as forged. Calling the right parser is the
		// whole fix; the failure mode was a middleware being defensive.
		switch mediaType(r) {
		case "multipart/form-data":
			if err := r.ParseMultipartForm(maxUploadMemory); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "application/json":
			// Left alone: the handler decodes the body itself, and a JSON caller
			// sends the token in the X-CSRF-Token header.
		default:
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if err := a.auth.checkCSRF(r, sess.Token); err != nil {
			http.Error(w, "this request did not come from a page on this site ("+err.Error()+")",
				http.StatusForbidden)
			return
		}
		if a.readOnly {
			http.Error(w, "this dashboard is read-only", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (a *App) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.RequestURI()
	// Only a path, never an absolute URL: taking one from the query would turn the
	// login page into an open redirect, which is how a phishing link ends up looking
	// like it points at the security console.
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(next), http.StatusSeeOther)
}

// badgeCounts is the queue depth shown in the navigation.
//
// Best effort: a console whose navigation fails to render because a count query was
// slow is worse than one with no badge.
func (a *App) badgeCounts(r *http.Request) map[string]int {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	from, to := windowRange(windowOf(r))
	counts, _, err := a.engine.TriageCounts(ctx, from, to)
	if err != nil {
		return nil
	}
	// Findings carry their own badge. They are not a triage state — a finding is
	// about a message that was already decided, which is the whole point — so they
	// would otherwise be invisible until somebody happened to open the page, and a
	// retrospective catch nobody looks at is not a catch.
	if f, err := a.engine.Findings(ctx, "new"); err == nil && f.Open > 0 {
		if counts == nil {
			counts = map[string]int{}
		}
		counts["findings"] = f.Open
	}
	return counts
}

func windowOf(r *http.Request) string {
	if w := r.URL.Query().Get("window"); w != "" {
		return w
	}
	return "30"
}

// windowRange turns the selector into a range.
//
// "all" is a real option because an archive being evaluated after the fact has
// messages dated years ago, and a page that silently shows nothing looks identical to
// one with no data.
func windowRange(window string) (time.Time, time.Time) {
	to := time.Now().UTC().AddDate(0, 0, 1)
	switch window {
	case "all":
		return time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), to
	case "1":
		return to.AddDate(0, 0, -2), to
	case "7":
		return to.AddDate(0, 0, -8), to
	case "90":
		return to.AddDate(0, 0, -91), to
	case "365":
		return to.AddDate(-1, 0, -1), to
	default:
		return to.AddDate(0, 0, -31), to
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func funcs() template.FuncMap {
	return template.FuncMap{
		"short": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return itoa(int(d.Minutes())) + "m ago"
			case d < 24*time.Hour:
				return itoa(int(d.Hours())) + "h ago"
			case d < 30*24*time.Hour:
				return itoa(int(d.Hours()/24)) + "d ago"
			}
			return t.UTC().Format("2006-01-02")
		},
		"stamp": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"join":  joinAny,
		"itoa":  itoa,
		"dict":  dict,
		"json":  prettyJSON,
		"badge": badgeClass,
		"stateLabel": func(s string) string {
			switch s {
			case "needs_remediation":
				return "needs remediation"
			case "unreviewed", "":
				return "unreviewed"
			default:
				return strings.ReplaceAll(s, "_", " ")
			}
		},
		"add": func(a, b int64) int64 { return a + b },
		"pct": func(a, b int64) string {
			if b == 0 {
				return "—"
			}
			return itoa(int(float64(a)/float64(b)*100)) + "%"
		},
	}
}

func badgeClass(v string) string {
	switch v {
	case "malicious", "needs_remediation", "critical", "high":
		return "bad"
	case "indeterminate", "unreviewed", "medium":
		return "unknown"
	case "remediated", "clean", "benign":
		return "ok"
	}
	return "neutral"
}

func dict(pairs ...any) map[string]any {
	out := map[string]any{}
	for i := 0; i+1 < len(pairs); i += 2 {
		if k, ok := pairs[i].(string); ok {
			out[k] = pairs[i+1]
		}
	}
	return out
}

func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

var errNotConfigured = errors.New("not configured")

// maxUploadMemory is how much of a multipart body is held in memory before the rest
// spills to temporary files. Not a size limit — the handler bounds what it reads —
// just where the bytes sit.
const maxUploadMemory = 8 << 20

// mediaType is the request's content type without its parameters, so that a boundary
// or a charset does not defeat the comparison.
func mediaType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return mt
}

// joinAny joins a list of strings that may have come from Go or from JSON.
//
// strings.Join takes []string, and anything decoded from a JSON response is []any.
// Handed the wrong one, html/template raises an execution error rather than printing
// something odd — which aborted the render and dropped the rest of the page. The
// tolerant version is the right one for a template helper: its inputs come from both
// sides and it cannot know which.
func joinAny(v any, sep string) string {
	switch list := v.(type) {
	case nil:
		return ""
	case []string:
		return strings.Join(list, sep)
	case []any:
		parts := make([]string, 0, len(list))
		for _, e := range list {
			parts = append(parts, fmt.Sprintf("%v", e))
		}
		return strings.Join(parts, sep)
	default:
		return fmt.Sprintf("%v", v)
	}
}
