// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Authentication and authorisation for the API.
//
// Two kinds of caller. A **session token**, held by a person's browser via the
// dashboard, and an **API token**, held by a service. Both arrive as a bearer token and
// both resolve to a role; the handlers check the role and never the kind.
//
// # Why this is on the engine rather than only on the dashboard
//
// The dashboard is one client. An engine that trusts anything able to reach its port is
// an engine where the login page protects the page and not the data — and this API can
// quarantine mail, read every message, and enumerate an organisation's correspondents.
//
// # Auth can be disabled, loudly
//
// -no-auth exists for a single-machine evaluation, and it logs a warning on every
// start. It is not the default, because a system that is insecure until configured is
// a system that ships insecure.

type contextKey struct{}

// CallerFrom returns the authenticated caller, if any.
func CallerFrom(ctx context.Context) *store.Caller {
	c, _ := ctx.Value(contextKey{}).(*store.Caller)
	return c
}

// authenticate resolves a bearer token into a caller.
func (a *API) authenticate(r *http.Request) (*store.Caller, error) {
	if a.noAuth {
		return &store.Caller{
			UserID: "anonymous", Email: "anonymous", TenantID: a.defaultTenant,
			Role: store.RoleAdmin, Service: "no-auth",
		}, nil
	}

	token := bearer(r)
	if token == "" {
		return nil, errors.New("no credentials")
	}

	// API tokens carry a prefix, so the common case is one lookup rather than two.
	// The prefix is also what makes a leaked credential recognisable in a log.
	if strings.HasPrefix(token, "lzt_") {
		return a.store.CallerByToken(r.Context(), token)
	}
	if c, err := a.store.CallerBySession(r.Context(), token); err == nil {
		return c, nil
	}
	return a.store.CallerByToken(r.Context(), token)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

// require wraps a handler with a minimum role.
func (a *API) require(need store.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := a.authenticate(r)
		if err != nil {
			// 401 with a WWW-Authenticate header, so a client knows to present
			// credentials rather than concluding the endpoint does not exist.
			w.Header().Set("WWW-Authenticate", `Bearer realm="lazaret"`)
			fail(w, http.StatusUnauthorized, errors.New("authentication required"))
			return
		}
		if !caller.Role.Allows(need) {
			fail(w, http.StatusForbidden,
				errors.New("this action needs the "+string(need)+" role; you have "+string(caller.Role)))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, caller)))
	}
}

// tenantOf returns the tenant a caller may act on.
//
// A caller's own tenant always wins over anything in the request. Letting a
// tenant_id parameter override it would make every endpoint a cross-tenant read for
// anyone who guessed another tenant's name.
func (a *API) tenantOf(r *http.Request) string {
	if c := CallerFrom(r.Context()); c != nil && c.TenantID != "" {
		return c.TenantID
	}
	return a.defaultTenant
}

// ---------------------------------------------------------------------------
// Session endpoints, used by the dashboard's login flow
// ---------------------------------------------------------------------------

// sessionTTL is how long a session lasts. Long enough not to interrupt a working day,
// short enough that a forgotten browser is not indefinite.
const sessionTTL = 12 * time.Hour

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	tenant := in.TenantID
	if tenant == "" {
		tenant = a.defaultTenant
	}

	user, err := a.store.Authenticate(r.Context(), tenant, in.Email, in.Password)
	if err != nil {
		// One message for both "no such account" and "wrong password", so nobody can
		// enumerate who has an account here.
		fail(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}

	token, expires, err := a.store.NewSession(r.Context(), user.ID,
		r.Header.Get("User-Agent"), clientIP(r), sessionTTL)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "expires_at": expires, "user": user,
	})
}

// ssoLogin exchanges verified identity-provider claims for a session.
//
// The OIDC dance itself happens in the dashboard, because it is a browser flow; this
// is the step that turns a verified identity into an engine session. It is therefore
// privileged: it creates a session for anyone it is told about, so it requires an
// admin API token and must never be reachable from a browser.
func (a *API) ssoLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Issuer   string `json:"issuer"`
		Subject  string `json:"subject"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		TenantID string `json:"tenant_id"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if in.Issuer == "" || in.Subject == "" {
		fail(w, http.StatusBadRequest, errors.New("issuer and subject are required"))
		return
	}
	tenant := in.TenantID
	if tenant == "" {
		tenant = a.defaultTenant
	}

	user, err := a.store.UpsertSSOUser(r.Context(), tenant, in.Issuer, in.Subject,
		in.Email, in.Name, store.Role(in.Role))
	if err != nil {
		fail(w, http.StatusForbidden, err)
		return
	}

	token, expires, err := a.store.NewSession(r.Context(), user.ID,
		r.Header.Get("User-Agent"), clientIP(r), sessionTTL)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "expires_at": expires, "user": user,
	})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if token := bearer(r); token != "" {
		_ = a.store.EndSession(r.Context(), token)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
}

func (a *API) whoami(w http.ResponseWriter, r *http.Request) {
	c := CallerFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id": c.UserID, "email": c.Email, "name": c.Name,
		"tenant_id": c.TenantID, "role": c.Role, "service": c.Service,
	})
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.Users(r.Context(), a.tenantOf(r))
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if users == nil {
		users = []store.User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	user, err := a.store.CreateUser(r.Context(), store.User{
		TenantID: a.tenantOf(r), Email: in.Email, Name: in.Name, Role: store.Role(in.Role),
	}, in.Password)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	id := r.PathValue("id")

	if in.Role != nil {
		if err := a.store.SetUserRole(r.Context(), id, store.Role(*in.Role)); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
	}
	if in.Disabled != nil {
		if err := a.store.SetUserDisabled(r.Context(), id, *in.Disabled); err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
	}
	if in.Password != nil {
		if err := a.store.SetPassword(r.Context(), id, *in.Password); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
	}
	user, err := a.store.UserByID(r.Context(), id)
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if in.Name == "" {
		fail(w, http.StatusBadRequest, errors.New("a name is required: an unnamed credential cannot be revoked with confidence"))
		return
	}
	token, err := a.store.NewAPIToken(r.Context(), a.tenantOf(r), in.Name, store.Role(in.Role))
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	// Returned once and never again: only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]string{
		"token": token,
		"note":  "This is shown once. Only a hash is stored, so it cannot be recovered.",
	})
}

// clientIP prefers the proxy header when one is configured to be trusted, and
// otherwise uses the peer address.
//
// X-Forwarded-For is trusted only behind a proxy, because anyone can send it: taking
// it unconditionally would let a caller write whatever they liked into the session log.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" && r.Header.Get("X-Lazaret-Trusted-Proxy") != "" {
		return ip
	}
	host, _, found := strings.Cut(r.RemoteAddr, ":")
	if !found {
		return r.RemoteAddr
	}
	return host
}
