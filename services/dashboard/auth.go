// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Signing people in.
//
// Two ways, and a deployment can have both at once. That combination is the point
// rather than indecision: an organisation running SSO still wants one local
// break-glass account, because the day the identity provider is broken is exactly the
// day someone needs to get into the security console.
//
// The dashboard does the browser half — a form, or an OIDC redirect — and exchanges
// the result for an engine session. The engine owns identity; this owns the cookie.

const (
	sessionCookie = "lazaret_session"
	csrfCookie    = "lazaret_csrf"
	oauthCookie   = "lazaret_oidc"
)

// Session is what the cookie resolves to.
type Session struct {
	Token string
	User  WhoAmI
}

// WhoAmI is the engine's view of the caller.
type WhoAmI struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

// Can reports whether this role is at least the one needed.
func (w WhoAmI) Can(need string) bool {
	rank := map[string]int{"viewer": 1, "analyst": 2, "admin": 3}
	return rank[w.Role] >= rank[need] && rank[need] > 0
}

// Auth holds the sign-in configuration.
type Auth struct {
	// Engine is used for local login and for whoami.
	Engine *EngineClient

	// ServiceToken is an admin API token. It is needed for exactly one thing: turning
	// verified OIDC claims into an engine session, which is a privileged operation
	// because it mints a session for whoever it is told about.
	ServiceToken string

	// Secure marks cookies Secure. On by default; -insecure-cookies turns it off for
	// plain-HTTP local development, and says so loudly.
	Secure bool

	// OIDC, when configured.
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config

	// DefaultRole is what a first-time SSO user gets. viewer, because an identity
	// provider vouching that someone works here is not the same as deciding they
	// should be able to quarantine mail.
	DefaultRole string
}

// SSOEnabled reports whether an identity provider is configured.
func (a *Auth) SSOEnabled() bool { return a.oauth != nil }

// ConfigureOIDC discovers a provider and prepares the flow.
func (a *Auth) ConfigureOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURL string, scopes []string) error {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("discovering %s: %w", issuer, err)
	}
	a.provider = provider
	a.verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	want := []string{oidc.ScopeOpenID, "profile", "email"}
	if len(scopes) > 0 {
		want = scopes
	}
	a.oauth = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       want,
	}
	return nil
}

// ---------------------------------------------------------------------------
// Cookies and CSRF
// ---------------------------------------------------------------------------

func (a *Auth) setSession(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true, // no script can read it, so an XSS cannot exfiltrate the session
		Secure:   a.Secure,
		// Lax rather than Strict: Strict breaks the OIDC return, because the redirect
		// back from the identity provider is a cross-site navigation. Lax still
		// withholds the cookie from cross-site POSTs, which is the case that matters,
		// and the CSRF token below covers the rest.
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearSession(w http.ResponseWriter) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == sessionCookie, Secure: a.Secure, SameSite: http.SameSiteLaxMode,
		})
	}
}

// issueCSRF sets a CSRF token bound to the session.
//
// A synchroniser token rather than relying on SameSite alone. SameSite=Lax is good and
// it is not a complete answer: it is a browser behaviour rather than a server-enforced
// invariant, older browsers differ, and a same-site subdomain can still post. Every
// state-changing form carries this and every POST handler checks it.
//
// Derived from the session token by HMAC-like hashing rather than stored, so there is
// no server-side CSRF table to expire and a token is automatically invalidated when
// the session changes.
func (a *Auth) issueCSRF(w http.ResponseWriter, sessionToken string) string {
	token := csrfFor(sessionToken)
	http.SetCookie(w, &http.Cookie{
		Name:  csrfCookie,
		Value: token,
		Path:  "/",
		// Readable by script on purpose: it is not a secret from this page, it is a
		// value a cross-site attacker cannot read because of the same-origin policy.
		HttpOnly: false,
		Secure:   a.Secure,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func csrfFor(sessionToken string) string {
	sum := sha256.Sum256([]byte("lazaret-csrf\x00" + sessionToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// checkCSRF verifies a state-changing request.
func (a *Auth) checkCSRF(r *http.Request, sessionToken string) error {
	want := csrfFor(sessionToken)

	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		got = r.FormValue("csrf_token")
	}
	if got == "" {
		return errors.New("missing CSRF token")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return errors.New("invalid CSRF token")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Local sign-in
// ---------------------------------------------------------------------------

// LoginLocal exchanges an email and password for an engine session.
func (a *Auth) LoginLocal(ctx context.Context, email, password string) (string, time.Time, error) {
	return a.Engine.Login(ctx, email, password)
}

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------

// StartOIDC redirects to the identity provider.
//
// state and nonce are both generated and both checked on return: state defends the
// callback against cross-site request forgery, and nonce binds the ID token to this
// particular request so a token replayed from elsewhere is rejected. PKCE is added
// too, which matters for a public client and costs nothing for a confidential one.
func (a *Auth) StartOIDC(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		http.Error(w, "single sign-on is not configured", http.StatusNotFound)
		return
	}

	state, err1 := randomString()
	nonce, err2 := randomString()
	verifier := oauth2.GenerateVerifier()
	if err1 != nil || err2 != nil {
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}

	// state, nonce and the PKCE verifier travel in one short-lived cookie rather than
	// in server memory, so a deployment can run more than one dashboard without
	// sticky sessions.
	http.SetCookie(w, &http.Cookie{
		Name:     oauthCookie,
		Value:    state + "|" + nonce + "|" + verifier,
		Path:     "/auth/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   a.Secure,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// CompleteOIDC handles the return from the identity provider.
func (a *Auth) CompleteOIDC(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, time.Time, error) {
	if a.oauth == nil {
		return "", time.Time{}, errors.New("single sign-on is not configured")
	}

	c, err := r.Cookie(oauthCookie)
	if err != nil {
		return "", time.Time{}, errors.New("the sign-in attempt expired; start again")
	}
	parts := strings.SplitN(c.Value, "|", 3)
	if len(parts) != 3 {
		return "", time.Time{}, errors.New("malformed sign-in state")
	}
	state, nonce, verifier := parts[0], parts[1], parts[2]

	// Cleared immediately: one attempt per redirect.
	http.SetCookie(w, &http.Cookie{Name: oauthCookie, Value: "", Path: "/auth/", MaxAge: -1})

	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(state)) != 1 {
		return "", time.Time{}, errors.New("state did not match; the sign-in was not started here")
	}
	if e := r.URL.Query().Get("error"); e != "" {
		return "", time.Time{}, fmt.Errorf("the identity provider refused: %s", e)
	}

	tok, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("exchanging the authorisation code: %w", err)
	}

	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", time.Time{}, errors.New("the provider returned no id_token")
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("verifying the id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return "", time.Time{}, errors.New("nonce did not match; the token was not issued for this sign-in")
	}

	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
		Name     string `json:"name"`
		Sub      string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", time.Time{}, fmt.Errorf("reading claims: %w", err)
	}
	if claims.Email == "" {
		return "", time.Time{}, errors.New("the provider returned no email claim")
	}
	// An unverified address is refused. Several providers let a user set any address
	// they like until it is verified, and an account here is matched partly on it.
	if claims.Verified != nil && !*claims.Verified {
		return "", time.Time{}, errors.New("the provider reports this email address as unverified")
	}

	return a.Engine.SSOLogin(ctx, a.ServiceToken, idToken.Issuer, claims.Sub,
		claims.Email, claims.Name, a.DefaultRole)
}

func randomString() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// warnInsecure is called at start-up when cookies are not marked Secure.
func warnInsecure() {
	log.Printf("")
	log.Printf("  *** -insecure-cookies: session cookies are not marked Secure ***")
	log.Printf("  A session can then be sent over plain HTTP and intercepted.")
	log.Printf("  Local development only.")
	log.Printf("")
}
