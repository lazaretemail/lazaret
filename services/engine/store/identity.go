// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Identity: who is asking, and what they are allowed to do.
//
// The engine owns this because the engine owns state. It authenticates two kinds of
// caller — people, who get a session from a browser flow, and services, which get an
// API token — and both resolve to a role that the API checks.
//
// Putting it here rather than in the dashboard is what makes the API itself protected.
// A login page in front of an unauthenticated API protects the page, not the API.

// Role is what a caller may do.
type Role string

const (
	// RoleViewer can read: triage, messages, insights, rules.
	RoleViewer Role = "viewer"

	// RoleAnalyst can also act: quarantine, release, run hunts, set triage state.
	RoleAnalyst Role = "analyst"

	// RoleAdmin can also manage users, tokens and tenants.
	RoleAdmin Role = "admin"
)

// rank orders the roles. Each includes everything below it.
func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleAnalyst:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

// Allows reports whether this role is at least the one required.
//
// Both sides must be a role this system knows. An unrecognised *requirement* denies
// rather than permits: without that check a typo in a route's role — need("analyts")
// — ranks zero and every caller clears it, which is a permission check that silently
// grants instead of failing.
func (r Role) Allows(need Role) bool {
	if !r.Valid() || !need.Valid() {
		return false
	}
	return r.rank() >= need.rank()
}

// Valid reports whether this is a role the system knows.
func (r Role) Valid() bool { return r.rank() > 0 }

// User is an account.
type User struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Email     string     `json:"email"`
	Name      string     `json:"name"`
	Role      Role       `json:"role"`
	Disabled  bool       `json:"disabled"`
	Local     bool       `json:"local"`
	SSO       bool       `json:"sso"`
	CreatedAt time.Time  `json:"created_at"`
	LastLogin *time.Time `json:"last_login,omitempty"`
}

// Caller is an authenticated request's identity.
type Caller struct {
	UserID   string
	Email    string
	Name     string
	TenantID string
	Role     Role

	// Service is set when the caller is an API token rather than a person. Actions
	// recorded by one are attributed to the token's name, so an audit trail can
	// distinguish "an analyst quarantined this" from "the IMAP connector did".
	Service string
}

// Actor is how this caller appears in the audit trail.
func (c *Caller) Actor() string {
	if c == nil {
		return "anonymous"
	}
	if c.Service != "" {
		return "service:" + c.Service
	}
	if c.Email != "" {
		return c.Email
	}
	return c.UserID
}

var (
	// ErrNoSuchUser is returned rather than distinguishing "no account" from "wrong
	// password", which would let anyone enumerate who has an account here.
	ErrNoSuchUser = errors.New("store: invalid credentials")

	// ErrDisabled is separate because it is returned only after the password has
	// already been verified, so it leaks nothing to someone guessing.
	ErrDisabled = errors.New("store: account disabled")

	ErrNoSession = errors.New("store: no such session")
)

// CreateUser adds a local or SSO account.
func (s *Store) CreateUser(ctx context.Context, u User, password string) (*User, error) {
	if u.Email == "" {
		return nil, errors.New("store: an email address is required")
	}
	if !u.Role.Valid() {
		u.Role = RoleViewer
	}
	if u.ID == "" {
		u.ID = newID("usr")
	}
	if u.TenantID == "" {
		u.TenantID = "default"
	}

	var hash *string
	if password != "" {
		h, err := HashPassword(password)
		if err != nil {
			return nil, err
		}
		hash = &h
	}

	_, err := s.pg.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, name, password_hash, role)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		u.ID, u.TenantID, strings.ToLower(u.Email), u.Name, hash, string(u.Role))
	if err != nil {
		return nil, fmt.Errorf("store: creating user: %w", err)
	}
	u.Local = hash != nil
	return &u, nil
}

// SetPassword changes or clears a local password.
func (s *Store) SetPassword(ctx context.Context, userID, password string) error {
	var hash *string
	if password != "" {
		h, err := HashPassword(password)
		if err != nil {
			return err
		}
		hash = &h
	}
	// Every existing session is ended. A password change that leaves old sessions
	// working does not actually lock anyone out, which is usually the reason for it.
	if _, err := s.pg.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, userID, hash); err != nil {
		return err
	}
	_, err := s.pg.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

// Authenticate verifies a local password.
func (s *Store) Authenticate(ctx context.Context, tenant, email, password string) (*User, error) {
	var (
		u    User
		hash *string
	)
	err := s.pg.QueryRow(ctx, `
		SELECT id, tenant_id, email, name, password_hash, role, disabled, created_at, last_login
		FROM users WHERE tenant_id = $1 AND lower(email) = lower($2)`,
		tenant, email).Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &hash, &u.Role,
		&u.Disabled, &u.CreatedAt, &u.LastLogin)
	if err != nil || hash == nil {
		// A dummy verification even when there is no account, so the time taken does
		// not reveal whether an address exists here.
		_, _ = VerifyPassword(dummyHash, password)
		return nil, ErrNoSuchUser
	}

	ok, err := VerifyPassword(*hash, password)
	if err != nil || !ok {
		return nil, ErrNoSuchUser
	}
	if u.Disabled {
		return nil, ErrDisabled
	}
	u.Local = true
	return &u, nil
}

// UpsertSSOUser finds or creates an account from an identity provider's claims.
//
// Matched on issuer and subject before email: an email address can be reassigned to a
// different person and a subject cannot, so matching on email alone would eventually
// hand someone else's account to a new joiner with a recycled address.
func (s *Store) UpsertSSOUser(ctx context.Context, tenant, issuer, subject, email, name string, defaultRole Role) (*User, error) {
	var u User
	err := s.pg.QueryRow(ctx, `
		SELECT id, tenant_id, email, name, role, disabled, created_at
		FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`,
		issuer, subject).Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &u.Role, &u.Disabled, &u.CreatedAt)
	if err == nil {
		if u.Disabled {
			return nil, ErrDisabled
		}
		u.SSO = true
		return &u, nil
	}

	// No subject match. Link to an existing local account with the same address if one
	// exists — an organisation adopting SSO should not end up with two accounts per
	// person — otherwise create.
	var existingID string
	if err := s.pg.QueryRow(ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND lower(email) = lower($2)`,
		tenant, email).Scan(&existingID); err == nil {
		if _, err := s.pg.Exec(ctx,
			`UPDATE users SET oidc_issuer = $2, oidc_subject = $3 WHERE id = $1`,
			existingID, issuer, subject); err != nil {
			return nil, err
		}
		return s.UserByID(ctx, existingID)
	}

	if !defaultRole.Valid() {
		defaultRole = RoleViewer
	}
	u = User{ID: newID("usr"), TenantID: tenant, Email: strings.ToLower(email), Name: name, Role: defaultRole, SSO: true}
	if _, err := s.pg.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, name, role, oidc_issuer, oidc_subject)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.ID, u.TenantID, u.Email, u.Name, string(u.Role), issuer, subject); err != nil {
		return nil, fmt.Errorf("store: creating SSO user: %w", err)
	}
	return &u, nil
}

// UserByID returns one account.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	var u User
	var hash, issuer *string
	err := s.pg.QueryRow(ctx, `
		SELECT id, tenant_id, email, name, password_hash, oidc_issuer, role, disabled, created_at, last_login
		FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &hash, &issuer, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLogin)
	if err != nil {
		return nil, ErrNoSuchUser
	}
	u.Local, u.SSO = hash != nil, issuer != nil
	return &u, nil
}

// Users lists accounts for a tenant.
func (s *Store) Users(ctx context.Context, tenant string) ([]User, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT id, tenant_id, email, name, password_hash IS NOT NULL,
		       oidc_issuer IS NOT NULL, role, disabled, created_at, last_login
		FROM users WHERE tenant_id = $1 ORDER BY lower(email)`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.Name, &u.Local, &u.SSO,
			&u.Role, &u.Disabled, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserRole changes a role.
func (s *Store) SetUserRole(ctx context.Context, id string, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("store: %q is not a role", role)
	}
	_, err := s.pg.Exec(ctx, `UPDATE users SET role = $2 WHERE id = $1`, id, string(role))
	return err
}

// SetUserDisabled enables or disables an account, ending its sessions when disabling.
func (s *Store) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	if _, err := s.pg.Exec(ctx, `UPDATE users SET disabled = $2 WHERE id = $1`, id, disabled); err != nil {
		return err
	}
	if disabled {
		_, err := s.pg.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id)
		return err
	}
	return nil
}

// CountUsers reports how many accounts a tenant has, for the first-run path.
func (s *Store) CountUsers(ctx context.Context, tenant string) (int, error) {
	var n int
	err := s.pg.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id = $1`, tenant).Scan(&n)
	return n, err
}

// NewSession issues a session and returns the token, which is never stored.
func (s *Store) NewSession(ctx context.Context, userID, userAgent, ip string, ttl time.Duration) (string, time.Time, error) {
	token, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	sum := sha256.Sum256([]byte(token))
	expires := time.Now().UTC().Add(ttl)

	if _, err := s.pg.Exec(ctx, `
		INSERT INTO sessions (token_hash, user_id, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5)`,
		sum[:], userID, expires, truncateStr(userAgent, 300), ip); err != nil {
		return "", time.Time{}, err
	}
	_, _ = s.pg.Exec(ctx, `UPDATE users SET last_login = now() WHERE id = $1`, userID)
	return token, expires, nil
}

// CallerBySession resolves a session token.
func (s *Store) CallerBySession(ctx context.Context, token string) (*Caller, error) {
	sum := sha256.Sum256([]byte(token))
	var c Caller
	var disabled bool
	err := s.pg.QueryRow(ctx, `
		SELECT u.id, u.email, u.name, u.tenant_id, u.role, u.disabled
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()`, sum[:]).
		Scan(&c.UserID, &c.Email, &c.Name, &c.TenantID, &c.Role, &disabled)
	if err != nil {
		return nil, ErrNoSession
	}
	if disabled {
		return nil, ErrDisabled
	}
	return &c, nil
}

// EndSession signs one session out.
func (s *Store) EndSession(ctx context.Context, token string) error {
	sum := sha256.Sum256([]byte(token))
	_, err := s.pg.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, sum[:])
	return err
}

// PurgeSessions removes expired rows. Called periodically; expiry is enforced by the
// query above regardless, so this is housekeeping rather than security.
func (s *Store) PurgeSessions(ctx context.Context) error {
	_, err := s.pg.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	return err
}

// NewAPIToken issues a service credential and returns it once.
func (s *Store) NewAPIToken(ctx context.Context, tenant, name string, role Role) (string, error) {
	if !role.Valid() {
		role = RoleAnalyst
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(token))
	_, err = s.pg.Exec(ctx, `
		INSERT INTO api_tokens (token_hash, tenant_id, name, role) VALUES ($1,$2,$3,$4)`,
		sum[:], tenant, name, string(role))
	if err != nil {
		return "", err
	}
	// Prefixed so a leaked credential is recognisable in a log or a paste, and so a
	// secret scanner has something to match on.
	return "lzt_" + token, nil
}

// CallerByToken resolves an API token.
func (s *Store) CallerByToken(ctx context.Context, token string) (*Caller, error) {
	token = strings.TrimPrefix(token, "lzt_")
	sum := sha256.Sum256([]byte(token))

	var c Caller
	err := s.pg.QueryRow(ctx, `
		SELECT name, tenant_id, role FROM api_tokens
		WHERE token_hash = $1 AND NOT disabled`, sum[:]).
		Scan(&c.Service, &c.TenantID, &c.Role)
	if err != nil {
		return nil, ErrNoSession
	}
	c.UserID = "token:" + c.Service
	// Best effort: a failed bookkeeping update must not fail the request.
	_, _ = s.pg.Exec(ctx, `UPDATE api_tokens SET last_used = now() WHERE token_hash = $1`, sum[:])
	return &c, nil
}

// ---------------------------------------------------------------------------
// Password hashing
// ---------------------------------------------------------------------------

// Argon2id parameters. The OWASP baseline: 19MiB, two passes, one lane. Deliberately
// not tuned down for a laptop — a login that takes 50ms is not a problem, and a
// database dump that can be cracked quickly is.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// dummyHash is verified against when no account exists, so that the response time does
// not reveal whether an address is registered. It is a hash of a value nobody knows.
var dummyHash = "$argon2id$v=19$m=19456,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$" +
	"c2hvdWxkbmV2ZXJtYXRjaGFueXRoaW5nYXRhbGw"

// HashPassword returns an encoded argon2id hash.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		// A floor rather than a composition rule. Length is what makes a password hard
		// to guess; requiring a digit and a symbol mostly produces Password1!
		return "", errors.New("store: a password must be at least 12 characters")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded hash, in constant time.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("store: unrecognised password hash")
	}
	var memory uint32
	var timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
