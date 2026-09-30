// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// The Microsoft 365 application registration.
//
// One per deployment, not one per mailbox: it is an app registration in a directory
// with permission over the mailboxes in it, and every Graph mailbox authenticates
// through the same one. That is why it could not sit on the mailbox row alongside
// the credential, and why it was the last thing in this platform still configured by
// editing a compose file.
//
// Everything about how it is stored follows the mailbox credential rules, because it
// is the same kind of thing: the secret is encrypted with the deployment key, it is
// never returned to a browser, and only a service token can read it back.

// GraphApp is the registration as an administrator enters it.
type GraphApp struct {
	DirectoryID string `json:"directory_id"`
	ClientID    string `json:"client_id"`

	// Cloud is which Microsoft cloud this tenant lives in. Empty means the public
	// one, which is nearly everybody.
	//
	// On the registration rather than as a connector flag, because it is a fact
	// about the tenant and two different processes now need it: the connector, to
	// reach the right API host, and the engine, to walk the directory. It was a
	// pair of flags on the connector alone, which meant a GCC High deployment
	// configured its cloud in a compose file — the exact thing this table exists to
	// stop — and would have left the engine calling the public cloud for a tenant
	// that is not on it.
	Cloud string `json:"cloud,omitempty"`

	// ClientSecret is only ever populated on the way in, and on the way out to a
	// connector authenticating with a service token. A browser never sees it.
	ClientSecret string `json:"client_secret,omitempty"`

	// NotifyURL is where Graph sends change notifications. Derived from the
	// deployment's public URL rather than stored, and filled in by the API on
	// the way out — see services/engine/publicurl.go. Empty means polling,
	// which needs no inbound path.
	NotifyURL string `json:"notify_url"`

	// ClientState is the secret Graph echoes back in every notification, so one
	// that did not come from Microsoft can be told from one that did. Generated
	// here rather than typed: it means nothing outside this pairing, and asking a
	// person to invent a shared secret reliably produces a weak one.
	ClientState string `json:"client_state,omitempty"`

	HasSecret bool       `json:"has_secret"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// Configured reports a registration complete enough to try.
func (g GraphApp) Configured() bool {
	return g.DirectoryID != "" && g.ClientID != "" && g.HasSecret
}

// Microsoft clouds. The sovereign ones are not on the public hosts, and hardcoding one
// endpoint quietly makes the platform unusable for a whole class of tenant.
const (
	CloudPublic   = "public"
	CloudUSGov    = "usgov"    // GCC High
	CloudUSGovDoD = "usgovdod" // DoD
	CloudChina    = "china"    // 21Vianet
)

// Hosts returns the Graph API and token hosts for this registration's cloud.
//
// An unknown value falls back to the public cloud rather than failing. A typo in a
// configuration field should not take mail collection down, and the request that
// follows will fail with Microsoft's own message, which says more than anything this
// function could invent.
func (g GraphApp) Hosts() (graphBase, loginBase string) {
	switch g.Cloud {
	case CloudUSGov:
		return "https://graph.microsoft.us", "https://login.microsoftonline.us"
	case CloudUSGovDoD:
		return "https://dod-graph.microsoft.us", "https://login.microsoftonline.us"
	case CloudChina:
		return "https://microsoftgraph.chinacloudapi.cn", "https://login.chinacloudapi.cn"
	default:
		return "https://graph.microsoft.com", "https://login.microsoftonline.com"
	}
}

// ValidCloud reports whether a value names a cloud. Empty is valid and means public.
func ValidCloud(c string) bool {
	switch c {
	case "", CloudPublic, CloudUSGov, CloudUSGovDoD, CloudChina:
		return true
	}
	return false
}

// SaveGraphApp stores the registration, encrypting the secrets.
//
// An empty ClientSecret leaves the stored one alone, so an administrator can change
// the notification URL without re-entering a secret they may not have kept — the
// same rule the mailbox form follows, for the same reason.
func (s *Store) SaveGraphApp(ctx context.Context, tenant string, g GraphApp, by string) error {
	if g.DirectoryID == "" || g.ClientID == "" {
		return errors.New("store: a registration needs a directory id and a client id")
	}
	if !ValidCloud(g.Cloud) {
		return fmt.Errorf("store: %q is not a Microsoft cloud", g.Cloud)
	}

	var sealed []byte
	if g.ClientSecret != "" {
		if s.secrets == nil {
			return errors.New("store: no secret key is configured, so the client secret " +
				"cannot be stored (the engine generates one on first start; check its log)")
		}
		var err error
		if sealed, err = s.secrets.Seal(g.ClientSecret); err != nil {
			return err
		}
	}

	// The client state is generated once and kept. Regenerating it on every save
	// would invalidate every live subscription, and the symptom — notifications
	// silently rejected — looks like a Microsoft problem rather than a local one.
	var state []byte
	if cur, err := s.GraphApp(ctx, tenant, true); err == nil && cur != nil && cur.ClientState != "" {
		if state, err = s.secrets.Seal(cur.ClientState); err != nil {
			return err
		}
	} else if s.secrets != nil {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return err
		}
		if state, err = s.secrets.Seal(base64.RawURLEncoding.EncodeToString(raw[:])); err != nil {
			return err
		}
	}

	_, err := s.pg.Exec(ctx, `
		INSERT INTO graph_app (tenant_id, directory_id, client_id, client_secret,
		                       client_state, cloud, updated_at, updated_by)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),now(),NULLIF($7,''))
		ON CONFLICT (tenant_id) DO UPDATE SET
		  directory_id  = EXCLUDED.directory_id,
		  client_id     = EXCLUDED.client_id,
		  cloud         = EXCLUDED.cloud,
		  -- Only replace the secret when a new one was given.
		  client_secret = coalesce(EXCLUDED.client_secret, graph_app.client_secret),
		  client_state  = coalesce(graph_app.client_state, EXCLUDED.client_state),
		  updated_at    = now(),
		  updated_by    = EXCLUDED.updated_by`,
		tenant, g.DirectoryID, g.ClientID, sealed, state, g.Cloud, by)
	return err
}

// GraphApp returns the registration. withSecrets decrypts the client secret and the
// client state, and is only ever true for a connector.
func (s *Store) GraphApp(ctx context.Context, tenant string, withSecrets bool) (*GraphApp, error) {
	var (
		g             GraphApp
		secret, state []byte
		updatedAt     *time.Time
		updatedBy     *string
	)
	var cloud *string
	err := s.pg.QueryRow(ctx, `
		SELECT directory_id, client_id, client_secret, client_state,
		       cloud, updated_at, updated_by
		FROM graph_app WHERE tenant_id = $1`, tenant).
		Scan(&g.DirectoryID, &g.ClientID, &secret, &state, &cloud, &updatedAt, &updatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	g.HasSecret = len(secret) > 0
	if cloud != nil {
		g.Cloud = *cloud
	}
	g.UpdatedAt = updatedAt
	if updatedBy != nil {
		g.UpdatedBy = *updatedBy
	}

	if withSecrets && s.secrets != nil {
		if len(secret) > 0 {
			if plain, err := s.secrets.Open(secret); err == nil {
				g.ClientSecret = plain
			}
		}
		if len(state) > 0 {
			if plain, err := s.secrets.Open(state); err == nil {
				g.ClientState = plain
			}
		}
	}
	return &g, nil
}

// DeleteGraphApp forgets the registration.
func (s *Store) DeleteGraphApp(ctx context.Context, tenant string) error {
	_, err := s.pg.Exec(ctx, `DELETE FROM graph_app WHERE tenant_id = $1`, tenant)
	return err
}
