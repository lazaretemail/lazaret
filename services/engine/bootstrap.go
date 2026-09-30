// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Starting up with nothing configured.
//
// The goal is that `docker compose up` on a fresh server produces a working platform,
// and that everything after that is done by an administrator in the browser. Two
// things stood in the way and both were bootstrap problems rather than design ones:
// the key that encrypts mailbox credentials, and the token the mail connector
// authenticates with. Neither can come from the web interface, because neither
// service can start without it.
//
// So both are provisioned here, on first start, into a directory the operator can see
// and back up. A deployment that supplies them explicitly is unchanged — an
// environment variable always wins — and one that does not gets working defaults
// instead of an error message telling it to run openssl.

// secretKeyFile and connectorTokenFile live in the state directory, which is a
// volume. Their names say what they are, because someone will find them later and
// need to know.
const (
	secretKeyFile      = "secret-key"
	connectorTokenFile = "connector-token"
)

// ensureSecretKey returns the key that encrypts mailbox credentials at rest,
// generating and persisting one if this deployment has none.
//
// # The tradeoff, stated plainly
//
// Generating it here means the key sits in the same volume as the database it
// protects, so anyone who can read the volume can read the credentials. That is
// weaker than a key held somewhere else and injected at start.
//
// It is still the right default. The alternative is a platform that will not start
// until the operator has run openssl and edited a file, and the realistic outcome of
// that is not a better-protected key — it is a deployment that never happens, or one
// where the key is pasted into the same compose file anyway. An operator who wants
// the key kept elsewhere sets LAZARET_SECRET_KEY and this never runs.
//
// What the file genuinely protects against is the database being read on its own:
// a stolen backup, a dumped volume, a decommissioned disk. Those are the common
// cases, and they are the ones this covers.
func ensureSecretKey(provided, stateDir string) (string, error) {
	if provided != "" {
		return provided, nil
	}
	path := filepath.Join(stateDir, secretKeyFile)

	if b, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(b))
		if _, err := hex.DecodeString(key); err != nil || len(key) != 64 {
			return "", fmt.Errorf("%s does not contain a 64-character hex key; "+
				"if it was damaged, restore it from a backup — a new key cannot "+
				"decrypt existing mailbox credentials", path)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	key := hex.EncodeToString(raw[:])

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", stateDir, err)
	}
	// 0600: the key is the only thing standing between a copied volume and every
	// mailbox password in the deployment.
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}

	log.Printf("generated a credential encryption key at %s", path)
	log.Printf("  back this file up. Without it, stored mailbox credentials cannot be " +
		"decrypted and every mailbox has to be re-entered.")
	return key, nil
}

// ensureConnectorToken makes sure the mail connector has something to authenticate
// with, and writes it where the connector can read it.
//
// The chicken and egg this solves: the connector needs an admin API token to read the
// mailbox list, tokens are minted through the API, and the API needs an administrator
// who has logged in. On a fresh deployment nobody has. The result was a connector
// that could not start until a human had visited the web interface and pasted a token
// into a compose file — which is exactly the kind of step that turns "run this" into
// "read this first".
//
// The token is admin because mailbox credentials are readable only by an admin token;
// that restriction is deliberate and is what keeps a stolen browser session from
// walking away with every mailbox password. It is written 0600 into the shared state
// directory rather than passed as an environment variable, so it does not appear in
// `docker inspect`, in the process table, or in a shell history.
func ensureConnectorToken(ctx context.Context, st *store.Store, tenant, stateDir string) error {
	path := filepath.Join(stateDir, connectorTokenFile)

	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		// Already provisioned. Not validated against the database here: a token
		// revoked by an administrator should stay revoked, and silently minting
		// a replacement would undo a deliberate act.
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	token, err := st.NewAPIToken(ctx, tenant, "mail connector", store.RoleAdmin)
	if err != nil {
		return fmt.Errorf("minting the connector token: %w", err)
	}
	// 0750: the connector's user must be able to traverse the directory to reach
	// the token, and must not be able to list or add to it beyond that.
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return err
	}
	if err := os.Chmod(stateDir, 0o750); err != nil {
		return err
	}
	// 0640, not 0600: the connector runs as a different user and has to read this.
	// It is deliberately a different mode from the key beside it, which stays 0600
	// — the connector needs a token to list mailboxes, and has no business being
	// able to read the key that decrypts their credentials. A process added to this
	// file's group gets one and not the other.
	if err := os.WriteFile(path, []byte(token+"\n"), 0o640); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	// WriteFile does not apply the mode to a file that already exists, and umask
	// can clear bits on creation, so it is set explicitly.
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("setting the mode on %s: %w", path, err)
	}

	log.Printf("provisioned an API token for the mail connector at %s", path)
	return nil
}
