// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A credential may arrive in a file, and the file wins over nothing.
//
// This is what lets the blob store configure itself: garage-init writes the key
// it created onto a shared volume and the engine reads it, so the deployment
// needs no step where a human runs a command, reads its output and pastes it into
// .env. It is also the Docker and Kubernetes secrets convention, so the same
// wiring works with a real secret store.
func TestEnvFileOr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	// Trailing newline on purpose: every way of writing a file adds one, and a
	// credential with \n on the end signs a request that the blob store rejects
	// as AuthorizationHeaderMalformed — an error that reads like the wrong key.
	if err := os.WriteFile(path, []byte("from-the-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("falls back to the default", func(t *testing.T) {
		if got := envFileOr("LAZARET_TEST_CRED", "fallback"); got != "fallback" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("reads the file", func(t *testing.T) {
		t.Setenv("LAZARET_TEST_CRED_FILE", path)
		if got := envFileOr("LAZARET_TEST_CRED", "fallback"); got != "from-the-file" {
			t.Errorf("got %q, want the file's contents with the newline trimmed", got)
		}
	})

	t.Run("the variable wins over the file", func(t *testing.T) {
		// An operator who set the credential explicitly must not be overridden by
		// one the bootstrap generated.
		t.Setenv("LAZARET_TEST_CRED_FILE", path)
		t.Setenv("LAZARET_TEST_CRED", "from-the-environment")
		if got := envFileOr("LAZARET_TEST_CRED", "fallback"); got != "from-the-environment" {
			t.Errorf("got %q", got)
		}
	})
}
