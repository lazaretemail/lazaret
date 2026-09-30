// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

func TestRoleHierarchy(t *testing.T) {
	for _, tc := range []struct {
		have, need store.Role
		want       bool
	}{
		{store.RoleAdmin, store.RoleViewer, true},
		{store.RoleAdmin, store.RoleAnalyst, true},
		{store.RoleAdmin, store.RoleAdmin, true},
		{store.RoleAnalyst, store.RoleViewer, true},
		{store.RoleAnalyst, store.RoleAdmin, false},
		{store.RoleViewer, store.RoleAnalyst, false},
		{store.RoleViewer, store.RoleViewer, true},
		{store.Role("nonsense"), store.RoleViewer, false},
		{store.RoleAdmin, store.Role("nonsense"), false},
	} {
		if got := tc.have.Allows(tc.need); got != tc.want {
			t.Errorf("%s allows %s = %v, want %v", tc.have, tc.need, got, tc.want)
		}
	}
}

func TestPasswordHashing(t *testing.T) {
	const pw = "a-sufficiently-long-password"

	h, err := store.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h, pw) {
		t.Fatal("the hash contains the password")
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Errorf("not argon2id: %s", h)
	}

	ok, err := store.VerifyPassword(h, pw)
	if err != nil || !ok {
		t.Errorf("the correct password did not verify: %v %v", ok, err)
	}
	ok, _ = store.VerifyPassword(h, pw+"x")
	if ok {
		t.Error("a wrong password verified")
	}

	// Salted: the same password twice must not produce the same hash, or a database
	// dump reveals which accounts share a password.
	h2, _ := store.HashPassword(pw)
	if h == h2 {
		t.Error("two hashes of the same password are identical; the salt is not working")
	}
}

// Length is what makes a password hard to guess. A floor is worth enforcing;
// composition rules mostly produce Password1!
func TestShortPasswordsAreRefused(t *testing.T) {
	if _, err := store.HashPassword("short"); err == nil {
		t.Error("a five-character password was accepted")
	}
	if _, err := store.HashPassword("exactly12chr"); err != nil {
		t.Errorf("a twelve-character password was refused: %v", err)
	}
}

// The actor on an action comes from the authenticated caller, never from the request.
// A client that can name its own actor can forge an audit trail.
func TestCallerActorIsNotClientSupplied(t *testing.T) {
	person := &store.Caller{UserID: "usr_1", Email: "analyst@example.com"}
	if got := person.Actor(); got != "analyst@example.com" {
		t.Errorf("actor = %q", got)
	}

	// A service is distinguishable from a person, so a trail can tell "an analyst
	// quarantined this" from "the IMAP connector did".
	svc := &store.Caller{UserID: "token:imap", Service: "imap"}
	if got := svc.Actor(); got != "service:imap" {
		t.Errorf("service actor = %q", got)
	}

	if got := (*store.Caller)(nil).Actor(); got != "anonymous" {
		t.Errorf("nil actor = %q", got)
	}
}
