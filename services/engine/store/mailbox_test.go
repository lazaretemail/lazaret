// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// A connector reporting health may only write to its own tenant's mailbox.
//
// The id comes off the wire, in the path of a request, so without the tenant in the
// WHERE clause a token in one tenant could write to a row in another. The prize is
// not a credential: last_error is free text that shows up on somebody else's settings
// page as the reason their mailbox is failing, and "Authentication failed" written
// onto a working mailbox is an efficient way to get an administrator to rotate a good
// password — or to stop believing the page at all.
func TestNoteMailboxIsScopedToItsTenant(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	for _, tn := range []string{"tenant-a", "tenant-b"} {
		if err := s.EnsureTenant(ctx, tn, tn, nil); err != nil {
			t.Fatalf("creating %s: %v", tn, err)
		}
	}

	victim, err := s.SaveMailbox(ctx, store.Mailbox{
		TenantID: "tenant-a", Kind: "imap", Address: "victim@a.test",
		// No secret: this test is about who may write to the row, and storing a
		// credential needs a configured secret key that is not what is under test.
		Host: "mail.a.test:993", Username: "victim", Enabled: true,
	})
	if err != nil {
		t.Fatalf("creating the mailbox: %v", err)
	}

	// The attack: tenant-b reports a failure against tenant-a's mailbox id.
	err = s.NoteMailbox(ctx, "tenant-b", victim.ID, 99, errors.New("Authentication failed"))
	if !errors.Is(err, store.ErrNoMailbox) {
		t.Errorf("a cross-tenant report returned %v, want ErrNoMailbox", err)
	}

	boxes, err := s.Mailboxes(ctx, "tenant-a", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(boxes) != 1 {
		t.Fatalf("expected one mailbox in tenant-a, got %d", len(boxes))
	}
	if boxes[0].LastError != "" {
		t.Errorf("another tenant wrote %q onto this mailbox", boxes[0].LastError)
	}
	if boxes[0].Messages != 0 {
		t.Errorf("another tenant moved the message count to %d", boxes[0].Messages)
	}

	// And the owning tenant's own report still works.
	if err := s.NoteMailbox(ctx, "tenant-a", victim.ID, 3, nil); err != nil {
		t.Fatalf("the owning tenant could not report: %v", err)
	}
	boxes, _ = s.Mailboxes(ctx, "tenant-a", false)
	if boxes[0].Messages != 3 {
		t.Errorf("messages = %d, want 3", boxes[0].Messages)
	}
	if boxes[0].LastSeen == nil {
		t.Error("last_seen was not set by a successful report")
	}
}

// A report against an id that does not exist says so rather than quietly writing
// nothing, so a connector cannot believe it recorded something it did not.
func TestNoteMailboxRejectsAnUnknownID(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	if err := s.EnsureTenant(ctx, "t", "t", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.NoteMailbox(ctx, "t", "mbx_does_not_exist", 0, nil); !errors.Is(err, store.ErrNoMailbox) {
		t.Errorf("got %v, want ErrNoMailbox", err)
	}
}
