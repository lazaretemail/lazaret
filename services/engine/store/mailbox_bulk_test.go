// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

func bulkStore(t *testing.T, tenant string) (*store.Store, context.Context) {
	t.Helper()
	s := openStore(t)
	ctx := context.Background()
	if err := s.EnsureTenant(ctx, tenant, tenant, nil); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	return s, ctx
}

func graphBox(tenant, addr string) store.Mailbox {
	return store.Mailbox{TenantID: tenant, Kind: "graph", Address: addr, GraphUser: addr, Enabled: true}
}

// A second walk of the directory does not duplicate what is already configured.
//
// An administrator onboards four hundred accounts, forty people join, and they walk the
// directory again. Without this they get four hundred duplicate rows, which means every
// one of those mailboxes is collected twice by two connectors.
func TestBulkAddSkipsMailboxesAlreadyConfigured(t *testing.T) {
	const tenant = "t_bulk_dupe"
	s, ctx := bulkStore(t, tenant)

	first := []store.Mailbox{
		graphBox(tenant, "dana@example.test"),
		graphBox(tenant, "sam@example.test"),
	}
	added, skipped, err := s.AddMailboxes(ctx, tenant, first)
	if err != nil {
		t.Fatalf("first add: %v", err)
	}
	if len(added) != 2 || len(skipped) != 0 {
		t.Fatalf("first add: %d added, %d skipped; want 2 and 0", len(added), len(skipped))
	}

	// The second walk returns the two already there plus one new joiner.
	second := append(first, graphBox(tenant, "joiner@example.test"))
	added, skipped, err = s.AddMailboxes(ctx, tenant, second)
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if len(added) != 1 || added[0].Address != "joiner@example.test" {
		t.Errorf("second add put in %d mailbox(es): %+v", len(added), added)
	}
	if len(skipped) != 2 {
		t.Errorf("second add skipped %d, want the 2 already configured", len(skipped))
	}

	boxes, err := s.Mailboxes(ctx, tenant, false)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(boxes) != 3 {
		t.Errorf("tenant holds %d mailboxes after two walks, want 3", len(boxes))
	}
}

// Addresses differing only in case are the same mailbox.
//
// Microsoft reports whatever case the directory holds, and it is not always what an
// administrator typed the first time. Two rows for Dana.Whitfield@ and dana.whitfield@
// are two connectors on one mailbox.
func TestBulkAddTreatsAddressCaseAsTheSameMailbox(t *testing.T) {
	const tenant = "t_bulk_case"
	s, ctx := bulkStore(t, tenant)

	if _, _, err := s.AddMailboxes(ctx, tenant, []store.Mailbox{
		graphBox(tenant, "dana.whitfield@example.test"),
	}); err != nil {
		t.Fatalf("first add: %v", err)
	}

	added, skipped, err := s.AddMailboxes(ctx, tenant, []store.Mailbox{
		graphBox(tenant, "Dana.Whitfield@EXAMPLE.test"),
	})
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if len(added) != 0 {
		t.Errorf("a differently-cased copy of a configured address was added: %+v", added)
	}
	if len(skipped) != 1 {
		t.Errorf("skipped %d, want 1", len(skipped))
	}
}

// Two addresses that are the same within one batch produce one mailbox.
//
// Not hypothetical: a directory can report the same primary address on two objects, and
// a console sending a selection has no reason to have deduplicated it.
func TestBulkAddDeduplicatesWithinOneBatch(t *testing.T) {
	const tenant = "t_bulk_within"
	s, ctx := bulkStore(t, tenant)

	added, skipped, err := s.AddMailboxes(ctx, tenant, []store.Mailbox{
		graphBox(tenant, "shared@example.test"),
		graphBox(tenant, "SHARED@example.test"),
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if len(added) != 1 {
		t.Errorf("one address given twice produced %d mailboxes", len(added))
	}
	if len(skipped) != 1 {
		t.Errorf("skipped %d, want 1", len(skipped))
	}
}

// Pausing a mailbox keeps everything else about it, including the credential.
//
// The point of pause rather than remove: an administrator taking a noisy mailbox out of
// collection should not have to destroy its configuration and re-enter a password to put
// it back. A toggle that went through the full save path would reset every field the
// caller did not happen to carry across.
func TestPausingAMailboxKeepsItsConfiguration(t *testing.T) {
	const tenant = "t_pause"
	s, ctx := bulkStore(t, tenant)

	key := make([]byte, 32)
	box, err := store.NewSecretBox(key)
	if err != nil {
		t.Fatalf("secret box: %v", err)
	}
	s.SetSecretBox(box)

	saved, err := s.SaveMailbox(ctx, store.Mailbox{
		TenantID: tenant, Kind: "imap", Address: "ops@example.test",
		Host: "imap.example.test", Username: "ops", Secret: "hunter2",
		Folder: "Archive", TLSMode: "starttls", Remediate: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("saving: %v", err)
	}

	if err := s.SetMailboxEnabled(ctx, tenant, saved.ID, false); err != nil {
		t.Fatalf("pausing: %v", err)
	}

	boxes, err := s.Mailboxes(ctx, tenant, true)
	if err != nil || len(boxes) != 1 {
		t.Fatalf("listing: %v (%d rows)", err, len(boxes))
	}
	got := boxes[0]
	switch {
	case got.Enabled:
		t.Error("the mailbox is still collecting after being paused")
	case got.Secret != "hunter2":
		t.Error("pausing destroyed the stored credential")
	case got.Folder != "Archive":
		t.Errorf("pausing reset the folder to %q", got.Folder)
	case !got.Remediate:
		t.Error("pausing cleared the remediate flag")
	case got.TLSMode != "starttls":
		t.Errorf("pausing reset the TLS mode to %q", got.TLSMode)
	}

	// And back again.
	if err := s.SetMailboxEnabled(ctx, tenant, saved.ID, true); err != nil {
		t.Fatalf("resuming: %v", err)
	}
	if boxes, _ = s.Mailboxes(ctx, tenant, false); !boxes[0].Enabled {
		t.Error("the mailbox did not resume")
	}
}

// One tenant cannot pause another's mailbox.
//
// The id travels in a request path. Without the tenant in the WHERE clause, knowing an
// id would be enough to stop somebody else's mail being collected — silently, because a
// paused mailbox looks exactly like one nobody has enabled yet.
func TestPausingIsScopedToTheTenant(t *testing.T) {
	const mine, theirs = "t_pause_mine", "t_pause_theirs"
	s, ctx := bulkStore(t, mine)
	if err := s.EnsureTenant(ctx, theirs, theirs, nil); err != nil {
		t.Fatalf("creating the other tenant: %v", err)
	}

	saved, err := s.SaveMailbox(ctx, store.Mailbox{
		TenantID: mine, Kind: "graph", Address: "dana@example.test", Enabled: true,
	})
	if err != nil {
		t.Fatalf("saving: %v", err)
	}

	err = s.SetMailboxEnabled(ctx, theirs, saved.ID, false)
	if !errors.Is(err, store.ErrNoMailbox) {
		t.Fatalf("another tenant paused the mailbox (err %v)", err)
	}

	boxes, _ := s.Mailboxes(ctx, mine, false)
	if len(boxes) != 1 || !boxes[0].Enabled {
		t.Error("the mailbox stopped collecting")
	}
}
