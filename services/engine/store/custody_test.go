// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Custody is the part of quarantine that makes it reversible. Quarantine deletes the
// message from the mailbox, so the held copy is the only one left, and every test
// here is really asking the same question: can the message be put back?

func TestCustodyRoundTrip(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	raw := []byte("Message-ID: <a@b.test>\r\nSubject: hello\r\n\r\nbody\r\n")
	if s.HasRaw(ctx, "t", "a@b.test") {
		t.Fatal("reports holding a message it was never given")
	}
	if _, err := s.Raw(ctx, "t", "a@b.test"); err != store.ErrNoRaw {
		t.Fatalf("reading an unheld message: got %v, want ErrNoRaw", err)
	}

	if err := s.PutRaw(ctx, "t", "a@b.test", raw); err != nil {
		t.Fatal(err)
	}
	if !s.HasRaw(ctx, "t", "a@b.test") {
		t.Error("does not report holding a message it was just given")
	}
	got, err := s.Raw(ctx, "t", "a@b.test")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Errorf("the bytes changed in custody:\n got %q\nwant %q", got, raw)
	}

	if err := s.PurgeRaw(ctx, "t", "a@b.test"); err != nil {
		t.Fatal(err)
	}
	if s.HasRaw(ctx, "t", "a@b.test") {
		t.Error("still holding a purged message")
	}
	// Purging twice is not an error: an operator clicking delete on an already
	// deleted message has got what they wanted.
	if err := s.PurgeRaw(ctx, "t", "a@b.test"); err != nil {
		t.Errorf("purging twice: %v", err)
	}
}

// TestCustodyPathIsNotDerivedFromUntrustedText covers a directory traversal.
//
// A Message-ID comes from the message headers, which is to say from the sender. Using
// one as a filename would let a sender choose where this writes — and the bytes being
// written are their own message, so it is a file-write primitive aimed at whatever
// path they like.
func TestCustodyPathIsNotDerivedFromUntrustedText(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	hostile := []string{
		"../../../../../../tmp/lazaret-escape",
		"..\\..\\windows\\system32\\escape",
		"/etc/cron.d/escape",
		strings.Repeat("a", 4096),
		"with\x00nul",
		".",
		"..",
	}
	for _, id := range hostile {
		if err := s.PutRaw(ctx, "t", id, []byte("x")); err != nil {
			t.Errorf("PutRaw(%.30q): %v", id, err)
			continue
		}
		got, err := s.Raw(ctx, "t", id)
		if err != nil {
			t.Errorf("Raw(%.30q): %v", id, err)
			continue
		}
		if string(got) != "x" {
			t.Errorf("Raw(%.30q) = %q", id, got)
		}
	}
	// Nothing escaped: every hostile id resolved inside the configured directory,
	// which is what the hashing is for.
	if _, err := s.Raw(ctx, "t", "../../../../../../tmp/lazaret-escape"); err != nil {
		t.Errorf("the traversal id should resolve to an ordinary held file: %v", err)
	}
}

// TestCustodyIsPerTenant checks that one tenant cannot read another's held mail.
func TestCustodyIsPerTenant(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	if err := s.PutRaw(ctx, "one", "shared@b.test", []byte("tenant one")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRaw(ctx, "two", "shared@b.test", []byte("tenant two")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Raw(ctx, "one", "shared@b.test")
	if err != nil || string(got) != "tenant one" {
		t.Errorf("tenant one read %q, %v", got, err)
	}
	got, _ = s.Raw(ctx, "two", "shared@b.test")
	if string(got) != "tenant two" {
		t.Errorf("tenant two read %q", got)
	}
}

// withSecrets gives the store a key, so mailbox credentials can be stored at all.
func withSecrets(t *testing.T, s *store.Store) {
	t.Helper()
	box, err := store.NewSecretBox([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetSecretBox(box)
}

func TestRemediationQueue(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	if err := s.EnsureTenant(ctx, "t", "t", nil); err != nil {
		t.Fatal(err)
	}
	withSecrets(t, s)
	box, err := s.SaveMailbox(ctx, store.Mailbox{
		TenantID: "t", Kind: "imap", Address: "watch@example.test",
		Host: "imap.example.test:993", Username: "watch", Secret: "pw",
		TLSMode: "tls", Folder: "INBOX", Enabled: true, Remediate: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := s.Enqueue(ctx, "t", "m1@example.test", store.OpRemove)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("queued %d jobs for one mailbox, want 1", n)
	}

	// Clicking twice must not queue the same work twice.
	if n, err := s.Enqueue(ctx, "t", "m1@example.test", store.OpRemove); err != nil || n != 0 {
		t.Errorf("a second identical enqueue produced %d jobs (%v), want 0", n, err)
	}

	jobs, err := s.Claim(ctx, "t", box.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Op != store.OpRemove || jobs[0].MessageID != "m1@example.test" {
		t.Fatalf("claimed %+v", jobs)
	}

	// A failure leaves it to be retried rather than dropping it: a remediation that
	// silently gave up is a message someone believes was removed and which is still
	// in an inbox.
	if err := s.Finish(ctx, "t", jobs[0].ID, "connection refused"); err != nil {
		t.Fatal(err)
	}
	again, err := s.Claim(ctx, "t", box.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 1 {
		t.Fatalf("a failed remediation was not retried: %+v", again)
	}

	if err := s.Finish(ctx, "t", again[0].ID, ""); err != nil {
		t.Fatal(err)
	}
	done, err := s.Claim(ctx, "t", box.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 0 {
		t.Errorf("a completed remediation was handed out again: %+v", done)
	}
	pending, err := s.PendingRemediations(ctx, "t")
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("still pending: %+v", pending)
	}
}

// TestRemediationSkipsDisabledMailboxes: a mailbox that is turned off is not one to
// queue work against, or the queue fills with jobs nothing will ever collect.
func TestRemediationSkipsDisabledMailboxes(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	if err := s.EnsureTenant(ctx, "t", "t", nil); err != nil {
		t.Fatal(err)
	}
	withSecrets(t, s)
	if _, err := s.SaveMailbox(ctx, store.Mailbox{
		TenantID: "t", Kind: "imap", Address: "off@example.test",
		Host: "h:993", Username: "u", Secret: "p", TLSMode: "tls", Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.Enqueue(ctx, "t", "m1@example.test", store.OpRemove)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("queued %d jobs against a disabled mailbox, want 0", n)
	}
}

// Remediation must be aimed at the mailbox a message arrived in, and only fan out
// when that is genuinely unknown.
func TestRemediationTargetsTheArrivalMailbox(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	if err := s.EnsureTenant(ctx, "t", "t", nil); err != nil {
		t.Fatal(err)
	}
	withSecrets(t, s)

	var boxes []string
	for _, addr := range []string{"one@example.test", "two@example.test", "three@example.test"} {
		b, err := s.SaveMailbox(ctx, store.Mailbox{
			TenantID: "t", Kind: "imap", Address: addr, Host: "h:993",
			Username: "u", Secret: "p", TLSMode: "tls", Enabled: true, Remediate: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		boxes = append(boxes, b.ID)
	}

	// Known origin: one job, for that mailbox.
	if err := s.RecordOrigin(ctx, "t", "known@example.test", boxes[1]); err != nil {
		t.Fatal(err)
	}
	n, err := s.Enqueue(ctx, "t", "known@example.test", store.OpRemove)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("queued %d jobs for a message with a known origin, want 1", n)
	}
	jobs, err := s.Claim(ctx, "t", boxes[1], 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Errorf("the job was not queued against the arrival mailbox: %+v", jobs)
	}

	// Two mailboxes received it: both must be cleaned, or the quarantine is half done.
	for _, b := range []string{boxes[0], boxes[2]} {
		if err := s.RecordOrigin(ctx, "t", "both@example.test", b); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.Enqueue(ctx, "t", "both@example.test", store.OpRemove); err != nil || n != 2 {
		t.Errorf("queued %d jobs for a message delivered to two mailboxes (%v), want 2", n, err)
	}

	// Unknown origin — mail seen in transit, or ingested before origins were kept —
	// still has to reach every mailbox, because any of them might hold it.
	if n, err := s.Enqueue(ctx, "t", "unknown@example.test", store.OpRemove); err != nil || n != 3 {
		t.Errorf("queued %d jobs for a message with no recorded origin (%v), want 3", n, err)
	}
}
