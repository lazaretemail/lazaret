// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// A scan's last error has to say when it happened, and has to outlive the scan.
//
// The text survives batches that report no error, because otherwise the only
// record of a transient failure is gone by the time anyone looks. The cost of that
// is what this pins down: a scan that failed one message out of two hundred and
// forty-two, hours ago, and had been ingesting happily ever since, showed that
// error on the history page with no count and no timestamp, and read as a scan
// that was broken right now.
func TestBackfillProgressTimestampsTheLastError(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	const tenant = "t_err"
	if err := s.EnsureTenant(ctx, tenant, tenant, nil); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}

	b, err := s.CreateBackfill(ctx, store.Backfill{
		TenantID: tenant, MailboxID: "mb_1", Since: day(1), Until: day(9),
	})
	if err != nil {
		t.Fatalf("creating the scan: %v", err)
	}
	// Claiming is what moves a scan to running, which is the only state
	// BackfillProgress will update.
	if _, err := s.ClaimBackfill(ctx, tenant, "mb_1", "test", time.Minute); err != nil {
		t.Fatalf("claiming the scan: %v", err)
	}

	// Nothing has gone wrong yet.
	if got, _ := s.BackfillByID(ctx, tenant, b.ID); got.LastErrorAt != nil {
		t.Fatalf("a scan with no error has a last_error_at of %v", got.LastErrorAt)
	}

	before := time.Now().Add(-time.Second)
	if err := s.BackfillProgress(ctx, tenant, b.ID, store.BackfillDelta{
		Examined: 1, Failures: 1, Cursor: day(2),
		LastError: `Post "http://engine:8700/v0/messages/ingest": net/http: request canceled`,
	}); err != nil {
		t.Fatalf("reporting the failure: %v", err)
	}

	failed, err := s.BackfillByID(ctx, tenant, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.LastError == "" {
		t.Fatal("the error text was not recorded")
	}
	if failed.LastErrorAt == nil {
		t.Fatal("the error was recorded without a time, so a reader cannot tell " +
			"a failure happening now from one that happened hours ago")
	}
	if failed.LastErrorAt.Before(before) {
		t.Errorf("last_error_at is %v, before the failure was reported", failed.LastErrorAt)
	}
	at := *failed.LastErrorAt

	// Two hundred more messages, all fine. The text stays — it is the only record
	// — but the clock must not move, or every later batch would make an old
	// failure look current.
	for i := 0; i < 200; i++ {
		if err := s.BackfillProgress(ctx, tenant, b.ID, store.BackfillDelta{
			Examined: 1, Ingested: 1, Cursor: day(3),
		}); err != nil {
			t.Fatalf("reporting progress: %v", err)
		}
	}

	after, err := s.BackfillByID(ctx, tenant, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastError != failed.LastError {
		t.Errorf("the error text was cleared by a clean batch: %q", after.LastError)
	}
	if after.LastErrorAt == nil || !after.LastErrorAt.Equal(at) {
		t.Errorf("last_error_at moved to %v on a batch that reported no error", after.LastErrorAt)
	}
	// And the number that gives the error its scale.
	if after.Failures != 1 || after.Examined != 201 {
		t.Errorf("failures=%d examined=%d, want 1 of 201", after.Failures, after.Examined)
	}

	// Finishing cleanly must not throw the reason away. It used to: the count of
	// failures survived and the explanation did not, so the history page could say
	// one message failed and nothing at all about why.
	if err := s.FinishBackfill(ctx, tenant, b.ID, store.BackfillDone, ""); err != nil {
		t.Fatalf("finishing the scan: %v", err)
	}
	done, err := s.BackfillByID(ctx, tenant, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.LastError != failed.LastError {
		t.Errorf("finishing the scan discarded why a message failed: %q", done.LastError)
	}
	if done.LastErrorAt == nil || !done.LastErrorAt.Equal(at) {
		t.Errorf("finishing the scan moved last_error_at to %v", done.LastErrorAt)
	}

	// A scan that fails outright does replace it — that failure is the reason.
	if err := s.FinishBackfill(ctx, tenant, b.ID, store.BackfillFailed, "the mailbox went away"); err != nil {
		t.Fatalf("failing the scan: %v", err)
	}
	broke, err := s.BackfillByID(ctx, tenant, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if broke.LastError != "the mailbox went away" {
		t.Errorf("last_error is %q, want the failure that ended the scan", broke.LastError)
	}
	if broke.LastErrorAt == nil || !broke.LastErrorAt.After(at) {
		t.Errorf("last_error_at did not move for the failure that ended the scan")
	}
}
