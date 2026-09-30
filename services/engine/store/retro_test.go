// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

func retroStore(t *testing.T, tenant string) (*store.Store, context.Context) {
	t.Helper()
	s := openStore(t)
	ctx := context.Background()
	if err := s.EnsureTenant(ctx, tenant, tenant, nil); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}
	return s, ctx
}

// A sweep that runs nightly must not file the same discovery every night.
//
// This is the failure mode of every alerting system that does not do it: the findings
// that are genuinely new get buried under repeats of the old ones by the end of the
// week, and the page stops being read.
func TestAFindingIsFiledOnce(t *testing.T) {
	const tenant = "t_find_once"
	s, ctx := retroStore(t, tenant)

	f := store.RetroFinding{
		MessageID: "m1", Kind: store.FindingRule, Source: "some_rule",
		Detail: "matches a rule that was not in effect at the time",
	}

	fresh, err := s.RecordFinding(ctx, tenant, f)
	if err != nil {
		t.Fatalf("filing: %v", err)
	}
	if !fresh {
		t.Fatal("the first filing of a finding did not report as new")
	}

	fresh, err = s.RecordFinding(ctx, tenant, f)
	if err != nil {
		t.Fatalf("re-filing: %v", err)
	}
	if fresh {
		t.Error("the same discovery filed twice reported as new both times")
	}

	got, err := s.Findings(ctx, tenant, store.FindingNew, 0)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("tonight's sweep left %d rows for one discovery", len(got))
	}
}

// Dismissing a finding is final, even though the fact that produced it is still true.
//
// The sweep re-observes the same thing on its next run, and the link check re-visits the
// same URL. Reviving the finding would put something a person has already dealt with
// back in front of them every six hours, which teaches them to ignore the page.
func TestADismissedFindingStaysDismissed(t *testing.T) {
	const tenant = "t_find_dismiss"
	s, ctx := retroStore(t, tenant)

	f := store.RetroFinding{MessageID: "m1", Kind: store.FindingLink, Source: "https://example.test/"}
	if _, err := s.RecordFinding(ctx, tenant, f); err != nil {
		t.Fatalf("filing: %v", err)
	}
	open, err := s.Findings(ctx, tenant, store.FindingNew, 0)
	if err != nil || len(open) != 1 {
		t.Fatalf("listing: %v (%d rows)", err, len(open))
	}

	if err := s.ResolveFinding(ctx, tenant, open[0].ID, store.FindingDismissed, "analyst@example.test"); err != nil {
		t.Fatalf("dismissing: %v", err)
	}

	// The next sweep sees the same thing.
	if _, err := s.RecordFinding(ctx, tenant, f); err != nil {
		t.Fatalf("re-filing: %v", err)
	}

	open, err = s.Findings(ctx, tenant, store.FindingNew, 0)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(open) != 0 {
		t.Errorf("a dismissed finding came back: %+v", open)
	}
	if n, err := s.OpenFindings(ctx, tenant); err != nil || n != 0 {
		t.Errorf("open count %d (err %v), want 0", n, err)
	}

	// It is still on the record, with who decided.
	all, err := s.Findings(ctx, tenant, "", 0)
	if err != nil || len(all) != 1 {
		t.Fatalf("history: %v (%d rows)", err, len(all))
	}
	if all[0].State != store.FindingDismissed || all[0].ReviewedBy != "analyst@example.test" {
		t.Errorf("history lost the decision: %+v", all[0])
	}
	if all[0].ReviewedAt == nil {
		t.Error("history lost when the decision was made")
	}
}

// Only a real resolution is accepted. "new" is not a decision, and neither is anything
// invented by a caller.
func TestAFindingCannotBeResolvedToNonsense(t *testing.T) {
	const tenant = "t_find_state"
	s, ctx := retroStore(t, tenant)

	if _, err := s.RecordFinding(ctx, tenant, store.RetroFinding{
		MessageID: "m1", Kind: store.FindingRule, Source: "r",
	}); err != nil {
		t.Fatalf("filing: %v", err)
	}
	open, _ := s.Findings(ctx, tenant, store.FindingNew, 0)

	for _, bad := range []string{"new", "", "quarantined"} {
		if err := s.ResolveFinding(ctx, tenant, open[0].ID, bad, "who"); err == nil {
			t.Errorf("%q was accepted as a way to resolve a finding", bad)
		}
	}
}

// Claiming a due link pushes it forward in the same statement.
//
// Without that, two workers — or the same worker on an overlapping tick — both fetch the
// same URL, which is a real outbound request to an address an attacker chose, made twice.
func TestClaimingALinkStopsItBeingClaimedAgain(t *testing.T) {
	const tenant = "t_watch_claim"
	s, ctx := retroStore(t, tenant)

	due := time.Now().UTC().Add(-time.Minute)
	for _, u := range []string{"https://a.test/", "https://b.test/"} {
		if err := s.WatchLink(ctx, tenant, u, "m1", "digest0", due); err != nil {
			t.Fatalf("scheduling %s: %v", u, err)
		}
	}

	first, err := s.DueLinks(ctx, tenant, 10, 6*time.Hour)
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("claimed %d of 2 due links", len(first))
	}
	for _, l := range first {
		if l.Attempts != 1 {
			t.Errorf("%s claimed with attempts %d, want 1", l.URL, l.Attempts)
		}
		if l.Digest != "digest0" {
			t.Errorf("%s lost the digest it was scheduled with", l.URL)
		}
	}

	second, err := s.DueLinks(ctx, tenant, 10, 6*time.Hour)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(second) != 0 {
		t.Errorf("an overlapping tick claimed %d link(s) a moment after the first did", len(second))
	}

	if n, err := s.WatchedCount(ctx, tenant); err != nil || n != 2 {
		t.Errorf("watched count %d (err %v), want 2", n, err)
	}
	if err := s.StopWatching(ctx, tenant, "https://a.test/", "m1"); err != nil {
		t.Fatalf("stopping: %v", err)
	}
	if n, _ := s.WatchedCount(ctx, tenant); n != 1 {
		t.Errorf("watched count %d after stopping one, want 1", n)
	}
}

// The same URL in two messages is two watches.
//
// A campaign sends one link to fifty mailboxes. The link changing is a finding about
// each of those messages, because each of them was judged on what it served at the time.
func TestTheSameLinkInTwoMessagesIsWatchedTwice(t *testing.T) {
	const tenant = "t_watch_two"
	s, ctx := retroStore(t, tenant)

	due := time.Now().UTC().Add(-time.Minute)
	for _, m := range []string{"m1", "m2"} {
		if err := s.WatchLink(ctx, tenant, "https://same.test/", m, "d", due); err != nil {
			t.Fatalf("scheduling for %s: %v", m, err)
		}
	}
	// Scheduling the same pair again is not a second row: one message's rules ask
	// about a link several times.
	if err := s.WatchLink(ctx, tenant, "https://same.test/", "m1", "d", due); err != nil {
		t.Fatalf("re-scheduling: %v", err)
	}

	if n, err := s.WatchedCount(ctx, tenant); err != nil || n != 2 {
		t.Errorf("watched count %d (err %v), want 2", n, err)
	}
}
