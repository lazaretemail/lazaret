// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mql"
)

type fakeEnricher struct {
	delay time.Duration
	err   error
	calls int
}

func (f *fakeEnricher) Enrich(ctx context.Context, cap enrich.Capability, _ []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	f.calls++
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return mql.NullValue, ctx.Err()
		}
	}
	return mql.NullValue, f.err
}

// A failure after the deadline has passed is the deadline's doing, not the service's.
//
// This is the distinction the whole thing turns on. Once a message runs out of time,
// every enrichment the evaluator happens to reach next fails — and being recorded as
// "capability unavailable" made one slow link fetch look like fifteen broken
// services, on a deployment where all fifteen worked.
func TestExpiredCallsAreCountedSeparately(t *testing.T) {
	inner := &fakeEnricher{delay: 50 * time.Millisecond}
	te := newTimingEnricher(inner)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if _, err := te.Enrich(ctx, enrich.CapNetworkWhois, nil, nil); err == nil {
		t.Fatal("expected the call to fail once the deadline passed")
	}

	report := te.Report()
	if len(report) != 1 {
		t.Fatalf("report has %d entries, want 1", len(report))
	}
	if report[0].Expired != 1 {
		t.Errorf("Expired = %d, want 1 — a deadline is not a broken service",
			report[0].Expired)
	}
}

// A genuine failure with time left is not an expiry, and must not be excused as one.
func TestARealFailureIsNotCountedAsExpired(t *testing.T) {
	te := newTimingEnricher(&fakeEnricher{err: errors.New("connection refused")})

	if _, err := te.Enrich(context.Background(), enrich.CapMLNLUClassifier, nil, nil); err == nil {
		t.Fatal("expected an error")
	}
	if got := te.Report()[0].Expired; got != 0 {
		t.Errorf("Expired = %d, want 0 — the service really is down", got)
	}
}

// The costliest capability is the one that caused an overrun, and naming it is the
// difference between a report an operator can act on and a list of blameless victims.
func TestCostliestNamesTheExpensiveCapability(t *testing.T) {
	te := newTimingEnricher(&fakeEnricher{delay: 30 * time.Millisecond})
	ctx := context.Background()

	_, _ = te.Enrich(ctx, enrich.CapMLLinkAnalysis, nil, nil)
	_, _ = te.Enrich(ctx, enrich.CapMLLinkAnalysis, nil, nil)

	te2 := newTimingEnricher(&fakeEnricher{})
	_, _ = te2.Enrich(ctx, enrich.CapProfileBySender, nil, nil)

	name, ms := te.Costliest()
	if name != string(enrich.CapMLLinkAnalysis) {
		t.Errorf("Costliest = %q, want ml.link_analysis", name)
	}
	if ms <= 0 {
		t.Errorf("Costliest reported %dms, want the time it actually took", ms)
	}
}

// Timing must count work, not cache hits: the number is there to say what the
// deployment actually spent.
func TestTimingSitsUnderTheCacheSoHitsAreNotCounted(t *testing.T) {
	inner := &fakeEnricher{}
	te := newTimingEnricher(inner)
	cached := mql.NewCache(te)

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _ = cached.Enrich(ctx, enrich.CapNetworkWhois,
			[]mql.Value{mql.StringValue("example.invalid")}, nil)
	}

	if inner.calls != 1 {
		t.Errorf("the provider was called %d times, want 1 — the cache should absorb the rest",
			inner.calls)
	}
	if got := te.Report()[0].Calls; got != 1 {
		t.Errorf("timing counted %d calls, want 1: a cache hit is not work", got)
	}
}
