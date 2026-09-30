// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The point of the bound: a hundred mailboxes delivering at once must not become a
// hundred concurrent analyses. Nothing limited this, and an engine in that state
// does not degrade — it thrashes the renderer and runs out of memory.
func TestConcurrencyIsBounded(t *testing.T) {
	const limit = 4
	a := newAdmitter(limit, time.Second)

	var running, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := a.Acquire(context.Background())
			if err != nil {
				return // refused under contention, which is the designed behaviour
			}
			defer release()
			n := running.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			running.Add(-1)
		}()
	}
	wg.Wait()

	if p := peak.Load(); p > limit {
		t.Errorf("%d analyses ran at once, over the limit of %d", p, limit)
	}
}

// A queue that never drains has to say so. A request that succeeds after four
// minutes is worse than a refusal: the connector gave up long ago and will offer
// the message again, so the work was wasted and paid for twice.
func TestSaturationIsRefusedNotQueuedForever(t *testing.T) {
	a := newAdmitter(1, 40*time.Millisecond)

	release, err := a.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	start := time.Now()
	if _, err := a.Acquire(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("second acquire returned %v, want ErrBusy", err)
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Errorf("waited %s before refusing; the bound on waiting is the point", waited)
	}
}

// A slot must come back when the caller finishes, or the engine bleeds capacity
// one request at a time until it serves nothing.
func TestSlotsAreReturned(t *testing.T) {
	a := newAdmitter(2, 50*time.Millisecond)

	for i := 0; i < 100; i++ {
		release, err := a.Acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire %d: %v — a slot was not returned", i, err)
		}
		release()
	}
}

// Releasing twice must not hand out a slot nobody holds.
func TestDoubleReleaseIsHarmless(t *testing.T) {
	a := newAdmitter(1, 20*time.Millisecond)
	release, err := a.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
	release()

	// The single slot is free exactly once.
	r2, err := a.Acquire(context.Background())
	if err != nil {
		t.Fatalf("the slot did not come back: %v", err)
	}
	defer r2()
	if _, err := a.Acquire(context.Background()); !errors.Is(err, ErrBusy) {
		t.Error("a double release created a slot out of nothing")
	}
}

// A caller that hangs up is not a refusal: nobody was told no, and counting it as
// one would make a client timeout look like engine overload.
func TestCallerCancellationIsNotARefusal(t *testing.T) {
	a := newAdmitter(1, time.Minute)
	release, err := a.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	if _, err := a.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want the caller's cancellation", err)
	}
}

// A nil admitter admits everything, so a test or an embedder that never built one
// is not silently blocked.
func TestNilAdmitterAdmits(t *testing.T) {
	var a *admitter
	release, err := a.Acquire(context.Background())
	if err != nil {
		t.Fatalf("nil admitter refused: %v", err)
	}
	release()
}
