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

// A screenshot is a whole browser process, not a goroutine. The engine admits 32
// analyses and every one of them may ask for a picture, so without this the host
// runs 32 Chromiums and each takes thirty seconds instead of one and a half.
func TestBrowsersAreBounded(t *testing.T) {
	const limit = 3
	p := newBrowserPool(limit, time.Second)

	var running, peak atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := p.Acquire(context.Background())
			if err != nil {
				return
			}
			defer release()
			n := running.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(3 * time.Millisecond)
			running.Add(-1)
		}()
	}
	wg.Wait()

	if got := peak.Load(); got > limit {
		t.Errorf("%d browsers ran at once, over the limit of %d", got, limit)
	}
}

// A render that waits forever has already lost: the analysis deadline passes, the
// caller gives up, and the browser launch is paid for and thrown away.
func TestBrowserSaturationIsRefused(t *testing.T) {
	p := newBrowserPool(1, 30*time.Millisecond)
	release, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	if _, err := p.Acquire(context.Background()); !errors.Is(err, ErrBrowsersBusy) {
		t.Errorf("got %v, want ErrBrowsersBusy", err)
	}
}

func TestBrowserSlotsAreReturned(t *testing.T) {
	p := newBrowserPool(2, 40*time.Millisecond)
	for i := 0; i < 50; i++ {
		release, err := p.Acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire %d: %v — a slot was not returned", i, err)
		}
		release()
	}
}

// A nil pool admits everything, so a test renderer built without one still works.
func TestNilBrowserPoolAdmits(t *testing.T) {
	var p *browserPool
	release, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("nil pool refused: %v", err)
	}
	release()
}
