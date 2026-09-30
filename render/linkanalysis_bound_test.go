// SPDX-License-Identifier: AGPL-3.0-only

package render

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Exercises the sweep through the path that actually adds entries, so removing
// the call site fails this rather than passing quietly — which the first version
// of this test did, because it called sweepLocked itself.
func TestFetchOnceKeepsTheMapBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"retrieved":true,"effective_url":"https://x.test/","status_code":200}`)
	}))
	defer srv.Close()

	c := New(&Options{Address: srv.URL, HTTPClient: srv.Client()}).EnableLinkAnalysis()

	for i := 0; i < maxInflight*2; i++ {
		if _, err := c.fetchOnce(context.Background(), fmt.Sprintf("https://a.test/%d", i)); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}

	c.inflightMu.Lock()
	n := len(c.inflight)
	c.inflightMu.Unlock()
	if n > maxInflight {
		t.Errorf("after %d distinct links the map holds %d entries, over the %d bound",
			maxInflight*2, n, maxInflight)
	}
}

// The dedupe map only ever deleted an entry when the same URL was asked for again
// after its TTL, or when the fetch failed. A URL fetched once and never seen again
// was kept forever, holding the page's DOM with it. Over a day of real mail that is
// tens of thousands of distinct links: it looked like caching and was a leak.
func TestInflightMapIsBounded(t *testing.T) {
	c := &Client{inflight: map[string]*fetchCall{}}

	// Settled entries, as they are after a completed fetch.
	stale := time.Now().Add(-2 * fetchTTL)
	for i := 0; i < maxInflight*3; i++ {
		c.inflight[fmt.Sprintf("https://a.test/%d", i)] = &fetchCall{done: closedChan(), at: stale}
		c.inflightMu.Lock()
		c.sweepLocked()
		c.inflightMu.Unlock()
	}

	if n := len(c.inflight); n > maxInflight {
		t.Errorf("map holds %d entries, over the %d bound", n, maxInflight)
	}
}

// A fetch still running must never be evicted: somebody is waiting on its channel,
// and removing it starts a second fetch of the same page.
func TestSweepNeverEvictsAFetchInFlight(t *testing.T) {
	c := &Client{inflight: map[string]*fetchCall{}}

	running := &fetchCall{done: make(chan struct{})} // at is zero: still in flight
	c.inflight["https://slow.test/"] = running

	stale := time.Now().Add(-2 * fetchTTL)
	for i := 0; i < maxInflight*2; i++ {
		c.inflight[fmt.Sprintf("https://a.test/%d", i)] = &fetchCall{done: closedChan(), at: stale}
	}

	c.inflightMu.Lock()
	c.sweepLocked()
	c.inflightMu.Unlock()

	if _, ok := c.inflight["https://slow.test/"]; !ok {
		t.Error("an in-flight fetch was evicted; its waiters would hang or refetch")
	}
}

// Expiry alone should be enough in the normal case: everything ages out within the
// TTL, and the oldest-drop path is the safety net rather than the mechanism.
func TestSweepPrefersExpiryOverDropping(t *testing.T) {
	c := &Client{inflight: map[string]*fetchCall{}}

	fresh := time.Now()
	for i := 0; i < maxInflight/2+10; i++ {
		c.inflight[fmt.Sprintf("https://fresh.test/%d", i)] = &fetchCall{done: closedChan(), at: fresh}
	}
	before := len(c.inflight)

	c.inflightMu.Lock()
	c.sweepLocked()
	c.inflightMu.Unlock()

	if len(c.inflight) != before {
		t.Errorf("swept %d fresh entries; nothing was expired and the map was under the bound",
			before-len(c.inflight))
	}
}

func closedChan() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
