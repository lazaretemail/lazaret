// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testCache() *urlCache { return newURLCache(time.Minute, 10*time.Second, 1<<20, 1<<18) }

func ok(url string) *FetchResult {
	return &FetchResult{OriginalURL: url, EffectiveURL: url, Retrieved: true, StatusCode: 200, FinalDOM: "<html>hi</html>"}
}

// The whole point: a campaign puts one URL in fifty messages, and it is fetched once.
func TestSecondFetchIsServedFromCache(t *testing.T) {
	c := testCache()
	var calls atomic.Int64
	get := func() (*FetchResult, error) { calls.Add(1); return ok("https://a.test/x"), nil }

	for i := 0; i < 50; i++ {
		if _, err, _ := c.Do("https://a.test/x", get); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("fetched %d times for 50 identical links, want 1", n)
	}
}

// A query string is frequently the entire payload of a phishing link. Two victims'
// URLs differ only in a token, and serving one the other's page would be both wrong
// and a cross-recipient information leak.
func TestQueryStringIsPartOfTheKey(t *testing.T) {
	c := testCache()
	var calls atomic.Int64
	get := func(u string) func() (*FetchResult, error) {
		return func() (*FetchResult, error) { calls.Add(1); return ok(u), nil }
	}

	a := "https://phish.test/login?token=victim-one"
	b := "https://phish.test/login?token=victim-two"
	c.Do(a, get(a))
	c.Do(b, get(b))

	if n := calls.Load(); n != 2 {
		t.Errorf("fetched %d times for two different tokens, want 2 — the query must key the cache", n)
	}
}

// The fragment never reaches the server, so two URLs differing only after the #
// are the same request.
func TestFragmentIsNotPartOfTheKey(t *testing.T) {
	c := testCache()
	var calls atomic.Int64
	get := func() (*FetchResult, error) { calls.Add(1); return ok("https://a.test/p"), nil }

	c.Do("https://a.test/p#top", get)
	c.Do("https://a.test/p#bottom", get)

	if n := calls.Load(); n != 1 {
		t.Errorf("fetched %d times for URLs differing only by fragment, want 1", n)
	}
}

// Thirty-two links prefetched at once frequently contain the same URL twice.
// Without coalescing that is two browser launches racing to populate one entry.
func TestConcurrentFetchesCoalesce(t *testing.T) {
	c := testCache()
	var calls atomic.Int64
	release := make(chan struct{})
	get := func() (*FetchResult, error) {
		calls.Add(1)
		<-release // hold the first caller inside the fetch
		return ok("https://slow.test/"), nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Do("https://slow.test/", get) }()
	}
	// Let them all arrive and queue behind the one in flight.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Errorf("%d concurrent fetches of one URL made %d calls, want 1", 20, n)
	}
}

// A URL is a thing an attacker controls. One that is harmless now may serve a login
// page later, so the window has to close.
func TestEntriesExpire(t *testing.T) {
	c := testCache()
	clock := time.Now()
	c.now = func() time.Time { return clock }

	var calls atomic.Int64
	get := func() (*FetchResult, error) { calls.Add(1); return ok("https://a.test/"), nil }

	c.Do("https://a.test/", get)
	clock = clock.Add(30 * time.Second)
	c.Do("https://a.test/", get) // still inside the minute
	if n := calls.Load(); n != 1 {
		t.Fatalf("refetched inside the TTL: %d calls", n)
	}

	clock = clock.Add(2 * time.Minute)
	c.Do("https://a.test/", get)
	if n := calls.Load(); n != 2 {
		t.Errorf("did not refetch after the TTL: %d calls", n)
	}
}

// Forty-four links to a dead domain should cost one timeout, not forty-four — but
// the host may only have been slow, so the memory is short.
func TestFailedFetchesUseTheShortTTL(t *testing.T) {
	c := testCache()
	clock := time.Now()
	c.now = func() time.Time { return clock }

	var calls atomic.Int64
	dead := func() (*FetchResult, error) {
		calls.Add(1)
		return &FetchResult{OriginalURL: "https://dead.test/", Retrieved: false, Error: "timeout"}, nil
	}

	c.Do("https://dead.test/", dead)
	c.Do("https://dead.test/", dead)
	if n := calls.Load(); n != 1 {
		t.Errorf("a dead host was retried inside its window: %d calls", n)
	}

	// Past the error TTL but well inside the success TTL: it must be retried.
	clock = clock.Add(30 * time.Second)
	c.Do("https://dead.test/", dead)
	if n := calls.Load(); n != 2 {
		t.Errorf("a failure was remembered for the full success TTL: %d calls", n)
	}
}

// A page carries its DOM. An unbounded map of them in a long-lived service is a
// memory leak with a schedule.
func TestCacheIsBounded(t *testing.T) {
	c := newURLCache(time.Minute, time.Minute, 64<<10, 16<<10)
	big := strings.Repeat("x", 8<<10)

	for i := 0; i < 200; i++ {
		u := fmt.Sprintf("https://a.test/%d", i)
		c.Do(u, func() (*FetchResult, error) {
			return &FetchResult{OriginalURL: u, EffectiveURL: u, Retrieved: true, FinalDOM: big}, nil
		})
	}

	_, entries, bytes := c.Stats()
	if bytes > 64<<10 {
		t.Errorf("cache holds %d bytes, over its %d bound", bytes, 64<<10)
	}
	if entries == 0 || entries > 200 {
		t.Errorf("cache holds %d entries, which is not a bound", entries)
	}
}

// One enormous page must not evict everything else to hold itself.
func TestOversizedEntryIsNotCached(t *testing.T) {
	c := newURLCache(time.Minute, time.Minute, 64<<10, 4<<10)
	var calls atomic.Int64
	huge := strings.Repeat("y", 32<<10)
	get := func() (*FetchResult, error) {
		calls.Add(1)
		return &FetchResult{OriginalURL: "https://big.test/", Retrieved: true, FinalDOM: huge}, nil
	}

	c.Do("https://big.test/", get)
	c.Do("https://big.test/", get)
	if n := calls.Load(); n != 2 {
		t.Errorf("an oversized page was cached: %d calls, want 2", n)
	}
}

// Two messages can reach the same page by different links, and the answer should
// say which link this caller asked about.
func TestOriginalURLIsPerCaller(t *testing.T) {
	c := testCache()
	get := func() (*FetchResult, error) {
		return &FetchResult{OriginalURL: "https://short.test/a", EffectiveURL: "https://real.test/page", Retrieved: true}, nil
	}
	c.Do("https://short.test/a", get)

	res, _, hit := c.Do("https://short.test/a#ref", get)
	if !hit {
		t.Fatal("expected a cache hit")
	}
	if res.OriginalURL != "https://short.test/a#ref" {
		t.Errorf("OriginalURL = %q; the cached copy leaked another caller's link", res.OriginalURL)
	}
	if res.EffectiveURL != "https://real.test/page" {
		t.Errorf("EffectiveURL = %q, want the cached destination", res.EffectiveURL)
	}
}

// A failed fetch must not be cached as a success.
func TestErrorsAreNotCached(t *testing.T) {
	c := testCache()
	var calls atomic.Int64
	boom := func() (*FetchResult, error) { calls.Add(1); return nil, errors.New("refused") }

	if _, err, _ := c.Do("https://err.test/", boom); err == nil {
		t.Fatal("expected the error through")
	}
	if _, err, _ := c.Do("https://err.test/", boom); err == nil {
		t.Fatal("expected the error through on the second call too")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("an errored fetch was cached: %d calls, want 2", n)
	}
}
