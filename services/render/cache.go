// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"container/list"
	"context"
	"net/url"
	"sync"
	"time"
)

// A cache of fetched links, shared across every message.
//
// The enrichment cache in the engine is deliberately per-message: within one
// analysis an enrichment is a pure function of its arguments, so there is nothing
// to invalidate. Across messages that is no longer true — but it is also where all
// the waste is. A campaign puts the same URL in fifty messages and it was fetched
// fifty times, and every marketing mail re-fetched the same unsubscribe link, the
// same CDN image, the same tracking domain. Measured at seventy-seven enrichment
// calls per message, most of them links.
//
// So the cache lives here rather than in the engine: this service does the
// expensive part, and everything that asks benefits, including a second engine.
//
// Three properties it has to have:
//
//   - A short TTL. A URL is not a constant — it is a thing an attacker controls,
//     and one that serves a login page an hour from now may serve nothing today.
//     The window only has to cover a campaign's burst to remove nearly all the
//     duplicate work, so it is minutes, not days.
//   - A bound. A fetched page carries its DOM, and an unbounded map of them in a
//     long-lived service is a memory leak with a schedule.
//   - Coalescing. Thirty-two links prefetched at once frequently contain the same
//     URL twice; without this they are two browser launches that start before
//     either can populate the cache.
type urlCache struct {
	// shared is the deployment-wide tier behind this one, or nil.
	//
	// Checked after the local map and before fetching, and populated alongside it.
	// A miss or a failure there is a miss here: the store exists to save work, and a
	// cache that can break the thing it accelerates is worse than none.
	shared *sharedStore

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List // most recently used at the front
	bytes   int64

	// inflight coalesces concurrent fetches of the same URL.
	inflight map[string]*fetchCall

	ttl      time.Duration
	errTTL   time.Duration
	maxBytes int64
	maxEntry int64

	now func() time.Time

	stats cacheStats
}

type cacheEntry struct {
	key     string
	res     *FetchResult
	expires time.Time
	size    int64
}

// fetchCall is one in-flight fetch that others are waiting on.
type fetchCall struct {
	done chan struct{}
	res  *FetchResult
	err  error
}

// SharedHits counts answers that came from the deployment-wide store rather than
// from this process. It is the number that says whether that tier is earning its
// place, and it is separate from Hits so the two tiers can be judged apart.
type cacheStats struct{ Hits, Misses, Coalesced, Evictions, SharedHits int64 }

func newURLCache(ttl, errTTL time.Duration, maxBytes, maxEntry int64) *urlCache {
	return &urlCache{
		entries:  map[string]*list.Element{},
		order:    list.New(),
		inflight: map[string]*fetchCall{},
		ttl:      ttl,
		errTTL:   errTTL,
		maxBytes: maxBytes,
		maxEntry: maxEntry,
		now:      time.Now,
	}
}

// cacheKey is what two requests must share to be the same fetch.
//
// The fragment is dropped because it never reaches the server, so two URLs
// differing only after the # are the same request. Everything else is kept: a
// query string is frequently the whole payload of a phishing link, and
// normalising it away would serve one victim's page for another's token.
func cacheKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// Do returns a cached result, or calls fetch once for concurrent callers.
func (c *urlCache) Do(raw string, fetch func() (*FetchResult, error)) (res *FetchResult, err error, hit bool) {
	key := cacheKey(raw)

	c.mu.Lock()
	if el, ok := c.entries[key]; ok {
		e := el.Value.(*cacheEntry)
		if c.now().Before(e.expires) {
			c.order.MoveToFront(el)
			c.stats.Hits++
			out := *e.res
			c.mu.Unlock()
			// A copy, so a caller cannot mutate what the next one reads. The
			// original URL is restored: two messages may reach the same page by
			// different links, and the answer should say which one this was.
			out.OriginalURL = raw
			return &out, nil, true
		}
		c.removeLocked(el)
	}

	// Somebody else is already fetching this: wait for them rather than starting
	// a second browser.
	if call, ok := c.inflight[key]; ok {
		c.stats.Coalesced++
		c.mu.Unlock()
		<-call.done
		if call.err != nil {
			return nil, call.err, false
		}
		out := *call.res
		out.OriginalURL = raw
		return &out, nil, true
	}

	call := &fetchCall{done: make(chan struct{})}
	c.inflight[key] = call
	c.stats.Misses++
	c.mu.Unlock()

	// The deployment-wide tier, before doing the expensive thing. Outside the lock:
	// it is a network call, short-deadlined, and holding the cache mutex across it
	// would serialise every other link behind it.
	//
	// Still inside the in-flight registration, so concurrent callers for the same URL
	// wait for this lookup rather than each making their own.
	if c.shared != nil {
		if hit := c.shared.Get(context.Background(), key); hit != nil {
			call.res = hit
			close(call.done)
			c.mu.Lock()
			delete(c.inflight, key)
			c.storeLocked(key, hit)
			c.stats.SharedHits++
			c.mu.Unlock()
			out := *hit
			out.OriginalURL = raw
			return &out, nil, true
		}
	}

	call.res, call.err = fetch()
	close(call.done)

	c.mu.Lock()
	delete(c.inflight, key)
	if call.err == nil && call.res != nil {
		c.storeLocked(key, call.res)
	}
	c.mu.Unlock()

	if call.err == nil && call.res != nil && c.shared != nil {
		c.shared.Put(context.Background(), key, call.res)
	}

	if call.err != nil {
		return nil, call.err, false
	}
	out := *call.res
	out.OriginalURL = raw
	return &out, nil, false
}

func (c *urlCache) storeLocked(key string, res *FetchResult) {
	size := int64(len(res.FinalDOM) + len(res.Screenshot) + len(res.EffectiveURL) + 128)
	if size > c.maxEntry {
		// One enormous page must not evict everything else to hold itself.
		return
	}

	ttl := c.ttl
	if !res.Retrieved || res.Error != "" {
		// A host that timed out is cached briefly too: forty-four links to a dead
		// domain should cost one timeout, not forty-four. Briefly, because the
		// host may simply have been slow.
		ttl = c.errTTL
	}

	e := &cacheEntry{key: key, res: res, expires: c.now().Add(ttl), size: size}
	c.entries[key] = c.order.PushFront(e)
	c.bytes += size

	for c.bytes > c.maxBytes && c.order.Len() > 0 {
		c.removeLocked(c.order.Back())
		c.stats.Evictions++
	}
}

func (c *urlCache) removeLocked(el *list.Element) {
	e := el.Value.(*cacheEntry)
	c.order.Remove(el)
	delete(c.entries, e.key)
	c.bytes -= e.size
}

// Stats is a snapshot, for the metrics exporter.
func (c *urlCache) Stats() (cacheStats, int, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats, c.order.Len(), c.bytes
}
