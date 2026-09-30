// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
)

// CachingEnricher memoises enrichment for the analysis of one message.
//
// Every rule that wants an exploded attachment writes `file.explode(.)` itself, because
// MQL has no way to share a result between rules. Around 500 corpus rules call it, so
// analysing one message with a two-attachment payload issues on the order of a thousand
// identical gRPC scans of the same bytes — which took a corpus measurement run from
// seconds to past a ten-minute timeout, and would be far worse in a pipeline than in a
// test. The same applies to network.whois over a sender domain and to every profile.*
// lookup: the argument is fixed by the message, so the answer is too.
//
// Scope is deliberately one message. A cache that outlived the message would have to
// reason about when a WHOIS record or a sender profile goes stale, and that is a
// different problem with a different answer per capability. Here the question never
// arises: within a single analysis, an enrichment is a pure function of its arguments,
// and answering it twice is only ever waste.
//
// Errors are cached too, including unavailability. A service that is down at the start
// of a message is down for that message, and retrying it once per rule turns one outage
// into a thousand timeouts — the slowest possible way to reach the same verdict.
type CachingEnricher struct {
	inner Enricher

	mu      sync.Mutex
	entries map[string]*cacheEntry

	// caps remembers which capability each key was for. The key is a sha256 and
	// cannot be reversed, and a snapshot whose entries cannot be named is unreadable
	// to a person and useless for reporting what a stored message can still answer.
	caps map[string]string
}

type cacheEntry struct {
	once  sync.Once
	value Value
	err   error
}

// NewCache wraps an enricher so that repeated identical calls are answered once.
//
// Create one per message, not one per process.
func NewCache(inner Enricher) *CachingEnricher {
	return &CachingEnricher{
		inner:   inner,
		entries: map[string]*cacheEntry{},
		caps:    map[string]string{},
	}
}

// Enrich implements Enricher.
func (c *CachingEnricher) Enrich(ctx context.Context, cap enrich.Capability, args []Value, kwargs map[string]Value) (Value, error) {
	if c.inner == nil {
		return NullValue, enrich.NotImplemented(cap)
	}

	key := cacheKey(cap, args, kwargs)
	c.mu.Lock()
	e, ok := c.entries[key]
	if !ok {
		e = &cacheEntry{}
		c.entries[key] = e
		c.caps[key] = string(cap)
	}
	c.mu.Unlock()

	// Outside the lock: a slow scan must not block every other capability, and two rules
	// asking for the same thing at once should wait for one call rather than make two.
	e.once.Do(func() { e.value, e.err = c.inner.Enrich(ctx, cap, args, kwargs) })
	return e.value, e.err
}

// Len reports how many distinct enrichments have been requested. For tests and for
// reporting how much work a message actually cost.
func (c *CachingEnricher) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// cacheKey digests a call. Attachment bytes are hashed rather than compared, so the key
// stays short for a 10MB file, and hashing megabytes is still orders of magnitude
// cheaper than the network round trip it avoids.
func cacheKey(cap enrich.Capability, args []Value, kwargs map[string]Value) string {
	h := sha256.New()
	h.Write([]byte(cap))
	h.Write([]byte{0})
	for _, a := range args {
		digestValue(h, a)
		h.Write([]byte{0})
	}
	names := make([]string, 0, len(kwargs))
	for k := range kwargs {
		names = append(names, k)
	}
	sort.Strings(names) // keyword order is not significant to the callee
	for _, k := range names {
		h.Write([]byte(k))
		h.Write([]byte{'='})
		digestValue(h, kwargs[k])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// digestValue writes a stable representation of one argument.
//
// Scalars digest as their text. Everything composite goes through Interface and JSON,
// which is the only representation that actually distinguishes two values: String
// renders any data-model struct as its bare type name, so two different attachments both
// print "<Attachment>" and would share a cache entry — returning one file's scan for
// another, which is worse than any amount of redundant scanning.
//
// Bytes are hashed rather than written whole, and are checked before the composite path
// so an attachment's payload is not base64-expanded on the way into the digest.
func digestValue(h io.Writer, v Value) {
	if v.IsNull() {
		h.Write([]byte("\x01null"))
		return
	}
	// Bytes by content, and before the kind switch, so an attachment's payload is not
	// base64-expanded into the digest.
	//
	// AsBytes deliberately succeeds on a string too, which is what makes this stable
	// across a storage round trip: a screenshot is KindBytes when it comes back from
	// the renderer and a base64 string when it comes back from a snapshot, and both
	// have to digest the same or every nested call misses on replay.
	if b, ok := v.AsBytes(); ok && len(b) > 0 {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(b)))
		h.Write([]byte("\x03"))
		h.Write(n[:])
		sum := sha256.Sum256(b)
		h.Write(sum[:])
		return
	}

	switch v.Kind() {
	case mdm.KindArray:
		h.Write([]byte("\x02["))
		for _, e := range v.Elements() {
			digestValue(h, e)
			h.Write([]byte{','})
		}
		h.Write([]byte{']'})
	case mdm.KindObject, mdm.KindMap, mdm.KindJSON:
		h.Write([]byte("\x05"))
		// Canonical JSON, not encoding/json's default. The default sorts the keys of a
		// map and keeps the field order of a struct, so one value and its own storage
		// round trip digest differently — and a nested call, ml.logo_detect over
		// file.message_screenshot() as a hundred corpus rules write it, would then miss
		// on replay and report a brand of nothing.
		//
		// An unencodable value falls back to Go's own rendering, which is still more
		// specific than the bare type name String would give.
		if raw, err := canonicalJSON(v.Interface()); err == nil {
			h.Write(raw)
		} else {
			fmt.Fprintf(h, "%#v", v.Interface())
		}
	default:
		h.Write([]byte("\x04"))
		h.Write([]byte(v.String()))
	}
}
