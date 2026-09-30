// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
)

// Freezing what enrichment answered, so a rule can be run again later without it.
//
// # Why this exists
//
// The corpus stores the model of a message and the verdict it produced. It does not
// store what the enrichers said, so every question that needs re-running a rule over
// old mail has to either re-fetch — impossible, the link is dead and the sender's WHOIS
// record has changed — or give up. Giving up is what it did: a hunt refuses any rule
// with a capability, which is 968 of the 1,513 rules in the corpus. file.explode alone
// accounts for 414 of them.
//
// A snapshot is the answers, keyed the same way the per-message cache keys them. Replay
// them and the rule sees exactly what it saw when the message arrived, which is the only
// defensible thing for it to see: a judgement about mail from March should be made on
// March's evidence.
//
// # A miss is unavailable, not absent
//
// A rule written last week may ask a question this message was never asked. Replay
// answers that with Unavailable, so the rule reports indeterminate and says why. It does
// not answer null, which would read as "the data says no" and quietly turn an unanswered
// question into a clean verdict — the failure this project is built to avoid. A backtest
// can therefore report three numbers honestly: matched, did not match, and could not be
// decided from what was kept.
type Snapshot struct {
	// Entries are keyed by the same digest the live cache uses, so a replayed call
	// looks up what the original call stored.
	Entries map[string]SnapshotEntry `json:"entries"`
}

// SnapshotEntry is one enrichment answer, in a form that survives storage.
type SnapshotEntry struct {
	// Capability is carried for diagnostics and for reporting which capabilities a
	// stored message can still answer. The key alone is opaque.
	Capability string `json:"capability"`

	// Kind distinguishes the few cases a JSON round trip would otherwise flatten.
	// Bytes in particular: a screenshot marshals to a base64 string, and a string is
	// not a picture.
	Kind string `json:"kind,omitempty"`

	// Value is the answer as canonical JSON, absent for an error.
	Value json.RawMessage `json:"value,omitempty"`

	// Bytes holds a binary answer, base64 as JSON does anyway.
	Bytes []byte `json:"bytes,omitempty"`

	// Unavailable names the capability when the answer was a null that knew why.
	Unavailable string `json:"unavailable,omitempty"`

	// Error records a failure. Reason is kept rather than the error value, because
	// what a later reader needs is why, not a Go type.
	Error string `json:"error,omitempty"`

	// ErrorUnavailable marks an error that meant "could not answer" rather than
	// "answered badly". The distinction decides indeterminate versus failed and must
	// survive, since an error string cannot be re-typed reliably.
	ErrorUnavailable bool `json:"error_unavailable,omitempty"`
}

// Snapshot returns everything this cache answered, ready to store.
//
// Safe to call once the analysis has finished. Calling it while enrichment is still in
// flight returns whatever has resolved so far, which is a partial record rather than a
// wrong one.
func (c *CachingEnricher) Snapshot() *Snapshot {
	c.mu.Lock()
	keys := make([]string, 0, len(c.entries))
	entries := make(map[string]*cacheEntry, len(c.entries))
	for k, e := range c.entries {
		keys = append(keys, k)
		entries[k] = e
	}
	c.mu.Unlock()

	out := &Snapshot{Entries: make(map[string]SnapshotEntry, len(keys))}
	for _, k := range keys {
		e := entries[k]
		cap := c.capFor(k)
		if se, ok := freeze(cap, e); ok {
			out.Entries[k] = se
		}
	}
	return out
}

// capFor recovers the capability a key was for. Recorded when the call is made,
// because a sha256 cannot be reversed and a snapshot with no capability names is
// unreadable to a human and useless for reporting coverage.
func (c *CachingEnricher) capFor(key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.caps[key]
}

func freeze(cap string, e *cacheEntry) (SnapshotEntry, bool) {
	se := SnapshotEntry{Capability: cap}

	if e.err != nil {
		se.Error = e.err.Error()
		var un *enrich.Unavailable
		se.ErrorUnavailable = errors.As(e.err, &un)
		return se, true
	}

	v := e.value
	se.Unavailable = v.Unavailable()

	switch v.Kind() {
	case mdm.KindNull:
		se.Kind = "null"
		return se, true
	case mdm.KindBytes:
		b, _ := v.AsBytes()
		se.Kind = "bytes"
		se.Bytes = b
		return se, true
	}

	raw, err := canonicalJSON(v.Interface())
	if err != nil {
		// An answer that will not marshal cannot be replayed, and recording it as a
		// null would be a lie. Leaving it out makes the replay report it unavailable,
		// which is what it is.
		return se, false
	}
	se.Kind = v.Kind().String()
	se.Value = raw
	return se, true
}

// Capabilities reports which capabilities a snapshot can answer, for the coverage a
// stored message still has.
func (s *Snapshot) Capabilities() []string {
	if s == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, e := range s.Entries {
		if e.Capability != "" {
			seen[e.Capability] = true
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Len is how many answers were kept.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.Entries)
}

// ReplayEnricher answers only from a snapshot, and never from the network.
//
// That is the guarantee, not an implementation detail. A hunt or a backtest walking a
// hundred thousand messages must not turn into a hundred thousand WHOIS lookups, and a
// verdict about old mail must not change because a domain was re-registered since.
type ReplayEnricher struct {
	snap *Snapshot

	// missed counts questions the snapshot could not answer, so a caller can report
	// how much of its result rests on evidence it does not have.
	missed map[string]int
}

// NewReplay returns an enricher backed by a snapshot.
func NewReplay(s *Snapshot) *ReplayEnricher {
	return &ReplayEnricher{snap: s, missed: map[string]int{}}
}

// Enrich implements Enricher.
func (r *ReplayEnricher) Enrich(_ context.Context, cap enrich.Capability, args []Value, kwargs map[string]Value) (Value, error) {
	if r.snap == nil {
		r.missed[string(cap)]++
		return NullValue, enrich.Unavailablef(cap, "nothing was recorded for this message")
	}
	e, ok := r.snap.Entries[cacheKey(cap, args, kwargs)]
	if !ok {
		r.missed[string(cap)]++
		return NullValue, enrich.Unavailablef(cap,
			"this question was not asked when the message was analysed, so the answer was never kept")
	}
	return thaw(cap, e)
}

// Missed reports the capabilities a replay could not answer and how often, so the
// caller can say what its result does not rest on.
func (r *ReplayEnricher) Missed() map[string]int {
	out := make(map[string]int, len(r.missed))
	for k, v := range r.missed {
		out[k] = v
	}
	return out
}

func thaw(cap enrich.Capability, e SnapshotEntry) (Value, error) {
	if e.Error != "" {
		if e.ErrorUnavailable {
			return NullValue, enrich.Unavailablef(cap, "%s", e.Error)
		}
		return NullValue, errors.New(e.Error)
	}
	switch e.Kind {
	case "null", "":
		if e.Unavailable != "" {
			return UnavailableValue(e.Unavailable), nil
		}
		return NullValue, nil
	case "bytes":
		return BytesValue(e.Bytes), nil
	}

	var any_ any
	if err := json.Unmarshal(e.Value, &any_); err != nil {
		return NullValue, enrich.Unavailablef(cap, "the stored answer could not be read back: %v", err)
	}
	return JSONValue(any_), nil
}

// canonicalJSON marshals with map keys sorted at every level.
//
// encoding/json sorts the keys of a map and keeps the field order of a struct, so the
// same content marshals two ways depending on which it started as. That matters here
// beyond tidiness: the cache key digests composite arguments as JSON, so a value and
// its own round trip would key differently, and a nested call — ml.logo_detect over
// file.message_screenshot(), which is what a hundred corpus rules do — would miss on
// replay and report a brand of nothing.
//
// Going through a generic decode and back is what normalises it: everything becomes a
// map, and maps sort.
func canonicalJSON(v any) (json.RawMessage, error) {
	first, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(first, &generic); err != nil {
		return nil, err
	}
	out, err := json.Marshal(generic)
	if err != nil {
		return nil, fmt.Errorf("re-marshalling: %w", err)
	}
	return out, nil
}
