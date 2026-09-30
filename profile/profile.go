// SPDX-License-Identifier: AGPL-3.0-only

// Package profile answers MQL's profile.* family from a history of messages.
//
// The corpus calls these 898 times — profile.by_sender alone 678 — and reads four fields
// above all others: any_messages_benign (299), solicited (251),
// any_messages_malicious_or_spam (199) and prevalence (123). They are what separates
// "a stranger is asking for a wire transfer" from "the CFO, who writes every week, is".
//
// # Time-relative by construction
//
// A profile is not a fact about a sender, it is a fact about a sender *as of a moment*.
// Every query here takes the time of the message being evaluated and considers only
// events strictly before it. That is not a refinement: a backtest run against
// present-day history would let a rule see the future, quietly score better than it ever
// did in production, and produce compatibility numbers that mean nothing.
//
// The store is therefore an append-only event log rather than a mutable counter per
// sender. A mutable table can answer "now" quickly and cannot answer "as of March" at
// all. Module 2 will put the log in DuckLake with a materialised current-profile row in
// Postgres for the delivery path; this package defines the interface both sides of that
// will meet, and ships a working in-memory implementation so the capability is real
// rather than declared.
//
// # A missing profile is not an empty profile
//
// If the history cannot be reached, these return ErrUnavailable and the rule reports
// indeterminate. They never return a zero-count profile, because that reads as "nobody
// has ever heard from this sender" — the most suspicious answer there is, asserted
// confidently on no evidence. That failure would fire every first-contact rule in the
// corpus after a restart.
package profile

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Direction is which way a message travelled, which is what makes `solicited` answerable.
type Direction string

const (
	Inbound  Direction = "inbound"
	Outbound Direction = "outbound"
	Internal Direction = "internal"
)

// Verdict is what the platform concluded about a message, once it concluded anything.
type Verdict string

const (
	VerdictUnknown   Verdict = ""
	VerdictBenign    Verdict = "benign"
	VerdictMalicious Verdict = "malicious"
	VerdictSpam      Verdict = "spam"

	// VerdictFalsePositive is a message this platform flagged and a human overturned.
	// Distinct from benign: it says the detection was wrong, not merely that the mail
	// was fine, and rules use it to stop re-flagging a correspondent.
	VerdictFalsePositive Verdict = "false_positive"
)

// Event is one message, recorded for later profiling.
//
// Deliberately small. Whatever stores this will hold one row per message per tenant for
// years, and the fields here are the ones the corpus actually reads back.
type Event struct {
	// At is when the message was seen. Queries are strictly before this.
	At time.Time

	// SenderEmail and SenderDomain are the keys profiles are built on. Both are stored
	// so that a domain profile does not require scanning every address under it.
	SenderEmail  string
	SenderDomain string

	// ReplyTo is the reply-to address when it differs from the sender, which is the
	// whole point of profile.by_reply_to: the address a victim would actually answer.
	ReplyTo string

	Direction Direction
	Verdict   Verdict

	// AuthFailed records that SPF, DKIM and DMARC did not vouch for this message.
	AuthFailed bool
}

// Store is the history a profile is computed from.
//
// One method, because everything the corpus asks for is derivable from the events before
// a moment, and an interface that grew one method per field would have to change every
// time a rule read something new.
type Store interface {
	// Events returns everything recorded for a key strictly before `at`, in any order.
	// The key is an address for byEmail and byReplyTo, a domain for byDomain.
	//
	// A store that cannot answer returns an error; it must not return an empty slice to
	// mean "unreachable", because the caller cannot tell that from "never seen".
	Events(ctx context.Context, key Key, at time.Time) ([]Event, error)
}

// Kind says which index a key addresses.
type Kind string

const (
	ByEmail   Kind = "email"
	ByDomain  Kind = "domain"
	ByReplyTo Kind = "reply_to"
)

// Key identifies whose history to read.
type Key struct {
	Kind  Kind
	Value string
}

// ErrNoHistory reports that a store is configured but holds nothing for a tenant yet.
// Distinct from an unreachable store: it is a real answer, and profiles built from it
// are honest empties rather than guesses.
var ErrNoHistory = errors.New("profile: no history")

// Memory is an in-memory Store, and the reference for what the interface means.
//
// Useful in its own right for a single-tenant deployment replaying a mailbox, and it is
// what the tests for the as-of semantics run against. Safe for concurrent use.
type Memory struct {
	mu      sync.RWMutex
	byEmail map[string][]Event
	byDomn  map[string][]Event
	byReply map[string][]Event
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		byEmail: map[string][]Event{},
		byDomn:  map[string][]Event{},
		byReply: map[string][]Event{},
	}
}

// Add records one message.
func (m *Memory) Add(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v := norm(e.SenderEmail); v != "" {
		m.byEmail[v] = append(m.byEmail[v], e)
	}
	if v := norm(e.SenderDomain); v != "" {
		m.byDomn[v] = append(m.byDomn[v], e)
	}
	if v := norm(e.ReplyTo); v != "" {
		m.byReply[v] = append(m.byReply[v], e)
	}
}

// Len reports how many events are indexed by address, for tests and reporting.
func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, evs := range m.byEmail {
		n += len(evs)
	}
	return n
}

// Events implements Store.
func (m *Memory) Events(_ context.Context, key Key, at time.Time) ([]Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var src []Event
	switch key.Kind {
	case ByEmail:
		src = m.byEmail[norm(key.Value)]
	case ByDomain:
		src = m.byDomn[norm(key.Value)]
	case ByReplyTo:
		src = m.byReply[norm(key.Value)]
	}

	out := make([]Event, 0, len(src))
	for _, e := range src {
		// Strictly before: a message never profiles itself, and two messages arriving in
		// the same second do not see each other. Both matter for reproducibility — a
		// backtest must not depend on the order a batch happened to be loaded in.
		if e.At.Before(at) {
			out = append(out, e)
		}
	}
	return out, nil
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Summary is the computed profile, before it is shaped into the MDM type.
type Summary struct {
	Count        int
	FirstContact time.Time
	LastContact  time.Time
	LastInbound  time.Time
	LastOutbound time.Time

	Solicited     bool
	AnyBenign     bool
	AnyMalicious  bool
	AnyFalsePos   bool
	AllAuthFailed bool
}

// Summarise folds events into the shape the MDM type needs.
//
// `at` is the message's own time, so day counts are measured from it rather than from
// now — the same reason the query is time-relative.
func Summarise(events []Event, at time.Time) Summary {
	s := Summary{Count: len(events)}
	if len(events) == 0 {
		return s
	}

	sorted := append([]Event(nil), events...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })

	s.FirstContact = sorted[0].At
	s.LastContact = sorted[len(sorted)-1].At
	s.AllAuthFailed = true

	for _, e := range sorted {
		switch e.Direction {
		case Inbound:
			if e.At.After(s.LastInbound) {
				s.LastInbound = e.At
			}
		case Outbound:
			if e.At.After(s.LastOutbound) {
				s.LastOutbound = e.At
			}
			// Solicited means someone here wrote to them first. Any outbound message in
			// the history establishes it.
			s.Solicited = true
		}
		switch e.Verdict {
		case VerdictBenign:
			s.AnyBenign = true
		case VerdictMalicious, VerdictSpam:
			s.AnyMalicious = true
		case VerdictFalsePositive:
			s.AnyFalsePos = true
			// A detection that was overturned is also evidence the mail was fine.
			s.AnyBenign = true
		}
		if !e.AuthFailed {
			s.AllAuthFailed = false
		}
	}
	return s
}

// Prevalence buckets how much history there is, using the vocabulary the schema declares:
// "new", "outlier", "common", or "unknown" when there is not enough to say.
//
// The thresholds are ours. Nothing published says where the boundaries fall, and the
// corpus only ever compares against the literal strings, so what matters is that the
// buckets are ordered sensibly and stated plainly rather than that they match Sublime's
// exactly. Recorded in docs/SEMANTICS.md as inferred.
func Prevalence(s Summary) string {
	switch {
	case s.Count == 0:
		return "new"
	case s.Count < 3:
		return "outlier"
	default:
		return "common"
	}
}

// Days between two instants, rounded down, never negative.
func Days(from, to time.Time) int64 {
	if from.IsZero() || to.Before(from) {
		return 0
	}
	return int64(to.Sub(from).Hours() / 24)
}
