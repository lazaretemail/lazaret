// SPDX-License-Identifier: AGPL-3.0-only

package profile_test

import (
	"context"
	"testing"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/profile"
)

func day(n int) time.Time {
	return time.Date(2026, 1, n, 12, 0, 0, 0, time.UTC)
}

func seeded() *profile.Memory {
	m := profile.NewMemory()
	m.Add(profile.Event{At: day(1), SenderEmail: "cfo@partner.test", SenderDomain: "partner.test", Direction: profile.Outbound, Verdict: profile.VerdictBenign})
	m.Add(profile.Event{At: day(3), SenderEmail: "cfo@partner.test", SenderDomain: "partner.test", Direction: profile.Inbound, Verdict: profile.VerdictBenign})
	m.Add(profile.Event{At: day(5), SenderEmail: "cfo@partner.test", SenderDomain: "partner.test", Direction: profile.Inbound})
	m.Add(profile.Event{At: day(20), SenderEmail: "attacker@evil.test", SenderDomain: "evil.test", Direction: profile.Inbound, Verdict: profile.VerdictMalicious, AuthFailed: true})
	return m
}

// The property the package exists for: a profile is a fact about a moment, not about a
// sender. A query from day 4 must not see day 5.
func TestEventsAreStrictlyBeforeTheMessage(t *testing.T) {
	m := seeded()
	ctx := context.Background()

	for _, tc := range []struct{ at, want int }{{2, 1}, {4, 2}, {6, 3}, {100, 3}} {
		got, err := m.Events(ctx, profile.Key{Kind: profile.ByEmail, Value: "cfo@partner.test"}, day(tc.at))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != tc.want {
			t.Errorf("as of day %d: %d events, want %d", tc.at, len(got), tc.want)
		}
	}

	// A message never profiles itself: the boundary is strict, so a query at exactly the
	// time of an event excludes it. Two messages in the same second not seeing each
	// other is what keeps a backtest independent of load order.
	got, _ := m.Events(ctx, profile.Key{Kind: profile.ByEmail, Value: "cfo@partner.test"}, day(3))
	if len(got) != 1 {
		t.Errorf("as of the instant of an event: %d events, want 1", len(got))
	}
}

func TestSummariseReadsTheFieldsRulesUse(t *testing.T) {
	m := seeded()
	events, _ := m.Events(context.Background(), profile.Key{Kind: profile.ByEmail, Value: "cfo@partner.test"}, day(10))
	s := profile.Summarise(events, day(10))

	if !s.Solicited {
		t.Error("solicited is false although the organisation wrote to them on day 1")
	}
	if !s.AnyBenign {
		t.Error("any_messages_benign is false although a message was marked benign")
	}
	if s.AnyMalicious {
		t.Error("any_messages_malicious_or_spam is true with no such verdict")
	}
	if got := profile.Prevalence(s); got != "common" {
		t.Errorf("prevalence = %q, want common for three messages", got)
	}
	if got := profile.Days(s.FirstContact, day(10)); got != 9 {
		t.Errorf("days_known = %d, want 9", got)
	}
}

func TestUnsolicitedAttackerLooksNew(t *testing.T) {
	m := seeded()
	events, _ := m.Events(context.Background(), profile.Key{Kind: profile.ByEmail, Value: "attacker@evil.test"}, day(21))
	s := profile.Summarise(events, day(21))

	if s.Solicited {
		t.Error("solicited is true for an address nobody has written to")
	}
	if !s.AnyMalicious {
		t.Error("any_messages_malicious_or_spam is false after a malicious verdict")
	}
	if !s.AllAuthFailed {
		t.Error("auth_failed is false although every message failed authentication")
	}
	if got := profile.Prevalence(s); got != "outlier" {
		t.Errorf("prevalence = %q, want outlier for one message", got)
	}
}

// A sender with no history at all profiles as new and unsolicited — which is a real
// answer, not a missing one, and is what makes first-contact rules work.
func TestUnknownSenderIsNewNotUnavailable(t *testing.T) {
	e := profile.New(profile.NewMemory())
	v, err := e.Enrich(context.Background(), enrich.CapProfileBySender, []mql.Value{message("stranger@nowhere.test", day(5))}, nil)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if v.IsNull() {
		t.Fatal("null for a sender with no history; empty history is an answer")
	}
	if got := v.Field("prevalence").String(); got != "new" {
		t.Errorf("prevalence = %q, want new", got)
	}
	if v.Field("solicited").Truthy() {
		t.Error("solicited is true for a stranger")
	}
}

// An unreachable store must report unavailable, never a zero-count profile: that reads
// as "nobody has ever heard from this sender", which is the most suspicious answer there
// is, asserted on no evidence.
func TestUnreachableStoreIsUnavailable(t *testing.T) {
	e := profile.New(brokenStore{})
	_, err := e.Enrich(context.Background(), enrich.CapProfileBySender, []mql.Value{message("a@b.test", day(5))}, nil)
	if !mql.IsUnavailable(err) {
		t.Fatalf("err = %v, want unavailable", err)
	}
}

type brokenStore struct{}

func (brokenStore) Events(context.Context, profile.Key, time.Time) ([]profile.Event, error) {
	return nil, context.DeadlineExceeded
}

func TestEnricherUsesTheMessageDateNotTheClock(t *testing.T) {
	m := seeded()
	e := profile.New(m)

	// As of day 4 the sender has two messages; as of day 100, three. If the enricher
	// used the wall clock both would say three, and every backtest would see the future.
	early, err := e.Enrich(context.Background(), enrich.CapProfileBySenderEmail, []mql.Value{message("cfo@partner.test", day(4))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	late, err := e.Enrich(context.Background(), enrich.CapProfileBySenderEmail, []mql.Value{message("cfo@partner.test", day(100))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if early.Field("prevalence").String() != "outlier" {
		t.Errorf("as of day 4 prevalence = %q, want outlier", early.Field("prevalence").String())
	}
	if late.Field("prevalence").String() != "common" {
		t.Errorf("as of day 100 prevalence = %q, want common", late.Field("prevalence").String())
	}
}

func message(sender string, at time.Time) mql.Value {
	domain := sender[len(sender)-len(sender)+indexAt(sender)+1:]
	return mql.FromGo(&mdm.MessageDataModel{
		Sender:  &mdm.SenderMailbox{Email: mdm.ParseEmailAddress(sender)},
		Headers: &mdm.Headers{Date: &at},
		Type:    &mdm.MessageType{Inbound: mdm.Ptr(true)},
		Subject: &mdm.Subject{Subject: mdm.Ptr("hello from " + domain)},
	})
}

func indexAt(s string) int {
	for i := range s {
		if s[i] == '@' {
			return i
		}
	}
	return -1
}
