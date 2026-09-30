// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"context"
	"fmt"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// Enricher answers the profile.* family from a Store.
type Enricher struct {
	store Store

	// Now is the clock, for tests. Nil means time.Now. It is only a fallback: the time a
	// profile is relative to comes from the message, and this is used only when the
	// message carries no date at all.
	Now func() time.Time
}

// New returns an Enricher backed by a store.
func New(store Store) *Enricher { return &Enricher{store: store} }

// Capabilities are what this answers, for registering with an mql.MuxEnricher.
func Capabilities() []enrich.Capability {
	return []enrich.Capability{
		enrich.CapProfileBySender,
		enrich.CapProfileBySenderEmail,
		enrich.CapProfileBySenderDomain,
		enrich.CapProfileByReplyTo,
	}
}

// Enrich implements mql.Enricher.
//
// The profile functions take no arguments in MQL, so the evaluator passes the message
// itself: `profile.by_sender` means the sender of the message being evaluated.
func (e *Enricher) Enrich(ctx context.Context, cap enrich.Capability, args []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	if e == nil || e.store == nil {
		return mql.NullValue, enrich.NotImplemented(cap)
	}
	if len(args) == 0 {
		return mql.NullValue, nil
	}
	msg := args[0]

	key, ok := e.keyFor(cap, msg)
	if !ok {
		// No sender or no reply-to to profile. Null, not an empty profile: the question
		// was not answerable, and a zero-count profile would claim it was.
		return mql.NullValue, nil
	}

	at := messageTime(msg, e.now())
	events, err := e.store.Events(ctx, key, at)
	if err != nil {
		return mql.NullValue, &enrich.Unavailable{
			Capability: cap,
			Reason:     "history unavailable",
			Err:        err,
		}
	}

	return mql.FromGo(build(Summarise(events, at), at)), nil
}

func (e *Enricher) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// keyFor picks which history to read.
//
// profile.by_sender is the general one and keys on the address, falling back to the
// domain when there is no usable address — which is what "keyed by address or domain" in
// the published signature means.
func (e *Enricher) keyFor(cap enrich.Capability, msg mql.Value) (Key, bool) {
	sender := msg.Field("sender").Field("email")
	email := str(sender.Field("email"))
	domain := str(sender.Field("domain").Field("domain"))

	switch cap {
	case enrich.CapProfileBySenderEmail:
		return Key{ByEmail, email}, email != ""
	case enrich.CapProfileBySenderDomain:
		return Key{ByDomain, domain}, domain != ""
	case enrich.CapProfileByReplyTo:
		// The reply-to address is the one a victim would actually answer, which is why
		// it has its own profile: a display-name impersonation keeps the real sender
		// domain and redirects the reply.
		for _, rt := range msg.Field("headers").Field("reply_to").Elements() {
			if v := str(rt.Field("email").Field("email")); v != "" {
				return Key{ByReplyTo, v}, true
			}
		}
		return Key{}, false
	default:
		if email != "" {
			return Key{ByEmail, email}, true
		}
		return Key{ByDomain, domain}, domain != ""
	}
}

// messageTime is the moment a profile is relative to.
//
// Falling back to the clock is safe for live delivery and wrong for a backtest, so a
// message with no parsable date is worth noticing rather than silently profiling against
// the present.
func messageTime(msg mql.Value, fallback time.Time) time.Time {
	for _, path := range [][]string{{"headers", "date"}, {"date"}} {
		v := msg
		for _, p := range path {
			v = v.Field(p)
		}
		if s := str(v); s != "" {
			for _, layout := range []string{time.RFC3339, time.RFC3339Nano, time.RFC1123Z, time.RFC1123} {
				if t, err := time.Parse(layout, s); err == nil {
					return t
				}
			}
		}
	}
	return fallback
}

// build shapes a summary into the published SenderProfile.
func build(s Summary, at time.Time) *mdm.SenderProfile {
	p := &mdm.SenderProfile{
		Prevalence:                 mdm.Ptr(Prevalence(s)),
		Solicited:                  mdm.Ptr(s.Solicited),
		AnyMessagesBenign:          mdm.Ptr(s.AnyBenign),
		AnyMessagesMaliciousOrSpam: mdm.Ptr(s.AnyMalicious),
		AnyFalsePositives:          mdm.Ptr(s.AnyFalsePos),
	}
	if s.Count > 0 {
		p.AuthFailed = mdm.Ptr(s.AllAuthFailed)
		p.DaysKnown = mdm.Ptr(Days(s.FirstContact, at))
		p.DaysSince = &mdm.SenderDaysSince{
			FirstContact: mdm.Ptr(Days(s.FirstContact, at)),
			LastContact:  mdm.Ptr(Days(s.LastContact, at)),
		}
		if !s.LastInbound.IsZero() {
			p.DaysSince.LastInbound = mdm.Ptr(Days(s.LastInbound, at))
		}
		if !s.LastOutbound.IsZero() {
			p.DaysSince.LastOutbound = mdm.Ptr(Days(s.LastOutbound, at))
		}
	}
	return p
}

func str(v mql.Value) string {
	s, ok := v.AsString()
	if !ok {
		return ""
	}
	return s
}

// Record adds a message to an in-memory store, deriving the event from the model.
//
// This is what a pipeline calls after it has a verdict, and what a replay of a mailbox
// calls per message. It lives here rather than in the caller so that every producer of
// history agrees on how a message becomes an event.
func Record(m *Memory, msg *mdm.MessageDataModel, verdict Verdict, at time.Time) error {
	if m == nil || msg == nil {
		return fmt.Errorf("profile: nothing to record")
	}
	e := Event{At: at, Verdict: verdict, Direction: Inbound}

	if s := msg.Sender; s != nil && s.Email != nil {
		e.SenderEmail = mdm.Deref(s.Email.Email)
		if s.Email.Domain != nil {
			e.SenderDomain = s.Email.Domain.Domain
		}
	}
	if h := msg.Headers; h != nil {
		for _, rt := range h.ReplyTo {
			if rt != nil && rt.Email != nil {
				e.ReplyTo = mdm.Deref(rt.Email.Email)
				break
			}
		}
	}
	if t := msg.Type; t != nil {
		switch {
		case mdm.Deref(t.Outbound):
			e.Direction = Outbound
		case mdm.Deref(t.Internal):
			e.Direction = Internal
		}
	}
	if h := msg.Headers; h != nil && h.AuthSummary != nil {
		dmarc := h.AuthSummary.DMARC
		e.AuthFailed = dmarc == nil || !mdm.Deref(dmarc.Pass)
	}
	m.Add(e)
	return nil
}
