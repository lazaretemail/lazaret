// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"context"
	"errors"

	"github.com/lazaretemail/lazaret/enrich"
)

// MuxEnricher routes each capability to the provider that implements it.
//
// Capabilities are answered by different things — a WHOIS client, a Strelka deployment, a
// model service — and a deployment will usually have some of them and not others. Rather
// than one object implementing everything, providers register for what they can do and
// this passes the rest along.
//
// A capability nobody claims reports unavailable, which is the same answer as having no
// enricher at all: the rule keeps running and its verdict becomes indeterminate.
type MuxEnricher struct {
	providers map[enrich.Capability]Enricher
	fallback  Enricher
}

// NewMux returns an empty multiplexer.
func NewMux() *MuxEnricher {
	return &MuxEnricher{providers: map[enrich.Capability]Enricher{}}
}

// Handle registers a provider for one or more capabilities. Later registrations for the
// same capability replace earlier ones.
func (m *MuxEnricher) Handle(e Enricher, caps ...enrich.Capability) *MuxEnricher {
	for _, c := range caps {
		m.providers[c] = e
	}
	return m
}

// Fallback registers a provider consulted for anything unclaimed. Without one, an
// unclaimed capability is reported unavailable.
func (m *MuxEnricher) Fallback(e Enricher) *MuxEnricher {
	m.fallback = e
	return m
}

// Capabilities lists what this multiplexer can answer.
func (m *MuxEnricher) Capabilities() []enrich.Capability {
	out := make([]enrich.Capability, 0, len(m.providers))
	for c := range m.providers {
		out = append(out, c)
	}
	sortCapabilities(out)
	return out
}

// Enrich implements Enricher.
func (m *MuxEnricher) Enrich(ctx context.Context, cap enrich.Capability, args []Value, kwargs map[string]Value) (Value, error) {
	provider, ok := m.providers[cap]
	if !ok {
		provider = m.fallback
	}
	if provider == nil {
		return NullValue, enrich.NotImplemented(cap)
	}
	return provider.Enrich(ctx, cap, args, kwargs)
}

// EnricherFunc adapts a function to the Enricher interface, for tests and for providers
// small enough not to need a type.
type EnricherFunc func(context.Context, enrich.Capability, []Value, map[string]Value) (Value, error)

func (f EnricherFunc) Enrich(ctx context.Context, cap enrich.Capability, args []Value, kwargs map[string]Value) (Value, error) {
	return f(ctx, cap, args, kwargs)
}

// UnavailableEnricher reports every capability as unavailable. It is what a deployment
// with no enrichment services configured should use, and it is explicit about that rather
// than leaving the field nil.
var UnavailableEnricher Enricher = EnricherFunc(
	func(_ context.Context, cap enrich.Capability, _ []Value, _ map[string]Value) (Value, error) {
		return NullValue, enrich.NotImplemented(cap)
	})

// IsUnavailable reports whether an error means a capability could not be provided, as
// opposed to an enricher failing at something it does support.
func IsUnavailable(err error) bool { return errors.Is(err, enrich.ErrUnavailable) }

func sortCapabilities(caps []enrich.Capability) {
	for i := 1; i < len(caps); i++ {
		for j := i; j > 0 && caps[j] < caps[j-1]; j-- {
			caps[j], caps[j-1] = caps[j-1], caps[j]
		}
	}
}
