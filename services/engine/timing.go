// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"context"
	"github.com/lazaretemail/lazaret/mdm"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mql"
)

// Where the time goes on one message.
//
// Worth having permanently rather than reaching for a profiler each time. An analysis
// that runs out of budget does so because of one or two capabilities, and which ones
// is not guessable: the expensive call is rarely the one that looks expensive. A real
// marketing email spent a minute and a half here, and the answer was not the part
// anyone would have picked.

// CapTiming is what one capability cost on one message.
type CapTiming struct {
	Capability string `json:"capability"`
	Calls      int    `json:"calls"`
	TotalMS    int64  `json:"total_ms"`
	SlowestMS  int64  `json:"slowest_ms"`

	// Slowest describes the argument of the slowest call, truncated. Which text
	// or URL was expensive is the first thing anyone asks and the one thing a
	// capability name cannot tell them.
	SlowestArg string `json:"slowest_arg,omitempty"`

	// Expired counts calls that failed only because the message had already run
	// out of time. These are not a broken service and must not be reported as one:
	// whichever capability the evaluator happened to reach after the deadline gets
	// the blame, which is how a slow link fetch made profile.by_sender_email and
	// network.whois look unavailable on a deployment where both worked perfectly.
	Expired int `json:"expired,omitempty"`
}

// timingEnricher records how long each capability took, and passes everything
// through unchanged.
//
// It wraps the cache rather than the other way round, so a cache hit costs nothing
// and is not counted as a call: the number here is work actually done.
type timingEnricher struct {
	inner mql.Enricher

	mu    sync.Mutex
	calls map[enrich.Capability]*CapTiming
}

func newTimingEnricher(inner mql.Enricher) *timingEnricher {
	return &timingEnricher{inner: inner, calls: map[enrich.Capability]*CapTiming{}}
}

func (t *timingEnricher) Enrich(ctx context.Context, cap enrich.Capability, args []mql.Value, kwargs map[string]mql.Value) (mql.Value, error) {
	start := time.Now()

	// One span per enrichment, which is the right grain: each is a call out to
	// Strelka, the ML service, the renderer or a registry, and between them they
	// are nearly all of an analysis's wall time. The cache wraps this, so a span
	// here is a real call rather than a lookup.
	ctx, span := engineTracer.Start(ctx, "enrich."+string(cap),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrCapability.String(string(cap))))

	v, err := t.inner.Enrich(ctx, cap, args, kwargs)

	elapsed := time.Since(start)
	ms := elapsed.Milliseconds()
	expired := err != nil && ctx.Err() != nil

	res := outcome(err, expired)
	span.SetAttributes(attrOutcome.String(res))
	if err != nil {
		// Recorded, not raised to an error status when it is only a capability this
		// deployment does not have: an unconfigured ML service is a fact about the
		// install, not a fault in this message, and colouring every span red for it
		// makes a trace view useless.
		span.RecordError(err)
		if !errors.Is(err, enrich.ErrUnavailable) && !expired {
			span.SetStatus(codes.Error, err.Error())
		}
	}
	span.End()

	attrs := metric.WithAttributes(attrCapability.String(string(cap)), attrOutcome.String(res))
	metricCapabilityCalls.Add(ctx, 1, attrs)
	metricCapabilityDuration.Record(ctx, elapsed.Seconds(), attrs)

	t.mu.Lock()
	rec := t.calls[cap]
	if rec == nil {
		rec = &CapTiming{Capability: string(cap)}
		t.calls[cap] = rec
	}
	rec.Calls++
	rec.TotalMS += ms
	if expired {
		rec.Expired++
	}
	if ms > rec.SlowestMS {
		rec.SlowestMS = ms
		rec.SlowestArg = argPreview(args)
	}
	t.mu.Unlock()

	return v, err
}

// Spent is the total enrichment time, which is nearly always the whole analysis.
func (t *timingEnricher) Spent() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	var total int64
	for _, r := range t.calls {
		total += r.TotalMS
	}
	return time.Duration(total) * time.Millisecond
}

// Costliest names the capability that used the most time, which on a message that
// ran out of budget is the one that caused it.
func (t *timingEnricher) Costliest() (string, int64) {
	r := t.Report()
	if len(r) == 0 {
		return "", 0
	}
	return r[0].Capability, r[0].TotalMS
}

// Report is the per-capability cost, most expensive first.
func (t *timingEnricher) Report() []CapTiming {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]CapTiming, 0, len(t.calls))
	for _, r := range t.calls {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TotalMS > out[j].TotalMS })
	return out
}

// Visiting a message's links before the rules ask for them.
//
// Rule evaluation is sequential, so nine links meant nine fetches back to back — 78
// seconds of the 95 one real message took, with everything else in the analysis
// waiting behind them and the deadline expiring partway through. Nothing about those
// fetches is ordered: they are independent requests to independent hosts.
//
// So they are started together, before evaluation. What makes the rules' own calls
// cheap afterwards is not this function but the render client's per-URL
// deduplication: a rule asking for a link already fetched joins the finished fetch
// instead of making another. Warming the evaluator's cache directly is not possible
// from here — it keys on the exact argument, and rules pass a link object where this
// has only the URL — and chasing that would make this depend on how each rule
// happens to be written.
//
// Measured on the message that prompted it: 95s to 28s, with no change to the
// verdict. It is the same calls with the same arguments; only the order changes.

// maxPrefetchLinks bounds how many distinct links are visited.
//
// A newsletter with two hundred links would otherwise open two hundred connections
// from the analysis network, which is a burst worth not making — and the rules that
// read link analysis are looking for one bad link, not an inventory. Links past the
// bound are still fetched if a rule actually asks for one; they are simply not
// fetched in advance.
const maxPrefetchLinks = 32

// prefetchConcurrency bounds how many run at once, so that a message cannot saturate
// the renderer for every other message being analysed at the same time.
// Matched to the renderer's CPU allocation, because a fetch is a browser and a
// browser is CPU work, not waiting.
//
// This is the opposite of the usual instinct. Measured against a renderer with two
// cores: one fetch alone took 0.7s, and nine at once took ten seconds each — so the
// concurrent version finished no sooner than doing them one at a time, having spent
// nine times the memory to get there. Above the core count this number buys nothing
// and costs contention; at or below it, the fetches genuinely overlap.
//
// Keep it equal to the renderer's cpus limit in the compose file.
const prefetchConcurrency = 4

// warmLinkAnalysis visits a message's distinct links concurrently.
func (p *Pipeline) warmLinkAnalysis(ctx context.Context, msg *mdm.MessageDataModel, enricher mql.Enricher) {
	if msg.Body == nil || len(msg.Body.Links) == 0 {
		return
	}
	// Only when something can actually answer. Firing these at a deployment with no
	// renderer would spend the whole budget collecting the same error repeatedly.
	if !p.canAnswer(ctx, enrich.CapMLLinkAnalysis) {
		return
	}

	seen := map[string]bool{}
	var targets []string
	for _, l := range msg.Body.Links {
		if l == nil || l.HrefURL == nil || l.HrefURL.URL == "" {
			continue
		}
		u := l.HrefURL.URL
		if seen[u] {
			continue
		}
		seen[u] = true
		targets = append(targets, u)
		if len(targets) >= maxPrefetchLinks {
			break
		}
	}
	if len(targets) < 2 {
		return // nothing to overlap
	}

	sem := make(chan struct{}, prefetchConcurrency)
	var wg sync.WaitGroup
	for _, u := range targets {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// The result is discarded: this runs for its effect on the cache, and
			// an error here is one the rule will see for itself in a moment.
			_, _ = enricher.Enrich(ctx, enrich.CapMLLinkAnalysis, []mql.Value{mql.StringValue(u)}, nil)
		}(u)
	}
	wg.Wait()
}

// canAnswer reports whether a capability is currently working, from the cached probe.
func (p *Pipeline) canAnswer(ctx context.Context, cap enrich.Capability) bool {
	for _, h := range p.CheckCapabilities(ctx, 5*time.Second) {
		if h.Capability == string(cap) {
			return h.OK
		}
	}
	return false
}

// argPreview is a short, safe description of what a call was about.
//
// Truncated hard: these are message contents, and a timing report is not a place to
// reproduce an email. Enough to recognise which call it was, and no more.
func argPreview(args []mql.Value) string {
	if len(args) == 0 {
		return ""
	}
	s, ok := args[0].AsString()
	if !ok {
		if inner := args[0].Field("url"); !inner.IsNull() {
			s, _ = inner.AsString()
		}
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return s
}
