// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"runtime"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/lazaretemail/lazaret/telemetry"
)

// Admission control on the analysis path.
//
// Nothing bounded this. One goroutine per mailbox upstream meant a hundred
// mailboxes delivering at once became a hundred concurrent analyses, each fanning
// out to dozens of link fetches — and an engine in that state does not slow down
// gracefully, it thrashes the renderer, exhausts memory and takes the whole
// pipeline with it.
//
// A bound converts overload into queueing, and queueing that goes on too long into
// an honest refusal the connector can back off from. A 503 with Retry-After is a
// far better answer than a request that succeeds in four minutes, because the
// connector will simply try that message again — whereas a timeout halfway through
// analysis has already paid for the enrichment.
type admitter struct {
	slots chan struct{}
	wait  time.Duration

	inFlight metric.Int64UpDownCounter
	waited   metric.Float64Histogram
	refused  metric.Int64Counter
}

// ErrBusy is returned when the engine is at capacity and stayed there.
var ErrBusy = errors.New("the engine is at capacity")

// defaultAnalysisLimit is how many messages may be analysed at once.
//
// One analysis is mostly waiting — on the renderer, on inference, on a registry —
// so this is larger than the core count would suggest, but not unbounded: each one
// also holds a parsed message, a rule set's worth of results and up to a few dozen
// fetched pages, and that memory is what actually runs out.
func defaultAnalysisLimit() int {
	n := runtime.NumCPU() * 2
	if n < 4 {
		n = 4
	}
	if n > 64 {
		n = 64
	}
	return n
}

func newAdmitter(limit int, wait time.Duration) *admitter {
	if limit <= 0 {
		limit = defaultAnalysisLimit()
	}
	if wait <= 0 {
		wait = 30 * time.Second
	}
	m := telemetry.Meter("lazaret/engine")
	return &admitter{
		slots: make(chan struct{}, limit),
		wait:  wait,
		inFlight: telemetry.UpDownCounter(m, "lazaret.analysis.in_flight",
			metric.WithDescription("Analyses running right now."),
			metric.WithUnit("{analysis}")),
		waited: telemetry.Histogram(m, "lazaret.analysis.queue_wait",
			metric.WithDescription("Time spent waiting for an analysis slot."),
			metric.WithUnit(telemetry.Seconds)),
		refused: telemetry.Counter(m, "lazaret.analysis.refused",
			metric.WithDescription("Analyses refused because the engine stayed at capacity."),
			metric.WithUnit("{analysis}")),
	}
}

// Acquire takes a slot, waiting up to the configured time.
//
// The returned release must be called exactly once. A caller that gives up first —
// the client hung up — releases nothing, because it never took a slot.
func (a *admitter) Acquire(ctx context.Context) (release func(), err error) {
	if a == nil {
		return func() {}, nil
	}
	start := time.Now()

	// The common case: a slot is free, and nothing is measured but the counter.
	select {
	case a.slots <- struct{}{}:
		a.inFlight.Add(ctx, 1)
		a.waited.Record(ctx, 0)
		return a.releaser(ctx), nil
	default:
	}

	timer := time.NewTimer(a.wait)
	defer timer.Stop()
	select {
	case a.slots <- struct{}{}:
		a.inFlight.Add(ctx, 1)
		a.waited.Record(ctx, time.Since(start).Seconds())
		return a.releaser(ctx), nil
	case <-ctx.Done():
		// The caller gave up. Not a refusal: nobody was told no.
		return nil, ctx.Err()
	case <-timer.C:
		a.refused.Add(ctx, 1, metric.WithAttributes(attribute.String("lazaret.reason", "queue_timeout")))
		a.waited.Record(ctx, time.Since(start).Seconds())
		return nil, ErrBusy
	}
}

func (a *admitter) releaser(ctx context.Context) func() {
	var once bool
	return func() {
		if once {
			return
		}
		once = true
		<-a.slots
		a.inFlight.Add(ctx, -1)
	}
}

// Limit is how many may run at once, for the start-up log.
func (a *admitter) Limit() int {
	if a == nil {
		return 0
	}
	return cap(a.slots)
}
