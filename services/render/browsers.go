// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"log"
	"runtime"
	"time"

	"go.opentelemetry.io/otel/metric"

	"github.com/lazaretemail/lazaret/telemetry"
)

// A bound on how many browsers run at once.
//
// The engine now admits a fixed number of analyses, but every one of them can ask
// for a screenshot, and a screenshot is a whole browser process — not a goroutine,
// not a connection. Thirty-two concurrent Chromiums on one host do not each take
// 1.4 seconds; they take thirty and then time out, which is what was happening:
// successes averaging 1.4s alongside failures at "timed out after 30s".
//
// So the renderer bounds itself rather than trusting whatever is upstream. A
// caller that waits is fine — the work is queued, not lost. A caller that waits
// too long is told, because a screenshot that arrives after the analysis deadline
// has cost a browser launch and bought nothing.
type browserPool struct {
	slots chan struct{}
	wait  time.Duration

	inUse   metric.Int64UpDownCounter
	waited  metric.Float64Histogram
	refused metric.Int64Counter
}

// ErrBrowsersBusy means the host is already running as many browsers as it should.
var ErrBrowsersBusy = errors.New("render: all browser slots are busy")

// defaultBrowsers is how many Chromiums may run at once.
//
// Half the cores, floor of four. The first attempt was a quarter, and measuring it
// showed why that was wrong: screenshots are one or two browser launches per
// message, but *link analysis* is around thirty-eight, so the pool is not
// protecting an occasional expensive operation — it is the main road. Set too
// tight it stops being a safety valve and becomes the bottleneck, and the 30s
// render timeouts got worse rather than better.
//
// THIS NUMBER IS NOT TUNED. Two bursts of eight concurrent analyses on a
// sixteen-core host gave 15-20s per analysis with twelve 30s render timeouts at a
// limit of four, and 44-47s with no timeouts at eight. Those contradict each
// other and neither is a controlled measurement — the host was also ingesting.
// Pick a value against your own mail with -max-browsers; what is here only
// guarantees the host is not asked to run an unbounded number of browsers.
func defaultBrowsers() int {
	n := runtime.NumCPU() / 4
	if n < 2 {
		n = 2
	}
	if n > 12 {
		n = 12
	}
	return n
}

// What a render costs, what the service costs before any render, and how much of
// the container to aim at. All three measured against real mail rather than
// guessed, by logging a browser's usage at the peak of a burst and again once its
// tabs had finished:
//
//	link browser kept — 2010MB during the burst, 734MB now that its 8 tabs finished
//	link browser kept — 2047MB during the burst, 749MB now that its 8 tabs finished
//
// So the idle floor is about 750MB — the Go process, and both browsers sitting
// there with nothing open — and a tab in flight adds about 160MB on top.
//
// The headroom factor is the part that was wrong first time round. The reserve and
// the per-tab cost were set so that a full complement of tabs came to exactly the
// container's limit, which is not headroom, it is the cliff: an eight-tab burst on
// a 2GiB container peaked at 2047MB of 2048MB and drove the cgroup into reclaim
// 55,092 times. Nothing was OOM-killed, because draining releases in time, but the
// kernel spent the whole run tearing page cache out from under the browsers.
// Target a fraction and the peak has somewhere to go.
const (
	memoryPerTab   = 160 << 20
	memoryReserve  = 768 << 20
	memoryHeadroom = 0.85
)

// tabsThatFit is how many concurrent renders a container of this size can hold
// without running its memory ceiling into the ground. At least one, because
// refusing to render at all is worse than rendering slowly.
func tabsThatFit(limit int64) int {
	budget := int64(float64(limit)*memoryHeadroom) - memoryReserve
	if budget < memoryPerTab {
		return 1
	}
	return int(budget / memoryPerTab)
}

// tabLimit is how many renders may run at once across the reused browsers.
//
// One per core, because a tab is a renderer process and the thing being rationed
// is CPU — not the browser's own fixed cost, which is what reuse removes. Floors
// at four so a small host still overlaps some I/O wait, and caps at thirty-two so
// a very large host does not hand hostile pages that much of the machine at once.
//
// Then capped again by memory, which is the bound that actually bites. A process
// per render gave memory back by exiting; a browser that stays up does not, so on
// a container with a limit the question is not how many renders the CPUs can
// carry but how many the cgroup can hold before the kernel kills all of them at
// once. On this host that is sixteen cores and a 2GiB limit: eight, not sixteen.
func tabLimit(configured int) int {
	if configured > 0 {
		return configured
	}
	n := runtime.NumCPU()
	if n < 4 {
		n = 4
	}
	if n > 32 {
		n = 32
	}
	if limit := memoryLimit(); limit > 0 {
		if byMemory := tabsThatFit(limit); byMemory < n {
			if byMemory < 1 {
				byMemory = 1
			}
			log.Printf("lazaret-render: %d tab(s) at once, not %d — %dMB of memory, "+
				"not %d core(s), is the binding limit here",
				byMemory, n, limit>>20, runtime.NumCPU())
			n = byMemory
		}
	}
	return n
}

func newBrowserPool(limit int, wait time.Duration) *browserPool {
	if limit <= 0 {
		limit = defaultBrowsers()
	}
	if wait <= 0 {
		wait = 45 * time.Second
	}
	m := telemetry.Meter("lazaret/render")
	return &browserPool{
		slots: make(chan struct{}, limit),
		wait:  wait,
		inUse: telemetry.UpDownCounter(m, "lazaret.render.browsers.running",
			metric.WithDescription("Browser processes running right now."),
			metric.WithUnit("{process}")),
		waited: telemetry.Histogram(m, "lazaret.render.browsers.queue_wait",
			metric.WithDescription("Time spent waiting for a browser slot."),
			metric.WithUnit(telemetry.Seconds)),
		refused: telemetry.Counter(m, "lazaret.render.browsers.refused",
			metric.WithDescription("Renders refused because every browser slot stayed busy."),
			metric.WithUnit("{render}")),
	}
}

// Acquire takes a slot. The returned release must be called exactly once.
func (p *browserPool) Acquire(ctx context.Context) (release func(), err error) {
	if p == nil {
		return func() {}, nil
	}
	start := time.Now()

	select {
	case p.slots <- struct{}{}:
		p.inUse.Add(ctx, 1)
		return p.releaser(ctx), nil
	default:
	}

	timer := time.NewTimer(p.wait)
	defer timer.Stop()
	select {
	case p.slots <- struct{}{}:
		p.inUse.Add(ctx, 1)
		p.waited.Record(ctx, time.Since(start).Seconds())
		return p.releaser(ctx), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		p.refused.Add(ctx, 1)
		return nil, ErrBrowsersBusy
	}
}

func (p *browserPool) releaser(ctx context.Context) func() {
	var done bool
	return func() {
		if done {
			return
		}
		done = true
		<-p.slots
		p.inUse.Add(ctx, -1)
	}
}

func (p *browserPool) Limit() int {
	if p == nil {
		return 0
	}
	return cap(p.slots)
}
