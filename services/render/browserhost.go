// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// A browser kept running, with a tab per job.
//
// Every render used to be a whole process: launch Chromium, build a profile, load
// one page, exit. Measured at roughly six hundred milliseconds of pure startup
// before any page work — and link analysis asks for about thirty-eight renders per
// message, so that is some twenty-three seconds per message spent creating and
// destroying processes. Reusing one browser removes essentially all of it.
//
// Two properties the process-per-render design gave away for free, and which this
// has to put back deliberately:
//
//   - Isolation. A fresh process meant a fresh profile, so one hostile page could
//     not leave a cookie, a service worker or a localStorage entry for the next.
//     Here every job gets its own *browser context* — Chromium's own boundary,
//     the same one incognito uses — created and discarded per job. It is cheap
//     because it is not a process.
//   - Blast radius. A browser that wedges or crashes used to take one render with
//     it. Now it would take every job in flight, so a dead browser is noticed and
//     replaced rather than retried against.
//
// What it cannot do is vary the command line per job, and one job needs a
// different command line: a message screenshot runs with the resolver disabled so
// that a tracking pixel in a message cannot fire. That is a structural guarantee —
// enforced by the browser rather than by our interception code — and worth
// keeping, so there are two hosts rather than one shared browser with request
// filtering bolted on. See newBrowserHosts.
type browserHost struct {
	name  string
	flags []chromedp.ExecAllocatorOption

	// allocator is the running browser's allocator, kept so shutdown can wait for
	// the process to exit rather than only signalling it.
	allocator *chromedp.ExecAllocator
	tabs      chan struct{}

	mu          sync.Mutex
	allocStop   context.CancelFunc
	browserStop context.CancelFunc
	browser     context.Context
	browserOK   bool
	generation  uint64
	fails       int
	jobs        int
	retiring    bool

	// Indirected so a test can pose as a container of a given size. Fields
	// rather than package variables: retirement runs on its own goroutine, and
	// a test swapping a global out from under it is a data race.
	memLimit func() int64
	memUsed  func() int64
}

// How long a browser gets to come up, and how many jobs may fail against one
// before we stop believing in it. A page that fails is ordinary — hostile sites
// time out all day — so a single failure says nothing about the browser. A run
// of them says the browser is wedged.
const (
	browserStartTimeout = 30 * time.Second
	browserFailStreak   = 5

	// How often to ask the kernel what the container is using. Cheap — two small
	// reads — but not free, and memory does not move fast enough to need it per
	// job.
	memoryCheckEvery = 25

	// The share of the container's memory limit at which a browser is looked at.
	// Well under the limit, because the check is periodic and because the tabs
	// running when it trips still have to finish.
	memoryHighWater = 0.70

	// And the share it must still be over once every tab has finished, to be
	// replaced rather than left alone. Draining is most of the remedy: the first
	// recycle in production tripped at over 1.4GB and, by the time the last tab
	// finished, the browser was holding 559MB. That was a busy minute, not a
	// browser that had grown — and throwing it away would have cost a second of
	// everybody's time to free nothing.
	memoryIdleHighWater = 0.50

	// The backstop when there is no memory limit to read, as on a plain host. A
	// recycle costs about a second, so this is roughly one percent of the time at
	// the throughput this service sustains.
	jobsPerBrowser = 2000
)

// ErrBrowserUnavailable means the host could not give out a tab.
var ErrBrowserUnavailable = errors.New("render: no browser available")

func newBrowserHost(name string, maxTabs int, flags []chromedp.ExecAllocatorOption) *browserHost {
	if maxTabs < 1 {
		maxTabs = 1
	}
	return &browserHost{
		name: name, flags: flags, tabs: make(chan struct{}, maxTabs),
		memLimit: memoryLimit, memUsed: memoryUsed,
	}
}

// ensure starts the browser if it is not running, and returns the generation the
// caller is working against so a crash can be attributed to the right instance.
func (h *browserHost) ensure(ctx context.Context) (context.Context, uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.browserOK && h.browser.Err() == nil {
		return h.browser, h.generation, nil
	}
	h.stopLocked()

	allocCtx, allocStop := chromedp.NewExecAllocator(context.Background(), h.flags...)
	browserCtx, browserStop := chromedp.NewContext(allocCtx)

	// Kept so shutdown can wait for the process rather than only ask it to go.
	var allocator *chromedp.ExecAllocator
	if c := chromedp.FromContext(allocCtx); c != nil {
		allocator, _ = c.Allocator.(*chromedp.ExecAllocator)
	}

	// Force the browser to actually start now rather than on first use, so a
	// failure to launch is reported here instead of inside somebody's render.
	//
	// Deliberately not context.WithTimeout(browserCtx, ...). chromedp launches the
	// process on whichever context first runs against it and ties the process's
	// lifetime to that context — so a timeout wrapper cancelled on the way out of
	// this function kills the browser it just started, and every later tab fails
	// with "context canceled" against a browser that is already gone. The deadline
	// has to live outside the context the browser is allocated on.
	started := make(chan error, 1)
	go func() { started <- chromedp.Run(browserCtx) }()
	var err error
	select {
	case err = <-started:
	case <-time.After(browserStartTimeout):
		err = fmt.Errorf("it did not come up within %s", browserStartTimeout)
	}
	if err != nil {
		browserStop()
		allocStop()
		return nil, 0, fmt.Errorf("render: starting the %s browser: %w", h.name, err)
	}

	h.allocStop, h.browserStop, h.browser, h.browserOK = allocStop, browserStop, browserCtx, true
	h.allocator = allocator
	h.generation++
	h.fails, h.jobs, h.retiring = 0, 0, false
	log.Printf("lazaret-render: %s browser started (generation %d, up to %d tabs)",
		h.name, h.generation, cap(h.tabs))
	return h.browser, h.generation, nil
}

// stopLocked shuts the browser down and waits for the process to be gone.
//
// The wait is the part that was missing, and it was not only a test annoyance.
// Cancelling the allocator asks Chromium to exit; it does not wait for it. So whoever
// deletes the profile directory afterwards — t.TempDir in the tests, browserHosts.Close
// in the service — raced a process that was still writing to it, and both reported the
// same thing: "directory not empty". The service leaked a profile directory per browser
// per run because of it.
//
// Bounded, because a browser that will not die must not hold shutdown open forever. The
// directory removal that follows may then still fail, which is the situation it was
// already in.
func (h *browserHost) stopLocked() {
	if h.browserStop != nil {
		h.browserStop()
	}
	if h.allocStop != nil {
		h.allocStop()
	}
	if h.allocator != nil {
		done := make(chan struct{})
		go func() { defer close(done); h.allocator.Wait() }()
		select {
		case <-done:
		case <-time.After(browserExitTimeout):
			log.Printf("lazaret-render: the %s browser has not exited after %s; "+
				"its profile directory may be left behind", h.name, browserExitTimeout)
		}
	}
	h.allocStop, h.browserStop, h.browser, h.browserOK, h.allocator = nil, nil, nil, false, nil
	h.fails, h.jobs, h.retiring = 0, 0, false
}

// browserExitTimeout bounds how long shutdown waits for a browser to actually go.
const browserExitTimeout = 10 * time.Second

// succeeded records that a browser is still doing useful work, and decides
// whether it has done enough of it to be worth replacing.
func (h *browserHost) succeeded(generation uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.generation != generation {
		return
	}
	h.fails = 0
	h.jobs++
	if h.retiring || !h.worthRetiringLocked() {
		return
	}
	h.retiring = true
	go h.retire(generation, h.memUsed())
}

// worthRetiringLocked reports whether this browser has grown enough to replace.
func (h *browserHost) worthRetiringLocked() bool {
	if limit := h.memLimit(); limit > 0 {
		if h.jobs%memoryCheckEvery != 0 {
			return false
		}
		return float64(h.memUsed()) > float64(limit)*memoryHighWater
	}
	return h.jobs >= jobsPerBrowser
}

// retire replaces a browser that has grown too large, without interrupting work.
//
// It takes every tab slot before touching anything. Holding all of them is the
// proof that no job is in flight — the same channel Do queues on, used as a
// drain — so a recycle never kills a render that is halfway through a page. New
// jobs block on the slots for the second or so this takes, which is the price and
// is much cheaper than being OOM-killed with sixteen renders in progress.
func (h *browserHost) retire(generation uint64, wasUsing int64) {
	for i := 0; i < cap(h.tabs); i++ {
		h.tabs <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(h.tabs); i++ {
			<-h.tabs
		}
	}()

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.generation != generation || !h.browserOK {
		return
	}

	// Nothing is in flight now, so what is still held is the browser's own
	// baseline rather than the work it was doing. That is the number worth acting
	// on, and it is usually far smaller than the one that raised the alarm.
	limit, idle := h.memLimit(), h.memUsed()
	if limit > 0 && float64(idle) <= float64(limit)*memoryIdleHighWater {
		log.Printf("lazaret-render: %s browser kept — %dMB during the burst, %dMB now "+
			"that its %d tab(s) have finished", h.name, wasUsing>>20, idle>>20, cap(h.tabs))
		h.retiring = false
		return
	}
	log.Printf("lazaret-render: recycling the %s browser after %d job(s) — still %dMB of %dMB "+
		"with nothing in flight", h.name, h.jobs, idle>>20, limit>>20)
	h.stopLocked()
}

// failed records a job that did not finish, and tears the browser down once
// enough of them have failed in a row to mean the browser rather than the pages.
// A browser whose context is already done is replaced immediately.
func (h *browserHost) failed(generation uint64, gone bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.generation != generation || !h.browserOK {
		return
	}
	h.fails++
	if !gone && h.fails < browserFailStreak {
		return
	}
	log.Printf("lazaret-render: %s browser is not answering (%d job(s) in a row); replacing it",
		h.name, h.fails)
	h.stopLocked()
}

// Close shuts the browser down.
func (h *browserHost) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopLocked()
}

// Do runs actions in a fresh tab, in its own browser context.
//
// The tab and its context are discarded afterwards, so nothing a page stored
// reaches the next job. Waiting for a tab is bounded: a caller that queues behind
// a browser for longer than its own deadline has already lost.
func (h *browserHost) Do(ctx context.Context, timeout time.Duration, actions ...chromedp.Action) error {
	select {
	case h.tabs <- struct{}{}:
		defer func() { <-h.tabs }()
	case <-ctx.Done():
		return ctx.Err()
	}

	browser, generation, err := h.ensure(ctx)
	if err != nil {
		return err
	}

	// A new browser context per job: Chromium's own isolation boundary, the same
	// one incognito uses. Cookies, storage and service workers from one hostile
	// page cannot be seen by the next.
	tabCtx, closeTab, err := h.newIsolatedTab(browser)
	if err != nil {
		h.failed(generation, browser.Err() != nil)
		return err
	}
	defer closeTab()

	runCtx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	if err := chromedp.Run(runCtx, actions...); err != nil {
		// A browser that has gone away fails every job until it is replaced, so
		// tell the host rather than just this caller. One failure is not evidence
		// of that — most of what this service opens is hostile and half of it is
		// broken — so the host decides, from the streak.
		h.failed(generation, browser.Err() != nil)
		return err
	}
	h.succeeded(generation)
	return nil
}

// newIsolatedTab opens a tab in a browser context of its own.
//
// chromedp.WithNewBrowserContext() would be the obvious way to write this, and it
// does not work here. It issues Target.createTarget with a browser context id but
// without newWindow, and headless Chromium answers "Failed to open new tab - no
// browser is open (-32000)": the new context owns no window, and createTarget
// will not make one unless asked. Every job failed that way, silently fell back
// to launching a process, and the reuse this whole file exists for never once
// happened. Proven by probe: identical calls differing only in newWindow, one
// erroring and one not, against Chromium 153.
//
// So the two calls chromedp would have made are made here, with the third
// argument it omits. disposeOnDetach is belt and braces — the context is also
// disposed explicitly — and covers the case where this process dies holding one.
func (h *browserHost) newIsolatedTab(browser context.Context) (context.Context, func(), error) {
	exec := cdp.WithExecutor(browser, chromedp.FromContext(browser).Browser)

	browserContext, err := target.CreateBrowserContext().WithDisposeOnDetach(true).Do(exec)
	if err != nil {
		return nil, nil, fmt.Errorf("render: %s browser: new context: %w", h.name, err)
	}
	dispose := func() {
		if err := target.DisposeBrowserContext(browserContext).Do(exec); err != nil {
			log.Printf("lazaret-render: discarding a %s browser context: %v", h.name, err)
		}
	}

	tab, err := target.CreateTarget("about:blank").
		WithBrowserContextID(browserContext).
		WithNewWindow(true).
		Do(exec)
	if err != nil {
		dispose()
		return nil, nil, fmt.Errorf("render: %s browser: new tab: %w", h.name, err)
	}

	tabCtx, cancelTab := chromedp.NewContext(browser, chromedp.WithTargetID(tab))
	return tabCtx, func() { cancelTab(); dispose() }, nil
}

// Tabs is the concurrency this host allows, for the start-up log.
func (h *browserHost) Tabs() int { return cap(h.tabs) }

// baseFlags are what every browser this service starts is given.
//
// dir is this host's own directory: it gets a profile and a crash-dump database
// under it, and nothing else writes there.
func baseFlags(dir string) []chromedp.ExecAllocatorOption {
	return []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoSandbox, // the container is the sandbox; see the Dockerfile
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("safebrowsing-disable-auto-update", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("mute-audio", true),
		chromedp.UserDataDir(filepath.Join(dir, "profile")),

		// Not optional, and not cosmetic. Chromium starts chrome_crashpad_handler
		// as a child and passes it --database built from this; with no value the
		// handler exits with "--database is required", the socket it was given is
		// reset, and the browser never gets as far as printing its DevTools URL.
		// chromedp then reports only "chrome failed to start", which is how this
		// cost an afternoon. The one-shot path in render.go always passed it — the
		// flag did not survive being rewritten as allocator options.
		chromedp.Flag("crash-dumps-dir", filepath.Join(dir, "crash")),

		// Same reason: the handler resolves its own paths against HOME, and the
		// service's HOME is not somewhere Chromium should be writing. Give each
		// host its own and nothing leaks between them.
		chromedp.Env("HOME=" + dir),
	}
}

// screenshotOf captures the viewport at a fixed size and pixel density.
//
// The scale is passed rather than hardcoded because this override silently wins over
// --force-device-scale-factor on the command line: setting the flag and leaving a 1
// here renders at 1x anyway, which is a configuration that looks applied and is not.
func screenshotOf(buf *[]byte, w, h int64, scale int) chromedp.Tasks {
	if scale < 1 {
		scale = 1
	}
	return chromedp.Tasks{
		emulation.SetDeviceMetricsOverride(w, h, float64(scale), false),
		chromedp.ActionFunc(func(ctx context.Context) error {
			data, err := page.CaptureScreenshot().WithFormat(page.CaptureScreenshotFormatPng).Do(ctx)
			if err != nil {
				return err
			}
			*buf = data
			return nil
		}),
	}
}

// setContent loads HTML into the tab without a navigation.
//
// Not a file:// URL and not a data: URL. A file would have to be written and
// cleaned up per render, and a data URL is length-limited in ways a large message
// body will eventually find. This hands the markup straight to the renderer.
func setContent(html string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		tree, err := page.GetFrameTree().Do(ctx)
		if err != nil {
			return err
		}
		return page.SetDocumentContent(tree.Frame.ID, html).Do(ctx)
	})
}

// pageFault reports whether a failure was the page's rather than the browser's,
// and so will happen again identically if it is retried in a second process.
//
// Worth separating from every other failure because the fallback is a whole extra
// browser loading the same URL. Two kinds qualify:
//
//   - The browser got a definitive answer and the answer was no — an error status,
//     a refused connection, a failed handshake. Seen in production against x.com,
//     which answers an error status to anything that looks automated: every link
//     to it cost two renders to learn the same fact once.
//   - It ran out of time. This is the expensive one. The tab already spent the
//     full render timeout, and re-running a page that is slow or deliberately
//     stalling spends it again, so a fallback doubles the cost of the slowest
//     pages there are.
//
// The risk in the second case is a wedged browser, where a process would have
// worked. That is not left to chance: a browser failing job after job is replaced
// by the streak in failed(), so it costs a handful of renders rather than a
// standing double charge on every slow page.
func pageFault(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "net::ERR_")
}
