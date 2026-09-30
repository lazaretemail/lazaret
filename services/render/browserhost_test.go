// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func TestPageFault(t *testing.T) {
	// The point of the distinction is cost: a refusal re-run in a second browser
	// process gets refused again, half a second later.
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("page load error net::ERR_HTTP_RESPONSE_CODE_FAILURE"), true},
		{errors.New("page load error net::ERR_NAME_NOT_RESOLVED"), true},
		{fmt.Errorf("wrapped: %w", errors.New("net::ERR_CONNECTION_REFUSED")), true},
		{context.DeadlineExceeded, true},
		{fmt.Errorf("render: %w", context.DeadlineExceeded), true},
		{context.Canceled, false},
		{errors.New("Failed to open new tab - no browser is open (-32000)"), false},
		{errors.New("render: starting the link browser: chrome failed to start"), false},
	} {
		if got := pageFault(tc.err); got != tc.want {
			t.Errorf("pageFault(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestTabLimit(t *testing.T) {
	if got := tabLimit(7); got != 7 {
		t.Errorf("an explicit limit should be honoured: got %d", got)
	}
	got := tabLimit(0)
	if got < 1 || got > 32 {
		t.Errorf("tabLimit(0) = %d, outside the 1..32 range", got)
	}

	limit := memoryLimit()
	if limit == 0 {
		// No cgroup limit: cores are the only bound.
		if n := runtime.NumCPU(); n >= 4 && n <= 32 && got != n {
			t.Errorf("tabLimit(0) = %d, want one per core (%d)", got, n)
		}
		// The bug this guards: tabs were bounded by the browser-process limit,
		// which is a quarter of the cores, so reuse could not use the machine.
		if got <= defaultBrowsers() && runtime.NumCPU() >= 8 {
			t.Errorf("tab limit %d is no larger than the browser-process limit %d",
				got, defaultBrowsers())
		}
		return
	}

	// With a limit, the answer must fit inside it with room to spare. Getting
	// this wrong does not make the service slow, it puts the cgroup into
	// permanent reclaim and eventually kills every render at once.
	if want := int64(got)*memoryPerTab + memoryReserve; want > limit && got > 1 {
		t.Errorf("%d tabs want %dMB but the container has %dMB",
			got, want>>20, limit>>20)
	}
}

// Straight arithmetic, so it holds on a machine with no cgroup at all.
func TestTabsThatFitLeaveHeadroom(t *testing.T) {
	var limit int64 = 2 << 30 // the container this was measured against

	got := tabsThatFit(limit)
	if got != 6 {
		t.Errorf("a 2GiB container should allow 6 tabs, not %d; memoryPerTab, "+
			"memoryReserve or memoryHeadroom moved without a measurement moving", got)
	}

	// The property that matters more than the number: a full complement of tabs
	// must not come to the whole container. The first version of this sized them
	// so that it did — 8 tabs at 192MB over a 512MB reserve is exactly 2048MB —
	// and an eight-tab burst duly peaked at 2047MB and drove the cgroup into
	// reclaim 55,092 times.
	peak := int64(got)*memoryPerTab + memoryReserve
	if peak > int64(float64(limit)*0.90) {
		t.Errorf("%d tabs peak at %dMB of a %dMB container, which is no headroom",
			got, peak>>20, limit>>20)
	}

	// Small containers still get to render.
	for _, small := range []int64{256 << 20, 512 << 20, 1 << 30} {
		if n := tabsThatFit(small); n < 1 {
			t.Errorf("a %dMB container was allowed %d tabs", small>>20, n)
		}
	}
}

// fakeRunning makes a host look like it has a live browser, without one.
func fakeRunning(t *testing.T) *browserHost {
	t.Helper()
	h := newBrowserHost("test", 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.browser, h.browserOK, h.generation = ctx, true, 1
	h.browserStop, h.allocStop = func() {}, func() {}
	return h
}

func TestFailedReplacesOnlyAfterAStreak(t *testing.T) {
	h := fakeRunning(t)
	// Most of what this service opens is hostile and half of it is broken, so a
	// failure is about the page, not the browser. Tearing the browser down on one
	// of them throws away every other job in flight.
	for i := 1; i < browserFailStreak; i++ {
		h.failed(1, false)
		if !h.browserOK {
			t.Fatalf("browser torn down after %d failure(s); the streak is %d",
				i, browserFailStreak)
		}
	}
	h.failed(1, false)
	if h.browserOK {
		t.Fatalf("browser survived %d failures in a row", browserFailStreak)
	}
}

func TestSuccessBreaksTheStreak(t *testing.T) {
	h := fakeRunning(t)
	for i := 0; i < browserFailStreak*3; i++ {
		h.failed(1, false)
		h.succeeded(1)
	}
	if !h.browserOK {
		t.Fatal("a browser that keeps succeeding was replaced")
	}
}

func TestFailedReplacesAtOnceWhenTheBrowserIsGone(t *testing.T) {
	h := fakeRunning(t)
	h.failed(1, true)
	if h.browserOK {
		t.Fatal("a browser whose context is done should be replaced immediately")
	}
}

func TestFailedIgnoresAStaleGeneration(t *testing.T) {
	h := fakeRunning(t)
	h.generation = 9
	// Jobs that were in flight against the browser we already replaced must not
	// take the replacement down with them.
	for i := 0; i < browserFailStreak*2; i++ {
		h.failed(1, true)
	}
	if !h.browserOK {
		t.Fatal("failures from an old generation replaced the current browser")
	}
}

// --- tests that need a real browser ---

func needBrowser(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"chromium", "chromium-browser", "chrome-headless-shell", "headless_shell"} {
		if _, err := exec.LookPath(bin); err == nil {
			return
		}
	}
	t.Skip("no chromium on PATH")
}

func testHost(t *testing.T, extra ...chromedp.ExecAllocatorOption) *browserHost {
	t.Helper()
	needBrowser(t)
	h := newBrowserHost("test", 4, append(baseFlags(t.TempDir()), extra...))
	t.Cleanup(h.Close)
	return h
}

// One browser, many jobs — which is the entire point of the file.
//
// It also pins the bug that made reuse a no-op for its first day: chromedp's
// WithNewBrowserContext creates the target without newWindow, and headless
// Chromium answers "Failed to open new tab - no browser is open (-32000)". Every
// Do failed, every render quietly fell back to its own process, and the timings
// looked fine because the URL cache was absorbing the difference. Without
// newIsolatedTab's newWindow(true) this test fails on the first job.
func TestBrowserHostRunsManyJobsInOneBrowser(t *testing.T) {
	h := testHost(t)
	ctx := context.Background()

	var gen0 uint64
	for i := 0; i < 5; i++ {
		var got string
		err := h.Do(ctx, 30*time.Second,
			setContent(fmt.Sprintf("<html><body><p id=x>job %d</p></body></html>", i)),
			chromedp.Text("#x", &got, chromedp.ByID))
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
		if want := fmt.Sprintf("job %d", i); got != want {
			t.Errorf("job %d rendered %q, want %q", i, got, want)
		}

		h.mu.Lock()
		gen := h.generation
		h.mu.Unlock()
		if i == 0 {
			gen0 = gen
			continue
		}
		if gen != gen0 {
			t.Fatalf("job %d ran against browser generation %d, not %d: "+
				"the browser is being relaunched per job, so nothing is reused",
				i, gen, gen0)
		}
	}
}

// A hostile page must not leave anything behind for the next one.
//
// This is what a fresh process used to give for free and what a browser context
// has to give back deliberately.
func TestBrowserHostTabsAreIsolated(t *testing.T) {
	h := testHost(t)

	// The server reports what the *browser* sent, which is the only honest way to
	// ask this. Reading document.cookie after a response that sets one tells you
	// nothing — it shows the cookie from that very response.
	var sentCookie atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("seen"); err == nil {
			sentCookie.Store(true)
		}
		fmt.Fprint(w, `<html><body><p id=x>ok</p></body></html>`)
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()

	// First job: leave a cookie and a localStorage entry behind.
	var set string
	if err := h.Do(ctx, 30*time.Second,
		chromedp.Navigate(srv.URL),
		chromedp.Evaluate(`document.cookie="seen=yes;path=/"; localStorage.setItem("k","v"); String(document.cookie)`, &set),
	); err != nil {
		t.Fatalf("first job: %v", err)
	}
	if set == "" {
		t.Fatal("the first job could not set a cookie at all, so this proves nothing")
	}

	// Second job: neither may reach it.
	var storage, cookie string
	if err := h.Do(ctx, 30*time.Second,
		chromedp.Navigate(srv.URL),
		chromedp.Evaluate(`String(localStorage.getItem("k"))`, &storage),
		chromedp.Evaluate(`String(document.cookie)`, &cookie),
	); err != nil {
		t.Fatalf("second job: %v", err)
	}
	if storage != "null" {
		t.Errorf("localStorage leaked between jobs: got %q", storage)
	}
	if cookie != "" {
		t.Errorf("a cookie leaked between jobs: got %q", cookie)
	}
	if sentCookie.Load() {
		t.Error("the second job sent the first job's cookie to the server")
	}
}

// The tracking-pixel guarantee has to survive being moved into a shared browser.
//
// offline_test.go proves it for the process-per-render path. This proves it for
// the reused document host, by hostname and by IP literal — because the resolver
// rule is the whole mechanism and "does MAP * cover an address that needs no
// resolving?" is exactly the question an attacker would ask.
func TestDocumentHostLoadsNothingRemote(t *testing.T) {
	needBrowser(t)
	hosts, err := newBrowserHosts(2, false, testIdentity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hosts.Close)

	var hit atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		w.Header().Set("Content-Type", "image/gif")
		w.Write([]byte("GIF89a"))
	}))
	t.Cleanup(srv.Close)

	for _, target := range []string{srv.URL + "/pixel.gif", "http://localhost:" + portOf(t, srv.URL) + "/pixel.gif"} {
		var status string
		err := hosts.docs.Do(context.Background(), 30*time.Second,
			setContent(`<html><body><img id=p src="`+target+`"></body></html>`),
			chromedp.Sleep(500*time.Millisecond),
			// naturalWidth is 0 for an image that never loaded.
			chromedp.Evaluate(`String(document.getElementById("p").naturalWidth)`, &status),
		)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if status != "0" {
			t.Errorf("%s: the image loaded (naturalWidth %s)", target, status)
		}
	}
	if n := hit.Load(); n != 0 {
		t.Errorf("the document browser made %d request(s) to the pixel server; "+
			"a tracking pixel in a real message would have fired", n)
	}
}

func portOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u.Port()
}

// poseAsContainer makes a host's memory readings say what a test needs them to.
func poseAsContainer(h *browserHost, limit, used int64) *browserHost {
	h.memLimit = func() int64 { return limit }
	h.memUsed = func() int64 { return used }
	return h
}

// waitUntilRunning waits for the retirement goroutine to reach a verdict.
func waitUntilRunning(t *testing.T, h *browserHost, want bool, why string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		running := h.browserOK
		h.mu.Unlock()
		if running == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (browserOK still %v)", why, running)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A browser that has grown near the container's limit is replaced.
//
// The failure this prevents is not slowness. A 2GiB container whose browser keeps
// growing is OOM-killed with every render in flight, and a process per render
// never had the problem because a process that exits gives its memory back.
func TestRetiresWhenMemoryIsHigh(t *testing.T) {
	h := poseAsContainer(fakeRunning(t), 2<<30, 1800<<20)
	for i := 0; i < memoryCheckEvery; i++ {
		h.succeeded(1)
	}
	waitUntilRunning(t, h, false, "a browser at 1.8GB of a 2GB limit was not recycled")
}

func TestDoesNotRetireWhenThereIsRoom(t *testing.T) {
	h := poseAsContainer(fakeRunning(t), 2<<30, 300<<20)
	for i := 0; i < memoryCheckEvery*20; i++ {
		h.succeeded(1)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.browserOK {
		t.Fatal("a browser well inside the limit was recycled anyway")
	}
}

// With no limit to read — a plain host rather than a container — the job count is
// the only thing left to go on.
func TestRetiresOnJobCountWithoutALimit(t *testing.T) {
	h := poseAsContainer(fakeRunning(t), 0, 0)
	for i := 0; i < jobsPerBrowser-1; i++ {
		h.succeeded(1)
	}
	h.mu.Lock()
	early := h.browserOK
	h.mu.Unlock()
	if !early {
		t.Fatalf("recycled before %d jobs", jobsPerBrowser)
	}
	h.succeeded(1)
	waitUntilRunning(t, h, false, "not recycled after the job-count backstop")
}

// Retirement must not interrupt work, and the way it proves that is by holding
// every tab slot before it touches the browser.
func TestRetireWaitsForJobsInFlight(t *testing.T) {
	h := poseAsContainer(newBrowserHost("test", 2, nil), 2<<30, 1900<<20)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.browser, h.browserOK, h.generation = ctx, true, 1
	h.browserStop, h.allocStop = func() {}, func() {}

	// Pose as a job that is halfway through a page.
	h.tabs <- struct{}{}

	for i := 0; i < memoryCheckEvery; i++ {
		h.succeeded(1)
	}
	time.Sleep(200 * time.Millisecond)
	h.mu.Lock()
	stillUp := h.browserOK
	h.mu.Unlock()
	if !stillUp {
		t.Fatal("the browser was torn down with a job still in flight")
	}

	<-h.tabs // the job finishes
	waitUntilRunning(t, h, false, "the browser was not recycled once the last job finished")
}

// A browser that was only busy, not bloated, is left alone.
//
// The first recycle in production tripped at over 1.4GB and the browser was
// holding 559MB by the time its tabs had finished: draining was the whole remedy,
// and replacing it as well would have cost a second to free nothing.
func TestBurstDrainsRatherThanRecycles(t *testing.T) {
	h := fakeRunning(t)
	h.memLimit = func() int64 { return 2 << 30 }

	// High while the burst is on, low once retire() has drained the tabs. The
	// switch is the drain: retire reads memory only after holding every slot.
	var drained atomic.Bool
	h.memUsed = func() int64 {
		if drained.Load() {
			return 559 << 20
		}
		return 1800 << 20
	}

	// A job in flight, so retire() genuinely has to wait for the drain — which is
	// also what makes the switch between the two readings deterministic.
	h.tabs <- struct{}{}
	for i := 0; i < memoryCheckEvery; i++ {
		h.succeeded(1)
	}
	drained.Store(true)
	<-h.tabs // the job finishes; retire() may now proceed

	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		running, retiring := h.browserOK, h.retiring
		h.mu.Unlock()
		if !running {
			t.Fatal("a browser that was merely busy was thrown away")
		}
		if !retiring {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the host stayed in retiring state, so it will never look again")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
