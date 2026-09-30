// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"github.com/chromedp/chromedp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"log"

	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Rendering, by driving Chromium's own headless mode.
//
// No browser-automation library. Chromium's `--headless --screenshot` does exactly what
// is needed for an email — a static document, rendered once, captured — and shelling out
// to it keeps this service's dependency list at zero beyond the standard library. A
// DevTools client would buy scrolling, network interception and script evaluation, none
// of which this needs, in exchange for a large dependency and a long-lived connection to
// a process that is deliberately treated as compromised.
//
// Every render is a fresh process with a fresh profile directory, which is deleted
// afterwards. That is the isolation that matters: a page that escapes its renderer gets
// a container with no egress and nothing of the previous message.

// Renderer turns HTML into a PNG.
type Renderer struct {
	// Binary is the Chromium executable. Empty means the first of the usual names found
	// on PATH.
	Binary string

	// Browsers bounds how many run at once. Nil means unbounded, which is only
	// appropriate for a test.
	Browsers *browserPool

	// Hosts are long-lived browsers. When set, renders run in a tab rather than
	// in a new process. Nil falls back to a process per render, which is what
	// this service did before and remains the behaviour under test.
	Hosts *browserHosts

	// Timeout bounds one render. Attacker-supplied HTML can be written to take
	// arbitrarily long to lay out.
	Timeout time.Duration

	// Width and Height are the viewport. Email is authored for a narrow column, so the
	// default is a tall portrait window rather than a desktop one.
	Width, Height int

	// Scale is the device pixel ratio. 1 by default; 2 renders every glyph at twice
	// the linear resolution.
	//
	// Not a cosmetic setting, and not free. The picture exists to be read by OCR, a
	// logo matcher and a QR decoder, and small text is where OCR fails first — so
	// there is a real argument for 2. Against it: four times the pixels in every
	// buffer, and this service has already been driven into cgroup reclaim once by
	// memory it did not budget for. Measured here on a 1000x2400 viewport, 2x cost
	// +17% wall time and 2.7x the PNG bytes.
	//
	// So it is a knob with the cheap setting as the default, and the question of
	// whether OCR actually reads more at 2x is one to settle by running the corpus
	// through both and diffing the extracted text — not by assuming.
	Scale int

	// MaxHTMLBytes caps the input.
	MaxHTMLBytes int
}

func (r *Renderer) binary() (string, error) {
	if r.Binary != "" {
		return r.Binary, nil
	}
	// The headless-only builds first.
	//
	// chrome-headless-shell is the same Blink engine with the browser around it
	// removed: no UI layer, no extensions, no sync, no profile machinery. It
	// starts faster and holds less, which matters because this service starts a
	// browser far more often than anything else in the system.
	//
	// These were already in this list — last, after chromium — which meant that on
	// any host with chromium installed they were never once used. Order is the
	// whole of the fix.
	for _, name := range []string{
		"chrome-headless-shell", "headless_shell",
		"chromium", "chromium-browser", "google-chrome-stable", "google-chrome",
	} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("render: no chromium on PATH")
}

func (r *Renderer) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return 30 * time.Second
}

func (r *Renderer) size() (int, int) {
	w, h := r.Width, r.Height
	if w <= 0 {
		w = 1000
	}
	if h <= 0 {
		h = 1400
	}
	return w, h
}

func (r *Renderer) maxHTML() int {
	if r.MaxHTMLBytes > 0 {
		return r.MaxHTMLBytes
	}
	return 8 << 20
}

// Screenshot renders HTML and returns a PNG.
// scale is the device pixel ratio, defaulting to 1.
func (r *Renderer) scale() int {
	if r.Scale > 1 {
		return r.Scale
	}
	return 1
}

// Flags that look like they would help here and do nothing, measured against
// Chromium 153 rather than assumed:
//
//   - --font-render-hinting=none|medium|full
//   - --enable-font-antialiasing
//
// Both produce byte-identical output to no flag at all, and to a deliberately invalid
// flag — they were switches on the old headless_shell and are inert in headless
// Chromium. They are listed here because they appear in every "headless Chrome flags"
// post, and the next person to find one should not have to re-run the experiment.
func (r *Renderer) Screenshot(ctx context.Context, html []byte) (shot []byte, err error) {
	// Chromium is the expensive part of this service by a wide margin, so the span
	// covers exactly that and carries the input size — the usual explanation for a
	// slow render is a very large message body.
	ctx, span := renderTracer.Start(ctx, "render.screenshot",
		trace.WithAttributes(attribute.Int("lazaret.render.input_bytes", len(html))))
	start := time.Now()
	defer func() {
		res := "ok"
		if err != nil {
			res = "error"
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.SetAttributes(attrOutcome.String(res), attribute.Int("lazaret.render.output_bytes", len(shot)))
		span.End()
		attrs := metric.WithAttributes(attrOutcome.String(res))
		metricRenders.Add(ctx, 1, attrs)
		metricRenderDuration.Record(ctx, time.Since(start).Seconds(), attrs)
	}()
	if len(html) == 0 {
		return nil, fmt.Errorf("render: empty document")
	}
	if len(html) > r.maxHTML() {
		return nil, fmt.Errorf("render: document is %d bytes, over the %d limit", len(html), r.maxHTML())
	}
	bin, err := r.binary()
	if err != nil {
		return nil, err
	}

	// A directory per render, removed afterwards, so nothing survives from one message
	// to the next — not a cache entry, not a cookie, not a crash dump.
	dir, err := os.MkdirTemp("", "lazaret-render-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	in := filepath.Join(dir, "message.html")
	out := filepath.Join(dir, "shot.png")
	if err := os.WriteFile(in, html, 0o600); err != nil {
		return nil, err
	}

	// A tab in the running browser, if there is one. Roughly six hundred
	// milliseconds of process startup per render, which at thirty-eight renders a
	// message is most of the cost of link analysis.
	if r.Hosts != nil && r.Hosts.docs != nil {
		shot, err := r.screenshotInTab(ctx, html)
		if err == nil {
			return shot, nil
		}
		if pageFault(err) {
			return nil, err
		}
		// Falling back rather than failing: a browser that will not start is a
		// deployment problem, and a process per render is slow but correct.
		log.Printf("render: tab screenshot failed (%v); falling back to a process", err)
	}

	// A slot before a browser. Taken before the timeout below starts, so time
	// spent queueing is not charged against the render's own budget — otherwise a
	// busy host fails renders that never got to run.
	release, err := r.Browsers.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	w, h := r.size()
	ctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()

	cmd := exec.CommandContext(ctx, bin,
		"--headless",
		"--disable-gpu",
		"--no-sandbox", // the container is the sandbox; see the Dockerfile
		"--disable-dev-shm-usage",
		"--hide-scrollbars",
		"--force-device-scale-factor="+strconv.Itoa(r.scale()),

		// This process opens hostile documents for a living. Everything that could
		// reach the network, persist state or start another process is refused.
		//
		// The resolver rule is the load-bearing one and it is not belt-and-braces.
		// A message body's remote images are tracking pixels: loading one tells the
		// sender their phishing arrived, who opened it and when, which is the single
		// worst thing an analysis platform can leak. It used to be enough that this
		// container sat on a network marked internal — but enabling link analysis
		// joins it to one with egress, and the guarantee must not quietly depend on
		// which compose file someone started. Every hostname fails to resolve here,
		// whatever the container can reach.
		//
		// Fetching a link is the deliberate exception and runs from fetch.go, which
		// builds its own arguments and does not inherit this.
		"--host-resolver-rules=MAP * ~NOTFOUND",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-default-apps",
		"--disable-client-side-phishing-detection",
		"--disable-component-update",
		"--safebrowsing-disable-auto-update",
		"--metrics-recording-only",
		"--mute-audio",
		"--user-data-dir="+filepath.Join(dir, "profile"),
		"--crash-dumps-dir="+filepath.Join(dir, "crash"),

		"--window-size="+strconv.Itoa(w)+","+strconv.Itoa(h),
		// Local HTML with no network to wait for: the page is a file: URL and
		// nothing is fetched, so a long settling budget buys nothing.
		"--virtual-time-budget=2000",
		"--screenshot="+out,
		"file://"+in,
	)
	cmd.Env = []string{"HOME=" + dir, "PATH=/usr/bin:/bin"}

	combined, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("render: timed out after %s", r.timeout())
		}
		return nil, fmt.Errorf("render: chromium: %w: %s", err, trim(combined, 400))
	}

	png, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("render: chromium wrote no image: %s", trim(combined, 400))
	}
	if len(png) == 0 {
		return nil, fmt.Errorf("render: empty image")
	}
	return png, nil
}

// name gives a stable file name for a rendered message, so the same message screenshots
// to the same name and a cache downstream has something to key on.
func name(html []byte) string {
	sum := sha256.Sum256(html)
	return "screenshot-" + hex.EncodeToString(sum[:8]) + ".png"
}

func trim(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// Small wrappers, so fetch.go and render.go share one notion of scratch space.
func tempDir() (string, error)          { return os.MkdirTemp("", "lazaret-render-*") }
func removeAll(dir string)              { _ = os.RemoveAll(dir) }
func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

// screenshotInTab renders a message body in the document browser, which cannot
// resolve a hostname — so a tracking pixel in the message still cannot fire.
func (r *Renderer) screenshotInTab(ctx context.Context, html []byte) ([]byte, error) {
	if len(html) > r.maxHTML() {
		return nil, fmt.Errorf("render: document is %d bytes, over the %d limit", len(html), r.maxHTML())
	}
	w, h := r.size()

	var shot []byte
	err := r.Hosts.docs.Do(ctx, r.timeout(),
		chromedp.Navigate("about:blank"),
		setContent(string(html)),
		screenshotOf(&shot, int64(w), int64(h), r.scale()),
	)
	if err != nil {
		return nil, err
	}
	if len(shot) == 0 {
		return nil, errors.New("render: empty image")
	}
	return shot, nil
}
