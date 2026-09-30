// SPDX-License-Identifier: AGPL-3.0-only

// Command lazaret-render screenshots email HTML.
//
// It replaces Sublime's render-email-html container and answers two MQL capabilities:
// file.message_screenshot, which the corpus calls 347 times, and file.html_screenshot.
// Neither is read for its own sake — a screenshot is always fed to something else, and
// in the corpus that is beta.ocr (161 calls), ml.logo_detect (76), beta.scan_qr (11) and
// beta.parse_exif (5). Rendering is what makes text-in-an-image phishing visible at all.
//
// # Security posture
//
// This process exists to open attacker-controlled documents. It is the most exposed
// thing in the deployment and is built on that assumption:
//
//   - One Chromium process per render, with its own profile directory, deleted after.
//     Nothing survives from one message to the next.
//   - No egress. The container belongs on an internal network, so a remote image, a
//     tracking pixel or a callback simply fails to load. That is deliberate twice over:
//     it contains the renderer, and it stops the mere act of analysing a message from
//     telling the sender it was read.
//   - Requests are size-capped and time-bounded, because layout is a fine denial of
//     service.
package main

import (
	"context"
	"runtime/debug"

	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/lazaretemail/lazaret/telemetry"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", ":8710", "listen address")
	binary := flag.String("chromium", "", "path to chromium (default: first found on PATH)")
	timeout := flag.Duration("timeout", 30*time.Second, "per-render timeout")
	fetchTimeout := flag.Duration("fetch-timeout", 10*time.Second,
		"budget for visiting one link, including rendering it; links are fetched one at a time, so this multiplies")
	width := flag.Int("width", 1000, "viewport width")
	height := flag.Int("height", 1400, "viewport height")
	scale := flag.Int("device-scale-factor", 1,
		"device pixel ratio for screenshots; 2 doubles the linear resolution, which may "+
			"help OCR read small text and costs four times the pixels in every buffer")
	maxBytes := flag.Int64("max-bytes", 8<<20, "maximum request body")
	allowFetch := flag.Bool("fetch", false, "enable /v1/fetch for ml.link_analysis; requires network egress")
	// Off by default. A picture of a fetched link costs a whole browser launch per
	// link — nine links meant nine launches on top of the nine already needed for
	// the DOM — and almost nothing reads it: the corpus reads final_dom about a
	// hundred and twenty times against fifteen for the screenshot, and the rules
	// that want the picture want it for credential-phishing classification, which
	// needs a model this service does not have. Turn it on when that changes.
	reuseBrowsers := flag.Bool("reuse-browsers", true,
		"keep browsers running and render in tabs, instead of a process per render")
	maxTabs := flag.Int("max-tabs", 0,
		"how many renders may share the reused browsers at once (0 chooses from the core count)")
	sharedStoreAddr := flag.String("link-store", envOr("LAZARET_LINK_STORE", ""),
		"host:port of a Garnet or other RESP server to share link results across "+
			"processes and restarts; empty keeps them in this process only")
	sharedStoreTTL := flag.Duration("link-store-ttl", 6*time.Hour,
		"how long a shared link result stays usable; longer than the in-process cache "+
			"because the point of it is to outlive a campaign's burst")
	maxBrowsers := flag.Int("max-browsers", 0,
		"how many browser processes may run at once; 0 derives one from the machine")
	browserWait := flag.Duration("browser-queue-wait", 45*time.Second,
		"how long a render waits for a browser slot before the service says it is busy")
	cacheTTL := flag.Duration("link-cache-ttl", 15*time.Minute,
		"how long a fetched link is reused across messages; 0 disables the cache")
	cacheErrTTL := flag.Duration("link-cache-error-ttl", 2*time.Minute,
		"how long a failed fetch is remembered, so a dead host costs one timeout per window")
	cacheMB := flag.Int64("link-cache-mb", 256, "memory bound for the link cache")
	fetchShots := flag.Bool("fetch-screenshot", false,
		"also screenshot fetched pages; costs a browser launch per link and little reads it")
	linkBrowserURL := flag.String("link-browser", envOr("LAZARET_LINK_BROWSER", ""),
		"CDP endpoint of an external browser to visit links with (e.g. http://obscura:9222), "+
			"instead of starting a second Chromium. The link path asks a browser for "+
			"outerHTML and nothing else, so a lightweight engine does the job at a "+
			"fraction of the memory; screenshots always stay on the local Chromium")
	linkBrowserToken := flag.String("link-browser-token", envOr("LAZARET_LINK_BROWSER_TOKEN", ""),
		"bearer token for the external link browser. Obscura refuses any non-loopback "+
			"bind without one, which is the right default for a port that is a remote "+
			"control for a browser")
	acceptLanguage := flag.String("accept-language", envOr("LAZARET_ACCEPT_LANGUAGE", "en-US,en"),
		"languages to ask for when visiting a link, as a comma-separated list of tags "+
			"(e.g. es-ES,es,en). A page served in the recipient's language is the page "+
			"the recipient saw; quality values are added automatically")
	browserPlatform := flag.String("browser-platform", envOr("LAZARET_BROWSER_PLATFORM", "linux"),
		"the platform a link visit presents as: linux, windows or macos. Everything that "+
			"has to agree — the user agent, Sec-CH-UA-Platform and the Client Hints "+
			"metadata — is derived from it, because a browser claiming one platform in "+
			"one header and another elsewhere is what a cloaking check looks for")
	flag.Parse()

	// Built before anything can use it, and fatal when wrong. A deployment that
	// quietly ignored the platform it was configured with would present one thing
	// while its operator believed it presented another.
	identity, err := newIdentity(*browserPlatform, *acceptLanguage)
	if err != nil {
		log.Fatalf("lazaret-render: %v", err)
	}

	// A misconfigured collector must not stop mail being processed: observability
	// is not allowed to take down the thing it observes. Say so loudly and carry on
	// with no-op providers.
	otelShutdown, err2 := telemetry.Setup(context.Background(), telemetry.Config{
		Service: "lazaret-render",
		Version: buildVersion(),
	})
	if err2 != nil {
		log.Printf("telemetry: disabled, %v", err2)
		otelShutdown = func(context.Context) error { return nil }
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			log.Printf("telemetry: shutting down: %v", err)
		}
	}()

	// One bound for every browser this service starts, screenshots and link
	// fetches alike: they are the same scarce resource.
	browsers := newBrowserPool(*maxBrowsers, *browserWait)
	r := &Renderer{Binary: *binary, Timeout: *timeout, Width: *width, Height: *height,
		Scale: *scale, Browsers: browsers}

	// Long-lived browsers, a tab per job. Falls back to a process per render if
	// one will not start, so a bad host is slow rather than broken.
	if *reuseBrowsers {
		// Not browsers.Limit(). That bound exists because a whole Chromium is
		// expensive to start and heavy to keep; a tab is a renderer process in a
		// browser that is already running, so bounding tabs by the number of
		// browsers the host could stand throttles the cheap thing with the
		// expensive thing's number. Measured: at a tab limit of four, eight
		// concurrent screenshots queued and reuse looked like no gain at all.
		hosts, err := newBrowserHosts(tabLimit(*maxTabs), *allowFetch, identity)
		if err != nil {
			log.Printf("lazaret-render: browser reuse unavailable (%v); using a process per render", err)
		} else {
			r.Hosts = hosts
			defer hosts.Close()
		}
	}

	// Fail at start rather than on the first message: a deployment whose renderer has no
	// browser should not look healthy and then report every screenshot as unavailable.
	if _, err := r.binary(); err != nil {
		log.Fatalf("lazaret-render: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/screenshot", func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(io.LimitReader(req.Body, *maxBytes+1))
		if err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		if int64(len(body)) > *maxBytes {
			httpError(w, http.StatusRequestEntityTooLarge, errors.New("document too large"))
			return
		}

		var in struct {
			HTML string `json:"html"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}

		png, err := r.Screenshot(req.Context(), []byte(in.HTML))
		if err != nil {
			// A render failure is the service's problem, not the caller's request being
			// wrong, and the caller turns a 5xx into "capability unavailable" rather
			// than into a clean scan.
			httpError(w, http.StatusBadGateway, err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"file_name": name([]byte(in.HTML)),
			"png":       png,
		})
	})

	// Fetching is opt-in and separately flagged, because it inverts this service's
	// security posture. Screenshotting a message needs no network at all; following a
	// link is a deliberate outbound connection to an address an attacker chose. An
	// operator turning this on is accepting that, and the SSRF guards in fetch.go are
	// what make it defensible rather than reckless.
	// An external link browser replaces the second Chromium entirely. Resolved before
	// anything else uses it, so a wrong address is a start-up failure rather than a
	// surprise on the first message with a link in it.
	if *allowFetch && *linkBrowserURL != "" {
		if r.Hosts == nil {
			log.Printf("lazaret-render: -link-browser needs browser reuse; ignoring it")
		} else if rb, err := newRemoteBrowser("link", *linkBrowserURL, *linkBrowserToken, tabLimit(*maxTabs)); err != nil {
			// Fatal rather than a fallback. Quietly starting a Chromium the
			// operator asked not to start is how a deployment ends up using twice
			// the memory it budgeted for, with nothing saying why.
			log.Fatalf("lazaret-render: -link-browser %s: %v", *linkBrowserURL, err)
		} else {
			r.Hosts.UseRemoteLinkBrowser(rb)
			log.Printf("lazaret-render: links are visited by %s, not by a local Chromium "+
				"— %d at once", *linkBrowserURL, rb.Tabs())
		}
	}

	if *allowFetch {
		f := &Fetcher{Renderer: r, Screenshot: *fetchShots, Timeout: *fetchTimeout,
			Identity: identity}
		log.Printf("lazaret-render: link visits present as Chrome on %s, asking for %s",
			identity.PlatformName, identity.AcceptLanguage)
		if *cacheTTL > 0 {
			// One entry is capped at a sixteenth of the budget so a single enormous
			// page cannot evict everything else to hold itself.
			maxBytes := *cacheMB << 20
			f.Cache = newURLCache(*cacheTTL, *cacheErrTTL, maxBytes, maxBytes/16)
			if *sharedStoreAddr != "" {
				// The same per-entry cap as the local tier. A page too large to
				// hold in memory is also too large to be worth sending across the
				// network to avoid fetching again.
				f.Cache.shared = newSharedStore(*sharedStoreAddr, *sharedStoreTTL, int(maxBytes/16))
				log.Printf("lazaret-render: sharing link results through %s for %s — "+
					"a URL is fetched once by the deployment rather than once per "+
					"process per %s", *sharedStoreAddr, *sharedStoreTTL, *cacheTTL)
			}
			log.Printf("lazaret-render: link cache on — %s, %dMB; the same URL in many messages is fetched once",
				*cacheTTL, *cacheMB)
			// Published rather than logged: "is the cache working" is a question
			// asked long after start-up.
			go func(c *urlCache) {
				tick := time.NewTicker(30 * time.Second)
				defer tick.Stop()
				for range tick.C {
					_, entries, bytes := c.Stats()
					metricCacheEntries.Record(context.Background(), int64(entries))
					metricCacheBytes.Record(context.Background(), bytes)

					// The shared tier is reported apart from the local one: a
					// deployment gets its saving across restarts and across
					// processes entirely from this, and a failure count climbing
					// quietly is the only visible sign that Garnet has gone, since
					// every failure there is deliberately a miss.
					hits, misses, stores, failures := c.shared.Stats()
					metricSharedHits.Record(context.Background(), hits)
					metricSharedMisses.Record(context.Background(), misses)
					metricSharedStores.Record(context.Background(), stores)
					metricSharedFailures.Record(context.Background(), failures)
				}
			}(f.Cache)
		}
		mux.HandleFunc("POST /v1/fetch", func(w http.ResponseWriter, req *http.Request) {
			var in struct {
				URL string `json:"url"`
				// Fresh asks for the page as it is now, not as it was. A re-visit
				// checking whether a link has changed cannot be answered from a
				// cache of what it looked like before.
				Fresh bool `json:"fresh,omitempty"`
			}
			if err := json.NewDecoder(io.LimitReader(req.Body, 64<<10)).Decode(&in); err != nil {
				httpError(w, http.StatusBadRequest, err)
				return
			}
			fetch := f.Fetch
			if in.Fresh {
				fetch = f.FetchFresh
			}
			res, err := fetch(req.Context(), in.URL)
			if err != nil {
				httpError(w, http.StatusBadRequest, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(res)
		})
		log.Printf("lazaret-render: /v1/fetch enabled — this service now makes outbound requests")
	}

	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := r.binary(); err != nil {
			httpError(w, http.StatusServiceUnavailable, err)
			return
		}
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           telemetry.Middleware("lazaret-render", recoverPanics(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		// Generous, because a render is slow; bounded, because a client that opens a
		// connection and stops talking should not hold a slot forever.
		ReadTimeout:  2 * time.Minute,
		WriteTimeout: 2 * time.Minute,
	}
	log.Printf("lazaret-render: at most %d browser(s) at once", browsers.Limit())
	log.Printf("lazaret-render listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "lazaret-render: %v\n", err)
		os.Exit(1)
	}
}

func httpError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// buildVersion reports the revision this binary was built from, for service.version.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return s.Value[:12]
		}
	}
	return info.Main.Version
}

// recoverPanics turns a panic into a 502 instead of a dropped connection.
//
// Everything this service parses was written by someone hostile, and a bug in a
// parser is a matter of when. Without this, net/http logs the panic and closes
// the connection, and the engine sees a transport error — which it cannot tell
// from the renderer being down, so one malformed page reports the whole
// capability as unavailable and every rule that needs it goes indeterminate. A
// 502 says "this page, not this service".
//
// Earned rather than theoretical: a single Turkish capital I in 400KB of markup
// panicked visibleTextLen and took the connection with it. See asciiLower.
func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			// ErrAbortHandler is net/http's own "stop, quietly" and is not a bug.
			if p == http.ErrAbortHandler {
				panic(p)
			}
			log.Printf("render: panic serving %s: %v\n%s", r.URL.Path, p, debug.Stack())
			httpError(w, http.StatusBadGateway, fmt.Errorf("render: %v", p))
		}()
		next.ServeHTTP(w, r)
	})
}

// envOr reads an environment variable, falling back to a default.
//
// Compose sets storage and endpoint configuration through the environment rather than
// through `command`, because compose replaces `command` wholesale and an overlay that
// restates it drops every flag the base file gains afterwards.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
