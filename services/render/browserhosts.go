// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// Two browsers, because one command line cannot serve both jobs.
//
// A message screenshot runs with every hostname unresolvable. The reason is in
// render.go and it is not negotiable: a message body's remote images are tracking
// pixels, and loading one tells the sender their phishing arrived, who opened it
// and when. That guarantee is enforced by the browser's own resolver rather than
// by request filtering we wrote, and it must not become conditional on a code path
// being taken.
//
// Link analysis is the deliberate exception: visiting a link is the entire point,
// so it needs the network.
//
// Sharing one browser between them would mean giving the message-screenshot job a
// browser that *can* resolve, and relying on per-request interception to stop it.
// That trades a structural guarantee for a conditional one, in the component whose
// job is to look at hostile content. Two browsers cost one extra idle process.
type browserHosts struct {
	// docs renders content we already have: message bodies and supplied HTML.
	// It cannot resolve a hostname.
	docs *browserHost

	// web visits links. It has the network, and it is the only one that does.
	//
	// An interface, because it is the one browser in this service that does not have
	// to be Chromium: the link path asks it for outerHTML and nothing else, so a
	// lightweight CDP engine does the job at a fraction of the memory. See
	// linkbrowser.go for why the screenshot host cannot be swapped the same way.
	web linkBrowser

	dir string
}

// linkBrowser is what the link path needs of a browser, which is one question:
// what does this URL look like after its script has run.
//
// Narrowed to that deliberately. It used to be "run these chromedp actions", which is
// the same thing said in Chromium's vocabulary — and that vocabulary is what made an
// external engine hard to drive, because chromedp models the browser's targets and
// sessions and an engine that reports them differently desynchronises it. Asking for a
// DOM instead lets each implementation get there its own way.
type linkBrowser interface {
	DOM(ctx context.Context, timeout time.Duration, url string) (string, error)
	Close()
	Tabs() int
}

// chromiumLinkBrowser is a local Chromium host used as a link browser.
type chromiumLinkBrowser struct {
	h  *browserHost
	id browserIdentity
}

// DOM loads the page in a tab and returns the document after script has run.
func (c chromiumLinkBrowser) DOM(ctx context.Context, timeout time.Duration, url string) (string, error) {
	var dom string
	err := c.h.Do(ctx, timeout,
		identify(c.id),
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Give a page that paints itself a moment to do so, bounded by the
			// render timeout above. The process path used --virtual-time-budget
			// for the same reason.
			return chromedp.Sleep(settleFor).Do(ctx)
		}),
		chromedp.OuterHTML("html", &dom, chromedp.ByQuery),
	)
	if err != nil {
		return "", err
	}
	return dom, nil
}

func (c chromiumLinkBrowser) Close()    { c.h.Close() }
func (c chromiumLinkBrowser) Tabs() int { return c.h.Tabs() }

func newBrowserHosts(maxTabs int, enableFetch bool, id browserIdentity) (*browserHosts, error) {
	dir, err := os.MkdirTemp("", "lazaret-browsers-")
	if err != nil {
		return nil, err
	}

	// Each host's directory has to exist before Chromium starts: it is that
	// host's HOME, and the crash handler resolves paths against it.
	docsDir, webDir := filepath.Join(dir, "docs"), filepath.Join(dir, "web")
	for _, d := range []string{docsDir, webDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}

	docsFlags := append(baseFlags(docsDir),
		chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND"),
		chromedp.Flag("disable-background-networking", true),
	)
	h := &browserHosts{
		docs: newBrowserHost("document", maxTabs, docsFlags),
		dir:  dir,
	}
	if enableFetch {
		// The link browser presents as an ordinary Chrome, not as HeadlessChrome.
		// Only this host: the document host resolves no hostnames at all, so what
		// it would claim never reaches anybody.
		//
		// The flag covers the User-Agent header. It does not cover Sec-CH-UA, which
		// Chromium derives from its own build and which would still have said
		// "Chromium" against a user agent claiming Chrome — a mismatch that is its
		// own signal. That half is set per page, in identify().
		webFlags := append(baseFlags(webDir),
			chromedp.UserAgent(id.UserAgent),
		)
		h.web = chromiumLinkBrowser{h: newBrowserHost("link", maxTabs, webFlags), id: id}
	}
	return h, nil
}

// UseRemoteLinkBrowser replaces the link browser with an external CDP engine, and stops
// the local one if it was already running.
//
// Only the link browser. The screenshot host stays local and stays Chromium, because
// its output is fed to OCR and a renderer that lays out incorrectly produces a valid
// picture of nothing — which every rule downstream reads as "found nothing" rather than
// "could not look".
func (h *browserHosts) UseRemoteLinkBrowser(r linkBrowser) {
	if h == nil {
		return
	}
	if h.web != nil {
		h.web.Close()
	}
	h.web = r
}

func (h *browserHosts) Close() {
	if h == nil {
		return
	}
	h.docs.Close()
	if h.web != nil {
		h.web.Close()
	}
	if err := os.RemoveAll(h.dir); err != nil {
		log.Printf("lazaret-render: cleaning up browser profiles: %v", err)
	}
}

// identify makes the browser's Client Hints agree with its user agent.
//
// --user-agent covers the User-Agent header and nothing else: Sec-CH-UA is built from
// Chromium's own brand list, so a browser told to claim Chrome still announced
// "Chromium" in the hints. Real Chrome sends both its own brand and Chromium's, and the
// deliberately meaningless "Not A Brand" entry that exists to stop servers parsing the
// list naively.
//
// Worth doing because the mismatch is exactly the kind of thing a cloaking check looks
// for — it does not need to detect a headless browser, only an inconsistent one.
func identify(id browserIdentity) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		return emulation.SetUserAgentOverride(id.UserAgent).
			// Without the quality values: Chromium appends its own, and passing
			// them here produced "en-US,en;q=0.9;q=0.9" — a malformed header, which
			// is a louder signal than the one it was meant to quieten.
			WithAcceptLanguage(id.AcceptLanguage).
			WithPlatform(id.PlatformName).
			WithUserAgentMetadata(&emulation.UserAgentMetadata{
				Brands: []*emulation.UserAgentBrandVersion{
					{Brand: "Not_A Brand", Version: "8"},
					{Brand: "Chromium", Version: chromeMajor},
					{Brand: "Google Chrome", Version: chromeMajor},
				},
				FullVersionList: []*emulation.UserAgentBrandVersion{
					{Brand: "Not_A Brand", Version: "8.0.0.0"},
					{Brand: "Chromium", Version: chromeFullVersion},
					{Brand: "Google Chrome", Version: chromeFullVersion},
				},
				Platform:        id.PlatformName,
				PlatformVersion: id.PlatformVersion,
				Architecture:    id.Arch,
				Bitness:         "64",
				Model:           "",
				Mobile:          false,
			}).Do(ctx)
	}
}
