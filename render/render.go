// SPDX-License-Identifier: AGPL-3.0-only

// Package render answers the screenshot capabilities from a lazaret-render service.
//
// file.message_screenshot is called 347 times in the corpus and file.html_screenshot 8,
// but neither is ever read for itself: a screenshot is always passed to something that
// looks at pixels. In the corpus that is beta.ocr (161), ml.logo_detect (76),
// beta.scan_qr (11) and beta.parse_exif (5). Rendering is what makes an attack that puts
// its text inside an image visible to a text engine at all.
//
// The client is deliberately stdlib-only. The browser lives in services/render, which is
// free to be fat; the root module stays small enough to `go get` for rule linting.
package render

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// Options configure a Client.
type Options struct {
	// Address is the base URL of a lazaret-render, e.g. http://localhost:8710.
	Address string

	// Timeout bounds one screenshot. Rendering is slow and a hostile document can make
	// it slower, so this is generous but finite.
	Timeout time.Duration

	// HTTPClient overrides the default client.
	HTTPClient *http.Client

	// MaxPNGBytes caps a response. A renderer that returns something enormous is
	// malfunctioning, and the engine should not hold it in memory to find out.
	MaxPNGBytes int64
}

func (o *Options) timeout() time.Duration {
	if o != nil && o.Timeout > 0 {
		return o.Timeout
	}
	return 60 * time.Second
}

func (o *Options) maxPNG() int64 {
	if o != nil && o.MaxPNGBytes > 0 {
		return o.MaxPNGBytes
	}
	return 32 << 20
}

// Client talks to a lazaret-render.
type Client struct {
	addr         string
	http         *http.Client
	max          int64
	linkAnalysis bool

	// inflight deduplicates concurrent and repeated fetches of the same URL.
	// See fetchOnce.
	inflightMu sync.Mutex
	inflight   map[string]*fetchCall
}

// New returns a client for the service at addr.
func New(opts *Options) *Client {
	c := &Client{max: opts.maxPNG()}
	if opts != nil {
		c.addr = opts.Address
		c.http = opts.HTTPClient
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: opts.timeout()}
	}
	return c
}

// Capabilities are what this client answers, for registering with an mql.MuxEnricher.
func Capabilities() []enrich.Capability {
	return []enrich.Capability{
		enrich.CapFileMessageScreenshot,
		enrich.CapFileHTMLScreenshot,
	}
}

// Enrich implements mql.Enricher.
func (c *Client) Enrich(ctx context.Context, cap enrich.Capability, args []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	if c == nil || c.addr == "" {
		return mql.NullValue, enrich.NotImplemented(cap)
	}
	if cap == enrich.CapMLLinkAnalysis {
		if !c.linkAnalysis {
			return mql.NullValue, enrich.NotImplemented(cap)
		}
		return c.enrichLinkAnalysis(ctx, args)
	}

	html, ok := c.htmlFor(cap, args)
	if !ok {
		// Nothing to render. Null rather than unavailable: the service is fine, this
		// message simply has no HTML body, and a plain-text message has no screenshot
		// in the same way it has no attachments.
		return mql.NullValue, nil
	}

	png, filename, err := c.screenshot(ctx, html)
	if err != nil {
		return mql.NullValue, &enrich.Unavailable{Capability: cap, Reason: "render failed", Err: err}
	}

	// A File, which is what the schema declares and what the scanners downstream accept:
	// beta.ocr(file.message_screenshot()) hands this straight to Strelka.
	return mql.FromGo(&mdm.File{
		FileName: mdm.Ptr(filename),
		Size:     mdm.Ptr(int64(len(png))),
		Raw:      png,
	}), nil
}

// htmlFor decides what to render.
//
// file.message_screenshot takes no arguments, so the evaluator hands it the message and
// the HTML body is pulled out here. file.html_screenshot takes a file and renders its
// content as a document in its own right.
func (c *Client) htmlFor(cap enrich.Capability, args []mql.Value) ([]byte, bool) {
	if len(args) == 0 {
		return nil, false
	}
	v := args[0]

	if cap == enrich.CapFileHTMLScreenshot {
		for _, field := range []string{"raw", "data", "content"} {
			if b, ok := v.Field(field).AsBytes(); ok && len(b) > 0 {
				return b, true
			}
		}
		if s, ok := v.AsString(); ok && s != "" {
			return []byte(s), true
		}
		return nil, false
	}

	body := v.Field("body")
	if b, ok := body.Field("html").Field("raw").AsBytes(); ok && len(b) > 0 {
		return b, true
	}
	if s, ok := body.Field("html").Field("raw").AsString(); ok && s != "" {
		return []byte(s), true
	}
	// A plain-text message still renders: wrapping it preserves the layout a recipient
	// would see, which is what an OCR or logo pass is looking at.
	if s, ok := body.Field("plain").Field("raw").AsString(); ok && s != "" {
		return []byte("<html><body><pre>" + escape(s) + "</pre></body></html>"), true
	}
	return nil, false
}

func (c *Client) screenshot(ctx context.Context, html []byte) ([]byte, string, error) {
	payload, err := json.Marshal(map[string]string{"html": string(html)})
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+"/v1/screenshot", bytes.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.max))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, "", fmt.Errorf("%s", e.Error)
	}

	var out struct {
		FileName string `json:"file_name"`
		PNG      []byte `json:"png"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, "", err
	}
	if len(out.PNG) == 0 {
		return nil, "", fmt.Errorf("render returned no image")
	}
	if out.FileName == "" {
		out.FileName = "screenshot.png"
	}
	return out.PNG, out.FileName, nil
}

// escape is a minimal HTML escaper, used only for wrapping plain text. html/template
// would be the right tool if this were building a page; it is quoting four characters
// inside a <pre>, and pulling in the template engine for that is not worth it.
func escape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
