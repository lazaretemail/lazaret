// SPDX-License-Identifier: AGPL-3.0-only

package render

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// ml.link_analysis, which is mostly not machine learning.
//
// Of what the corpus reads off it, final_dom (133 uses), effective_url (60),
// redirect_history (28), unique_urls_accessed (16), files_downloaded (17) and screenshot
// (15) are observations: follow the link and report what happened. Only credphish (66)
// is a model's opinion, and that field stays absent until one is configured — absent
// rather than guessed, because a rule reading `.credphish.disposition == "phishing"`
// should get no answer instead of a fabricated one.
//
// The name is Sublime's, and it groups a browser's job with a classifier's. Splitting
// them is what lets the browser half work today.

// EnableLinkAnalysis adds ml.link_analysis to what this client answers.
//
// Separate from Capabilities because it needs a lazaret-render started with -fetch, and
// that service is making outbound requests to addresses an attacker chose. Claiming the
// capability against a renderer that cannot fetch would report every link as
// unretrievable, which reads like a finding about the message.
func (c *Client) EnableLinkAnalysis() *Client {
	c.linkAnalysis = true
	return c
}

// LinkAnalysisCapability is what EnableLinkAnalysis lets this client answer.
func LinkAnalysisCapability() enrich.Capability { return enrich.CapMLLinkAnalysis }

func (c *Client) enrichLinkAnalysis(ctx context.Context, args []mql.Value) (mql.Value, error) {
	if len(args) == 0 {
		return mql.NullValue, nil
	}
	target := urlFrom(args[0])
	if target == "" {
		return mql.NullValue, nil
	}

	res, err := c.fetchOnce(ctx, target)
	if err != nil {
		return mql.NullValue, &enrich.Unavailable{
			Capability: enrich.CapMLLinkAnalysis,
			Reason:     "fetch failed",
			Err:        err,
		}
	}

	out := &mdm.LinkAnalysisOutput{
		OriginalURL:  mdm.ParseURL(res.OriginalURL, true),
		EffectiveURL: mdm.ParseURL(res.EffectiveURL, true),
		Retrieved:    mdm.Ptr(res.Retrieved),
		Submitted:    mdm.Ptr(true),

		// Analyzed is specifically "was this page analysed for credential phishing".
		// It is false: the page was fetched, not classified. Reporting true because a
		// fetch succeeded would make `.analyzed and not .credphish...` read as a clean
		// verdict from a service that never looked.
		Analyzed: mdm.Ptr(false),
	}
	if !res.RetrievedAtZero() {
		out.RetrievedAt = &res.At
	}
	if res.StatusCode > 0 {
		code := int64(res.StatusCode)
		out.StatusCode, out.PageStatusCode = &code, &code
	}
	if res.ContentType != "" {
		out.ContentType = mdm.Ptr(res.ContentType)
	}
	for _, u := range res.RedirectHistory {
		out.RedirectHistory = append(out.RedirectHistory, mdm.ParseURL(u, true))
	}
	if res.FinalDOM != "" {
		out.FinalDom = finalDOM(res.FinalDOM)
	}
	if len(res.Screenshot) > 0 {
		out.Screenshot = &mdm.File{
			FileName: mdm.Ptr("link-screenshot.png"),
			Size:     mdm.Ptr(int64(len(res.Screenshot))),
			Raw:      res.Screenshot,
		}
	}
	return mql.FromGo(out), nil
}

// finalDOM fills the published shape from the fetched document.
//
// Rules read .raw (the served HTML), .inner_text and .display_text (what a person would
// read) and .links. The text forms matter because a phishing page's give-away is often
// wording that never appears in its markup as a contiguous string.
func finalDOM(raw string) *mdm.FinalDOM {
	dom := &mdm.FinalDOM{Raw: mdm.Ptr(raw)}

	parsed := mql.ParseHTML(raw)
	if parsed == nil {
		return dom
	}
	dom.InnerText = parsed.InnerText
	// display_text is documented as the visible text with invisible characters removed
	// and non-ASCII folded to spaces — the form in which a confusable or a zero-width
	// space stops hiding a word from a rule.
	if parsed.InnerText != nil {
		dom.DisplayText = mdm.Ptr(displayText(*parsed.InnerText))
	}
	dom.Links = parsed.Links
	return dom
}

func displayText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x20:
			b.WriteByte(' ')
		case r < 0x7f:
			b.WriteRune(r)
		default:
			b.WriteByte(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// urlFrom pulls a URL out of whatever the rule passed: the corpus idiom is
// `any(body.links, ml.link_analysis(.))`, so the argument is usually a Link.
func urlFrom(v mql.Value) string {
	for _, path := range [][]string{{"href_url", "url"}, {"url"}, {"href_url"}} {
		cur := v
		for _, p := range path {
			cur = cur.Field(p)
		}
		if s, ok := cur.AsString(); ok && s != "" {
			return s
		}
	}
	if s, ok := v.AsString(); ok {
		return s
	}
	return ""
}

// fetchResult mirrors the service's response.
type fetchResult struct {
	OriginalURL     string    `json:"original_url"`
	EffectiveURL    string    `json:"effective_url"`
	RedirectHistory []string  `json:"redirect_history"`
	StatusCode      int       `json:"status_code"`
	ContentType     string    `json:"content_type"`
	Retrieved       bool      `json:"retrieved"`
	FinalDOM        string    `json:"final_dom"`
	Screenshot      []byte    `json:"screenshot"`
	Error           string    `json:"error"`
	At              time.Time `json:"-"`
}

func (r *fetchResult) RetrievedAtZero() bool { return r.At.IsZero() }

func (c *Client) fetch(ctx context.Context, target string, fresh bool) (*fetchResult, error) {
	payload, err := json.Marshal(map[string]any{"url": target, "fresh": fresh})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+"/v1/fetch", strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out fetchResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	out.At = time.Now().UTC()
	return &out, nil
}

// Fetching each URL once.
//
// Visiting a link is by far the most expensive thing this package does — seconds of
// real network and a browser — and the engine asks for the same one repeatedly. Two
// reasons, both outside this package's control:
//
//   - Rules write `ml.link_analysis(link)` and `ml.link_analysis(link, mode=
//     "aggressive")`, and the evaluator's cache keys on arguments including keywords.
//     Those are two cache entries. They are not two requests: the mode describes how
//     to interpret a page, not how to retrieve it, and this client sends the same
//     body either way. A real message doubled its fetch count on that alone.
//   - Several rules independently reach the same link.
//
// Deduplicating here rather than asking the evaluator's cache to know which keywords
// a provider ignores, which is this client's business and nobody else's. One real
// message went from eighteen fetches to nine.

// fetchCall is one fetch, shared by everyone who asked for that URL.
type fetchCall struct {
	done chan struct{}
	res  *fetchResult
	err  error
	at   time.Time
}

// fetchTTL is how long a fetched page stands for.
//
// Short. A page is a live thing and an analysis should not be reasoning about what a
// URL served ten minutes ago; this exists to collapse the calls made while one
// message is being evaluated, not to be a web cache.
const fetchTTL = 90 * time.Second

// fetchOnce fetches a URL, or joins a fetch already running for it.
func (c *Client) fetchOnce(ctx context.Context, target string) (*fetchResult, error) {
	c.inflightMu.Lock()
	if c.inflight == nil {
		c.inflight = map[string]*fetchCall{}
	}
	if call, ok := c.inflight[target]; ok {
		if call.at.IsZero() || time.Since(call.at) < fetchTTL {
			c.inflightMu.Unlock()
			select {
			case <-call.done:
				return call.res, call.err
			case <-ctx.Done():
				// This caller gave up; the fetch continues for whoever else is
				// waiting on it.
				return nil, ctx.Err()
			}
		}
		delete(c.inflight, target)
	}
	call := &fetchCall{done: make(chan struct{})}
	c.inflight[target] = call
	c.sweepLocked()
	c.inflightMu.Unlock()

	// Deliberately not the caller's context. The first caller to ask must not be able
	// to cancel a fetch that others are waiting on, and a fetch abandoned halfway is
	// the worst of both — the page was visited, the sender was told, and nobody got
	// an answer. The client's own timeout bounds it.
	call.res, call.err = c.fetch(context.WithoutCancel(ctx), target, false)

	c.inflightMu.Lock()
	call.at = time.Now()
	if call.err != nil {
		// A failure is not cached: a timeout is usually about the moment rather
		// than the URL, and holding it would fail every later look at the same link.
		delete(c.inflight, target)
	}
	c.inflightMu.Unlock()
	close(call.done)

	return call.res, call.err
}

// maxInflight bounds how many fetched pages are remembered at once.
//
// The map was unbounded: an entry is removed when the same URL is asked for again
// after its TTL, or when the fetch failed — so a URL fetched once and never seen
// again was held forever, and each entry carries the page's DOM. A connector
// running for a day over real mail sees tens of thousands of distinct links, and
// the engine's memory grew with every one of them. It looked like caching and was
// a leak with a slow fuse.
const maxInflight = 4096

// sweepLocked drops expired entries, and the oldest if the map is still too big.
//
// Opportunistic rather than a background goroutine: this runs on the path that
// adds entries, so the map cannot grow without the sweep also running. A client
// that stops fetching stops needing to be swept.
func (c *Client) sweepLocked() {
	if len(c.inflight) <= maxInflight/2 {
		return
	}

	now := time.Now()
	for k, call := range c.inflight {
		// Never evict a fetch still in flight: somebody is waiting on it, and
		// removing it would start a second fetch of the same page.
		if call.at.IsZero() {
			continue
		}
		if now.Sub(call.at) >= fetchTTL {
			delete(c.inflight, k)
		}
	}

	// Still over after expiry: drop the oldest settled entries. Go randomises map
	// iteration, so this is approximate, which is the right amount of effort for
	// a cache whose entries all expire within ninety seconds anyway.
	for k, call := range c.inflight {
		if len(c.inflight) <= maxInflight {
			return
		}
		if !call.at.IsZero() {
			delete(c.inflight, k)
		}
	}
}

// Revisit is what a link serves now, ignoring every cache between here and the page.
//
// Separate from the enrichment path on purpose. That path is answering "what did this
// message carry", and it deduplicates, caches and shares results precisely so a link is
// visited once. This one is answering "is it still the same", which is the opposite
// question: a shared answer is exactly the wrong answer, and the result is not stored,
// because what a link serves today is not evidence about a message from Tuesday.
func (c *Client) Revisit(ctx context.Context, target string) (*LinkSnapshot, error) {
	res, err := c.fetch(ctx, target, true)
	if err != nil {
		return nil, err
	}
	return &LinkSnapshot{
		EffectiveURL:    res.EffectiveURL,
		RedirectHistory: res.RedirectHistory,
		StatusCode:      res.StatusCode,
		ContentType:     res.ContentType,
		Retrieved:       res.Retrieved,
		BodyLen:         len(res.FinalDOM),
		Error:           res.Error,
	}, nil
}

// LinkSnapshot is what one visit saw, reduced to what a comparison needs.
//
// The page itself is deliberately not here. Keeping every DOM of every link of every
// message would be a second corpus, and the question a re-visit asks does not need it.
type LinkSnapshot struct {
	EffectiveURL    string   `json:"effective_url"`
	RedirectHistory []string `json:"redirect_history,omitempty"`
	StatusCode      int      `json:"status_code"`
	ContentType     string   `json:"content_type,omitempty"`
	Retrieved       bool     `json:"retrieved"`
	BodyLen         int      `json:"body_len"`
	Error           string   `json:"error,omitempty"`
}
