// SPDX-License-Identifier: AGPL-3.0-only

// Package whois answers MQL's network.whois, using RDAP in preference to legacy WHOIS.
//
// # Why RDAP first
//
// Legacy WHOIS is free text over a cleartext TCP socket with no schema. Every registry
// formats it differently, dates appear in half a dozen layouts, and the only way to read
// it is a pile of per-registry guesses that rot. RDAP is JSON with a specification
// (RFC 9083), a discovery mechanism (RFC 9224), TLS, and proper HTTP status codes — a 404
// genuinely means the domain is not registered rather than being a phrase one has to
// recognise in a paragraph.
//
// That matters here more than it might elsewhere. `days_old` is the single most-used
// WHOIS field in the public rule corpus — 116 references — because a domain registered
// last week is one of the cheapest and most reliable phishing signals there is. A date
// parser that quietly fails on one registry's format turns that signal off for every
// domain under it, and nothing about the resulting no-match looks wrong.
//
// So: RDAP by default, and legacy WHOIS only where RDAP does not exist. That is a real
// set — .de publishes no RDAP server at all — so the fallback is necessary, not
// ceremonial. When it is used, the result says so.
//
// # Discovery
//
// The TLD's RDAP service is found by asking IANA:
//
//	GET https://rdap.iana.org/domain/<tld>
//
// whose response carries a link with type "application/rdap+json" pointing at the
// registry's own RDAP base URL. Those answers are cached, including the negative ones, so
// a TLD without RDAP is not re-discovered on every message.
//
// # Talking to the internet from an email pipeline
//
// Every lookup here is triggered by a domain an attacker chose. Two consequences shape
// this package. The set of hosts contacted is bounded by IANA's registry rather than by
// anything in the message, redirects are limited and must stay on HTTPS, and responses
// are size-capped. And registries rate-limit: a burst of lookups from a mail pipeline
// looks like abuse, so requests are serialised per host with a minimum interval, results
// are cached, and concurrency is bounded.
package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// Defaults chosen to be polite to registries rather than fast.
const (
	// DefaultTimeout bounds one lookup, including discovery.
	DefaultTimeout = 10 * time.Second

	// DefaultCacheTTL is how long a result is reused. Registration data changes on the
	// order of months; Sublime's own service documents a delay of roughly a day, so a day
	// is not a compromise so much as the natural granularity.
	DefaultCacheTTL = 24 * time.Hour

	// DefaultNegativeTTL applies to failures. Shorter, because a registry being briefly
	// unreachable should not blind us for a day.
	DefaultNegativeTTL = 15 * time.Minute

	// DefaultBootstrapTTL applies to TLD discovery, which changes very rarely.
	DefaultBootstrapTTL = 7 * 24 * time.Hour

	// DefaultMinInterval is the minimum gap between requests to one host.
	DefaultMinInterval = 250 * time.Millisecond

	// DefaultMaxConcurrent bounds simultaneous lookups across all hosts.
	DefaultMaxConcurrent = 4

	// maxResponseBytes caps what will be read from a registry. RDAP records are a few
	// kilobytes; anything vastly larger is a malfunction or an attack.
	maxResponseBytes = 4 << 20
)

// BootstrapURL is IANA's RDAP service for the root zone, used to discover each TLD's own
// RDAP server.
const BootstrapURL = "https://rdap.iana.org/domain/"

// Options configure a Client.
type Options struct {
	// Timeout bounds a single lookup. Zero means DefaultTimeout.
	Timeout time.Duration

	// CacheTTL, NegativeTTL and BootstrapTTL control reuse. Zero means the defaults.
	CacheTTL     time.Duration
	NegativeTTL  time.Duration
	BootstrapTTL time.Duration

	// MinInterval is the minimum gap between requests to the same host.
	MinInterval time.Duration

	// MaxConcurrent bounds simultaneous outbound lookups.
	MaxConcurrent int

	// DisableLegacyWHOIS turns off the port-43 fallback entirely. A deployment that
	// cannot make arbitrary outbound TCP connections, or simply does not want to parse
	// free text, should set this: the result is then "unavailable" for TLDs without
	// RDAP, which is honest.
	DisableLegacyWHOIS bool

	// UserAgent identifies this client to registries. Several ask that clients be
	// identifiable, and an anonymous one is the first to be blocked.
	UserAgent string

	// BootstrapURL overrides IANA's RDAP service, used to discover a TLD's server.
	// For tests.
	BootstrapURL string

	// BootstrapIPv4URL, BootstrapIPv6URL and BootstrapASNURL override the RFC 9224
	// bootstrap registries. For tests.
	BootstrapIPv4URL string
	BootstrapIPv6URL string
	BootstrapASNURL  string

	// HTTPClient overrides the default. For tests.
	HTTPClient *http.Client

	// Now overrides the clock, so that `days_old` is testable.
	Now func() time.Time
}

func (o *Options) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultTimeout
}

func (o *Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}

func (o *Options) bootstrapURL() string {
	if o.BootstrapURL != "" {
		return o.BootstrapURL
	}
	return BootstrapURL
}

func (o *Options) bootstrapIPv4URL() string {
	if o.BootstrapIPv4URL != "" {
		return o.BootstrapIPv4URL
	}
	return BootstrapIPv4URL
}

func (o *Options) bootstrapIPv6URL() string {
	if o.BootstrapIPv6URL != "" {
		return o.BootstrapIPv6URL
	}
	return BootstrapIPv6URL
}

func (o *Options) bootstrapASNURL() string {
	if o.BootstrapASNURL != "" {
		return o.BootstrapASNURL
	}
	return BootstrapASNURL
}

func (o *Options) userAgent() string {
	if o.UserAgent != "" {
		return o.UserAgent
	}
	return "lazaret/0.1 (+https://github.com/lazaretemail/lazaret)"
}

// Client looks up registration data.
//
// Safe for concurrent use: one client serves a whole deployment, and its cache and rate
// limiter are what keep that from looking like abuse to a registry.
type Client struct {
	opts Options
	http *http.Client

	sem chan struct{}

	mu        sync.Mutex
	hostLast  map[string]time.Time
	bootstrap map[string]bootstrapEntry
	results   map[string]resultEntry

	// registries holds the parsed RFC 9224 bootstrap files for addresses and AS
	// numbers, which are bulk documents rather than per-object lookups.
	registries registryCache
}

type bootstrapEntry struct {
	// base is the registry's RDAP base URL, empty when the TLD publishes none.
	base    string
	expires time.Time
}

// resultEntry caches one lookup. The value is typed `any` because the same cache serves
// domains, addresses and AS numbers, keyed by a prefix on the name.
type resultEntry struct {
	out     any
	err     error
	expires time.Time
}

// New returns a client.
func New(opts *Options) *Client {
	var o Options
	if opts != nil {
		o = *opts
	}
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = DefaultMaxConcurrent
	}
	if o.MinInterval <= 0 {
		o.MinInterval = DefaultMinInterval
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = DefaultCacheTTL
	}
	if o.NegativeTTL <= 0 {
		o.NegativeTTL = DefaultNegativeTTL
	}
	if o.BootstrapTTL <= 0 {
		o.BootstrapTTL = DefaultBootstrapTTL
	}

	c := &Client{
		opts:      o,
		sem:       make(chan struct{}, o.MaxConcurrent),
		hostLast:  map[string]time.Time{},
		bootstrap: map[string]bootstrapEntry{},
		results:   map[string]resultEntry{},
	}

	c.http = o.HTTPClient
	if c.http == nil {
		c.http = &http.Client{
			Timeout: o.timeout(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Registries do redirect — a thin registry can hand off to the
				// registrar's own RDAP server — but the hop must stay on TLS and the
				// chain must stay short. Both bound where an attacker-chosen domain can
				// send us.
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				if req.URL.Scheme != "https" {
					return fmt.Errorf("refusing to follow a redirect to %s", req.URL.Scheme)
				}
				return nil
			},
		}
	}
	return c
}

// Source records how an answer was obtained. It is worth knowing: a legacy WHOIS result
// is best-effort text parsing and deserves less trust than an RDAP one.
type Source string

const (
	SourceRDAP   Source = "rdap"
	SourceLegacy Source = "whois"
)

// ErrNoRDAP reports that a TLD publishes no RDAP service.
var ErrNoRDAP = errors.New("whois: the TLD publishes no RDAP service")

// Lookup returns registration data for a domain.
//
// A domain that is definitively not registered yields a result with Found false and no
// error — that is an answer, and a useful one. An error means the question could not be
// put, which the evaluator turns into indeterminate rather than into a verdict.
func (c *Client) Lookup(ctx context.Context, domain string) (*mdm.WhoisOutput, error) {
	parsed := mdm.ParseDomain(domain)
	if parsed == nil {
		return nil, fmt.Errorf("whois: %q is not a domain", domain)
	}
	// Registration is a property of the registrable domain, not of a subdomain: looking
	// up mail.example.com must ask about example.com.
	name := parsed.Domain
	if parsed.RootDomain != nil {
		name = *parsed.RootDomain
	}

	// A reserved TLD has a definite answer, and it is not "unknown".
	//
	// .test, .invalid, .example and .localhost are set aside by RFC 2606 and RFC
	// 6761 precisely so that they can never be registered. There is no registry to
	// ask, so discovery fails — and reporting that as an unavailable capability
	// says "I could not find out" about something we know for certain.
	//
	// It matters beyond pedantry: network.whois is read by 103 rules, so a message
	// from a reserved domain would push all of them to indeterminate on the grounds
	// that a registry we know does not exist did not answer. And the fact itself is
	// a finding — mail from a .test address arriving in production is not ordinary.
	if reservedTLD(name) {
		return &mdm.WhoisOutput{Found: mdm.Ptr(false), Domain: parsed}, nil
	}

	if out, err, ok := c.cached(name); ok {
		return out, err
	}

	out, err := c.lookupUncached(ctx, name)
	c.store(name, out, err)
	return out, err
}

func (c *Client) lookupUncached(ctx context.Context, name string) (*mdm.WhoisOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.timeout())
	defer cancel()

	base, err := c.rdapBase(ctx, tldOf(name))
	switch {
	case err != nil:
		return nil, err

	case base != "":
		out, err := c.rdapLookup(ctx, base, name)
		if err == nil {
			return out, nil
		}
		// RDAP exists but did not answer. Falling back to WHOIS here would be wrong
		// rather than resilient: if the registry has RDAP, its WHOIS is the same data
		// through a worse pipe, and a transient failure should read as transient.
		return nil, err
	}

	// No RDAP for this TLD. This is the case the fallback exists for.
	if c.opts.DisableLegacyWHOIS {
		return nil, fmt.Errorf("%w and legacy WHOIS is disabled", ErrNoRDAP)
	}
	return c.legacyLookup(ctx, name)
}

// Enrich implements mql.Enricher.
//
// It answers network.whois and the two extension capabilities, and reports anything else
// unavailable rather than guessing — so it composes through mql.MuxEnricher alongside
// providers for the models and file analysis.
func (c *Client) Enrich(ctx context.Context, cap enrich.Capability, args []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	switch cap {
	case enrich.CapNetworkWhois:
		return c.enrichDomain(ctx, args)
	case CapIP:
		return c.enrichIP(ctx, args)
	case CapASN:
		return c.enrichASN(ctx, args)
	}
	return mql.NullValue, enrich.NotImplemented(cap)
}

// enrichDomain answers network.whois.
func (c *Client) enrichDomain(ctx context.Context, args []mql.Value) (mql.Value, error) {
	if len(args) == 0 {
		return mql.NullValue, nil
	}

	// The argument is a Domain object in the corpus idiom
	// `network.whois(sender.email.domain)`, but a bare string is accepted too.
	name, ok := args[0].AsString()
	if !ok {
		if inner := args[0].Field("domain"); !inner.IsNull() {
			name, ok = inner.AsString()
		}
	}
	if !ok || name == "" {
		return mql.NullValue, nil
	}

	out, err := c.Lookup(ctx, name)
	if err != nil {
		// A lookup that could not be made is a missing capability for this message, not
		// an evaluation failure: the rule keeps running and the verdict becomes
		// indeterminate.
		return mql.NullValue, &enrich.Unavailable{
			Capability: enrich.CapNetworkWhois,
			Reason:     "lookup failed",
			Err:        err,
		}
	}
	return mql.FromGo(out), nil
}

// ---------------------------------------------------------------------------
// caching and rate limiting
// ---------------------------------------------------------------------------

// cachedAny returns a cached lookup of any kind.
func (c *Client) cachedAny(key string) (any, error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.results[key]
	if !ok || c.opts.now().After(entry.expires) {
		return nil, nil, false
	}
	return entry.out, entry.err, true
}

func (c *Client) storeAny(key string, out any, err error) {
	ttl := c.opts.CacheTTL
	if err != nil {
		ttl = c.opts.NegativeTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results[key] = resultEntry{out: out, err: err, expires: c.opts.now().Add(ttl)}
}

func (c *Client) cached(name string) (*mdm.WhoisOutput, error, bool) {
	v, err, ok := c.cachedAny("domain:" + name)
	if !ok {
		return nil, nil, false
	}
	out, _ := v.(*mdm.WhoisOutput)
	return out, err, true
}

func (c *Client) store(name string, out *mdm.WhoisOutput, err error) {
	c.storeAny("domain:"+name, out, err)
}

// acquire takes a concurrency slot and waits out the per-host interval.
//
// Registries rate-limit, and a mail pipeline looking up every sender domain is exactly
// the traffic shape that gets an IP blocked. Being slow here costs nothing: results are
// cached for a day.
func (c *Client) acquire(ctx context.Context, host string) (release func(), err error) {
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	release = func() { <-c.sem }

	c.mu.Lock()
	last := c.hostLast[host]
	now := c.opts.now()
	wait := c.opts.MinInterval - now.Sub(last)
	if wait < 0 {
		wait = 0
	}
	c.hostLast[host] = now.Add(wait)
	c.mu.Unlock()

	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}

// tldOf returns the last label of a domain, which is the key RDAP bootstrap uses. For
// example.co.uk that is "uk": the registry for .uk serves the whole tree beneath it.
func tldOf(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i+1:]
	}
	return name
}
