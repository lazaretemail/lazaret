// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/lists"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/orgconfig"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Resolving named lists, from five different kinds of source, behind one interface.
//
// The corpus references 32 lists and a rule cannot tell them apart — nor should it.
// What differs is where the contents come from:
//
//	embedded  18 lists compiled into the binary from sublime-security/static-files
//	fetch     4 ranked domain tables too large to embed, downloaded and cached
//	feed      2 abuse.ch feeds, which change hourly
//	org       5 lists that are facts about the organisation
//	history   4 derived from what this deployment has actually seen
//
// Every one of them is then subject to operator overrides, which are applied last and
// never lost to a refresh.

// staticFilesBase is where the published data lives. MIT; see lists/data/LICENSE.
const staticFilesBase = "https://raw.githubusercontent.com/sublime-security/static-files/main/"

// defaultLists is the seed, and it is deliberately exhaustive: every list any rule in
// the public corpus references appears here, so a fresh deployment has a row for each
// and an operator can see the whole surface rather than discovering a missing list
// when a rule reports indeterminate.
var defaultLists = []store.ListConfig{
	// Ranked domain tables. Too large to embed — tranco is 21MB, umbrella 35MB,
	// majestic 80MB — so they are fetched and cached. Weekly: these are reputation
	// rankings that move slowly, and re-downloading 35MB to re-answer "is this domain
	// popular" is not a good trade.
	{Name: "tranco_1m", Source: store.SourceFetch, URL: staticFilesBase + "tranco.csv",
		Format: "csv2", Enabled: true, RefreshEvery: 7 * 24 * time.Hour,
		Description: "The Tranco top million domains. Popularity, used as a weak trust signal."},
	{Name: "tranco_50k", Source: store.SourceFetch, URL: staticFilesBase + "tranco_top_50k.csv",
		Format: "csv2", Enabled: true, RefreshEvery: 7 * 24 * time.Hour,
		Description: "The Tranco top 50,000."},
	{Name: "umbrella_1m", Source: store.SourceFetch, URL: staticFilesBase + "umbrella_top_1m.csv",
		Format: "csv2", Enabled: true, RefreshEvery: 7 * 24 * time.Hour,
		Description: "Cisco Umbrella's top million, ranked by DNS traffic."},
	// Cloudflare Radar's top million, the living successor to Alexa.
	//
	// Off unless an API token is configured: Radar's dataset endpoints need one,
	// though a free Cloudflare account provides it. Set the token as the auth header
	// on this list and enable it.
	{Name: "cloudflare_radar_1m", Source: store.SourceRadar, Enabled: false,
		RefreshEvery: 7 * 24 * time.Hour, FallbackTo: "tranco_1m",
		Description: "Cloudflare Radar's top million domains, by DNS traffic. Needs a Cloudflare API token; falls back to Tranco without one."},

	// Alexa was discontinued in 2022, so there is no current data to fetch and two
	// corpus rules read the list. Left enabled but with nothing of its own, so it
	// answers from the chain below: Radar where a token exists, Tranco otherwise.
	//
	// A substitution rather than a silence, and deliberately visible as one — the
	// settings page shows what each list is actually answering from. The rules that
	// read it are asking "is this a popular domain", which Tranco answers better
	// than a four-year-old Alexa snapshot would.
	{Name: "alexa_1m", Source: store.SourceFetch, Enabled: true,
		RefreshEvery: 30 * 24 * time.Hour, FallbackTo: "cloudflare_radar_1m",
		Description: "Alexa's top million. The ranking was discontinued in 2022, so this answers from Cloudflare Radar, or Tranco."},
	{Name: "majestic_million", Source: store.SourceFetch, URL: staticFilesBase + "majestic_million.csv",
		Format: "csv3", Enabled: false, RefreshEvery: 7 * 24 * time.Hour,
		Description: "Majestic's top million, by referring subnets. 80MB; off by default."},

	// Threat intel. Hourly, because a URL blocked today was registered yesterday, and
	// a feed refreshed daily is a feed that misses the window that matters.
	//
	// Sublime's lists are filtered to "trusted reporters" — a distinction their
	// platform makes and abuse.ch's public export does not expose. These therefore
	// carry the full feed, which is broader: more coverage, and more chance of a
	// reporter nobody vetted. Recorded as a decision rather than hidden.
	{Name: "abuse_ch_urlhaus_domains_trusted_reporters", Source: store.SourceFeed,
		URL: "https://urlhaus.abuse.ch/downloads/text/", Format: "lines", Enabled: true,
		RefreshEvery: time.Hour,
		Description: "URLhaus malware-distribution hosts. The full feed by default: abuse.ch does not publish " +
			"a trusted-reporter subset. Set a filter to narrow it."},
	{Name: "abuse_ch_malwarebazaar_sha256_trusted_reporters", Source: store.SourceFeed,
		URL: "https://bazaar.abuse.ch/export/txt/sha256/recent/", Format: "lines", Enabled: true,
		RefreshEvery: time.Hour,
		Description:  "MalwareBazaar recent SHA-256 hashes. The recent export rather than the full one, which is hundreds of megabytes."},

	// Facts about the organisation. Filled from the tenant's configuration.
	{Name: "org_domains", Source: store.SourceOrg, Enabled: true,
		Description: "Your verified sending domains. type.inbound is defined against these, so 145 rules depend on it."},
	{Name: "tenant_domains", Source: store.SourceOrg, Enabled: true,
		Description: "Domains belonging to this tenant. Usually the same as org_domains."},
	{Name: "org_slds", Source: store.SourceOrg, Enabled: true,
		Description: "The second-level parts of your domains, for lookalike detection."},
	{Name: "org_vips", Source: store.SourceOrg, Enabled: true,
		Description: "People worth impersonating: executives, finance, HR."},
	{Name: "org_display_names", Source: store.SourceOrg, Enabled: true,
		Description: "Display names worth impersonating."},

	// Derived from what this deployment has seen.
	{Name: "sender_emails", Source: store.SourceHistory, Enabled: true,
		Description: "Addresses that have written to you before."},
	{Name: "sender_domains", Source: store.SourceHistory, Enabled: true,
		Description: "Domains that have written to you before."},
	{Name: "recipient_emails", Source: store.SourceHistory, Enabled: true,
		Description: "Your own recipient addresses, learned from delivered mail."},
	{Name: "recipient_domains", Source: store.SourceHistory, Enabled: true,
		Description: "Domains you receive mail for."},
}

// ListManager resolves every named list and keeps the remote ones fresh.
type ListManager struct {
	store    *store.Store
	tenant   string
	embedded *lists.Resolver
	client   *http.Client

	mu       sync.RWMutex
	resolver *lists.Resolver
	org      *orgconfig.Config

	// onChange is called with the lists whose contents actually changed in a refresh.
	//
	// A list gaining a domain is the same event as a feed gaining a rule: the engine
	// now knows something it did not know when yesterday's mail was judged. Only the
	// lists that changed, and only when they changed — a refresh that re-downloads
	// the same two million rows is not new intelligence.
	onChange func(context.Context, []string)
}

// OnChange registers what to do when a refresh changes a list's contents. Optional.
func (m *ListManager) OnChange(fn func(context.Context, []string)) { m.onChange = fn }

// NewListManager seeds the defaults and builds the first resolver.
func NewListManager(ctx context.Context, st *store.Store, tenant string, org *orgconfig.Config) (*ListManager, error) {
	embedded, err := lists.Embedded()
	if err != nil {
		return nil, err
	}

	m := &ListManager{
		store: st, tenant: tenant, embedded: embedded, org: org,
		client: &http.Client{Timeout: 15 * time.Minute},
	}

	// Every embedded list gets a row too, so the settings page shows the whole
	// surface rather than only the parts that need configuring.
	for _, name := range embedded.Names() {
		if err := st.EnsureList(ctx, tenant, store.ListConfig{
			Name: name, Source: store.SourceEmbedded, Enabled: true,
			Description: "Published by sublime-security/static-files, compiled into this binary.",
		}); err != nil {
			return nil, err
		}
	}
	for _, c := range defaultLists {
		if err := st.EnsureList(ctx, tenant, c); err != nil {
			return nil, err
		}
	}

	if err := m.Rebuild(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// ListManager implements mql.ListResolver itself, rather than handing out a snapshot.
//
// That matters: a snapshot taken at start-up would never see a refresh, an operator
// override, or a newly added mailbox. Every lookup goes through the current resolver,
// which is swapped wholesale on a rebuild so a half-updated list is never visible to
// an evaluation in progress.
var _ mql.ListResolver = (*ListManager)(nil)

// Contains implements mql.ListResolver.
func (m *ListManager) Contains(ctx context.Context, name string, value mql.Value, fold bool) (found, known bool) {
	m.mu.RLock()
	r := m.resolver
	m.mu.RUnlock()
	if r == nil {
		return false, false
	}
	return r.Contains(ctx, name, value, fold)
}

// Elements implements mql.ListResolver.
func (m *ListManager) Elements(ctx context.Context, name string) ([]mql.Value, bool) {
	m.mu.RLock()
	r := m.resolver
	m.mu.RUnlock()
	if r == nil {
		return nil, false
	}
	return r.Elements(ctx, name)
}

// Known reports whether a list can be resolved at all, for the coverage view.
func (m *ListManager) Known(name string) bool {
	m.mu.RLock()
	r := m.resolver
	m.mu.RUnlock()
	return r != nil && r.Known(name)
}

// Rebuild recomposes every list from its source and applies the overrides.
func (m *ListManager) Rebuild(ctx context.Context) error {
	configs, err := m.store.Lists(ctx, m.tenant)
	if err != nil {
		return err
	}
	overrides, err := m.store.AllOverrides(ctx, m.tenant)
	if err != nil {
		return err
	}

	next := lists.NewResolver()
	for _, c := range configs {
		if !c.Enabled {
			// A disabled list is *unknown*, not empty. Empty would answer a confident
			// "not a member" to every rule that uses it, which silently changes
			// verdicts; unknown makes those rules report indeterminate, which is the
			// honest answer to "you turned this off".
			continue
		}

		base, err := m.baseFor(ctx, c)
		if err != nil {
			log.Printf("lists: %s: %v", c.Name, err)
			continue
		}
		values := applyOverrides(base, overrides[c.Name])
		if len(values) == 0 {
			// Nothing of its own. A list can name another to stand in for it, which
			// is how a list whose upstream no longer exists still answers.
			if fb := m.resolveFallback(ctx, c, configs, overrides, 0); len(fb) > 0 {
				log.Printf("lists: %s is empty, answering from %s", c.Name, c.FallbackTo)
				next.Add(lists.NewSet(c.Name, fb))
				continue
			}
			// Same reasoning as a disabled list: one that resolves to nothing stays
			// unknown rather than becoming a confident negative.
			continue
		}
		next.Add(lists.NewSet(c.Name, values))
	}

	m.mu.Lock()
	m.resolver = next
	m.mu.Unlock()
	return nil
}

// resolveFallback follows a list's fallback chain.
//
// Bounded, and cycle-safe by depth rather than by a visited set: the chains are two
// or three long by construction and a misconfiguration should stop rather than be
// clever about it.
func (m *ListManager) resolveFallback(ctx context.Context, c store.ListConfig, all []store.ListConfig, overrides map[string][]store.ListOverride, depth int) []string {
	if c.FallbackTo == "" || depth > 4 {
		return nil
	}
	for _, other := range all {
		if other.Name != c.FallbackTo || !other.Enabled {
			continue
		}
		base, err := m.baseFor(ctx, other)
		if err != nil {
			return nil
		}
		if vals := applyOverrides(base, overrides[other.Name]); len(vals) > 0 {
			return vals
		}
		return m.resolveFallback(ctx, other, all, overrides, depth+1)
	}
	return nil
}

// baseFor returns a list's contents before overrides.
func (m *ListManager) baseFor(ctx context.Context, c store.ListConfig) ([]string, error) {
	switch c.Source {
	case store.SourceEmbedded:
		vals, _ := m.embedded.Elements(ctx, c.Name)
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			if s, ok := v.AsString(); ok {
				out = append(out, s)
			}
		}
		return out, nil

	case store.SourceFetch, store.SourceFeed, store.SourceRadar:
		return m.store.CachedList(ctx, m.tenant, c.Name)

	case store.SourceOrg:
		return m.orgValues(c.Name), nil

	case store.SourceHistory:
		return m.historyValues(ctx, c.Name)

	default: // manual: overrides are the whole content
		return nil, nil
	}
}

func (m *ListManager) orgValues(name string) []string {
	if m.org == nil {
		return nil
	}
	switch name {
	case "org_domains", "tenant_domains":
		return m.org.Domains
	case "org_slds":
		var out []string
		for _, d := range m.org.Domains {
			if sld, _, found := strings.Cut(d, "."); found && sld != "" {
				out = append(out, sld)
			}
		}
		return out
	case "org_vips":
		var out []string
		for _, v := range m.org.VIPs {
			if v.Email != "" {
				out = append(out, v.Email)
			}
		}
		return out
	case "org_display_names":
		var out []string
		for _, v := range m.org.VIPs {
			if v.DisplayName != "" {
				out = append(out, v.DisplayName)
			}
		}
		return append(out, m.org.DisplayNames...)
	}
	return nil
}

func (m *ListManager) historyValues(ctx context.Context, name string) ([]string, error) {
	switch name {
	case "sender_emails":
		return m.store.SenderList(ctx, m.tenant, "email")
	case "sender_domains":
		return m.store.SenderList(ctx, m.tenant, "domain")
	case "recipient_emails":
		// Configured mailboxes as well as observed recipients. A fresh deployment
		// already knows which mailboxes it collects from, and waiting for mail to
		// arrive before learning that leaves 45 rules blind on day one.
		seen, err := m.store.RecipientList(ctx, m.tenant, "email")
		if err != nil {
			return nil, err
		}
		configured, err := m.store.RecipientAddresses(ctx, m.tenant)
		if err != nil {
			return seen, nil
		}
		return append(seen, configured...), nil
	case "recipient_domains":
		seen, err := m.store.RecipientList(ctx, m.tenant, "domain")
		if err != nil {
			return nil, err
		}
		configured, err := m.store.RecipientAddresses(ctx, m.tenant)
		if err != nil {
			return seen, nil
		}
		for _, a := range configured {
			if _, d, found := strings.Cut(a, "@"); found {
				seen = append(seen, d)
			}
		}
		return seen, nil
	}
	return nil, nil
}

// applyOverrides adds and removes what an operator configured.
//
// Excludes win over includes and over the base, because an exclusion is someone
// saying "this specific entry is wrong for us" and that should not be undone by the
// same value also appearing upstream.
func applyOverrides(base []string, overrides []store.ListOverride) []string {
	excluded := map[string]bool{}
	for _, o := range overrides {
		if o.Kind == "exclude" {
			excluded[strings.ToLower(strings.TrimSpace(o.Value))] = true
		}
	}

	seen := map[string]bool{}
	out := make([]string, 0, len(base)+len(overrides))
	add := func(v string) {
		k := strings.ToLower(strings.TrimSpace(v))
		if k == "" || excluded[k] || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, v)
	}
	for _, v := range base {
		add(v)
	}
	for _, o := range overrides {
		if o.Kind == "include" {
			add(o.Value)
		}
	}
	return out
}

// RefreshDue downloads any fetch or feed list whose contents are stale.
func (m *ListManager) RefreshDue(ctx context.Context) {
	due, err := m.store.DueForRefresh(ctx, m.tenant)
	if err != nil {
		log.Printf("lists: checking what needs refreshing: %v", err)
		return
	}
	if len(due) == 0 {
		return
	}

	changed := false
	var grew []string
	for _, c := range due {
		n, err := m.refreshOne(ctx, c)
		if err != nil {
			log.Printf("lists: refreshing %s: %v", c.Name, err)
			// The previous contents stay. An upstream outage degrading to stale data
			// is far better than degrading to an empty list, which a rule reads as a
			// confident "not a member".
			_ = m.store.NoteListError(ctx, m.tenant, c.Name, err)
			continue
		}
		log.Printf("lists: %s refreshed, %d entries", c.Name, n)
		changed = true
		// Only a list that gained entries is new intelligence. One that shrank or
		// stayed the same cannot make a rule match something it did not match
		// before, so sweeping for it would be work with no possible finding.
		if int64(n) > c.EntryCount {
			grew = append(grew, c.Name)
		}
	}
	if changed {
		if err := m.Rebuild(ctx); err != nil {
			log.Printf("lists: rebuilding after refresh: %v", err)
		}
	}
	// After the rebuild, so a sweep resolves the list it was told about rather than
	// the one that was loaded before it.
	if len(grew) > 0 && m.onChange != nil {
		go m.onChange(context.WithoutCancel(ctx), grew)
	}
}

func (m *ListManager) refreshOne(ctx context.Context, c store.ListConfig) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	if c.Source == store.SourceRadar {
		url, err := m.radarDownloadURL(ctx, c)
		if err != nil {
			return 0, err
		}
		c.URL = url
		// The signed URL carries its own authorisation; sending the API token to it
		// as well would hand a Cloudflare credential to whatever host the signed URL
		// happens to name.
		c.AuthHeader = ""
		c.Format = "csv1"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return 0, err
	}
	if c.AuthHeader != "" {
		// abuse.ch now requires an Auth-Key on some endpoints. Stored per list so a
		// deployment can supply one without a rebuild.
		name, value, found := strings.Cut(c.AuthHeader, ":")
		if !found {
			name, value = "Auth-Key", c.AuthHeader
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s: %s", c.URL, resp.Status)
	}

	var body io.Reader = io.LimitReader(resp.Body, 512<<20)
	if c.Filter != "" {
		re, err := regexp.Compile(c.Filter)
		if err != nil {
			return 0, fmt.Errorf("the filter for %s does not compile: %w", c.Name, err)
		}
		body = filterLines(body, re)
	}
	values, err := parseListBody(body, c.Format)
	if err != nil {
		return 0, err
	}
	if len(values) == 0 {
		// Refusing an empty download rather than storing it. A feed that answers 200
		// with nothing — a maintenance page, a rate limit, an expired key — would
		// otherwise replace a working list with silence.
		return 0, fmt.Errorf("the download was empty; keeping the previous contents")
	}
	return len(values), m.store.ReplaceCache(ctx, m.tenant, c.Name, values)
}

// radarDownloadURL asks Cloudflare Radar for a signed URL to its top-domains CSV.
//
// Two calls rather than one download: Radar publishes ranking data as *datasets*, so
// the dataset for the size wanted has to be found first and then exchanged for a
// short-lived URL. The chart attachment link the web UI uses is not an alternative —
// it sits behind a bot challenge and answers a server with an HTML interstitial.
//
// A Cloudflare API token is required, which is why this list ships disabled. A free
// account provides one, and the token goes in the list's auth header.
func (m *ListManager) radarDownloadURL(ctx context.Context, c store.ListConfig) (string, error) {
	if c.AuthHeader == "" {
		return "", fmt.Errorf("Cloudflare Radar needs an API token; set one as this list's auth header")
	}
	token := c.AuthHeader
	if _, v, found := strings.Cut(c.AuthHeader, ":"); found {
		token = strings.TrimSpace(v)
	}
	token = strings.TrimPrefix(token, "Bearer ")

	get := func(url string, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := m.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return fmt.Errorf("cloudflare radar: %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}

	var datasets struct {
		Success bool `json:"success"`
		Result  struct {
			Datasets []struct {
				ID          int    `json:"id"`
				Alias       string `json:"alias"`
				Title       string `json:"title"`
				Description string `json:"description"`
			} `json:"datasets"`
		} `json:"result"`
	}
	if err := get("https://api.cloudflare.com/client/v4/radar/datasets?datasetType=RANKING_BUCKET&limit=100", &datasets); err != nil {
		return "", err
	}

	// The million-domain bucket. Matched on the alias, which names the bucket size,
	// rather than on position in the list — the order is not documented as stable.
	id := 0
	for _, d := range datasets.Result.Datasets {
		if strings.Contains(d.Alias, "1000000") || strings.Contains(d.Title, "1,000,000") {
			id = d.ID
			break
		}
	}
	if id == 0 {
		return "", fmt.Errorf("cloudflare radar published no top-1,000,000 ranking dataset")
	}

	var dl struct {
		Result struct {
			Dataset struct {
				URL string `json:"url"`
			} `json:"dataset"`
		} `json:"result"`
	}
	if err := get(fmt.Sprintf("https://api.cloudflare.com/client/v4/radar/datasets/download?datasetId=%d", id), &dl); err != nil {
		return "", err
	}
	if dl.Result.Dataset.URL == "" {
		return "", fmt.Errorf("cloudflare radar returned no download url for dataset %d", id)
	}
	return dl.Result.Dataset.URL, nil
}

// filterLines keeps only the lines a pattern matches.
//
// Applied to the raw line before the value is extracted, so a pattern can test
// columns the list format is about to discard — which is the point for the abuse.ch
// feeds, where the reporter and tags live in columns the rules never see.
func filterLines(r io.Reader, re *regexp.Regexp) io.Reader {
	var out bytes.Buffer
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		line := sc.Text()
		// Comments are kept so the parser can skip them as it normally would,
		// rather than having the filter decide what a comment is.
		if strings.HasPrefix(strings.TrimSpace(line), "#") || re.MatchString(line) {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return &out
}

// parseListBody reads the shapes these sources actually publish.
func parseListBody(r io.Reader, format string) ([]string, error) {
	switch format {
	case "csv1", "csv2", "csv3":
		col := map[string]int{"csv1": 0, "csv2": 1, "csv3": 2}[format]
		rd := csv.NewReader(r)
		rd.FieldsPerRecord = -1
		rd.ReuseRecord = true
		var out []string
		for {
			rec, err := rd.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				// One malformed row does not fail a million-line table.
				continue
			}
			if col < len(rec) {
				if v := strings.TrimSpace(rec[col]); v != "" {
					out = append(out, v)
				}
			}
		}
		return out, nil

	default: // lines
		var out []string
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			// abuse.ch prefixes its exports with a comment block.
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// URLhaus publishes full URLs; rules match hosts.
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				if host := hostOf(line); host != "" {
					out = append(out, host)
					continue
				}
			}
			out = append(out, strings.Trim(line, `"`))
		}
		return out, sc.Err()
	}
}

func hostOf(rawURL string) string {
	rest := rawURL
	if _, after, found := strings.Cut(rest, "://"); found {
		rest = after
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if _, after, found := strings.Cut(rest, "@"); found {
		rest = after
	}
	if host, _, found := strings.Cut(rest, ":"); found {
		rest = host
	}
	return strings.ToLower(rest)
}

// RefreshNow downloads one list immediately, for an operator who does not want to
// wait for the schedule.
func (m *ListManager) RefreshNow(ctx context.Context, c store.ListConfig) {
	n, err := m.refreshOne(ctx, c)
	if err != nil {
		log.Printf("lists: refreshing %s: %v", c.Name, err)
		_ = m.store.NoteListError(ctx, m.tenant, c.Name, err)
		return
	}
	log.Printf("lists: %s refreshed on request, %d entries", c.Name, n)
	if err := m.Rebuild(ctx); err != nil {
		log.Printf("lists: rebuild: %v", err)
	}
}

// RefreshLoop keeps the remote lists current.
func (m *ListManager) RefreshLoop(ctx context.Context, every time.Duration) {
	m.RefreshDue(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.RefreshDue(ctx)
		}
	}
}

// RebuildLoop recomposes the history-derived lists periodically.
//
// Separate from the refresh loop and much more frequent: sender_emails changes with
// every message, and a list of known correspondents that lags by a day is a list that
// treats yesterday's colleague as a stranger.
func (m *ListManager) RebuildLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Rebuild(ctx); err != nil {
				log.Printf("lists: rebuild: %v", err)
			}
		}
	}
}

// SetOrg updates the organisation configuration and recomposes.
func (m *ListManager) SetOrg(ctx context.Context, org *orgconfig.Config) error {
	m.mu.Lock()
	m.org = org
	m.mu.Unlock()
	return m.Rebuild(ctx)
}
