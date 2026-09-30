// SPDX-License-Identifier: AGPL-3.0-only

package lists

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// The ranked domain tables, which are too large to vendor.
//
// tranco is 21MB, umbrella 35MB, alexa 12MB and majestic 80MB. Embedding them would put
// 150MB of CSV into a module whose whole point is being small enough to `go get` for rule
// linting, so they are fetched on request and cached on disk instead.
//
// Fetching is opt-in, never implicit, for the same reason RDAP lookups are: a tool run
// over a message should not reach the network because of what the message happened to
// contain. A list that has not been fetched stays *unknown* rather than empty, so a rule
// using one reports an unresolvable capability instead of a confident no-match.

// DefaultStaticFilesBase is where sublime-security publishes the data. MIT licensed; see
// data/LICENSE, vendored alongside the embedded lists.
const DefaultStaticFilesBase = "https://raw.githubusercontent.com/sublime-security/static-files/main/"

// maxListBytes caps a single download. majestic_million is the largest published table
// at 80MB; the ceiling is set well above it so a legitimate list is never truncated, and
// low enough that a redirect to something unbounded is refused rather than streamed to
// disk forever.
const maxListBytes = 256 << 20

// DefaultCacheTTL is how long a cached table is reused. These are reputation rankings
// that move slowly, and re-downloading 80MB to re-answer "is this domain popular" is not
// a good trade.
const DefaultCacheTTL = 7 * 24 * time.Hour

// Fetcher downloads the published lists that are too large to embed.
type Fetcher struct {
	// BaseURL is where the files live. Overridden in tests.
	BaseURL string

	// CacheDir is where downloads are kept. Empty means os.UserCacheDir/lazaret/lists.
	CacheDir string

	// TTL is how long a cached copy is reused. Zero means DefaultCacheTTL.
	TTL time.Duration

	// Client is the HTTP client. Nil means a client with a generous timeout, because
	// these are large files on a possibly slow link.
	Client *http.Client
}

func (f *Fetcher) base() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return DefaultStaticFilesBase
}

func (f *Fetcher) ttl() time.Duration {
	if f.TTL > 0 {
		return f.TTL
	}
	return DefaultCacheTTL
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

func (f *Fetcher) cacheDir() (string, error) {
	if f.CacheDir != "" {
		return f.CacheDir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "lazaret", "lists"), nil
}

// Fetchable reports the lists this fetcher can supply that are not already embedded —
// the identifiers, as a rule writes them.
func Fetchable() []string {
	var out []string
	for _, e := range publishedLists() {
		if e.File == "" {
			continue // an abuse.ch feed, not a file
		}
		if _, err := embedded.Open(path.Join("data", e.File)); err == nil {
			continue // already vendored
		}
		out = append(out, e.Identifier)
	}
	sortStrings(out)
	return out
}

// publishedLists reads the vendored manifest. It describes every list Sublime publishes,
// including the ones whose data is too large to vendor, which is what lets this package
// know that `$tranco_1m` is a real list it does not currently hold.
func publishedLists() []manifestEntry {
	raw, err := embedded.ReadFile("data/manifest.json")
	if err != nil {
		return nil
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m.Lists
}

// Fetch downloads the named lists and adds them to the resolver, using a cached copy
// when one is fresh enough. Names are identifiers as a rule writes them, without the `$`.
//
// An empty list of names fetches everything publishable that is not already embedded.
func (r *Resolver) Fetch(ctx context.Context, f *Fetcher, names ...string) error {
	if f == nil {
		f = &Fetcher{}
	}
	if len(names) == 0 {
		names = Fetchable()
	}

	byID := map[string]manifestEntry{}
	for _, e := range publishedLists() {
		byID[e.Identifier] = e
	}

	for _, name := range names {
		entry, ok := byID[name]
		if !ok {
			return fmt.Errorf("lists: %q is not a published list", name)
		}
		if entry.File == "" {
			// abuse.ch feeds have no published file. They are a threat-intel provider's
			// job, not a static download, and stay unknown here.
			continue
		}
		values, err := f.load(ctx, entry.File)
		if err != nil {
			return fmt.Errorf("lists: fetching %s: %w", name, err)
		}
		if len(values) > 0 {
			r.Add(NewSet(name, values))
		}
	}
	return nil
}

// load returns a list's values, from cache when fresh and from the network otherwise.
func (f *Fetcher) load(ctx context.Context, file string) ([]string, error) {
	dir, err := f.cacheDir()
	if err != nil {
		return nil, err
	}
	cached := filepath.Join(dir, file)

	if info, err := os.Stat(cached); err == nil && time.Since(info.ModTime()) < f.ttl() {
		fh, err := os.Open(cached)
		if err == nil {
			defer fh.Close()
			return parseList(fh, strings.HasSuffix(file, ".csv")), nil
		}
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	url := f.base() + file
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}

	// Written to a temporary file and renamed, so an interrupted download cannot leave a
	// truncated table in the cache to be read back as authoritative next time.
	tmp, err := os.CreateTemp(dir, ".partial-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, maxListBytes)); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), cached); err != nil {
		return nil, err
	}

	fh, err := os.Open(cached)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return parseList(fh, strings.HasSuffix(file, ".csv")), nil
}
