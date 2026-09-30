// SPDX-License-Identifier: AGPL-3.0-only

package lists

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// The `$list` data Sublime publishes, vendored.
//
// sublime-security/static-files is MIT and carries its own LICENSE in data/. It is the
// same data Sublime's own engine resolves these names against, so vendoring it is what
// makes `$high_trust_sender_root_domains` mean the same thing here as there — and that
// list alone gates 692 corpus rules, the largest single dependency in the corpus after
// the ML classifier.
//
// Everything under 400KB is embedded, which is 22 of the 32 published lists for about a
// megabyte. The other ten are ranked domain tables — tranco at 21MB, umbrella at 35MB,
// majestic at 80MB — and those are fetched on request and cached on disk, because a Go
// module that carries 150MB of CSV is not a library anyone wants to depend on.
//
//go:embed data/manifest.json data/LICENSE data/*.txt data/*.csv
var embedded embed.FS

// manifest is the index static-files publishes alongside the data.
//
// It is load-bearing rather than documentation: the list *identifier* a rule writes is
// frequently not the file name. `$tranco_10k` lives in tranco_top_10k.csv, `$tranco_1m`
// in tranco.csv, `$umbrella_1m` in umbrella_top_1m.csv. Naming lists after their files —
// which is the obvious thing to do, and what this package used to do — silently fails to
// provide four lists that 72 corpus rules use, with no error anywhere.
type manifest struct {
	Lists []manifestEntry `json:"lists"`
}

type manifestEntry struct {
	// Identifier is the name a rule writes after the `$`.
	Identifier string `json:"identifier"`

	// File is where the data lives. Absent for the abuse.ch feeds, which are fetched
	// live rather than published as files.
	File string `json:"file"`

	// Format is "hostname" or empty. Informational; the parse is decided by extension.
	Format string `json:"format"`
}

// Embedded returns a resolver holding every list vendored into this package.
//
// Lists too large to embed are absent rather than empty, so a rule using one reports its
// capability as missing instead of quietly evaluating against nothing. Add them with
// [Resolver.Fetch] or by pointing [Resolver.LoadDir] at a checkout.
func Embedded() (*Resolver, error) {
	r := NewResolver()
	if err := r.loadFS(embedded, "data"); err != nil {
		return nil, err
	}
	return r, nil
}

// MustEmbedded is Embedded for callers that cannot handle a failure. The data is
// compiled in, so a failure means the build is broken rather than the environment.
func MustEmbedded() *Resolver {
	r, err := Embedded()
	if err != nil {
		panic("lists: embedded data is unreadable: " + err.Error())
	}
	return r
}

// LoadDir adds every list in a directory, which is how a caller supplies a full
// static-files checkout including the ranked tables too large to embed.
//
// A manifest.json in the directory maps identifiers to files. Without one, each file
// names its own list, which is right for a directory of hand-written lists and wrong for
// a static-files checkout — so a checkout should always have its manifest.
func (r *Resolver) LoadDir(dir string) error {
	return r.loadFS(dirFS(dir), ".")
}

func (r *Resolver) loadFS(fsys fs.FS, dir string) error {
	byFile := map[string]string{} // file -> identifier
	if raw, err := fs.ReadFile(fsys, path.Join(dir, "manifest.json")); err == nil {
		var m manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("lists: reading manifest: %w", err)
		}
		for _, e := range m.Lists {
			if e.File != "" && e.Identifier != "" {
				byFile[e.File] = e.Identifier
			}
		}
	}

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := path.Ext(entry.Name())
		if ext != ".txt" && ext != ".csv" {
			continue
		}

		name := byFile[entry.Name()]
		if name == "" {
			name = strings.TrimSuffix(entry.Name(), ext)
		}

		raw, err := fs.ReadFile(fsys, path.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		values := parseList(bytes.NewReader(raw), ext == ".csv")
		if len(values) == 0 {
			// An empty list is worse than an absent one: it is *known*, so every
			// membership test against it answers a confident false. static-files ships
			// tenant_domains.txt and org_brand_names.txt empty, as placeholders for data
			// an operator supplies, and those must stay unknown until one does.
			continue
		}
		r.Add(NewSet(name, values))
	}
	return nil
}

// parseList reads one list file. Shared by the embedded data, a checkout on disk, and a
// fetched table, so all three agree on comments, blank lines and CSV rank columns.
func parseList(rd io.Reader, csv bool) []string {
	var out []string
	scanner := bufio.NewScanner(rd)
	// The ranked tables run to a million lines; a larger buffer avoids surprises on a
	// pathological entry rather than on length.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if csv {
			// "1,google.com" — the rank is not the value.
			if _, rest, found := strings.Cut(line, ","); found {
				line = strings.TrimSpace(rest)
			}
		}
		out = append(out, line)
	}
	return out
}

// dirFS adapts a directory path to fs.FS so the embedded data and a checkout on disk go
// through exactly one loader. Two loaders is how the manifest came to be honoured in one
// place and not the other.
func dirFS(dir string) fs.FS { return os.DirFS(dir) }
