// SPDX-License-Identifier: AGPL-3.0-only

// Package corpus loads Sublime's public rule corpus for compatibility testing.
//
// The project's central claim — that the open rule ecosystem runs on this engine — is only
// worth making if it is measured, so the corpus is a test fixture rather than an
// afterthought. Every stage of the pipeline is graded against it: how many rules lex, parse,
// type-check and evaluate.
//
// The corpus is not vendored. It is MIT-licensed and could be, but it is 3.5 MB of rules
// that change weekly upstream, and pinning a copy would quietly turn a compatibility claim
// about the live ecosystem into one about a snapshot. Tests skip when it is absent.
package corpus

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// EnvVar names the environment variable holding a path to a sublime-rules checkout.
const EnvVar = "LAZARET_CORPUS"

// Entity is one YAML file from the corpus.
//
// Upstream uses five values for Type, only two of which their published JSON schema
// mentions: "rule" and "query" are documented, while "dlp", "exclusion" and "triage_rule"
// appear only in the corpus itself.
type Entity struct {
	// Path is relative to the corpus root, for use in test names and failure messages.
	Path string

	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Source string `yaml:"source"`
	ID     string `yaml:"id"`
}

// Dir returns the corpus root, or "" if it is not available.
//
// It looks at $LAZARET_CORPUS first, then at a sibling checkout, which is where a
// contributor following the README would naturally put one.
func Dir() string {
	if dir := os.Getenv(EnvVar); dir != "" {
		if isCorpus(dir) {
			return dir
		}
		return ""
	}
	for _, guess := range []string{
		"../testdata/sublime-rules",
		"../../testdata/sublime-rules",
		"../sublime-rules",
	} {
		if isCorpus(guess) {
			return guess
		}
	}
	return ""
}

func isCorpus(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, "detection-rules"))
	return err == nil && fi.IsDir()
}

// SkipReason explains why corpus tests cannot run, or "" when they can.
func SkipReason() string {
	if Dir() != "" {
		return ""
	}
	return fmt.Sprintf(
		"rule corpus not found; set %s to a checkout of github.com/sublime-security/sublime-rules",
		EnvVar,
	)
}

// Load reads every rule entity under dir.
//
// Files that are not rule entities are skipped rather than reported: the corpus also holds
// GitHub workflows, raw .eml samples and .yar signatures, none of which carry MQL.
func Load(dir string) ([]Entity, error) {
	var out []Entity

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// .github holds CI workflows that parse as YAML but are not rules.
			if name := d.Name(); name == ".git" || name == ".github" {
				return fs.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var e Entity
		if err := yaml.Unmarshal(raw, &e); err != nil {
			// Not every YAML file here is an entity; a decode failure means "not ours".
			return nil
		}
		if e.Source == "" || e.Type == "" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		e.Path = filepath.ToSlash(rel)
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no rule entities found under %s", dir)
	}
	return out, nil
}

// Tally counts outcomes per entity type, so results can be reported the way the corpus is
// organised rather than as one undifferentiated number.
type Tally struct {
	Total map[string]int
	Pass  map[string]int
}

func NewTally() *Tally {
	return &Tally{Total: map[string]int{}, Pass: map[string]int{}}
}

func (t *Tally) Add(entityType string, ok bool) {
	t.Total[entityType]++
	if ok {
		t.Pass[entityType]++
	}
}

// Failures returns the number of entities that did not pass.
func (t *Tally) Failures() int {
	var n int
	for typ, total := range t.Total {
		n += total - t.Pass[typ]
	}
	return n
}

// String renders the tally as a table, ordered by type name.
func (t *Tally) String() string {
	types := make([]string, 0, len(t.Total))
	for typ := range t.Total {
		types = append(types, typ)
	}
	// Small, fixed-size input; insertion order does not matter beyond determinism.
	for i := 1; i < len(types); i++ {
		for j := i; j > 0 && types[j] < types[j-1]; j-- {
			types[j], types[j-1] = types[j-1], types[j]
		}
	}

	var b strings.Builder
	var allTotal, allPass int
	for _, typ := range types {
		total, pass := t.Total[typ], t.Pass[typ]
		allTotal, allPass = allTotal+total, allPass+pass
		fmt.Fprintf(&b, "  %-14s %5d/%-5d %6.2f%%\n", typ, pass, total, percent(pass, total))
	}
	fmt.Fprintf(&b, "  %-14s %5d/%-5d %6.2f%%", "TOTAL", allPass, allTotal, percent(allPass, allTotal))
	return b.String()
}

func percent(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}
