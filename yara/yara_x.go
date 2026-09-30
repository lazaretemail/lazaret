// SPDX-License-Identifier: AGPL-3.0-only

//go:build yara

package yara

import (
	"fmt"
	"strings"
	"sync"
	"time"

	yarax "github.com/VirusTotal/yara-x/go"
)

// The real scanner, built only with -tags yara.
//
// YARA-X rather than the original libyara: it is VirusTotal's own Rust rewrite, it is
// what new signatures are written against, and it avoids a C library with a long history
// of parser bugs in a component whose entire job is reading hostile files.

// scanTimeout bounds one scan.
//
// Signatures come from feeds, and a pathological one over a large attachment can run for
// a very long time. A partial scan reports what it found and flags the timeout, which is
// more useful than either hanging or discarding the matches already made.
const scanTimeout = 30 * time.Second

func available() bool { return true }

type xScanner struct {
	rules *yarax.Rules
	count int

	// YARA-X scanners are not safe for concurrent use, but compiled rules are. One
	// scanner per goroutine, sharing the rules, is the intended pattern.
	pool sync.Pool
}

func compile(sources map[string]string) (Scanner, error) {
	compiler, err := yarax.NewCompiler(
		// A feed can carry a signature whose pattern is quadratic. Refusing those at
		// compile time is better than discovering one in production.
		yarax.ErrorOnSlowPattern(true),
		yarax.RelaxedReSyntax(true),
	)
	if err != nil {
		return nil, fmt.Errorf("yara: creating compiler: %w", err)
	}
	defer compiler.Destroy()

	var problems []string
	compiled := 0
	for _, name := range sortedNames(sources) {
		// One namespace per file, so that two feeds defining the same rule identifier do
		// not collide.
		compiler.NewNamespace(name)
		if err := compiler.AddSource(sources[name], yarax.WithOrigin(name)); err != nil {
			// A broken signature file should not cost the deployment every other
			// signature, so it is recorded and skipped — the same posture the rule loader
			// takes for MQL.
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		compiled++
	}
	if compiled == 0 {
		return nil, fmt.Errorf("yara: no signatures compiled:\n  %s", strings.Join(problems, "\n  "))
	}

	rules := compiler.Build()
	s := &xScanner{rules: rules, count: rules.Count()}
	s.pool.New = func() any { return yarax.NewScanner(rules) }
	return s, nil
}

func (s *xScanner) Count() int { return s.count }

func (s *xScanner) Scan(data []byte) (*Result, error) {
	scanner := s.pool.Get().(*yarax.Scanner)
	defer s.pool.Put(scanner)

	scanner.SetTimeout(scanTimeout)

	results, err := scanner.Scan(data)
	if err != nil {
		// A timeout still leaves whatever matched, so it is a flag rather than a failure.
		if strings.Contains(strings.ToLower(err.Error()), "timeout") {
			return &Result{Flags: []string{"timeout"}}, nil
		}
		return nil, fmt.Errorf("yara: %w", err)
	}

	out := &Result{}
	for _, rule := range results.MatchingRules() {
		m := Match{
			Name:      rule.Identifier(),
			Namespace: rule.Namespace(),
			Tags:      rule.Tags(),
		}
		if meta := rule.Metadata(); len(meta) > 0 {
			m.Meta = make(map[string]string, len(meta))
			for _, entry := range meta {
				// Metadata values are strings, integers or booleans; rules compare them
				// as text, so they are normalised here rather than at every call site.
				m.Meta[entry.Identifier()] = fmt.Sprint(entry.Value())
			}
		}
		out.Matches = append(out.Matches, m)
	}
	return out, nil
}

func (s *xScanner) Close() error {
	s.rules.Destroy()
	return nil
}
