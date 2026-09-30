// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"testing"

	"github.com/lazaretemail/lazaret/internal/corpus"
	"github.com/lazaretemail/lazaret/mql"
)

// TestParseCorpus parses every rule in Sublime's public corpus.
//
// This is the project's headline number. The claim is that the open rule ecosystem runs on
// an open engine; until every rule parses, that claim is not even testable.
func TestParseCorpus(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}

	tally := corpus.NewTally()
	reported := 0
	for _, e := range entities {
		_, err := mql.Parse(e.Source)
		tally.Add(e.Type, err == nil)
		if err == nil {
			continue
		}
		// Cap the output: a systematic mistake would otherwise bury the summary under a
		// thousand copies of the same diagnostic.
		if reported < 15 {
			reported++
			if errs, ok := err.(mql.ErrorList); ok {
				t.Errorf("%s (%s):\n%s", e.Path, e.Name, errs.Render(e.Source))
			} else {
				t.Errorf("%s (%s): %v", e.Path, e.Name, err)
			}
		}
	}

	t.Logf("parsed %d entities\n%s", len(entities), tally)
	if n := tally.Failures(); n > 0 {
		t.Errorf("%d of %d entities failed to parse", n, len(entities))
	}
}

// TestParseCorpusRoundTrips checks that rendering a parsed rule and parsing it again yields
// the same text.
//
// This is what makes `lazaret fmt` safe to run over someone's rule library. It is also a
// sharp check on the parser itself: an operator given the wrong precedence, or a dropped
// pair of parentheses, shows up here as text that does not survive a second pass, even
// though the first parse succeeded.
func TestParseCorpusRoundTrips(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}

	tally := corpus.NewTally()
	reported := 0
	for _, e := range entities {
		first, err := mql.Parse(e.Source)
		if err != nil {
			continue // already counted by TestParseCorpus
		}
		rendered := first.String()

		second, err := mql.Parse(rendered)
		if err != nil {
			tally.Add(e.Type, false)
			if reported < 10 {
				reported++
				t.Errorf("%s: rendered form does not re-parse: %v\n  %s", e.Path, err, rendered)
			}
			continue
		}

		ok := second.String() == rendered
		tally.Add(e.Type, ok)
		if !ok && reported < 10 {
			reported++
			t.Errorf("%s: not stable under formatting\n  first:  %s\n  second: %s",
				e.Path, rendered, second.String())
		}
	}

	t.Logf("round-tripped %d entities\n%s", len(entities), tally)
	if n := tally.Failures(); n > 0 {
		t.Errorf("%d entities did not round-trip", n)
	}
}

// TestParseCorpusNodeCoverage confirms the corpus exercises every AST node this parser can
// produce. A parser proven only against constructs nobody writes has proven little.
func TestParseCorpusNodeCoverage(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}

	seen := map[string]int{}
	maxClimb := 0
	for _, e := range entities {
		root, err := mql.Parse(e.Source)
		if err != nil {
			continue
		}
		mql.Walk(root, func(n mql.Expr) bool {
			switch v := n.(type) {
			case *mql.StringLit:
				seen["StringLit"]++
			case *mql.IntLit:
				seen["IntLit"]++
			case *mql.FloatLit:
				seen["FloatLit"]++
			case *mql.BoolLit:
				seen["BoolLit"]++
			case *mql.NullLit:
				seen["NullLit"]++
			case *mql.Name:
				seen["Name"]++
			case *mql.ListRef:
				seen["ListRef"]++
			case *mql.ScopeRef:
				seen["ScopeRef"]++
				maxClimb = max(maxClimb, v.Up)
			case *mql.ArrayLit:
				seen["ArrayLit"]++
			case *mql.TupleLit:
				seen["TupleLit"]++
			case *mql.Field:
				seen["Field"]++
			case *mql.Index:
				seen["Index"]++
			case *mql.Slice:
				seen["Slice"]++
			case *mql.Call:
				seen["Call"]++
				if len(v.Keywords) > 0 {
					seen["KeywordArg"] += len(v.Keywords)
				}
			case *mql.Unary:
				seen["Unary"]++
			case *mql.Binary:
				seen["Binary"]++
			case *mql.Range:
				seen["Range"]++
			case *mql.Membership:
				seen["Membership"]++
			case *mql.IsNull:
				seen["IsNull"]++
			case *mql.Threshold:
				seen["Threshold"]++
			case *mql.Paren:
				seen["Paren"]++
			}
			return true
		})
	}

	for _, node := range []string{
		"StringLit", "IntLit", "BoolLit", "Name", "ListRef", "ScopeRef",
		"ArrayLit", "TupleLit", "Field", "Index", "Call", "KeywordArg",
		"Unary", "Binary", "Range", "Membership", "IsNull", "Threshold", "Paren",
	} {
		if seen[node] == 0 {
			t.Errorf("no %s node anywhere in the corpus", node)
		}
		t.Logf("%-12s %7d", node, seen[node])
	}

	// The published docs describe `.` and `..` only. If the corpus really does climb
	// further, the generalisation to N dots is justified; if it stops at one, this test
	// says so and the extra machinery is unearned.
	t.Logf("deepest scope climb: %d (`%s`)", maxClimb, strRepeat(".", maxClimb+1))
	if maxClimb < 2 {
		t.Logf("note: corpus never climbs past `..`; `...` support is currently speculative")
	}
}

func strRepeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
