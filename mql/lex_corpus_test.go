// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"testing"

	"github.com/lazaretemail/lazaret/internal/corpus"
	"github.com/lazaretemail/lazaret/mql"
)

// TestLexCorpus lexes every rule in Sublime's public corpus.
//
// Lexing is the stage where a wrong assumption is cheapest to find and most expensive to
// miss: a mis-scanned string terminator does not fail loudly, it silently swallows the rest
// of a rule and changes what that rule matches. Anything less than 100% here is a bug in
// this package, never in the corpus.
func TestLexCorpus(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}

	tally := corpus.NewTally()
	for _, e := range entities {
		lx := mql.NewLexer(e.Source)
		toks := lx.Tokens()
		errs := lx.Errors()

		ok := len(errs) == 0
		tally.Add(e.Type, ok)
		if !ok {
			t.Errorf("%s (%s):\n%s", e.Path, e.Name, errs.Sorted().Render(e.Source))
			continue
		}
		// A source that lexes to nothing but EOF means the scanner consumed the rule
		// without producing it — a silent failure the error list would not catch.
		if len(toks) < 2 {
			t.Errorf("%s: lexed to %d tokens, want at least one before EOF", e.Path, len(toks))
		}
	}

	t.Logf("lexed %d entities\n%s", len(entities), tally)
	if n := tally.Failures(); n > 0 {
		t.Errorf("%d entities failed to lex", n)
	}
}

// TestLexCorpusTokenCoverage confirms the corpus actually exercises the constructs this
// lexer was written for. A green test suite over inputs that never use `in~` or a raw
// string would prove very little.
func TestLexCorpusTokenCoverage(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}

	seen := map[mql.Kind]int{}
	for _, e := range entities {
		for _, tok := range mql.NewLexer(e.Source).Tokens() {
			seen[tok.Kind]++
		}
	}

	// Constructs the plan identified as load-bearing, several of which are undocumented.
	want := []mql.Kind{
		mql.Ident, mql.String, mql.Int, mql.Float, mql.List,
		mql.Dot, mql.Comma, mql.LParen, mql.RParen, mql.LBracket, mql.RBracket,
		mql.Assign, // keyword arguments
		mql.Eq, mql.NotEq, mql.IEq, mql.INotEq,
		mql.Lt, mql.LtEq, mql.Gt, mql.GtEq,
		mql.Plus, mql.Minus, mql.Slash,
		mql.And, mql.Or, mql.Not,
		mql.In, mql.IIn, mql.Of,
		mql.Is, mql.Null, mql.True, mql.False,
	}
	for _, k := range want {
		if seen[k] == 0 {
			t.Errorf("no %s token anywhere in the corpus; the test fixture may be wrong", k)
		}
	}
	if n := seen[mql.Invalid]; n != 0 {
		t.Errorf("%d invalid tokens in the corpus", n)
	}

	for _, k := range want {
		t.Logf("%-12s %6d", k, seen[k])
	}
}
