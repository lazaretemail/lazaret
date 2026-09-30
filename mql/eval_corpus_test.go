// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/eml"
	"github.com/lazaretemail/lazaret/internal/corpus"
	"github.com/lazaretemail/lazaret/lists"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/orgconfig"
)

// TestEvalCorpus runs every rule in the public corpus against real messages.
//
// Parsing proved the syntax; checking proved the model; this proves the engine survives
// contact with both at once. The bar is not "how many matched" — these are mostly rules
// for attacks these samples are not — but "how many ran to a definite answer without
// falling over".
//
// A rule reporting indeterminate is a pass: it asked for a capability this build does not
// have and said so, which is the behaviour the whole design is built around.
func TestEvalCorpus(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}
	messages := loadSampleMessages(t)
	if len(messages) == 0 {
		t.Skip("no sample messages in the corpus checkout")
	}

	ctx := context.Background()

	// The published $list data is embedded in the lists package, so it is part of what
	// this engine can do with no configuration at all and belongs in the headline
	// number. $high_trust_sender_root_domains alone gates 692 corpus rules.
	evalOpts := &mql.EvalOptions{Lists: lists.MustEmbedded()}

	tally := corpus.NewTally()
	failures := map[string]int{}
	examples := map[string]string{}

	var matches, noMatches, indeterminate int

	for _, e := range entities {
		if e.Type == "triage_rule" {
			continue // evaluated against triage state, which a message does not carry
		}
		checked, err := mql.Compile(e.Source, nil)
		if err != nil {
			continue // counted by the parse and check tests
		}

		ok := true
		for _, msg := range messages {
			res := mql.Eval(ctx, checked, msg, evalOpts)
			switch {
			case res.Err != nil:
				ok = false
				key := normaliseDiagnostic(res.Err.Error())
				failures[key]++
				if _, seen := examples[key]; !seen {
					examples[key] = e.Path + ": " + res.Err.Error()
				}
			case res.Verdict == mql.Match:
				matches++
			case res.Verdict == mql.Indeterminate:
				indeterminate++
			default:
				noMatches++
			}
		}
		tally.Add(e.Type, ok)
	}

	t.Logf("evaluated %d entities against %d messages\n%s", len(entities), len(messages), tally)
	t.Logf("verdicts: %d match, %d no-match, %d indeterminate", matches, noMatches, indeterminate)

	if len(failures) > 0 {
		keys := make([]string, 0, len(failures))
		for k := range failures {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return failures[keys[i]] > failures[keys[j]] })
		var b strings.Builder
		b.WriteString("evaluation errors, most frequent first:\n")
		for _, k := range keys {
			b.WriteString("  " + padCount(failures[k]) + "  " + k + "\n    e.g. " + truncate(examples[k], 130) + "\n")
		}
		t.Log(b.String())
	}

	if n := tally.Failures(); n > 0 {
		t.Errorf("%d entities failed to evaluate", n)
	}

	// Indeterminate results are expected and correct here — most of the corpus needs ML
	// or file explosion — but a run where *nothing* reached a definite answer would mean
	// the engine is not actually evaluating anything.
	if matches+noMatches == 0 {
		t.Error("no rule reached a definite verdict; the evaluator may not be running")
	}
}

// TestEvalCorpusIsDeterministic guards against map iteration order or anything else
// leaking into a verdict. A detection engine that answers differently on the same input
// cannot be reasoned about at all.
func TestEvalCorpusIsDeterministic(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}
	messages := loadSampleMessages(t)
	if len(messages) == 0 {
		t.Skip("no sample messages")
	}

	ctx := context.Background()
	for _, e := range entities {
		if e.Type == "triage_rule" {
			continue
		}
		checked, err := mql.Compile(e.Source, nil)
		if err != nil {
			continue
		}
		for _, msg := range messages {
			first := mql.Eval(ctx, checked, msg, nil)
			for range 2 {
				again := mql.Eval(ctx, checked, msg, nil)
				if again.Verdict != first.Verdict || again.Value.String() != first.Value.String() {
					t.Fatalf("%s is not deterministic: %s/%s then %s/%s",
						e.Path, first.Verdict, first.Value, again.Verdict, again.Value)
				}
			}
		}
	}
}

// loadSampleMessages parses the real phishing samples shipped with the corpus.
func loadSampleMessages(t *testing.T) []*mdm.MessageDataModel {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(corpus.Dir(), "emls", "*.eml"))
	if err != nil || len(paths) == 0 {
		return nil
	}

	org := &orgconfig.Config{Domains: []string{"example.com", "sublimesecurity.com"}}
	org.Normalize()

	var out []*mdm.MessageDataModel
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		m, err := eml.Parse(raw, &eml.Options{Org: org})
		if err != nil {
			t.Errorf("parsing %s: %v", p, err)
			continue
		}
		out = append(out, m)
	}
	return out
}
