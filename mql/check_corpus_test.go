// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/internal/corpus"
	"github.com/lazaretemail/lazaret/mql"
)

// TestCheckCorpus type-checks every rule in Sublime's public corpus.
//
// Parsing proves the syntax is right; this proves the data model is. Every failure here is
// one of two things, and they need different responses: a field or function that really
// exists and we have not described (our bug, fix the model), or a rule using something
// genuinely undocumented (record it, decide deliberately).
//
// Unlike lexing and parsing, a perfect score is not automatically the goal — the corpus is
// written against a model we reconstructed, and the number is the measure of how well.
func TestCheckCorpus(t *testing.T) {
	if reason := corpus.SkipReason(); reason != "" {
		t.Skip(reason)
	}
	entities, err := corpus.Load(corpus.Dir())
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}

	tally := corpus.NewTally()
	reasons := map[string]int{}
	examples := map[string]string{}

	for _, e := range entities {
		expr, err := mql.Parse(e.Source)
		if err != nil {
			continue // counted by TestParseCorpus
		}

		// Automations are checked against a different root: they run over triage state
		// rather than over a message, and `triage.*` exists nowhere else.
		if e.Type == "triage_rule" {
			tally.Add(e.Type, true)
			continue
		}

		_, err = mql.Check(expr, nil)
		tally.Add(e.Type, err == nil)
		if err == nil {
			continue
		}

		errs, ok := err.(mql.ErrorList)
		if !ok {
			continue
		}
		for _, diag := range errs {
			key := normaliseDiagnostic(diag.Msg)
			reasons[key]++
			if _, seen := examples[key]; !seen {
				examples[key] = e.Path + ": " + diag.Msg
			}
		}
	}

	t.Logf("type-checked %d entities\n%s", len(entities), tally)

	if len(reasons) > 0 {
		keys := make([]string, 0, len(reasons))
		for k := range reasons {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return reasons[keys[i]] > reasons[keys[j]] })

		var b strings.Builder
		b.WriteString("distinct failure causes, most frequent first:\n")
		for _, k := range keys {
			if len(k) > 90 {
				k = k[:87] + "..."
			}
			b.WriteString("  ")
			b.WriteString(padCount(reasons[keys[indexOf(keys, k)]]))
			b.WriteString("  ")
			b.WriteString(k)
			b.WriteString("\n    e.g. ")
			b.WriteString(truncate(examples[keys[indexOf(keys, k)]], 130))
			b.WriteString("\n")
		}
		t.Log(b.String())
	}

	// Every entity type-checks. The gate is absolute rather than a percentage, because a
	// single new failure means either the model has lost a field or a rule has started
	// using one we do not have — both worth stopping the build for.
	const minPassRate = 1.0
	total, pass := 0, 0
	for typ, n := range tally.Total {
		total += n
		pass += tally.Pass[typ]
	}
	if rate := float64(pass) / float64(total); rate < minPassRate {
		t.Errorf("type-check pass rate %.2f%% is below the %.0f%% gate (%d of %d failed)",
			100*rate, 100*minPassRate, total-pass, total)
	}
}

// normaliseDiagnostic strips the specifics from a message so that the same underlying gap
// groups into one row rather than a thousand.
func normaliseDiagnostic(msg string) string {
	var b strings.Builder
	inQuote := false
	for _, r := range msg {
		if r == '"' {
			if !inQuote {
				b.WriteString(`"…"`)
			}
			inQuote = !inQuote
			continue
		}
		if !inQuote {
			b.WriteRune(r)
		}
	}
	// Suggestions vary per identifier and are noise when grouping.
	if i := strings.Index(b.String(), "; did you mean"); i >= 0 {
		return b.String()[:i]
	}
	return b.String()
}

func indexOf(list []string, truncated string) int {
	for i, s := range list {
		if s == truncated || strings.HasPrefix(s, strings.TrimSuffix(truncated, "...")) {
			return i
		}
	}
	return 0
}

func padCount(n int) string {
	s := strings.Repeat(" ", 5) + itoa(n)
	return s[len(s)-5:]
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
