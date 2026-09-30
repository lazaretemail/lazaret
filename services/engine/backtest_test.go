// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"
	"time"
)

// A backtest refuses an insight query, because there is nothing to count.
//
// An insight query legitimately yields an array or a number — `map(attachments, ...)`
// is a real corpus entity — and MQL has no truthiness, so there is no honest way to
// turn one into "would have fired". Refusing with the type named is better than
// counting something arbitrary.
func TestBacktestRefusesAQueryRatherThanARule(t *testing.T) {
	p := extendedPipeline(t)
	b := NewBacktester(nil, nil)
	b.UseRegistry(p.Registry())

	// No store, so a rule that compiles gets as far as the corpus check; the type
	// check happens first and is what this is about.
	_, err := b.Start(t.Context(), "t", "q", `subject.subject`, time.Now(), time.Now())
	if err == nil {
		t.Fatal("a string-valued query was accepted as a detection rule")
	}
	if !strings.Contains(err.Error(), "true or false") {
		t.Errorf("refusal does not say what is wrong: %v", err)
	}
}

// Precision is withheld until enough of the matches were judged.
//
// A proposed rule that matched three messages and an analyst called two of them benign
// is not a 33% rule, it is an unmeasured one. Showing a number there is a lie told with
// arithmetic, and it is exactly the number someone would use to reject a good rule.
func TestBacktestWithholdsPrecisionUntilItMeansSomething(t *testing.T) {
	j := &BacktestJob{Matched: 40}

	j.Reviewed, j.Confirmed, j.Benign = 3, 1, 2
	if j.PrecisionKnown() {
		t.Error("precision reported from three reviews")
	}

	j.Reviewed, j.Confirmed, j.Benign = 10, 7, 3
	if !j.PrecisionKnown() {
		t.Fatal("precision withheld from ten reviews")
	}
	if got := j.Precision(); got != 0.7 {
		t.Errorf("precision %v, want 0.7", got)
	}
}

// A run reports what it could not decide, separately from what did not match.
//
// The whole value of a backtest is the decision it informs, so "34 matched" has to come
// with "and 900 could not be checked, because the evidence those rules wanted was never
// kept". Folding the second into no-match would make a thin result look like a clean
// one.
func TestBacktestKeepsUndecidedApartFromNoMatch(t *testing.T) {
	j := &BacktestJob{Scanned: 1000, Matched: 34, Undecided: 900}
	if j.Scanned-j.Matched-j.Undecided != 66 {
		t.Fatalf("the three numbers do not partition the scan: %d/%d/%d",
			j.Scanned, j.Matched, j.Undecided)
	}
	view := backtestView(j)
	if _, ok := view["messages_undecided"]; !ok {
		t.Error("the undecided count is not in the API view, so nothing can show it")
	}
	if _, ok := view["precision"]; ok {
		t.Error("precision was published with no reviews behind it")
	}
}
