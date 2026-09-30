// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"math"
	"testing"
)

// The guard rails matter more than the accuracy here. A model that learns well from
// good data is ordinary; a model that refuses to speak when the data cannot support
// it is the part that keeps an operator's trust.

func TestTrainRefusesTooFewReviews(t *testing.T) {
	var ex []Example
	for i := 0; i < 20; i++ {
		ex = append(ex, Example{MessageID: fmt.Sprint(i), Features: []string{"rule:x"}, Label: LabelBad})
	}
	if _, err := Train(ex, 0.01, 50); err == nil {
		t.Fatal("trained on 20 reviews; below MinExamples it should refuse")
	}
}

func TestTrainRefusesOneSidedReviews(t *testing.T) {
	// A hundred confirmations and three dismissals teaches "everything is bad" at
	// 97% accuracy, which is the most dangerous kind of useless.
	var ex []Example
	for i := 0; i < 100; i++ {
		ex = append(ex, Example{MessageID: fmt.Sprint(i), Features: []string{"rule:x"}, Label: LabelBad})
	}
	for i := 0; i < 3; i++ {
		ex = append(ex, Example{MessageID: fmt.Sprintf("g%d", i), Features: []string{"rule:y"}, Label: LabelGood})
	}
	_, err := Train(ex, 0.01, 50)
	if err == nil {
		t.Fatal("trained on 100 bad and 3 good; it should refuse as too one-sided")
	}
}

// The thing it exists to do: learn which rules this deployment disagrees with.
func TestLearnsAFalsePositiveRule(t *testing.T) {
	var ex []Example
	// A rule the analysts always confirm.
	for i := 0; i < 60; i++ {
		ex = append(ex, Example{
			MessageID: fmt.Sprintf("bad%d", i),
			Features:  []string{"rule:Credential phishing", "severity:high", "insight:A link uses a URL shortener"},
			Label:     LabelBad,
		})
	}
	// A rule the analysts always dismiss.
	for i := 0; i < 60; i++ {
		ex = append(ex, Example{
			MessageID: fmt.Sprintf("good%d", i),
			Features:  []string{"rule:Newsletter heuristic", "severity:low", "sender_domain:marketing.test"},
			Label:     LabelGood,
		})
	}

	m, err := Train(ex, 0.001, 300)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Useful() {
		t.Errorf("accuracy %.2f against a %.2f baseline: the model learned nothing separable",
			m.Accuracy, m.Baseline)
	}

	badScore := m.Score([]string{"rule:Credential phishing", "severity:high"})
	goodScore := m.Score([]string{"rule:Newsletter heuristic", "severity:low"})
	if badScore <= goodScore {
		t.Errorf("the confirmed rule scored %.2f and the dismissed one %.2f; they are the wrong way round",
			badScore, goodScore)
	}
	if goodScore > 0.5 {
		t.Errorf("a rule dismissed sixty times still scores %.2f", goodScore)
	}

	// And it has to be able to say why.
	why := m.Explain([]string{"rule:Newsletter heuristic", "severity:low"}, 3)
	if len(why) == 0 {
		t.Fatal("no explanation for a score")
	}
	if why[0].Toward != "good" {
		t.Errorf("top contribution points %q for a message the analysts always dismissed", why[0].Toward)
	}
}

// Held-out accuracy must be measured on data the model has not seen, or a sparse
// linear model over rule names reports near-perfect memorisation.
func TestAccuracyIsHeldOut(t *testing.T) {
	var ex []Example
	// Labels uncorrelated with features: nothing is learnable, so a model that
	// measures on its training data will still claim to have learned something.
	for i := 0; i < 200; i++ {
		lab := LabelBad
		if i%2 == 0 {
			lab = LabelGood
		}
		ex = append(ex, Example{
			MessageID: fmt.Sprintf("m%d", i),
			Features:  []string{fmt.Sprintf("rule:unique-%d", i)},
			Label:     lab,
		})
	}
	m, err := Train(ex, 0.01, 200)
	if err != nil {
		t.Fatal(err)
	}
	if m.Useful() {
		t.Errorf("claimed to be useful (%.2f vs %.2f baseline) on unlearnable data — "+
			"accuracy is being measured on the training set", m.Accuracy, m.Baseline)
	}
}

// The split has to be stable, or reported accuracy wanders between identical runs
// and nobody can tell a real change from a reshuffle.
func TestSplitIsDeterministic(t *testing.T) {
	var ex []Example
	for i := 0; i < 200; i++ {
		lab := LabelBad
		if i%3 == 0 {
			lab = LabelGood
		}
		ex = append(ex, Example{MessageID: fmt.Sprintf("m%d", i),
			Features: []string{fmt.Sprintf("rule:r%d", i%7)}, Label: lab})
	}
	a, err := Train(ex, 0.01, 100)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Train(ex, 0.01, 100)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(a.Accuracy-b.Accuracy) > 1e-9 {
		t.Errorf("two runs on identical data reported %.4f and %.4f", a.Accuracy, b.Accuracy)
	}
}

// A score must never be NaN: it renders as a blank cell rather than as an error, so
// it fails silently in the worst place.
func TestScoreStaysFinite(t *testing.T) {
	m := &Model{Weights: map[string]float64{"a": 1e6, "b": -1e9}, Bias: 1e7}
	for _, fs := range [][]string{{"a"}, {"b"}, {"a", "b"}, {}, {"absent"}} {
		got := m.Score(fs)
		if math.IsNaN(got) || math.IsInf(got, 0) || got < 0 || got > 1 {
			t.Errorf("Score(%v) = %v, want a probability", fs, got)
		}
	}
}

func TestFeaturesAreStableAndNamed(t *testing.T) {
	an := &StoredAnalysis{
		Detections: []Detection{{Name: "Brand impersonation: Microsoft", Severity: "high"}},
		Insights: []Insight{
			{Label: "A link uses a URL shortener", Warn: true, Value: true},
			{Label: "Intent", Value: []any{"cred_theft"}},
			{Label: "Sender domain registered in the last 30 days", Warn: true, Unknown: true},
		},
	}
	f := FeaturesFor(an, Summary{Direction: "inbound", Links: 2}, SenderDetails{
		Domain:     "mail.account-verify.example.com",
		Prevalence: "new",
		DomainInfo: DomainInfo{DomainKnown: true, DomainRegistered: true, DomainAgeDays: 12},
	})

	want := map[string]bool{
		"rule:Brand impersonation: Microsoft": true,
		"severity:high":                       true,
		"insight:A link uses a URL shortener": true,
		"intent:cred_theft":                   true,
		"prevalence:new":                      true,
		"sender_domain:example.com":           true,
		"domain_age:<=30":                     true,
		"direction:inbound":                   true,
	}
	have := map[string]bool{}
	for _, x := range f {
		have[x] = true
	}
	for w := range want {
		if !have[w] {
			t.Errorf("missing feature %q; got %v", w, f)
		}
	}
	// An insight nobody could establish must not become a feature: the model would
	// learn that a broken RDAP service means the message is fine.
	if have["insight:Sender domain registered in the last 30 days"] {
		t.Error("an unknown insight became a feature; the model would be learning from a service outage")
	}
}
