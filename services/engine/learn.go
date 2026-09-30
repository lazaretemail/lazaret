// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Learning from what analysts decided.
//
// Every review an analyst makes is a labelled example: this rule was right, this one
// was wrong, this newsletter is noise we do not want to see. The rules are someone
// else's and are the same for everybody; the reviews are this deployment's own, and
// they are the only signal in the system that knows what *this* organisation
// considers a problem.
//
// # Why a linear model and not something bigger
//
// Because it has to be arguable. An analyst asking "why did this score high" gets a
// list of features and the weight each contributed, and an administrator can read
// the whole model on one page and disagree with it. A gradient-boosted ensemble or a
// fine-tuned transformer would score better on a benchmark and would be unauditable
// by the person whose job it is to trust it — and in a tool that quarantines mail,
// unauditable is disqualifying.
//
// It also trains in milliseconds on a laptop from a few thousand reviews, needs no
// GPU, and is small enough to store as JSON. A deployment gets a model the week it
// starts reviewing rather than the quarter it buys hardware.
//
// # What it actually learns, which is narrower than it sounds
//
// The examples are messages an analyst looked at, and analysts look at what the
// rules flagged. So the model learns to predict *whether an analyst will agree with
// a detection*, not whether a message is malicious in general. That is a genuinely
// useful thing — it is exactly the false-positive problem — but it is not a detector,
// it cannot find what the rules never surfaced, and presenting it as one would be a
// lie. It is wired in as a signal alongside the rules and never as a replacement.

// Label is what an analyst concluded about a message.
type Label int

const (
	LabelUnknown Label = iota
	// LabelBad: the analyst confirmed it, or overruled the block while agreeing the
	// rule was right.
	LabelBad
	// LabelGood: the analyst said the rule was wrong, or the message was harmless.
	LabelGood
)

// Example is one reviewed message, reduced to features and a label.
type Example struct {
	MessageID string
	Features  []string
	Label     Label
}

// Model is a logistic regression over named binary features.
//
// Weights are stored by name rather than by index, so a model survives the feature
// set changing: a feature that no longer exists is simply never seen again, and a
// new one starts at zero rather than shifting everything after it. Index-based
// weights would silently reinterpret themselves the first time a rule was added.
type Model struct {
	Weights map[string]float64 `json:"weights"`
	Bias    float64            `json:"bias"`

	// Trained describes the data it came from, so a page can say how much to
	// believe it rather than only what it says.
	Examples  int     `json:"examples"`
	Bad       int     `json:"bad"`
	Good      int     `json:"good"`
	Accuracy  float64 `json:"accuracy"`
	Baseline  float64 `json:"baseline"`
	TrainedAt string  `json:"trained_at,omitempty"`
	Version   int     `json:"version"`
}

// MinExamples is the fewest reviews worth training on.
//
// Below this the model is not wrong so much as meaningless: with nine reviews a
// single analyst's afternoon becomes a rule applied to everything afterwards. The
// page says "not enough reviews yet" and shows nothing, which is more useful than a
// confident number derived from a handful of clicks.
const MinExamples = 50

// MinPerClass is the fewest of each answer. A hundred confirmations and two
// false positives teaches only "everything is bad", at 98% accuracy.
const MinPerClass = 10

// Train fits a model by gradient descent on the log loss.
//
// Deliberately plain: batch gradient descent, L2 regularisation, a fixed schedule.
// The dataset is thousands of examples with thousands of sparse features, which is
// small enough that cleverness buys nothing and costs the ability to explain what
// happened.
func Train(examples []Example, l2 float64, epochs int) (*Model, error) {
	var bad, good int
	for _, e := range examples {
		switch e.Label {
		case LabelBad:
			bad++
		case LabelGood:
			good++
		}
	}
	if bad+good < MinExamples {
		return nil, fmt.Errorf("only %d reviewed messages; %d are needed before a model means anything",
			bad+good, MinExamples)
	}
	if bad < MinPerClass || good < MinPerClass {
		return nil, fmt.Errorf("reviews are too one-sided to learn from: %d confirmed and %d dismissed, "+
			"and at least %d of each are needed", bad, good, MinPerClass)
	}

	// Held out before training, not after: measuring on data the model has seen
	// reports how well it memorised, which for a sparse linear model over rule
	// names is close to perfect and close to meaningless.
	train, test := split(examples, 0.2)

	m := &Model{Weights: map[string]float64{}, Examples: bad + good, Bad: bad, Good: good}

	// Class weighting, because review queues are lopsided. An analyst confirms far
	// more than they dismiss, and without this the model learns that saying "bad"
	// is right most of the time — which is true and useless.
	wBad, wGood := 1.0, 1.0
	if bad > good && good > 0 {
		wGood = float64(bad) / float64(good)
	} else if good > bad && bad > 0 {
		wBad = float64(good) / float64(bad)
	}

	lr := 0.5
	for epoch := 0; epoch < epochs; epoch++ {
		grad := map[string]float64{}
		var gradBias float64

		for _, e := range train {
			y := 0.0
			w := wGood
			if e.Label == LabelBad {
				y, w = 1.0, wBad
			}
			p := m.probability(e.Features)
			err := (p - y) * w
			gradBias += err
			for _, f := range e.Features {
				grad[f] += err
			}
		}

		n := float64(len(train))
		m.Bias -= lr * gradBias / n
		for f, g := range grad {
			// L2 pulls unseen-but-once features back towards zero, which is what
			// stops a rule that fired on a single reviewed message from acquiring
			// a large opinion.
			m.Weights[f] -= lr * (g/n + l2*m.Weights[f])
		}
		// Decay, so late epochs settle rather than oscillate.
		lr *= 0.995
	}

	m.Accuracy = m.evaluate(test)
	m.Baseline = majorityBaseline(test)
	return m, nil
}

// Score returns the probability that an analyst would call this bad.
func (m *Model) Score(features []string) float64 {
	if m == nil {
		return 0
	}
	return m.probability(features)
}

func (m *Model) probability(features []string) float64 {
	z := m.Bias
	for _, f := range features {
		z += m.Weights[f]
	}
	// Clamped before exp: a sparse model with many active features can produce a
	// z large enough to overflow, and a NaN score renders as a blank cell rather
	// than as an error anybody notices.
	if z > 30 {
		return 1
	}
	if z < -30 {
		return 0
	}
	return 1 / (1 + math.Exp(-z))
}

// Contribution is one feature's effect on a score.
type Contribution struct {
	Feature string  `json:"feature"`
	Weight  float64 `json:"weight"`
	Toward  string  `json:"toward"`
}

// Explain lists the features that moved this score most, in both directions.
//
// The reason the model is linear. "Scored 0.91" is not something an analyst can act
// on; "scored 0.91, mostly because this rule has been confirmed nineteen times and
// this sender domain has been dismissed twice" is.
func (m *Model) Explain(features []string, n int) []Contribution {
	if m == nil {
		return nil
	}
	out := make([]Contribution, 0, len(features))
	for _, f := range features {
		w, ok := m.Weights[f]
		if !ok || w == 0 {
			continue
		}
		toward := "bad"
		if w < 0 {
			toward = "good"
		}
		out = append(out, Contribution{Feature: f, Weight: w, Toward: toward})
	}
	sort.Slice(out, func(i, j int) bool {
		return math.Abs(out[i].Weight) > math.Abs(out[j].Weight)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Top returns the strongest weights in the whole model, for the page that shows an
// administrator what it has learned.
func (m *Model) Top(n int) []Contribution {
	if m == nil {
		return nil
	}
	out := make([]Contribution, 0, len(m.Weights))
	for f, w := range m.Weights {
		toward := "bad"
		if w < 0 {
			toward = "good"
		}
		out = append(out, Contribution{Feature: f, Weight: w, Toward: toward})
	}
	sort.Slice(out, func(i, j int) bool {
		if math.Abs(out[i].Weight) != math.Abs(out[j].Weight) {
			return math.Abs(out[i].Weight) > math.Abs(out[j].Weight)
		}
		return out[i].Feature < out[j].Feature
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Useful reports whether the model beats guessing the majority answer.
//
// A model that does not is not a weak model, it is no model: predicting "bad" for
// everything scores whatever fraction of reviews were bad, and anything at or below
// that has learned nothing. Reporting it as a percentage anyway is how a number that
// means nothing ends up on a dashboard.
func (m *Model) Useful() bool {
	return m != nil && m.Accuracy > m.Baseline+0.02
}

func (m *Model) evaluate(test []Example) float64 {
	if len(test) == 0 {
		return 0
	}
	right := 0
	for _, e := range test {
		predicted := LabelGood
		if m.probability(e.Features) >= 0.5 {
			predicted = LabelBad
		}
		if predicted == e.Label {
			right++
		}
	}
	return float64(right) / float64(len(test))
}

func majorityBaseline(test []Example) float64 {
	if len(test) == 0 {
		return 0
	}
	bad := 0
	for _, e := range test {
		if e.Label == LabelBad {
			bad++
		}
	}
	frac := float64(bad) / float64(len(test))
	return math.Max(frac, 1-frac)
}

// split partitions deterministically by message id.
//
// By hash rather than at random, so that re-training on the same data produces the
// same split and a change in reported accuracy means the data changed — not that the
// shuffle did. It also keeps a message in the same half as the corpus grows.
func split(examples []Example, testFraction float64) (train, test []Example) {
	cut := uint32(testFraction * 1000)
	for _, e := range examples {
		if e.Label == LabelUnknown {
			continue
		}
		if fnv32(e.MessageID)%1000 < cut {
			test = append(test, e)
		} else {
			train = append(train, e)
		}
	}
	// A tiny dataset can hash entirely into one side. Better to measure on the
	// training data and say so than to report nothing.
	if len(test) == 0 || len(train) == 0 {
		return examples, examples
	}
	return train, test
}

func fnv32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// FeaturesFor reduces a stored analysis to the names a model works on.
//
// Binary and named, never continuous: "the domain is under 30 days old" is a fact an
// analyst can argue with, where "domain_age=0.0384" is a number with a coefficient.
// Continuous features would fit marginally better and would make every explanation
// unreadable.
func FeaturesFor(an *StoredAnalysis, s Summary, sender SenderDetails) []string {
	seen := map[string]bool{}
	var out []string
	add := func(parts ...string) {
		f := strings.Join(parts, ":")
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}

	// What fired. The strongest signal by far, and the one the model is really
	// learning about: which rules this organisation agrees with.
	for _, d := range an.Detections {
		add("rule", d.Name)
		if d.Severity != "" {
			add("severity", strings.ToLower(d.Severity))
		}
	}
	add("rules", bucket(len(an.Detections), 0, 1, 2, 5))

	// What the evidence said. Only the warnings: the context facts are either
	// constant or already covered by a more specific feature.
	for _, in := range an.Insights {
		if in.Warn && !in.Unknown {
			add("insight", in.Label)
		}
		switch in.Label {
		case "Intent", "Topic":
			if vals, ok := in.Value.([]any); ok {
				for _, v := range vals {
					add(strings.ToLower(in.Label), fmt.Sprint(v))
				}
			}
		case "Language":
			if s, ok := in.Value.(string); ok {
				add("language", s)
			}
		}
	}

	// Who it came from. The root domain is included because a tenant's own
	// experience of a specific sender is exactly the local knowledge the shared
	// rules cannot have.
	if sender.Prevalence != "" {
		add("prevalence", sender.Prevalence)
	}
	if sender.SeenBad {
		add("sender", "seen_bad")
	}
	if sender.SeenBenign {
		add("sender", "seen_benign")
	}
	if sender.Solicited {
		add("sender", "solicited")
	}
	if d := rootish(sender.Domain); d != "" {
		add("sender_domain", d)
	}
	if sender.DomainKnown {
		add("domain_age", bucket(int(sender.DomainAgeDays), 30, 180, 365, 1825))
	}

	add("direction", orUnknown(s.Direction))
	add("links", bucket(s.Links, 0, 1, 3, 10))
	add("attachments", bucket(s.Attachments, 0, 1, 3))
	if s.ReplyTo != "" {
		add("has", "reply_to")
	}
	return out
}

// bucket turns a count into a band name.
func bucket(v int, edges ...int) string {
	for _, e := range edges {
		if v <= e {
			return fmt.Sprintf("<=%d", e)
		}
	}
	return fmt.Sprintf(">%d", edges[len(edges)-1])
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// rootish trims a domain to something a model can generalise over without learning
// every subdomain separately.
func rootish(d string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(d)), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ---------------------------------------------------------------------------
// Wiring: training, loading, scoring
// ---------------------------------------------------------------------------

// LearnedScore is what the model says about one message.
type LearnedScore struct {
	Score float64 `json:"score"`

	// Agreement is the plain reading of the score: whether analysts here have
	// tended to confirm messages that look like this one.
	Agreement string `json:"agreement"`

	Why     []Contribution `json:"why,omitempty"`
	Version int            `json:"version,omitempty"`

	// Advisory is always true, and is in the payload rather than only in the docs
	// so that anything consuming this cannot mistake it for a verdict.
	Advisory bool `json:"advisory"`
}

// scoreWith applies a model to an analysis.
//
// The result never changes the verdict. It is shown beside it, because a model
// trained on which detections analysts agreed with cannot be allowed to overrule the
// detections themselves — that is a loop in which the system learns to stop
// reporting the things nobody has got round to reviewing.
func scoreWith(m *Model, an *StoredAnalysis, s Summary, sender SenderDetails) *LearnedScore {
	if m == nil || !m.Useful() {
		return nil
	}
	features := FeaturesFor(an, s, sender)
	p := m.Score(features)

	agreement := "no clear pattern"
	switch {
	case p >= 0.8:
		agreement = "messages like this are usually confirmed"
	case p >= 0.6:
		agreement = "leans towards confirmed"
	case p <= 0.2:
		agreement = "messages like this are usually dismissed"
	case p <= 0.4:
		agreement = "leans towards dismissed"
	}

	return &LearnedScore{
		Score:     p,
		Agreement: agreement,
		Why:       m.Explain(features, 5),
		Version:   m.Version,
		Advisory:  true,
	}
}
