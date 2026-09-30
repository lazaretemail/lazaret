// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log"
	"math"
	"sort"
	"strings"
)

// finding is one classification, before it becomes JSON.
type finding struct {
	Name       string
	Text       string
	Confidence string
	Score      float64

	// at is the byte offset the span was found at, used only to order the output.
	at int
}

// ZeroShot scores arbitrary labels against a text.
//
// An entailment model, not a trained classifier, and that is what makes the label
// vocabulary in labels.go usable at all: the labels come from the rule corpus, nobody
// has a labelled email set for them, and a zero-shot model needs neither.
type ZeroShot interface {
	// Score returns the entailment probability for each label. Absent labels in the
	// result are treated as unknown rather than as zero.
	Score(ctx context.Context, text string, labels []Label) (map[string]float64, error)
	Close() error
}

// NLU answers ml.nlu_classifier.
//
// # Partial availability is the whole design of this type
//
// The four accessors are four different problems. Entities and language are lexical
// and are answered with no model at all. Intents, topics and tags are judgements and
// need one.
//
// So this capability can be half-available, and that has to be expressed rather than
// smoothed over. With no model loaded the result carries entities and language, and
// omits intents, topics and tags entirely — not as empty arrays. An empty array is a
// confident statement that the classifier looked and found nothing, and the corpus is
// full of clauses written to exclude benign mail:
//
//	not any(ml.nlu_classifier(body.current_thread.text).topics,
//	        .name == "Newsletters and Digests" and .confidence == "high")
//
// An empty topics array makes that negation true and the rule fires because no model
// was deployed. Omitting the field yields null, `any` over null is null, and the rule
// reports indeterminate — which is the true answer to "was this a newsletter?" when
// nothing capable of deciding was running.
//
// This is the same bug this engine already shipped once, by folding a null array into
// an empty one, and it produced a false positive on a real corpus rule. It is worth
// being this careful about twice.
type NLU struct {
	model ZeroShot

	// Where the confidence buckets fall. See Thresholds.
	T Thresholds
}

// Thresholds decide which findings are reported as "high" and which as "medium".
//
// The corpus reads `.confidence == "high"` 315 times and `"medium"` 111 times, so
// these change a lot of verdicts and are worth being explicit about.
//
// # Why these numbers and not others
//
// The first version used absolute cut-offs on the entailment probability, chosen by
// eye. That was wrong twice over. An entailment probability from this model is not
// comparable *between messages* — the same confident answer scores 0.14 on one input
// and 0.99 on another — so an absolute threshold on a normalised share means
// something different for every message. And 0.8 and 0.4 were not derived from
// anything.
//
// What replaced them:
//
//   - **Intents are exclusive**, so the question is "which one", and the honest test
//     is dominance rather than magnitude: a label is high when it is clearly ahead of
//     the runner-up. A ratio is scale-free, so it survives the between-message
//     variation that defeats an absolute threshold.
//   - **Topics and tags are not exclusive**, so there is no runner-up to compare
//     against and an absolute threshold is unavoidable. But the number can still mean
//     something: this is an NLI head, so 0.5 is the point where the model considers
//     the hypothesis more likely entailed than not. That is a definition rather than
//     a guess.
//
// None of this is a substitute for measuring against real mail. `lazaret-ml
// calibrate` exists for that, and Calibrate below is what it fits.
type Thresholds struct {
	// HighRatio is how far ahead of the runner-up an exclusive label must be to be
	// high. 2.0 means twice the share.
	HighRatio float64

	// MediumRatio is the same for medium.
	MediumRatio float64

	// HighFloor is a minimum share regardless of the ratio, so that a label winning
	// a field of near-zeroes is not called high on the strength of the others being
	// worse.
	HighFloor float64

	// HighProb and MediumProb are the absolute entailment thresholds for the
	// non-exclusive labels. MediumProb is 0.5 because that is what the head means.
	HighProb   float64
	MediumProb float64

	// TrustSuppression allows a suppressive label to be reported high at all.
	//
	// Off by default, which caps `benign` at medium. The corpus only suppresses on
	// high — `not any(intents, .name == "benign" and .confidence == "high")` — so
	// with this off a wrong benign cannot stop a rule firing, while every intent that
	// *causes* a rule to fire is unaffected.
	//
	// The cost is real and worth stating: those negations exist to keep genuine
	// benign mail out of noisy rules, and capping benign gives that up. Measurement
	// on the nine corpus samples plus four benign controls is what makes the default
	// this way round — even after the SuppressiveFloor fix, two of nine phishing
	// samples still scored benign-high, and each one would have silently stopped a
	// rule. Two silent false negatives is worse than some extra noise.
	//
	// Turn it on once a deployment has measured its own mail and decided the
	// suppression earns its keep.
	TrustSuppression bool

	// SuppressiveFloor is the raw entailment probability a *suppressive* label must
	// reach before it can be reported high, on top of the usual dominance test.
	//
	// This one is measured rather than reasoned. Running the nine real phishing
	// samples in the rule corpus plus four hand-written benign messages showed the
	// share test alone calling four of the nine benign — because on a message whose
	// maliciousness is not in its prose, every other intent scores near zero and
	// `benign` wins the normalised share by default. The raw probabilities separate
	// those cases cleanly:
	//
	//	phishing wrongly called benign   0.0026, 0.0139
	//	genuinely benign                 0.5354, 0.7484, 0.8676, 0.9779
	//
	// 0.25 sits in that gap with room on both sides — eighteen times the highest
	// false positive, half the lowest true one. It removes two of the four errors at
	// no cost to the benign messages.
	//
	// The remaining two scored 0.5567 and 0.8088: punycode-domain phishing and a
	// generic "outline for new project" lure. The model is not wrong about those in
	// any way a threshold could fix — their prose *is* ordinary, and they are caught
	// by the rules that look at the domain rather than the language.
	SuppressiveFloor float64

	// Floor is the point below which a finding is not emitted at all.
	Floor float64
}

// DefaultThresholds are the reasoned starting point, not a measured one.
func DefaultThresholds() Thresholds {
	return Thresholds{
		HighRatio:        2.0,
		MediumRatio:      1.2,
		HighFloor:        0.30,
		HighProb:         0.90,
		MediumProb:       0.50,
		SuppressiveFloor: 0.25,
		Floor:            0.15,
	}
}

// NewNLU returns the capability. model may be nil, which is the normal state of a
// deployment with no weights.
func NewNLU(model ZeroShot) *NLU {
	return &NLU{model: model, T: DefaultThresholds()}
}

func (n *NLU) Capability() string { return "ml.nlu_classifier" }

func (n *NLU) Close() error {
	if n.model != nil {
		return n.model.Close()
	}
	return nil
}

// nluResult mirrors mdm.NluResult. Every field is omitempty and every model-backed one
// is a pointer to a slice, so "not classified" and "classified as nothing" serialise
// differently: the first omits the key, the second emits [].
type nluResult struct {
	Intents  *[]jsonFinding `json:"intents,omitempty"`
	Entities *[]jsonFinding `json:"entities,omitempty"`
	Topics   *[]jsonFinding `json:"topics,omitempty"`
	Tags     *[]jsonFinding `json:"tags,omitempty"`
	Language *string        `json:"language,omitempty"`
	Text     *string        `json:"text,omitempty"`

	// Unavailable names the accessors no model could answer. Not part of Sublime's
	// schema and not reachable from MQL — it is for the client, which records the
	// capability so the verdict can say what was missing rather than only that
	// something was.
	Unavailable []string `json:"unavailable,omitempty"`
}

type jsonFinding struct {
	Name       string   `json:"name"`
	Text       string   `json:"text,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Score      *float64 `json:"score,omitempty"`
}

func (n *NLU) Infer(ctx context.Context, req Request) (any, error) {
	text := normaliseBody(req.Text)
	out := nluResult{}
	if text != "" {
		t := text
		out.Text = &t
	}

	ents := toJSON(extractEntities(text))
	out.Entities = &ents

	if lang, conf := detectLanguage(text); lang != "" && conf > 0 {
		out.Language = &lang
	}
	// No language field when identification failed. Unknown, not English.

	if n.model == nil || text == "" {
		out.Unavailable = []string{"intents", "topics", "tags"}
		return out, nil
	}

	var failed []string
	for _, spec := range []struct {
		name   string
		labels []Label
		dst    **[]jsonFinding
		// multi says several labels can hold at once. Intents are exclusive — a
		// message has one purpose — while a message can be about several topics.
		multi bool
	}{
		{"intents", Intents, &out.Intents, false},
		{"topics", Topics, &out.Topics, true},
		{"tags", Tags, &out.Tags, true},
	} {
		fs, err := n.classify(ctx, text, spec.labels, spec.multi)
		if err != nil {
			// Logged, because the response says only "unavailable" and an operator
			// staring at a capability that is loaded and still not answering has
			// nothing else to go on.
			log.Printf("nlu: %s: %v", spec.name, err)
			failed = append(failed, spec.name)
			continue
		}
		j := toJSON(fs)
		*spec.dst = &j
	}
	out.Unavailable = failed
	return out, nil
}

// classify scores the labels and buckets them.
func (n *NLU) classify(ctx context.Context, text string, labels []Label, multi bool) ([]finding, error) {
	// Too short to carry an intent, and answered without asking the model.
	//
	// The cost of a zero-shot pass is the number of candidate labels, not the length
	// of the text: every label is a separate premise-hypothesis row in one batch. So
	// classifying the two words "billing settings" costs exactly what classifying a
	// whole email costs — five seconds, measured — and rules that ask about a link's
	// display text ask it once per link. One real message spent twenty-four seconds
	// running nine full inferences over link labels.
	//
	// Returning no findings here is an answer, not an absence: a fragment of a few
	// words has no ask in it to detect, and what the model produces from one is
	// noise that happens to be shaped like a verdict. It is deliberately a low bar —
	// "please wire the funds today" clears it — because the aim is to skip labels
	// and captions, not short messages.
	if tooShortToClassify(text) {
		return []finding{}, nil
	}

	scores, err := n.model.Score(ctx, text, labels)
	if err != nil {
		return nil, err
	}

	var fs []finding
	if !multi {
		// Exclusive: normalise across the labels, then judge by how far ahead the
		// leader is. Both steps matter. Normalising makes the numbers comparable
		// within a message; the ratio makes the verdict comparable between messages,
		// which the raw probabilities are not.
		total := 0.0
		for _, l := range labels {
			total += scores[l.Name]
		}
		if total <= 0 {
			return []finding{}, nil
		}
		shares := make(map[string]float64, len(labels))
		for _, l := range labels {
			shares[l.Name] = scores[l.Name] / total
		}
		runnerUp := secondHighest(shares)
		for _, l := range labels {
			conf := n.T.exclusive(shares[l.Name], runnerUp)
			// A label the rules use to suppress is held to a higher standard, in two
			// steps. Unless suppression is trusted it cannot be high at all; and
			// even when it is, it needs absolute evidence as well as a dominant
			// share, because winning a field of near-zeroes is not the same as the
			// model believing it.
			if conf == ConfHigh && l.Suppressive {
				if !n.T.TrustSuppression || scores[l.Name] < n.T.SuppressiveFloor {
					conf = ConfMedium
				}
			}
			if conf != "" {
				fs = append(fs, finding{Name: l.Name, Confidence: conf, Score: scores[l.Name]})
			}
		}
	} else {
		for _, l := range labels {
			if conf := n.T.absolute(scores[l.Name]); conf != "" {
				fs = append(fs, finding{Name: l.Name, Confidence: conf, Score: scores[l.Name]})
			}
		}
	}
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Score > fs[j].Score })
	if fs == nil {
		fs = []finding{}
	}
	return fs, nil
}

// exclusive buckets one label of a mutually exclusive set.
//
// share is this label's share of the total; runnerUp is the second-highest share in
// the set. A label that *is* the runner-up is compared against the leader, so only
// one label can be high.
func (t Thresholds) exclusive(share, runnerUp float64) string {
	if share < t.Floor {
		return ""
	}
	ratio := math.Inf(1)
	if runnerUp > 0 && share != runnerUp {
		ratio = share / runnerUp
	} else if share == runnerUp {
		// This label is the runner-up, or tied with it. Either way it is not ahead.
		ratio = 1
	}
	switch {
	case ratio >= t.HighRatio && share >= t.HighFloor:
		return ConfHigh
	case ratio >= t.MediumRatio:
		return ConfMedium
	default:
		// Emitted but invisible to the corpus, which compares only against "high"
		// and "medium". Kept so a human reading the output can see what the
		// classifier nearly said.
		return ConfLow
	}
}

// absolute buckets one label of a set where several can hold at once.
func (t Thresholds) absolute(p float64) string {
	switch {
	case p >= t.HighProb:
		return ConfHigh
	case p >= t.MediumProb:
		return ConfMedium
	case p >= t.Floor:
		return ConfLow
	}
	return ""
}

// secondHighest returns the runner-up value, which is what a leader is measured
// against.
func secondHighest(m map[string]float64) float64 {
	first, second := 0.0, 0.0
	for _, v := range m {
		switch {
		case v > first:
			first, second = v, first
		case v > second:
			second = v
		}
	}
	return second
}

func toJSON(fs []finding) []jsonFinding {
	out := make([]jsonFinding, 0, len(fs))
	for _, f := range fs {
		j := jsonFinding{Name: f.Name, Text: f.Text, Confidence: f.Confidence}
		if f.Score > 0 {
			s := f.Score
			j.Score = &s
		}
		out = append(out, j)
	}
	return out
}

// normaliseBody trims the text to what is worth classifying.
//
// Quoted history and signature blocks are removed because they are someone else's
// words: a reply to a newsletter is not a newsletter, and a thread that has been
// forwarded four times otherwise classifies as whatever it was originally about.
func normaliseBody(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, ">") && len(t) < 2000 {
			continue
		}
		if isQuoteHeader(t) {
			break
		}
		out = append(out, l)
	}
	kept := strings.TrimSpace(strings.Join(out, "\n"))

	// A backstop for the degenerate case only: stripping left nothing at all.
	//
	// Deliberately not a ratio. A one-line reply on a long thread legitimately
	// discards most of the bytes, and treating that as a misfire would feed the
	// quoted history back in and classify the wrong message. What is never right is
	// handing the classifier an empty string when there was a message to read.
	//
	// The case that motivated this is fixed upstream of here, in isSeparatorLine: a
	// FedEx sample arrived as a single 1,890-character line beginning with Outlook's
	// row of underscores, and the separator check matched the prefix and broke,
	// discarding the message. HTML mail flattened to text often has no line breaks
	// at all, so "the line starts like a separator" was the same as "discard
	// everything". A separator must now be the whole line.
	if kept == "" {
		return strings.TrimSpace(s)
	}
	return kept
}

// isQuoteHeader reports a line that introduces quoted history.
//
// The separator forms must be the *whole* line. A row of underscores with eighteen
// hundred characters of message after it is not a thread separator, it is a message
// that happens to start with a rule — and treating it as a separator discards the
// text this service exists to read.
func isQuoteHeader(t string) bool {
	if strings.HasPrefix(t, "-----Original Message-----") {
		return true
	}
	if isSeparatorLine(t) {
		return true
	}
	lower := strings.ToLower(t)
	return strings.HasPrefix(lower, "on ") && strings.HasSuffix(lower, "wrote:")
}

// isSeparatorLine reports a line that is nothing but a horizontal rule.
func isSeparatorLine(t string) bool {
	if len(t) < 16 {
		return false
	}
	for _, r := range t {
		if r != '_' && r != '-' && r != '=' && r != '*' {
			return false
		}
	}
	return true
}

// minWordsToClassify is the fewest words that can express an ask.
//
// Five. Below it, a string is a link label, a button caption or a heading — and the
// rules that pass those in are asking about a fragment, not a message.
const minWordsToClassify = 5

func tooShortToClassify(text string) bool {
	return len(strings.Fields(text)) < minWordsToClassify
}
