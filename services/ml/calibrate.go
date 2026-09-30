// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// Fitting the confidence thresholds to real mail.
//
// The defaults in DefaultThresholds are reasoned rather than measured: nobody has a
// labelled email set for this label vocabulary, because the vocabulary was extracted
// from someone else's rule corpus. That is a defensible starting point and not a good
// permanent answer — `.confidence == "high"` gates 315 places in the corpus, and where
// that line falls decides a lot of verdicts.
//
// This is the thing to run once a deployment has judged mail of its own. It needs no
// model training and no GPU: score the examples once, then sweep the thresholds over
// the scores and report what each choice would do.
//
// Input is JSON lines, one message per line:
//
//	{"text": "...", "intents": ["cred_theft"], "topics": ["Financial Communications"]}
//
// `intents` and `topics` are the labels a human says are correct. An empty list is
// meaningful — it says none of them apply — so a message with no labels is a useful
// negative example rather than a missing one.

type example struct {
	Text    string   `json:"text"`
	Intents []string `json:"intents"`
	Topics  []string `json:"topics"`
	Tags    []string `json:"tags"`
}

// Calibrate scores every example once and reports how each candidate threshold would
// have performed.
//
// Deliberately reports rather than decides. Precision and recall trade against each
// other and which one matters is a deployment's choice: a rule that fires on high
// confidence wants precision, and a rule that *excludes* on high confidence — which
// is most of how the corpus uses topics — wants recall, because a missed exclusion is
// a false positive.
func Calibrate(ctx context.Context, reg *Registry, in io.Reader, out io.Writer) error {
	nlu, ok := reg.models["ml.nlu_classifier"].(*NLU)
	if !ok || nlu.model == nil {
		return fmt.Errorf("calibration needs the entailment model; none is loaded")
	}

	var examples []example
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e example
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("line %d: %w", len(examples)+1, err)
		}
		examples = append(examples, e)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(examples) == 0 {
		return fmt.Errorf("no examples read")
	}
	fmt.Fprintf(out, "scoring %d example(s)...\n\n", len(examples))

	// Score once. The sweep is then arithmetic over the stored scores, which is what
	// makes trying forty threshold combinations cheap.
	type scored struct {
		intents map[string]float64
		topics  map[string]float64
		want    example
	}
	all := make([]scored, 0, len(examples))
	for i, e := range examples {
		text := normaliseBody(e.Text)
		is, err := nlu.model.Score(ctx, text, Intents)
		if err != nil {
			return fmt.Errorf("example %d: %w", i+1, err)
		}
		ts, err := nlu.model.Score(ctx, text, Topics)
		if err != nil {
			return fmt.Errorf("example %d: %w", i+1, err)
		}
		all = append(all, scored{intents: is, topics: ts, want: e})
	}

	// Intents: sweep the dominance ratio.
	fmt.Fprintln(out, "intents — high when the leader is this far ahead of the runner-up")
	fmt.Fprintf(out, "  %-8s %-10s %-10s %-10s\n", "ratio", "precision", "recall", "F1")
	for _, ratio := range []float64{1.2, 1.5, 2.0, 2.5, 3.0, 4.0, 6.0} {
		t := DefaultThresholds()
		t.HighRatio = ratio
		tp, fp, fn := 0, 0, 0
		for _, s := range all {
			got := highExclusive(s.intents, Intents, t)
			want := set(s.want.Intents)
			for name := range got {
				if want[name] {
					tp++
				} else {
					fp++
				}
			}
			for name := range want {
				if !got[name] {
					fn++
				}
			}
		}
		p, r, f := prf(tp, fp, fn)
		fmt.Fprintf(out, "  %-8.1f %-10.3f %-10.3f %-10.3f\n", ratio, p, r, f)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "topics — high above this entailment probability")
	fmt.Fprintf(out, "  %-8s %-10s %-10s %-10s\n", "p", "precision", "recall", "F1")
	for _, prob := range []float64{0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99} {
		t := DefaultThresholds()
		t.HighProb = prob
		tp, fp, fn := 0, 0, 0
		for _, s := range all {
			want := set(s.want.Topics)
			for _, l := range Topics {
				isHigh := t.absolute(s.topics[l.Name]) == ConfHigh
				switch {
				case isHigh && want[l.Name]:
					tp++
				case isHigh:
					fp++
				case want[l.Name]:
					fn++
				}
			}
		}
		p, r, f := prf(tp, fp, fn)
		fmt.Fprintf(out, "  %-8.2f %-10.3f %-10.3f %-10.3f\n", prob, p, r, f)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "Pick by how the rules use the label, not by F1 alone: a topic the corpus")
	fmt.Fprintln(out, "negates to exclude benign mail wants recall, because a missed exclusion is a")
	fmt.Fprintln(out, "false positive. Set the chosen values with -high-ratio and -high-prob.")
	return nil
}

// highExclusive returns the labels a threshold set would call high.
func highExclusive(scores map[string]float64, labels []Label, t Thresholds) map[string]bool {
	total := 0.0
	for _, l := range labels {
		total += scores[l.Name]
	}
	out := map[string]bool{}
	if total <= 0 {
		return out
	}
	shares := make(map[string]float64, len(labels))
	for _, l := range labels {
		shares[l.Name] = scores[l.Name] / total
	}
	runnerUp := secondHighest(shares)
	for _, l := range labels {
		if t.exclusive(shares[l.Name], runnerUp) == ConfHigh {
			out[l.Name] = true
		}
	}
	return out
}

func set(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func prf(tp, fp, fn int) (precision, recall, f1 float64) {
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn)
	}
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	return
}

// SampleCalibrationSet writes a starter file naming every label, so an operator
// labelling their own mail does not have to copy the vocabulary out of the source.
func SampleCalibrationSet(out io.Writer) error {
	names := append(Names(Intents), "")
	sort.Strings(names)
	fmt.Fprintln(out, "# One JSON object per line. Labels a human judges correct.")
	fmt.Fprintf(out, "# intents: %v\n", Names(Intents))
	fmt.Fprintln(out, "# topics: see labels.go; 33 of them, Title Case, exact spacing")
	fmt.Fprintln(out, `{"text":"Your password expires today, verify your account","intents":["cred_theft"],"topics":["Security and Authentication"]}`)
	fmt.Fprintln(out, `{"text":"Notes from yesterday's planning meeting are attached","intents":["benign"],"topics":[]}`)
	return nil
}

var _ = os.Stdout
