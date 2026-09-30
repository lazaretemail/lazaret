// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log"
	"strings"
	"time"
)

// Compiling every shape before answering anything.
//
// A graph compiler does not compile a model, it compiles a model *for a given input
// shape*, on first use, and caches the result. Measured on an RX 9060 XT: the first
// request took two to three minutes and the next took three tenths of a second.
//
// Left alone, that cost lands on real messages, and it lands badly. The label sets
// compile independently, so a message analysed during warm-up comes back with its
// intents but not its topics, or its topics but not its tags — a complete-looking
// answer that quietly omits whatever had not finished compiling. Two identical
// requests returned different results for exactly this reason, and neither was
// marked incomplete.
//
// That is the failure this project exists to avoid making: a partial answer
// presented as a whole one. So every combination is compiled here, before the
// service accepts a single request. A cold cache makes startup slow and says so; a
// warm one costs about ten seconds.

// warmupText is a body long enough to clear the fragment threshold and to exercise
// a realistic sequence length.
const warmupText = "Please review the attached invoice and confirm the payment details " +
	"for this account before the end of the week so that the transfer can be scheduled."

// Warm compiles every label set the classifier can be asked for.
//
// Returns the time spent, so the caller can say whether this was a cold cache or a
// warm one — the difference is three minutes against ten seconds, and an operator
// watching a slow start deserves to know which they are looking at.
func Warm(ctx context.Context, r *Registry) time.Duration {
	start := time.Now()

	m, ok := r.models["ml.nlu_classifier"]
	if !ok {
		return 0
	}
	nlu, ok := m.(*NLU)
	if !ok || nlu.model == nil {
		return 0
	}

	// One per label set, because each compiles separately. The sequence buckets in
	// the tokeniser mean a handful of shapes rather than one per message, and the
	// longest is compiled here: a shorter text pads up to a bucket that is compiled
	// on demand, which is fast, while the longest is the expensive one.
	sets := []struct {
		name   string
		labels []Label
		multi  bool
	}{
		{"intents", Intents, false},
		{"topics", Topics, true},
		{"tags", Tags, true},
	}

	text := warmupText
	for _, s := range sets {
		if ctx.Err() != nil {
			log.Printf("lazaret-ml: warm-up interrupted during %s", s.name)
			return time.Since(start)
		}
		t := time.Now()
		if _, err := nlu.classify(ctx, text, s.labels, s.multi); err != nil {
			log.Printf("lazaret-ml: warming %s: %v", s.name, err)
			continue
		}
		log.Printf("lazaret-ml: warmed %s in %s", s.name, time.Since(t).Round(time.Millisecond))
	}

	// A long text as well, so the widest sequence bucket is compiled too rather
	// than being paid for by whichever message happens to be long.
	long := strings.Repeat(warmupText+" ", 8)
	if ctx.Err() == nil {
		if _, err := nlu.classify(ctx, long, Intents, false); err != nil {
			log.Printf("lazaret-ml: warming the long sequence: %v", err)
		}
	}

	return time.Since(start)
}
