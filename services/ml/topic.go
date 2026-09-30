// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log"
)

// Topic answers beta.ml_topic.
//
// The same classification as ml.nlu_classifier's .topics, reached through a different
// function name — 14 rules call it and read `.topics`, exactly as they would on the
// NLU result. It shares the NLU's model rather than loading a second copy, so the two
// cannot disagree about the same message.
type Topic struct{ nlu *NLU }

func (t *Topic) Capability() string { return "beta.ml_topic" }
func (t *Topic) Close() error       { return nil }

type topicResult struct {
	Topics *[]jsonFinding `json:"topics,omitempty"`

	Unavailable bool `json:"unavailable,omitempty"`
}

func (t *Topic) Infer(ctx context.Context, req Request) (any, error) {
	text := normaliseBody(req.Text)
	if t.nlu == nil || t.nlu.model == nil || text == "" {
		return topicResult{Unavailable: true}, nil
	}
	fs, err := t.nlu.classify(ctx, text, Topics, true)
	if err != nil {
		log.Printf("beta.ml_topic: %v", err)
		return topicResult{Unavailable: true}, nil
	}
	j := toJSON(fs)
	return topicResult{Topics: &j}, nil
}
