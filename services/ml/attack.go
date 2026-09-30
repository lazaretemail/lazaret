// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"strings"
)

// AttackScore answers ml.attack_score and beta.fuzzy_attack_score.
//
// These are the only capabilities here that take no argument: `fuzzy_attack_score()`
// is called bare and is a judgement about the whole message rather than about a value
// in it. So the request carries the message model instead of a string, and the score
// is a composition over signals the rest of the platform already produced — the NLU
// intents, the authentication results, the bulk-mail headers — rather than a separate
// model.
//
// Composition rather than a model is not a shortcut here. A meta-model over other
// models' outputs needs labelled verdicts to train against, which is precisely the
// data an open implementation does not have; a stated combination of signals can at
// least be read, argued with and changed by an operator who disagrees with it.
//
// The corpus reads exactly one thing off this: `.verdict == "graymail"`, in a rule
// that flags graymail. So graymail is the verdict that has to be right, and it is also
// the most tractable: bulk mail announces itself in its headers.
type AttackScore struct {
	cap string
	nlu *NLU
}

func (a *AttackScore) Capability() string { return a.cap }
func (a *AttackScore) Close() error       { return nil }

type attackResult struct {
	Score      *float64 `json:"score,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
}

// messageView is the part of the message model this needs. Deliberately small: the
// service is sent a subset rather than the whole model, so that adding a field here is
// a visible change to the contract between the two.
type messageView struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Headers struct {
		ListUnsubscribe string            `json:"list_unsubscribe"`
		Precedence      string            `json:"precedence"`
		AutoSubmitted   string            `json:"auto_submitted"`
		Other           map[string]string `json:"other"`
	} `json:"headers"`
	Auth struct {
		DMARCPass *bool `json:"dmarc_pass"`
		SPFPass   *bool `json:"spf_pass"`
		DKIMPass  *bool `json:"dkim_pass"`
	} `json:"auth"`
	SenderDomain  string `json:"sender_domain"`
	FirstContact  *bool  `json:"first_contact"`
	LinkCount     int    `json:"link_count"`
	AttachedFiles int    `json:"attached_files"`
}

func (a *AttackScore) Infer(ctx context.Context, req Request) (any, error) {
	var m messageView
	if len(req.MDM) > 0 {
		if err := json.Unmarshal(req.MDM, &m); err != nil {
			return nil, err
		}
	}

	bulk := bulkSignals(&m)

	// Intents, when a model is loaded. Without one there is no opinion about intent,
	// and the verdict says so rather than defaulting to benign.
	var intents map[string]string
	if a.nlu != nil && a.nlu.model != nil {
		text := strings.TrimSpace(m.Subject + "\n\n" + m.Body)
		if fs, err := a.nlu.classify(ctx, normaliseBody(text), Intents, false); err == nil {
			intents = map[string]string{}
			for _, f := range fs {
				intents[f.Name] = f.Confidence
			}
		}
	}

	res := attackResult{}
	switch {
	case intents == nil && bulk < 2:
		// No intent model and nothing decisive in the headers: no verdict. An
		// omitted verdict reads as null in MQL, so `== "graymail"` is null rather
		// than false and the rule reports indeterminate.
		return res, nil

	case malicious(intents):
		s := 0.9
		res.Score, res.Verdict, res.Confidence = &s, "malicious", ConfHigh

	case bulk >= 2 && !suspicious(intents):
		// Graymail: bulk mail that nothing suggests is an attack. Two independent
		// bulk signals rather than one, because List-Unsubscribe alone is now added
		// by plenty of ordinary automated mail.
		s := 0.2
		conf := ConfMedium
		if bulk >= 3 {
			conf = ConfHigh
		}
		res.Score, res.Verdict, res.Confidence = &s, "graymail", conf

	case suspicious(intents):
		s := 0.6
		res.Score, res.Verdict, res.Confidence = &s, "suspicious", ConfMedium

	default:
		s := 0.05
		res.Score, res.Verdict, res.Confidence = &s, "benign", ConfMedium
	}

	if m.Auth.DMARCPass != nil && !*m.Auth.DMARCPass && res.Verdict == "benign" {
		res.Verdict, res.Confidence = "suspicious", ConfLow
		s := 0.4
		res.Score = &s
	}
	return res, nil
}

// bulkSignals counts the independent indications that a message was sent to a list.
func bulkSignals(m *messageView) int {
	n := 0
	if m.Headers.ListUnsubscribe != "" {
		n++
	}
	switch strings.ToLower(m.Headers.Precedence) {
	case "bulk", "list", "junk":
		n++
	}
	if m.Headers.AutoSubmitted != "" && !strings.EqualFold(m.Headers.AutoSubmitted, "no") {
		n++
	}
	for k := range m.Headers.Other {
		switch strings.ToLower(k) {
		case "x-campaign", "x-campaignid", "x-mailer-campaign", "x-csa-complaints",
			"x-feedback-id", "list-id", "x-marketing", "x-mailgun-tag", "x-ses-configuration-set":
			n++
		}
	}
	return n
}

func malicious(intents map[string]string) bool {
	for _, name := range []string{"cred_theft", "bec", "extortion", "advance_fee", "callback_scam"} {
		if intents[name] == ConfHigh {
			return true
		}
	}
	return false
}

func suspicious(intents map[string]string) bool {
	if intents == nil {
		return false
	}
	for name, conf := range intents {
		if name == "benign" {
			continue
		}
		if conf == ConfHigh || conf == ConfMedium {
			return true
		}
	}
	return false
}
