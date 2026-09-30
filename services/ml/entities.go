// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"regexp"
	"sort"
	"strings"
)

// Entity extraction is lexical, and that is the right method rather than a concession.
//
// The nine entities the corpus reads are surface features of a message. A greeting is
// the words "Dear Sir"; a salutation is "Kind regards"; a disclaimer is the block of
// legal text at the bottom; an org is a company name; urgency is the words that convey
// it. Rules read .text on an entity 209 times — more often than .confidence — because
// what a rule wants is the span, and a model that returns a label without the words
// behind it would answer a question nobody asked.
//
// The classification tasks in this service go to the entailment model. These do not,
// and swapping them for one would make them worse.

type entityRule struct {
	name string
	re   *regexp.Regexp
	// strong marks a pattern specific enough that one hit is high confidence. The
	// weak ones need corroboration, because "please" is a request the same way every
	// polite sentence is one.
	strong bool
}

// The patterns are deliberately anchored on phrasing rather than single words. A rule
// asking whether a message conveys urgency is not asking whether it contains "now".
var entityRules = []entityRule{
	// urgency — 38 corpus references.
	{"urgency", regexp.MustCompile(`(?i)\b(?:as soon as possible|asap|right away|immediately|without delay|urgently|time[- ]sensitive|act now|expires? (?:today|tonight|in \d+|soon)|within (?:the next )?\d+ (?:minutes?|hours?)|before (?:the )?(?:end of (?:the )?(?:day|business)|cob|eod)|last (?:chance|warning|reminder)|final (?:notice|reminder|warning)|deadline is|no later than)\b`), true},
	{"urgency", regexp.MustCompile(`(?i)\b(?:urgent|important|priority|critical|attention required|action required|immediate action)\b`), false},

	// financial — 35 references.
	{"financial", regexp.MustCompile(`(?i)\b(?:wire transfer|bank transfer|wire the|remittance|ach (?:transfer|payment)|swift code|iban\b|routing number|account number|beneficiary|payment (?:details|instructions|information)|invoice (?:number|attached|payment)|outstanding balance|past due|overdue (?:payment|invoice)|gift cards?|bitcoin|btc\b|cryptocurrency|crypto wallet|western union|moneygram|zelle|purchase order)\b`), true},
	{"financial", regexp.MustCompile(`(?i)(?:[$£€]\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*(?:\.\d{2})?\s?(?:usd|eur|gbp|dollars?|euros?|pounds?)\b)`), false},

	// request — 55 references, the most-read entity.
	{"request", regexp.MustCompile(`(?i)\b(?:(?:can|could|would) you (?:please )?(?:kindly )?\w+|i need you to|i would like you to|please (?:confirm|verify|review|process|complete|update|send|provide|approve|arrange|action|proceed|advise|reply|respond|sign|click|download|open|call)|kindly (?:confirm|verify|review|process|send|provide|advise|revert)|let me know (?:if|when|your|asap)|awaiting your (?:response|reply|confirmation)|get back to me|revert (?:back )?to me|are you (?:at your desk|available|around|in the office))\b`), true},

	// greeting — 5 references. The opening address.
	{"greeting", regexp.MustCompile(`(?im)^\s*(?:hi|hello|hey|dear|good (?:morning|afternoon|evening)|greetings|to whom it may concern)\b[^\n]{0,60}`), true},

	// salutation — 2 references. The closing.
	{"salutation", regexp.MustCompile(`(?im)^\s*(?:(?:kind|best|warm)(?:est)? regards|regards|sincerely|yours (?:sincerely|faithfully|truly)|thanks?(?: you)?(?: again)?|cheers|respectfully|cordially|best wishes|many thanks)\b[^\n]{0,40}`), true},

	// disclaimer — 11 references. The legal block, usually appended by a gateway.
	{"disclaimer", regexp.MustCompile(`(?i)(?:this (?:e-?mail|message|communication)(?: and any attachments?)? (?:is|are|may be) (?:confidential|intended|privileged)|confidentiality notice|the information (?:contained )?in this (?:e-?mail|message)|if you (?:are not the intended recipient|have received this (?:e-?mail|message) in error)|unauthori[sz]ed (?:use|disclosure|copying|dissemination)|please (?:notify the sender|delete this (?:e-?mail|message))|caution: this e-?mail originated|external e-?mail)[^\n]{0,400}`), true},
}

// Organisation names: capitalised runs ending in a company suffix, plus bare runs of
// capitalised words. The suffix form is strong; the bare form is not, because a
// capitalised run is also how a sentence starts.
var (
	orgSuffix = regexp.MustCompile(`\b(?:[A-Z][\w&.-]*\s+){0,4}[A-Z][\w&.-]*\s*(?:,?\s*(?:Inc|Incorporated|LLC|L\.L\.C|Ltd|Limited|LLP|PLC|GmbH|S\.A|SARL|B\.V|A/S|AB|Oy|Pty|Corp|Corporation|Co|Company|Group|Holdings|Bank|Trust|Partners|Capital|Technologies|Solutions|Systems|Services)\b\.?)`)
	orgBare   = regexp.MustCompile(`\b(?:[A-Z][a-z]{2,}\s+){1,3}[A-Z][a-z]{2,}\b`)

	// sender / recipient identification.
	senderSign = regexp.MustCompile(`(?im)^\s*(?:--\s*\n)?\s*([A-Z][a-z]+(?:\s+[A-Z]\.?)?(?:\s+[A-Z][a-z]+){0,2})\s*$`)
	addressed  = regexp.MustCompile(`(?im)^\s*(?:hi|hello|hey|dear)\s+((?:[A-Z][\w'’-]+)(?:\s+[A-Z][\w'’-]+){0,2})\b`)
)

// extractEntities finds every entity in the text.
//
// Ordered by position, and deduplicated by (name, span): a message that says "urgent"
// four times conveys urgency once, and a rule counting findings should not be counting
// repetitions of the same word.
func extractEntities(text string) []finding {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	// A bound on the work, not on the answer: the patterns are linear, but a 5MB body
	// pasted into a thread is not made more classifiable by scanning all of it.
	const limit = 200 << 10
	if len(text) > limit {
		text = text[:limit]
	}

	var out []finding
	seen := map[string]bool{}
	add := func(name, span string, conf string, at int) {
		span = strings.TrimSpace(collapse(span))
		if span == "" || len(span) > 500 {
			return
		}
		key := name + "\x00" + strings.ToLower(span)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, finding{Name: name, Text: span, Confidence: conf, at: at})
	}

	// Count how many distinct strong signals each weak entity has, so a single
	// currency amount is medium and an amount plus "wire transfer" is high.
	strongHits := map[string]int{}
	for _, r := range entityRules {
		if !r.strong {
			continue
		}
		for _, m := range r.re.FindAllStringIndex(text, 8) {
			// A salutation is a sign-off, so position is part of what makes it one.
			// "Thank you for your purchase" opening a receipt matches the same words
			// and is not a salutation; requiring it in the last part of the message
			// is what separates them.
			if r.name == "salutation" && !nearEnd(text, m[0]) {
				continue
			}
			strongHits[r.name]++
			add(r.name, text[m[0]:m[1]], ConfHigh, m[0])
		}
	}
	for _, r := range entityRules {
		if r.strong {
			continue
		}
		conf := ConfMedium
		if strongHits[r.name] > 0 {
			conf = ConfHigh
		}
		for _, m := range r.re.FindAllStringIndex(text, 8) {
			add(r.name, text[m[0]:m[1]], conf, m[0])
		}
	}

	for _, m := range orgSuffix.FindAllStringIndex(text, 12) {
		add("org", text[m[0]:m[1]], ConfHigh, m[0])
	}
	if len(strongHits) >= 0 {
		for _, m := range orgBare.FindAllStringIndex(text, 12) {
			span := text[m[0]:m[1]]
			if isSentenceStart(text, m[0]) || commonPhrase(span) {
				continue
			}
			add("org", span, ConfMedium, m[0])
		}
	}

	for _, m := range addressed.FindAllStringSubmatchIndex(text, 3) {
		add("recipient", text[m[2]:m[3]], ConfHigh, m[2])
	}
	// The sender's own name, taken from the sign-off: a bare capitalised line in the
	// last part of the message, after a salutation.
	if tail := lastPart(text); tail != "" {
		for _, m := range senderSign.FindAllStringSubmatchIndex(tail, 3) {
			name := tail[m[2]:m[3]]
			if commonPhrase(name) {
				continue
			}
			add("sender", name, ConfMedium, len(text)-len(tail)+m[2])
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].at < out[j].at })
	return out
}

// nearEnd reports whether an offset falls in the closing part of the message: the
// last third, or within four lines of the end, whichever is more generous. Both, because
// a two-line message has no last third worth speaking of and a long one has no last four
// lines that mean anything.
func nearEnd(text string, at int) bool {
	if at*3 >= len(text)*2 {
		return true
	}
	return strings.Count(text[at:], "\n") <= 4
}

// lastPart returns the text after the final salutation, which is where a sign-off is.
func lastPart(text string) string {
	idx := -1
	for _, r := range entityRules {
		if r.name != "salutation" {
			continue
		}
		for _, m := range r.re.FindAllStringIndex(text, -1) {
			if m[1] > idx && nearEnd(text, m[0]) {
				idx = m[1]
			}
		}
	}
	if idx < 0 {
		return ""
	}
	return text[idx:]
}

func isSentenceStart(text string, at int) bool {
	for i := at - 1; i >= 0 && at-i < 4; i-- {
		switch text[i] {
		case ' ', '\t':
			continue
		case '.', '!', '?', '\n', '\r':
			return true
		default:
			return false
		}
	}
	return at == 0
}

// commonPhrase filters the capitalised runs that are English rather than names.
var commonPhrases = map[string]bool{
	"thank you": true, "best regards": true, "kind regards": true, "good morning": true,
	"good afternoon": true, "good evening": true, "dear sir": true, "dear madam": true,
	"please note": true, "let me": true, "i am": true, "we are": true,
	"click here": true, "learn more": true, "read more": true, "sign in": true,
	"log in": true, "get started": true, "view online": true, "privacy policy": true,
	"terms of service": true, "all rights reserved": true, "unsubscribe here": true,
}

func commonPhrase(s string) bool { return commonPhrases[strings.ToLower(strings.TrimSpace(s))] }

var spaces = regexp.MustCompile(`\s+`)

func collapse(s string) string { return spaces.ReplaceAllString(s, " ") }
