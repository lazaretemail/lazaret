// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/netip"

	"context"
	"fmt"
	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/rdap"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rules"
)

// The facts behind a verdict, written in the same language as the rules.
//
// An analyst looking at a flagged message asks the same questions every time: has
// this sender written before, how old is the domain, does the reply-to match, what
// did the links point at, what did the classifier think. Those are not verdicts and
// they are not rules — they are the evidence a person weighs before agreeing or
// overruling.
//
// Each is an MQL expression rather than Go reaching into the model. Three reasons,
// and the third is the one that matters:
//
//   - it runs against the same enricher the rules used, through the same per-message
//     cache, so an insight cannot disagree with a detection about the same fact;
//   - adding one is a line of MQL, which is the language an operator already has to
//     know to read their own rules;
//   - and it is checked by the same type checker, so an insight naming a field that
//     does not exist fails at startup rather than rendering blank forever.

// insightSpec is one fact worth showing.
type insightSpec struct {
	// Label is what a person reads.
	Label string

	// Expr is the MQL that produces the value.
	Expr string

	// Warn marks a fact that is notable when truthy — a mismatch, a new domain. It
	// is shown prominently and only when its value is true or non-empty.
	//
	// Facts without it are context: shown whatever the value, because "SPF passed"
	// and "this domain is nineteen years old" are exactly as useful as their
	// opposites when deciding whether a rule was right.
	Warn bool

	// Group orders the grid: identity first, then reputation, then content.
	Group string
}

// insightSpecs is the catalogue. Deliberately a list rather than a config file: it
// is part of what the product *is*, and an operator who wants different ones is
// better served by a rule.
var insightSpecs = []insightSpec{
	// Who sent it, and does the envelope agree with itself.
	{Group: "identity", Label: "Sender", Expr: `sender.email.email`},
	{Group: "identity", Label: "Sender display name", Expr: `sender.display_name`},
	{Group: "identity", Label: "Sender domain", Expr: `sender.email.domain.domain`},
	{Group: "identity", Label: "Return path", Expr: `headers.return_path.email`},
	{Group: "identity", Label: "Reply-to", Expr: `map(headers.reply_to, .email.email)`},
	{Group: "identity", Label: "Reply-to differs from sender", Warn: true,
		Expr: `any(headers.reply_to, .email.domain.domain != sender.email.domain.domain)`},
	{Group: "identity", Label: "Return path differs from sender", Warn: true,
		Expr: `headers.return_path.domain.domain != sender.email.domain.domain`},
	{Group: "identity", Label: "Message-ID", Expr: `headers.message_id`},
	{Group: "identity", Label: "Recipients", Expr: `length(recipients.to)`},
	{Group: "identity", Label: "Sender is also the only recipient", Warn: true,
		Expr: `length(recipients.to) == 1 and any(recipients.to, .email.email == sender.email.email)`},

	// What history says. These need the profile store, and report unavailable
	// rather than "no" when it cannot be reached — a missing profile is not an
	// empty one.
	{Group: "reputation", Label: "Sender prevalence", Expr: `profile.by_sender().prevalence`},
	{Group: "reputation", Label: "You have written to them before", Expr: `profile.by_sender().solicited`},
	{Group: "reputation", Label: "Previously judged benign", Expr: `profile.by_sender().any_messages_benign`},
	{Group: "reputation", Label: "Previously judged malicious", Warn: true,
		Expr: `profile.by_sender().any_messages_malicious_or_spam`},

	// What the registry says about the domain.
	{Group: "reputation", Label: "Sender domain age (days)", Expr: `network.whois(sender.email.domain.domain).days_old`},
	{Group: "reputation", Label: "Sender domain registered in the last 30 days", Warn: true,
		Expr: `network.whois(sender.email.domain.domain).days_old < 30`},
	{Group: "reputation", Label: "Registrar", Expr: `network.whois(sender.email.domain.domain).registrar_name`},
	{Group: "reputation", Label: "Registrant", Expr: `network.whois(sender.email.domain.domain).registrant_company`},
	{Group: "reputation", Label: "Registrant country", Expr: `network.whois(sender.email.domain.domain).registrant_country`},

	// Where it points.
	{Group: "content", Label: "Links in body", Expr: `length(body.links)`},
	{Group: "content", Label: "Link domains",
		Expr: `distinct(map(body.links, .href_url.domain.domain))`},
	{Group: "content", Label: "A link domain is newly registered", Warn: true,
		Expr: `any(body.links, network.whois(.href_url.domain.domain).days_old < 30)`},
	{Group: "content", Label: "A link uses a URL shortener", Warn: true,
		Expr: `any(body.links, .href_url.domain.root_domain in $url_shorteners)`},
	{Group: "content", Label: "Link text disagrees with its destination", Warn: true,
		Expr: `any(body.links, strings.contains(.display_text, "://") and not strings.contains(.display_text, .href_url.domain.domain))`},
	{Group: "content", Label: "Attachments", Expr: `length(attachments)`},

	// What the classifier made of it.
	{Group: "content", Label: "Language", Expr: `ml.nlu_classifier(body.current_thread.text).language`},
	{Group: "content", Label: "Intent",
		Expr: `map(filter(ml.nlu_classifier(body.current_thread.text).intents, .confidence in ("high", "medium")), .name)`},
	{Group: "content", Label: "Topic",
		Expr: `map(filter(ml.nlu_classifier(body.current_thread.text).topics, .confidence == "high"), .name)`},
	{Group: "content", Label: "Urgency or financial language", Warn: true,
		Expr: `any(ml.nlu_classifier(body.current_thread.text).entities, .name in ("urgency", "financial"))`},
}

// Insight is one evaluated fact.
type Insight struct {
	Label string `json:"label"`
	Group string `json:"group"`
	Value any    `json:"value,omitempty"`

	// Warn is set when this is a notable finding rather than context.
	Warn bool `json:"warn,omitempty"`

	// Unknown says the fact could not be established — a capability was missing, not
	// that the answer was no. The distinction is the whole point of the engine and
	// it has to survive into the page, or an analyst reads "no" where the truth is
	// "nobody looked".
	Unknown bool `json:"unknown,omitempty"`

	// Missing names what would have answered it.
	Missing []string `json:"missing,omitempty"`
}

// compiledInsights is the catalogue, compiled once.
var (
	insightsOnce sync.Once
	compiled     []compiledInsight
)

type compiledInsight struct {
	spec    insightSpec
	checked *mql.Checked
}

func buildInsights() {
	for _, spec := range insightSpecs {
		c, err := mql.Compile(spec.Expr, nil)
		if err != nil {
			// Skipped rather than fatal: one bad insight should not stop the
			// service, and the log names it precisely enough to fix.
			log.Printf("insight %q does not compile: %v", spec.Label, err)
			continue
		}
		compiled = append(compiled, compiledInsight{spec: spec, checked: c})
	}
}

// messageInsights evaluates the catalogue against one message.
func (p *Pipeline) messageInsights(ctx context.Context, msg *mdm.MessageDataModel, enricher mql.Enricher) []Insight {
	insightsOnce.Do(buildInsights)

	out := make([]Insight, 0, len(compiled))
	for _, ci := range compiled {
		res := mql.Eval(ctx, ci.checked, msg, &mql.EvalOptions{
			Enricher: enricher,
			Lists:    p.lists,
		})

		in := Insight{Label: ci.spec.Label, Group: ci.spec.Group, Warn: ci.spec.Warn}
		switch {
		case res.Err != nil:
			continue
		case len(res.Missing) > 0 && res.Value.IsNull():
			in.Unknown = true
			for _, m := range res.Missing {
				in.Missing = append(in.Missing, string(m))
			}
		case res.Value.IsNull():
			// Nothing to say. A warn-fact that is simply false is not shown at all;
			// a context fact with no value is not worth a row either.
			continue
		default:
			in.Value = res.Value.Interface()
		}

		// A notable fact is only notable when it holds. "Reply-to differs from
		// sender: false" is noise on every ordinary message.
		if in.Warn && !in.Unknown && !truthy(in.Value) {
			continue
		}
		// An empty list is not a fact worth a row. "Reply-to:" with nothing after
		// it reads as though the value failed to load, when what it means is that
		// the header was not present.
		if !in.Unknown && !hasValue(in.Value) {
			continue
		}
		out = append(out, in)
	}
	return out
}

// hasValue reports whether there is anything to show.
//
// Distinct from truthy: `false` and `0` are worth showing as context — "attachments:
// 0" answers a question — while an empty string or an empty list is just an absent
// header rendered as a blank row.
func hasValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(t) != ""
	case []any:
		return len(t) > 0
	}
	return true
}

// truthy reports whether an insight value counts as present.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return strings.TrimSpace(t) != ""
	case []any:
		return len(t) > 0
	case float64:
		return t != 0
	case int64:
		return t != 0
	}
	return true
}

// attackSignals turns the matched rules into the short plain-English account a person
// reads first.
//
// Not a second detection pass: it is the same rules, grouped by what they were about,
// so the top of the page says "why" in a sentence before the list says "which rule".
// A page that opens with eleven rule names has told an analyst nothing they can act
// on until they have read all eleven.
func attackSignals(flagged []Detection, insights []Insight) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	for _, in := range insights {
		if !in.Warn || in.Unknown {
			continue
		}
		switch in.Label {
		case "Sender domain registered in the last 30 days":
			add("The sending domain was registered within the last month. Newly registered domains are " +
				"the cheapest way to get a clean reputation, and are strongly associated with attacks.")
		case "A link domain is newly registered":
			add("A domain linked in the message was registered within the last month.")
		case "Reply-to differs from sender":
			add("Replies would go to a different domain than the one that sent the message, which is how " +
				"a conversation gets moved somewhere the sender controls.")
		case "A link uses a URL shortener":
			add("A link is shortened, which hides where it actually goes.")
		case "Link text disagrees with its destination":
			add("A link displays one address and points at another.")
		case "Previously judged malicious":
			add("This sender has sent mail judged malicious before.")
		case "Sender is also the only recipient":
			add("The sender and the only recipient are the same address, which usually means the real " +
				"recipients are hidden in BCC.")
		case "Return path differs from sender":
			add("The bounce address is on a different domain than the visible sender, which is common " +
				"in bulk sending and also in spoofing.")
		case "Urgency or financial language":
			add("The message combines time pressure with money, which is the shape of most payment " +
				"fraud and is what a classifier is for.")
		}
	}

	// Severity from the rules themselves, so the account leads with the worst thing.
	for _, d := range flagged {
		if strings.EqualFold(d.Severity, "critical") {
			add(fmt.Sprintf("A rule rated critical matched: %s.", d.Name))
		}
	}

	// A flagged message always gets an account, even when none of the catalogued
	// signals applies. The rules caught something the insight catalogue has no
	// sentence for, and an empty explanation above a red banner is worse than a
	// plain one — it reads as though the verdict came from nowhere.
	if len(out) == 0 && len(flagged) > 0 {
		names := make([]string, 0, 3)
		for _, d := range flagged {
			if len(names) == 3 {
				break
			}
			names = append(names, d.Name)
		}
		more := ""
		if len(flagged) > len(names) {
			more = fmt.Sprintf(", and %d more", len(flagged)-len(names))
		}
		add(fmt.Sprintf("Flagged by %s%s. The evidence below is what the rules were reading.",
			strings.Join(names, "; "), more))
	}
	return out
}

// SenderDetails is what is known about who sent this, beyond the message itself.
type SenderDetails struct {
	Address     string `json:"address,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Domain      string `json:"domain,omitempty"`

	// Prevalence is the profile store's word: new, outlier, common. Empty when the
	// store could not be reached, which is not the same as "new" — a missing
	// profile read as a brand-new sender would fire every first-contact rule.
	Prevalence string `json:"prevalence,omitempty"`
	Known      bool   `json:"known"`

	Solicited    bool `json:"solicited"`
	SeenBenign   bool `json:"seen_benign"`
	SeenBad      bool `json:"seen_bad"`
	MessageCount int  `json:"message_count"`

	FirstContact string `json:"first_contact,omitempty"`
	LastContact  string `json:"last_contact,omitempty"`

	// RootDomain is the registrable domain, which is what the registry holds and
	// what most rules key on.
	RootDomain string `json:"root_domain,omitempty"`

	// DomainInfo is the registry's view, in the same shape the links table uses.
	DomainInfo
}

// senderDetails gathers the sender panel, again through MQL so it agrees with the
// rules.
func (p *Pipeline) senderDetails(ctx context.Context, msg *mdm.MessageDataModel, enricher mql.Enricher) SenderDetails {
	out := SenderDetails{}
	if msg.Sender != nil {
		out.DisplayName = mdm.Deref(msg.Sender.DisplayName)
		if msg.Sender.Email != nil {
			out.Address = mdm.Deref(msg.Sender.Email.Email)
			if d := msg.Sender.Email.Domain; d != nil {
				out.Domain = d.Domain
				out.RootDomain = mdm.Deref(d.RootDomain)
			}
		}
	}

	eval := func(expr string) (mql.Value, bool) {
		c, err := mql.Compile(expr, nil)
		if err != nil {
			return mql.NullValue, false
		}
		res := mql.Eval(ctx, c, msg, &mql.EvalOptions{Enricher: enricher, Lists: p.lists})
		if res.Err != nil || res.Value.IsNull() {
			return mql.NullValue, false
		}
		return res.Value, true
	}

	if v, ok := eval(`profile.by_sender().prevalence`); ok {
		out.Prevalence, _ = v.AsString()
		out.Known = true
	}
	if v, ok := eval(`profile.by_sender().solicited`); ok {
		out.Solicited, _ = v.AsBool()
	}
	if v, ok := eval(`profile.by_sender().any_messages_benign`); ok {
		out.SeenBenign, _ = v.AsBool()
	}
	if v, ok := eval(`profile.by_sender().any_messages_malicious_or_spam`); ok {
		out.SeenBad, _ = v.AsBool()
	}

	out.DomainInfo = lookupDomain(ctx, enricher, out.Domain, out.RootDomain)
	return out
}

// authBadges is the three-state authentication summary a person reads at a glance.
//
// Three states, not two. "No DKIM signature" and "DKIM failed" are different facts
// about a message and collapsing them into a red cross is how an analyst comes to
// distrust the badge — plenty of legitimate mail is unsigned.
type authBadge struct {
	Name   string `json:"name"`
	State  string `json:"state"` // pass | fail | absent
	Detail string `json:"detail,omitempty"`
}

func authBadges(m *mdm.MessageDataModel) []authBadge {
	out := []authBadge{}
	if m.Headers == nil || m.Headers.AuthSummary == nil {
		return out
	}
	as := m.Headers.AuthSummary

	badge := func(name string, pass *bool, detail string) authBadge {
		switch {
		case pass == nil:
			return authBadge{Name: name, State: "absent", Detail: detail}
		case *pass:
			return authBadge{Name: name, State: "pass", Detail: detail}
		default:
			return authBadge{Name: name, State: "fail", Detail: detail}
		}
	}

	errText := func(e *bool) string {
		if e != nil && *e {
			return "the receiving MTA reported an error performing the check"
		}
		return ""
	}

	if as.DMARC != nil {
		out = append(out, badge("DMARC", as.DMARC.Pass, errText(as.DMARC.Error)))
	} else {
		out = append(out, authBadge{Name: "DMARC", State: "absent"})
	}
	if as.SPF != nil {
		out = append(out, badge("SPF", as.SPF.Pass, errText(as.SPF.Error)))
	} else {
		out = append(out, authBadge{Name: "SPF", State: "absent"})
	}
	// DKIM is absent from AuthSummary — DMARC alignment is what the rules ask about,
	// and a DKIM pass that does not align proves nothing about the visible sender.
	// Read from the receiving hop so the page can still say whether the message was
	// signed, which is a different fact from whether it aligned.
	out = append(out, dkimBadge(m))
	return out
}

func dkimBadge(m *mdm.MessageDataModel) authBadge {
	if m.Headers == nil {
		return authBadge{Name: "DKIM", State: "absent", Detail: "not signed"}
	}
	// The first hop is the one nearest the recipient, and its Authentication-Results
	// is the verdict the receiving MTA actually reached.
	for _, hop := range m.Headers.Hops {
		if hop == nil || hop.AuthenticationResults == nil {
			continue
		}
		d := hop.AuthenticationResults.DKIM
		if d == nil {
			continue
		}
		// An enumerated verdict, not a boolean, and the distinctions matter:
		// "none" means unsigned, while temperror and permerror mean the check
		// could not be completed. Reporting either as a failure would say the
		// signature was bad when nobody managed to look at it.
		switch *d {
		case mdm.AuthResultsDKIMPass:
			return authBadge{Name: "DKIM", State: "pass"}
		case mdm.AuthResultsDKIMFail, mdm.AuthResultsDKIMPolicy:
			return authBadge{Name: "DKIM", State: "fail"}
		case mdm.AuthResultsDKIMTemperror, mdm.AuthResultsDKIMPermerror:
			return authBadge{Name: "DKIM", State: "absent", Detail: "the receiving MTA could not complete the check"}
		case mdm.AuthResultsDKIMNone:
			return authBadge{Name: "DKIM", State: "absent", Detail: "not signed"}
		}
	}
	return authBadge{Name: "DKIM", State: "absent", Detail: "not signed, or the receiving MTA reported no result"}
}

// contentViews is the message as a person and as a machine.
//
// Four renderings of the same thing, because an analyst needs different ones at
// different moments: the text to read, the HTML to inspect for hidden content, and
// the model to check what the engine actually saw. A page that offers only the first
// makes the other two a shell command.
type contentView struct {
	Text        string `json:"text,omitempty"`
	HTML        string `json:"html,omitempty"`
	DisplayText string `json:"display_text,omitempty"`
	Subject     string `json:"subject,omitempty"`
}

func contentViews(m *mdm.MessageDataModel) contentView {
	out := contentView{}
	if m.Subject != nil {
		out.Subject = mdm.Deref(m.Subject.Subject)
	}
	if m.Body == nil {
		return out
	}
	if m.Body.CurrentThread != nil {
		out.Text = mdm.Deref(m.Body.CurrentThread.Text)
	}
	if m.Body.HTML != nil {
		out.HTML = mdm.Deref(m.Body.HTML.Raw)
		out.DisplayText = mdm.Deref(m.Body.HTML.DisplayText)
	}
	if out.Text == "" {
		if m.Body.Plain != nil {
			out.Text = mdm.Deref(m.Body.Plain.Raw)
		}
	}
	return out
}

// Summary is the header block: the handful of facts that identify a message.
type Summary struct {
	Subject    string   `json:"subject,omitempty"`
	Sender     string   `json:"sender,omitempty"`
	SenderName string   `json:"sender_name,omitempty"`
	Recipients []string `json:"recipients,omitempty"`
	ReplyTo    string   `json:"reply_to,omitempty"`
	ReturnPath string   `json:"return_path,omitempty"`
	Date       string   `json:"date,omitempty"`
	Direction  string   `json:"direction,omitempty"`
	Mailer     string   `json:"mailer,omitempty"`
	MessageID  string   `json:"message_id,omitempty"`

	Attachments int `json:"attachments"`
	Links       int `json:"links"`
}

func messageSummary(m *mdm.MessageDataModel) Summary {
	s := Summary{Attachments: len(m.Attachments)}
	if m.Subject != nil {
		s.Subject = mdm.Deref(m.Subject.Subject)
	}
	if m.Sender != nil {
		s.SenderName = mdm.Deref(m.Sender.DisplayName)
		if m.Sender.Email != nil {
			s.Sender = mdm.Deref(m.Sender.Email.Email)
		}
	}
	if m.Recipients != nil {
		for _, r := range m.Recipients.To {
			if r != nil && r.Email != nil {
				s.Recipients = append(s.Recipients, mdm.Deref(r.Email.Email))
			}
		}
	}
	if m.Headers != nil {
		s.MessageID = mdm.Deref(m.Headers.MessageID)
		s.Mailer = mdm.Deref(m.Headers.Mailer)
		if m.Headers.Date != nil {
			s.Date = m.Headers.Date.UTC().Format("2006-01-02 15:04 MST")
		}
		if m.Headers.ReturnPath != nil {
			s.ReturnPath = mdm.Deref(m.Headers.ReturnPath.Email)
		}
		for _, rt := range m.Headers.ReplyTo {
			if rt != nil && rt.Email != nil {
				s.ReplyTo = mdm.Deref(rt.Email.Email)
				break
			}
		}
	}
	if m.Type != nil {
		switch {
		case mdm.Deref(m.Type.Inbound):
			s.Direction = "inbound"
		case mdm.Deref(m.Type.Outbound):
			s.Direction = "outbound"
		case mdm.Deref(m.Type.Internal):
			s.Direction = "internal"
		}
	}
	if m.Body != nil {
		s.Links = len(m.Body.Links)
	}
	return s
}

// StoredAnalysis is the part of the detail view that costs enrichment to produce.
//
// Written once at ingest and read back on every view. Deliberately the whole shaped
// result rather than the raw enrichment outputs: replaying those would mean
// re-deciding what counts as an insight every time the catalogue changed, and a
// message's page would then show findings the verdict never saw.
type StoredAnalysis struct {
	// Schema is the shape of this blob. Analyses outlive the code that wrote them,
	// and a field added later is indistinguishable, once stored, from one that is
	// legitimately empty — so the version is recorded rather than guessed at. A blob
	// below the current version is recomputed on next view.
	Schema int `json:"schema,omitempty"`

	At            string        `json:"at,omitempty"`
	Detections    []Detection   `json:"detections"`
	Indeterminate []Detection   `json:"indeterminate"`
	Excluded      []Detection   `json:"excluded"`
	Queries       any           `json:"queries,omitempty"`
	Missing       []string      `json:"missing,omitempty"`
	Insights      []Insight     `json:"insights,omitempty"`
	Signals       []string      `json:"signals,omitempty"`
	Sender        SenderDetails `json:"sender"`

	// Links carries the domain intelligence, which is why it is stored rather than
	// derived on view: the registry lookups behind it are the expensive part of the
	// page and they do not change between clicks.
	Links []LinkDetail `json:"links,omitempty"`

	// Origin is the server that handed the message over, and who owns its address.
	Origin *OriginDetails `json:"origin,omitempty"`

	// Learned is what the model trained on this deployment's own reviews makes of
	// the message. Advisory, and absent until a model exists and is better than
	// guessing.
	Learned *LearnedScore `json:"learned,omitempty"`

	// Recomputed marks an answer produced now rather than read back — either
	// because it was asked for, or because this message predates stored analysis.
	// Shown in the page, because "this is what the rules say today" and "this is
	// what they said when it arrived" are different claims.
	Recomputed bool `json:"recomputed,omitempty"`
}

// analyseForDetail produces the stored analysis for one message.
//
// The single place that runs the rules and the insight catalogue together, so what
// is written at ingest and what a re-evaluation produces cannot drift apart.
//
// One cache across the whole thing: the rule run, the insights and the sender panel
// all ask for the same RDAP lookup and the same classifier pass, and without sharing
// they would each pay for it — and could each get a different answer when a lookup
// is flaky, leaving a page that disagrees with itself.
func (p *Pipeline) analyseForDetail(ctx context.Context, msg *mdm.MessageDataModel) *StoredAnalysis {
	cache := mql.NewCache(p.enricher)

	report := p.rules().RunWith(ctx, msg, &rules.RunOptions{
		Enricher: cache,
		Lists:    p.lists,
	})

	flagged := detections(report.Flagged)
	insights := p.messageInsights(ctx, msg, cache)
	sender := p.senderDetails(ctx, msg, cache)

	out := &StoredAnalysis{
		Schema:        analysisSchema,
		At:            time.Now().UTC().Format(time.RFC3339),
		Detections:    flagged,
		Indeterminate: detections(report.Indeterminate),
		Excluded:      detections(report.Excluded),
		Queries:       queryValues(report.Queries),
		Missing:       capList(report.Missing),
		Insights:      insights,
		Signals:       attackSignals(flagged, insights),
		Sender:        sender,
		Links:         p.linkDetails(ctx, msg, cache),
		Origin:        p.originDetails(ctx, msg, cache),
	}
	out.Learned = scoreWith(p.model.get(), out, messageSummary(msg), sender)
	return out
}

// analysisSchema is the current shape of a stored analysis. Bump it whenever the page
// starts showing something a stored blob would not contain.
//
//	1: detections, insights, sender, learned score
//	2: per-link domain intelligence
//	3: the sending server, and the sender domain sharing the links' registry shape
const analysisSchema = 3

// LinkDetail is one link, with what the registry says about where it goes.
//
// The domain intelligence is the point. A link's text and its destination are in the
// message and cost nothing to show; whether the domain it points at was registered
// last Tuesday is the thing that separates a phishing lure from a newsletter, and it
// is the first question an analyst asks about a link they do not recognise.
type LinkDetail struct {
	URL         string `json:"url"`
	DisplayText string `json:"display_text,omitempty"`
	Domain      string `json:"domain,omitempty"`
	RootDomain  string `json:"root_domain,omitempty"`

	// TextMismatch marks a link that displays one address and points at another.
	TextMismatch bool `json:"text_mismatch,omitempty"`

	// Shortener marks a destination that is itself a redirect, which hides the
	// real one.
	Shortener bool `json:"shortener,omitempty"`

	// DomainInfo is the registry's view of the domain, embedded so it stays the same
	// shape here, on the sender, and anywhere else a domain is shown.
	DomainInfo
}

// linkDetails summarises every link and looks up the domains behind them.
//
// One lookup per distinct domain, not per link: a newsletter with forty links to the same
// host asks the registry once. The per-message enricher cache does the deduplicating,
// which is also why this has to run with the same cache as everything else on the page —
// called with a fresh enricher it would be correct but slow.
//
// The enricher is called directly rather than through a compiled expression. The domain
// comes from the message, and the alternative — pasting it into MQL source — would let a
// sender choose what gets evaluated.
func (p *Pipeline) linkDetails(ctx context.Context, msg *mdm.MessageDataModel, enricher mql.Enricher) []LinkDetail {
	if msg.Body == nil || len(msg.Body.Links) == 0 {
		return nil
	}

	out := make([]LinkDetail, 0, len(msg.Body.Links))
	for _, l := range msg.Body.Links {
		if l == nil || l.HrefURL == nil {
			continue
		}
		d := LinkDetail{
			URL:         l.HrefURL.URL,
			DisplayText: mdm.Deref(l.DisplayText),
		}
		if l.HrefURL.Domain != nil {
			d.Domain = l.HrefURL.Domain.Domain
			d.RootDomain = mdm.Deref(l.HrefURL.Domain.RootDomain)
		}
		d.TextMismatch = textDisagrees(d.DisplayText, d.Domain)

		if d.Domain != "" {
			if p.lists != nil {
				if found, known := p.lists.Contains(ctx, "url_shorteners", mql.StringValue(d.Domain), true); known {
					d.Shortener = found
				}
			}
			d.DomainInfo = lookupDomain(ctx, enricher, d.Domain, d.RootDomain)
		}
		out = append(out, d)
	}
	return out
}

// DomainInfo is what the registry says about a domain.
//
// Known distinguishes "we could not ask" from "the registry answered". Registered is
// only meaningful once Known is true, and the difference between an unregistered domain
// and an unanswered lookup is the difference between a finding and an absence of one.
type DomainInfo struct {
	DomainKnown      bool `json:"domain_known"`
	DomainRegistered bool `json:"domain_registered"`

	// LookedUp is the name actually queried, which is the registrable domain rather
	// than the host when those differ. Shown, because "mail.example.com is 9000 days
	// old" is a claim about example.com and saying so avoids implying otherwise.
	LookedUp string `json:"looked_up,omitempty"`

	DomainAgeDays     int64    `json:"domain_age_days,omitempty"`
	Registrar         string   `json:"registrar,omitempty"`
	RegistrantCompany string   `json:"registrant_company,omitempty"`
	RegistrantCountry string   `json:"registrant_country,omitempty"`
	RegistrantEmail   string   `json:"registrant_email,omitempty"`
	NameServers       []string `json:"name_servers,omitempty"`
}

// NewDomain reports a registration recent enough to be worth saying out loud.
func (d DomainInfo) NewDomain() bool {
	return d.DomainKnown && d.DomainRegistered && d.DomainAgeDays < 30
}

// lookupDomain asks the registry about a domain.
//
// The registrable domain is tried when the host itself has no record, which is the
// normal case: registries hold `example.com`, not `mail.example.com`, so looking up the
// host alone reports "unknown" for most mail in existence.
func lookupDomain(ctx context.Context, enricher mql.Enricher, host, root string) DomainInfo {
	var out DomainInfo
	if enricher == nil || host == "" {
		return out
	}
	for _, name := range candidates(host, root) {
		v, err := enricher.Enrich(ctx, enrich.CapNetworkWhois, []mql.Value{mql.StringValue(name)}, nil)
		if err != nil || v.IsNull() {
			continue
		}
		out = DomainInfo{DomainKnown: true, LookedUp: name}
		out.DomainRegistered, _ = v.Field("found").AsBool()
		if !out.DomainRegistered {
			// Keep looking: the host having no record says nothing about the
			// registrable domain, which is the thing anyone actually means.
			continue
		}
		out.DomainAgeDays, _ = v.Field("days_old").AsInt()
		out.Registrar, _ = v.Field("registrar_name").AsString()
		out.RegistrantCompany, _ = v.Field("registrant_company").AsString()
		out.RegistrantCountry, _ = v.Field("registrant_country").AsString()
		if out.RegistrantCountry == "" {
			out.RegistrantCountry, _ = v.Field("registrant_country_code").AsString()
		}
		out.RegistrantEmail, _ = v.Field("registrant_email").AsString()
		for _, ns := range v.Field("name_servers").Elements() {
			if n, ok := ns.Field("domain").AsString(); ok && n != "" {
				out.NameServers = append(out.NameServers, n)
			}
		}
		return out
	}
	return out
}

// candidates is the host and, when it differs, its registrable domain.
func candidates(host, root string) []string {
	if root == "" || root == host {
		return []string{host}
	}
	return []string{host, root}
}

// textDisagrees reports a link whose visible text claims a destination it does not have.
//
// Only text that reads like an address counts. "Click here" pointing anywhere is ordinary
// HTML; "https://login.microsoft.com" pointing at a domain that is not that one is the
// oldest trick in the file, and flagging the former as well would bury the latter.
func textDisagrees(text, domain string) bool {
	if text == "" || domain == "" {
		return false
	}
	looksLikeAddress := strings.Contains(text, "://") ||
		(strings.Contains(text, ".") && !strings.ContainsAny(text, " \t\n"))
	return looksLikeAddress && !containsFold(text, domain)
}

// AttachmentDetail is one attachment as the message describes it.
//
// Everything here is read straight off the parsed message, so unlike LinkDetail it costs
// nothing and needs no enrichment. It is typed for the same reason: a map with lowercase
// keys renders as blank cells in a template that asks for fields, silently.
type AttachmentDetail struct {
	FileName    string `json:"file_name,omitempty"`
	Extension   string `json:"extension,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size,omitempty"`
	MD5         string `json:"md5,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

// OriginDetails is the server that actually handed the message over, and who owns it.
//
// "Actually" is doing real work in that sentence. A message carries a stack of Received
// headers and the sender wrote most of them: everything below the first server we
// operate is whatever the sender felt like claiming. The only lines that mean anything
// are the ones our own infrastructure added, and the IP in those is the single hardest
// fact in the whole message — it is the one thing the sender could not forge, because
// it is where the TCP connection came from.
//
// So this records not just the address but how we came to believe it, and Authenticated
// says whether the receiving server vouched for it or we parsed it out of a header.
// Those are different grades of evidence and an analyst acting on the second one should
// know that is what they are doing.
type OriginDetails struct {
	IP string `json:"ip,omitempty"`

	// Basis is the provenance, in words, for the person reading the page.
	Basis string `json:"basis,omitempty"`

	// Authenticated marks an address the receiving server itself recorded as the
	// peer it accepted the connection from, via Received-SPF. Anything else is a
	// header, and a header is a claim.
	Authenticated bool `json:"authenticated"`

	// Helo is the name the sending server gave for itself, and RDNS the name the
	// receiving server resolved for it. When they disagree, or when the reverse name
	// has nothing to do with the sender's domain, that is worth seeing.
	Helo string `json:"helo,omitempty"`
	RDNS string `json:"rdns,omitempty"`

	// What the regional registry says about the address.
	Known        bool     `json:"known"`
	Allocated    bool     `json:"allocated"`
	Organization string   `json:"organization,omitempty"`
	Network      string   `json:"network,omitempty"`
	Country      string   `json:"country,omitempty"`
	RangeAgeDays int64    `json:"range_age_days,omitempty"`
	AbuseEmail   string   `json:"abuse_email,omitempty"`
	Status       []string `json:"status,omitempty"`

	// The autonomous system announcing the range: who carries its traffic, which is
	// a more durable identity than the netblock holder for hosting providers that
	// resell address space.
	ASN             int64  `json:"asn,omitempty"`
	ASNOrganization string `json:"asn_organization,omitempty"`
	ASNCountry      string `json:"asn_country,omitempty"`
}

// originDetails finds the sending server and looks up who owns its address.
func (p *Pipeline) originDetails(ctx context.Context, msg *mdm.MessageDataModel, enricher mql.Enricher) *OriginDetails {
	out := pickOrigin(msg)
	if out == nil {
		return nil
	}
	if enricher != nil {
		out.applyRegistry(ctx, enricher)
	}
	return out
}

// pickOrigin decides which of a message's addresses is the sending server.
//
// Hops are ordered sender to recipient, so this walks backwards — from our own
// infrastructure outwards — and stops at the first address that is not ours. Private
// and loopback addresses are skipped because they are internal relays, and the
// sender-most hops are never reached: by the time the walk gets there it has already
// found the boundary, which is the point.
//
// Received-SPF wins over everything when it is present, because it is the receiving
// server's own record of the peer it accepted rather than a line of text to be parsed.
func pickOrigin(msg *mdm.MessageDataModel) *OriginDetails {
	h := msg.Headers
	if h == nil {
		return nil
	}

	for i := len(h.Hops) - 1; i >= 0; i-- {
		hop := h.Hops[i]
		if hop == nil || hop.ReceivedSPF == nil || hop.ReceivedSPF.ClientIP == nil {
			continue
		}
		if ip := hop.ReceivedSPF.ClientIP.IP; external(ip) {
			out := &OriginDetails{
				IP:            ip,
				Authenticated: true,
				Basis:         "recorded by the receiving server as the peer it accepted",
			}
			if hop.ReceivedSPF.Helo != nil {
				out.Helo = hop.ReceivedSPF.Helo.Domain
			}
			// The reverse name has to come from the hop that carried the
			// connection, not from the hop the Received-SPF header happens to sit
			// on. Those are usually different lines — SPF is written by the
			// boundary MTA above its own Received — and taking the neighbouring
			// one reports the organisation's own relay as the sender's hostname.
			out.RDNS = reverseNameFor(h.Hops, ip)
			return out
		}
	}

	for i := len(h.Hops) - 1; i >= 0; i-- {
		hop := h.Hops[i]
		if hop == nil || hop.Received == nil || hop.Received.Source == nil {
			continue
		}
		raw := mdm.Deref(hop.Received.Source.Raw)
		ip := firstIPIn(raw)
		if !external(ip) {
			continue
		}
		return &OriginDetails{
			IP:    ip,
			Basis: "the outermost Received header your infrastructure added",
			RDNS:  hostFromReceived(raw),
		}
	}

	// Last resort, and labelled as such. These headers are written by the sending
	// client, so they are a statement of what the sender wants believed. Worth
	// showing — a forged one is itself a signal — but not worth trusting.
	for _, c := range []struct {
		ip    *mdm.IP
		field string
	}{{h.XOriginatingIP, "X-Originating-IP"}, {h.XClientIP, "X-Client-IP"}} {
		if c.ip != nil && external(c.ip.IP) {
			return &OriginDetails{
				IP:    c.ip.IP,
				Basis: "the " + c.field + " header, which the sender wrote",
			}
		}
	}
	return nil
}

// reverseNameFor finds the name the receiving server resolved for an address, by
// matching the address rather than by position.
func reverseNameFor(hops []*mdm.Hop, ip string) string {
	for _, hop := range hops {
		if hop == nil || hop.Received == nil || hop.Received.Source == nil {
			continue
		}
		raw := mdm.Deref(hop.Received.Source.Raw)
		if firstIPIn(raw) == ip {
			return hostFromReceived(raw)
		}
	}
	return ""
}

// applyRegistry fills in who holds the address and who announces it.
func (o *OriginDetails) applyRegistry(ctx context.Context, enricher mql.Enricher) {
	v, err := enricher.Enrich(ctx, rdap.CapIP, []mql.Value{mql.StringValue(o.IP)}, nil)
	if err != nil || v.IsNull() {
		return
	}
	o.Known = true
	o.Allocated, _ = v.Field("found").AsBool()
	o.Organization, _ = v.Field("organization").AsString()
	o.Country, _ = v.Field("country").AsString()
	o.RangeAgeDays, _ = v.Field("days_old").AsInt()
	o.AbuseEmail, _ = v.Field("abuse_email").AsString()
	for _, s := range v.Field("status").Elements() {
		if str, ok := s.AsString(); ok {
			o.Status = append(o.Status, str)
		}
	}
	if cidrs := v.Field("cidr").Elements(); len(cidrs) > 0 {
		o.Network, _ = cidrs[0].AsString()
	}

	// The AS is a second lookup and only some registries publish the number, so an
	// absent one is ordinary rather than a failure.
	asns := v.Field("asns").Elements()
	if len(asns) == 0 {
		return
	}
	n, ok := asns[0].AsInt()
	if !ok {
		return
	}
	o.ASN = n
	av, err := enricher.Enrich(ctx, rdap.CapASN, []mql.Value{mql.IntValue(n)}, nil)
	if err != nil || av.IsNull() {
		return
	}
	o.ASNOrganization, _ = av.Field("organization").AsString()
	o.ASNCountry, _ = av.Field("country").AsString()
}

// external reports an address that came from outside this deployment.
//
// Anything private, loopback, link-local or carrier-grade-NAT is a relay inside the
// path rather than the sender, and treating one as the origin would name your own mail
// server as the culprit on every message.
func external(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	// 100.64.0.0/10, which netip has no predicate for and which is not private under
	// RFC 1918 but is just as certainly not a sender.
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return false
		}
	}
	return true
}

// hostFromReceived pulls the hostname out of a Received header's "from" clause.
//
// The shape is `mail.example.com (mail.example.com [203.0.113.9])`, where the bare name
// is what the peer claimed and the parenthesised one is what the receiving server
// resolved. The resolved name is the one worth having, so it is preferred.
func hostFromReceived(raw string) string {
	if raw == "" {
		return ""
	}
	if i := strings.IndexByte(raw, '('); i >= 0 {
		inner := raw[i+1:]
		if j := strings.IndexAny(inner, " [)"); j > 0 {
			if h := strings.TrimSpace(inner[:j]); looksLikeHost(h) {
				return h
			}
		}
	}
	first := strings.Fields(raw)
	if len(first) > 0 && looksLikeHost(first[0]) {
		return first[0]
	}
	return ""
}

func looksLikeHost(s string) bool {
	return s != "" && strings.Contains(s, ".") && !strings.ContainsAny(s, "[]()@") &&
		netipParseFails(s)
}

// netipParseFails keeps a bare address out of the reverse-name field, where it would
// read as a resolved hostname that happens to look like the IP it resolved from.
func netipParseFails(s string) bool {
	_, err := netip.ParseAddr(s)
	return err != nil
}

// firstIPIn extracts the first address from a Received header's "from" clause.
func firstIPIn(raw string) string {
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '[' || r == ']' || r == '(' || r == ')' || r == ';' || r == ','
	}) {
		tok = strings.TrimPrefix(tok, "IPv6:")
		if addr, err := netip.ParseAddr(tok); err == nil {
			return addr.Unmap().String()
		}
	}
	return ""
}
