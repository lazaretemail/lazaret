// SPDX-License-Identifier: AGPL-3.0-only

package main

// The label vocabularies are extracted from the rule corpus, not invented here, and
// not taken from documentation either.
//
// Nothing publishes the set of intents ml.nlu_classifier can return. What exists is
// 358 rules that compare against them, which is a better specification than a list
// would be: a label no rule reads cannot change a verdict, and a label a rule reads
// and the classifier never emits makes that rule dead. So the vocabulary is whatever
// the corpus asks about, and the extraction that produced it is reproducible —
// `.name == "x"` and `.name in (...)` within each accessor's expression.
//
// Counts below are corpus references, and they are the reason the sets are ordered as
// they are: cred_theft alone is 162 of the 311 intent references, so a deployment that
// gets only one label right should get that one.

// Intents are what the message is trying to achieve. Eight labels, all of the
// snake_case form.
var Intents = []Label{
	{Name: "cred_theft", Hypothesis: "a phishing attempt to steal login credentials", Refs: 162},
	{Name: "callback_scam", Hypothesis: "a scam that instructs the reader to call a phone number", Refs: 50},
	{Name: "bec", Hypothesis: "an executive or colleague urgently requesting a payment, wire transfer or gift card", Refs: 35},
	{Name: "benign", Hypothesis: "an ordinary harmless message with no malicious intent", Refs: 17, Suppressive: true},
	{Name: "advance_fee", Hypothesis: "advance fee fraud promising a large sum of money in return for a payment", Refs: 11},
	{Name: "steal_pii", Hypothesis: "a request for personal identifying information such as a date of birth, address or government identifier", Refs: 9},
	{Name: "extortion", Hypothesis: "a blackmail or extortion threat demanding payment", Refs: 5},
	{Name: "job_scam", Hypothesis: "a fraudulent job or employment offer", Refs: 5},
}

// Topics are what the message is about, independent of intent. A phishing message and
// a real notice can share a topic, which is exactly why the corpus uses these to
// *exclude* — "not a newsletter" narrows a rule without asserting anything malicious.
//
// Title Case, with the spacing and ampersands exactly as the rules spell them. These
// are compared with ==, so "Charity and Non-Profit" and "Charity and Non Profit" are
// different labels and only one of them matches anything.
var Topics = []Label{
	{Name: "Newsletters and Digests", Hypothesis: "a newsletter or a digest of recent content", Refs: 25},
	{Name: "Financial Communications", Hypothesis: "a financial communication such as a statement, balance or transaction notice", Refs: 23},
	{Name: "Advertising and Promotions", Hypothesis: "advertising, marketing or a promotional offer", Refs: 20},
	{Name: "Security and Authentication", Hypothesis: "a security or authentication notice such as a login alert or verification code", Refs: 18},
	{Name: "Secure Message", Hypothesis: "a notification that a secure or encrypted message is waiting", Refs: 13},
	{Name: "Reminders and Notifications", Hypothesis: "a reminder or an automated notification", Refs: 12},
	{Name: "Request to View Invoice", Hypothesis: "a request to view, open or download an invoice", Refs: 12},
	{Name: "Professional and Career Development", Hypothesis: "professional training, career development or recruitment", Refs: 11},
	{Name: "B2B Cold Outreach", Hypothesis: "unsolicited business-to-business sales outreach", Refs: 11},
	{Name: "Payment Information", Hypothesis: "payment details, bank account information or remittance instructions", Refs: 9},
	{Name: "Events and Webinars", Hypothesis: "an invitation to an event, conference or webinar", Refs: 8},
	{Name: "Voicemail Call and Missed Call Notifications", Hypothesis: "a voicemail, missed call or call recording notification", Refs: 6},
	{Name: "Customer Service and Support", Hypothesis: "customer service or technical support correspondence", Refs: 5},
	{Name: "Entertainment and Sports", Hypothesis: "entertainment, sports or leisure content", Refs: 5},
	{Name: "File Sharing and Cloud Services", Hypothesis: "a shared file or a cloud storage notification", Refs: 5},
	{Name: "Legal and Compliance", Hypothesis: "a legal, regulatory or compliance matter", Refs: 4},
	{Name: "Bounce Back and Delivery Failure Notifications", Hypothesis: "a bounce message or a mail delivery failure notification", Refs: 4},
	{Name: "Software and App Updates", Hypothesis: "a software release, update or patch notice", Refs: 4},
	{Name: "Order Confirmations", Hypothesis: "an order confirmation or a purchase receipt", Refs: 4},
	{Name: "E-Signature", Hypothesis: "a request to electronically sign a document", Refs: 4},
	{Name: "Romance", Hypothesis: "romantic or dating overtures", Refs: 4},
	{Name: "Sexually Explicit Messages", Hypothesis: "sexually explicit content", Refs: 4},
	{Name: "Political Mail", Hypothesis: "political campaigning or advocacy", Refs: 3},
	{Name: "News and Current Events", Hypothesis: "news or current events", Refs: 3},
	{Name: "Travel and Transportation", Hypothesis: "travel, a booking or transportation", Refs: 3},
	{Name: "Benefit Enrollment", Hypothesis: "employee benefits, payroll or enrollment", Refs: 3},
	{Name: "Educational and Research", Hypothesis: "education, academic study or research", Refs: 2},
	{Name: "Health and Wellness", Hypothesis: "health, medical care or wellness", Refs: 2},
	{Name: "Shipping and Package", Hypothesis: "a shipment, parcel delivery or tracking update", Refs: 2},
	{Name: "Out of Band Pivot", Hypothesis: "a request to continue the conversation on another channel such as WhatsApp, Telegram or a personal number", Refs: 1},
	{Name: "Contact List Solicitation", Hypothesis: "an offer to sell contact lists or lead data", Refs: 1},
	{Name: "Charity and Non-Profit", Hypothesis: "a charitable appeal or non-profit fundraising", Refs: 1},
	{Name: "Government Services", Hypothesis: "a government service, tax or public agency notice", Refs: 1},
}

// Tags are narrow document kinds. Three of them, and unlike topics they are read
// together with .text, because a rule wants the words that justified the tag.
var Tags = []Label{
	{Name: "invoice", Hypothesis: "an invoice or a bill", Refs: 16},
	{Name: "payment", Hypothesis: "a payment or remittance", Refs: 9},
	{Name: "purchase_order", Hypothesis: "a purchase order", Refs: 5},
}

// Label is one classification target.
type Label struct {
	// Name is the string a rule compares against. It is the contract; changing one
	// silently stops every rule that reads it from ever matching.
	Name string

	// Hypothesis is the sentence given to the entailment model, completing "This text
	// is {hypothesis}." It is a description rather than the label itself, because a
	// zero-shot model scores a sentence and "cred_theft" is not one.
	Hypothesis string

	// Refs is how many places in the corpus compare against this name. Kept because it
	// is the only ranking available for which labels matter, and because a label whose
	// count is zero should be questioned rather than kept.
	Refs int

	// Suppressive marks a label the rules use to *stop* firing rather than to fire.
	//
	// Only `benign` is one, and the asymmetry is worth spelling out because it
	// changes how the label must be scored. The corpus is full of
	//
	//	not any(ml.nlu_classifier(...).intents, .name == "benign" and .confidence == "high")
	//
	// so a wrong `benign (high)` does not produce a false positive — it produces a
	// silent false *negative*, in a rule that would otherwise have fired. Every other
	// intent is used the other way round, where being wrong costs an alert somebody
	// reads.
	//
	// The cost matrix is therefore lopsided, and scoring the labels symmetrically
	// treats the two kinds of mistake as equal when they are not. See
	// Thresholds.exclusive for what this changes.
	Suppressive bool
}

// suppressive reports whether a label is one the rules use to stop firing.
func suppressive(labels []Label, name string) bool {
	for _, l := range labels {
		if l.Name == name {
			return l.Suppressive
		}
	}
	return false
}

// Names returns just the label strings.
func Names(ls []Label) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.Name
	}
	return out
}

// Brands are the classes ml.logo_detect returns, likewise taken from what the corpus
// compares against.
//
// Three of these are not brands at all — FakeAttachment, Generic Webmail and Invite
// Company are shapes a detector recognises rather than companies — which is worth
// knowing before treating the list as a trademark index.
var Brands = []string{
	"Adobe", "Amazon", "AT&T", "Box", "Capital One Bank", "Chase", "Coinbase",
	"DHL", "Discord", "Disney", "DocuSign", "Dropbox", "Ebay", "Facebook", "FedEx",
	"FakeAttachment", "Gemini Trust", "Generic Webmail", "GeekSquad", "Google",
	"Gusto", "Hulu", "Instagram", "Invite Company", "MailChimp", "Mailgun", "McAfee",
	"Meta", "MetaMask", "Microsoft", "Microsoft OneDrive", "Microsoft SharePoint",
	"Navan", "Netflix", "Norton", "Okta", "PayPal", "PNC", "Quickbooks",
	"Robert Half", "SendGrid", "Shein", "Slack", "Spotify", "Square", "SSA",
	"TD Bank", "Threads", "TikTok", "USPS", "X", "Zoom",
}

// ExtraBrands are impersonation targets the corpus vocabulary does not name.
//
// Kept apart from Brands on purpose. That list is what Sublime's rules compare
// against and is not ours to edit — a name added there would look like corpus
// vocabulary and would not be. These are an extension, and a rule that reads one of
// them will not run on Sublime's engine.
//
// Government agencies and postal carriers, because that is the gap. Sublime's list is
// almost entirely SaaS and finance, and it contains SSA and USPS but not the rest of a
// category that is heavily impersonated: a tax authority demanding payment and a
// carrier demanding a redelivery fee are two of the most-worn costumes in phishing.
//
// Being here does not make a rule fire by itself. It puts the name in the analyst's
// view, and it feeds the corpus rules that ask whether *any* brand was detected
// alongside other signals — impersonation_ups.yml is written that way and, until now,
// could never see a UPS logo because UPS was not a brand this could return.
//
// Only marks that survive the pack guards end up matchable by symbol. Most federal
// seals do not: an eagle in a circle at nine by eight pixels is the same picture as
// another eagle in a circle, and IRS, FBI, DHS and the Treasury all collide with each
// other or with unrelated marks. Those are caught by wordmark in OCR text instead,
// which for an agency is the better signal anyway — "Internal Revenue Service" is
// unmistakable as text and unremarkable as a shape.
var ExtraBrands = []string{
	// United States
	"IRS", "US Treasury", "FBI", "DHS", "CISA", "USCIS", "Medicare",
	"US Dept of Education", "E-ZPass",
	// United Kingdom
	"NHS", "TV Licensing", "DVLA", "HMRC", "Royal Mail",
	// Carriers and postal operators
	"UPS", "An Post", "Australia Post", "Canada Post", "Chronopost", "Correos",
	"DPD", "La Poste", "PostNL", "PostNord", "Poste Italiane", "Swiss Post",
}

// AllBrands is what ml.logo_detect may return.
func AllBrands() []string {
	out := make([]string, 0, len(Brands)+len(ExtraBrands))
	out = append(out, Brands...)
	return append(out, ExtraBrands...)
}

// Confidence buckets. The corpus reads only "high" (315) and "medium" (111); "low" is
// emitted but nothing compares against it, so a low finding is effectively invisible
// to the rules — which is the intended behaviour and the reason for emitting it at all
// rather than dropping the finding.
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)
