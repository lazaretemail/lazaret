// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// sampleMessage is the message the evaluation tests run against. It is built in code
// rather than parsed, so that a test about `and` with a null operand cannot fail because
// of something in the MIME parser.
func sampleMessage() *mdm.MessageDataModel {
	return &mdm.MessageDataModel{
		Type: &mdm.MessageType{
			Inbound:  mdm.Ptr(true),
			Outbound: mdm.Ptr(false),
			Internal: mdm.Ptr(false),
		},
		Sender: &mdm.SenderMailbox{
			DisplayName: mdm.Ptr("Alice Smith"),
			Email:       mdm.ParseEmailAddress("alice@sender.test"),
		},
		Subject: &mdm.Subject{
			Subject: mdm.Ptr("Urgent: invoice"),
			Base:    mdm.Ptr("invoice"),
			IsReply: mdm.Ptr(false),
		},
		Recipients: &mdm.Recipients{
			To: []*mdm.Mailbox{{Email: mdm.ParseEmailAddress("bob@example.com")}},
		},
		Headers: &mdm.Headers{
			// InReplyTo is deliberately absent, so `is null` has something to find.
			MessageID:   mdm.Ptr("abc@sender.test"),
			AuthSummary: &mdm.AuthSummary{DMARC: &mdm.DMARCSummary{Pass: mdm.Ptr(false)}},
		},
		Body: &mdm.Body{
			CurrentThread: &mdm.Thread{Text: mdm.Ptr("Please pay the attached invoice today.")},
			Plain:         &mdm.Plain{Raw: mdm.Ptr("Please pay the attached invoice today.")},
			Links: []*mdm.Link{
				{HrefURL: mdm.ParseURL("https://evil.test/pay", true), DisplayText: mdm.Ptr("Pay now")},
				{HrefURL: mdm.ParseURL("https://good.test/x", true)},
			},
		},
		Attachments: []*mdm.Attachment{
			{FileName: mdm.Ptr("invoice.pdf"), FileExtension: mdm.Ptr("pdf"), Size: mdm.Ptr(int64(1024))},
			{FileName: mdm.Ptr("notes.txt"), FileExtension: mdm.Ptr("txt"), Size: mdm.Ptr(int64(16))},
		},
	}
}

// evalTo evaluates an expression and returns the value it produced.
func evalTo(t *testing.T, src string) mql.Value {
	t.Helper()
	checked, err := mql.Compile(src, nil)
	if err != nil {
		t.Fatalf("compiling %q: %v", src, err)
	}
	res := mql.Eval(context.Background(), checked, sampleMessage(), nil)
	if res.Err != nil {
		t.Fatalf("evaluating %q: %v", src, res.Err)
	}
	return res.Value
}

// wants checks the rendered result, which keeps the table below readable.
func wants(t *testing.T, src, want string) {
	t.Helper()
	if got := evalTo(t, src).String(); got != want {
		t.Errorf("%s\n got: %s\nwant: %s", src, got, want)
	}
}

func TestEvalFieldAccess(t *testing.T) {
	wants(t, `type.inbound`, "true")
	wants(t, `sender.email.email`, "alice@sender.test")
	wants(t, `sender.email.domain.root_domain`, "sender.test")
	wants(t, `subject.base`, "invoice")
	wants(t, `length(attachments)`, "2")
	wants(t, `attachments[0].file_name`, "invoice.pdf")
	// An absent optional field is null, not an empty string. That distinction is the
	// reason the generated model uses pointers.
	wants(t, `headers.in_reply_to`, "null")
	wants(t, `headers.in_reply_to is null`, "true")
	wants(t, `headers.message_id is not null`, "true")
}

// TestNullSemanticsDocumented covers every null rule the documentation actually states.
// Each row here corresponds to one cited line in docs/SEMANTICS.md; if we disagree with
// the docs, we are wrong.
func TestNullSemanticsDocumented(t *testing.T) {
	tests := []struct{ src, want, why string }{
		{`length(headers.in_reply_to)`, "null", "length of a null string is null"},
		{`length(body.previous_threads)`, "0", "length of an absent array is 0"},
		{`coalesce(headers.in_reply_to, "fallback")`, "fallback", "coalesce skips null"},
		{`coalesce(null, null)`, "null", "all-null coalesce is null"},
		{`all(body.previous_threads, .text == "x")`, "true", "all over an empty array is vacuously true"},
		{`ratio(body.previous_threads, .text == "x")`, "null", "ratio over an empty array is null"},
		{`attachments[-1]`, "null", "a negative index is null"},
		{`attachments[99]`, "null", "an out-of-range index is null"},
		{`attachments[99:200]`, "[]", "out-of-range slice bounds clamp"},
		{`subject.subject[0:6]`, "Urgent", "string slicing counts code points"},
		{`subject.subject[:6]`, "Urgent", "an open lower bound starts at 0"},
		{`headers.in_reply_to[0:5]`, "null", "a null operand anywhere in a slice is null"},
		{`regex.match(headers.in_reply_to, '.*')`, "null", "regex over null input is null"},
		{`strings.icontains(headers.in_reply_to, "x")`, "null", "a null source is null"},
		{`strings.parse_domain("not a domain")`, "null", "an unparseable domain is null"},
		{`strings.parse_json("{{{")`, "null", "unparseable JSON is null"},
		{`length(strings.scan_base64("nothing here"))`, "0", "scan_base64 finding nothing is an empty array"},
	}
	for _, tc := range tests {
		t.Run(tc.why, func(t *testing.T) { wants(t, tc.src, tc.want) })
	}
}

// TestNullSemanticsConfirmedAgainstSublime covers behaviour no published page defines,
// which was settled by running the equivalent expression on Sublime's own engine —
// analyzer.sublime.security, which needs no authentication — on 2026-09-18. Each row
// corresponds to a "Specified by observation" entry in docs/SEMANTICS.md.
//
// These were the largest single compatibility risk in the project: nothing in the corpus
// pass rate can detect a wrong answer here, because a wrong verdict is still a verdict.
// `go test ./mql -run Differential -tags differential` re-runs the comparison upstream.
func TestNullSemanticsConfirmedAgainstSublime(t *testing.T) {
	tests := []struct{ src, want, why string }{
		// Kleene logic. The asymmetry is the point: a decisive operand decides, an
		// indecisive one only spreads when nothing else settles the question.
		{`headers.in_reply_to is null and type.inbound`, "true", "true and true"},
		{`type.outbound and length(headers.in_reply_to) > 1`, "false", "false and null is false"},
		{`type.inbound and length(headers.in_reply_to) > 1`, "null", "true and null is null"},
		{`type.inbound or length(headers.in_reply_to) > 1`, "true", "true or null is true"},
		{`type.outbound or length(headers.in_reply_to) > 1`, "null", "false or null is null"},
		{`not (length(headers.in_reply_to) > 1)`, "null", "not null is null"},

		// Comparison against null is null, never false.
		{`headers.in_reply_to == "x"`, "null", "comparing null with a string is null"},
		{`headers.in_reply_to != "x"`, "null", "and so is the negation"},
		{`length(headers.in_reply_to) > 1`, "null", "ordering against null is null"},

		// Membership inherits equality's behaviour, in both directions.
		{`headers.in_reply_to in ("a", "b")`, "null", "membership of null is null"},
		{`headers.in_reply_to not in ("a", "b")`, "null", "non-membership of null is null too"},

		// `of` is three-valued, the same way `and` and `or` are. Reaching the threshold on
		// true clauses alone settles it; otherwise an undecided clause means unknown, not
		// false, because it could have been the clause that reached the threshold.
		{`1 of (type.inbound, headers.in_reply_to == "x")`, "true", "the threshold is met without the null"},
		{`2 of (type.inbound, headers.in_reply_to == "x")`, "null", "the null could have met the threshold"},
		{`1 of (type.outbound, headers.in_reply_to == "x")`, "null", "a false clause does not settle it either"},
		{`1 of (type.outbound, type.outbound)`, "false", "nothing undecided, threshold unmet"},
		{`2 of (type.inbound, type.inbound, headers.in_reply_to == "x")`, "true", "enough trues, null irrelevant"},

		// `is null` binds as a comparison: tighter than `not`, `and` and `or`.
		{`not headers.in_reply_to is null`, "false", "parses as not (x is null)"},

		// Scalar string functions propagate null like the documented regex ones.
		{`regex.contains(headers.in_reply_to, "x")`, "null", "regex.contains matches regex.match"},
		{`regex.count(headers.in_reply_to, "x")`, "null", "and so does regex.count"},
		{`strings.levenshtein(headers.in_reply_to, "abc")`, "null", "distance to null is null"},

		// A rule fires only on exactly true; null is not a match. Upstream reports the
		// same verdict, but reports no reason — which is what `indeterminate` adds.
		{`headers.in_reply_to == "x"`, "null", "a null top-level result is not a match"},
	}
	for _, tc := range tests {
		t.Run(tc.why, func(t *testing.T) { wants(t, tc.src, tc.want) })
	}
}

// TestNullArrayIsNotEmptyArray pins the distinction that caused the only false positive
// this engine has produced against Sublime's own verdicts.
//
// `ml.nlu_classifier(x).topics` with no ML service is a *null* array. Folding it to an
// empty one makes `any` false and `not any` true, and the corpus is full of
// `not any(ml.…(…), …)` clauses written to exclude newsletters and benign mail — so a
// brand impersonation rule fired *because* the classifier was missing. Confirmed against
// Sublime's analyzer on 2026-09-18; which builtins propagate and which absorb is
// irregular, so each was measured rather than derived.
func TestNullArrayIsNotEmptyArray(t *testing.T) {
	const null = `regex.extract(headers.in_reply_to, "(?P<a>x)")`
	tests := []struct{ src, want, why string }{
		{null, "null", "the array itself is null"},
		{"length(" + null + ")", "null", "length propagates"},
		{"any(" + null + ", true)", "null", "any propagates — not false"},
		{"not any(" + null + ", true)", "null", "so the negation cannot assert anything"},
		{"all(" + null + ", true)", "true", "all is vacuously true, as over []"},
		{"ratio(" + null + ", true)", "null", "ratio propagates"},
		{"length(map(" + null + ", 1))", "null", "map propagates"},
		{"length(filter(" + null + ", true))", "0", "filter absorbs, returning []"},
		{"sum(map(" + null + ", 1))", "0", "sum absorbs, returning its zero"},
		{null + "[0]", "null", "indexing propagates"},
	}
	for _, tc := range tests {
		t.Run(tc.why, func(t *testing.T) { wants(t, tc.src, tc.want) })
	}

	// The contrast that makes the point: an absent MDM array is empty, not null, so a
	// false from it is a real answer rather than a guess.
	wants(t, "length(body.previous_threads)", "0")
	wants(t, "any(body.previous_threads, true)", "false")
}

// TestUnresolvableListIsIndeterminate covers the same invariant in the lists subsystem.
//
// The lists package already answers "I do not know" rather than "no" for a list nobody
// configured, but the evaluator used to drop that on the floor and return a bare null —
// which reads as a clean no-match at the top level. $high_trust_sender_root_domains gates
// 683 corpus rules and $org_domains another 202, so this silently switched off a large
// part of the corpus while reporting full confidence.
func TestUnresolvableListIsIndeterminate(t *testing.T) {
	for _, src := range []string{
		`sender.email.email not in $recipient_emails`,
		`sender.email.email in $recipient_emails`,
		`$org_domains`,
		`any($high_trust_sender_root_domains, . == "example.com")`,
	} {
		t.Run(src, func(t *testing.T) {
			checked, err := mql.Compile(src, nil)
			if err != nil {
				t.Fatalf("compiling: %v", err)
			}
			res := mql.Eval(context.Background(), checked, sampleMessage(), nil)
			if res.Verdict != mql.Indeterminate {
				t.Errorf("verdict = %v, want indeterminate", res.Verdict)
			}
			if len(res.Missing) == 0 {
				t.Error("no missing capability recorded; the report cannot say which list")
			}
			for _, c := range res.Missing {
				if !strings.HasPrefix(string(c), "$") {
					t.Errorf("missing capability %q is not named for a list", c)
				}
			}
		})
	}
}

// TestNullSemanticsStillInferred covers what the differential run could not settle,
// because the construct does not exist on Sublime's engine at all. Kept separate from the
// confirmed table so the distinction stays visible: these remain choices, not findings.
func TestNullSemanticsStillInferred(t *testing.T) {
	tests := []struct{ src, want, why string }{
		// `none of (...)` is not MQL — Sublime's parser rejects it (see
		// docs/SEMANTICS.md). Its null behaviour is therefore ours to define, and it is
		// defined to stay consistent with the confirmed `X of (...)` rule above.
		{`none of (type.outbound, type.outbound)`, "true", "no clause holds"},
		{`none of (type.inbound, type.outbound)`, "false", "a clause holds"},
		{`none of (type.outbound, headers.in_reply_to == "x")`, "null", "an undecided clause could have held"},
	}
	for _, tc := range tests {
		t.Run(tc.why, func(t *testing.T) { wants(t, tc.src, tc.want) })
	}
}

func TestArithmetic(t *testing.T) {
	// Integer division stays integral, which is documented and which rules rely on.
	wants(t, `5 / 2`, "2")
	wants(t, `5 / 2.0`, "2.5")
	wants(t, `5.0 / 2`, "2.5")
	wants(t, `7 % 3`, "1")
	wants(t, `2 + 3 * 4`, "14")
	// Division by zero is null rather than a failure: one bad rule should not take down
	// the evaluation of a message.
	wants(t, `1 / 0`, "null")
}

func TestComparisonAndCaseFolding(t *testing.T) {
	wants(t, `subject.subject == "Urgent: invoice"`, "true")
	wants(t, `subject.subject == "urgent: invoice"`, "false")
	wants(t, `subject.subject =~ "urgent: invoice"`, "true")
	wants(t, `subject.subject !~ "urgent: invoice"`, "false")
	// Documented: an integer widens before comparison, so this is false rather than an
	// error or a rounded match.
	wants(t, `3 == 3.14`, "false")
	wants(t, `0 < length(attachments) <= 2`, "true")
	wants(t, `0 < length(attachments) < 2`, "false")
}

func TestArrayFunctions(t *testing.T) {
	wants(t, `any(attachments, .file_extension == "pdf")`, "true")
	wants(t, `any(attachments, .file_extension == "docx")`, "false")
	wants(t, `all(attachments, .size > 0)`, "true")
	wants(t, `length(filter(attachments, .file_extension == "pdf"))`, "1")
	wants(t, `map(attachments, .file_extension)`, "[pdf, txt]")
	wants(t, `sum(attachments, .size)`, "1040")
	wants(t, `ratio(attachments, .file_extension == "pdf")`, "0.5")
	wants(t, `length(distinct(map(attachments, .file_extension)))`, "2")
	wants(t, `flatten([[1, 2], [3]])`, "[1, 2, 3]")
	wants(t, `any(body.links, .href_url.domain.root_domain == "evil.test")`, "true")
}

func TestScopedIteration(t *testing.T) {
	// Climbing out of a loop to reach the enclosing item, which is how impersonation
	// rules compare a link against a recipient.
	wants(t, `any(recipients.to, any(body.links, strings.icontains(.href_url.url, "pay")))`, "true")
	wants(t, `any(recipients.to, any(body.links, ..email.domain.domain == "example.com"))`, "true")
}

func TestStringFunctions(t *testing.T) {
	wants(t, `strings.icontains(body.current_thread.text, "INVOICE")`, "true")
	wants(t, `strings.contains(body.current_thread.text, "INVOICE")`, "false")
	wants(t, `strings.istarts_with(subject.subject, "urgent")`, "true")
	wants(t, `strings.iends_with(subject.subject, "INVOICE")`, "true")
	wants(t, `strings.ilike(subject.subject, "*invoice*")`, "true")
	wants(t, `strings.like(subject.subject, "Urgent: ???????")`, "true")
	wants(t, `strings.like(subject.subject, "Urgent: ??")`, "false")
	wants(t, `strings.count(body.current_thread.text, "invoice")`, "1")
	wants(t, `strings.levenshtein("kitten", "sitting")`, "3")
	wants(t, `strings.concat("a", "b", "c")`, "abc")
	wants(t, `strings.concat("a", headers.in_reply_to)`, "null")
	wants(t, `strings.parse_float("3.5")`, "3.5")
	wants(t, `strings.decode_hex("6869")`, "hi")
}

func TestConfusableFolding(t *testing.T) {
	// The backbone of lookalike-domain detection: a Cyrillic а renders identically to a
	// Latin one, and without folding the comparison simply never fires.
	wants(t, `strings.replace_confusables("аpple.com") == "apple.com"`, "true")
	wants(t, `strings.replace_confusables("ρaypal.com") == "paypal.com"`, "true")
	wants(t, `strings.replace_confusables("apple.com") == "apple.com"`, "true")
}

func TestRegexFunctions(t *testing.T) {
	wants(t, `regex.icontains(body.current_thread.text, 'inv[o0]ice')`, "true")
	wants(t, `regex.match(subject.subject, '.*invoice')`, "true")
	wants(t, `regex.match(subject.subject, 'invoice')`, "false")
	wants(t, `regex.count(body.current_thread.text, '[aeiou]') > 5`, "true")
	wants(t, `any(regex.iextract(subject.subject, '(?P<word>urgent)'), .named_groups["word"] =~ "urgent")`, "true")
	// A group that did not participate is the empty string, never null.
	wants(t, `any(regex.extract("ab", '(a)(z)?'), .groups[1] == "")`, "true")
}

func TestRegexCompilationErrorIsReported(t *testing.T) {
	// Unlike an absent field, a pattern that will not compile is a mistake in the rule.
	// Returning null would leave it matching nothing forever with nobody the wiser.
	checked, err := mql.Compile(`regex.contains(subject.subject, '([')`, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := mql.Eval(context.Background(), checked, sampleMessage(), nil)
	if res.Err == nil {
		t.Fatal("a malformed pattern evaluated without error")
	}
	if res.Verdict != mql.Indeterminate {
		t.Errorf("verdict = %s, want indeterminate", res.Verdict)
	}
}

func TestGlobSemantics(t *testing.T) {
	// `*` and `?` are the only wildcards, and matching is against the whole string.
	wants(t, `strings.ilike("hello world", "hello*")`, "true")
	wants(t, `strings.ilike("hello world", "*world")`, "true")
	wants(t, `strings.ilike("hello world", "hello")`, "false")
	wants(t, `strings.ilike("hello", "h?llo")`, "true")
	wants(t, `strings.ilike("hllo", "h?llo")`, "false")
	// No escape mechanism is documented, so an asterisk in a pattern is always a
	// wildcard. Recorded as inferred.
	wants(t, `strings.ilike("anything", "*")`, "true")
}

func TestGlobIsNotExponential(t *testing.T) {
	// The classic catastrophic pattern. Rule text is attacker-influenced, so this must
	// stay linear rather than becoming a way to stall the engine.
	src := `strings.ilike("` + strings.Repeat("a", 2000) + `", "*a*a*a*a*a*a*b")`
	if got := evalTo(t, src).String(); got != "false" {
		t.Errorf("got %s, want false", got)
	}
}

func TestIPMembership(t *testing.T) {
	wants(t, `beta.ip_in("192.168.1.5", "10.0.0.0/8", "192.168.0.0/16")`, "true")
	wants(t, `beta.ip_in("8.8.8.8", "10.0.0.0/8", "192.168.0.0/16")`, "false")
	wants(t, `beta.ip_in("not an ip", "10.0.0.0/8")`, "null")
	// An IPv4 address written in IPv6 form still belongs to its v4 range.
	wants(t, `beta.ip_in("::ffff:192.168.1.5", "192.168.0.0/16")`, "true")
}

func TestHashFunctions(t *testing.T) {
	wants(t, `hash.sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`, "true")
	wants(t, `hash.md5("") == "d41d8cd98f00b204e9800998ecf8427e"`, "true")
}

func TestXPath(t *testing.T) {
	msg := sampleMessage()
	msg.Body.HTML = &mdm.BodyHTML{Raw: mdm.Ptr(
		`<html><body><a href="https://evil.test/x">Click</a><h2>Heading</h2></body></html>`)}

	checked, err := mql.Compile(`any(html.xpath(body.html, '//h2').nodes, .inner_text == "Heading")`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res := mql.Eval(context.Background(), checked, msg, nil); !res.Value.Truthy() {
		t.Errorf("xpath query did not match: %v (%v)", res.Value, res.Err)
	}

	checked, _ = mql.Compile(`any(html.xpath(body.html, '//a').nodes, any(.links, .href_url.domain.domain == "evil.test"))`, nil)
	if res := mql.Eval(context.Background(), checked, msg, nil); !res.Value.Truthy() {
		t.Errorf("links within a matched node were not found: %v (%v)", res.Value, res.Err)
	}
}

// unavailableEnricher stands in for a deployment where the model services are not
// reachable — which is every deployment of module 1, and any deployment at all during an
// outage.
type unavailableEnricher struct{ calls int }

func (u *unavailableEnricher) Enrich(_ context.Context, cap enrich.Capability, _ []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
	u.calls++
	return mql.NullValue, enrich.NotImplemented(cap)
}

func TestUnavailableCapabilityIsIndeterminateNotNoMatch(t *testing.T) {
	// The single most important behaviour in the evaluator. "We could not tell" must
	// never be reported as "this message is fine".
	checked, err := mql.Compile(`network.whois(sender.email.domain).days_old < 30`, nil)
	if err != nil {
		t.Fatal(err)
	}

	enricher := &unavailableEnricher{}
	res := mql.Eval(context.Background(), checked, sampleMessage(), &mql.EvalOptions{Enricher: enricher})

	if res.Verdict != mql.Indeterminate {
		t.Errorf("verdict = %s, want indeterminate", res.Verdict)
	}
	if len(res.Missing) != 1 || res.Missing[0] != enrich.CapNetworkWhois {
		t.Errorf("missing = %v, want [network.whois]", res.Missing)
	}
	if enricher.calls != 1 {
		t.Errorf("enricher called %d times, want 1", enricher.calls)
	}
}

func TestNoEnricherStillReportsTheGap(t *testing.T) {
	// With no enricher configured at all the answer must be the same, not a quiet false.
	checked, _ := mql.Compile(`any(ml.nlu_classifier(body.current_thread.text).intents, .name == "bec")`, nil)
	res := mql.Eval(context.Background(), checked, sampleMessage(), nil)
	if res.Verdict != mql.Indeterminate {
		t.Errorf("verdict = %s, want indeterminate", res.Verdict)
	}
	if len(res.Missing) == 0 {
		t.Error("the missing capability was not reported")
	}
}

func TestMatchDespiteMissingCapabilityIsStillAMatch(t *testing.T) {
	// A rule that found what it was looking for has found it, whatever else it could not
	// see. Only the negative answer is untrustworthy.
	checked, _ := mql.Compile(`type.inbound or network.whois(sender.email.domain).days_old < 30`, nil)
	res := mql.Eval(context.Background(), checked, sampleMessage(), &mql.EvalOptions{Enricher: &unavailableEnricher{}})
	if res.Verdict != mql.Match {
		t.Errorf("verdict = %s, want match", res.Verdict)
	}
}

func TestShortCircuitAvoidsUnnecessaryEnrichment(t *testing.T) {
	// `type.inbound and <expensive>` is the standard shape of a corpus rule. On outbound
	// mail the expensive half must not run: it would be slow, and it would report a
	// capability as missing that the rule never actually needed.
	checked, _ := mql.Compile(`type.outbound and network.whois(sender.email.domain).days_old < 30`, nil)
	enricher := &unavailableEnricher{}
	res := mql.Eval(context.Background(), checked, sampleMessage(), &mql.EvalOptions{Enricher: enricher})

	if enricher.calls != 0 {
		t.Errorf("the enricher was called %d times behind a false guard", enricher.calls)
	}
	if res.Verdict != mql.NoMatch {
		t.Errorf("verdict = %s, want no-match", res.Verdict)
	}
	if len(res.Missing) != 0 {
		t.Errorf("missing = %v, want none: the rule never needed it", res.Missing)
	}
}

// staticLists is a minimal resolver for testing list behaviour.
type staticLists map[string][]string

func (s staticLists) Contains(_ context.Context, list string, v mql.Value, fold bool) (bool, bool) {
	entries, known := s[list]
	if !known {
		return false, false
	}
	want, ok := v.AsString()
	if !ok {
		return false, true
	}
	for _, e := range entries {
		if e == want || (fold && strings.EqualFold(e, want)) {
			return true, true
		}
	}
	return false, true
}

func (s staticLists) Elements(_ context.Context, list string) ([]mql.Value, bool) {
	entries, known := s[list]
	if !known {
		return nil, false
	}
	out := make([]mql.Value, len(entries))
	for i, e := range entries {
		out[i] = mql.StringValue(e)
	}
	return out, true
}

func TestListMembership(t *testing.T) {
	lists := staticLists{
		"free_email_providers": {"gmail.com", "outlook.com"},
		"org_domains":          {"example.com"},
	}
	opts := &mql.EvalOptions{Lists: lists}

	eval := func(src string) mql.Value {
		t.Helper()
		checked, err := mql.Compile(src, nil)
		if err != nil {
			t.Fatalf("compiling %q: %v", src, err)
		}
		return mql.Eval(context.Background(), checked, sampleMessage(), opts).Value
	}

	if got := eval(`sender.email.domain.domain in $free_email_providers`).String(); got != "false" {
		t.Errorf("got %s, want false", got)
	}
	if got := eval(`sender.email.domain.domain not in $free_email_providers`).String(); got != "true" {
		t.Errorf("got %s, want true", got)
	}
	if got := eval(`any(recipients.to, .email.domain.domain in $org_domains)`).String(); got != "true" {
		t.Errorf("got %s, want true", got)
	}

	// An unconfigured list is not an empty list. Answering false would silently switch
	// off every rule that depends on it, and nobody would see anything wrong.
	if got := eval(`sender.email.domain.domain in $never_configured`).String(); got != "null" {
		t.Errorf("membership of an unconfigured list = %s, want null", got)
	}
}

func TestListsUnavailableEntirely(t *testing.T) {
	// With no resolver at all, the same reasoning applies.
	checked, _ := mql.Compile(`sender.email.domain.domain in $org_domains`, nil)
	res := mql.Eval(context.Background(), checked, sampleMessage(), nil)
	if !res.Value.IsNull() {
		t.Errorf("value = %s, want null when no lists are configured", res.Value)
	}
}

func TestStepBudget(t *testing.T) {
	// Rule text is attacker-influenced in a multi-tenant deployment, so runaway work has
	// to stop rather than occupy a worker indefinitely.
	checked, _ := mql.Compile(`any(attachments, any(attachments, any(attachments, .size > 0)))`, nil)
	res := mql.Eval(context.Background(), checked, sampleMessage(), &mql.EvalOptions{MaxSteps: 5})
	if res.Err == nil {
		t.Fatal("the step budget was not enforced")
	}
	if res.Verdict != mql.Indeterminate {
		t.Errorf("verdict = %s, want indeterminate", res.Verdict)
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checked, _ := mql.Compile(`any(attachments, .size > 0)`, nil)
	// Cancellation is checked periodically rather than every step, so a tiny rule may
	// still finish. What must not happen is a panic or a hang.
	_ = mql.Eval(ctx, checked, sampleMessage(), &mql.EvalOptions{MaxSteps: 8192})
}

func TestInsightQueriesReturnValues(t *testing.T) {
	// Insight queries exist to return data, which is why the evaluator is
	// value-returning rather than a predicate engine.
	v := evalTo(t, `map(attachments, coalesce(.file_name, "Unnamed Attachment"))`)
	if v.Kind() != mdm.KindArray {
		t.Fatalf("kind = %s, want array", v.Kind())
	}
	if got := v.String(); got != "[invoice.pdf, notes.txt]" {
		t.Errorf("got %s", got)
	}
	// And they are ordinary Go data on the way out, for a dashboard to render.
	list, ok := v.Interface().([]any)
	if !ok || len(list) != 2 {
		t.Errorf("Interface() = %#v, want a two-element slice", v.Interface())
	}
}

func TestEmptyMessageDoesNotPanic(t *testing.T) {
	// An almost-empty model is what a badly malformed message produces, and every rule
	// still has to run against it.
	empty := &mdm.MessageDataModel{}
	for _, src := range []string{
		`type.inbound`,
		`any(body.links, .href_url.domain.root_domain == "x")`,
		`length(attachments) > 0`,
		`strings.icontains(body.current_thread.text, "x")`,
		`sender.email.domain.root_domain in ("a", "b")`,
		`attachments[0].file_name`,
		`body.current_thread.text[0:10]`,
	} {
		t.Run(truncateName(src), func(t *testing.T) {
			checked, err := mql.Compile(src, nil)
			if err != nil {
				t.Fatal(err)
			}
			res := mql.Eval(context.Background(), checked, empty, nil)
			if res.Err != nil {
				t.Errorf("evaluating against an empty message: %v", res.Err)
			}
			if res.Verdict == mql.Match {
				t.Errorf("matched an empty message with %s", res.Value)
			}
		})
	}
}

// A capability that answers part of itself must only degrade the rules that read the
// part it could not answer.
//
// ml.nlu_classifier with no entailment model still returns entities and language. A
// rule reading only .entities was answered completely and should not appear in the
// missing-capability list; a rule reading .intents should.
func TestPartialCapabilityIsRecordedOnlyWhenRead(t *testing.T) {
	partial := mql.EnricherFunc(func(_ context.Context, _ enrich.Capability, _ []mql.Value, _ map[string]mql.Value) (mql.Value, error) {
		return mql.JSONValue(map[string]any{
			"entities":    []any{map[string]any{"name": "urgency", "text": "right away"}},
			"language":    "english",
			"unavailable": []any{"ml.nlu_classifier.intents", "ml.nlu_classifier.topics"},
		}), nil
	})

	for _, tc := range []struct {
		name       string
		source     string
		wantMissed bool
	}{
		{
			name:       "reads only the answerable half",
			source:     `any(ml.nlu_classifier(body.current_thread.text).entities, .name == "urgency")`,
			wantMissed: false,
		},
		{
			name:       "reads the unanswerable half",
			source:     `any(ml.nlu_classifier(body.current_thread.text).intents, .name == "cred_theft")`,
			wantMissed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checked, err := mql.Compile(tc.source, nil)
			if err != nil {
				t.Fatal(err)
			}
			res := mql.Eval(context.Background(), checked, sampleMessage(), &mql.EvalOptions{Enricher: partial})

			got := false
			for _, m := range res.Missing {
				if strings.HasPrefix(string(m), "ml.nlu_classifier") {
					got = true
				}
			}
			if got != tc.wantMissed {
				t.Errorf("missing = %v, want a capability reported: %v", res.Missing, tc.wantMissed)
			}
		})
	}
}
