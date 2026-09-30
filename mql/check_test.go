// SPDX-License-Identifier: AGPL-3.0-only

package mql_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

func check(t *testing.T, src string) *mql.Checked {
	t.Helper()
	c, err := mql.Compile(src, nil)
	if err != nil {
		t.Fatalf("checking %q:\n%v", src, err)
	}
	return c
}

func checkFails(t *testing.T, src, wantSubstring string) {
	t.Helper()
	_, err := mql.Compile(src, nil)
	if err == nil {
		t.Fatalf("checking %q succeeded, want an error mentioning %q", src, wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Errorf("checking %q gave %q, want it to mention %q", src, err, wantSubstring)
	}
}

func TestRealRulesCheck(t *testing.T) {
	// A sample of shapes the corpus actually uses. The corpus test covers all 1,521; these
	// are here so a failure points at the construct rather than at a rule file.
	for _, src := range []string{
		`type.inbound`,
		`sender.email.domain.root_domain == "example.com"`,
		`any(body.links, .href_url.domain.root_domain in $org_domains)`,
		`all(recipients.to, .email.domain.domain == "example.com")`,
		`length(filter(attachments, .file_extension == "xls")) > 2`,
		`map(attachments, .file_name)`,
		`0 < length(body.links) < 20`,
		`headers.in_reply_to is null`,
		`subject.subject in~ ("urgent", "important")`,
		`2 of (type.inbound, subject.is_reply, length(attachments) > 0)`,
		`none of (type.inbound, type.outbound)`,
		`coalesce(body.html.display_text, body.plain.raw)`,
		`strings.ilike(body.plain.raw, "*password*")`,
		`regex.icontains(body.current_thread.text, '\d\d\d')`,
		`any(regex.iextract(sender.display_name, '(?P<n>.*)'), .named_groups["n"] == "x")`,
		`attachments[0].file_type == "pdf"`,
		`body.current_thread.text[0:100]`,
		`body.previous_threads[length(body.previous_threads) - 1].sender.display_name`,
		`flatten([recipients.to, recipients.cc])`,
		`any(flatten([recipients.to, recipients.cc]), .email.domain.valid)`,
		`any(body.links, 'utm_source' in keys(.href_url.query_params_decoded))`,
		`sum(attachments, .size) > 1000`,
		`ratio(attachments, .file_extension == "xls") > 0.5`,
		`any(headers.hops, .index == 0 and any(.fields, .name =~ "x-mailer"))`,
		`coalesce(headers.auth_summary.dmarc.pass, false)`,
		// Nested scopes, including climbing two levels.
		`any(recipients.to, any(body.links, strings.icontains(.href_url.url, ..email.email)))`,
		`any(recipients.to, any(body.links, any(strings.scan_base64(.href_url.url), strings.icontains(., ...email.email))))`,
	} {
		t.Run(truncateName(src), func(t *testing.T) { check(t, src) })
	}
}

func TestMisspelledFieldIsCaught(t *testing.T) {
	// The whole point of checking. Without it this is a silent null, and the rule quietly
	// never fires — which is worse than no rule, because someone believes it works.
	checkFails(t, `sender.emial == "x"`, `no field "emial"`)
	checkFails(t, `sender.email.domain.root_doman == "x"`, `no field "root_doman"`)
	checkFails(t, `nonexistent`, `no field "nonexistent"`)

	// And it should say what was probably meant.
	_, err := mql.Compile(`sender.emial == "x"`, nil)
	if !strings.Contains(err.Error(), `did you mean "email"?`) {
		t.Errorf("diagnostic %q offers no suggestion", err)
	}
}

func TestMisspelledFunctionIsCaught(t *testing.T) {
	checkFails(t, `strings.icontian(subject.subject, "x")`, `no function "strings.icontian"`)
	_, err := mql.Compile(`strings.icontian(subject.subject, "x")`, nil)
	if !strings.Contains(err.Error(), `did you mean "strings.icontains"?`) {
		t.Errorf("diagnostic %q offers no suggestion", err)
	}
}

func TestArrayFieldWithoutIterationIsCaught(t *testing.T) {
	// Reading a field off an array is how someone writes a rule they think loops. MQL has
	// no such thing, so accepting it silently would hide a missing any().
	checkFails(t, `body.links.href_url`, "is an array; use any()")
	checkFails(t, `attachments.file_name == "x"`, "is an array; use any()")
}

func TestArityAndArgumentTypes(t *testing.T) {
	checkFails(t, `length()`, "takes 1 argument, but got 0")
	checkFails(t, `strings.levenshtein("a")`, "takes 2 arguments, but got 1")
	checkFails(t, `strings.icontains(subject.subject)`, "at least 2 arguments")
	checkFails(t, `any(body.links)`, "takes 2 arguments")
	checkFails(t, `strings.icontains(attachments, "x")`, "expects string for source")
	checkFails(t, `any(subject.subject, . == "x")`, "expects [any] for array")
}

func TestCheckKeywordArguments(t *testing.T) {
	check(t, `strings.parse_url(subject.subject, strict=false)`)
	check(t, `ml.link_analysis(body.links, mode="aggressive")`)
	checkFails(t, `strings.parse_url(subject.subject, stict=false)`, `did you mean "strict"?`)
	checkFails(t, `strings.parse_url(subject.subject, strict="yes")`, "expects boolean for strict")
}

func TestScopeErrors(t *testing.T) {
	// A loop item outside a loop is a copy-paste mistake, and it resolves to nothing.
	checkFails(t, `.href_url.url == "x"`, "not inside any()")
	// Climbing further than there are scopes is the same mistake one level in.
	checkFails(t, `any(body.links, ..href_url.url == "x")`, "climbs 1 scope")
}

func TestBooleanDiscipline(t *testing.T) {
	// MQL has no truthiness: the docs are explicit that even a JSON boolean needs an
	// explicit comparison.
	checkFails(t, `not subject.subject`, "`not` needs a boolean")
	checkFails(t, `subject.subject and type.inbound`, "`and` needs a boolean")
	checkFails(t, `type.inbound and length(attachments)`, "`and` needs a boolean")
	checkFails(t, `2 of (type.inbound, subject.subject)`, "must be a boolean")
}

func TestComparisonTypes(t *testing.T) {
	checkFails(t, `subject.subject == length(attachments)`, "cannot compare string with integer")
	checkFails(t, `attachments =~ "x"`, "compares strings")
	// Numeric promotion is documented and must be allowed.
	check(t, `length(attachments) < 1.5`)
	// Null compares with anything: that is what makes null propagation work.
	check(t, `subject.subject == null`)
}

func TestArithmeticIsNumericOnly(t *testing.T) {
	// `+` does not join strings; strings.concat does. Accepting it would silently produce
	// something no rule author intended.
	checkFails(t, `subject.subject + "x"`, "`+` needs numbers")
	check(t, `length(attachments) + 1 > 2`)
	// Mixing int and float promotes, as documented.
	if got := check(t, `length(attachments) + 1.5`).Type; got.Kind != mdm.KindFloat {
		t.Errorf("int + float is %s, want float", got.Describe())
	}
}

func TestThresholdBounds(t *testing.T) {
	// A threshold above the clause count can never be met, so the rule is dead and
	// nobody would ever notice it had stopped working.
	checkFails(t, `5 of (type.inbound, type.outbound)`, "can never be met")
	checkFails(t, `0 of (type.inbound)`, "always holds")
	check(t, `2 of (type.inbound, type.outbound, type.internal)`)
}

func TestCheckMembershipForms(t *testing.T) {
	check(t, `sender.email.domain.domain in $org_domains`)
	check(t, `sender.email.domain.domain not in $free_email_providers`)
	check(t, `subject.subject in ("a", "b")`)
	check(t, `sender.email.email in map(recipients.to, .email.email)`)
	checkFails(t, `subject.subject in body.html.raw`, "`in` needs a list or array")
	checkFails(t, `subject.subject in body.links[0].href_url.query_params_decoded`, "use keys() or values()")
}

func TestListElementsAreNotAlwaysStrings(t *testing.T) {
	// $org_vips holds people, not strings. Typing every list as an array of strings
	// rejected 75 real rules.
	check(t, `any($org_vips, .display_name == "Dana Reed")`)
	check(t, `any($org_domains, . == "example.com")`)
}

func TestCapabilitiesAreReported(t *testing.T) {
	// Knowing what a rule needs before running it is what lets a deployment say
	// "indeterminate" instead of "no match".
	pure := check(t, `type.inbound and any(body.links, .href_url.domain.valid)`)
	if pure.NeedsEnrichment() {
		t.Errorf("a pure rule reported capabilities: %v", pure.Capabilities)
	}

	enriched := check(t, `any(attachments, any(file.explode(.), length(.scan.yara.matches) > 0))`)
	if !slices.Contains(enriched.Capabilities, enrich.CapFileExplode) {
		t.Errorf("capabilities = %v, want file.explode", enriched.Capabilities)
	}

	multi := check(t, `network.whois(sender.email.domain).days_old < 30
		and any(ml.nlu_classifier(body.current_thread.text).intents, .name == "cred_theft")`)
	want := []enrich.Capability{enrich.CapMLNLUClassifier, enrich.CapNetworkWhois}
	if !slices.Equal(multi.Capabilities, want) {
		t.Errorf("capabilities = %v, want %v", multi.Capabilities, want)
	}
}

func TestListsAreReported(t *testing.T) {
	c := check(t, `sender.email.domain.domain in $org_domains
		or sender.email.domain.root_domain in $free_email_providers`)
	want := []string{"free_email_providers", "org_domains"}
	if !slices.Equal(c.Lists, want) {
		t.Errorf("lists = %v, want %v", c.Lists, want)
	}
}

func TestUnknownListIsCaughtWhenTheSetIsKnown(t *testing.T) {
	// A misspelled list is indistinguishable from an empty one at evaluation, which
	// silently switches a detection off.
	opts := &mql.CheckOptions{KnownLists: []string{"org_domains"}}
	if _, err := mql.Compile(`sender.email.domain.domain in $org_domains`, opts); err != nil {
		t.Fatalf("a known list was rejected: %v", err)
	}
	_, err := mql.Compile(`sender.email.domain.domain in $org_domians`, opts)
	if err == nil || !strings.Contains(err.Error(), "no list named $org_domians") {
		t.Errorf("a misspelled list was accepted: %v", err)
	}
}

func TestRequireBoolean(t *testing.T) {
	// Insight queries return values by design; detection rules must not.
	valueQuery := `map(attachments, coalesce(.file_name, "Unnamed Attachment"))`
	if _, err := mql.Compile(valueQuery, nil); err != nil {
		t.Fatalf("an insight query was rejected: %v", err)
	}
	_, err := mql.Compile(valueQuery, &mql.CheckOptions{RequireBoolean: true})
	if err == nil || !strings.Contains(err.Error(), "must evaluate to a boolean") {
		t.Errorf("a value-returning detection rule was accepted: %v", err)
	}
	if _, err := mql.Compile(`type.inbound`, &mql.CheckOptions{RequireBoolean: true}); err != nil {
		t.Errorf("a boolean detection rule was rejected: %v", err)
	}
}

func TestResultTypes(t *testing.T) {
	for src, want := range map[string]mdm.Kind{
		`type.inbound`:                       mdm.KindBool,
		`subject.subject`:                    mdm.KindString,
		`length(attachments)`:                mdm.KindInt,
		`ratio(attachments, .size > 0)`:      mdm.KindFloat,
		`attachments`:                        mdm.KindArray,
		`map(attachments, .file_name)`:       mdm.KindArray,
		`filter(attachments, .size > 0)`:     mdm.KindArray,
		`sender.email.domain`:                mdm.KindObject,
		`strings.parse_json(body.plain.raw)`: mdm.KindJSON,
	} {
		t.Run(truncateName(src), func(t *testing.T) {
			if got := check(t, src).Type.Kind; got != want {
				t.Errorf("%s has type %s, want %s", src, got, want)
			}
		})
	}

	// map() carries the element type through, so a later field access still checks.
	c := check(t, `map(attachments, .file_name)`)
	if elem := c.Type.Elem_(); elem.Kind != mdm.KindString {
		t.Errorf("map(attachments, .file_name) yields [%s], want [string]", elem.Describe())
	}
}

func TestJSONTraversalIsDynamic(t *testing.T) {
	// JSON is dynamic by definition: traversal must not be rejected for shapes that are
	// only known at run time.
	check(t, `strings.parse_json(body.plain.raw)["company"] == "Sublime Security"`)
	check(t, `any(keys(strings.parse_json(body.plain.raw)["meta"]), . == "name")`)
}

func TestRegistryExtension(t *testing.T) {
	reg := mql.NewRegistry()
	if err := reg.Register(&mql.Func{
		Name: "acme.reputation", Params: []mql.Param{{Name: "domain"}}, Return: mdm.Int,
	}); err != nil {
		t.Fatalf("registering an extension: %v", err)
	}
	if _, err := mql.Compile(`acme.reputation(sender.email.domain) > 50`, &mql.CheckOptions{Registry: reg}); err != nil {
		t.Errorf("an extension function was rejected: %v", err)
	}
	// The default registry must not have gained it.
	checkFails(t, `acme.reputation(sender.email.domain) > 50`, `no function "acme.reputation"`)

	// Extensions must be namespaced, so they can never collide with a future builtin.
	if err := reg.Register(&mql.Func{Name: "reputation"}); err == nil {
		t.Error("an unnamespaced extension was accepted")
	}
	// And strict mode refuses them outright, which is what keeps the compatibility
	// number meaningful after someone has extended the language.
	if err := mql.NewRegistry().Strict().Register(&mql.Func{Name: "acme.other"}); err == nil {
		t.Error("a strict registry accepted an extension")
	}
}

func TestStandardRegistryCoversTheCorpusSurface(t *testing.T) {
	// The namespaced functions the corpus calls, plus the builtins. A missing entry here
	// is a rule that stops compiling.
	for _, name := range []string{
		"any", "all", "filter", "map", "distinct", "flatten", "sum", "ratio",
		"length", "coalesce", "keys", "values",
		"strings.icontains", "strings.ilike", "strings.replace_confusables",
		"strings.levenshtein", "strings.parse_url", "strings.scan_base64", "strings.decode_hex",
		"regex.icontains", "regex.iextract", "regex.icount",
		"html.xpath", "hash.sha256",
		"file.explode", "file.parse_eml", "file.oletools", "file.message_screenshot",
		"ml.nlu_classifier", "ml.link_analysis", "ml.logo_detect", "ml.attack_score",
		"network.whois",
		"profile.by_sender", "profile.by_reply_to",
		"beta.ip_in", "beta.ocr", "beta.scan_qr", "beta.file.parse_ics", "beta.profile.by_reply_to",
	} {
		if _, ok := mql.NewRegistry().Lookup(name); !ok {
			t.Errorf("the standard registry has no %q", name)
		}
	}
}

func TestPureFunctionsNeedNoCapability(t *testing.T) {
	// The split between what module 1 implements and what a later service provides.
	reg := mql.NewRegistry()
	for _, name := range []string{
		"any", "length", "strings.icontains", "regex.match", "html.xpath",
		"file.parse_html", "file.parse_eml", "beta.ip_in", "hash.sha256",
	} {
		f, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("no %q", name)
		}
		if !f.Pure() {
			t.Errorf("%s reports capability %q, want none", name, f.Capability)
		}
	}
	for _, name := range []string{
		"file.explode", "ml.nlu_classifier", "network.whois", "profile.by_sender", "beta.ocr",
	} {
		f, _ := reg.Lookup(name)
		if f.Pure() {
			t.Errorf("%s reports no capability, but it cannot be computed from the message", name)
		}
	}
}

func truncateName(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}
