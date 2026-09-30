// SPDX-License-Identifier: AGPL-3.0-only

package rules_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rules"
)

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testMessage() *mdm.MessageDataModel {
	return &mdm.MessageDataModel{
		Type:    &mdm.MessageType{Inbound: mdm.Ptr(true), Outbound: mdm.Ptr(false), Internal: mdm.Ptr(false)},
		Sender:  &mdm.SenderMailbox{Email: mdm.ParseEmailAddress("attacker@evil.test")},
		Subject: &mdm.Subject{Subject: mdm.Ptr("Urgent wire transfer")},
		Body:    &mdm.Body{CurrentThread: &mdm.Thread{Text: mdm.Ptr("Please send the payment today.")}},
	}
}

func TestLoadAcceptsTheShapesTheCorpusUses(t *testing.T) {
	dir := t.TempDir()

	// A block scalar, the usual form.
	writeRule(t, dir, "block.yml", `
name: "Block form"
type: "rule"
severity: "high"
source: |
  type.inbound
  and strings.icontains(subject.subject, "urgent")
`)
	// A plain scalar. Not in any published schema, but the corpus contains several,
	// including a literal `source: true`.
	writeRule(t, dir, "plain.yml", `
name: "Plain form"
type: "rule"
source: type.inbound and strings.icontains(subject.subject, "wire")
`)
	writeRule(t, dir, "literal.yml", `
name: "Always fires"
type: "triage_rule"
source: true
`)
	// authors is a list of single-key maps, not strings.
	writeRule(t, dir, "authors.yml", `
name: "With authors"
type: "rule"
source: "type.inbound"
authors:
  - twitter: "someone"
  - name: "A Person"
tags:
 - "one-space-indent"
`)
	// An insight query, which returns a value rather than a boolean.
	writeRule(t, dir, "query.yml", `
name: "Attachment names"
type: "query"
source: map(attachments, coalesce(.file_name, "Unnamed Attachment"))
`)

	entities, err := rules.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(entities) != 5 {
		t.Fatalf("loaded %d entities, want 5", len(entities))
	}

	byName := map[string]*rules.Entity{}
	for _, e := range entities {
		byName[e.Name] = e
	}

	if got := byName["Plain form"].Source; !strings.Contains(got, "wire") {
		t.Errorf("a plain-scalar source was lost: %q", got)
	}
	if got := byName["Always fires"].Source; got != "true" {
		t.Errorf("`source: true` decoded as %q, want the text \"true\"", got)
	}
	if a := byName["With authors"].Authors; len(a) != 2 || a[0].Twitter != "someone" || a[1].Name != "A Person" {
		t.Errorf("authors = %+v", a)
	}
	if got := byName["With authors"].Authors[0].String(); got != "someone" {
		t.Errorf("Author.String() = %q", got)
	}
}

func TestLoadSkipsNonContent(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "real.yml", "name: \"R\"\ntype: \"rule\"\nsource: \"type.inbound\"\n")
	// A rule feed is a git repository, so it contains all of this too.
	writeRule(t, dir, "workflow.yml", "on:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
	writeRule(t, dir, "notes.txt", "not yaml at all")
	writeRule(t, dir, "sig.yar", "rule x { condition: true }")

	entities, err := rules.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entities) != 1 || entities[0].Name != "R" {
		t.Errorf("loaded %d entities, want just the rule", len(entities))
	}
}

func TestValidation(t *testing.T) {
	for name, e := range map[string]*rules.Entity{
		"no name":      {Type: rules.KindRule, Source: "type.inbound"},
		"no source":    {Name: "x", Type: rules.KindRule},
		"no type":      {Name: "x", Source: "type.inbound"},
		"unknown type": {Name: "x", Type: "nonsense", Source: "type.inbound"},
		"bad severity": {Name: "x", Type: rules.KindRule, Source: "type.inbound", Severity: "urgent"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := e.Validate(); err == nil {
				t.Error("validation passed")
			}
		})
	}

	ok := &rules.Entity{Name: "x", Type: rules.KindRule, Source: "type.inbound", Severity: rules.SeverityHigh}
	if err := ok.Validate(); err != nil {
		t.Errorf("a valid entity was rejected: %v", err)
	}
}

func TestEnabledDefaultsToTrue(t *testing.T) {
	if !(&rules.Entity{}).Enabled() {
		t.Error("an entity with no `active` field is disabled, want enabled")
	}
	off := false
	if (&rules.Entity{Active: &off}).Enabled() {
		t.Error("`active: false` was ignored")
	}
}

func TestOneBrokenRuleDoesNotStopTheRest(t *testing.T) {
	// A feed with a broken rule should still protect against the other fifteen hundred,
	// and the broken one should be loudly visible rather than silently absent.
	dir := t.TempDir()
	writeRule(t, dir, "good.yml", "name: \"Good\"\ntype: \"rule\"\nsource: \"type.inbound\"\n")
	writeRule(t, dir, "typo.yml", "name: \"Typo\"\ntype: \"rule\"\nsource: \"sender.emial == 'x'\"\n")
	writeRule(t, dir, "syntax.yml", "name: \"Syntax\"\ntype: \"rule\"\nsource: \"type.inbound and (\"\n")

	engine, failures, err := rules.LoadPath(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if engine.Len() != 1 {
		t.Errorf("loaded %d rules, want 1", engine.Len())
	}
	if len(failures) != 2 {
		t.Fatalf("reported %d failures, want 2", len(failures))
	}
	for _, f := range failures {
		if f.Error() == "" || f.Entity == nil {
			t.Errorf("a failure carries no context: %+v", f)
		}
	}
}

func TestNonBooleanRuleIsRejectedButQueryIsNot(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yml", "name: \"Value rule\"\ntype: \"rule\"\nsource: \"subject.subject\"\n")
	writeRule(t, dir, "query.yml", "name: \"Value query\"\ntype: \"query\"\nsource: \"subject.subject\"\n")

	engine, failures, err := rules.LoadPath(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 || failures[0].Entity.Name != "Value rule" {
		t.Errorf("failures = %v, want just the detection rule", failures)
	}
	if engine.Len() != 1 {
		t.Errorf("loaded %d entities, want the query to survive", engine.Len())
	}
}

func TestRunFlagsAndRanks(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "high.yml", `
name: "Wire transfer language"
type: "rule"
severity: "high"
source: "type.inbound and strings.icontains(body.current_thread.text, 'payment')"
`)
	writeRule(t, dir, "low.yml", `
name: "Urgent subject"
type: "rule"
severity: "low"
source: "type.inbound and strings.icontains(subject.subject, 'urgent')"
`)
	writeRule(t, dir, "quiet.yml", `
name: "Outbound only"
type: "rule"
severity: "critical"
source: "type.outbound"
`)

	engine, failures, err := rules.LoadPath(dir, nil)
	if err != nil || len(failures) > 0 {
		t.Fatalf("loading: %v %v", err, failures)
	}

	report := engine.Run(context.Background(), testMessage())
	if len(report.Flagged) != 2 {
		t.Fatalf("flagged %d rules, want 2", len(report.Flagged))
	}
	// Most serious first, so the reason a message was flagged leads the report.
	if report.Flagged[0].Entity.Severity != rules.SeverityHigh {
		t.Errorf("first flagged is %s, want high", report.Flagged[0].Entity.Severity)
	}
	if got := report.Severity(); got != rules.SeverityHigh {
		t.Errorf("report severity = %s, want high", got)
	}
	if report.Clean() {
		t.Error("a flagged message reports itself clean")
	}
}

func TestExclusionSuppresses(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "detect.yml", `
name: "Urgent subject"
type: "rule"
severity: "high"
source: "type.inbound and strings.icontains(subject.subject, 'urgent')"
`)
	writeRule(t, dir, "exclude.yml", `
name: "Known simulation vendor"
type: "exclusion"
source: "sender.email.domain.domain == 'evil.test'"
`)

	engine, _, err := rules.LoadPath(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := engine.Run(context.Background(), testMessage())

	if !report.Suppressed() {
		t.Fatal("the exclusion did not match")
	}
	// The detection still fired and is still reported; what changes is the conclusion.
	if len(report.Flagged) != 1 {
		t.Errorf("flagged %d, want the detection still recorded", len(report.Flagged))
	}
	if len(report.Excluded) != 1 {
		t.Errorf("excluded %d, want 1", len(report.Excluded))
	}
}

func TestQueriesReturnValues(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "q.yml", `
name: "Sender domain"
type: "query"
source: "sender.email.domain.root_domain"
`)
	engine, _, err := rules.LoadPath(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := engine.Run(context.Background(), testMessage())

	got, ok := report.Queries["Sender domain"]
	if !ok {
		t.Fatalf("no query result; got %v", report.Queries)
	}
	if got.String() != "evil.test" {
		t.Errorf("query result = %s, want evil.test", got)
	}
	// A query is not a detection and must not flag anything.
	if len(report.Flagged) != 0 {
		t.Errorf("a query flagged the message: %v", report.Flagged)
	}
}

func TestCleanRequiresEverythingToHaveRun(t *testing.T) {
	// The central honesty property of the report. A message where part of the rule set
	// could not run has been partially inspected, not cleared.
	dir := t.TempDir()
	writeRule(t, dir, "needs-ml.yml", `
name: "Needs a model"
type: "rule"
source: "type.inbound and any(ml.nlu_classifier(body.current_thread.text).intents, .name == 'bec')"
`)
	engine, _, err := rules.LoadPath(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := engine.Run(context.Background(), testMessage())

	if len(report.Flagged) != 0 {
		t.Error("a rule fired that could not have")
	}
	if len(report.Indeterminate) != 1 {
		t.Fatalf("indeterminate = %d, want 1", len(report.Indeterminate))
	}
	if report.Clean() {
		t.Error("a message reports clean although a rule could not run")
	}
	if len(report.Missing) == 0 {
		t.Error("the missing capability was not reported")
	}
}

func TestCapabilitiesAndListsAreKnownBeforeAnyMessage(t *testing.T) {
	// A deployment should be able to see at startup how much of its rule set it can
	// actually answer, rather than discovering it one message at a time.
	dir := t.TempDir()
	writeRule(t, dir, "a.yml", `
name: "A"
type: "rule"
source: "type.inbound and network.whois(sender.email.domain).days_old < 30"
`)
	writeRule(t, dir, "b.yml", `
name: "B"
type: "rule"
source: "sender.email.domain.domain in $org_domains"
`)
	engine, _, err := rules.LoadPath(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if caps := engine.Capabilities(); len(caps) != 1 || string(caps[0]) != "network.whois" {
		t.Errorf("capabilities = %v", caps)
	}
	if l := engine.Lists(); len(l) != 1 || l[0] != "org_domains" {
		t.Errorf("lists = %v", l)
	}
}

func TestDisabledRulesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "off.yml", `
name: "Disabled"
type: "rule"
active: false
source: "type.inbound"
`)
	engine, _, err := rules.LoadPath(dir, &rules.Options{SkipDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if engine.Len() != 0 {
		t.Errorf("loaded %d rules, want the disabled one skipped", engine.Len())
	}
}

func TestRunIsConcurrencySafe(t *testing.T) {
	// One engine serves every message in a deployment, so evaluation must be read-only.
	dir := t.TempDir()
	writeRule(t, dir, "r.yml", `
name: "R"
type: "rule"
source: "type.inbound and strings.icontains(subject.subject, 'urgent')"
`)
	engine, _, err := rules.LoadPath(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan mql.Verdict, 32)
	for range 32 {
		go func() {
			r := engine.Run(context.Background(), testMessage())
			if len(r.Flagged) == 1 {
				done <- mql.Match
				return
			}
			done <- mql.NoMatch
		}()
	}
	for range 32 {
		if v := <-done; v != mql.Match {
			t.Fatalf("concurrent run produced %s", v)
		}
	}
}
