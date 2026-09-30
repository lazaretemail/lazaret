// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rules"
)

// evidenceWith builds a frozen-evidence blob holding one ml.link_analysis answer, the
// way the pipeline writes it.
func evidenceWith(t *testing.T, out *mdm.LinkAnalysisOutput) []byte {
	t.Helper()
	value, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	snap := mql.Snapshot{Entries: map[string]mql.SnapshotEntry{
		"k": {Capability: string(enrich.CapMLLinkAnalysis), Kind: "object", Value: value},
	}}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The watch list comes out of the frozen evidence, with the digest of what was seen.
//
// This is the whole premise of the feature: the pipeline already records what every
// link served when the message was judged, so scheduling a re-visit needs no second
// code path collecting the same URLs — and no second code path that could disagree
// with the record about what "before" was.
func TestWatchListComesFromFrozenEvidence(t *testing.T) {
	ev := evidenceWith(t, &mdm.LinkAnalysisOutput{
		OriginalURL:  mdm.ParseURL("https://example.com/invoice", true),
		EffectiveURL: mdm.ParseURL("https://example.com/landing", true),
		Retrieved:    mdm.Ptr(true),
		FinalDom:     &mdm.FinalDOM{Raw: mdm.Ptr(strings.Repeat("x", 4000))},
	})

	links := watchableLinks(ev)
	digest, ok := links["https://example.com/invoice"]
	if !ok {
		t.Fatalf("the link was not scheduled; got %v", links)
	}
	if want := LinkDigest("https://example.com/landing", true, 4000); digest != want {
		t.Errorf("digest %q does not describe what was seen (want %q)", digest, want)
	}
}

// A message whose links were never fetched schedules nothing.
//
// Correct rather than a gap: with no "before" there is nothing a later visit could be
// compared against, and watching the link anyway would file a finding the first time it
// was looked at, for every link in every message.
func TestNothingIsWatchedWithoutAFetch(t *testing.T) {
	if got := watchableLinks(nil); len(got) != 0 {
		t.Errorf("scheduled %v from no evidence", got)
	}

	other, _ := json.Marshal(mql.Snapshot{Entries: map[string]mql.SnapshotEntry{
		"k": {Capability: "file.explode", Value: json.RawMessage(`{}`)},
	}})
	if got := watchableLinks(other); len(got) != 0 {
		t.Errorf("scheduled %v from evidence with no link analysis in it", got)
	}
}

// Links a browser cannot be pointed at are left out.
//
// mailto: and tel: are in real mail and have no page to re-visit. Scheduling them would
// put a row in the table for every one, each of which fails four times before it is
// given up on.
func TestUnfetchableSchemesAreNotWatched(t *testing.T) {
	ev := evidenceWith(t, &mdm.LinkAnalysisOutput{
		OriginalURL: mdm.ParseURL("mailto:accounts@example.com", true),
		Retrieved:   mdm.Ptr(false),
	})
	if got := watchableLinks(ev); len(got) != 0 {
		t.Errorf("scheduled %v for a mailto: link", got)
	}
}

// The digest is deaf to ordinary churn and alert to a link moving.
//
// A page with a nonce or a rotating advert differs on every load. If the comparison
// were a hash of the page, every such link would be a finding every six hours, and the
// findings that matter would be buried by lunchtime.
func TestDigestIgnoresChurnAndNoticesRedirection(t *testing.T) {
	base := LinkDigest("https://example.com/a", true, 41000)

	if churned := LinkDigest("https://example.com/a", true, 41900); churned != base {
		t.Error("a page that grew by 2% reads as a changed link")
	}
	if moved := LinkDigest("https://elsewhere.test/a", true, 41000); moved == base {
		t.Error("a link that now resolves somewhere else reads as unchanged")
	}
	if dead := LinkDigest("https://example.com/a", false, 0); dead == base {
		t.Error("a link that stopped responding reads as unchanged")
	}
	// The case the feature exists for: a page that was a 404 stub and is now a
	// credential form.
	if armed := LinkDigest("https://example.com/a", true, 41000); armed ==
		LinkDigest("https://example.com/a", true, 900) {
		t.Error("a stub replaced by a full page reads as unchanged")
	}
}

// A reload reports only the rules that were not already running.
//
// The sweep is triggered by this, and a first load must report nothing: against an
// empty engine every rule is new, and sweeping the whole corpus over the whole corpus
// on first start would file a finding for every message any rule has ever matched.
func TestOnlyNewRulesTriggerASweep(t *testing.T) {
	prev := engineWith(t, map[string]string{
		"a": `subject.subject is not null`,
		"b": `type.inbound`,
	})
	next := engineWith(t, map[string]string{
		"a": `subject.subject is not null`,              // unchanged
		"b": `type.inbound and length(attachments) > 0`, // rewritten
		"c": `type.outbound`,                            // new
	})

	got := map[string]bool{}
	for _, n := range appeared(prev, next) {
		got[n] = true
	}
	if got["a"] {
		t.Error("an unchanged rule was swept again")
	}
	if !got["b"] {
		t.Error("a rewritten rule was not swept; what the old version would have caught is a different question")
	}
	if !got["c"] {
		t.Error("a new rule was not swept, which is the whole point of the trigger")
	}
	if n := appeared(nil, next); len(n) != 0 {
		t.Errorf("first load swept %d rule(s) over the whole corpus", len(n))
	}
}

// engineWith builds a rules engine from name→source pairs.
func engineWith(t *testing.T, sources map[string]string) *rules.Engine {
	t.Helper()
	var entities []*rules.Entity
	for name, src := range sources {
		entities = append(entities, &rules.Entity{Name: name, Type: rules.KindRule, Source: src})
	}
	eng, failures := rules.New(entities, nil)
	if len(failures) > 0 {
		t.Fatalf("building engine: %v", failures)
	}
	return eng
}

// A restart does not sweep the whole corpus.
//
// The engine starts with only its local rules directory — one rule in a normal
// deployment — and the feeds bring in twelve hundred a moment later. Compared against
// what was running, all twelve hundred look new, so without this the first reload after
// every restart would run the entire rule set over the entire corpus and file findings
// for everything any rule has ever matched. A restart is not new intelligence.
func TestARestartDoesNotSweepEverything(t *testing.T) {
	var swept [][]string
	f := &FeedSyncer{}
	f.OnNewRules(func(_ context.Context, names []string) { swept = append(swept, names) })

	local := engineWith(t, map[string]string{"local": `type.inbound`})
	feeds := engineWith(t, map[string]string{
		"local": `type.inbound`,
		"a":     `type.outbound`,
		"b":     `subject.subject is not null`,
	})

	// What Reload does around the hook, without the filesystem and store it needs.
	fire := func(prev, next *rules.Engine) {
		first := !f.reloaded
		f.reloaded = true
		if f.onNewRules != nil && !first {
			if names := appeared(prev, next); len(names) > 0 {
				f.onNewRules(context.Background(), names)
			}
		}
	}

	fire(local, feeds) // the reload every start does
	if len(swept) != 0 {
		t.Fatalf("a restart swept %v", swept)
	}

	// A feed genuinely gaining a rule afterwards still sweeps.
	more := engineWith(t, map[string]string{
		"local": `type.inbound`,
		"a":     `type.outbound`,
		"b":     `subject.subject is not null`,
		"c":     `length(attachments) > 0`,
	})
	fire(feeds, more)
	if len(swept) != 1 || len(swept[0]) != 1 || swept[0][0] != "c" {
		t.Errorf("a feed update swept %v, want just the one new rule", swept)
	}
}
