// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rdap"
	"github.com/lazaretemail/lazaret/rules"
)

// An expression using rdap.ip is valid where the engine has it.
//
// The bug this covers: the engine compiled rules against its own registry, which
// with -rdap (on by default) includes rdap.ip and rdap.asn, while the validate
// endpoint and the hunter both called mql.Compile with no registry at all. So the
// engine would happily evaluate a rule that its own editor told the author was
// invalid — the worst kind of disagreement, because the author believes the editor.
const rdapExpr = `type.inbound and any(headers.ips, rdap.ip(.ip).days_old < 90)`

func extendedPipeline(t *testing.T) *Pipeline {
	t.Helper()
	reg, err := rdap.ExtendedRegistry()
	if err != nil {
		t.Fatalf("extended registry: %v", err)
	}
	eng, failures := rules.New(nil, &rules.Options{Registry: reg})
	if len(failures) > 0 {
		t.Fatalf("building engine: %v", failures)
	}
	p := &Pipeline{}
	p.setRules(eng)
	return p
}

func TestValidationUsesTheEnginesRegistry(t *testing.T) {
	p := extendedPipeline(t)

	if p.Registry() == nil {
		t.Fatal("Pipeline.Registry() is nil; validation would fall back to the stock surface")
	}
	if _, err := mql.Compile(rdapExpr, &mql.CheckOptions{
		RequireBoolean: true,
		Registry:       p.Registry(),
	}); err != nil {
		t.Errorf("engine registry rejected an expression the engine can evaluate: %v", err)
	}
}

// The other half: without the extension the same expression must still be refused,
// and say why. A deployment running -rdap=false should not silently accept a rule
// that will never answer.
func TestStockRegistryStillRefusesExtensions(t *testing.T) {
	_, err := mql.Compile(rdapExpr, &mql.CheckOptions{RequireBoolean: true})
	if err == nil {
		t.Fatal("the stock registry accepted rdap.ip; extensions must stay opt-in")
	}
	if !strings.Contains(err.Error(), "rdap.ip") {
		t.Errorf("refusal does not name the missing function: %v", err)
	}
}

// A hunt has to accept exactly what the rules accept, or an analyst cannot hunt for
// the thing a rule just matched.
func TestHunterCompilesAgainstTheEnginesRegistry(t *testing.T) {
	p := extendedPipeline(t)

	h := NewHunter(nil, nil)
	if _, err := mql.Compile(rdapExpr, &mql.CheckOptions{Registry: h.registry}); err == nil {
		t.Error("a hunter with no registry accepted an extension function")
	}

	h.UseRegistry(p.Registry())
	if _, err := mql.Compile(rdapExpr, &mql.CheckOptions{Registry: h.registry}); err != nil {
		t.Errorf("hunter refused an expression the engine evaluates: %v", err)
	}
}

// A hunt must never report a confident zero for something it could not check.
//
// It used to guarantee that by refusing: an expression calling network.whois or rdap.ip
// was rejected before any row was read, because evaluating it with no enricher would
// answer null for every message and finish with "0 matched" — which reads as "nothing
// in your mail looks like this" when the truth is "this was never checked".
//
// Refusing was the right answer while the corpus kept only conclusions. Now that what
// enrichment said is kept beside each message, the hunt runs and the same guarantee is
// met a better way: what it cannot resolve is indeterminate, counted as undecided, and
// never as a no. This test pins the guarantee rather than the refusal.
func TestHuntCannotTurnAnUnansweredQuestionIntoANo(t *testing.T) {
	p := extendedPipeline(t)
	h := NewHunter(nil, nil)
	h.UseRegistry(p.Registry())

	// Reaches the enricher unconditionally. The corpus-shaped fixture above is
	// guarded by type.inbound, which is null on a bare model, so `and` short-circuits
	// and the enrichment is never asked for — a test that never reaches the code it
	// is about.
	checked, err := mql.Compile(`rdap.ip("203.0.113.1").days_old < 90`,
		&mql.CheckOptions{Registry: h.registry})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !checked.NeedsEnrichment() {
		t.Fatal("the expression no longer needs enrichment; this test is moot")
	}

	// A message with no evidence kept: the state every message ingested before this
	// existed is in, and the state a hunt must not misread.
	replay := mql.NewReplay(nil)
	res := mql.Eval(context.Background(), checked, &mdm.MessageDataModel{},
		&mql.EvalOptions{Enricher: replay, Registry: h.registry})

	if res.Verdict == mql.NoMatch {
		t.Fatal("an expression whose evidence was never kept evaluated to a clean " +
			"no-match; a hunt would report it as nothing found")
	}
	if res.Verdict != mql.Indeterminate {
		t.Errorf("verdict %v, want indeterminate", res.Verdict)
	}
	if len(replay.Missed()) == 0 {
		t.Error("the replay did not record which capability it could not answer, so a " +
			"hunt could not tell anyone why its result is thin")
	}
}

// An expression that reads only the stored model needs no evidence at all, and must
// not be dragged through the replay path or reported as undecided.
func TestHuntStillAcceptsPlainExpressions(t *testing.T) {
	p := extendedPipeline(t)
	h := NewHunter(nil, nil)
	h.UseRegistry(p.Registry())

	checked, err := mql.Compile(`type.inbound`, &mql.CheckOptions{Registry: h.registry})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if checked.NeedsEnrichment() {
		t.Fatalf("a plain expression was read as needing enrichment: %v", checked.Capabilities)
	}

	// With no enricher at all, which is how the hunt runs it, this still reaches a
	// real verdict rather than indeterminate.
	res := mql.Eval(context.Background(), checked, &mdm.MessageDataModel{}, &mql.EvalOptions{})
	if res.Verdict == mql.Indeterminate {
		t.Error("a plain expression came out indeterminate with no enricher")
	}
}

// A hunt must evaluate against the registry it compiled against.
//
// It did not: Start compiled with the engine's registry, which may carry the rdap
// extensions, and run evaluated with EvalOptions.Registry unset, which means the
// standard set. An extension then resolved to an unknown function and reported its
// capability unavailable without the enricher ever being asked — so a hunt for
// `rdap.ip(...)` came back undecided for every message, naming no capability, which
// reads as missing evidence and was a registry mismatch.
func TestHuntEvaluatesAgainstTheRegistryItCompiledWith(t *testing.T) {
	p := extendedPipeline(t)
	h := NewHunter(nil, nil)
	h.UseRegistry(p.Registry())

	const expr = `rdap.ip("203.0.113.1").days_old < 90`
	checked, err := mql.Compile(expr, &mql.CheckOptions{Registry: h.registry})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	replay := mql.NewReplay(nil)
	mql.Eval(context.Background(), checked, &mdm.MessageDataModel{},
		&mql.EvalOptions{Enricher: replay, Registry: h.registry})

	if replay.Missed()["rdap.ip"] == 0 {
		t.Error("an extension function never reached the enricher: evaluation used the " +
			"standard registry rather than the one the expression was compiled against")
	}
}
