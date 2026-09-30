// SPDX-License-Identifier: AGPL-3.0-only

package rules

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// Engine holds compiled detection content and runs it over messages.
//
// Compilation happens once, at load: a rule is parsed and type-checked before any message
// reaches it, so a typo is a startup error rather than a detection that quietly never
// fires. Evaluation is then read-only and safe to run concurrently.
type Engine struct {
	compiled []*Compiled
	opts     Options
}

// Compiled is one entity ready to run.
type Compiled struct {
	Entity  *Entity
	Checked *mql.Checked
}

// Options configure an engine.
type Options struct {
	// Registry is the function set. Nil means the standard one.
	Registry *mql.Registry

	// Enricher answers what the message alone cannot. Nil means nothing beyond the
	// message is available, and rules needing more report indeterminate.
	Enricher mql.Enricher

	// Lists resolves named lists.
	Lists mql.ListResolver

	// MaxSteps bounds the work one rule may do.
	MaxSteps int

	// SkipDisabled leaves out entities marked inactive.
	SkipDisabled bool

	// Concurrency is how many rules evaluate at once, for the whole engine. Zero
	// uses defaultConcurrency. A RunOptions value overrides it for one run.
	Concurrency int
}

// LoadError records an entity that could not be compiled.
type LoadError struct {
	Entity *Entity
	Err    error
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("%s (%s): %v", e.Entity.displayPath(), e.Entity.Name, e.Err)
}

func (e *LoadError) Unwrap() error { return e.Err }

// New compiles a set of entities into an engine.
//
// Entities that fail to compile are returned separately rather than aborting the load. A
// feed with one broken rule should still protect against the other fifteen hundred, and
// the broken one should be loudly visible rather than silently absent.
func New(entities []*Entity, opts *Options) (*Engine, []*LoadError) {
	if opts == nil {
		opts = &Options{}
	}
	eng := &Engine{opts: *opts}

	var failures []*LoadError
	for _, e := range entities {
		if opts.SkipDisabled && !e.Enabled() {
			continue
		}
		if err := e.Validate(); err != nil {
			failures = append(failures, &LoadError{Entity: e, Err: err})
			continue
		}
		// Automations run over triage state, which this engine does not model.
		if e.Type == KindTriageRule {
			continue
		}

		checked, err := mql.Compile(e.Source, &mql.CheckOptions{
			Registry: opts.Registry,
			// Only detection rules must yield a boolean. An insight query returning a
			// list of attachment names is doing exactly its job.
			RequireBoolean: e.Type == KindRule || e.Type == KindDLP || e.Type == KindExclusion,
		})
		if err != nil {
			failures = append(failures, &LoadError{Entity: e, Err: err})
			continue
		}
		eng.compiled = append(eng.compiled, &Compiled{Entity: e, Checked: checked})
	}
	return eng, failures
}

// LoadPath builds an engine from a file or directory of detection content.
func LoadPath(path string, opts *Options) (*Engine, []*LoadError, error) {
	entities, err := LoadDir(path)
	if err != nil {
		return nil, nil, err
	}
	if len(entities) == 0 {
		return nil, nil, fmt.Errorf("no detection content found under %s", path)
	}
	eng, failures := New(entities, opts)
	return eng, failures, nil
}

// Len reports how many entities are loaded.
func (e *Engine) Len() int { return len(e.compiled) }

// Compiled exposes the loaded entities, for a caller that needs to report on the rule
// set rather than run it — a rules view in a dashboard, or an operator asking what a
// deployment would evaluate before sending a message through it.
//
// The slice is the engine's own, not a copy: it is read-only after loading, and
// copying a thousand compiled rules per request to defend against a caller who
// modifies them would cost more than the mistake.
func (e *Engine) Compiled() []*Compiled { return e.compiled }

// Capabilities lists every enrichment the loaded content can ask for. Knowing this before
// any message arrives is what lets a deployment see, at startup, how much of its rule set
// it can actually answer.
func (e *Engine) Capabilities() []enrich.Capability {
	seen := map[enrich.Capability]bool{}
	var out []enrich.Capability
	for _, c := range e.compiled {
		for _, cap := range c.Checked.Capabilities {
			if !seen[cap] {
				seen[cap] = true
				out = append(out, cap)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CapabilityCounts is how many rules depend on each capability.
//
// The number is what makes an unavailable provider legible: "strelka is down" is a
// fact about infrastructure, "and 214 rules cannot run" is a fact about detection
// coverage, and only the second tells an operator whether to care right now.
func (e *Engine) CapabilityCounts() map[enrich.Capability]int {
	out := map[enrich.Capability]int{}
	for _, c := range e.compiled {
		seen := map[enrich.Capability]bool{}
		for _, cap := range c.Checked.Capabilities {
			if seen[cap] {
				continue
			}
			seen[cap] = true
			out[cap]++
		}
	}
	return out
}

// Lists names every list the loaded content references.
func (e *Engine) Lists() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range e.compiled {
		for _, l := range c.Checked.Lists {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Detection is one rule's outcome on one message.
type Detection struct {
	Entity  *Entity
	Verdict mql.Verdict

	// Value is what the entity evaluated to. For a query this is the answer; for a rule
	// it is the boolean behind the verdict.
	Value mql.Value

	// Missing lists the capabilities this entity could not get.
	Missing []enrich.Capability

	// Err is a genuine evaluation failure, distinct from a missing capability.
	Err error
}

// Report is everything the engine concluded about one message.
type Report struct {
	// Flagged are the detection rules that fired and were not excluded.
	Flagged []*Detection

	// Excluded are the exclusion rules that matched. A message with any of these is not
	// flagged, however many detections fired.
	Excluded []*Detection

	// Indeterminate are entities that could not reach a verdict. These are the reason the
	// report cannot simply be read as "clean" when Flagged is empty.
	Indeterminate []*Detection

	// Queries are the insight results, keyed by entity name.
	Queries map[string]mql.Value

	// Errors are entities that failed outright.
	Errors []*Detection

	// Missing is every capability anything asked for and could not get.
	Missing []enrich.Capability
}

// Clean reports whether the message can honestly be called clean.
//
// It is deliberately not "no detections fired". A message where half the rule set could
// not run has not been cleared, it has been partially inspected, and saying otherwise is
// how a model outage turns into a delivered attack.
func (r *Report) Clean() bool {
	return len(r.Flagged) == 0 && len(r.Indeterminate) == 0 && len(r.Errors) == 0
}

// Suppressed reports whether an exclusion matched.
func (r *Report) Suppressed() bool { return len(r.Excluded) > 0 }

// Severity returns the highest severity among the flagged rules.
func (r *Report) Severity() Severity {
	var worst Severity
	for _, d := range r.Flagged {
		if d.Entity.Severity.rank() > worst.rank() {
			worst = d.Entity.Severity
		}
	}
	return worst
}

// RunOptions override the engine's defaults for one message.
//
// The enricher is the reason this exists. An engine is built once and run over many
// messages, but enrichment must be cached *per message*: within one analysis an
// enrichment is a pure function of its arguments, and across messages it is not.
// Without a per-run override a caller would have to rebuild the engine — recompiling
// every rule — to get a fresh cache.
type RunOptions struct {
	// Enricher replaces the engine's, for this message only.
	Enricher mql.Enricher

	// Lists replaces the engine's, for this message only. A service resolving
	// history-backed lists per tenant needs this for the same reason.
	Lists mql.ListResolver

	// Concurrency is how many rules are evaluated at once. Zero means the
	// package default; one restores strictly sequential evaluation.
	//
	// See the note on parallel evaluation above RunWith.
	Concurrency int
}

// defaultConcurrency is how many rules evaluate at once.
//
// Modest, and measured rather than reasoned. The intuition is that this work is all
// waiting — on a browser, on inference, on a registry — so more concurrency is free.
// It is not: those services are CPU-bound themselves, and a single ONNX inference
// already uses every core. Raising this to sixteen made a real message *slower*, from
// 27 seconds to 35, with the inference service's own summed time tripling under
// contention.
//
// A handful still helps, because some calls really are idle waiting — an RDAP lookup,
// an HTTP fetch — and those overlap with everything else. Beyond that the queue
// simply moves from this process into the service.
//
// That measurement was taken when inference ran on the CPU and one classification
// cost seconds. It now runs on the GPU in about eighty milliseconds, and the cost
// moved to link fetching. The right number under those conditions is not
// necessarily four, which is why it is settable per deployment — but the default
// stays where it was measured until a new measurement replaces it.
const defaultConcurrency = 4

// Run evaluates every loaded entity against a message.
func (e *Engine) Run(ctx context.Context, msg *mdm.MessageDataModel) *Report {
	return e.RunWith(ctx, msg, nil)
}

// RunWith evaluates every loaded entity against a message, with per-run overrides.
func (e *Engine) RunWith(ctx context.Context, msg *mdm.MessageDataModel, opts *RunOptions) *Report {
	report := &Report{Queries: map[string]mql.Value{}}
	evalOpts := &mql.EvalOptions{
		Registry: e.opts.Registry,
		Enricher: e.opts.Enricher,
		Lists:    e.opts.Lists,
		MaxSteps: e.opts.MaxSteps,
	}
	if opts != nil {
		if opts.Enricher != nil {
			evalOpts.Enricher = opts.Enricher
		}
		if opts.Lists != nil {
			evalOpts.Lists = opts.Lists
		}
	}

	missing := map[enrich.Capability]bool{}

	// Rules are evaluated in parallel, and the results are classified in order.
	//
	// Almost nothing here is CPU work. A rule that reads ml.link_analysis waits on a
	// browser visiting a URL; one that reads ml.nlu_classifier waits on inference;
	// file.explode waits on Strelka. Evaluated one after another, every one of those
	// waits is added to the last, and a real message with nine links spent ninety
	// seconds doing almost nothing — long enough to blow the analysis deadline, after
	// which every capability the evaluator reached next was reported missing and a
	// working deployment looked broken.
	//
	// Nothing about rules is ordered. They are independent expressions over one
	// immutable message, and the per-message cache is built for this: it holds a
	// mutex and a sync.Once per entry, so two rules asking the same question
	// concurrently make one call and both wait on it. That is a better outcome than
	// the sequential version, which made the same call twice in a row.
	//
	// Results are collected by index and classified afterwards in the original order,
	// so a report is identical whatever the scheduler does — the same rules in the
	// same places, just sooner.
	results := make([]*mql.Result, len(e.compiled))

	// Per-run beats per-engine beats the default. Options.Concurrency was being
	// ignored entirely — the engine-level setting existed, was plumbed through
	// Options, and nothing ever read it, so a deployment that configured it got
	// the default and no complaint.
	limit := e.concurrency(opts)
	if limit > len(e.compiled) {
		limit = len(e.compiled)
	}

	if limit <= 1 {
		for i, c := range e.compiled {
			results[i] = mql.Eval(ctx, c.Checked, msg, evalOpts)
		}
	} else {
		sem := make(chan struct{}, limit)
		var wg sync.WaitGroup
		for i, c := range e.compiled {
			wg.Add(1)
			go func(i int, c *Compiled) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				results[i] = mql.Eval(ctx, c.Checked, msg, evalOpts)
			}(i, c)
		}
		wg.Wait()
	}

	for i, c := range e.compiled {
		res := *results[i]
		d := &Detection{
			Entity:  c.Entity,
			Verdict: res.Verdict,
			Value:   res.Value,
			Missing: res.Missing,
			Err:     res.Err,
		}
		for _, cap := range res.Missing {
			missing[cap] = true
		}

		switch {
		case res.Err != nil:
			report.Errors = append(report.Errors, d)

		case c.Entity.Type == KindQuery:
			// A query has no verdict; its value is the point.
			if res.Err == nil {
				report.Queries[c.Entity.Name] = res.Value
			}

		case c.Entity.Type == KindExclusion:
			if res.Verdict == mql.Match {
				report.Excluded = append(report.Excluded, d)
			}

		case res.Verdict == mql.Match:
			report.Flagged = append(report.Flagged, d)

		case res.Verdict == mql.Indeterminate:
			report.Indeterminate = append(report.Indeterminate, d)
		}
	}

	for cap := range missing {
		report.Missing = append(report.Missing, cap)
	}
	sort.Slice(report.Missing, func(i, j int) bool { return report.Missing[i] < report.Missing[j] })

	// Most serious first, so the reason a message was flagged leads the report.
	sort.SliceStable(report.Flagged, func(i, j int) bool {
		return report.Flagged[i].Entity.Severity.rank() > report.Flagged[j].Entity.Severity.rank()
	})
	return report
}

// Registry is the function set this engine compiles against.
//
// Exposed because the engine is not the only thing that type-checks MQL: the API
// validates rules an analyst is writing, and a hunt compiles an expression before
// running it. Those have to agree with the engine or they reject expressions the
// engine would happily evaluate — which is what happened to the rdap.* extensions,
// valid at run time and refused by the editor.
//
// Nil means the standard Sublime surface.
func (e *Engine) Registry() *mql.Registry { return e.opts.Registry }

// concurrency resolves how many rules to evaluate at once: per-run, then
// per-engine, then the measured default.
func (e *Engine) concurrency(opts *RunOptions) int {
	if opts != nil && opts.Concurrency > 0 {
		return opts.Concurrency
	}
	if e.opts.Concurrency > 0 {
		return e.opts.Concurrency
	}
	return defaultConcurrency
}
