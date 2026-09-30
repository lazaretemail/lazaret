// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Hunt: run one MQL expression over historical messages.
//
// # Why this evaluates in Go rather than compiling to SQL
//
// The corpus is Parquet and the query engine is DuckDB, so translating MQL into SQL and
// letting the database do the work is the obvious optimisation. It is also the one
// worth refusing.
//
// MQL's semantics are this project's entire claim, and they are subtle in exactly the
// places a translation would paper over: three-valued logic through `and`, `or` and
// `X of (...)`; the difference between a null array and an empty one; `is null` binding
// as a comparison. Every one of those was settled by running expressions against
// Sublime's own engine, and several were wrong before that. A SQL compiler would be a
// second implementation of all of it, free to disagree with the first — and a hunt that
// disagrees with live evaluation is worse than a slow hunt, because it quietly tells
// an analyst that a rule would not have caught something it would have.
//
// So DuckLake does what a columnar store is uniquely good at — prune partitions, read
// one column — and the evaluator does the semantics. A 30-day hunt over a year of mail
// reads a thirtieth of the files.

// HuntJob is one historical search.
type HuntJob struct {
	ID        string       `json:"id"`
	TenantID  string       `json:"-"`
	Source    string       `json:"source"`
	State     string       `json:"state"`
	CreatedAt time.Time    `json:"created_at"`
	Finished  *time.Time   `json:"finished_at,omitempty"`
	Scanned   int64        `json:"messages_scanned"`
	Matched   int64        `json:"messages_matched"`
	Error     string       `json:"error,omitempty"`
	Results   []HuntResult `json:"results"`

	// Undecided counts messages the expression could not be resolved against,
	// because the evidence it needed was never kept. Reported rather than folded
	// into "did not match", which would turn "we do not know" into "no" — the one
	// answer a hunt must never give silently.
	Undecided int64 `json:"messages_undecided"`

	// Missing names the capabilities that went unanswered and how often, so an
	// operator can see whether a thin result means the mail was clean or the
	// evidence was not there.
	Missing map[string]int `json:"missing_evidence,omitempty"`
}

// HuntResult is one matching message.
type HuntResult struct {
	MessageID string `json:"message_id"`
}

// maxHuntResults caps what one job returns. A hunt matching everything is a mistake in
// the expression, and materialising a million results to demonstrate that helps nobody.
const maxHuntResults = 1000

// Hunter runs hunt jobs.
type Hunter struct {
	store *store.Store
	lists mql.ListResolver

	// registry is the function set to compile a hunt against, so a hunt accepts
	// exactly what the rules engine accepts. Nil means the standard surface.
	registry *mql.Registry

	// enricher is nil today: a hunt scans stored models rather than re-running
	// enrichment, which over a year of mail would mean millions of lookups. It
	// exists so the refusal above has something to check, and so wiring one later
	// is a change in one place.
	enricher mql.Enricher

	mu   sync.Mutex
	jobs map[string]*HuntJob
}

// NewHunter returns a hunter.
func NewHunter(s *store.Store, lists mql.ListResolver) *Hunter {
	return &Hunter{store: s, lists: lists, jobs: map[string]*HuntJob{}}
}

// UseRegistry points the hunter at the engine's function set, including whatever
// extensions this deployment enabled. Without it a hunt refuses expressions the
// rules running beside it use every day.
func (h *Hunter) UseRegistry(reg *mql.Registry) { h.registry = reg }

// Start compiles an expression and begins a hunt.
//
// Compilation happens synchronously so that a bad expression is a 400 with a caret
// pointing at the problem, rather than a job that fails a minute later.
func (h *Hunter) Start(ctx context.Context, tenant, source string, from, to time.Time) (*HuntJob, error) {
	checked, err := mql.Compile(source, &mql.CheckOptions{Registry: h.registry})
	if err != nil {
		return nil, err
	}

	// A hunt evaluates stored message data models and has no enrichment behind it.
	// An expression needing enrichment used to be refused here, because answering
	// null for every message would report a confident zero matches — the "unavailable
	// is false" collapse the engine refuses everywhere else, and worse here because
	// the number looks like an answer.
	//
	// It is no longer refused, because the answers are kept with the message now. What
	// it cannot resolve comes back as undecided, counted separately from no-match, with
	// the capabilities it wanted named on the job.

	job := &HuntJob{
		ID:        fmt.Sprintf("hunt-%d", time.Now().UnixNano()),
		TenantID:  tenant,
		Source:    source,
		State:     "running",
		CreatedAt: time.Now().UTC(),
		Results:   []HuntResult{},
	}

	h.mu.Lock()
	h.jobs[job.ID] = job
	h.mu.Unlock()

	if err := h.persist(ctx, job); err != nil {
		return nil, err
	}

	// Detached from the request. A hunt outlives the HTTP call that asked for it, which
	// is why the API is a job to poll rather than a synchronous search.
	go h.run(context.WithoutCancel(ctx), job, checked, from, to)
	return job, nil
}

func (h *Hunter) run(ctx context.Context, job *HuntJob, checked *mql.Checked, from, to time.Time) {
	// Enrichment is replayed, never re-run.
	//
	// Both halves of that matter. Re-running would be wrong as well as slow: a year of
	// mail is a year of models and WHOIS lookups, and the answers would be today's.
	// A link that was live in March is dead now, and a domain registered the week it
	// was used is two years old by the time anyone hunts for it — so a re-fetch quietly
	// answers a question about March with October's facts.
	//
	// What the message was actually told is kept beside it. A question the message was
	// never asked comes back unavailable rather than null, so the expression reports
	// indeterminate and the hunt counts it as undecided instead of as a clean no.
	missing := map[string]int{}

	scanned, err := h.store.ScanWithEvidence(ctx, job.TenantID, from, to,
		func(id string, raw, evidence []byte) error {
			var msg mdm.MessageDataModel
			if err := json.Unmarshal(raw, &msg); err != nil {
				// One unreadable row does not fail a hunt over a year of mail; it is
				// counted as scanned and skipped.
				return nil
			}

			// The same registry the expression was compiled against. Without it
			// evaluation falls back to the standard function set, and an extension
			// — rdap.ip, rdap.asn — resolves to unknown and reports unavailable
			// without the enricher ever being asked. The hunt then counted it as
			// undecided and named no capability, which looks like missing evidence
			// and is actually a registry mismatch.
			opts := &mql.EvalOptions{Lists: h.lists, Registry: h.registry}
			var replay *mql.ReplayEnricher
			if checked.NeedsEnrichment() {
				replay = mql.NewReplay(snapshotOf(evidence))
				opts.Enricher = replay
			}

			res := mql.Eval(ctx, checked, &msg, opts)

			h.mu.Lock()
			switch {
			case res.Verdict == mql.Match:
				if len(job.Results) < maxHuntResults {
					job.Results = append(job.Results, HuntResult{MessageID: id})
				}
				job.Matched++
			case res.Verdict == mql.Indeterminate:
				job.Undecided++
			}
			if replay != nil {
				for cap, n := range replay.Missed() {
					missing[cap] += n
				}
			}
			h.mu.Unlock()
			return nil
		})

	h.mu.Lock()
	now := time.Now().UTC()
	job.Scanned = int64(scanned)
	if len(missing) > 0 {
		job.Missing = missing
	}
	job.Finished = &now
	job.State = "finished"
	if err != nil {
		job.State = "failed"
		job.Error = err.Error()
	}
	h.mu.Unlock()

	_ = h.persist(ctx, job)
}

// Get returns a job by id.
func (h *Hunter) Get(ctx context.Context, tenant, id string) (*HuntJob, error) {
	h.mu.Lock()
	job, ok := h.jobs[id]
	h.mu.Unlock()
	if ok && job.TenantID == tenant {
		return job, nil
	}

	// Not in memory: another instance ran it, or this one restarted. Postgres holds the
	// record, which is why hunt jobs are relational state rather than corpus.
	var j HuntJob
	var results []byte
	var finished *time.Time
	err := h.store.PG().QueryRow(ctx, `
		SELECT id, source, state, created_at, finished_at, scanned, matched,
		       coalesce(error,''), results
		FROM hunt_jobs WHERE id = $1 AND tenant_id = $2`, id, tenant).
		Scan(&j.ID, &j.Source, &j.State, &j.CreatedAt, &finished, &j.Scanned, &j.Matched,
			&j.Error, &results)
	if err != nil {
		return nil, err
	}
	j.Finished = finished
	j.TenantID = tenant
	if err := json.Unmarshal(results, &j.Results); err != nil {
		j.Results = []HuntResult{}
	}
	return &j, nil
}

func (h *Hunter) persist(ctx context.Context, job *HuntJob) error {
	h.mu.Lock()
	results, _ := json.Marshal(job.Results)
	j := *job
	h.mu.Unlock()

	_, err := h.store.PG().Exec(ctx, `
		INSERT INTO hunt_jobs (id, tenant_id, source, state, created_at, finished_at,
		                       scanned, matched, error, results)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO UPDATE SET
		  state = EXCLUDED.state, finished_at = EXCLUDED.finished_at,
		  scanned = EXCLUDED.scanned, matched = EXCLUDED.matched,
		  error = EXCLUDED.error, results = EXCLUDED.results`,
		j.ID, j.TenantID, j.Source, j.State, j.CreatedAt, j.Finished,
		j.Scanned, j.Matched, nullIf(j.Error), results)
	return err
}

func nullIf(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// snapshotOf decodes frozen evidence, or returns nil.
//
// A nil snapshot is not an error and not empty-means-clean: mql.NewReplay answers every
// question against it with unavailable, so a message ingested before evidence was kept
// reports as undecided rather than as a message where nothing was found.
func snapshotOf(evidence []byte) *mql.Snapshot {
	if len(evidence) == 0 {
		return nil
	}
	var snap mql.Snapshot
	if err := json.Unmarshal(evidence, &snap); err != nil {
		return nil
	}
	return &snap
}
