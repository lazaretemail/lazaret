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

// What a rule would have done, before it is allowed to do anything.
//
// Enabling a detection rule is a decision made blind almost everywhere: you read the
// expression, you guess, and you find out from the complaints. The corpus knows what
// arrived and, now that enrichment is frozen beside it, what each message was told —
// so the rule can simply be run over the last ninety days and asked.
//
// Three numbers come back, and the third is the one that makes the other two honest:
//
//   - matched, with examples
//   - did not match
//   - could not be decided, because the evidence that rule wanted was never kept
//
// Most tools would fold the third into the second. That turns "we never checked" into
// "nothing found", which is the collapse this engine refuses everywhere else, and it is
// worse here because the number is about to be used to make a decision.
//
// # Precision, where it can be had
//
// A new rule has no reviews of its own. What it does have is the triage state of the
// messages it would have matched: an analyst has already looked at some of them and
// said benign, or confirmed them. That is a real precision signal for a rule nobody has
// ever run — "it would have fired on 34, and you already called 11 of those benign" is
// the sentence that stops a bad rule being enabled.
//
// Reported only when enough of the matches were reviewed, on the same footing as
// store.RuleStat: a rule with two reviews and both benign is not a bad rule, it is an
// unmeasured one, and presenting 0% for it would be a lie told with arithmetic.
type Backtester struct {
	store    *store.Store
	lists    mql.ListResolver
	registry *mql.Registry

	mu   sync.Mutex
	jobs map[string]*BacktestJob
}

// BacktestJob is one run of a rule over stored mail.
type BacktestJob struct {
	ID       string `json:"id"`
	TenantID string `json:"-"`

	// Rule is what was tested, as given. Kept so a result can be read months later
	// without hunting for the version of the rule that produced it.
	Rule     string `json:"rule"`
	RuleName string `json:"rule_name,omitempty"`

	State     string     `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	Finished  *time.Time `json:"finished_at,omitempty"`
	Error     string     `json:"error,omitempty"`

	From time.Time `json:"from"`
	To   time.Time `json:"to"`

	Scanned   int64 `json:"messages_scanned"`
	Matched   int64 `json:"messages_matched"`
	Undecided int64 `json:"messages_undecided"`

	// Missing names the capabilities the rule wanted and the stored evidence could
	// not answer. A large number here means the result is thin, and says why.
	Missing map[string]int `json:"missing_evidence,omitempty"`

	// Reviewed is how many of the matches an analyst had already judged, and how
	// they judged them.
	Reviewed  int64 `json:"reviewed"`
	Benign    int64 `json:"benign"`
	Confirmed int64 `json:"confirmed"`

	Results []BacktestHit `json:"results"`
}

// BacktestHit is one message the rule would have fired on.
type BacktestHit struct {
	MessageID  string    `json:"message_id"`
	ReceivedAt time.Time `json:"received_at"`
	Subject    string    `json:"subject,omitempty"`
	Sender     string    `json:"sender,omitempty"`

	// Triage is what an analyst had already concluded about this message, if
	// anything. "benign" against a proposed detection is the interesting case.
	Triage string `json:"triage,omitempty"`

	// Verdict is what the deployment concluded at the time, so an operator can see
	// whether the rule is finding something new or agreeing with what already fired.
	Verdict string `json:"verdict,omitempty"`
}

// maxBacktestHits caps what one run returns, for the same reason a hunt is capped: a
// rule matching everything is a mistake in the expression, and materialising a hundred
// thousand examples to demonstrate that helps nobody.
const maxBacktestHits = 500

// minReviewedForPrecision is how many of a rule's matches must already have been
// judged before a precision figure means anything. Same bar as store.RuleStat.
const minReviewedForPrecision = 5

// NewBacktester returns a runner.
func NewBacktester(s *store.Store, lists mql.ListResolver) *Backtester {
	return &Backtester{store: s, lists: lists, jobs: map[string]*BacktestJob{}}
}

// UseRegistry sets the function set rules are compiled and evaluated against, so a
// deployment with the rdap extensions can test a rule that uses them.
func (b *Backtester) UseRegistry(reg *mql.Registry) { b.registry = reg }

// PrecisionKnown reports whether enough matches were reviewed to say anything.
func (j *BacktestJob) PrecisionKnown() bool { return j.Reviewed >= minReviewedForPrecision }

// Precision is confirmed over reviewed, and meaningless unless PrecisionKnown.
func (j *BacktestJob) Precision() float64 {
	if j.Reviewed == 0 {
		return 0
	}
	return float64(j.Confirmed) / float64(j.Reviewed)
}

// Start compiles a rule and runs it over a window, returning a job to poll.
func (b *Backtester) Start(ctx context.Context, tenant, name, source string, from, to time.Time) (*BacktestJob, error) {
	// Compile before looking at the deployment. A malformed rule is the author's
	// problem whatever this engine has behind it, and being told "no corpus" when the
	// actual fault is a typo in the expression sends someone off to check their
	// storage configuration.
	checked, err := mql.Compile(source, &mql.CheckOptions{Registry: b.registry})
	if err != nil {
		// The compiler's message is the useful one — it points at the column.
		return nil, err
	}
	// Detection rules yield a boolean; an insight query legitimately yields an array
	// or a number, and backtesting one would be counting truthiness that MQL does not
	// have.
	if k := checked.Type.KindOr(mdm.KindBool); k != mdm.KindBool {
		return nil, fmt.Errorf("a detection rule has to evaluate to true or false; this "+
			"one yields %s, which is an insight query rather than a rule", checked.Type.Describe())
	}

	if b.store == nil {
		return nil, fmt.Errorf("the rule is valid, but no corpus is configured, so there " +
			"is nothing to test it against")
	}

	job := &BacktestJob{
		ID:        fmt.Sprintf("bt-%d", time.Now().UnixNano()),
		TenantID:  tenant,
		Rule:      source,
		RuleName:  name,
		State:     "running",
		CreatedAt: time.Now().UTC(),
		From:      from,
		To:        to,
		Results:   []BacktestHit{},
	}
	b.mu.Lock()
	b.jobs[job.ID] = job
	b.mu.Unlock()

	go b.run(context.WithoutCancel(ctx), job, checked)
	return job, nil
}

func (b *Backtester) run(ctx context.Context, job *BacktestJob, checked *mql.Checked) {
	missing := map[string]int{}
	var hits []BacktestHit

	scanned, err := b.store.ScanMessagesWithEvidence(ctx, job.TenantID, job.From, job.To,
		func(m store.ScannedMessage) error {
			var msg mdm.MessageDataModel
			if err := json.Unmarshal(m.MDM, &msg); err != nil {
				return nil // one unreadable row does not fail a run over a year of mail
			}

			opts := &mql.EvalOptions{Lists: b.lists, Registry: b.registry}
			var replay *mql.ReplayEnricher
			if checked.NeedsEnrichment() {
				replay = mql.NewReplay(snapshotOf(m.Evidence))
				opts.Enricher = replay
			}
			res := mql.Eval(ctx, checked, &msg, opts)

			switch res.Verdict {
			case mql.Match:
				job.Matched++
				if len(hits) < maxBacktestHits {
					hits = append(hits, BacktestHit{
						MessageID:  m.MessageID,
						ReceivedAt: m.ReceivedAt,
						Subject:    m.Subject,
						Sender:     m.SenderEmail,
						Verdict:    m.Verdict,
					})
				}
			case mql.Indeterminate:
				job.Undecided++
			}
			if replay != nil {
				for cap, n := range replay.Missed() {
					missing[cap] += n
				}
			}
			return nil
		})

	// What an analyst already thought of the messages this rule would have caught.
	// Done once at the end over the collected ids rather than per row: it is a
	// Postgres query and a scan is a columnar read, and mixing them per message turns
	// one query into a hundred thousand.
	if len(hits) > 0 {
		ids := make([]string, len(hits))
		for i, h := range hits {
			ids[i] = h.MessageID
		}
		if states, err := b.store.TriageFor(ctx, job.TenantID, ids); err == nil {
			for i := range hits {
				t, ok := states[hits[i].MessageID]
				if !ok {
					continue
				}
				hits[i].Triage = string(t.State)
				switch t.State {
				case store.StateUnreviewed:
					// Not a judgement, so not counted as one.
				case store.StateBenign:
					job.Reviewed++
					job.Benign++
				default:
					// Remediated, needs remediation, ignored: all of them are a
					// person having looked and not said "this was harmless".
					job.Reviewed++
					job.Confirmed++
				}
			}
		}
	}

	b.mu.Lock()
	now := time.Now().UTC()
	job.Scanned = int64(scanned)
	job.Results = hits
	if len(missing) > 0 {
		job.Missing = missing
	}
	job.Finished = &now
	job.State = "finished"
	if err != nil {
		job.State = "failed"
		job.Error = err.Error()
	}
	b.mu.Unlock()
}

// Get returns a job by id.
func (b *Backtester) Get(tenant, id string) (*BacktestJob, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	j, ok := b.jobs[id]
	if !ok || j.TenantID != tenant {
		return nil, false
	}
	return j, true
}

// List returns this tenant's runs, newest first.
func (b *Backtester) List(tenant string) []*BacktestJob {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []*BacktestJob{}
	for _, j := range b.jobs {
		if j.TenantID == tenant {
			out = append(out, j)
		}
	}
	for i := 0; i < len(out); i++ {
		for k := i + 1; k < len(out); k++ {
			if out[k].CreatedAt.After(out[i].CreatedAt) {
				out[i], out[k] = out[k], out[i]
			}
		}
	}
	return out
}
