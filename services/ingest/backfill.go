// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Walking a mailbox's existing mail.
//
// An operator installing this on Monday wants two things that watching for new mail
// cannot give them: what already got through, and enough history for the rules that
// ask "have we heard from this sender before" to mean anything. Both come from
// reading what is already in the mailbox.
//
// Two properties of this code matter more than the rest of it, and both are about
// restraint.
//
// # It never acts
//
// The verdict comes back and is counted and then discarded. No quarantine, no
// removal, no banner — not because a retrospective verdict is untrustworthy, but
// because the message was delivered weeks ago and whatever it was going to do it has
// done. Deleting ninety days of somebody's mail on the strength of a rule sweep would
// be a far worse incident than anything the sweep found, and the way to be sure that
// cannot happen is for this file to contain no code that could do it.
//
// # It walks oldest-first
//
// Sender profiles answer from events strictly before the message being judged, so a
// message is evaluated against whatever history had been stored by the time it was
// processed. Oldest-first rebuilds that history in the order it happened, and each
// message is judged on what was genuinely known before it. Newest-first judges
// January against March: the profile is read before it is written, every early
// message looks like a first contact, and the verdicts come out confidently wrong.

// Backfill is one claimed retrospective scan, as the engine describes it.
type Backfill struct {
	ID        string     `json:"id"`
	MailboxID string     `json:"mailbox_id"`
	Since     time.Time  `json:"since"`
	Until     time.Time  `json:"until"`
	State     string     `json:"state"`
	Cursor    *time.Time `json:"cursor,omitempty"`
	KeepRaw   bool       `json:"keep_raw"`
}

// Done reports a scan that should stop, including one an operator cancelled while
// it was running.
func (b *Backfill) Done() bool {
	switch b.State {
	case "done", "failed", "cancelled":
		return true
	}
	return false
}

// From is where the walk resumes: the cursor if there is one, the window start
// otherwise.
func (b *Backfill) From() time.Time {
	if b.Cursor != nil && b.Cursor.After(b.Since) {
		return *b.Cursor
	}
	return b.Since
}

// HistoricalSource is a connector that can walk its mailbox's existing mail.
//
// Separate from Source deliberately. Watching for new mail and sweeping old mail are
// different operations with different risks, and a connector that has not
// implemented the second should not accidentally inherit a default that guesses.
type HistoricalSource interface {
	// Walk delivers messages received in [from, until) in ascending time order,
	// calling visit for each. Returning an error from visit stops the walk.
	Walk(ctx context.Context, from, until time.Time, visit func(context.Context, RawMessage) error) error
}

// backfillBatch is how much work is repeated if the connector dies. Small enough
// that a crash costs little, large enough not to make a request per message.
const backfillBatch = 25

// progressEvery bounds how long the console can show a stale number.
//
// Reporting only every backfillBatch messages tied the refresh rate to analysis
// throughput, and one message is not cheap: the full rule set, enrichment, link
// analysis. Measured on real mail that is around fifteen seconds each, so the first
// update arrived roughly seven minutes after the scan started and an operator
// watching the page had no way to tell a working scan from a wedged one.
//
// Whichever comes first, so a fast mailbox still batches and a slow one still moves.
//
// A var, not a const, so a test can shorten it: proving the clock path with the
// real three seconds would mean a three-second test.
var progressEvery = 3 * time.Second

// RunBackfills claims and runs scans for one mailbox until the context ends.
func RunBackfills(ctx context.Context, e *Engine, mailboxID string, src HistoricalSource, poll time.Duration) {
	if poll <= 0 {
		poll = 30 * time.Second
	}
	for {
		b, err := e.ClaimBackfill(ctx, mailboxID)
		switch {
		case err != nil:
			log.Printf("backfill: claiming for %s: %v", mailboxID, err)
		case b != nil:
			if err := runBackfill(ctx, e, b, src); err != nil && ctx.Err() == nil {
				log.Printf("backfill %s: %v", b.ID, err)
				_, _ = e.BackfillProgress(context.WithoutCancel(ctx), b.ID, BackfillReport{
					State: "failed", Error: err.Error(), Cursor: b.From(),
				})
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}
}

// runBackfill walks one scan to completion.
func runBackfill(ctx context.Context, e *Engine, b *Backfill, src HistoricalSource) error {
	log.Printf("backfill %s: scanning %s from %s to %s",
		b.ID, b.MailboxID, b.Since.Format(time.DateOnly), b.Until.Format(time.DateOnly))

	var (
		batch     BackfillReport
		batchMu   sync.Mutex
		stopped   bool
		lastSeen  = b.From()
		lastFlush = time.Now()
	)

	flush := func(ctx context.Context) error {
		// Under the same lock the shards write through: the counters are shared
		// state now, and reading them while a shard increments is a race that
		// would silently lose progress.
		batchMu.Lock()
		if batch.Examined == 0 {
			batchMu.Unlock()
			return nil
		}
		batch.Cursor = lastSeen
		snapshot := batch
		batch = BackfillReport{}
		lastFlush = time.Now()
		batchMu.Unlock()

		state, err := e.BackfillProgress(ctx, b.ID, snapshot)
		if err != nil {
			return err
		}
		// Cancellation reaches us here rather than through a separate channel:
		// the operator sets the state and the next progress report tells us.
		if state != nil && state.Done() {
			stopped = true
		}
		return nil
	}

	// Sharded by sender, so messages that cannot affect each other's profile are
	// analysed together while those that can stay in order. See ordered.go.
	pool := newOrderedPool(scanConcurrency)

	err := src.Walk(ctx, b.From(), b.Until, func(ctx context.Context, msg RawMessage) error {
		if stopped || ctx.Err() != nil {
			return errStopWalk
		}

		pool.Submit(senderKey(msg.Raw), func() { scanOne(ctx, e, b, msg, &batch, &batchMu, &lastSeen) })

		batchMu.Lock()
		due := batch.Examined >= backfillBatch || time.Since(lastFlush) >= progressEvery
		batchMu.Unlock()
		if due {
			return flush(ctx)
		}
		return nil
	})
	pool.Wait()

	if err != nil && err != errStopWalk {
		_ = flush(context.WithoutCancel(ctx))
		return err
	}
	if err := flush(context.WithoutCancel(ctx)); err != nil {
		return err
	}
	if stopped {
		log.Printf("backfill %s: stopped", b.ID)
		return nil
	}

	// Finished: the cursor goes to the end of the window so a resumed scan does
	// not re-walk the tail.
	_, err = e.BackfillProgress(context.WithoutCancel(ctx), b.ID, BackfillReport{
		State: "done", Cursor: b.Until,
	})
	log.Printf("backfill %s: complete", b.ID)
	return err
}

// errStopWalk unwinds a walk without making it look like a failure.
var errStopWalk = fmt.Errorf("backfill: stopping")

// BackfillReport is one batch of progress.
type BackfillReport struct {
	Examined   int64     `json:"examined"`
	Ingested   int64     `json:"ingested"`
	Duplicates int64     `json:"duplicates"`
	Flagged    int64     `json:"flagged"`
	Failures   int64     `json:"failures"`
	Cursor     time.Time `json:"cursor"`
	Error      string    `json:"error,omitempty"`
	State      string    `json:"state,omitempty"`
}

// ClaimBackfill asks the engine for work on a mailbox. A nil result with no error
// means there is nothing to do.
func (e *Engine) ClaimBackfill(ctx context.Context, mailboxID string) (*Backfill, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.Address+"/v0/mailboxes/"+mailboxID+"/backfill/claim", nil)
	if err != nil {
		return nil, err
	}
	e.authorize(req)

	resp, err := e.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine: claiming a scan: %s", resp.Status)
	}
	var b Backfill
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// BackfillProgress reports a batch and returns the scan's current state, which is
// how cancellation reaches a running walk.
func (e *Engine) BackfillProgress(ctx context.Context, id string, rep BackfillReport) (*Backfill, error) {
	body, err := json.Marshal(rep)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.Address+"/v0/backfills/"+id+"/progress", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	e.authorize(req)

	resp, err := e.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine: reporting progress: %s", resp.Status)
	}
	var b Backfill
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// IngestHistorical records a message a scan found, marked as such.
func (e *Engine) IngestHistorical(ctx context.Context, msg RawMessage, backfillID string, skipCustody bool) (*Verdict, error) {
	body, err := json.Marshal(map[string]any{
		"raw_message":  base64.StdEncoding.EncodeToString(msg.Raw),
		"tenant_id":    e.Tenant,
		"mailbox_id":   msg.MailboxID,
		"backfill_id":  backfillID,
		"skip_custody": skipCustody,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		e.Address+"/v0/messages/ingest", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	e.authorize(req)

	resp, err := e.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine: %s", resp.Status)
	}
	var v Verdict
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// sortByTime puts a batch of messages in the order they were received.
//
// The walk promises ascending order and the providers mostly give it, but IMAP's
// SEARCH returns UIDs and a UID is only approximately chronological — a message
// moved between folders gets a new one. Sorting a fetched batch by its real
// internal date costs nothing and removes the "mostly".
func sortByTime(msgs []RawMessage) {
	sort.SliceStable(msgs, func(i, j int) bool {
		return msgs[i].ReceivedAt.Before(msgs[j].ReceivedAt)
	})
}

// scanConcurrency is how many messages a retrospective scan analyses at once.
//
// Bounded by the engine anyway — it admits a fixed number and queues the rest —
// so this is about not queueing pointlessly rather than about throughput. Four
// shards give most of the overlap a real mailbox can use, because consecutive
// messages are nearly always from different senders.
const scanConcurrency = 4

// scanOne analyses one historical message and records what happened.
//
// The counters are shared across shards, so they are taken under a lock. That is
// cheap next to an analysis and it is the only shared state: everything else a
// message touches belongs to the engine.
func scanOne(ctx context.Context, e *Engine, b *Backfill, msg RawMessage,
	batch *BackfillReport, mu *sync.Mutex, lastSeen *time.Time) {

	v, err := e.IngestHistorical(ctx, msg, b.ID, !b.KeepRaw)

	mu.Lock()
	defer mu.Unlock()

	batch.Examined++
	// The message's own time, not now. It is what the cursor records and what
	// makes resuming land in the right place.
	//
	// Taken as the maximum rather than the last seen, because shards finish out of
	// step with each other: a resumed scan must not skip a message that an earlier
	// shard had not finished when a later one recorded its own time.
	if !msg.ReceivedAt.IsZero() && msg.ReceivedAt.After(*lastSeen) {
		*lastSeen = msg.ReceivedAt
	}

	switch {
	case err != nil:
		batch.Failures++
		batch.Error = err.Error()
	case v == nil:
		batch.Failures++
	case v.Duplicate:
		// Already known, which is the normal case where a scan window overlaps
		// mail the live connector already saw.
		batch.Duplicates++
	default:
		batch.Ingested++
		if v.Verdict == "malicious" {
			batch.Flagged++
		}
	}

	// The verdict is deliberately not acted on. See the file comment: this message
	// was delivered weeks ago, and a sweep is not a delivery decision. There is
	// intentionally no branch here that removes anything.
}
