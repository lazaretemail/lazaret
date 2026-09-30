// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"
)

// fakeMailbox is a mailbox with mail in it, deliberately not in time order — which
// is how IMAP hands them over.
type fakeMailbox struct {
	msgs    []RawMessage
	walked  []time.Time
	stopAt  int
	mu      sync.Mutex
	walkErr error
}

func (f *fakeMailbox) Walk(ctx context.Context, from, until time.Time, visit func(context.Context, RawMessage) error) error {
	if f.walkErr != nil {
		return f.walkErr
	}
	// A source that promises ascending order delivers ascending order; the
	// question under test is whether the runner preserves it and whether the
	// window is honoured.
	in := make([]RawMessage, 0, len(f.msgs))
	for _, m := range f.msgs {
		if m.ReceivedAt.Before(from) || !m.ReceivedAt.Before(until) {
			continue
		}
		in = append(in, m)
	}
	sortByTime(in)

	for i, m := range in {
		if f.stopAt > 0 && i >= f.stopAt {
			return nil
		}
		f.mu.Lock()
		f.walked = append(f.walked, m.ReceivedAt)
		f.mu.Unlock()
		if err := visit(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

// engineStub stands in for the engine, recording what the runner sent it.
type engineStub struct {
	mu        sync.Mutex
	ingested  []time.Time
	backfills []string
	skipRaw   []bool
	progress  []BackfillReport
	state     string
	verdict   string
	srv       *httptest.Server
}

func newEngineStub(t *testing.T, job *Backfill) (*Engine, *engineStub) {
	t.Helper()
	st := &engineStub{state: "running", verdict: "clean"}
	mux := http.NewServeMux()
	claimed := false

	mux.HandleFunc("POST /v0/mailboxes/{id}/backfill/claim", func(w http.ResponseWriter, r *http.Request) {
		if claimed || job == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		claimed = true
		json.NewEncoder(w).Encode(job)
	})
	mux.HandleFunc("POST /v0/backfills/{id}/progress", func(w http.ResponseWriter, r *http.Request) {
		var rep BackfillReport
		json.NewDecoder(r.Body).Decode(&rep)
		st.mu.Lock()
		st.progress = append(st.progress, rep)
		state := st.state
		st.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"id": job.ID, "state": state})
	})
	mux.HandleFunc("POST /v0/messages/ingest", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			BackfillID  string `json:"backfill_id"`
			SkipCustody bool   `json:"skip_custody"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		st.mu.Lock()
		st.backfills = append(st.backfills, in.BackfillID)
		st.skipRaw = append(st.skipRaw, in.SkipCustody)
		v := st.verdict
		st.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"verdict": v, "message_id": "m"})
	})
	// Any remediation route existing at all is a trap: the runner must never call
	// one, so reaching it fails the test rather than succeeding quietly.
	for _, p := range []string{"POST /v0/messages/{id}/actions", "GET /v0/mailboxes/{id}/remediations"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("the scan called %s — a retrospective scan must never act", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		})
	}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	st.srv = srv
	return &Engine{Address: srv.URL, Tenant: "default", Client: srv.Client()}, st
}

func msgsAcross(days int, base time.Time) []RawMessage {
	var out []RawMessage
	for i := 0; i < days; i++ {
		out = append(out, RawMessage{
			Raw:        []byte(fmt.Sprintf("Subject: day %d\r\n\r\nbody\r\n", i)),
			ReceivedAt: base.AddDate(0, 0, i),
			MailboxID:  "mb1",
		})
	}
	// Shuffled into the order a UID search would give: not chronological.
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt.After(out[j].ReceivedAt) })
	return out
}

// The property the whole design rests on: messages reach the engine oldest first.
//
// Sender profiles answer from events strictly before the message being judged, so
// processing order is belief order. Newest-first judges January against March, and
// every early message looks like a first contact.
func TestScanIngestsOldestFirst(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	box := &fakeMailbox{msgs: msgsAcross(10, base)}
	job := &Backfill{ID: "bf_1", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 30), State: "running"}
	e, _ := newEngineStub(t, job)

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatalf("runBackfill: %v", err)
	}

	box.mu.Lock()
	defer box.mu.Unlock()
	if len(box.walked) != 10 {
		t.Fatalf("walked %d messages, want 10", len(box.walked))
	}
	for i := 1; i < len(box.walked); i++ {
		if box.walked[i].Before(box.walked[i-1]) {
			t.Fatalf("message %d (%s) was processed after a later one (%s)",
				i, box.walked[i].Format(time.DateOnly), box.walked[i-1].Format(time.DateOnly))
		}
	}
}

// Every ingest is marked with the scan that found it, so a verdict reached weeks
// after delivery is never counted as a catch at the door.
func TestScanMarksEveryMessageAsHistorical(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	box := &fakeMailbox{msgs: msgsAcross(5, base)}
	job := &Backfill{ID: "bf_marked", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 30), State: "running"}
	e, st := newEngineStub(t, job)

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatal(err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.backfills) != 5 {
		t.Fatalf("ingested %d, want 5", len(st.backfills))
	}
	for i, id := range st.backfills {
		if id != "bf_marked" {
			t.Errorf("message %d was ingested with backfill_id %q", i, id)
		}
		if !st.skipRaw[i] {
			t.Errorf("message %d kept custody; the job did not ask for it", i)
		}
	}
}

// keep_raw asks for the bytes to be kept, so custody is not skipped.
func TestKeepRawIsHonoured(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	box := &fakeMailbox{msgs: msgsAcross(2, base)}
	job := &Backfill{ID: "bf_keep", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 30), State: "running", KeepRaw: true}
	e, st := newEngineStub(t, job)

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, skip := range st.skipRaw {
		if skip {
			t.Errorf("message %d skipped custody although keep_raw was set", i)
		}
	}
}

// A malicious verdict on old mail is counted and nothing else. The stub fails the
// test if any remediation route is touched.
func TestMaliciousHistoricalMessageIsNotActedOn(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	box := &fakeMailbox{msgs: msgsAcross(4, base)}
	job := &Backfill{ID: "bf_bad", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 30), State: "running"}
	e, st := newEngineStub(t, job)
	st.verdict = "malicious"

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatal(err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	var flagged int64
	for _, p := range st.progress {
		flagged += p.Flagged
	}
	if flagged != 4 {
		t.Errorf("flagged = %d, want 4 — findings must still be counted", flagged)
	}
}

// Cancelling a running scan stops it, and it finds out through its next progress
// report rather than needing a channel of its own.
func TestCancellationStopsTheWalk(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	box := &fakeMailbox{msgs: msgsAcross(200, base)}
	job := &Backfill{ID: "bf_cancel", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 400), State: "running"}
	e, st := newEngineStub(t, job)
	st.state = "cancelled"

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatalf("a cancelled scan should stop cleanly, got %v", err)
	}

	box.mu.Lock()
	walked := len(box.walked)
	box.mu.Unlock()
	if walked >= 200 {
		t.Errorf("walked %d of 200 messages; cancellation did not stop it", walked)
	}
	if walked > backfillBatch*2 {
		t.Errorf("walked %d messages before noticing; a batch is %d", walked, backfillBatch)
	}
}

// Resuming starts from the cursor, not the beginning. Without this a scan
// interrupted at day 80 of 90 would re-read eighty days of mail.
func TestResumeStartsFromTheCursor(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	cursor := base.AddDate(0, 0, 6)
	box := &fakeMailbox{msgs: msgsAcross(10, base)}
	job := &Backfill{ID: "bf_resume", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 30), State: "running", Cursor: &cursor}
	e, _ := newEngineStub(t, job)

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatal(err)
	}

	box.mu.Lock()
	defer box.mu.Unlock()
	for _, at := range box.walked {
		if at.Before(cursor) {
			t.Errorf("re-read %s, which is before the cursor %s",
				at.Format(time.DateOnly), cursor.Format(time.DateOnly))
		}
	}
	if len(box.walked) == 0 {
		t.Error("resumed and read nothing")
	}
}

// The cursor only ever moves forward, so a late progress report from a restarted
// connector cannot rewind a scan another pass already took further.
func TestProgressCursorIsTheLatestMessageSeen(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	box := &fakeMailbox{msgs: msgsAcross(60, base)}
	job := &Backfill{ID: "bf_cursor", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 90), State: "running"}
	e, st := newEngineStub(t, job)

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatal(err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	var last time.Time
	for i, p := range st.progress {
		if p.Cursor.Before(last) {
			t.Errorf("progress report %d moved the cursor backwards: %s after %s",
				i, p.Cursor.Format(time.DateOnly), last.Format(time.DateOnly))
		}
		if !p.Cursor.IsZero() {
			last = p.Cursor
		}
	}
}

// Messages outside the window are not touched, however the provider answers a
// day-granularity search.
func TestWindowIsHonouredExactly(t *testing.T) {
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	box := &fakeMailbox{msgs: msgsAcross(30, base)}
	from, until := base.AddDate(0, 0, 10), base.AddDate(0, 0, 20)
	job := &Backfill{ID: "bf_window", MailboxID: "mb1", Since: from, Until: until, State: "running"}
	e, _ := newEngineStub(t, job)

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatal(err)
	}

	box.mu.Lock()
	defer box.mu.Unlock()
	for _, at := range box.walked {
		if at.Before(from) || !at.Before(until) {
			t.Errorf("read %s, outside [%s, %s)", at.Format(time.DateOnly),
				from.Format(time.DateOnly), until.Format(time.DateOnly))
		}
	}
	if len(box.walked) != 10 {
		t.Errorf("read %d messages, want the 10 inside the window", len(box.walked))
	}
}

// A scan must report progress while it is running, not only when it ends.
//
// Progress used to flush every backfillBatch (25) messages and nothing else. One
// message is not cheap — the whole rule set, enrichment, link analysis — and on
// real mail that measured around fifteen seconds each, so the first number reached
// the console about seven minutes in. Until then the history page showed
// examined=0, which is indistinguishable from a scan that never started.
func TestProgressIsReportedBeforeTheBatchFills(t *testing.T) {
	restore := progressEvery
	progressEvery = 10 * time.Millisecond
	t.Cleanup(func() { progressEvery = restore })

	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	const total = 6 // deliberately fewer than backfillBatch
	box := &fakeMailbox{msgs: msgsAcross(total, base)}
	job := &Backfill{ID: "bf_slow", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 30), State: "running"}
	e, st := newEngineStub(t, job)

	// Analysis that takes long enough for the clock to trip between messages.
	e.Client.Transport = slowRoundTripper{base: e.Client.Transport, delay: 25 * time.Millisecond}

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatalf("runBackfill: %v", err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if len(st.progress) < 2 {
		t.Fatalf("progress was reported %d time(s); a slow scan must report as it goes, "+
			"not once at the end", len(st.progress))
	}

	// Some report has to arrive while there is still work left, or "as it goes" is
	// only true in the sense that the last batch is also a batch.
	var seen int64
	mid := false
	for _, p := range st.progress {
		seen += p.Examined
		if seen > 0 && seen < total {
			mid = true
		}
	}
	if !mid {
		t.Error("every report landed at the end; nothing was visible mid-scan")
	}

	// The counters are deltas that the engine adds up, so resetting the batch after
	// each flush must not lose or double-count anything.
	if seen != total {
		t.Errorf("reports summed to %d examined, want %d", seen, total)
	}
}

// A mailbox fast enough to fill a batch still batches, rather than making a request
// per message.
func TestFastScanStillBatches(t *testing.T) {
	restore := progressEvery
	progressEvery = time.Hour // the clock must not be what trips here
	t.Cleanup(func() { progressEvery = restore })

	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	box := &fakeMailbox{msgs: msgsAcross(backfillBatch+5, base)}
	job := &Backfill{ID: "bf_fast", MailboxID: "mb1", Since: base.AddDate(0, 0, -1),
		Until: base.AddDate(0, 0, 90), State: "running"}
	e, st := newEngineStub(t, job)

	if err := runBackfill(context.Background(), e, job, box); err != nil {
		t.Fatalf("runBackfill: %v", err)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	// One flush at 25, one for the remainder, one for the terminal state.
	if len(st.progress) > 4 {
		t.Errorf("%d progress reports for %d messages; batching stopped working",
			len(st.progress), backfillBatch+5)
	}
}

type slowRoundTripper struct {
	base  http.RoundTripper
	delay time.Duration
}

func (s slowRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	base := s.base
	if base == nil {
		base = http.DefaultTransport
	}
	// Only the ingest call is slow; progress reports stay fast, as they are in life.
	if r.URL.Path == "/v0/messages/ingest" {
		time.Sleep(s.delay)
	}
	return base.RoundTrip(r)
}
