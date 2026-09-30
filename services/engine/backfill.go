// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Retrospective scanning: evaluating mail that was already delivered.
//
// Two things an operator wants on the first day, and neither is served by watching
// for new mail. The first is finding what got through before the platform existed —
// a credential phish from three weeks ago is still a credential phish, and the
// account it took is still taken. The second is that a deployment with no history
// answers "have we heard from this sender before" with "no" for every sender alive,
// so the profile-backed rules are dead weight and the learned model has nothing to
// learn from. Ninety days of mail fixes both.
//
// # What a retrospective verdict is not
//
// It is not a delivery decision. The message was delivered, weeks ago, and whatever
// was going to happen has happened. So a scan reports and never acts: no quarantine,
// no removal, no banner. That is enforced in the connector, which simply does not
// look at the verdict it gets back, and it is the single most important property
// here — a backfill that decided to quarantine ninety days of mail would be a far
// worse incident than anything it found.
//
// # Why the walk is oldest-first
//
// Sender profiles answer from events strictly before the message being judged, so a
// message is evaluated against whatever history was stored at the moment it was
// processed. Walking oldest-first rebuilds that history in the order it actually
// happened, and every message is judged on what was genuinely known before it.
// Walking newest-first judges January's mail against March's knowledge: the
// profiles are read before they are written, every early message looks like a first
// contact, and the resulting verdicts are worse than useless because they look
// exactly like real ones.

// maxBackfillDays bounds a scan window.
//
// Not a technical limit — the walk is incremental and resumable, and a year would
// work. It is a limit on how much mail one request can commit a connector to
// fetching, since the request is cheap to make and the work is not.
const maxBackfillDays = 400

// staleClaim is how long a claimed scan may go quiet before another connector may
// take it. Long enough to survive a slow batch; short enough that a connector which
// died does not strand the job until someone notices.
const staleClaim = 15 * time.Minute

// createBackfill starts a retrospective scan.
func (a *API) createBackfill(w http.ResponseWriter, r *http.Request) {
	var in struct {
		MailboxID string `json:"mailbox_id"`
		// Days is the convenient form — "the last 90 days" — and Since/Until the
		// precise one. Days wins if both are given.
		Days    int        `json:"days"`
		Since   *time.Time `json:"since"`
		Until   *time.Time `json:"until"`
		KeepRaw bool       `json:"keep_raw"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	if !a.mailboxExists(ctx, tenant, in.MailboxID) {
		fail(w, http.StatusBadRequest, errors.New("no such mailbox"))
		return
	}

	until := time.Now().UTC()
	if in.Until != nil {
		until = in.Until.UTC()
	}
	var since time.Time
	switch {
	case in.Days > 0:
		since = until.AddDate(0, 0, -in.Days)
	case in.Since != nil:
		since = in.Since.UTC()
	default:
		fail(w, http.StatusBadRequest, errors.New("give either days or since"))
		return
	}

	if until.Sub(since) > maxBackfillDays*24*time.Hour {
		fail(w, http.StatusBadRequest, errors.New("that window is longer than this will scan in one job; split it"))
		return
	}

	b, err := a.store.CreateBackfill(ctx, store.Backfill{
		TenantID:  tenant,
		MailboxID: in.MailboxID,
		Since:     since,
		Until:     until,
		KeepRaw:   in.KeepRaw,
		CreatedBy: callerName(r),
	})
	switch {
	case errors.Is(err, store.ErrBackfillExists):
		fail(w, http.StatusConflict, err)
		return
	case err != nil:
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, b)
}

// listBackfills reports scans and their progress.
func (a *API) listBackfills(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	out, err := a.store.Backfills(store.WithTenant(r.Context(), tenant), tenant)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backfills": out})
}

// getBackfill reports one scan.
func (a *API) getBackfill(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	b, err := a.store.BackfillByID(store.WithTenant(r.Context(), tenant), tenant, r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// cancelBackfill stops a scan. What it already ingested stays: those messages were
// evaluated and recorded, and throwing them away would discard exactly the history
// the scan existed to build.
func (a *API) cancelBackfill(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	if err := a.store.FinishBackfill(ctx, tenant, r.PathValue("id"), store.BackfillCancelled, ""); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	b, _ := a.store.BackfillByID(ctx, tenant, r.PathValue("id"))
	writeJSON(w, http.StatusOK, b)
}

// claimBackfill hands a connector the work for one mailbox.
func (a *API) claimBackfill(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	b, err := a.store.ClaimBackfill(ctx, tenant, r.PathValue("id"), callerName(r), staleClaim)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if b == nil {
		// Nothing to do is not an error; a connector asks on a timer.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// backfillProgress records a batch and, when the connector says so, the end.
func (a *API) backfillProgress(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Examined   int64     `json:"examined"`
		Ingested   int64     `json:"ingested"`
		Duplicates int64     `json:"duplicates"`
		Flagged    int64     `json:"flagged"`
		Failures   int64     `json:"failures"`
		Cursor     time.Time `json:"cursor"`
		Error      string    `json:"error"`

		// State, when the connector is finishing: done, failed or paused.
		State string `json:"state"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	id := r.PathValue("id")

	if err := a.store.BackfillProgress(ctx, tenant, id, store.BackfillDelta{
		Examined: in.Examined, Ingested: in.Ingested, Duplicates: in.Duplicates,
		Flagged: in.Flagged, Failures: in.Failures, Cursor: in.Cursor, LastError: in.Error,
	}); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	if in.State != "" {
		if err := a.store.FinishBackfill(ctx, tenant, id, in.State, in.Error); err != nil {
			fail(w, http.StatusBadRequest, err)
			return
		}
	}

	b, err := a.store.BackfillByID(ctx, tenant, id)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	// The connector reads the state back to learn about cancellation: an operator
	// who stops a scan does so here, and the connector finds out on its next
	// progress report rather than needing to be told.
	writeJSON(w, http.StatusOK, b)
}

// mailboxExists checks the scan target before committing a connector to a walk of it.
func (a *API) mailboxExists(ctx context.Context, tenant, id string) bool {
	boxes, err := a.store.Mailboxes(ctx, tenant, false)
	if err != nil {
		return false
	}
	for _, m := range boxes {
		if m.ID == id {
			return true
		}
	}
	return false
}

// callerName identifies who asked, for the audit trail on a job that will read
// every message in someone's mailbox.
func callerName(r *http.Request) string {
	c := CallerFrom(r.Context())
	if c == nil {
		return ""
	}
	// A token's name, so the trail distinguishes "an analyst started this scan"
	// from "the IMAP connector claimed it".
	switch {
	case c.Service != "":
		return c.Service
	case c.Email != "":
		return c.Email
	default:
		return c.UserID
	}
}
