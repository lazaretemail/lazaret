// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Whether a mailbox actually works.
//
// Configuring a mailbox and reaching it are different things, and until now the
// platform could only tell you the first. An admin who typed a password wrong, or
// whose provider wants an app password, or who left TLS on the wrong setting, had no
// way to find out except reading connector logs — and the settings page cheerfully
// showed the mailbox as though it were collecting mail.
//
// The store has always had somewhere to put this. NoteMailbox was written for it and
// had no callers at all: the mechanism existed, nothing reported into it, and the
// absence looked exactly like a mailbox that was working and had simply not seen any
// mail yet.
//
// # Why the connector reports rather than the engine testing
//
// The engine cannot reach the connector, deliberately: a connector that has to be
// reachable from the engine is a connector that needs an inbound path, and this one
// is meant to run behind whatever network someone already has. So the connector,
// which is the thing actually holding the socket, says how it went — on every
// connection attempt, not only when asked. That makes the status continuously true
// rather than true at the moment somebody pressed a button.

// mailboxHealth records a connector's report about one mailbox.
func (a *API) mailboxHealth(w http.ResponseWriter, r *http.Request) {
	var in struct {
		// Seen is how many messages this connector has handled since its last
		// report, added to the mailbox's running count.
		Seen int64 `json:"seen"`

		// Error is empty when the connector reached the mailbox.
		Error string `json:"error"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	id := r.PathValue("id")

	var reported error
	if in.Error != "" {
		reported = errors.New(in.Error)
	}
	switch err := a.store.NoteMailbox(ctx, tenant, id, in.Seen, reported); {
	case errors.Is(err, store.ErrNoMailbox):
		// A mismatched tenant and id is indistinguishable from a mailbox that
		// was deleted while a connector was mid-cycle, and both deserve the same
		// answer: nothing was written, and the caller is told so rather than
		// being allowed to believe otherwise.
		fail(w, http.StatusNotFound, err)
		return
	case err != nil:
		fail(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// recheckMailbox clears a mailbox's status so the next connector report repopulates
// it.
//
// Not a test in itself, and deliberately not pretending to be one: the engine has no
// socket to the provider and inventing one here would mean a second implementation
// of every connector, which would then be the one that disagreed. What this does is
// discard the last answer, so the page stops showing a stale "connected" from before
// a password was changed and shows "checking" until the connector says otherwise.
func (a *API) recheckMailbox(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	if err := a.store.ClearMailboxHealth(ctx, tenant, r.PathValue("id")); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
