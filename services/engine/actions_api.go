// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lazaretemail/lazaret/actions"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// Configuring what detections do.
//
// Two levels, and keeping them apart is the point. An administrator first decides
// what their organisation's actions *are* — "Auto-trash", "Move to Junk", "Tell the
// SOC channel" — and then attaches those to rules. Without the indirection, every
// one of a thousand rules would carry its own copy of the decision, and changing
// where junk goes would be a thousand edits.

// actionTypes lists what this platform can do, for the form that creates one.
func (a *API) actionTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"types": actions.Types})
}

// listActions returns the configured actions.
func (a *API) listActions(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	out, err := a.store.ConfiguredActions(store.WithTenant(r.Context(), tenant), tenant)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if out == nil {
		out = []store.ConfiguredAction{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": out})
}

// saveAction creates or updates one.
func (a *API) saveAction(w http.ResponseWriter, r *http.Request) {
	var in actions.Instance
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if id := r.PathValue("id"); id != "" {
		in.ID = id
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	saved, err := a.store.SaveAction(ctx, tenant, in, callerName(r))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	// Recorded: creating an action that quarantines mail is a change worth being
	// able to attribute later.
	_ = a.store.RecordAction(ctx, tenant, "", "action-configured:"+saved.Label, callerName(r), "")
	writeJSON(w, http.StatusOK, saved)
}

// deleteAction removes one, and with it every rule's use of it.
func (a *API) deleteAction(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	id := r.PathValue("id")

	existing, err := a.store.ActionByID(ctx, tenant, id)
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	if err := a.store.DeleteAction(ctx, tenant, id); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	_ = a.store.RecordAction(ctx, tenant, "", "action-removed:"+existing.Label, callerName(r), "")
	w.WriteHeader(http.StatusNoContent)
}

// ruleActions reports which actions each rule has.
func (a *API) ruleActions(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	out, err := a.store.RuleActions(store.WithTenant(r.Context(), tenant), tenant)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

// attachActions adds or removes actions across many rules at once.
//
// One endpoint for both because the interface is one control — a set of checkboxes
// with Add and Remove — and splitting it would mean the dashboard deciding which
// verb to use for a gesture the user thinks of as one thing.
func (a *API) attachActions(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RuleIDs   []string `json:"rule_ids"`
		ActionIDs []string `json:"action_ids"`
		Remove    bool     `json:"remove"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if len(in.RuleIDs) == 0 || len(in.ActionIDs) == 0 {
		fail(w, http.StatusBadRequest, errors.New("name at least one rule and one action"))
		return
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	var err error
	if in.Remove {
		err = a.store.DetachActions(ctx, tenant, in.RuleIDs, in.ActionIDs)
	} else {
		err = a.store.AttachActions(ctx, tenant, in.RuleIDs, in.ActionIDs, callerName(r))
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	verb := "attached"
	if in.Remove {
		verb = "detached"
	}
	_ = a.store.RecordAction(ctx, tenant, "",
		"rule-actions-"+verb, callerName(r), "")
	w.WriteHeader(http.StatusNoContent)
}
