// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/lazaretemail/lazaret/orgconfig"
	"github.com/lazaretemail/lazaret/services/engine/store"
	yaml "go.yaml.in/yaml/v3"
)

// Configuration endpoints: named lists, mailboxes, and the organisation.
//
// All three used to be files or flags. They are configuration a person changes while
// the system is running — a new mailbox, a domain wrongly on a blocklist, a VIP who
// joined this week — and requiring a restart and a deploy for each of those is how a
// security product stops being maintained.

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

func (a *API) listLists(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	configs, err := a.store.Lists(r.Context(), tenant)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// Which lists the loaded rules actually use, and how many depend on each. A
	// settings page that lists 32 names alphabetically tells an operator nothing
	// about which one to fix first.
	usage := map[string]int{}
	for _, c := range a.pipeline.rules().Compiled() {
		for _, l := range c.Checked.Lists {
			usage[l]++
		}
	}

	type row struct {
		store.ListConfig
		RefreshSeconds int  `json:"refresh_every_seconds"`
		RulesUsing     int  `json:"rules_using"`
		Resolvable     bool `json:"resolvable"`
	}
	out := make([]row, 0, len(configs))
	for _, c := range configs {
		// The live count, not the cached one. Only fetched and feed lists have a
		// cache row, so reporting EntryCount alone showed every embedded, org and
		// history list as holding nothing — which reads as broken rather than as
		// "this one is not stored in the cache table".
		_, live := a.pipeline.listSample(c.Name, 0)
		if live > 0 {
			c.EntryCount = int64(live)
		}
		out = append(out, row{
			ListConfig:     c,
			RefreshSeconds: int(c.RefreshEvery.Seconds()),
			RulesUsing:     usage[c.Name],
			Resolvable:     a.pipeline.listsKnown(c.Name),
		})
	}

	// Anything a rule references that has no configuration at all. Should be empty;
	// if it is not, a rule is silently unanswerable and nobody would otherwise know.
	var unconfigured []string
	known := map[string]bool{}
	for _, c := range configs {
		known[c.Name] = true
	}
	for name := range usage {
		if !known[name] {
			unconfigured = append(unconfigured, name)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"lists":        out,
		"unconfigured": unconfigured,
	})
}

func (a *API) getList(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	name := r.PathValue("name")

	cfg, err := a.store.ListByName(r.Context(), tenant, name)
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	overrides, _ := a.store.Overrides(r.Context(), tenant, name)
	if overrides == nil {
		overrides = []store.ListOverride{}
	}

	// A sample rather than the whole thing: tranco_1m has a million entries and
	// nobody is reading them in a browser.
	sample, total := a.pipeline.listSample(name, 50)

	writeJSON(w, http.StatusOK, map[string]any{
		"list": cfg, "overrides": overrides,
		"refresh_every_seconds": int(cfg.RefreshEvery.Seconds()),
		"sample":                sample, "resolved_count": total,
		"resolvable": a.pipeline.listsKnown(name),
	})
}

func (a *API) updateList(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled      *bool   `json:"enabled"`
		URL          *string `json:"url"`
		AuthHeader   *string `json:"auth_header"`
		RefreshHours *int    `json:"refresh_hours"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	var every *time.Duration
	if in.RefreshHours != nil {
		d := time.Duration(*in.RefreshHours) * time.Hour
		every = &d
	}
	if err := a.store.UpdateList(r.Context(), a.tenantOf(r), r.PathValue("name"),
		in.Enabled, in.URL, in.AuthHeader, every); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.lists.Rebuild(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *API) addListEntry(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Value string `json:"value"`
		Kind  string `json:"kind"`
		Note  string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if in.Kind == "" {
		in.Kind = "include"
	}
	by := CallerFrom(r.Context()).Actor()
	if err := a.store.AddOverride(r.Context(), a.tenantOf(r), r.PathValue("name"),
		in.Value, in.Kind, in.Note, by); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := a.lists.Rebuild(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "added", "by": by})
}

func (a *API) removeListEntry(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind := q.Get("kind")
	if kind == "" {
		kind = "include"
	}
	if err := a.store.RemoveOverride(r.Context(), a.tenantOf(r), r.PathValue("name"),
		q.Get("value"), kind); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.lists.Rebuild(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// refreshList downloads a list now rather than at its next scheduled time.
func (a *API) refreshList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg, err := a.store.ListByName(r.Context(), a.tenantOf(r), name)
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	if cfg.Source != store.SourceFetch && cfg.Source != store.SourceFeed {
		fail(w, http.StatusBadRequest, errors.New("only fetch and feed lists are downloaded"))
		return
	}

	// Detached: tranco is 21MB and an HTTP request should not wait on it.
	go func() {
		ctx, cancel := contextWithTimeout(20 * time.Minute)
		defer cancel()
		a.lists.RefreshNow(ctx, *cfg)
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "refreshing"})
}

// ---------------------------------------------------------------------------
// Mailboxes
// ---------------------------------------------------------------------------

func (a *API) listMailboxes(w http.ResponseWriter, r *http.Request) {
	// Never with secrets. A credential readable through an HTTP endpoint is one XSS
	// away from being taken; the connector reads them from the database directly.
	boxes, err := a.store.Mailboxes(r.Context(), a.tenantOf(r), false)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if boxes == nil {
		boxes = []store.Mailbox{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mailboxes": boxes})
}

// mailboxSecrets is how a connector gets the credentials it needs to log in.
//
// # Service tokens only, never a browser session
//
// The ordinary mailbox endpoint never returns a secret, on the reasoning that a
// credential readable over HTTP is one XSS away from being taken. That reasoning is
// about *browsers*: the attack needs a session cookie the browser will attach on its
// own. So this endpoint refuses anything that is not an API token, which a browser
// does not hold and a script running in one cannot obtain from the dashboard.
//
// The alternative was to give the connector its own Postgres connection and the
// decryption key. That was rejected because it makes the ingest service a second
// writer against a schema the engine owns, and spreads the key to a second process
// to avoid an endpoint that can be restricted to a credential browsers do not carry.
//
// Every read is written to the audit log, because a credential fetch is exactly the
// event worth being able to reconstruct later.
func (a *API) mailboxSecrets(w http.ResponseWriter, r *http.Request) {
	caller := CallerFrom(r.Context())
	if caller == nil || caller.Service == "" {
		fail(w, http.StatusForbidden, errors.New("this endpoint is for service tokens; a signed-in session cannot read mailbox credentials"))
		return
	}
	boxes, err := a.store.Mailboxes(r.Context(), a.tenantOf(r), true)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if boxes == nil {
		boxes = []store.Mailbox{}
	}
	_ = a.store.RecordAction(r.Context(), a.tenantOf(r), "",
		"mailbox-secrets-read", fmt.Sprintf("%d mailbox(es)", len(boxes)), caller.Actor())
	writeJSON(w, http.StatusOK, map[string]any{"mailboxes": boxes})
}

func (a *API) saveMailbox(w http.ResponseWriter, r *http.Request) {
	var m store.Mailbox
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&m); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	m.TenantID = a.tenantOf(r)

	saved, err := a.store.SaveMailbox(r.Context(), m)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	// A new mailbox changes $recipient_emails, which 45 rules use.
	if err := a.lists.Rebuild(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}

func (a *API) deleteMailbox(w http.ResponseWriter, r *http.Request) {
	if err := a.store.DeleteMailbox(r.Context(), a.tenantOf(r), r.PathValue("id")); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	_ = a.lists.Rebuild(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// ---------------------------------------------------------------------------
// Organisation
// ---------------------------------------------------------------------------

func (a *API) getOrg(w http.ResponseWriter, r *http.Request) {
	raw, err := a.store.OrgConfig(r.Context(), a.tenantOf(r))
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	w.Write(raw)
}

// updateOrg replaces the organisation configuration.
//
// type.inbound is defined against the verified domains here, and 145 rules are gated
// on it, so this is the single most consequential setting in the product — which is
// why it takes admin and why the list rebuild is synchronous: an operator who adds a
// domain should see the effect on the next message, not after a restart.
func (a *API) updateOrg(w http.ResponseWriter, r *http.Request) {
	body, err := readAll(r, 1<<20)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	org, err := parseOrg(body)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	tenant := a.tenantOf(r)
	if err := a.store.EnsureTenant(r.Context(), tenant, tenant, body); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	a.pipeline.setOrg(org)
	if err := a.lists.SetOrg(r.Context(), org); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "updated", "domains": len(org.Domains), "vips": len(org.VIPs),
	})
}

// contextWithTimeout detaches a background refresh from the request that asked for it.
// A download of tranco is 21MB and outlives the HTTP call by a long way.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func readAll(r *http.Request, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, limit))
}

// parseOrg accepts the organisation config as JSON or YAML, because an operator
// pasting the orgconfig.yaml they already have should not have to convert it first.
func parseOrg(body []byte) (*orgconfig.Config, error) {
	var cfg orgconfig.Config
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("could not read the configuration: %w", err)
	}
	cfg.Normalize()
	if len(cfg.Domains) == 0 {
		// Refused rather than accepted quietly. type.inbound is defined against these
		// and gates 145 rules; an empty set means every message has an unknown
		// direction and most of the corpus reports indeterminate.
		return nil, errors.New("at least one verified domain is required: " +
			"message direction is defined against them, and 145 rules depend on it")
	}
	return &cfg, nil
}

// ---------------------------------------------------------------------------
// The remediation queue
// ---------------------------------------------------------------------------

// claimRemediations hands a connector the work waiting for one of its mailboxes.
//
// Service tokens only, like the credential endpoint and for a stronger reason: the
// response to a restore carries the whole original message, malicious content and
// all. That is the point — it is what gets put back — but it is not something a
// browser should ever be able to fetch.
func (a *API) claimRemediations(w http.ResponseWriter, r *http.Request) {
	caller := CallerFrom(r.Context())
	if caller == nil || caller.Service == "" {
		fail(w, http.StatusForbidden, errors.New("this endpoint is for service tokens"))
		return
	}
	tenant := a.tenantOf(r)
	jobs, err := a.store.Claim(r.Context(), tenant, r.PathValue("id"), 50)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]store.Remediation, 0, len(jobs))
	for _, j := range jobs {
		if j.Op == store.OpRestore {
			raw, err := a.store.Raw(r.Context(), tenant, j.MessageID)
			if err != nil {
				// Nothing to put back. Marked failed rather than retried forever:
				// no number of attempts will produce bytes that are not held.
				_ = a.store.Finish(r.Context(), tenant, j.ID, "the original message is not held")
				continue
			}
			j.Raw = raw
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, map[string]any{"remediations": out})
}

func (a *API) finishRemediation(w http.ResponseWriter, r *http.Request) {
	caller := CallerFrom(r.Context())
	if caller == nil || caller.Service == "" {
		fail(w, http.StatusForbidden, errors.New("this endpoint is for service tokens"))
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	var in struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in)

	if err := a.store.Finish(r.Context(), a.tenantOf(r), id, in.Error); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
}

// pendingRemediations is the operator's view: what has been decided and not yet done.
//
// Worth a page of its own because the gap is real. A message shows as quarantined the
// moment an analyst clicks, and it is still in the inbox until a connector picks the
// job up — and if the connector is down, it stays there. Somewhere has to say so.
func (a *API) pendingRemediations(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.store.PendingRemediations(r.Context(), a.tenantOf(r))
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if jobs == nil {
		jobs = []store.Remediation{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"remediations": jobs})
}
