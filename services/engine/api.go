// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rules"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// The public HTTP API, aiming at the documented Sublime surface.
//
// Compatibility here is a means rather than a goal: an engine that speaks the same API
// as the thing it replaces can be put behind the same tooling, and a migration is a
// base URL rather than a rewrite.

// API serves the engine.
type API struct {
	store    *store.Store
	pipeline *Pipeline
	hunter   *Hunter
	backtest *Backtester
	retro    *Retro
	feeds    *FeedSyncer
	admit    *admitter

	// defaultTenant is used when a request names none. A single-tenant deployment
	// should not have to say so on every call.
	defaultTenant string

	maxBody int64

	// lists resolves named lists and keeps the remote ones fresh.
	lists *ListManager

	// publicBase is where this deployment is reachable from the internet, if it
	// is. Callback URLs are derived from it rather than configured.
	publicBase string

	// noAuth disables authentication entirely, for a single-machine evaluation. Not
	// the default, and logged on every start: a system that is insecure until
	// configured is a system that ships insecure.
	noAuth bool
}

// Routes returns the mux.
//
// Every route carries a minimum role. Reading needs viewer, acting needs analyst,
// managing identity needs admin — and the two unauthenticated endpoints are health,
// which a load balancer needs, and login, which is how you get a credential in the
// first place.
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated, deliberately and only these.
	mux.HandleFunc("GET /v0/readiness", a.require(store.RoleViewer, a.readiness))
	mux.HandleFunc("GET /v0/health", a.health)
	mux.HandleFunc("POST /v0/auth/login", a.login)

	// Session management.
	mux.HandleFunc("POST /v0/auth/logout", a.require(store.RoleViewer, a.logout))
	mux.HandleFunc("GET /v0/auth/whoami", a.require(store.RoleViewer, a.whoami))
	// Privileged: it mints a session for whoever it is told about, so it takes an
	// admin token and must never be reachable from a browser.
	mux.HandleFunc("POST /v0/auth/sso", a.require(store.RoleAdmin, a.ssoLogin))

	// Reading.
	mux.HandleFunc("GET /v0/messages", a.require(store.RoleViewer, a.listMessages))
	mux.HandleFunc("GET /v0/messages/{id}/message_data_model", a.require(store.RoleViewer, a.messageDataModel))
	mux.HandleFunc("GET /v0/messages/{id}", a.require(store.RoleViewer, a.messageDetail))
	mux.HandleFunc("GET /v0/messages/{id}/actions", a.require(store.RoleViewer, a.actionLog))
	mux.HandleFunc("GET /v0/messages/{id}/raw", a.require(store.RoleAnalyst, a.rawMessage))
	mux.HandleFunc("GET /v0/messages/{id}/screenshot", a.require(store.RoleViewer, a.messageScreenshot))
	mux.HandleFunc("GET /v0/rules", a.require(store.RoleViewer, a.listRules))
	mux.HandleFunc("GET /v0/rules/{id}", a.require(store.RoleViewer, a.ruleDetail))
	mux.HandleFunc("GET /v0/insights", a.require(store.RoleViewer, a.insights))
	mux.HandleFunc("GET /v0/rule-effectiveness", a.require(store.RoleViewer, a.ruleEffectiveness))
	mux.HandleFunc("GET /v0/coverage", a.require(store.RoleViewer, a.coverage))
	mux.HandleFunc("GET /v0/triage/counts", a.require(store.RoleViewer, a.triageCounts))
	mux.HandleFunc("GET /v0/stats", a.require(store.RoleViewer, a.stats))
	mux.HandleFunc("GET /v0/capabilities", a.require(store.RoleViewer, a.capabilities))
	mux.HandleFunc("GET /v0/hunt-jobs/{id}", a.require(store.RoleViewer, a.getHunt))
	mux.HandleFunc("GET /v0/backtests", a.require(store.RoleViewer, a.listBacktests))
	mux.HandleFunc("GET /v0/backtests/{id}", a.require(store.RoleViewer, a.getBacktest))
	mux.HandleFunc("GET /v0/findings", a.require(store.RoleViewer, a.listFindings))
	mux.HandleFunc("GET /v0/campaigns", a.require(store.RoleViewer, a.campaigns))

	// Acting.
	mux.HandleFunc("POST /v0/messages/analyze", a.require(store.RoleAnalyst, a.analyze))
	mux.HandleFunc("POST /v0/messages/ingest", a.require(store.RoleAnalyst, a.ingest))
	mux.HandleFunc("POST /v0/messages/{id}/actions", a.require(store.RoleAnalyst, a.action))
	mux.HandleFunc("POST /v0/messages/{id}/triage", a.require(store.RoleAnalyst, a.setTriage))
	// Rule feeds: where detection content comes from. Admin only — a feed decides
	// what the engine looks for.
	mux.HandleFunc("GET /v0/rule-feeds", a.require(store.RoleAdmin, a.listRuleFeeds))
	mux.HandleFunc("POST /v0/rule-feeds", a.require(store.RoleAdmin, a.saveRuleFeed))
	mux.HandleFunc("DELETE /v0/rule-feeds/{id}", a.require(store.RoleAdmin, a.deleteRuleFeed))
	mux.HandleFunc("POST /v0/rule-feeds/{id}/sync", a.require(store.RoleAdmin, a.syncRuleFeed))

	// What the editor needs to offer completions: this engine's function registry,
	// the generated MDM type graph, and the lists that actually resolve here.
	mux.HandleFunc("GET /v0/mql/schema", a.require(store.RoleViewer, a.mqlSchema))

	mux.HandleFunc("POST /v0/rules/validate", a.require(store.RoleAnalyst, a.validate))
	mux.HandleFunc("POST /v0/hunt-jobs", a.require(store.RoleAnalyst, a.startHunt))
	mux.HandleFunc("POST /v0/backtests", a.require(store.RoleAnalyst, a.startBacktest))
	mux.HandleFunc("POST /v0/findings/{id}/resolve", a.require(store.RoleAnalyst, a.resolveFinding))

	// Configuration. Reading needs viewer so an analyst can see why a rule is
	// unanswerable; changing needs admin.
	mux.HandleFunc("GET /v0/lists", a.require(store.RoleViewer, a.listLists))
	mux.HandleFunc("GET /v0/lists/{name}", a.require(store.RoleViewer, a.getList))
	mux.HandleFunc("PATCH /v0/lists/{name}", a.require(store.RoleAdmin, a.updateList))
	mux.HandleFunc("POST /v0/lists/{name}/entries", a.require(store.RoleAnalyst, a.addListEntry))
	mux.HandleFunc("DELETE /v0/lists/{name}/entries", a.require(store.RoleAnalyst, a.removeListEntry))
	mux.HandleFunc("POST /v0/lists/{name}/refresh", a.require(store.RoleAnalyst, a.refreshList))

	mux.HandleFunc("GET /v0/mailboxes", a.require(store.RoleViewer, a.listMailboxes))
	mux.HandleFunc("GET /v0/mailboxes/secrets", a.require(store.RoleAdmin, a.mailboxSecrets))
	mux.HandleFunc("GET /v0/mailboxes/{id}/remediations", a.require(store.RoleAdmin, a.claimRemediations))
	mux.HandleFunc("POST /v0/remediations/{id}", a.require(store.RoleAdmin, a.finishRemediation))
	mux.HandleFunc("GET /v0/remediations", a.require(store.RoleViewer, a.pendingRemediations))

	// Retrospective scans. Creating one is an admin action: it reads every message
	// in a mailbox for the window, which is a great deal of somebody's mail.
	mux.HandleFunc("GET /v0/backfills", a.require(store.RoleViewer, a.listBackfills))
	mux.HandleFunc("POST /v0/backfills", a.require(store.RoleAdmin, a.createBackfill))
	mux.HandleFunc("GET /v0/backfills/{id}", a.require(store.RoleViewer, a.getBackfill))
	mux.HandleFunc("POST /v0/backfills/{id}/cancel", a.require(store.RoleAnalyst, a.cancelBackfill))
	// Claimed and reported by connectors, which authenticate as admin tokens the
	// same way remediation does.
	mux.HandleFunc("POST /v0/mailboxes/{id}/backfill/claim", a.require(store.RoleAdmin, a.claimBackfill))
	mux.HandleFunc("POST /v0/backfills/{id}/progress", a.require(store.RoleAdmin, a.backfillProgress))
	mux.HandleFunc("POST /v0/mailboxes", a.require(store.RoleAdmin, a.saveMailbox))
	// Onboarding an estate: read the directory, then add what was chosen from it.
	// Admin, because one is a listing of every account in the organisation and the
	// other configures collection from them.
	mux.HandleFunc("GET /v0/graph/directory", a.require(store.RoleAdmin, a.listGraphDirectory))
	mux.HandleFunc("POST /v0/mailboxes/bulk", a.require(store.RoleAdmin, a.addGraphMailboxes))
	mux.HandleFunc("POST /v0/mailboxes/{id}/enabled", a.require(store.RoleAdmin, a.setMailboxEnabled))
	mux.HandleFunc("DELETE /v0/mailboxes/{id}", a.require(store.RoleAdmin, a.deleteMailbox))
	// Reported by connectors on every connection attempt, so the settings page can
	// say whether a mailbox is reachable rather than only that it is configured.
	mux.HandleFunc("POST /v0/mailboxes/{id}/health", a.require(store.RoleAdmin, a.mailboxHealth))
	mux.HandleFunc("POST /v0/mailboxes/{id}/recheck", a.require(store.RoleAdmin, a.recheckMailbox))

	mux.HandleFunc("GET /v0/model", a.require(store.RoleViewer, a.describeModel))
	mux.HandleFunc("POST /v0/model/train", a.require(store.RoleAdmin, a.trainModel))
	mux.HandleFunc("DELETE /v0/model", a.require(store.RoleAdmin, a.forgetModel))

	// The Microsoft 365 application registration. Reading needs admin — the ids
	// are not secrets but they name the directory — and the secret is readable
	// only by a connector's service token.
	// What detections do. Reading needs viewer so an analyst can see why a
	// message was moved; changing needs admin, because it automates mailbox
	// changes on the strength of a rule firing.
	mux.HandleFunc("GET /v0/action-types", a.require(store.RoleViewer, a.actionTypes))
	mux.HandleFunc("GET /v0/actions", a.require(store.RoleViewer, a.listActions))
	mux.HandleFunc("POST /v0/actions", a.require(store.RoleAdmin, a.saveAction))
	mux.HandleFunc("PUT /v0/actions/{id}", a.require(store.RoleAdmin, a.saveAction))
	mux.HandleFunc("DELETE /v0/actions/{id}", a.require(store.RoleAdmin, a.deleteAction))
	mux.HandleFunc("GET /v0/rule-actions", a.require(store.RoleViewer, a.ruleActions))
	mux.HandleFunc("POST /v0/rule-actions", a.require(store.RoleAdmin, a.attachActions))

	mux.HandleFunc("GET /v0/graph-app", a.require(store.RoleAdmin, a.getGraphApp))
	mux.HandleFunc("PUT /v0/graph-app", a.require(store.RoleAdmin, a.updateGraphApp))
	mux.HandleFunc("DELETE /v0/graph-app", a.require(store.RoleAdmin, a.deleteGraphApp))
	mux.HandleFunc("GET /v0/graph-app/secrets", a.require(store.RoleAdmin, a.graphAppSecrets))

	mux.HandleFunc("GET /v0/org", a.require(store.RoleViewer, a.getOrg))
	mux.HandleFunc("PUT /v0/org", a.require(store.RoleAdmin, a.updateOrg))

	// Administration.
	mux.HandleFunc("GET /v0/users", a.require(store.RoleAdmin, a.listUsers))
	mux.HandleFunc("POST /v0/users", a.require(store.RoleAdmin, a.createUser))
	mux.HandleFunc("PATCH /v0/users/{id}", a.require(store.RoleAdmin, a.updateUser))
	mux.HandleFunc("POST /v0/tokens", a.require(store.RoleAdmin, a.createToken))

	return mux
}

// analyze runs the rule set over a message without recording it.
//
// Deliberately stateless. Recording messages submitted here would let anyone with API
// access poison every sender profile in the tenant by submitting mail that was never
// delivered, which is a cheap way to make a target look like an established
// correspondent. /v0/messages/ingest is the path that writes.
func (a *API) analyze(w http.ResponseWriter, r *http.Request) {
	a.runAnalysis(w, r, false)
}

// ingest analyses a message and records it: the delivery path.
func (a *API) ingest(w http.ResponseWriter, r *http.Request) {
	a.runAnalysis(w, r, true)
}

func (a *API) runAnalysis(w http.ResponseWriter, r *http.Request, persist bool) {
	// Admission before parsing: a request that will not be served should not first
	// be decoded into memory, and under load that decode is itself part of the
	// problem.
	release, err := a.admit.Acquire(r.Context())
	if err != nil {
		if errors.Is(err, ErrBusy) {
			// Retry-After rather than a bare 503: the connector should back off
			// and re-offer the message, which is safe because nothing has been
			// recorded. A request that eventually succeeds after four minutes is
			// worse — the connector has already given up and will send it again.
			w.Header().Set("Retry-After", "5")
			fail(w, http.StatusServiceUnavailable, fmt.Errorf(
				"%w (%d analyses already running); the message was not read, retry it",
				err, a.admit.Limit()))
			return
		}
		// The caller hung up.
		return
	}
	defer release()

	var in struct {
		RawMessage string `json:"raw_message"`
		TenantID   string `json:"tenant_id"`

		// MailboxID is which mailbox this arrived in, when a managed connector
		// sent it. Recorded so a later removal can be aimed rather than fanned out.
		// Empty from the inline path, which sees mail in transit.
		MailboxID string `json:"mailbox_id"`

		// BackfillID marks a message a retrospective scan found rather than one
		// seen on arrival. It changes nothing about how the message is
		// evaluated — the rules do not know or care — and everything about how
		// the verdict should be read afterwards.
		BackfillID string `json:"backfill_id"`

		// SkipCustody declines to keep the original bytes, for a scan that is
		// building history rather than preparing to quarantine anything.
		SkipCustody bool `json:"skip_custody"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBody)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(in.RawMessage)
	if err != nil {
		// Accept a raw message as well as a base64 one. Sublime's API takes base64, and
		// a caller with a file on disk should not have to encode it to try something.
		raw = []byte(in.RawMessage)
	}
	if len(raw) == 0 {
		fail(w, http.StatusBadRequest, errors.New("raw_message is empty"))
		return
	}

	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	out, err := a.pipeline.AnalyzeWith(ctx, tenant, raw, persist, IngestOptions{
		MailboxID:   in.MailboxID,
		BackfillID:  in.BackfillID,
		SkipCustody: in.SkipCustody,
	})
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// The ingest path answers with the verdict and nothing else: a connector reads
	// this on every message and has no use for several kilobytes of page content.
	// The analyzer path answers with everything the message page shows, because
	// there is nowhere to read it back from afterwards — not storing the message is
	// the entire point of that endpoint, and a verdict with no evidence behind it
	// asks an analyst to take the engine's word for it.
	if persist || out.Detail == nil || out.Model == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	writeJSON(w, http.StatusOK, a.pipeline.analyzerPayload(ctx, out))
}

// messageDataModel returns a stored message's parsed model.
func (a *API) messageDataModel(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	raw, err := a.store.MDMByID(store.WithTenant(r.Context(), tenant), tenant, r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

// action records a disposition: quarantine, release, trash.
//
// The part of the platform the project is named for. Append-only, and the actor is
// required — an audit trail that cannot say who decided is not one.
func (a *API) action(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"`
		Reason string `json:"reason"`

		// Disposition says why a message is being released: "false_positive" when
		// the rule was wrong, "accepted_risk" when it was right and the message is
		// wanted anyway. They are different facts about the rule and only one of
		// them should change its effectiveness numbers.
		Disposition string `json:"disposition"`

		// Force deletes a message whose original bytes are not held.
		//
		// Separate from the action rather than implied by an admin role, because it
		// is the one operation here that destroys mail irrecoverably: without
		// custody there is nothing to release it from. It has to be asked for in as
		// many words, and it is recorded as such.
		Force bool `json:"force"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	switch in.Action {
	case "quarantine", "release", "trash", "restore", "flag", "unflag":
	default:
		fail(w, http.StatusBadRequest, fmt.Errorf("unknown action %q", in.Action))
		return
	}
	// The actor is the authenticated caller, never a field in the request. A client
	// that can name its own actor can forge an audit trail, which is the one thing an
	// audit trail must not allow.
	caller := CallerFrom(r.Context())
	actor := caller.Actor()

	tenant := a.tenantOf(r)
	id := r.PathValue("id")

	// Quarantine and trash take the message out of the mailbox altogether, so the
	// copy this system holds becomes the only one. Refusing when there is no copy is
	// the whole of the safety here: the alternative is deleting a message nobody can
	// get back, on the strength of a verdict an analyst may be about to overturn.
	held := a.store.HasRaw(r.Context(), tenant, id)
	if in.Action == "quarantine" || in.Action == "trash" {
		switch {
		case held:
		case !in.Force:
			fail(w, http.StatusConflict, fmt.Errorf(
				"refusing to %s %s: the original message is not held, so it could not be released again. "+
					"Messages ingested before custody was configured cannot be removed from a mailbox. "+
					`Send {"force": true} to delete it anyway, which cannot be undone`, in.Action, id))
			return
		case caller.Role != store.RoleAdmin:
			fail(w, http.StatusForbidden, errors.New(
				"forcing a removal without custody destroys the message; only an admin may do that"))
			return
		}
	}

	// The reason recorded is the operator's, with the disposition folded in so the
	// audit trail reads as a sentence rather than as two fields someone has to join
	// up later.
	reason := in.Reason
	if in.Action == "release" || in.Action == "restore" {
		switch in.Disposition {
		case "false_positive":
			reason = "false positive: " + reason
		case "accepted_risk":
			reason = "accepted risk: " + reason
		}
	}
	if !held && in.Force {
		reason = "forced without custody (unrecoverable): " + reason
	}

	if err := a.store.RecordAction(r.Context(), tenant, id, in.Action, reason, actor); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// Recording is not doing. The mailbox is reachable only from a connector, so what
	// happens here is that the work is queued; the connector collects it and reports
	// back. An action with no enabled mailbox queues nothing, and says so.
	queued := 0
	switch in.Action {
	case "quarantine", "trash":
		n, err := a.store.Enqueue(r.Context(), tenant, id, store.OpRemove)
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		queued = n
	case "release", "restore":
		n, err := a.store.Enqueue(r.Context(), tenant, id, store.OpRestore)
		if err != nil {
			fail(w, http.StatusInternalServerError, err)
			return
		}
		queued = n
	}

	// Disposition is stored alongside the action so effectiveness can distinguish a
	// rule that was wrong from one that was right and overruled.
	if in.Disposition != "" {
		if err := a.store.SetDisposition(r.Context(), tenant, id, in.Disposition); err != nil {
			log.Printf("recording disposition for %s: %v", id, err)
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "recorded", "queued": queued,
	})
}

func (a *API) actionLog(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	actions, err := a.store.Actions(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if actions == nil {
		actions = []store.Action{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

// validate compiles a rule and reports what it needs.
//
// No auth and no state, matching the endpoint Sublime exposes on their analyzer — which
// is also what this project's own differential harness points at, so the symmetry is
// deliberate: someone can point our harness at us.
func (a *API) validate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Source string `json:"source"`
		Type   string `json:"type"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBody)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	// The engine's own registry, not the default one. With -rdap the deployment has
	// rdap.ip and rdap.asn, and validating against the stock surface told an author
	// their expression was invalid while the engine next door would have run it.
	checked, err := mql.Compile(in.Source, &mql.CheckOptions{
		RequireBoolean: in.Type == "rule",
		Registry:       a.pipeline.Registry(),
	})
	if err != nil {
		out := map[string]any{"success": false, "error": err.Error()}
		if errs, ok := err.(mql.ErrorList); ok {
			out["diagnostics"] = errs.Render(in.Source)
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	caps := make([]string, len(checked.Capabilities))
	for i, c := range checked.Capabilities {
		caps[i] = string(c)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"type":    checked.Type.Describe(),
		"lists":   checked.Lists,
		"needs":   caps,
	})
}

func (a *API) startHunt(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Source   string `json:"source"`
		From     string `json:"from"`
		To       string `json:"to"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBody)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	// A default window rather than all of history: an unbounded hunt over years of mail
	// is almost never what someone meant, and it is expensive enough to be worth asking
	// for explicitly.
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -30)
	if in.From != "" {
		if t, err := time.Parse(time.RFC3339, in.From); err == nil {
			from = t
		}
	}
	if in.To != "" {
		if t, err := time.Parse(time.RFC3339, in.To); err == nil {
			to = t
		}
	}

	tenant := a.tenantOf(r)
	job, err := a.hunter.Start(store.WithTenant(r.Context(), tenant), tenant, in.Source, from, to)
	if err != nil {
		out := map[string]any{"success": false, "error": err.Error()}
		if errs, ok := err.(mql.ErrorList); ok {
			out["diagnostics"] = errs.Render(in.Source)
		}
		writeJSON(w, http.StatusBadRequest, out)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (a *API) getHunt(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	job, err := a.hunter.Get(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// listMessages is the triage list.
//
// Summaries rather than models: a page of two hundred messages does not need two
// hundred parsed MDMs, and sending them makes the page slow in a way no amount of
// front-end work fixes. The full model is one request away per message.
func (a *API) listMessages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	opts := store.ListOptions{
		Verdict: q.Get("verdict"),
		Sender:  q.Get("sender"),
		Search:  q.Get("q"),
		Limit:   atoiOr(q.Get("limit"), 100),
		Offset:  atoiOr(q.Get("offset"), 0),
	}
	if v := q.Get("from"); v != "" {
		opts.From, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("to"); v != "" {
		opts.To, _ = time.Parse(time.RFC3339, v)
	}

	msgs, err := a.store.List(ctx, tenant, opts)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// The last action per message, so triage can show what has already been done and
	// an analyst does not quarantine something a colleague released a minute ago.
	ids := make([]string, len(msgs))
	for i, m := range msgs {
		ids[i] = m.MessageID
	}
	if actions, err := a.store.LastActions(ctx, tenant, ids); err == nil {
		for i := range msgs {
			msgs[i].LastAction = actions[msgs[i].MessageID]
		}
	}
	// Triage state travels with the list, so the queues are one request rather than
	// one per row. Absence means unreviewed: nobody has looked, which is a state.
	if states, err := a.store.TriageFor(ctx, tenant, ids); err == nil {
		for i := range msgs {
			if t, ok := states[msgs[i].MessageID]; ok {
				msgs[i].TriageState = string(t.State)
			} else {
				msgs[i].TriageState = string(store.StateUnreviewed)
			}
		}
	}

	if msgs == nil {
		msgs = []store.Summary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs, "count": len(msgs)})
}

// listRules reports the loaded content, for the rules view.
func (a *API) listRules(w http.ResponseWriter, r *http.Request) {
	type ruleInfo struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Type     string   `json:"type"`
		Severity string   `json:"severity,omitempty"`
		Needs    []string `json:"needs,omitempty"`
		Lists    []string `json:"lists,omitempty"`
		Source   string   `json:"source,omitempty"`
	}

	full := r.URL.Query().Get("source") == "true"
	out := make([]ruleInfo, 0, a.pipeline.rules().Len())
	for _, c := range a.pipeline.rules().Compiled() {
		info := ruleInfo{
			ID: c.Entity.ID, Name: c.Entity.Name,
			Type: string(c.Entity.Type), Severity: string(c.Entity.Severity),
			Lists: c.Checked.Lists,
		}
		for _, cap := range c.Checked.Capabilities {
			info.Needs = append(info.Needs, string(cap))
		}
		if full {
			info.Source = c.Entity.Source
		}
		out = append(out, info)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out, "count": len(out)})
}

// insights are the aggregate views a dashboard opens with.
func (a *API) insights(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenant := a.tenantOf(r)

	to := time.Now().UTC()
	from := to.AddDate(0, 0, -30)
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}

	ins, err := a.store.Insights(store.WithTenant(r.Context(), tenant), tenant, from, to)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, ins)
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	st, err := a.store.Stats(store.WithTenant(r.Context(), tenant), tenant)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// capabilities reports what this deployment can actually answer, and what the loaded
// rules want.
//
// Worth exposing rather than leaving in the logs: the difference between the two is the
// honest measure of how much of a rule set a deployment can evaluate, and an operator
// should be able to see it without sending a message through.
func (a *API) capabilities(w http.ResponseWriter, r *http.Request) {
	wanted := a.pipeline.rules().Capabilities()
	names := make([]string, len(wanted))
	for i, c := range wanted {
		names[i] = string(c)
	}
	// Probed, not assumed. "Attached" only ever meant a client was constructed
	// with an address; this is whether a real call comes back.
	health := a.pipeline.CheckCapabilities(r.Context(), 8*time.Second)
	var broken, lostRules int
	for _, h := range health {
		if !h.OK {
			broken++
			lostRules += h.Rules
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"rules_loaded":       a.pipeline.rules().Len(),
		"capabilities_used":  names,
		"capability_health":  health,
		"capabilities_down":  broken,
		"rules_unanswerable": lostRules,
		"lists_referenced":   a.pipeline.rules().Lists(),
		"providers_attached": a.pipeline.providerNames,
		// What inference is running on. The classifier is the largest single cost
		// in analysing a message and a GPU changes it by an order of magnitude, so
		// "cpu, having offered rocm and been refused" is the difference between a
		// deployment that is slow and one that is slow for a reason you can fix.
		"inference": a.inference(r.Context()),
		// Whether a message could be held if a verdict came in now. Quarantine
		// deletes from the mailbox, so this is the difference between the platform
		// being able to act on a detection and only being able to report it.
		"custody": a.store.Custody(r.Context()),
	})
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readiness is health plus the things whose absence changes what the platform can do.
//
// Separate from /v0/health, which a load balancer polls and which must stay cheap and
// must not fail for a degraded dependency — taking the engine out of rotation because
// the blob store is slow would turn a reduced capability into an outage.
func (a *API) readiness(w http.ResponseWriter, r *http.Request) {
	cust := a.store.Custody(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"custody": cust,
		"rules":   a.pipeline.rules().Len(),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// loadRules is shared by start-up and the reload path.
func loadRules(dir string, opts *rules.Options) (*rules.Engine, []*rules.LoadError, error) {
	return rules.LoadPath(dir, opts)
}

// inference reports what the model service is running on, or nil when there is none.
func (a *API) inference(ctx context.Context) any {
	if a.pipeline.ml == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	inf, err := a.pipeline.ml.Inference(ctx)
	if err != nil {
		return nil
	}
	return inf
}

// Backtesting: what a rule would have done, before it is allowed to do anything.
//
// Analyst rather than admin, deliberately. Running a rule over stored mail changes
// nothing — it reads the corpus and the triage states and writes no verdict, sends no
// remediation — so the person who will have to live with the rule can find out what it
// does without asking anybody.
func (a *API) startBacktest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rule string `json:"rule"`
		Name string `json:"name"`
		Days int    `json:"days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBody)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if in.Rule == "" {
		fail(w, http.StatusBadRequest, errors.New("a rule to test is required"))
		return
	}
	if in.Days <= 0 {
		in.Days = 30
	}
	if in.Days > 365 {
		in.Days = 365
	}

	to := time.Now().UTC()
	from := to.AddDate(0, 0, -in.Days)

	tenant := a.tenantOf(r)
	job, err := a.backtest.Start(store.WithTenant(r.Context(), tenant), tenant, in.Name, in.Rule, from, to)
	if err != nil {
		out := map[string]any{"success": false, "error": err.Error()}
		// The compiler's diagnostics point at a column, which is the whole reason to
		// test a rule here rather than by enabling it and waiting.
		if errs, ok := err.(mql.ErrorList); ok {
			out["diagnostics"] = errs.Render(in.Rule)
		}
		writeJSON(w, http.StatusBadRequest, out)
		return
	}
	writeJSON(w, http.StatusAccepted, backtestView(job))
}

func (a *API) getBacktest(w http.ResponseWriter, r *http.Request) {
	job, ok := a.backtest.Get(a.tenantOf(r), r.PathValue("id"))
	if !ok {
		fail(w, http.StatusNotFound, errors.New("no such backtest"))
		return
	}
	writeJSON(w, http.StatusOK, backtestView(job))
}

func (a *API) listBacktests(w http.ResponseWriter, r *http.Request) {
	jobs := a.backtest.List(a.tenantOf(r))
	out := make([]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, backtestView(j))
	}
	writeJSON(w, http.StatusOK, map[string]any{"backtests": out})
}

// backtestView adds the derived numbers, so the console does not have to know the rule
// for when a precision figure is worth showing.
func backtestView(j *BacktestJob) map[string]any {
	b, _ := json.Marshal(j)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	out["precision_known"] = j.PrecisionKnown()
	if j.PrecisionKnown() {
		out["precision"] = j.Precision()
	}
	return out
}

// Findings: what we learned about mail that had already been delivered.
//
// Viewer to read, analyst to resolve — the same split as triage, and for the same
// reason. Resolving a finding records a decision; it does not act on the message. The
// message's own actions endpoint is where quarantining lives, so an analyst who decides
// a finding is real takes the same explicit step they would have taken on the day.
func (a *API) listFindings(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		fail(w, http.StatusServiceUnavailable, errors.New("no corpus is configured"))
		return
	}
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)

	// Defaults to the ones nobody has dealt with, because that is the question the
	// page is asking. ?state=all shows the history.
	state := r.URL.Query().Get("state")
	if state == "" {
		state = store.FindingNew
	}
	if state == "all" {
		state = ""
	}

	findings, err := a.store.Findings(ctx, tenant, state, atoiOr(r.URL.Query().Get("limit"), 200))
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// The subject and sender, joined in so the list is triageable without opening
	// every message. One query for the page rather than one per row.
	if ids := findingMessageIDs(findings); len(ids) > 0 {
		if heads, err := a.store.MessageHeads(ctx, tenant, ids); err == nil {
			for i := range findings {
				if h, ok := heads[findings[i].MessageID]; ok {
					findings[i].Subject, findings[i].Sender = h.Subject, h.SenderEmail
				}
			}
		}
	}

	open, _ := a.store.OpenFindings(ctx, tenant)
	watched, _ := a.store.WatchedCount(ctx, tenant)
	writeJSON(w, http.StatusOK, map[string]any{
		"findings":      findings,
		"open":          open,
		"links_watched": watched,
		// What is actually looking. An empty list means "nothing turned up" or
		// "nothing is checking", and those are opposite things to an operator.
		"sweeping":    a.retro.Armed(),
		"window_days": a.retro.WindowDays(),
	})
}

func findingMessageIDs(f []store.RetroFinding) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(f))
	for _, x := range f {
		if !seen[x.MessageID] {
			seen[x.MessageID] = true
			out = append(out, x.MessageID)
		}
	}
	return out
}

func (a *API) resolveFinding(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		fail(w, http.StatusServiceUnavailable, errors.New("no corpus is configured"))
		return
	}
	var in struct {
		State string `json:"state"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, a.maxBody)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	tenant := a.tenantOf(r)
	who := CallerFrom(r.Context()).Actor()
	err := a.store.ResolveFinding(store.WithTenant(r.Context(), tenant), tenant,
		r.PathValue("id"), in.State, who)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// Campaigns: one attack, grouped instead of triaged thirty times.
//
// Computed on request rather than stored. The grouping depends on a window and a
// threshold, both of which an analyst changes while looking at it, and the expensive
// part — the fingerprint — is already done and sitting in a column. Clustering a month
// of mail is a scan of five columns and some bit counting.
func (a *API) campaigns(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		fail(w, http.StatusServiceUnavailable, errors.New("no corpus is configured"))
		return
	}
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	from, to := windowFrom(r)

	rows, err := a.store.CampaignCandidates(ctx, tenant, from, to, 0)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// What an analyst already decided, joined in once. A campaign where most members
	// were called benign and two were not is the interesting one, and it cannot be
	// seen message by message.
	if len(rows) > 0 {
		ids := make([]string, len(rows))
		for i, m := range rows {
			ids[i] = m.MessageID
		}
		if states, err := a.store.TriageFor(ctx, tenant, ids); err == nil {
			for i := range rows {
				if t, ok := states[rows[i].MessageID]; ok {
					rows[i].Triage = string(t.State)
				}
			}
		}
	}

	campaigns := Cluster(rows)
	grouped := 0
	for _, c := range campaigns {
		grouped += c.Size
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"campaigns": campaigns,
		// Said plainly, because the number that matters is how much of the queue
		// this collapses: "412 messages, 61 of them in 8 campaigns" is the claim.
		"messages_considered": len(rows),
		"messages_grouped":    grouped,
		"from":                from,
		"to":                  to,
	})
}
