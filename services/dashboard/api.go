// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"
)

//go:generate go run github.com/gzuidhof/tygo@v0.2.21 generate

// The console's JSON API.
//
// Every endpoint here is written out by hand, and that is the point. The obvious
// alternative — proxying /api/v0/* straight through to the engine behind a path
// allowlist — is a trap this service cannot afford: the engine serves both
// GET /v0/mailboxes/{id}/remediations and GET /v0/mailboxes/secrets, so any allowlist
// expressed as a pattern ("/v0/mailboxes/*") hands mailbox credentials to any signed-in
// browser. Mailbox secrets are reachable by a connector's service token and by nothing
// else. With explicit handlers there is no pattern to get wrong: an endpoint exists
// because somebody wrote it, and the ones that would leak were never written.
//
// Role enforcement lives in the route table in app.go, not here.

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

// fail turns an engine error into a status the console can act on.
func (a *App) fail(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	switch s := StatusOf(err); {
	case s == http.StatusNotFound:
		status = http.StatusNotFound
	case s == http.StatusForbidden:
		status = http.StatusForbidden
	case s == http.StatusConflict:
		status = http.StatusConflict
	case s == http.StatusBadRequest:
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// okJSON answers a mutation that has nothing to return.
func okJSON(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) }

// body decodes a JSON request, refusing unknown fields.
//
// Strict decoding because the client and this server are generated from the same
// types: a field the server does not know is a bug in one of them, and silently
// dropping it is how a setting appears to save and then does not.
func body[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request: " + err.Error()})
		return v, false
	}
	return v, true
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

// Bootstrap is what the console needs before it can draw anything: who is signed in,
// what they may do, and the queue depths the navigation shows.
type Bootstrap struct {
	User     WhoAmI         `json:"user"`
	Counts   map[string]int `json:"counts"`
	ReadOnly bool           `json:"read_only"`
	SSO      bool           `json:"sso"`
	Queues   []Queue        `json:"queues"`
}

// Queue is one triage tab.
type Queue struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Hint  string `json:"hint"`
}

func queues() []Queue {
	out := make([]Queue, 0, len(triageQueues))
	for _, q := range triageQueues {
		out = append(out, Queue{Key: q.Key, Label: q.Label, Hint: q.Hint})
	}
	return out
}

func (a *App) apiSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return
	}
	// Reissue the CSRF cookie on every bootstrap so a console left open across a
	// re-login picks up the current token without a reload.
	a.auth.issueCSRF(w, sess.Token)

	writeJSON(w, http.StatusOK, Bootstrap{
		User:     sess.User,
		Counts:   a.badgeCounts(r),
		ReadOnly: a.readOnly,
		SSO:      a.auth.SSOEnabled(),
		Queues:   queues(),
	})
}

// ---------------------------------------------------------------------------
// Triage
// ---------------------------------------------------------------------------

// TriagePage is one queue's worth of mail.
type TriagePage struct {
	Messages []Message      `json:"messages"`
	Counts   map[string]int `json:"counts"`
	State    string         `json:"state"`
	Window   string         `json:"window"`
	Total    int            `json:"total"`
}

func (a *App) apiTriage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" {
		// Needs-remediation first: the queue where a message is confirmed bad and
		// still sitting in someone's inbox is the only one actively costing
		// something while it waits.
		state = "needs_remediation"
	}
	win := windowOf(r)
	from, to := windowRange(win)

	params := url.Values{"limit": {"500"}, "from": {from.Format(time.RFC3339)}, "to": {to.Format(time.RFC3339)}}
	if state != "all" {
		params.Set("verdict", "")
	}
	for _, k := range []string{"q", "sender"} {
		if v := q.Get(k); v != "" {
			params.Set(k, v)
		}
	}

	msgs, err := a.engine.Messages(r.Context(), params)
	if err != nil {
		a.fail(w, err)
		return
	}

	// The queue is a view over the window rather than an API concept: filtering here
	// keeps the engine's message API general instead of growing an endpoint per tab.
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		if state == "all" {
			out = append(out, m)
			continue
		}
		if m.Verdict == "clean" {
			continue
		}
		if triageStateOf(m) == state {
			out = append(out, m)
		}
	}

	counts, total, err := a.engine.TriageCounts(r.Context(), from, to)
	if err != nil {
		// A queue that renders without its badges is far better than one that does
		// not render, so a counts failure is not fatal to the page.
		counts = nil
	}

	writeJSON(w, http.StatusOK, TriagePage{
		Messages: out, Counts: counts, State: state, Window: win, Total: total,
	})
}

// ---------------------------------------------------------------------------
// Message detail
// ---------------------------------------------------------------------------

// MessagePage is the detail view: the engine's analysis plus what the console adds.
type MessagePage struct {
	ID      string         `json:"id"`
	Detail  *MessageDetail `json:"detail"`
	Verdict string         `json:"verdict"`

	// Screenshot is the URL the Rendered tab loads. A stored message has an endpoint
	// to fetch its picture from; a transient analysis carries one inline instead.
	Screenshot string `json:"screenshot,omitempty"`

	// Insights arrive as one list and are shown as three, because an analyst reads
	// them in that order: who sent it, what is known about them, what is in it.
	Identity   []Insight `json:"identity"`
	Reputation []Insight `json:"reputation"`
	Content    []Insight `json:"content"`

	Summary map[string]any `json:"summary"`
	MDM     any            `json:"mdm"`
	States  []Queue        `json:"states"`
}

func (a *App) apiMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	detail, err := a.engine.Detail(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, messagePage(id, detail))
}

func messagePage(id string, detail *MessageDetail) MessagePage {
	var model map[string]any
	_ = json.Unmarshal(detail.MessageDataModel, &model)

	groups := map[string][]Insight{}
	for _, in := range detail.Insights {
		groups[in.Group] = append(groups[in.Group], in)
	}

	return MessagePage{
		ID:         id,
		Detail:     detail,
		Verdict:    verdictOf(detail),
		Screenshot: string(screenshotSrcFor(id, detail)),
		Identity:   groups["identity"],
		Reputation: groups["reputation"],
		Content:    groups["content"],
		Summary:    summarise(model),
		MDM:        model,
		States:     queues(),
	}
}

type actRequest struct {
	Action      string `json:"action"`
	Reason      string `json:"reason"`
	Disposition string `json:"disposition"`
	Force       bool   `json:"force"`
}

func (a *App) apiAct(w http.ResponseWriter, r *http.Request) {
	req, ok := body[actRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.Act(r.Context(), r.PathValue("id"), req.Action, req.Reason, req.Disposition, req.Force); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

type triageRequest struct {
	State string `json:"state"`
	Note  string `json:"note"`
}

func (a *App) apiSetTriage(w http.ResponseWriter, r *http.Request) {
	req, ok := body[triageRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.SetTriage(r.Context(), r.PathValue("id"), req.State, req.Note); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// apiBulkTriage applies one judgement to a selection.
//
// A queue is worked in batches — twenty of the same campaign get the same verdict —
// and doing that one request at a time was the single most tedious thing about the
// old console. Partial success is reported rather than hidden: the caller is told
// exactly which ids failed, so the page can leave those rows selected.
type bulkTriageRequest struct {
	IDs   []string `json:"ids"`
	State string   `json:"state"`
	Note  string   `json:"note"`
}

type bulkResult struct {
	Done   int               `json:"done"`
	Failed map[string]string `json:"failed,omitempty"`
}

func (a *App) apiBulkTriage(w http.ResponseWriter, r *http.Request) {
	req, ok := body[bulkTriageRequest](w, r)
	if !ok {
		return
	}
	if len(req.IDs) > 500 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many messages in one request"})
		return
	}
	res := bulkResult{Failed: map[string]string{}}
	for _, id := range req.IDs {
		if err := a.engine.SetTriage(r.Context(), id, req.State, req.Note); err != nil {
			res.Failed[id] = err.Error()
			continue
		}
		res.Done++
	}
	if len(res.Failed) == 0 {
		res.Failed = nil
	}
	writeJSON(w, http.StatusOK, res)
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

func (a *App) apiSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	win := windowOf(r)
	from, to := windowRange(win)
	params := url.Values{"limit": {"200"}, "from": {from.Format(time.RFC3339)}, "to": {to.Format(time.RFC3339)}}
	for _, k := range []string{"q", "sender", "verdict", "rule"} {
		if v := q.Get(k); v != "" {
			params.Set(k, v)
		}
	}
	msgs, err := a.engine.Messages(r.Context(), params)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs, "window": win})
}

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

func (a *App) apiRules(w http.ResponseWriter, r *http.Request) {
	rules, err := a.engine.Rules(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	caps, err := a.engine.Capabilities(r.Context())
	if err != nil {
		// Capabilities decorate the list with what is answerable today. Losing them
		// costs a column, not the page.
		caps = nil
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "capabilities": caps})
}

func (a *App) apiRule(w http.ResponseWriter, r *http.Request) {
	rule, err := a.engine.Rule(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	actions, err := a.engine.RuleActions(r.Context())
	if err != nil {
		actions = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"rule": rule, "actions": actions[r.PathValue("id")]})
}

func (a *App) apiEffectiveness(w http.ResponseWriter, r *http.Request) {
	from, to := windowRange(windowOf(r))
	eff, err := a.engine.Effectiveness(r.Context(), from, to)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, eff)
}

func (a *App) apiCoverage(w http.ResponseWriter, r *http.Request) {
	cov, err := a.engine.Coverage(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cov)
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

func (a *App) apiOverview(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	from, to := windowRange(win)
	ins, err := a.engine.InsightsRange(r.Context(), from, to)
	if err != nil {
		a.fail(w, err)
		return
	}
	caps, err := a.engine.Capabilities(r.Context())
	if err != nil {
		caps = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"insights": ins, "capabilities": caps, "window": win})
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

// apiAnalyze accepts a pasted or uploaded .eml and returns the full detail view.
//
// Multipart rather than JSON: an .eml is bytes, and base64 in a JSON field would cost
// a third again in size for no gain.
func (a *App) apiAnalyze(w http.ResponseWriter, r *http.Request) {
	raw := []byte(r.FormValue("eml"))
	if f, _, err := r.FormFile("file"); err == nil {
		defer f.Close()
		if b, err := io.ReadAll(io.LimitReader(f, 32<<20)); err == nil && len(b) > 0 {
			raw = b
		}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "paste a message, or choose a .eml file"})
		return
	}
	detail, err := a.engine.AnalyzeDetail(r.Context(), raw)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, messagePage(detail.MessageID, detail))
}

// ---------------------------------------------------------------------------
// Settings — organisation
// ---------------------------------------------------------------------------

func (a *App) apiOrg(w http.ResponseWriter, r *http.Request) {
	org, err := a.engine.Org(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (a *App) apiSaveOrg(w http.ResponseWriter, r *http.Request) {
	req, ok := body[OrgConfig](w, r)
	if !ok {
		return
	}
	if err := a.engine.SaveOrg(r.Context(), req); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// ---------------------------------------------------------------------------
// Settings — mailboxes
// ---------------------------------------------------------------------------

func (a *App) apiMailboxes(w http.ResponseWriter, r *http.Request) {
	boxes, err := a.engine.Mailboxes(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mailboxes": boxes})
}

func (a *App) apiSaveMailbox(w http.ResponseWriter, r *http.Request) {
	req, ok := body[map[string]any](w, r)
	if !ok {
		return
	}
	if err := a.engine.SaveMailbox(r.Context(), req); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// apiSetMailboxEnabled pauses or resumes one mailbox.
//
// Separate from the save endpoint rather than a field on it, because the console's
// mailbox form holds a whole configuration and this must change exactly one thing. A
// pause built on the save path would need the row read back first, and anything the
// page did not carry across — folder, TLS mode, whether the deployment may act on the
// mailbox — would be quietly reset by an administrator clicking "pause".
func (a *App) apiSetMailboxEnabled(w http.ResponseWriter, r *http.Request) {
	req, ok := body[struct {
		Enabled bool `json:"enabled"`
	}](w, r)
	if !ok {
		return
	}
	if err := a.engine.SetMailboxEnabled(r.Context(), r.PathValue("id"), req.Enabled); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// apiGraphDirectory walks the Microsoft tenant so an estate can be onboarded at once.
func (a *App) apiGraphDirectory(w http.ResponseWriter, r *http.Request) {
	dir, err := a.engine.Directory(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dir)
}

type bulkMailboxRequest struct {
	Addresses []string `json:"addresses"`
	Enabled   bool     `json:"enabled"`
}

// apiAddMailboxes configures the accounts an administrator picked from the directory.
func (a *App) apiAddMailboxes(w http.ResponseWriter, r *http.Request) {
	req, ok := body[bulkMailboxRequest](w, r)
	if !ok {
		return
	}
	out, err := a.engine.AddMailboxes(r.Context(), req.Addresses, req.Enabled)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) apiDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.DeleteMailbox(r.Context(), r.PathValue("id")); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiRecheckMailbox(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.RecheckMailbox(r.Context(), r.PathValue("id")); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// ---------------------------------------------------------------------------
// Settings — actions
// ---------------------------------------------------------------------------

func (a *App) apiActions(w http.ResponseWriter, r *http.Request) {
	types, err := a.engine.ActionTypes(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	configured, err := a.engine.ConfiguredActions(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	byRule, err := a.engine.RuleActions(r.Context())
	if err != nil {
		byRule = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"types": types, "actions": configured, "by_rule": byRule})
}

func (a *App) apiSaveAction(w http.ResponseWriter, r *http.Request) {
	req, ok := body[ConfiguredAction](w, r)
	if !ok {
		return
	}
	if err := a.engine.SaveAction(r.Context(), req); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiDeleteAction(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.DeleteAction(r.Context(), r.PathValue("id")); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

type attachRequest struct {
	RuleIDs   []string `json:"rule_ids"`
	ActionIDs []string `json:"action_ids"`
	Remove    bool     `json:"remove"`
}

func (a *App) apiAttachActions(w http.ResponseWriter, r *http.Request) {
	req, ok := body[attachRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.AttachActions(r.Context(), req.RuleIDs, req.ActionIDs, req.Remove); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// ---------------------------------------------------------------------------
// Settings — Microsoft 365
// ---------------------------------------------------------------------------

func (a *App) apiGraphApp(w http.ResponseWriter, r *http.Request) {
	app, err := a.engine.GraphApp(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

type graphAppRequest struct {
	GraphApp `tstype:",extends"`
	Secret   string `json:"secret"`
}

func (a *App) apiSaveGraphApp(w http.ResponseWriter, r *http.Request) {
	req, ok := body[graphAppRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.SaveGraphApp(r.Context(), req.GraphApp, req.Secret); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiDeleteGraphApp(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.DeleteGraphApp(r.Context()); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// ---------------------------------------------------------------------------
// Settings — history scans
// ---------------------------------------------------------------------------

func (a *App) apiBackfills(w http.ResponseWriter, r *http.Request) {
	runs, err := a.engine.Backfills(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	boxes, err := a.engine.Mailboxes(r.Context())
	if err != nil {
		boxes = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"backfills": runs, "mailboxes": boxes})
}

type backfillRequest struct {
	MailboxID string `json:"mailbox_id"`
	Days      int    `json:"days"`
	KeepRaw   bool   `json:"keep_raw"`
}

func (a *App) apiStartBackfill(w http.ResponseWriter, r *http.Request) {
	req, ok := body[backfillRequest](w, r)
	if !ok {
		return
	}
	run, err := a.engine.StartBackfill(r.Context(), req.MailboxID, req.Days, req.KeepRaw)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (a *App) apiCancelBackfill(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.CancelBackfill(r.Context(), r.PathValue("id")); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// ---------------------------------------------------------------------------
// Settings — lists
// ---------------------------------------------------------------------------

func (a *App) apiLists(w http.ResponseWriter, r *http.Request) {
	configs, names, err := a.engine.Lists(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lists": configs, "available": names})
}

func (a *App) apiList(w http.ResponseWriter, r *http.Request) {
	cfg, overrides, sample, size, err := a.engine.List(r.Context(), r.PathValue("name"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"list": cfg, "overrides": overrides, "sample": sample, "size": size,
	})
}

func (a *App) apiUpdateList(w http.ResponseWriter, r *http.Request) {
	req, ok := body[map[string]any](w, r)
	if !ok {
		return
	}
	if err := a.engine.UpdateList(r.Context(), r.PathValue("name"), req); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

type listEntryRequest struct {
	Value string `json:"value"`
	Kind  string `json:"kind"`
	Note  string `json:"note"`
}

func (a *App) apiAddListEntry(w http.ResponseWriter, r *http.Request) {
	req, ok := body[listEntryRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.AddListEntry(r.Context(), r.PathValue("name"), req.Value, req.Kind, req.Note); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiRemoveListEntry(w http.ResponseWriter, r *http.Request) {
	req, ok := body[listEntryRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.RemoveListEntry(r.Context(), r.PathValue("name"), req.Value, req.Kind); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiRefreshList(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.RefreshList(r.Context(), r.PathValue("name")); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// ---------------------------------------------------------------------------
// Settings — learning
// ---------------------------------------------------------------------------

func (a *App) apiModel(w http.ResponseWriter, r *http.Request) {
	report, err := a.engine.Model(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (a *App) apiTrainModel(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.TrainModel(r.Context()); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiForgetModel(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.ForgetModel(r.Context()); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

// ---------------------------------------------------------------------------
// Settings — users and tokens
// ---------------------------------------------------------------------------

func (a *App) apiUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.engine.Users(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

type createUserRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (a *App) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	req, ok := body[createUserRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.CreateUser(r.Context(), req.Email, req.Name, req.Password, req.Role); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiUpdateUser(w http.ResponseWriter, r *http.Request) {
	req, ok := body[map[string]any](w, r)
	if !ok {
		return
	}
	if err := a.engine.UpdateUser(r.Context(), r.PathValue("id"), req); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

type createTokenRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// apiCreateToken returns the new token exactly once.
//
// The engine does not store a recoverable copy, so this response is the only chance
// to see it. The console says so next to the value.
func (a *App) apiCreateToken(w http.ResponseWriter, r *http.Request) {
	req, ok := body[createTokenRequest](w, r)
	if !ok {
		return
	}
	token, err := a.engine.CreateToken(r.Context(), req.Name, req.Role)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// ---------------------------------------------------------------------------
// Remediations
// ---------------------------------------------------------------------------

func (a *App) apiRemediations(w http.ResponseWriter, r *http.Request) {
	rems, err := a.engine.Remediations(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"remediations": rems})
}

// ---------------------------------------------------------------------------
// Sign in
// ---------------------------------------------------------------------------

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// apiLogin exchanges credentials for a session cookie.
//
// The cookie is set here rather than handed to script: the session token stays
// HttpOnly, so a cross-site script that manages to run cannot read it. Only the CSRF
// token is script-visible, which is the point of the pair.
func (a *App) apiLogin(w http.ResponseWriter, r *http.Request) {
	req, ok := body[loginRequest](w, r)
	if !ok {
		return
	}
	token, expires, err := a.auth.LoginLocal(r.Context(), req.Email, req.Password)
	if err != nil {
		// One message whatever went wrong, matching the engine: distinguishing "no
		// such account" from "wrong password" lets anyone enumerate who works here.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Those credentials were not accepted."})
		return
	}
	a.auth.setSession(w, token, expires)
	a.auth.issueCSRF(w, token)
	okJSON(w)
}

func (a *App) apiLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		// End it on the engine too. Clearing only the cookie leaves a working token
		// behind, which is not signing out.
		_ = a.engine.Logout(WithToken(r.Context(), c.Value))
	}
	a.auth.clearSession(w)
	okJSON(w)
}

// apiValidateRule type-checks an expression without running it.
type validateRequest struct {
	Source string `json:"source"`
}

func (a *App) apiValidateRule(w http.ResponseWriter, r *http.Request) {
	req, ok := body[validateRequest](w, r)
	if !ok {
		return
	}
	out, err := a.engine.Validate(r.Context(), req.Source)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type huntRequest struct {
	Source string `json:"source"`
	Window string `json:"window"`
}

func (a *App) apiHuntStart(w http.ResponseWriter, r *http.Request) {
	req, ok := body[huntRequest](w, r)
	if !ok {
		return
	}
	from, to := windowRange(req.Window)
	job, err := a.engine.StartHunt(r.Context(), req.Source, from.Format(time.RFC3339), to.Format(time.RFC3339))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (a *App) apiHuntJob(w http.ResponseWriter, r *http.Request) {
	job, err := a.engine.Hunt(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// ssoCallback completes the OpenID Connect handshake and lands the browser on the
// console.
//
// A redirect rather than JSON: the identity provider sent the browser here directly,
// so there is no fetch() waiting for an answer.
func (a *App) ssoCallback(w http.ResponseWriter, r *http.Request) {
	token, expires, err := a.auth.CompleteOIDC(r.Context(), w, r)
	if err != nil {
		http.Redirect(w, r, "/auth/login?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	a.auth.setSession(w, token, expires)
	a.auth.issueCSRF(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Settings — rule feeds
// ---------------------------------------------------------------------------

func (a *App) apiRuleFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := a.engine.RuleFeeds(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"feeds": feeds})
}

type ruleFeedRequest struct {
	RuleFeed
	Secret string `json:"secret"`
}

func (a *App) apiSaveRuleFeed(w http.ResponseWriter, r *http.Request) {
	req, ok := body[ruleFeedRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.SaveRuleFeed(r.Context(), req.RuleFeed, req.Secret); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiDeleteRuleFeed(w http.ResponseWriter, r *http.Request) {
	if err := a.engine.DeleteRuleFeed(r.Context(), r.PathValue("id")); err != nil {
		a.fail(w, err)
		return
	}
	okJSON(w)
}

func (a *App) apiSyncRuleFeed(w http.ResponseWriter, r *http.Request) {
	out, err := a.engine.SyncRuleFeed(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// apiMQLSchema hands the editor the language definition.
//
// Cached hard by the browser for a short while: it changes only when rules reload
// or a list is added, and an editor that refetches a few hundred kilobytes of type
// graph on every keystroke is worse than no completion at all.
func (a *App) apiMQLSchema(w http.ResponseWriter, r *http.Request) {
	raw, err := a.engine.MQLSchema(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(raw)
}

// ---------------------------------------------------------------------------
// Backtesting, findings and campaigns
// ---------------------------------------------------------------------------

type backtestRequest struct {
	Rule string `json:"rule"`
	Name string `json:"name"`
	Days int    `json:"days"`
}

// apiBacktestStart runs a proposed rule over stored mail.
//
// Analyst rather than admin, like the engine endpoint behind it and for the same
// reason: it reads the corpus and writes nothing, so the person who will have to live
// with a rule can find out what it does without asking anybody.
func (a *App) apiBacktestStart(w http.ResponseWriter, r *http.Request) {
	req, ok := body[backtestRequest](w, r)
	if !ok {
		return
	}
	out, err := a.engine.StartBacktest(r.Context(), req.Name, req.Rule, req.Days)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) apiBacktest(w http.ResponseWriter, r *http.Request) {
	out, err := a.engine.Backtest(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) apiFindings(w http.ResponseWriter, r *http.Request) {
	out, err := a.engine.Findings(r.Context(), r.URL.Query().Get("state"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type resolveFindingRequest struct {
	State string `json:"state"`
}

func (a *App) apiResolveFinding(w http.ResponseWriter, r *http.Request) {
	req, ok := body[resolveFindingRequest](w, r)
	if !ok {
		return
	}
	if err := a.engine.ResolveFinding(r.Context(), r.PathValue("id"), req.State); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (a *App) apiCampaigns(w http.ResponseWriter, r *http.Request) {
	from, to := windowRange(r.URL.Query().Get("window"))
	out, err := a.engine.Campaigns(r.Context(), from.Format(time.RFC3339), to.Format(time.RFC3339))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
