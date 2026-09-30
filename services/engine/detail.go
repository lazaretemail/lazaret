// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
	"github.com/lazaretemail/lazaret/rules"
	"github.com/lazaretemail/lazaret/services/engine/store"
)

// The views that answer "why", rather than "what".
//
// A triage list says a rule fired. That is the least useful thing an analyst can be
// told: the next question is always which clause matched, what the sender's history
// looks like, whether authentication passed, and what the engine could not see. These
// endpoints answer that, and they are the reason the detail page is worth building.

// messageDetail is everything known about one message.
//
// Read from what was stored at ingest, not recomputed.
//
// The first version re-ran the rules on every page load, on the argument that the
// page should reflect the rules as they are now. That argument is real but it is not
// worth what it cost: a full run of 1,257 rules, a fresh RDAP lookup, another pass of
// the classifier, and — with link analysis on — another visit to every link in the
// message. Five seconds a click, repeated network traffic to the attacker's
// infrastructure, and a page that could quietly disagree with the verdict it was
// explaining, because a flaky lookup makes the second answer differ from the first.
//
// So the analysis is computed once, when the message is ingested, and stored beside
// the model. Re-evaluation is still available and still useful — `?reevaluate=1`,
// which is what an analyst tuning a rule wants — but it is asked for rather than
// assumed. Messages ingested before the analysis was stored fall back to evaluating,
// and say so.
func (a *API) messageDetail(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	id := r.PathValue("id")
	ctx := store.WithTenant(r.Context(), tenant)

	raw, err := a.store.MDMByID(ctx, tenant, id)
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}

	var msg mdm.MessageDataModel
	if err := json.Unmarshal(raw, &msg); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// The expensive half: detections, insights and the sender panel, all of which
	// need enrichment. Stored at ingest and read back here.
	var an *StoredAnalysis
	fresh := r.URL.Query().Get("reevaluate") != ""
	if !fresh {
		if blob, err := a.store.AnalysisByID(ctx, tenant, id); err == nil && len(blob) > 0 {
			var parsed StoredAnalysis
			if json.Unmarshal(blob, &parsed) == nil && !stale(&parsed) {
				an = &parsed
			}
		}
	}
	if an == nil {
		an = a.pipeline.analyseForDetail(ctx, &msg)

		// Written back, so the work is not repeated and so a re-evaluation
		// actually sticks. An analyst who fixes a rule and re-runs it expects the
		// message to stay fixed; without this the page would show the new answer
		// once and revert to the old one on the next click.
		//
		// Stored before the flag is set, deliberately: "recomputed" describes this
		// response, not the analysis. Marshalling it into the blob would make
		// every subsequent read claim it had just re-run the rules.
		if blob, err := json.Marshal(an); err == nil {
			if err := a.store.SetAnalysis(ctx, tenant, id, blob); err != nil {
				log.Printf("storing re-evaluated analysis for %s: %v", id, err)
			}
		}
		an.Recomputed = true
	}

	// staleness check above, not here: a blob written before a field existed is
	// indistinguishable from one where the field is legitimately empty, so the
	// decision has to be made against the message.

	out := detailPayload(id, &msg, an, json.RawMessage(raw))

	if actions, err := a.store.Actions(ctx, tenant, id); err == nil {
		out["actions"] = actions
	}

	// Whether the original bytes are held, which decides whether this message can be
	// quarantined at all. Surfaced on the message rather than left for the action to
	// fail on, so an analyst sees it before choosing.
	out["held"] = a.store.HasRaw(ctx, tenant, id)

	if d, err := a.store.Dispositions(ctx, tenant, []string{id}); err == nil && d[id] != "" {
		out["disposition"] = d[id]
	}
	if t, err := a.store.TriageFor(ctx, tenant, []string{id}); err == nil {
		if state, ok := t[id]; ok {
			out["triage"] = state
		} else {
			out["triage"] = store.Triage{MessageID: id, State: store.StateUnreviewed}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// Detection is one rule's outcome, with enough to explain it.
type Detection struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Techniques  []string `json:"techniques,omitempty"`
	AttackTypes []string `json:"attack_types,omitempty"`

	// Missing is what this specific rule could not see. A rule reporting
	// indeterminate is only useful if it says what it was waiting for.
	Missing []string `json:"missing,omitempty"`

	// Source is the MQL. An analyst deciding whether a detection is a false positive
	// needs to read the rule, and making them go and find the file is how "I'll look
	// at it later" happens.
	Source string `json:"source,omitempty"`
}

func detections(ds []*rules.Detection) []Detection {
	out := make([]Detection, 0, len(ds))
	for _, d := range ds {
		out = append(out, Detection{
			ID:          d.Entity.ID,
			Name:        d.Entity.Name,
			Severity:    string(d.Entity.Severity),
			Description: d.Entity.Description,
			Tags:        d.Entity.Tags,
			Techniques:  d.Entity.TacticsAndTechniques,
			AttackTypes: d.Entity.AttackTypes,
			Missing:     capList(d.Missing),
			Source:      d.Entity.Source,
		})
	}
	return out
}

// queryValues renders the insight queries, which return values rather than verdicts.
// This is what the `type: query` entities in the corpus are for, and why the evaluator
// is value-returning rather than a predicate engine.
func queryValues(q map[string]mql.Value) map[string]any {
	out := make(map[string]any, len(q))
	for name, v := range q {
		if v.IsNull() {
			continue
		}
		out[name] = v.Interface()
	}
	return out
}

func capList(caps []enrich.Capability) []string {
	out := make([]string, len(caps))
	for i, c := range caps {
		out[i] = string(c)
	}
	sort.Strings(out)
	return out
}

// authSummary is what the receiving MTA concluded, which is the first thing anyone
// looks at on a suspected impersonation.
func authSummary(m *mdm.MessageDataModel) map[string]any {
	out := map[string]any{}
	if m.Headers == nil || m.Headers.AuthSummary == nil {
		return out
	}
	as := m.Headers.AuthSummary
	// DMARC and SPF only: AuthSummary carries no DKIM field, because DMARC alignment
	// is what a rule actually asks about and a DKIM pass that does not align proves
	// nothing about the visible sender.
	if as.DMARC != nil {
		out["dmarc"] = map[string]any{"pass": mdm.Deref(as.DMARC.Pass), "error": mdm.Deref(as.DMARC.Error)}
	}
	if as.SPF != nil {
		out["spf"] = map[string]any{"pass": mdm.Deref(as.SPF.Pass), "error": mdm.Deref(as.SPF.Error)}
	}
	return out
}

func attachmentSummary(m *mdm.MessageDataModel) []AttachmentDetail {
	out := make([]AttachmentDetail, 0, len(m.Attachments))
	for _, att := range m.Attachments {
		if att == nil {
			continue
		}
		out = append(out, AttachmentDetail{
			FileName:    mdm.Deref(att.FileName),
			Extension:   mdm.Deref(att.FileExtension),
			ContentType: mdm.Deref(att.ContentType),
			Size:        mdm.Deref(att.Size),
			MD5:         mdm.Deref(att.MD5),
			SHA256:      mdm.Deref(att.SHA256),
		})
	}
	return out
}

// headerSummary is the routing story: who sent it, who it says it is from, and the
// path it took.
func headerSummary(m *mdm.MessageDataModel) map[string]any {
	out := map[string]any{}
	h := m.Headers
	if h == nil {
		return out
	}
	out["message_id"] = mdm.Deref(h.MessageID)
	out["in_reply_to"] = mdm.Deref(h.InReplyTo)
	if h.Date != nil {
		out["date"] = h.Date
	}
	var replyTo []string
	for _, rt := range h.ReplyTo {
		if rt != nil && rt.Email != nil {
			replyTo = append(replyTo, mdm.Deref(rt.Email.Email))
		}
	}
	out["reply_to"] = replyTo

	hops := make([]map[string]any, 0, len(h.Hops))
	for _, hop := range h.Hops {
		if hop == nil {
			continue
		}
		entry := map[string]any{"index": hop.Index}
		if rec := hop.Received; rec != nil {
			if rec.Source != nil {
				entry["from"] = mdm.Deref(rec.Source.Raw)
			}
			if rec.Server != nil {
				entry["by"] = mdm.Deref(rec.Server.Raw)
			}
			if rec.Time != nil {
				entry["time"] = rec.Time
			}
		}
		hops = append(hops, entry)
	}
	out["hops"] = hops
	return out
}

func containsFold(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	h, n := []rune(lower(haystack)), []rune(lower(needle))
outer:
	for i := 0; i+len(n) <= len(h); i++ {
		for j := range n {
			if h[i+j] != n[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

func lower(s string) string {
	b := []rune(s)
	for i, r := range b {
		if r >= 'A' && r <= 'Z' {
			b[i] = r + 32
		}
	}
	return string(b)
}

// ruleDetail returns one rule with its source and what it needs.
func (a *API) ruleDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	for _, c := range a.pipeline.rules().Compiled() {
		if c.Entity.ID != id && c.Entity.Name != id {
			continue
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id": c.Entity.ID, "name": c.Entity.Name, "type": c.Entity.Type,
			"severity": c.Entity.Severity, "description": c.Entity.Description,
			"source": c.Entity.Source, "tags": c.Entity.Tags,
			"attack_types": c.Entity.AttackTypes,
			"techniques":   c.Entity.TacticsAndTechniques,
			"references":   c.Entity.References,
			"needs":        capList(c.Checked.Capabilities),
			"lists":        c.Checked.Lists,
		})
		return
	}
	fail(w, http.StatusNotFound, errors.New("no such rule"))
}

// ruleEffectiveness reports which rules are earning their place.
//
// A rule that never fires is not necessarily bad — most of a corpus is dormant most of
// the time — but a rule that fires constantly and is always dismissed as benign is a
// rule generating work rather than detections, and that is invisible without joining
// what fired to what an analyst then concluded.
func (a *API) ruleEffectiveness(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	from, to := windowFrom(r)

	stats, err := a.store.RuleEffectiveness(ctx, tenant, from, to)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}

	// Loaded rules that have never fired in the window. Worth naming rather than
	// leaving as an absence: it is the difference between "this rule is quiet" and
	// "this rule is not loaded".
	fired := map[string]bool{}
	for _, s := range stats {
		fired[s.Rule] = true
	}
	var dormant []string
	for _, c := range a.pipeline.rules().Compiled() {
		if c.Entity.Type == "rule" && !fired[c.Entity.Name] {
			dormant = append(dormant, c.Entity.Name)
		}
	}
	sort.Strings(dormant)

	writeJSON(w, http.StatusOK, map[string]any{
		"rules":         stats,
		"dormant":       dormant,
		"dormant_count": len(dormant),
		"loaded":        a.pipeline.rules().Len(),
	})
}

// coverage reports how much of the loaded rule set this deployment can actually
// evaluate.
//
// The honest headline number. A deployment with a thousand rules and no ML service is
// not a deployment with a thousand rules, and nothing else in the product says so as
// directly as this.
func (a *API) coverage(w http.ResponseWriter, r *http.Request) {
	type capCoverage struct {
		Capability string `json:"capability"`
		Rules      int    `json:"rules"`
		Available  bool   `json:"available"`

		// Reason says why an absent capability is absent, and Remedy says what to do
		// about it. "missing" on its own is a status, not information: an operator
		// reading it cannot tell a service they forgot to start from a model that
		// does not exist, and those need completely different actions.
		Reason string `json:"reason,omitempty"`
		Remedy string `json:"remedy,omitempty"`
	}

	// Answerable means a real call came back, not that some provider claims the
	// capability. Those are different questions and this page used to ask the
	// easy one: with Strelka unreachable it reported file.explode available and
	// the headline number counted rules that could not run.
	answerable := map[string]bool{}
	probed := map[string]CapabilityState{}
	for _, h := range a.pipeline.CheckCapabilities(r.Context(), 8*time.Second) {
		answerable[h.Capability] = h.OK
		probed[h.Capability] = h
	}

	byCap := map[string]int{}
	fullyAnswerable, blocked := 0, 0
	for _, c := range a.pipeline.rules().Compiled() {
		ok := true
		for _, cap := range c.Checked.Capabilities {
			byCap[string(cap)]++
			if !answerable[string(cap)] {
				ok = false
			}
		}
		if ok {
			fullyAnswerable++
		} else {
			blocked++
		}
	}

	caps := make([]capCoverage, 0, len(byCap))
	for name, n := range byCap {
		c := capCoverage{Capability: name, Rules: n, Available: answerable[name]}
		if !c.Available {
			c.Reason, c.Remedy = whyMissing(name)
			// What the probe actually saw beats the generic explanation: "timed
			// out — the service is not answering" tells an operator to go and
			// look at the service, which "needs Strelka" does not.
			if d := probed[name].Detail; d != "" {
				c.Reason = d
			}
		}
		caps = append(caps, c)
	}
	sort.Slice(caps, func(i, j int) bool {
		if caps[i].Available != caps[j].Available {
			return !caps[i].Available // what is missing leads
		}
		return caps[i].Rules > caps[j].Rules
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"loaded":            a.pipeline.rules().Len(),
		"fully_answerable":  fullyAnswerable,
		"blocked":           blocked,
		"capabilities":      caps,
		"providers":         a.pipeline.providerNames,
		"lists_unavailable": a.unavailableLists(),
	})
}

func (a *API) unavailableLists() []string {
	var out []string
	for _, name := range a.pipeline.rules().Lists() {
		if !a.pipeline.listsKnown(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func (a *API) triageCounts(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	ctx := store.WithTenant(r.Context(), tenant)
	from, to := windowFrom(r)

	flagged, err := a.store.FlaggedIDs(ctx, tenant, from, to)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	counts, err := a.store.TriageCounts(ctx, tenant, flagged)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"counts": counts, "flagged": len(flagged)})
}

func (a *API) setTriage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		State    string `json:"state"`
		Assignee string `json:"assignee"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if !store.ValidTriageState(in.State) {
		fail(w, http.StatusBadRequest, errors.New("unknown triage state "+in.State))
		return
	}

	by := CallerFrom(r.Context()).Actor()
	err := a.store.SetTriage(r.Context(), a.tenantOf(r), r.PathValue("id"), store.Triage{
		State: store.TriageState(in.State), Assignee: in.Assignee, Note: in.Note,
	}, by)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": in.State, "reviewed_by": by})
}

func windowFrom(r *http.Request) (time.Time, time.Time) {
	to := time.Now().UTC().AddDate(0, 0, 1)
	from := to.AddDate(0, 0, -31)
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t
		}
	}
	return from, to
}

// whyMissing explains an absent capability.
//
// Three genuinely different situations, and conflating them is why a coverage page
// that only says "missing" is close to useless:
//
//   - a service exists and is not connected — start it, pass the flag;
//   - a service exists and needs weights nobody has loaded;
//   - it is declined, and will not appear however much is deployed.
func whyMissing(capability string) (reason, remedy string) {
	switch capability {
	case "file.explode", "file.expand_archives", "beta.ocr", "beta.scan_qr", "beta.parse_exif":
		return "Strelka is not connected",
			"Run third_party/strelka and start the engine with -strelka host:57314"
	case "file.message_screenshot", "file.html_screenshot":
		return "lazaret-render is not connected",
			"Run services/render and start the engine with -render http://host:8710"
	case "ml.link_analysis":
		// Deliberately separate from -render. Screenshotting a message needs no
		// network at all, and the renderer is deployed egress-free so that analysing
		// a message cannot tell its sender it was read. Following its links is the
		// opposite: an outbound request to an address an attacker chose.
		return "link following is off; it is a separate decision from rendering",
			"Start the renderer with -fetch and the engine with -link-analysis. Everything " +
				"except .credphish works without a model — the page is fetched, not classified"
	case "network.whois":
		return "RDAP lookups are disabled",
			"Start the engine without -rdap=false; it needs no external service"
	case "ml.nlu_classifier", "ml.logo_detect", "ml.macro_classifier", "ml.attack_score",
		"beta.ml_topic", "beta.ml_translate", "beta.fuzzy_attack_score":
		return "lazaret-ml has no model for this",
			"Place <capability>.onnx in the models directory and build lazaret-ml with -tags onnx. " +
				"No weights ship: they carry their own licence, and a weak classifier here is " +
				"worse than none because the corpus negates these to exclude benign mail"
	case "file.oletools":
		return "declined: Strelka does not emit what this needs",
			"Not planned. Strelka reports stream counts; the corpus reads .relationships and " +
				".indicators, which are not on the wire. See third_party/strelka/README.md"
	case "beta.ml_extract_sensitive_information":
		return "this should always be available", "Report this: it runs in-process and needs nothing"
	}
	return "no provider claims this capability", "Check which services the engine was started with"
}

// rawMessage serves the original bytes.
//
// Analyst and above, not viewer. This is live malicious content — the attachment, the
// link, the whole thing exactly as it was delivered — and handing it to anyone with a
// read-only login is handing them something that can hurt them. The same copy is what
// a release puts back, so it is also the thing whose integrity matters most.
//
// Served as an attachment with a nosniff header, so a browser saves it rather than
// deciding for itself that a message full of HTML would be nicer rendered.
func (a *API) rawMessage(w http.ResponseWriter, r *http.Request) {
	tenant := a.tenantOf(r)
	id := r.PathValue("id")

	raw, err := a.store.Raw(store.WithTenant(r.Context(), tenant), tenant, id)
	if err != nil {
		if errors.Is(err, store.ErrNoRaw) {
			fail(w, http.StatusNotFound, errors.New(
				"the original bytes of this message are not held; it was ingested before custody was configured"))
			return
		}
		fail(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "message/rfc822")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(id)+`.eml"`)
	w.Write(raw)
}

// safeFilename turns a message id into something a Content-Disposition header can
// carry.
//
// The id comes from the message headers, which is to say from the sender: a literal
// one can contain quotes, semicolons, newlines and non-ASCII, and each of those is a
// way to break out of the header and inject another. Reduced to a conservative set
// rather than escaped, because the filename is a convenience and the id is in the
// page anyway.
func safeFilename(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '@':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() > 80 {
			break
		}
	}
	if b.Len() == 0 {
		return "message"
	}
	return b.String()
}

// stale reports a stored analysis written before something the page now shows.
//
// Recomputing costs one page load per message, once. The alternative to noticing is a
// permanently empty panel on every message that arrived before the feature shipped,
// which looks exactly like a bug and is the kind of thing nobody reports because it is
// not obviously broken.
func stale(an *StoredAnalysis) bool { return an.Schema < analysisSchema }

// detailPayload is the shape of a message detail view.
//
// One function, because there are two callers and they must agree. The message page
// reads a stored analysis; the analyzer runs one against a message it will never
// record. If those produced different payloads the analyzer would drift into being a
// worse view of the same facts, which is exactly what it was — a verdict and nothing
// else, on a page with a rule engine behind it.
//
// Everything here except the analysis itself is derived from the model with no
// enrichment at all, so it is recomputed on every view: it costs nothing and cannot
// go stale.
func detailPayload(id string, msg *mdm.MessageDataModel, an *StoredAnalysis, raw json.RawMessage) map[string]any {
	return map[string]any{
		"message_id":         id,
		"message_data_model": raw,
		"detections":         an.Detections,
		"indeterminate":      an.Indeterminate,
		"excluded":           an.Excluded,
		"queries":            an.Queries,
		"missing":            an.Missing,
		"insights":           an.Insights,
		"signals":            an.Signals,
		"sender":             an.Sender,
		"learned":            an.Learned,
		"analysed_at":        an.At,
		"recomputed":         an.Recomputed,
		"authentication":     authSummary(msg),
		"auth_badges":        authBadges(msg),
		"links":              an.Links,
		"origin":             an.Origin,
		"attachments":        attachmentSummary(msg),
		"headers":            headerSummary(msg),
		"content":            contentViews(msg),
		// Whether there is a body a browser could lay out, so the page knows to
		// ask for a picture instead of guessing from the text it was given.
		"renderable": len(renderableBody(msg)) > 0,
		"summary":    messageSummary(msg),
	}
}
