// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EngineClient is the dashboard's only dependency: the engine's public HTTP API.
//
// No database handle and no shared Go types. The constraint is deliberate — it keeps
// the API exercised by a real consumer rather than only by its own tests, and it means
// anything this UI can do, a script can do too.
type EngineClient struct {
	Base   string
	Tenant string
	HTTP   *http.Client
}

// tokenKey carries the caller's engine credential through the context.
//
// Per request rather than a single service credential for everything, so the engine
// sees the actual person: role checks are enforced there, and the audit trail records
// who acted rather than "the dashboard". A dashboard that holds one powerful token and
// decides for itself who may do what is a dashboard whose authorisation can be
// bypassed by talking to the engine directly.
type tokenKey struct{}

// WithToken scopes a context to a caller's engine credential.
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}

func tokenFrom(ctx context.Context) string {
	t, _ := ctx.Value(tokenKey{}).(string)
	return t
}

// Message is one row of the triage list.
type Message struct {
	MessageID   string    `json:"message_id"`
	ReceivedAt  time.Time `json:"received_at"`
	Sender      string    `json:"sender"`
	Subject     string    `json:"subject"`
	Direction   string    `json:"direction"`
	Verdict     string    `json:"verdict"`
	Matched     []string  `json:"matched"`
	Missing     []string  `json:"missing"`
	LastAction  string    `json:"last_action"`
	TriageState string    `json:"triage_state"`
}

type Insights struct {
	ByDay      []DayCount       `json:"by_day"`
	TopRules   []NameCount      `json:"top_rules"`
	TopSenders []NameCount      `json:"top_senders"`
	Missing    []NameCount      `json:"missing_capabilities"`
	Totals     map[string]int64 `json:"totals"`
}

type DayCount struct {
	Day           string `json:"day"`
	Malicious     int64  `json:"malicious"`
	Indeterminate int64  `json:"indeterminate"`
	Clean         int64  `json:"clean"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Severity string   `json:"severity"`
	Needs    []string `json:"needs"`
	Lists    []string `json:"lists"`
	Source   string   `json:"source"`
}

type Action struct {
	Action    string    `json:"action"`
	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	At        time.Time `json:"at"`
	MessageID string    `json:"message_id"`
}

// Inference is the model service's execution provider, mirroring ml.Inference.
type Inference struct {
	// Provider is what it is using: "cpu", "migraphx", "cuda", "tensorrt".
	Provider string `json:"provider"`

	// Tried is what was offered to the runtime. More than one entry with a cpu
	// provider means GPU providers were offered and refused — which is a
	// deployment running without the accelerator someone intended it to have,
	// rather than one that never had a GPU.
	Tried []string `json:"tried,omitempty"`
}

type Capabilities struct {
	RulesLoaded       int      `json:"rules_loaded"`
	CapabilitiesUsed  []string `json:"capabilities_used"`
	ListsReferenced   []string `json:"lists_referenced"`
	ProvidersAttached []string `json:"providers_attached"`

	// Health is whether each capability actually answers, probed by the engine
	// with a real call. ProvidersAttached above only ever meant a client was
	// constructed with an address — which is how an unreachable Strelka went
	// unnoticed while a fifth of the rule set silently reported indeterminate.
	Health            []CapabilityState `json:"capability_health"`
	Down              int               `json:"capabilities_down"`
	RulesUnanswerable int               `json:"rules_unanswerable"`

	// Inference is which execution provider the model service ended up on.
	//
	// Carried to the console because the console is where somebody notices that
	// rules are going unanswered, and a CPU fallback is the likeliest reason. The
	// classifier is 0.3s on a GPU and 8s on a CPU alone, and under real concurrency
	// it was measured at 82s against the engine's 120s budget — at which point 358
	// rules report indeterminate and nothing on the page says why.
	Inference *Inference `json:"inference,omitempty"`
}

// CapabilityState is whether one enrichment capability answered a real call.
type CapabilityState struct {
	Capability string `json:"capability"`
	OK         bool   `json:"ok"`
	Detail     string `json:"detail"`
	Rules      int    `json:"rules"`
	TookMS     int64  `json:"took_ms"`
}

// Broken is the capabilities that did not answer, which the engine returns first and
// in the order that costs the most rules.
func (c Capabilities) Broken() []CapabilityState {
	var out []CapabilityState
	for _, h := range c.Health {
		if !h.OK {
			out = append(out, h)
		}
	}
	return out
}

// Working is the capabilities that did.
func (c Capabilities) Working() []CapabilityState {
	var out []CapabilityState
	for _, h := range c.Health {
		if h.OK {
			out = append(out, h)
		}
	}
	return out
}

type HuntJob struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	State   string `json:"state"`
	Scanned int64  `json:"messages_scanned"`
	Matched int64  `json:"messages_matched"`
	Error   string `json:"error"`
	Results []struct {
		MessageID string `json:"message_id"`
	} `json:"results"`
	Success     *bool  `json:"success"`
	Diagnostics string `json:"diagnostics"`

	// Undecided is how many messages the expression could not be resolved against,
	// because the evidence it wanted was never kept. Carried through to the console
	// rather than dropped: folding it into "did not match" would turn "we never
	// checked" into "nothing found", which is the one answer a hunt must not give
	// silently.
	Undecided int64 `json:"messages_undecided"`

	// Missing names those capabilities and how often, so a thin result says whether
	// the mail was clean or the evidence was not there.
	Missing map[string]int `json:"missing_evidence"`
}

// Backtest is what a proposed rule would have done over stored mail.
type Backtest struct {
	ID        string `json:"id"`
	Rule      string `json:"rule"`
	RuleName  string `json:"rule_name"`
	State     string `json:"state"`
	Error     string `json:"error"`
	Scanned   int64  `json:"messages_scanned"`
	Matched   int64  `json:"messages_matched"`
	Undecided int64  `json:"messages_undecided"`

	Missing map[string]int `json:"missing_evidence"`

	Reviewed  int64 `json:"reviewed"`
	Benign    int64 `json:"benign"`
	Confirmed int64 `json:"confirmed"`

	// PrecisionKnown says whether enough of the matches had already been judged for
	// Precision to mean anything. The console must not show a figure without it: a
	// rule with two reviews and both benign is unmeasured, not bad.
	PrecisionKnown bool    `json:"precision_known"`
	Precision      float64 `json:"precision"`

	Results []BacktestHit `json:"results"`

	Diagnostics string `json:"diagnostics"`
}

// BacktestHit is one message a proposed rule would have fired on.
type BacktestHit struct {
	MessageID  string    `json:"message_id"`
	ReceivedAt time.Time `json:"received_at"`
	Subject    string    `json:"subject"`
	Sender     string    `json:"sender"`
	Triage     string    `json:"triage"`
	Verdict    string    `json:"verdict"`
}

// Finding is something learned about a message after it was delivered.
type Finding struct {
	ID         string     `json:"id"`
	MessageID  string     `json:"message_id"`
	Kind       string     `json:"kind"`
	Source     string     `json:"source"`
	Detail     string     `json:"detail"`
	State      string     `json:"state"`
	FoundAt    time.Time  `json:"found_at"`
	ReviewedBy string     `json:"reviewed_by"`
	ReviewedAt *time.Time `json:"reviewed_at"`
	Subject    string     `json:"subject"`
	Sender     string     `json:"sender"`
}

// Findings is the page: the findings themselves, plus what is still being watched.
type Findings struct {
	Findings []Finding `json:"findings"`
	Open     int       `json:"open"`

	// LinksWatched is how many links from delivered mail are still scheduled to be
	// looked at again. Shown because an empty findings list means two very different
	// things depending on whether anything is being watched at all.
	LinksWatched int `json:"links_watched"`

	// Sweeping says whether new detection content and list updates are checked
	// against delivered mail at all, and WindowDays how far back. Same reason: an
	// empty list means "nothing turned up" or "nothing is checking".
	Sweeping   bool `json:"sweeping"`
	WindowDays int  `json:"window_days"`
}

// Campaign is one attack that arrived many times.
type Campaign struct {
	ID          string           `json:"id"`
	Size        int              `json:"size"`
	Subject     string           `json:"subject"`
	Senders     []string         `json:"senders"`
	LinkDomains []string         `json:"link_domains"`
	First       string           `json:"first_seen"`
	Last        string           `json:"last_seen"`
	Verdicts    map[string]int   `json:"verdicts"`
	Triage      map[string]int   `json:"triage"`
	Messages    []CampaignMember `json:"messages"`
}

// CampaignMember is one message inside a campaign.
type CampaignMember struct {
	MessageID   string    `json:"message_id"`
	ReceivedAt  time.Time `json:"received_at"`
	Subject     string    `json:"subject"`
	Sender      string    `json:"sender"`
	Verdict     string    `json:"verdict"`
	Triage      string    `json:"triage"`
	LinkDomains []string  `json:"link_domains"`
}

// Campaigns is the page.
type Campaigns struct {
	Campaigns []Campaign `json:"campaigns"`

	// Considered and Grouped are the claim the page makes: "412 messages, 61 of them
	// in 8 campaigns". Without the first number the second says nothing.
	Considered int `json:"messages_considered"`
	Grouped    int `json:"messages_grouped"`
}

func (c *EngineClient) Messages(ctx context.Context, q url.Values) ([]Message, error) {
	q.Set("tenant_id", c.Tenant)
	var out struct {
		Messages []Message `json:"messages"`
	}
	return out.Messages, c.get(ctx, "/v0/messages?"+q.Encode(), &out)
}

func (c *EngineClient) InsightsRange(ctx context.Context, from, to time.Time) (*Insights, error) {
	q := url.Values{
		"tenant_id": {c.Tenant},
		"from":      {from.Format(time.RFC3339)},
		"to":        {to.Format(time.RFC3339)},
	}
	var out Insights
	return &out, c.get(ctx, "/v0/insights?"+q.Encode(), &out)
}

func (c *EngineClient) Rules(ctx context.Context) ([]Rule, error) {
	var out struct {
		Rules []Rule `json:"rules"`
	}
	return out.Rules, c.get(ctx, "/v0/rules", &out)
}

func (c *EngineClient) Capabilities(ctx context.Context) (*Capabilities, error) {
	var out Capabilities
	return &out, c.get(ctx, "/v0/capabilities", &out)
}

func (c *EngineClient) MDM(ctx context.Context, id string) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.get(ctx, "/v0/messages/"+url.PathEscape(id)+"/message_data_model?tenant_id="+url.QueryEscape(c.Tenant), &out)
	return out, err
}

func (c *EngineClient) Actions(ctx context.Context, id string) ([]Action, error) {
	var out struct {
		Actions []Action `json:"actions"`
	}
	return out.Actions, c.get(ctx, "/v0/messages/"+url.PathEscape(id)+"/actions?tenant_id="+url.QueryEscape(c.Tenant), &out)
}

// Act records a disposition. No actor: the engine takes it from the authenticated
// caller, so a client cannot forge one.
func (c *EngineClient) Act(ctx context.Context, id, action, reason, disposition string, force bool) error {
	body, _ := json.Marshal(map[string]any{
		"action": action, "reason": reason,
		"disposition": disposition, "force": force,
	})
	return c.post(ctx, "/v0/messages/"+url.PathEscape(id)+"/actions", body, nil)
}

func (c *EngineClient) Validate(ctx context.Context, source string) (map[string]any, error) {
	body, _ := json.Marshal(map[string]string{"source": source})
	var out map[string]any
	return out, c.post(ctx, "/v0/rules/validate", body, &out)
}

func (c *EngineClient) StartHunt(ctx context.Context, source, from, to string) (*HuntJob, error) {
	body, _ := json.Marshal(map[string]string{
		"source": source, "from": from, "to": to, "tenant_id": c.Tenant,
	})
	var out HuntJob
	return &out, c.post(ctx, "/v0/hunt-jobs", body, &out)
}

func (c *EngineClient) Hunt(ctx context.Context, id string) (*HuntJob, error) {
	var out HuntJob
	return &out, c.get(ctx, "/v0/hunt-jobs/"+url.PathEscape(id)+"?tenant_id="+url.QueryEscape(c.Tenant), &out)
}

// StartBacktest runs a proposed rule over stored mail.
func (c *EngineClient) StartBacktest(ctx context.Context, name, rule string, days int) (*Backtest, error) {
	body, _ := json.Marshal(map[string]any{
		"rule": rule, "name": name, "days": days, "tenant_id": c.Tenant,
	})
	var out Backtest
	return &out, c.post(ctx, "/v0/backtests", body, &out)
}

// Backtest polls one.
func (c *EngineClient) Backtest(ctx context.Context, id string) (*Backtest, error) {
	var out Backtest
	return &out, c.get(ctx, "/v0/backtests/"+url.PathEscape(id)+"?tenant_id="+url.QueryEscape(c.Tenant), &out)
}

// Findings lists what was learned about mail after it was delivered.
func (c *EngineClient) Findings(ctx context.Context, state string) (*Findings, error) {
	q := url.Values{"tenant_id": {c.Tenant}}
	if state != "" {
		q.Set("state", state)
	}
	var out Findings
	return &out, c.get(ctx, "/v0/findings?"+q.Encode(), &out)
}

// ResolveFinding records what a person decided about one. It does not act on the
// message; the message's own actions are a separate, explicit step.
func (c *EngineClient) ResolveFinding(ctx context.Context, id, state string) error {
	body, _ := json.Marshal(map[string]string{"state": state, "tenant_id": c.Tenant})
	return c.post(ctx, "/v0/findings/"+url.PathEscape(id)+"/resolve", body, nil)
}

// Campaigns groups a window of mail into the attacks it actually was.
func (c *EngineClient) Campaigns(ctx context.Context, from, to string) (*Campaigns, error) {
	q := url.Values{"tenant_id": {c.Tenant}, "from": {from}, "to": {to}}
	var out Campaigns
	return &out, c.get(ctx, "/v0/campaigns?"+q.Encode(), &out)
}

func (c *EngineClient) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, into)
}

func (c *EngineClient) post(ctx context.Context, path string, body []byte, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, into)
}

// Login exchanges a password for an engine session.
func (c *EngineClient) Login(ctx context.Context, email, password string) (string, time.Time, error) {
	body, _ := json.Marshal(map[string]string{
		"email": email, "password": password, "tenant_id": c.Tenant,
	})
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := c.post(ctx, "/v0/auth/login", body, &out); err != nil {
		return "", time.Time{}, err
	}
	if out.Token == "" {
		return "", time.Time{}, errors.New("invalid credentials")
	}
	return out.Token, out.ExpiresAt, nil
}

// SSOLogin turns verified identity-provider claims into an engine session.
//
// Uses the service token rather than a caller's, because there is no caller yet — this
// is the step that creates one. It is the only place the dashboard's own credential is
// used, and the engine requires admin for it.
func (c *EngineClient) SSOLogin(ctx context.Context, serviceToken, issuer, subject, email, name, role string) (string, time.Time, error) {
	body, _ := json.Marshal(map[string]string{
		"issuer": issuer, "subject": subject, "email": email,
		"name": name, "tenant_id": c.Tenant, "role": role,
	})
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := c.post(WithToken(ctx, serviceToken), "/v0/auth/sso", body, &out); err != nil {
		return "", time.Time{}, err
	}
	return out.Token, out.ExpiresAt, nil
}

// Logout ends the engine session as well as clearing the cookie. Without this, signing
// out would leave a working token behind.
func (c *EngineClient) Logout(ctx context.Context) error {
	return c.post(ctx, "/v0/auth/logout", []byte("{}"), nil)
}

// WhoAmI resolves the caller.
func (c *EngineClient) WhoAmI(ctx context.Context) (*WhoAmI, error) {
	var out WhoAmI
	return &out, c.get(ctx, "/v0/auth/whoami", &out)
}

// allow400 are the endpoints whose 400 carries a result rather than a failure.
// Listed explicitly, because the alternative — tolerating 400 everywhere — turns every
// rejected request into a silent success.
var allow400 = map[string]bool{
	"/v0/rules/validate": true,
	"/v0/hunt-jobs":      true,
	// A backtest refuses a malformed rule with the compiler's diagnostics in the
	// body, which is the whole reason to test a rule here rather than by enabling it
	// and waiting.
	"/v0/backtests": true,
}

// EngineError is a refused request, carrying the status the engine gave.
//
// The status is kept rather than folded into the message because the console has to
// tell the cases apart: a 404 for a message that was purged is a normal thing to say
// plainly, while a 502 means the engine is down and the page should offer a retry.
// Flattening both to a string made every failure look like the same failure.
type EngineError struct {
	Status  int
	Message string
}

func (e *EngineError) Error() string { return "engine: " + e.Message }

// StatusOf reports the engine status behind an error, or 0 if it was not an engine
// refusal — a timeout or a dial failure has no status of its own.
func StatusOf(err error) int {
	var e *EngineError
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func (c *EngineClient) do(req *http.Request, into any) error {
	if token := tokenFrom(req.Context()); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	// A 400 is an error everywhere except validate and hunt, which answer a rejected
	// expression with a useful body — diagnostics with a caret — and want it decoded.
	// Treating 400 as success globally, which this did, meant a failed user creation
	// reported success: the engine refused, the response had no body to decode, and
	// the caller saw a nil error.
	tolerate400 := into != nil && allow400[req.URL.Path]
	if resp.StatusCode/100 != 2 && !(tolerate400 && resp.StatusCode == http.StatusBadRequest) {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(payload, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &EngineError{Status: resp.StatusCode, Message: e.Error}
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(payload, into)
}

// The richer reads the new views need.

// MessageDetail is everything known about one message, re-evaluated on demand.
// Insight is one evaluated fact about a message: the evidence behind a verdict.
type Insight struct {
	Label   string   `json:"label"`
	Group   string   `json:"group"`
	Value   any      `json:"value,omitempty"`
	Warn    bool     `json:"warn,omitempty"`
	Unknown bool     `json:"unknown,omitempty"`
	Missing []string `json:"missing,omitempty"`
}

// Display renders an insight value for a person rather than for a parser.
func (i Insight) Display() string {
	switch v := i.Value.(type) {
	case nil:
		return ""
	case bool:
		if v {
			return "yes"
		}
		return "no"
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', 2, 64)
	case []any:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprint(i.Value)
}

// AuthBadge is one authentication result, in three states rather than two.
type AuthBadge struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// SenderDetails is what is known about who sent a message.
type SenderDetails struct {
	Address     string `json:"address,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Domain      string `json:"domain,omitempty"`

	Prevalence string `json:"prevalence,omitempty"`
	Known      bool   `json:"known"`
	Solicited  bool   `json:"solicited"`
	SeenBenign bool   `json:"seen_benign"`
	SeenBad    bool   `json:"seen_bad"`

	RootDomain string `json:"root_domain,omitempty"`
	DomainInfo `tstype:",extends"`
}

// DomainInfo is the registry's view of a domain, in the one shape used wherever a
// domain is shown — the sender panel and the links table both render these fields, and
// a second shape for the same facts would drift.
//
// Known distinguishes "we could not ask" from "the registry answered"; Registered is
// only meaningful once Known is true. Collapsing the two is how an unreachable registry
// comes to look like a clean domain.
type DomainInfo struct {
	DomainKnown      bool `json:"domain_known"`
	DomainRegistered bool `json:"domain_registered"`

	// LookedUp is the name actually queried, which is the registrable domain rather
	// than the host when those differ.
	LookedUp string `json:"looked_up,omitempty"`

	DomainAgeDays     int64    `json:"domain_age_days,omitempty"`
	Registrar         string   `json:"registrar,omitempty"`
	RegistrantCompany string   `json:"registrant_company,omitempty"`
	RegistrantCountry string   `json:"registrant_country,omitempty"`
	RegistrantEmail   string   `json:"registrant_email,omitempty"`
	NameServers       []string `json:"name_servers,omitempty"`
}

// Age renders the registration age the way an analyst reads it, or says why it cannot.
func (d DomainInfo) Age() string {
	switch {
	case !d.DomainKnown:
		return "unknown"
	case !d.DomainRegistered:
		return "unregistered"
	case d.DomainAgeDays < 1:
		return "today"
	case d.DomainAgeDays < 90:
		return fmt.Sprintf("%d days", d.DomainAgeDays)
	case d.DomainAgeDays < 730:
		return fmt.Sprintf("%d months", d.DomainAgeDays/30)
	default:
		return fmt.Sprintf("%d years", d.DomainAgeDays/365)
	}
}

// NewDomain reports a registration recent enough to be worth colouring.
func (d DomainInfo) NewDomain() bool {
	return d.DomainKnown && d.DomainRegistered && d.DomainAgeDays < 30
}

// Registrant is the company and country as one line, empty when the registry gave
// neither — which is most of the time, since redaction is now the norm rather than
// the exception.
func (d DomainInfo) Registrant() string {
	switch {
	case d.RegistrantCompany != "" && d.RegistrantCountry != "":
		return d.RegistrantCompany + " (" + d.RegistrantCountry + ")"
	case d.RegistrantCompany != "":
		return d.RegistrantCompany
	default:
		return d.RegistrantCountry
	}
}

// MessageSummary is the identifying header block.
type MessageSummary struct {
	Subject     string   `json:"subject,omitempty"`
	Sender      string   `json:"sender,omitempty"`
	SenderName  string   `json:"sender_name,omitempty"`
	Recipients  []string `json:"recipients,omitempty"`
	ReplyTo     string   `json:"reply_to,omitempty"`
	ReturnPath  string   `json:"return_path,omitempty"`
	Date        string   `json:"date,omitempty"`
	Direction   string   `json:"direction,omitempty"`
	Mailer      string   `json:"mailer,omitempty"`
	MessageID   string   `json:"message_id,omitempty"`
	Attachments int      `json:"attachments"`
	Links       int      `json:"links"`
}

// ContentView is the message body in the forms an analyst needs.
type ContentView struct {
	Text        string `json:"text,omitempty"`
	HTML        string `json:"html,omitempty"`
	DisplayText string `json:"display_text,omitempty"`
	Subject     string `json:"subject,omitempty"`
}

type MessageDetail struct {
	// Held says the engine has the original bytes, which is what makes quarantine
	// reversible and therefore permitted.
	Held bool `json:"held"`

	// Renderable says the message has a body a browser could lay out, so the
	// Rendered tab asks the engine for a screenshot instead of falling back to text.
	Renderable bool `json:"renderable"`

	// Screenshot is a base64 PNG, present only for an analysis of a message that
	// was not stored: there is no endpoint to fetch one from afterwards, so it
	// comes with the answer.
	Screenshot string `json:"screenshot,omitempty"`

	// Transient marks an analysis of a message that was deliberately not recorded.
	// The view hides what cannot be acted on rather than offering broken buttons.
	Transient bool `json:"transient,omitempty"`

	// Disposition is an analyst's recorded judgement, once released.
	Disposition string `json:"disposition,omitempty"`

	Signals    []string       `json:"signals,omitempty"`
	Insights   []Insight      `json:"insights,omitempty"`
	AuthBadges []AuthBadge    `json:"auth_badges,omitempty"`
	Sender     SenderDetails  `json:"sender"`
	Summary    MessageSummary `json:"summary"`
	Content    ContentView    `json:"content"`

	// AnalysedAt is when the stored analysis was produced, and Recomputed says this
	// page ran the rules again instead of reading it. Shown, because "what the
	// rules say today" and "what they said when it arrived" are different claims.
	AnalysedAt string `json:"analysed_at,omitempty"`
	Recomputed bool   `json:"recomputed,omitempty"`

	// Learned is what this deployment's own model makes of the message, when one
	// has been trained and is better than guessing. Advisory.
	Learned *LearnedScore `json:"learned,omitempty"`

	MessageID        string          `json:"message_id"`
	MessageDataModel json.RawMessage `json:"message_data_model"`
	Detections       []Detection     `json:"detections"`
	Indeterminate    []Detection     `json:"indeterminate"`
	Excluded         []Detection     `json:"excluded"`
	Queries          map[string]any  `json:"queries"`
	Missing          []string        `json:"missing"`
	Authentication   map[string]any  `json:"authentication"`
	Links            []Link          `json:"links"`
	Origin           *Origin         `json:"origin"`
	Attachments      []Attachment    `json:"attachments"`
	Headers          map[string]any  `json:"headers"`
	Actions          []Action        `json:"actions"`
	Triage           TriageState     `json:"triage"`
}

// Link is one link and what the registry says about where it points.
//
// Typed rather than a map, and that is not a style preference: html/template resolves
// .URL on a map[string]any by looking up the key "URL", finds "url" instead, and renders
// an empty cell with no error. The count in the heading stays right, so the table looks
// populated and every row is blank.
type Link struct {
	URL         string `json:"url"`
	DisplayText string `json:"display_text"`
	Domain      string `json:"domain"`
	RootDomain  string `json:"root_domain"`

	// TextMismatch marks a link that displays one address and points at another.
	TextMismatch bool `json:"text_mismatch"`

	// Shortener marks a destination that is itself a redirect, hiding the real one.
	Shortener bool `json:"shortener"`

	DomainInfo `tstype:",extends"`
}

// Origin is the server that actually handed the message over.
//
// The address here is the one thing in a message a sender cannot forge — it is where
// the connection came from — but only when our own infrastructure recorded it.
// Authenticated says which of those two situations this is, and the page has to show
// the difference: acting on a header the sender wrote, believing it to be the origin,
// is a worse mistake than having no origin at all.
type Origin struct {
	IP            string `json:"ip"`
	Basis         string `json:"basis"`
	Authenticated bool   `json:"authenticated"`
	Helo          string `json:"helo"`
	RDNS          string `json:"rdns"`

	Known        bool     `json:"known"`
	Allocated    bool     `json:"allocated"`
	Organization string   `json:"organization"`
	Network      string   `json:"network"`
	Country      string   `json:"country"`
	RangeAgeDays int64    `json:"range_age_days"`
	AbuseEmail   string   `json:"abuse_email"`
	Status       []string `json:"status"`

	ASN             int64  `json:"asn"`
	ASNOrganization string `json:"asn_organization"`
	ASNCountry      string `json:"asn_country"`
}

// Owner is who holds the address range, falling back to the autonomous system when the
// registry redacted the netblock holder but the AS is still named.
func (o Origin) Owner() string {
	switch {
	case o.Organization != "":
		return o.Organization
	case o.ASNOrganization != "":
		return o.ASNOrganization
	default:
		return ""
	}
}

// AS renders the autonomous system as it is normally written.
func (o Origin) AS() string {
	if o.ASN == 0 {
		return ""
	}
	s := fmt.Sprintf("AS%d", o.ASN)
	if o.ASNOrganization != "" {
		s += " " + o.ASNOrganization
	}
	return s
}

// RangeAge is how long ago the netblock was allocated. A range handed out last month
// that is already sending mail is worth a second look.
func (o Origin) RangeAge() string {
	switch {
	case !o.Known || o.RangeAgeDays <= 0:
		return ""
	case o.RangeAgeDays < 365:
		return fmt.Sprintf("%d days", o.RangeAgeDays)
	default:
		return fmt.Sprintf("%d years", o.RangeAgeDays/365)
	}
}

// NewRange reports address space allocated recently enough to be unusual for mail.
func (o Origin) NewRange() bool { return o.Known && o.RangeAgeDays > 0 && o.RangeAgeDays < 180 }

// Attachment is one attachment as the message describes it.
type Attachment struct {
	FileName    string `json:"file_name"`
	Extension   string `json:"extension"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	MD5         string `json:"md5"`
	SHA256      string `json:"sha256"`
}

// HumanSize renders bytes at the precision a person cares about.
func (a Attachment) HumanSize() string {
	switch {
	case a.Size >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(a.Size)/(1<<20))
	case a.Size >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(a.Size)/(1<<10))
	default:
		return fmt.Sprintf("%d B", a.Size)
	}
}

// Detection is one rule's outcome with enough to explain it.
type Detection struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Techniques  []string `json:"techniques"`
	AttackTypes []string `json:"attack_types"`
	Missing     []string `json:"missing"`
	Source      string   `json:"source"`
}

type TriageState struct {
	MessageID  string     `json:"message_id"`
	State      string     `json:"state"`
	Assignee   string     `json:"assignee"`
	ReviewedBy string     `json:"reviewed_by"`
	ReviewedAt *time.Time `json:"reviewed_at"`
	Note       string     `json:"note"`
}

type Coverage struct {
	Loaded          int `json:"loaded"`
	FullyAnswerable int `json:"fully_answerable"`
	Blocked         int `json:"blocked"`
	Capabilities    []struct {
		Capability string `json:"capability"`
		Rules      int    `json:"rules"`
		Available  bool   `json:"available"`
	} `json:"capabilities"`
	Providers        []string `json:"providers"`
	ListsUnavailable []string `json:"lists_unavailable"`
}

type Effectiveness struct {
	Rules []struct {
		Rule       string `json:"rule"`
		Fired      int64  `json:"fired"`
		Confirmed  int64  `json:"confirmed"`
		Benign     int64  `json:"benign"`
		Ignored    int64  `json:"ignored"`
		Unreviewed int64  `json:"unreviewed"`
	} `json:"rules"`
	Dormant      []string `json:"dormant"`
	DormantCount int      `json:"dormant_count"`
	Loaded       int      `json:"loaded"`
}

func (c *EngineClient) Detail(ctx context.Context, id string) (*MessageDetail, error) {
	var out MessageDetail
	return &out, c.get(ctx, "/v0/messages/"+url.PathEscape(id), &out)
}

func (c *EngineClient) TriageCounts(ctx context.Context, from, to time.Time) (map[string]int, int, error) {
	var out struct {
		Counts  map[string]int `json:"counts"`
		Flagged int            `json:"flagged"`
	}
	err := c.get(ctx, "/v0/triage/counts?"+window(from, to), &out)
	return out.Counts, out.Flagged, err
}

func (c *EngineClient) SetTriage(ctx context.Context, id, state, note string) error {
	body, _ := json.Marshal(map[string]string{"state": state, "note": note})
	return c.post(ctx, "/v0/messages/"+url.PathEscape(id)+"/triage", body, nil)
}

func (c *EngineClient) Coverage(ctx context.Context) (*Coverage, error) {
	var out Coverage
	return &out, c.get(ctx, "/v0/coverage", &out)
}

func (c *EngineClient) Effectiveness(ctx context.Context, from, to time.Time) (*Effectiveness, error) {
	var out Effectiveness
	return &out, c.get(ctx, "/v0/rule-effectiveness?"+window(from, to), &out)
}

func (c *EngineClient) Rule(ctx context.Context, id string) (map[string]any, error) {
	var out map[string]any
	return out, c.get(ctx, "/v0/rules/"+url.PathEscape(id), &out)
}

// Analyze runs the rule set over a pasted message without recording it.
func (c *EngineClient) Analyze(ctx context.Context, raw []byte) (map[string]any, error) {
	body, _ := json.Marshal(map[string]string{
		"raw_message": base64.StdEncoding.EncodeToString(raw),
	})
	var out map[string]any
	return out, c.post(ctx, "/v0/messages/analyze", body, &out)
}

func (c *EngineClient) Users(ctx context.Context) ([]User, error) {
	var out struct {
		Users []User `json:"users"`
	}
	return out.Users, c.get(ctx, "/v0/users", &out)
}

func (c *EngineClient) CreateUser(ctx context.Context, email, name, password, role string) error {
	body, _ := json.Marshal(map[string]string{
		"email": email, "name": name, "password": password, "role": role,
	})
	return c.post(ctx, "/v0/users", body, nil)
}

func (c *EngineClient) UpdateUser(ctx context.Context, id string, patch map[string]any) error {
	body, _ := json.Marshal(patch)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.Base+"/v0/users/"+url.PathEscape(id), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *EngineClient) CreateToken(ctx context.Context, name, role string) (string, error) {
	body, _ := json.Marshal(map[string]string{"name": name, "role": role})
	var out struct {
		Token string `json:"token"`
	}
	return out.Token, c.post(ctx, "/v0/tokens", body, &out)
}

type User struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	Disabled  bool       `json:"disabled"`
	Local     bool       `json:"local"`
	SSO       bool       `json:"sso"`
	LastLogin *time.Time `json:"last_login"`
}

func window(from, to time.Time) string {
	return url.Values{
		"from": {from.Format(time.RFC3339)},
		"to":   {to.Format(time.RFC3339)},
	}.Encode()
}

// ---------------------------------------------------------------------------
// Settings: lists, mailboxes, the organisation
// ---------------------------------------------------------------------------

// ListConfig is one named list as the settings page shows it.
type ListConfig struct {
	LastRefresh *time.Time `json:"last_refresh,omitempty"`
	Name        string     `json:"name"`
	Source      string     `json:"source"`
	URL         string     `json:"url,omitempty"`
	Format      string     `json:"format,omitempty"`
	Description string     `json:"description,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	Refresh     int        `json:"refresh_every_seconds"`
	Entries     int64      `json:"entry_count"`
	Includes    int        `json:"includes"`
	Excludes    int        `json:"excludes"`
	RulesUsing  int        `json:"rules_using"`
	Enabled     bool       `json:"enabled"`
	Resolvable  bool       `json:"resolvable"`
	HasAuth     bool       `json:"has_auth"`
}

// RefreshHours is the refresh interval in whole hours, for the form.
func (l ListConfig) RefreshHours() int { return l.Refresh / 3600 }

// Blocked reports a list that rules depend on and that cannot currently be resolved.
// This is the row a settings page should draw attention to: it is the difference
// between a rule being off and a rule being quietly unanswerable.
func (l ListConfig) Blocked() bool { return l.RulesUsing > 0 && !l.Resolvable }

type ListOverride struct {
	Name    string    `json:"name"`
	Value   string    `json:"value"`
	Kind    string    `json:"kind"`
	Note    string    `json:"note,omitempty"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

type Mailbox struct {
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Address   string     `json:"address"`
	Host      string     `json:"host,omitempty"`
	Username  string     `json:"username,omitempty"`
	TLSMode   string     `json:"tls_mode,omitempty"`
	Folder    string     `json:"folder,omitempty"`
	GraphUser string     `json:"graph_user,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	Messages  int64      `json:"messages"`
	Enabled   bool       `json:"enabled"`
	Remediate bool       `json:"remediate"`
	HasSecret bool       `json:"has_secret"`
}

type OrgConfig struct {
	Domains      []string `json:"domains"`
	VIPs         []OrgVIP `json:"vips"`
	DisplayNames []string `json:"display_names"`
}

type OrgVIP struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

func (c *EngineClient) Lists(ctx context.Context) ([]ListConfig, []string, error) {
	var out struct {
		Lists        []ListConfig `json:"lists"`
		Unconfigured []string     `json:"unconfigured"`
	}
	err := c.get(ctx, "/v0/lists", &out)
	return out.Lists, out.Unconfigured, err
}

func (c *EngineClient) List(ctx context.Context, name string) (*ListConfig, []ListOverride, []string, int, error) {
	var out struct {
		List      ListConfig     `json:"list"`
		Overrides []ListOverride `json:"overrides"`
		Sample    []string       `json:"sample"`
		Resolved  int            `json:"resolved_count"`
		Refresh   int            `json:"refresh_every_seconds"`
	}
	err := c.get(ctx, "/v0/lists/"+url.PathEscape(name), &out)
	out.List.Refresh = out.Refresh
	return &out.List, out.Overrides, out.Sample, out.Resolved, err
}

func (c *EngineClient) UpdateList(ctx context.Context, name string, patch map[string]any) error {
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	return c.patch(ctx, "/v0/lists/"+url.PathEscape(name), body)
}

func (c *EngineClient) AddListEntry(ctx context.Context, name, value, kind, note string) error {
	body, _ := json.Marshal(map[string]string{"value": value, "kind": kind, "note": note})
	return c.post(ctx, "/v0/lists/"+url.PathEscape(name)+"/entries", body, nil)
}

func (c *EngineClient) RemoveListEntry(ctx context.Context, name, value, kind string) error {
	q := url.Values{"value": {value}, "kind": {kind}}
	return c.delete(ctx, "/v0/lists/"+url.PathEscape(name)+"/entries?"+q.Encode())
}

func (c *EngineClient) RefreshList(ctx context.Context, name string) error {
	return c.post(ctx, "/v0/lists/"+url.PathEscape(name)+"/refresh", nil, nil)
}

// Remediation is queued work for a connector: a message to remove from a mailbox, or
// one to put back.
type Remediation struct {
	ID        int64      `json:"id"`
	MessageID string     `json:"message_id"`
	MailboxID string     `json:"mailbox_id"`
	Op        string     `json:"op"`
	State     string     `json:"state"`
	Attempts  int        `json:"attempts"`
	LastError string     `json:"last_error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	DoneAt    *time.Time `json:"done_at,omitempty"`
}

func (c *EngineClient) Remediations(ctx context.Context) ([]Remediation, error) {
	var out struct {
		Remediations []Remediation `json:"remediations"`
	}
	err := c.get(ctx, "/v0/remediations", &out)
	return out.Remediations, err
}

func (c *EngineClient) Mailboxes(ctx context.Context) ([]Mailbox, error) {
	var out struct {
		Mailboxes []Mailbox `json:"mailboxes"`
	}
	err := c.get(ctx, "/v0/mailboxes", &out)
	return out.Mailboxes, err
}

func (c *EngineClient) SaveMailbox(ctx context.Context, m map[string]any) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return c.post(ctx, "/v0/mailboxes", body, nil)
}

func (c *EngineClient) DeleteMailbox(ctx context.Context, id string) error {
	return c.delete(ctx, "/v0/mailboxes/"+url.PathEscape(id))
}

// SetMailboxEnabled pauses or resumes collection from one mailbox, without touching
// anything else about it — notably not the stored credential.
func (c *EngineClient) SetMailboxEnabled(ctx context.Context, id string, enabled bool) error {
	body, _ := json.Marshal(map[string]bool{"enabled": enabled})
	return c.post(ctx, "/v0/mailboxes/"+url.PathEscape(id)+"/enabled", body, nil)
}

// GraphDirectoryUser is one account in the Microsoft directory.
type GraphDirectoryUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"display_name,omitempty"`
	UserPrincipalName string `json:"user_principal_name"`

	// Always present: the engine only returns accounts that have one.
	Mail           string `json:"mail"`
	AccountEnabled bool   `json:"account_enabled"`
	UserType       string `json:"user_type,omitempty"`

	// Configured says this address is already collected here.
	Configured bool `json:"configured"`
}

// GraphDirectory is what a walk of the tenant found.
//
// The three counts are one sentence and are meaningless apart: "460 accounts, 431 with
// a mailbox, 412 already collected" tells an administrator where they stand, while any
// one number alone invites the wrong conclusion.
type GraphDirectory struct {
	Users             []GraphDirectoryUser `json:"users"`
	AccountsInDirect  int                  `json:"accounts_in_directory"`
	WithMailboxes     int                  `json:"with_mailboxes"`
	AlreadyConfigured int                  `json:"already_configured"`
}

// Directory walks the Microsoft tenant and reports what could be collected.
func (c *EngineClient) Directory(ctx context.Context) (*GraphDirectory, error) {
	var out GraphDirectory
	return &out, c.get(ctx, "/v0/graph/directory", &out)
}

// BulkAdded is the outcome of onboarding an estate.
type BulkAdded struct {
	Added   int      `json:"added"`
	Skipped []string `json:"skipped"`
	Enabled bool     `json:"enabled"`
	Error   string   `json:"error,omitempty"`
}

// AddMailboxes configures several Microsoft mailboxes at once.
func (c *EngineClient) AddMailboxes(ctx context.Context, addresses []string, enabled bool) (*BulkAdded, error) {
	body, _ := json.Marshal(map[string]any{"addresses": addresses, "enabled": enabled})
	var out BulkAdded
	return &out, c.post(ctx, "/v0/mailboxes/bulk", body, &out)
}

func (c *EngineClient) Org(ctx context.Context) (*OrgConfig, error) {
	var out OrgConfig
	err := c.get(ctx, "/v0/org", &out)
	return &out, err
}

func (c *EngineClient) SaveOrg(ctx context.Context, o OrgConfig) error {
	body, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return c.put(ctx, "/v0/org", body)
}

func (c *EngineClient) patch(ctx context.Context, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *EngineClient) put(ctx context.Context, path string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *EngineClient) delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.Base+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// ---------------------------------------------------------------------------
// The learned model
// ---------------------------------------------------------------------------

// Contribution is one feature's pull on a learned score.
type Contribution struct {
	Feature string  `json:"feature"`
	Weight  float64 `json:"weight"`
	Toward  string  `json:"toward"`
}

// Strength renders a weight as a width, for a bar an eye can compare.
func (c Contribution) Strength() int {
	w := c.Weight
	if w < 0 {
		w = -w
	}
	n := int(w * 40)
	if n > 100 {
		n = 100
	}
	if n < 3 {
		n = 3
	}
	return n
}

// LearnedScore is the model's advisory opinion on one message.
type LearnedScore struct {
	Score     float64        `json:"score"`
	Agreement string         `json:"agreement"`
	Why       []Contribution `json:"why,omitempty"`
	Version   int            `json:"version,omitempty"`
	Advisory  bool           `json:"advisory"`
}

// Percent is the score as a whole number, which is how a person reads it.
func (l LearnedScore) Percent() int { return int(l.Score*100 + 0.5) }

// ModelReport is the state of the learned model, for the settings page.
type ModelReport struct {
	Trained   bool           `json:"trained"`
	Useful    bool           `json:"useful"`
	Version   int            `json:"version"`
	TrainedAt string         `json:"trained_at,omitempty"`
	Reviews   int            `json:"reviews"`
	Confirmed int            `json:"confirmed"`
	Dismissed int            `json:"dismissed"`
	Accuracy  float64        `json:"accuracy"`
	Baseline  float64        `json:"baseline"`
	Top       []Contribution `json:"top,omitempty"`

	NeedTotal   int `json:"need_total"`
	NeedPerSide int `json:"need_per_side"`
}

func (m ModelReport) AccuracyPct() int { return int(m.Accuracy*100 + 0.5) }
func (m ModelReport) BaselinePct() int { return int(m.Baseline*100 + 0.5) }

// Shortfall is how many more reviews are needed before training is possible, and of
// which kind. Shown instead of "no model", because "23 more dismissals" is something
// an operator can act on.
func (m ModelReport) Shortfall() string {
	if m.Trained {
		return ""
	}
	switch {
	case m.Reviews < m.NeedTotal:
		return fmt.Sprintf("%d more reviewed messages", m.NeedTotal-m.Reviews)
	case m.Confirmed < m.NeedPerSide:
		return fmt.Sprintf("%d more confirmed detections", m.NeedPerSide-m.Confirmed)
	case m.Dismissed < m.NeedPerSide:
		return fmt.Sprintf("%d more dismissed detections", m.NeedPerSide-m.Dismissed)
	}
	return "enough reviews — train it"
}

func (c *EngineClient) Model(ctx context.Context) (*ModelReport, error) {
	var out ModelReport
	err := c.get(ctx, "/v0/model", &out)
	return &out, err
}

func (c *EngineClient) TrainModel(ctx context.Context) error {
	return c.post(ctx, "/v0/model/train", []byte(`{}`), nil)
}

func (c *EngineClient) ForgetModel(ctx context.Context) error {
	return c.delete(ctx, "/v0/model")
}

// Blob fetches a binary resource from the engine and hands back the response for
// streaming, rather than reading it into memory like every other call here.
//
// Screenshots and original messages are megabytes, not kilobytes, and buffering them
// twice — once in the client, once in the response writer — to serve a picture is
// waste that grows with how many analysts are working at once. The caller closes the
// body.
func (c *EngineClient) Blob(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return nil, err
	}
	if token := tokenFrom(ctx); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNoContent {
		defer resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, fmt.Errorf("engine: %s", e.Error)
	}
	return resp, nil
}

// AnalyzeDetail runs the rule set over a message without storing it, and returns
// everything the message page shows rather than just the verdict.
//
// Same endpoint as Analyze and the same request; the engine answers the documented
// fields plus the detail ones, so this is a second reading of one response rather
// than a second call.
func (c *EngineClient) AnalyzeDetail(ctx context.Context, raw []byte) (*MessageDetail, error) {
	body, err := json.Marshal(map[string]string{
		"raw_message": base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.Base+"/v0/messages/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	var out MessageDetail
	return &out, c.do(req, &out)
}

// Backfill is one retrospective scan of a mailbox's existing mail.
type Backfill struct {
	ID        string     `json:"id"`
	MailboxID string     `json:"mailbox_id"`
	Since     time.Time  `json:"since"`
	Until     time.Time  `json:"until"`
	State     string     `json:"state"`
	Cursor    *time.Time `json:"cursor"`

	Examined   int64 `json:"examined"`
	Ingested   int64 `json:"ingested"`
	Duplicates int64 `json:"duplicates"`
	Flagged    int64 `json:"flagged"`
	Failures   int64 `json:"failures"`

	KeepRaw   bool   `json:"keep_raw"`
	LastError string `json:"last_error"`

	// When LastError happened. The engine keeps the text sticky so a transient
	// failure leaves a record, which means the text on its own cannot be read as
	// the scan's current condition — see the console, which shows it against the
	// failure count and this time rather than beside the state.
	LastErrorAt *time.Time `json:"last_error_at"`

	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// Running reports a scan that is still doing work.
func (b Backfill) Running() bool {
	switch b.State {
	case "pending", "running", "paused":
		return true
	}
	return false
}

// Percent is how far through the window the scan has reached.
//
// By time rather than by message count, because the count is not known until the
// walk ends — so it moves unevenly, as mail is not spread evenly through a window.
func (b Backfill) Percent() int {
	if b.Cursor == nil {
		return 0
	}
	span := b.Until.Sub(b.Since)
	if span <= 0 {
		return 100
	}
	done := b.Cursor.Sub(b.Since)
	switch {
	case done <= 0:
		return 0
	case done >= span:
		return 100
	default:
		return int(float64(done) / float64(span) * 100)
	}
}

// Window is the scan's range, as a person reads it.
func (b Backfill) Window() string {
	return b.Since.Format("2 Jan") + " – " + b.Until.Format("2 Jan 2006")
}

func (c *EngineClient) Backfills(ctx context.Context) ([]Backfill, error) {
	var out struct {
		Backfills []Backfill `json:"backfills"`
	}
	return out.Backfills, c.get(ctx, "/v0/backfills", &out)
}

func (c *EngineClient) StartBackfill(ctx context.Context, mailboxID string, days int, keepRaw bool) (*Backfill, error) {
	body, err := json.Marshal(map[string]any{
		"mailbox_id": mailboxID, "days": days, "keep_raw": keepRaw,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/v0/backfills", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	var out Backfill
	return &out, c.do(req, &out)
}

func (c *EngineClient) CancelBackfill(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.Base+"/v0/backfills/"+url.PathEscape(id)+"/cancel", nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// RecheckMailbox forgets the last connection result so the next connector report
// repopulates it.
func (c *EngineClient) RecheckMailbox(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.Base+"/v0/mailboxes/"+url.PathEscape(id)+"/recheck", nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// GraphApp is the Microsoft 365 application registration.
//
// One per deployment: it is an app registration in a directory with permission over
// the mailboxes in it, so every Microsoft mailbox authenticates through the same
// one. The client secret is write-only here — the engine will not return it to a
// browser session, only to a connector's service token.
type GraphApp struct {
	DirectoryID string `json:"directory_id"`
	ClientID    string `json:"client_id"`

	// Cloud is which Microsoft cloud the tenant is in: "" or "public", "usgov"
	// (GCC High), "usgovdod", "china" (21Vianet). It was a pair of connector flags,
	// which meant a sovereign-cloud deployment configured it in a compose file.
	Cloud string `json:"cloud,omitempty"`
	// NotifyURL is derived by the engine from the deployment's public address
	// and is read-only here — it is shown so an administrator knows what to
	// allow through their proxy, not so they can change it.
	NotifyURL string     `json:"notify_url"`
	HasSecret bool       `json:"has_secret"`
	UpdatedAt *time.Time `json:"updated_at"`
	UpdatedBy string     `json:"updated_by"`
}

// Configured reports a registration complete enough for the connector to use.
func (g GraphApp) Configured() bool {
	return g.DirectoryID != "" && g.ClientID != "" && g.HasSecret
}

// Webhook reports whether Graph will push notifications rather than being polled.
func (g GraphApp) Webhook() bool { return g.NotifyURL != "" }

func (c *EngineClient) GraphApp(ctx context.Context) (*GraphApp, error) {
	var out GraphApp
	return &out, c.get(ctx, "/v0/graph-app", &out)
}

func (c *EngineClient) SaveGraphApp(ctx context.Context, g GraphApp, secret string) error {
	payload := map[string]any{
		"directory_id": g.DirectoryID,
		"client_id":    g.ClientID,
		"cloud":        g.Cloud,
	}
	// Omitted when blank, so saving the form without retyping the secret keeps
	// the stored one rather than clearing it.
	if secret != "" {
		payload["client_secret"] = secret
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.Base+"/v0/graph-app", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *EngineClient) DeleteGraphApp(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.Base+"/v0/graph-app", nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// ActionType is something the platform knows how to do.
type ActionType struct {
	Type           string        `json:"type"`
	Label          string        `json:"label"`
	Detail         string        `json:"detail"`
	Destructive    bool          `json:"destructive"`
	NeedsCustody   bool          `json:"needs_custody"`
	TouchesMailbox bool          `json:"touches_mailbox"`
	Providers      []string      `json:"providers"`
	Params         []ActionParam `json:"params"`
}

// ActionParam is one setting an instance of a type needs.
type ActionParam struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Detail      string `json:"detail"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder"`
}

// ConfiguredAction is a named, configured action that rules are attached to.
type ConfiguredAction struct {
	ID        string            `json:"id"`
	Label     string            `json:"label"`
	Type      string            `json:"type"`
	Config    map[string]string `json:"config"`
	Enabled   bool              `json:"enabled"`
	Rules     int               `json:"rules"`
	UpdatedAt time.Time         `json:"updated_at"`
	UpdatedBy string            `json:"updated_by"`
}

func (c *EngineClient) ActionTypes(ctx context.Context) ([]ActionType, error) {
	var out struct {
		Types []ActionType `json:"types"`
	}
	return out.Types, c.get(ctx, "/v0/action-types", &out)
}

func (c *EngineClient) ConfiguredActions(ctx context.Context) ([]ConfiguredAction, error) {
	var out struct {
		Actions []ConfiguredAction `json:"actions"`
	}
	return out.Actions, c.get(ctx, "/v0/actions", &out)
}

func (c *EngineClient) SaveAction(ctx context.Context, a ConfiguredAction) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/v0/actions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

func (c *EngineClient) DeleteAction(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.Base+"/v0/actions/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// RuleActions maps rule id to the actions configured on it.
func (c *EngineClient) RuleActions(ctx context.Context) (map[string][]ConfiguredAction, error) {
	var out struct {
		Rules map[string][]ConfiguredAction `json:"rules"`
	}
	return out.Rules, c.get(ctx, "/v0/rule-actions", &out)
}

// AttachActions adds or removes actions across a set of rules.
func (c *EngineClient) AttachActions(ctx context.Context, ruleIDs, actionIDs []string, remove bool) error {
	body, err := json.Marshal(map[string]any{
		"rule_ids": ruleIDs, "action_ids": actionIDs, "remove": remove,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.Base+"/v0/rule-actions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, nil)
}

// ---------------------------------------------------------------------------
// Rule feeds
// ---------------------------------------------------------------------------

// RuleFeed is a git repository of detection content.
//
// Secret is absent by design: the token is write-only from the console's point of
// view, exactly as a mailbox credential is. HasSecret is what the page renders.
type RuleFeed struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Branch string `json:"branch,omitempty"`
	Subdir string `json:"subdir,omitempty"`

	Enabled   bool `json:"enabled"`
	EverySecs int  `json:"every_seconds"`
	HasSecret bool `json:"has_secret"`

	LastSync   *time.Time `json:"last_sync,omitempty"`
	LastCommit string     `json:"last_commit,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	RuleCount  int        `json:"rule_count"`

	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (c *EngineClient) RuleFeeds(ctx context.Context) ([]RuleFeed, error) {
	var out struct {
		Feeds []RuleFeed `json:"feeds"`
	}
	return out.Feeds, c.get(ctx, "/v0/rule-feeds", &out)
}

func (c *EngineClient) SaveRuleFeed(ctx context.Context, f RuleFeed, secret string) error {
	body, err := json.Marshal(struct {
		RuleFeed
		Secret string `json:"secret"`
	}{RuleFeed: f, Secret: secret})
	if err != nil {
		return err
	}
	return c.post(ctx, "/v0/rule-feeds", body, nil)
}

func (c *EngineClient) DeleteRuleFeed(ctx context.Context, id string) error {
	return c.delete(ctx, "/v0/rule-feeds/"+url.PathEscape(id))
}

// SyncRuleFeed pulls one now. The engine answers 200 with ok=false when the pull
// itself failed, so the caller gets the reason rather than a bare status.
func (c *EngineClient) SyncRuleFeed(ctx context.Context, id string) (map[string]any, error) {
	var out map[string]any
	err := c.post(ctx, "/v0/rule-feeds/"+url.PathEscape(id)+"/sync", nil, &out)
	return out, err
}

// MQLSchema is what the editor needs to offer completions: the engine's own
// function registry, the MDM type graph and the lists that resolve here.
//
// Passed through verbatim rather than reshaped. The console renders it; the engine
// decides what MQL is.
func (c *EngineClient) MQLSchema(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	return out, c.get(ctx, "/v0/mql/schema", &out)
}
