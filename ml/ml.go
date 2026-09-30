// SPDX-License-Identifier: AGPL-3.0-only

// Package ml answers the model-backed capabilities from a lazaret-ml service.
//
// What is left in this namespace after the rest of it was implemented elsewhere:
//
//	ml.nlu_classifier        731 corpus calls
//	ml.logo_detect           127
//	beta.ml_topic             18
//	ml.attack_score            7
//	ml.macro_classifier        4
//	beta.ml_translate          2
//	beta.fuzzy_attack_score    2
//
// The larger part of the ml.* surface turned out not to need a model at all.
// beta.ml_extract_sensitive_information (304 calls) is patterns and checksums, in
// package sensitive. beta.ocr, beta.scan_qr and beta.parse_exif are Strelka scanners.
// Three-quarters of what the corpus reads off ml.link_analysis is a browser's
// observations, in package render. Separating those out is what left this package with
// only the irreducible part.
//
// A capability with no model loaded reports unavailable, so the rule reports
// indeterminate. See the service's documentation for why that is preferred to a weak
// classifier: the corpus negates these functions to exclude benign mail, and a model
// that cannot recognise benign mail makes those negations fire.
package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mql"
)

// Options configure a Client.
type Options struct {
	// Address is the base URL of a lazaret-ml, e.g. http://localhost:8720.
	Address string

	// Timeout bounds one inference.
	Timeout time.Duration

	// HTTPClient overrides the default.
	HTTPClient *http.Client
}

func (o *Options) timeout() time.Duration {
	if o != nil && o.Timeout > 0 {
		return o.Timeout
	}
	return 30 * time.Second
}

// Client talks to a lazaret-ml.
type Client struct {
	addr string
	http *http.Client
}

// New returns a client for the service at addr.
func New(opts *Options) *Client {
	c := &Client{}
	if opts != nil {
		c.addr = opts.Address
		c.http = opts.HTTPClient
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: opts.timeout()}
	}
	return c
}

// capabilityPath maps a capability to the service endpoint that answers it. The two
// strings are the same by construction, so a rule, a log line and a model file all use
// one name.
var capabilityPath = map[enrich.Capability]string{
	enrich.CapMLNLUClassifier:   "ml.nlu_classifier",
	enrich.CapMLLogoDetect:      "ml.logo_detect",
	enrich.CapMLMacroClassifier: "ml.macro_classifier",
	enrich.CapMLAttackScore:     "ml.attack_score",
	enrich.CapBetaMLTopic:       "beta.ml_topic",
	enrich.CapBetaTranslate:     "beta.ml_translate",
	enrich.CapBetaFuzzyScore:    "beta.fuzzy_attack_score",
}

// Capabilities are what this client can answer, for registering with an mql.MuxEnricher.
func Capabilities() []enrich.Capability {
	out := make([]enrich.Capability, 0, len(capabilityPath))
	for c := range capabilityPath {
		out = append(out, c)
	}
	return out
}

// Enrich implements mql.Enricher.
func (c *Client) Enrich(ctx context.Context, cap enrich.Capability, args []mql.Value, kwargs map[string]mql.Value) (mql.Value, error) {
	path, ok := capabilityPath[cap]
	if !ok {
		return mql.NullValue, enrich.NotImplemented(cap)
	}
	if c == nil || c.addr == "" {
		return mql.NullValue, enrich.NotImplemented(cap)
	}
	if len(args) == 0 {
		return mql.NullValue, nil
	}

	req := request{Options: map[string]string{}}

	// Which capabilities take an image, by name, rather than by asking the value
	// what it is.
	//
	// The obvious version of this was `if b, ok := args[0].AsBytes(); ok` — and
	// AsBytes succeeds on a *string*, returning its bytes. So every message body
	// went into the image field, req.Text stayed empty, and the service reported
	// intents, topics and tags unavailable because it had been handed no text. All
	// 358 rules that read .intents were quietly indeterminate on a deployment where
	// the model was loaded and working, and the service's own tests could not see
	// it because they call it directly.
	wantsImage := cap == enrich.CapMLLogoDetect

	if b, ok := args[0].AsBytes(); wantsImage && ok && len(b) > 0 {
		req.Image = b
		// The wordmark half of brand detection reads text a scanner already found in
		// the image. Most of the brands the corpus asks about — PayPal, Netflix,
		// Norton, DocuSign — have a logo that is their name in a typeface, so OCR
		// finds them and no reference pack is needed. Strelka has already run by the
		// time this is called, so the text is to hand.
		if cap == enrich.CapMLLogoDetect {
			if t := ocrTextOf(args[0]); t != "" {
				req.Options["ocr_text"] = t
			}
		}
	} else if s := textOf(args[0]); strings.TrimSpace(s) != "" {
		req.Text = s
	} else if cap == enrich.CapMLAttackScore || cap == enrich.CapBetaFuzzyScore {
		// These two take no argument and judge the whole message, so the evaluator
		// passes the message itself. What goes over the wire is a named subset
		// rather than the model, so widening it is a visible change on both sides.
		req.MDM = messageSubset(args[0])
		if req.MDM == nil {
			return mql.NullValue, nil
		}
	} else {
		return mql.NullValue, nil
	}
	for k, v := range kwargs {
		req.Options[k] = v.String()
	}

	raw, err := c.post(ctx, path, req)
	if err != nil {
		return mql.NullValue, err
	}

	// The service returns the capability's published output shape as JSON, so it is
	// handed to the evaluator as decoded data rather than being remapped here. A
	// mapping layer would be a second place for the shape to drift.
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return mql.NullValue, fmt.Errorf("ml: decoding %s: %w", path, err)
	}

	// A capability can answer part of itself. ml.nlu_classifier with no entailment
	// model returns entities and language and omits intents, topics and tags; brand
	// detection reads wordmarks without a reference pack but not symbols.
	//
	// The unanswerable field names are qualified with the capability and left on the
	// value rather than deleted, so that reading one produces a null that knows why
	// — and the tracker records it at the point a rule actually reaches for it. A
	// rule that only read the half which worked is not reported as degraded, which
	// is the difference between a useful "missing capabilities" list and one that
	// names something on every message.
	if m, ok := decoded.(map[string]any); ok {
		if whole := qualifyUnavailable(m, string(cap)); whole {
			// The whole capability failed, so there is no field for a rule to
			// reach for and nothing to defer. Recorded now.
			enrich.RecordPartial(ctx, cap)
		}
	}
	return mql.JSONValue(decoded), nil
}

// qualifyUnavailable rewrites the service's field names into capability-qualified
// ones, and normalises the whole-capability form.
//
// Two shapes arrive. A list of field names — ["intents","topics"] — becomes
// ["ml.nlu_classifier.intents", …]. A bare `true`, which is how the single-valued
// capabilities say they could not answer at all, is recorded immediately, because
// there is no field for a rule to reach for.
// It reports whether the capability failed as a whole.
func qualifyUnavailable(m map[string]any, cap string) (whole bool) {
	switch u := m["unavailable"].(type) {
	case []any:
		out := make([]any, 0, len(u))
		for _, it := range u {
			if s, ok := it.(string); ok {
				out = append(out, cap+"."+s)
			}
		}
		if len(out) == 0 {
			delete(m, "unavailable")
			return false
		}
		m["unavailable"] = out
		return false
	case bool:
		delete(m, "unavailable")
		return u
	default:
		delete(m, "unavailable")
		return false
	}
}

// messageSubset extracts what the attack-score capabilities need from a message.
func messageSubset(v mql.Value) json.RawMessage {
	get := func(path ...string) string {
		cur := v
		for _, p := range path {
			cur = cur.Field(p)
		}
		s, _ := cur.AsString()
		return s
	}
	out := map[string]any{
		"subject":       get("subject", "subject"),
		"body":          get("body", "current_thread", "text"),
		"sender_domain": get("sender", "email", "domain", "domain"),
	}
	headers := map[string]any{
		"list_unsubscribe": get("headers", "list_unsubscribe"),
		"precedence":       get("headers", "precedence"),
		"auto_submitted":   get("headers", "auto_submitted"),
	}
	// Whatever else the parser kept, by name. The service looks for a fixed set of
	// campaign headers in here rather than being sent every header there is.
	other := map[string]string{}
	if hs := v.Field("headers").Field("all"); !hs.IsNull() {
		for _, h := range hs.Elements() {
			if n, ok := h.Field("name").AsString(); ok {
				val, _ := h.Field("value").AsString()
				other[n] = val
			}
		}
	}
	headers["other"] = other
	out["headers"] = headers

	auth := map[string]any{}
	for key, path := range map[string][]string{
		"dmarc_pass": {"headers", "auth_summary", "dmarc", "pass"},
		"spf_pass":   {"headers", "auth_summary", "spf", "pass"},
		"dkim_pass":  {"headers", "auth_summary", "dkim", "pass"},
	} {
		cur := v
		for _, p := range path {
			cur = cur.Field(p)
		}
		if b, ok := cur.AsBool(); ok {
			auth[key] = b
		}
	}
	out["auth"] = auth

	out["link_count"] = len(v.Field("body").Field("links").Elements())
	out["attached_files"] = len(v.Field("attachments").Elements())

	raw, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return raw
}

// ocrTextOf finds the text a scanner already read out of an image.
func ocrTextOf(v mql.Value) string {
	for _, path := range [][]string{
		{"scan", "ocr", "text"},
		{"scan", "ocr", "raw"},
		{"ocr", "text"},
	} {
		cur := v
		for _, p := range path {
			cur = cur.Field(p)
		}
		if s, ok := cur.AsString(); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func (c *Client) post(ctx context.Context, path string, in request) ([]byte, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+"/v1/"+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &enrich.Unavailable{Capability: enrich.Capability(path), Reason: "unreachable", Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		return body, nil
	case resp.StatusCode == http.StatusNotImplemented:
		// No model for this capability. Unavailable, so the rule is indeterminate —
		// never an empty result, which would read as a model having looked.
		return nil, &enrich.Unavailable{Capability: enrich.Capability(path), Reason: "no model loaded"}
	default:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, &enrich.Unavailable{Capability: enrich.Capability(path), Reason: e.Error}
	}
}

type request struct {
	Text    string            `json:"text,omitempty"`
	Image   []byte            `json:"image,omitempty"`
	Options map[string]string `json:"options,omitempty"`
	MDM     json.RawMessage   `json:"mdm,omitempty"`
}

// textOf pulls text out of whatever the rule passed: a bare string, a message, a body,
// or a file already parsed to text.
//
// Whitespace counts as nothing. A rule reading the OCR text of an image that contains
// no words, or the body of an empty part, otherwise hands the service a string of
// newlines — which it normalises to empty and reports as unable to answer, and the
// verdict then names ml.nlu_classifier as a missing capability on a deployment where
// it is running perfectly well. There is no text to classify; that is a fact about
// the message, not about what this deployment can do.
func textOf(v mql.Value) string {
	if s, ok := v.AsString(); ok && strings.TrimSpace(s) != "" {
		return s
	}
	for _, path := range [][]string{
		{"body", "current_thread", "text"},
		{"current_thread", "text"},
		{"text"},
		{"inner_text"},
		{"raw"},
	} {
		cur := v
		for _, p := range path {
			cur = cur.Field(p)
		}
		if s, ok := cur.AsString(); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// Inference describes what the model service is actually running on.
//
// Worth asking for, and worth showing. A zero-shot pass costs the number of
// candidate labels rather than the length of the text, so it is seconds on a CPU and
// a fraction of one on a GPU — the largest single cost in analysing a message, and
// the one most likely to be silently wrong. A deployment with a GPU whose runtime
// has no provider for it falls back to the CPU and works perfectly, just slowly, and
// nothing about the result says so.
type Inference struct {
	// Provider is what ended up being used: cuda, tensorrt, rocm, coreml,
	// directml, cpu, or none when no model is loaded.
	Provider string `json:"provider"`

	// Detail explains a surprise, such as a requested provider the runtime would
	// not accept.
	Detail string `json:"detail,omitempty"`

	// Tried lists the providers offered before one stuck, so an operator who
	// mounted a GPU and is getting CPU speeds can see the attempt was made and
	// refused rather than never attempted.
	Tried []string `json:"tried,omitempty"`
}

// OnGPU reports whether inference is running anywhere other than the CPU.
func (i Inference) OnGPU() bool {
	switch i.Provider {
	case "", "cpu", "none":
		return false
	}
	return true
}

// Inference asks the service what it is running on.
func (c *Client) Inference(ctx context.Context) (*Inference, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+"/v1/capabilities", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ml: %s", resp.Status)
	}

	var out struct {
		Accelerator Inference `json:"accelerator"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return &out.Accelerator, nil
}
