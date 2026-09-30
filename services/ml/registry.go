// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Capabilities are the MQL functions this service exists to answer. The endpoint path,
// the model file name and the rule text all use the same string, so there is nothing to
// translate between a deployment and a rule.
var Capabilities = []string{
	"ml.nlu_classifier",
	"ml.logo_detect",
	"ml.macro_classifier",
	"ml.attack_score",
	"beta.ml_topic",
	"beta.ml_translate",
	"beta.fuzzy_attack_score",
}

// ErrNoModel reports that a capability has no model loaded. It is the normal state of a
// fresh deployment, not a fault.
var ErrNoModel = errors.New("no model loaded for this capability")

// Request is what a client sends. One shape for every capability, because they all take
// either text or an image and the alternative is seven near-identical structs.
type Request struct {
	// Text is the input for the language capabilities.
	Text string `json:"text,omitempty"`

	// Image is a PNG, for logo detection — normally a rendered message from
	// lazaret-render.
	Image []byte `json:"image,omitempty"`

	// Options carries per-capability settings, such as ml.link_analysis's mode= or a
	// target language for translation. ml.logo_detect reads "ocr_text" from here: the
	// text a scanner already found in the image, which is how the wordmark half of
	// brand detection works without this service running an OCR engine of its own.
	Options map[string]string `json:"options,omitempty"`

	// MDM is a subset of the message model, for the two capabilities that take no
	// argument and judge the whole message. A subset rather than the whole thing, so
	// that widening what this service is told is a visible change on both sides.
	MDM json.RawMessage `json:"mdm,omitempty"`
}

// Model is one loaded model.
//
// The interface is what matters here rather than any implementation: it is the seam an
// operator plugs weights into, and it is deliberately narrow so that an ONNX session, a
// remote inference endpoint and a test fake are all equally easy to put behind it.
type Model interface {
	// Capability is the MQL function this answers.
	Capability() string

	// Infer runs the model. The result is marshalled to JSON as the capability's
	// published output type, so an implementation returns the shape mdm declares.
	Infer(ctx context.Context, req Request) (any, error)

	// Close releases the session.
	Close() error
}

// Registry holds the loaded models.
type Registry struct {
	mu     sync.RWMutex
	models map[string]Model
}

// Options configure what LoadRegistry builds.
type Options struct {
	// Dir holds the weights. Its layout:
	//
	//	zeroshot.onnx             the entailment model
	//	zeroshot.tokenizer.json   its tokenizer
	//	logos/<Brand>/*.png       the logo reference pack
	//	<capability>.onnx         a purpose-trained model, overriding the built-in
	Dir string

	// TranslateEndpoint is a LibreTranslate base URL. Empty leaves translation
	// answering only the already-in-the-target-language case.
	TranslateEndpoint string
	TranslateAPIKey   string
	TranslateTarget   string

	// Accelerator picks an execution provider: "auto" tries the fastest the
	// runtime will accept and falls back to CPU, "cpu" pins it, and a name such as
	// "cuda" demands that one.
	Accelerator string
}

// LoadRegistry builds every capability this service answers.
//
// Each capability is always registered, and this is the part worth understanding: a
// capability being *present* is not the same as it being *answerable*. Several of
// these answer part of their contract with no weights at all — the NLU classifier
// returns entities and language, logo detection reads wordmarks out of OCR text, the
// macro classifier needs no model in the first place — and report the rest as
// unavailable inside the response.
//
// The alternative, registering only what has weights, would make a fresh deployment
// report ml.nlu_classifier missing entirely and lose the half of it that works.
func LoadRegistry(opts Options) (*Registry, error) {
	r := &Registry{models: map[string]Model{}}
	var problems []string

	zs, err := openZeroShot(opts.Dir, opts.Accelerator)
	if err != nil {
		// A model that is present but unloadable is a fault, unlike one that is
		// absent. Reported, and the service still starts: the capabilities that do
		// not need it should not be taken down by it.
		problems = append(problems, err.Error())
	}

	nlu := NewNLU(zs)
	r.Register(nlu)
	r.Register(&Topic{nlu: nlu})
	r.Register(MacroClassifier{})
	r.Register(&AttackScore{cap: "ml.attack_score", nlu: nlu})
	r.Register(&AttackScore{cap: "beta.fuzzy_attack_score", nlu: nlu})
	r.Register(NewTranslate(opts.TranslateEndpoint, opts.TranslateAPIKey, opts.TranslateTarget))

	logos := &LogoDetect{}
	if shipped, local, err := logos.LoadReferences(filepath.Join(opts.Dir, "logos")); err != nil {
		problems = append(problems, fmt.Sprintf("logo reference pack: %v", err))
	} else if local > 0 {
		log.Printf("lazaret-ml: logo references: %d shipped hash(es) + %d from your own images",
			shipped, local)
	} else {
		log.Printf("lazaret-ml: logo references: %d shipped hash(es); add your own images "+
			"under %s/logos/<Brand>/ to improve it", shipped, opts.Dir)
	}
	r.Register(logos)

	// There is deliberately no "drop <capability>.onnx in and it is used" path.
	//
	// An earlier version of this had one, and it could not work: a purpose-trained
	// classifier needs its label set in a known order and its own tokenizer, and
	// nothing in a bare .onnx file declares either. Loading one anyway would produce
	// confident scores against the wrong labels, which is the failure mode this
	// service exists to avoid.
	//
	// The extension seam is the Model interface, which a fork implements directly,
	// and the entailment model, whose labels live in labels.go where they can be read.

	if len(problems) > 0 {
		return r, errors.New(strings.Join(problems, "; "))
	}
	return r, nil
}

// Accelerator reports what inference is running on, or "none" with no model.
//
// On the capabilities endpoint because it is an operational fact an operator cannot
// otherwise see: a deployment that mounted a GPU and is silently running on CPU looks
// identical to one that is not, apart from being twenty times slower.
func (r *Registry) Accelerator() any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.models["ml.nlu_classifier"].(*NLU)
	if !ok || n.model == nil {
		return map[string]string{"provider": "none", "detail": "no model loaded"}
	}
	type reporter interface{ Accelerator() accelerator }
	if a, ok := n.model.(reporter); ok {
		return a.Accelerator()
	}
	return map[string]string{"provider": "cpu"}
}

// HasZeroShot reports whether the entailment model is loaded, which is what decides
// whether intents, topics and tags can be answered at all.
func (r *Registry) HasZeroShot() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.models["ml.nlu_classifier"].(*NLU)
	return ok && n.model != nil
}

func valid(cap string) bool {
	for _, c := range Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// Names lists the capabilities that have a model.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.models))
	for c := range r.models {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Partial lists the capabilities that are registered but cannot answer their whole
// contract, and says what is missing from each.
//
// This exists because "available" became a misleading word once capabilities started
// answering part of themselves. ml.nlu_classifier with no entailment model answers
// entities and language and nothing else; reporting it as simply available tells an
// operator the 358 rules that read .intents will work, and they will not.
func (r *Registry) Partial() map[string][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := map[string][]string{}
	if n, ok := r.models["ml.nlu_classifier"].(*NLU); ok && n.model == nil {
		out["ml.nlu_classifier"] = []string{"intents", "topics", "tags"}
		out["beta.ml_topic"] = []string{"topics"}
		out["ml.attack_score"] = []string{"intent-based verdicts"}
		out["beta.fuzzy_attack_score"] = []string{"intent-based verdicts"}
	}
	if l, ok := r.models["ml.logo_detect"].(*LogoDetect); ok {
		l.mu.RLock()
		n := len(l.refs)
		l.mu.RUnlock()
		if n == 0 {
			out["ml.logo_detect"] = []string{"symbol logos (no reference pack); wordmarks still answered"}
		}
	}
	if t, ok := r.models["beta.ml_translate"].(*Translate); ok && t.Endpoint == "" {
		out["beta.ml_translate"] = []string{"translation (no backend configured); same-language text still answered"}
	}
	return out
}

// Missing lists the capabilities that do not.
func (r *Registry) Missing() []string {
	have := map[string]bool{}
	for _, n := range r.Names() {
		have[n] = true
	}
	var out []string
	for _, c := range Capabilities {
		if !have[c] {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// Infer runs a capability, or reports that nothing can.
func (r *Registry) Infer(ctx context.Context, cap string, req Request) (any, error) {
	r.mu.RLock()
	m, ok := r.models[cap]
	r.mu.RUnlock()
	backend := currentBackend()
	if !ok {
		return nil, fmt.Errorf("%s: %w", cap, ErrNoModel)
	}

	ctx, span := mlTracer.Start(ctx, "ml.infer."+cap, trace.WithAttributes(
		attrCapability.String(cap),
		attrBackend.String(backend),
	))
	start := time.Now()

	out, err := m.Infer(ctx, req)

	elapsed := time.Since(start)
	res := "ok"
	if err != nil {
		res = "error"
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.SetAttributes(attrOutcome.String(res))
	span.End()

	attrs := metric.WithAttributes(
		attrCapability.String(cap),
		attrBackend.String(backend),
		attrOutcome.String(res),
	)
	metricInferences.Add(ctx, 1, attrs)
	metricInferenceDuration.Record(ctx, elapsed.Seconds(), attrs)

	return out, err
}

// Register adds a model, for tests and for an operator wiring a non-ONNX backend.
func (r *Registry) Register(m Model) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.models[m.Capability()] = m
}
