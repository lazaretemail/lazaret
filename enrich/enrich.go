// SPDX-License-Identifier: AGPL-3.0-only

// Package enrich defines the boundary between MQL evaluation and everything that
// evaluation cannot do by itself.
//
// MQL's function surface splits in two. Most of it — strings, regex, the array and map
// builtins, HTML queries, the parse_* family — is computable from the message alone, and
// lives in the mql package. The rest needs a machine learning model, a network lookup, a
// sandbox that can explode an archive, or a history of everything the organisation has
// received. Those are declared here as interfaces and implemented by separate services.
//
// The interfaces are deliberately context-aware and free of package-level state: each one
// becomes an RPC boundary to a container once the corresponding module lands, and a seam
// that assumed in-process synchronous calls would have to be rebuilt to get there.
//
// # Unavailable is not false
//
// Every interface here has a default implementation that returns [ErrUnavailable]. The
// evaluator turns that into a null value and records the [Capability] that was missing, so
// a rule depending on it reports as indeterminate rather than as a clean no-match.
//
// This is not only about the engine being incomplete. Once every module exists, a service
// can still be down, and "we could not tell" remains a different answer from "this message
// is fine". Detection systems that quietly downgrade the first into the second are how
// outages turn into missed attacks.
package enrich

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// ErrUnavailable reports that a capability is not implemented, not deployed, or not
// reachable. Callers distinguish it with [errors.Is].
//
// It is never an evaluation failure. An MQL function whose enricher returns it yields null
// and marks the capability as missing; the rule still runs to completion.
var ErrUnavailable = errors.New("enrich: capability unavailable")

// Unavailable wraps [ErrUnavailable] with the capability that was missing and, optionally,
// the underlying cause — a dial error, a timeout, a disabled feature flag.
type Unavailable struct {
	Capability Capability
	Reason     string
	Err        error
}

func (u *Unavailable) Error() string {
	var b strings.Builder
	b.WriteString(string(u.Capability))
	b.WriteString(" unavailable")
	if u.Reason != "" {
		b.WriteString(": ")
		b.WriteString(u.Reason)
	}
	if u.Err != nil {
		b.WriteString(": ")
		b.WriteString(u.Err.Error())
	}
	return b.String()
}

func (u *Unavailable) Is(target error) bool { return target == ErrUnavailable }

func (u *Unavailable) Unwrap() error { return u.Err }

// Unavailablef builds an [Unavailable] for cap with a formatted reason.
func Unavailablef(cap Capability, format string, args ...any) error {
	return &Unavailable{Capability: cap, Reason: fmt.Sprintf(format, args...)}
}

// NotImplemented is the reason used by the default enrichers, which stand in for modules
// that have not been built yet.
func NotImplemented(cap Capability) error {
	return &Unavailable{Capability: cap, Reason: "not implemented in this build"}
}

// Capability names an MQL function that requires an enricher, using the same spelling the
// rule author writes. Reporting "ml.link_analysis" rather than "LinkAnalyzer.Analyze" means
// the person reading the result can find it in their own rule without a translation table.
type Capability string

// The capabilities MQL can ask for, grouped by the service that will answer.
//
// Naming follows the rule text exactly, including the beta. prefix where Sublime uses one.
const (
	// File analysis — Strelka (module 3).
	CapFileExplode        Capability = "file.explode"
	CapFileExpandArchives Capability = "file.expand_archives"
	CapFileOletools       Capability = "file.oletools"

	// Rendering — lazaret-render (module 4).
	CapFileMessageScreenshot Capability = "file.message_screenshot"
	CapFileHTMLScreenshot    Capability = "file.html_screenshot"

	// Models — lazaret-ml (module 5).
	CapMLLinkAnalysis    Capability = "ml.link_analysis"
	CapMLLogoDetect      Capability = "ml.logo_detect"
	CapMLMacroClassifier Capability = "ml.macro_classifier"
	CapMLNLUClassifier   Capability = "ml.nlu_classifier"
	CapMLAttackScore     Capability = "ml.attack_score"

	CapBetaOCR        Capability = "beta.ocr"
	CapBetaScanQR     Capability = "beta.scan_qr"
	CapBetaParseExif  Capability = "beta.parse_exif"
	CapBetaMLTopic    Capability = "beta.ml_topic"
	CapBetaTranslate  Capability = "beta.ml_translate"
	CapBetaExtractPII Capability = "beta.ml_extract_sensitive_information"
	CapBetaFuzzyScore Capability = "beta.fuzzy_attack_score"

	// Network lookups (module 2).
	CapNetworkWhois Capability = "network.whois"

	// Historical context — needs the message store (module 2).
	CapProfileBySender       Capability = "profile.by_sender"
	CapProfileBySenderDomain Capability = "profile.by_sender_domain"
	CapProfileBySenderEmail  Capability = "profile.by_sender_email"
	CapProfileByReplyTo      Capability = "profile.by_reply_to"
)

// ListCapability names a `$list` the evaluator could not resolve, so that an unresolvable
// list is reported the same way an unreachable service is.
//
// A named list is a capability like any other: `$high_trust_sender_root_domains` is a
// 198MB feed, `$recipient_emails` needs the message history that module 2 will hold, and
// neither is answerable from the message. The lists package is already careful to answer
// "I do not know" rather than "no" — this is what carries that answer up to the verdict,
// which otherwise reads a bare null as a clean no-match.
//
// The capability is named for the reference as written, so a report says
// `missing: $recipient_emails` rather than something the rule author would have to
// translate.
func ListCapability(name string) Capability {
	return Capability("$" + name)
}

// Tracker records which capabilities an evaluation asked for and could not get.
//
// One is created per message evaluation and shared by every rule in that run, so a report
// can state once that ml.link_analysis was unreachable rather than repeating it for each of
// the several hundred rules that wanted it.
//
// A Tracker is safe for concurrent use; rules within a run may be evaluated in parallel.
type Tracker struct {
	mu      sync.Mutex
	missing map[Capability]int
}

// Record notes one request for cap that could not be served.
func (t *Tracker) Record(cap Capability) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.missing == nil {
		t.missing = make(map[Capability]int)
	}
	t.missing[cap]++
}

// Missing reports the capabilities that were requested but unavailable, sorted so that
// output is stable across runs.
func (t *Tracker) Missing() []Capability {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.missing) == 0 {
		// nil rather than an empty slice, so that a Tracker that recorded nothing and a nil
		// Tracker report identically, and so `omitempty` elides the field in JSON output.
		return nil
	}
	caps := make([]Capability, 0, len(t.missing))
	for c := range t.missing {
		caps = append(caps, c)
	}
	slices.Sort(caps)
	return caps
}

// Any reports whether any capability was missing. A rule evaluated against a Tracker that
// reports true cannot be trusted to have returned a definitive no-match.
func (t *Tracker) Any() bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.missing) > 0
}

// ---------------------------------------------------------------------------
// Partial availability
// ---------------------------------------------------------------------------

type trackerKey struct{}

// WithTracker puts t in ctx so that an enricher reached through a context can record
// against it.
//
// The evaluator holds the Tracker and records the plain case itself: an enricher that
// returns ErrUnavailable has its capability recorded without needing to know a Tracker
// exists. This exists for the case that does not fit that shape — an enricher that
// answers *part* of a capability.
//
// ml.nlu_classifier is the one that forced it. With no entailment model it still
// returns entities and language, and omits intents, topics and tags. That is a
// successful call returning a useful value, so there is no error to record, and yet an
// evaluation that consulted it has not seen everything it asked for. Without this the
// verdict would report no missing capabilities and be wrong about it.
func WithTracker(ctx context.Context, t *Tracker) context.Context {
	if t == nil {
		return ctx
	}
	return context.WithValue(ctx, trackerKey{}, t)
}

// TrackerFrom returns the Tracker in ctx, or nil. A nil Tracker is usable: Record on
// one does nothing.
func TrackerFrom(ctx context.Context) *Tracker {
	t, _ := ctx.Value(trackerKey{}).(*Tracker)
	return t
}

// RecordPartial notes that cap answered, but not completely.
//
// Deliberately recorded the same way a wholly unavailable capability is, rather than
// in a separate list. The question a verdict answers is "could this evaluation see
// everything it needed?", and a half-answered capability makes that a no. Splitting
// the two would invite a reader to treat one as benign, and the rule that wanted the
// missing half cannot tell the difference.
func RecordPartial(ctx context.Context, cap Capability) {
	TrackerFrom(ctx).Record(cap)
}
