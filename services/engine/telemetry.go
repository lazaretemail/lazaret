// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/lazaretemail/lazaret/telemetry"
)

// The engine's own instruments.
//
// Deliberately few. Each one answers a question an operator actually asks when
// something is wrong — is mail flowing, is it being judged, what is slow, what is
// unavailable — rather than mirroring every internal counter into a dashboard
// nobody reads.
//
// Attribute cardinality is the thing to watch: a label whose value comes from a
// message (a sender, a subject, a message id) would create one time series per
// message and take the metrics backend down. Everything below is bounded by the
// rule set or by a fixed vocabulary, and anything per-message belongs on a span.

var (
	engineTracer = telemetry.Tracer("lazaret/engine")
	engineMeter  = telemetry.Meter("lazaret/engine")

	// metricAnalyzed counts messages that finished analysis, by what was decided.
	metricAnalyzed = telemetry.Counter(engineMeter, "lazaret.messages.analyzed",
		metric.WithDescription("Messages that completed analysis, by verdict."),
		metric.WithUnit("{message}"))

	// metricAnalysisDuration is the headline latency: how long one message takes
	// from bytes to verdict. The thing that was 95 seconds and is now under two.
	metricAnalysisDuration = telemetry.Histogram(engineMeter, "lazaret.analysis.duration",
		metric.WithDescription("Wall time to analyse one message, bytes to verdict."),
		metric.WithUnit(telemetry.Seconds))

	// metricRuleMatched counts detections. Bounded by the rule set, which is ~1500
	// entries — large for a label, but it is the set operators tune against.
	metricRuleMatched = telemetry.Counter(engineMeter, "lazaret.rules.matched",
		metric.WithDescription("Rule matches, by rule and severity."),
		metric.WithUnit("{match}"))

	// metricCapabilityCalls and its histogram are what made the optimisation work
	// legible: which enrichment is being asked for, how often, and how slow.
	metricCapabilityCalls = telemetry.Counter(engineMeter, "lazaret.capability.calls",
		metric.WithDescription("Enrichment calls, by capability and outcome."),
		metric.WithUnit("{call}"))

	metricCapabilityDuration = telemetry.Histogram(engineMeter, "lazaret.capability.duration",
		metric.WithDescription("Time spent in one enrichment call."),
		metric.WithUnit(telemetry.Seconds))

	// metricCapabilityUp is 1 when a capability answers its probe and 0 when it
	// does not. A gauge rather than a counter because the question is always "right
	// now", and because the number of rules it takes down with it is the thing an
	// operator is actually asking about.
	metricCapabilityUp = telemetry.Gauge(engineMeter, "lazaret.capability.up",
		metric.WithDescription("1 when an enrichment capability answers, 0 when it does not."),
		metric.WithUnit("{capability}"))

	// metricActions counts what was done to a mailbox. Custody makes these the
	// highest-consequence operations in the system, so they are counted separately
	// from the analysis that prompted them.
	metricActions = telemetry.Counter(engineMeter, "lazaret.remediation.actions",
		metric.WithDescription("Mailbox actions attempted, by action and outcome."),
		metric.WithUnit("{action}"))
)

// Attribute keys, named once so a typo cannot split a series in two.
const (
	attrVerdict    = attribute.Key("lazaret.verdict")
	attrDirection  = attribute.Key("lazaret.direction")
	attrCapability = attribute.Key("lazaret.capability")
	attrOutcome    = attribute.Key("lazaret.outcome")
	attrRule       = attribute.Key("lazaret.rule")
	attrSeverity   = attribute.Key("lazaret.severity")
	attrAction     = attribute.Key("lazaret.action")
	attrTenant     = attribute.Key("lazaret.tenant")
	attrSource     = attribute.Key("lazaret.source")
)

// outcome collapses an error into a label with a fixed vocabulary.
//
// The error text itself must never become a label: it can contain a hostname, a
// message id or a remote server's prose, and each distinct string would be another
// time series. The detail belongs on the span, where it costs nothing.
func outcome(err error, expired bool) string {
	switch {
	case expired:
		return "timeout"
	case err != nil:
		return "error"
	default:
		return "ok"
	}
}
