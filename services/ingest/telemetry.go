// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/lazaretemail/lazaret/telemetry"
)

var (
	ingestTracer = telemetry.Tracer("lazaret/ingest")
	ingestMeter  = telemetry.Meter("lazaret/ingest")

	metricDelivered = telemetry.Counter(ingestMeter, "lazaret.ingest.messages",
		metric.WithDescription("Messages handed to the engine, by source and outcome."),
		metric.WithUnit("{message}"))

	metricDeliverDuration = telemetry.Histogram(ingestMeter, "lazaret.ingest.duration",
		metric.WithDescription("Time from collecting a message to the engine's verdict."),
		metric.WithUnit(telemetry.Seconds))

	// Delivery lag is the number that matters for an IMAP deployment: how long a
	// message sat in the mailbox before anything looked at it. It is the difference
	// between catching a phish before it is clicked and after.
	metricLag = telemetry.Histogram(ingestMeter, "lazaret.ingest.lag",
		metric.WithDescription("Age of a message when collection reached it."),
		metric.WithUnit(telemetry.Seconds))
)

const (
	attrSource    = attribute.Key("lazaret.source")
	attrVerdict   = attribute.Key("lazaret.verdict")
	attrOutcome   = attribute.Key("lazaret.outcome")
	attrMailboxID = attribute.Key("lazaret.mailbox_id")
)

// instrument wraps a Deliver so every message, from whichever source, is traced and
// counted in one place.
//
// Decoration rather than editing the IMAP and Graph loops separately: Deliver is
// already the seam both sources funnel through, so instrumenting it cannot miss one
// and cannot drift between them.
func instrument(next Deliver) Deliver {
	return func(ctx context.Context, msg RawMessage) (*Verdict, error) {
		// A new root span per message. The alternative — one long-lived span for the
		// poll loop — produces a trace that never ends and grows without bound.
		ctx, span := ingestTracer.Start(ctx, "ingest.deliver",
			trace.WithSpanKind(trace.SpanKindConsumer),
			trace.WithNewRoot(),
			trace.WithAttributes(
				attrSource.String(msg.Source),
				attrMailboxID.String(msg.MailboxID),
				attribute.Int("lazaret.message.bytes", len(msg.Raw)),
			))
		defer span.End()

		if !msg.ReceivedAt.IsZero() {
			lag := time.Since(msg.ReceivedAt).Seconds()
			span.SetAttributes(attribute.Float64("lazaret.ingest.lag_seconds", lag))
			metricLag.Record(ctx, lag, metric.WithAttributes(attrSource.String(msg.Source)))
		}

		start := time.Now()
		v, err := next(ctx, msg)
		elapsed := time.Since(start)

		verdict, res := "", "ok"
		switch {
		case err != nil:
			res = "error"
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		case v != nil:
			verdict = v.Verdict
			span.SetAttributes(
				attribute.String("lazaret.message.id", v.MessageID),
				attrVerdict.String(v.Verdict),
				attribute.Bool("lazaret.duplicate", v.Duplicate),
				attribute.Bool("lazaret.recorded", v.Recorded),
			)
			if v.Duplicate {
				// Not an error: a redelivery is ordinary. Counted apart so a source
				// that has started looping is visible.
				res = "duplicate"
			}
		}

		attrs := metric.WithAttributes(
			attrSource.String(msg.Source),
			attrVerdict.String(verdict),
			attrOutcome.String(res),
		)
		metricDelivered.Add(ctx, 1, attrs)
		metricDeliverDuration.Record(ctx, elapsed.Seconds(), attrs)

		return v, err
	}
}
