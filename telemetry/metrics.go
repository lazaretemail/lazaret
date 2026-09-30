// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
)

// Tracer and Meter for a package. Both are cheap and safe to call at init: before
// Setup runs they return no-op implementations that cost a branch.
func Tracer(name string) trace.Tracer { return otel.Tracer(name) }
func Meter(name string) metric.Meter  { return otel.Meter(name) }

// The must* helpers exist because instrument construction returns an error that is
// non-nil only for a malformed instrument name — a programming mistake, not a
// runtime condition. Handling it at every call site would put three lines of dead
// error plumbing around each counter; here it is logged once and the caller gets a
// working no-op instead of a nil pointer to dereference later.

func Counter(m metric.Meter, name string, opts ...metric.Int64CounterOption) metric.Int64Counter {
	c, err := m.Int64Counter(name, opts...)
	if err != nil {
		log.Printf("telemetry: counter %q: %v", name, err)
		c, _ = noop.Meter{}.Int64Counter(name)
	}
	return c
}

func UpDownCounter(m metric.Meter, name string, opts ...metric.Int64UpDownCounterOption) metric.Int64UpDownCounter {
	c, err := m.Int64UpDownCounter(name, opts...)
	if err != nil {
		log.Printf("telemetry: updowncounter %q: %v", name, err)
		c, _ = noop.Meter{}.Int64UpDownCounter(name)
	}
	return c
}

func Gauge(m metric.Meter, name string, opts ...metric.Int64GaugeOption) metric.Int64Gauge {
	g, err := m.Int64Gauge(name, opts...)
	if err != nil {
		log.Printf("telemetry: gauge %q: %v", name, err)
		g, _ = noop.Meter{}.Int64Gauge(name)
	}
	return g
}

func Histogram(m metric.Meter, name string, opts ...metric.Float64HistogramOption) metric.Float64Histogram {
	h, err := m.Float64Histogram(name, opts...)
	if err != nil {
		log.Printf("telemetry: histogram %q: %v", name, err)
		h, _ = noop.Meter{}.Float64Histogram(name)
	}
	return h
}

// Seconds is the unit every duration histogram here uses.
//
// Seconds rather than milliseconds because that is what the OpenTelemetry
// conventions specify, and a backend that knows the convention renders them
// correctly without per-dashboard configuration.
const Seconds = "s"

// Error marks the span failed and records the error, or does nothing for a nil
// error. Saves the `if err != nil` around every span in the codebase.
func Error(span trace.Span, err error) error {
	if err != nil && span != nil && span.IsRecording() {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	return err
}

// End finishes a span and records err on it, for `defer`.
func End(span trace.Span, err *error) {
	if err != nil {
		Error(span, *err)
	}
	span.End()
}

// Start begins a span on the package tracer.
func Start(ctx context.Context, tracer trace.Tracer, name string, kv ...attribute.KeyValue) (context.Context, trace.Span) {
	return tracer.Start(ctx, name, trace.WithAttributes(kv...))
}
