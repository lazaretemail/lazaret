// SPDX-License-Identifier: AGPL-3.0-only

// Package telemetry wires OpenTelemetry for a Lazaret service.
//
// It is a module of its own rather than part of the root library on purpose. The
// core packages — mql, eml, mdm, rules — are meant to stay light enough that someone
// can `go get` just the MQL engine, and the OpenTelemetry SDK plus its exporters is
// a large graph to inherit for that. Services depend on this module; the libraries
// they call are instrumented by decoration at the service boundary, which the
// architecture already allows because enrichment and storage are interfaces.
//
// Nothing here is on by default. A deployment that has not configured a collector
// gets no-op providers and one line in the log saying so, because the alternative —
// exporters retrying against a socket nobody is listening on — turns a working
// install into a stream of connection errors.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// Config describes the service being instrumented.
type Config struct {
	// Service is the value of service.name. Required.
	Service string

	// Version is service.version, usually a build stamp. Optional.
	Version string

	// Tenant, when set, is attached to every signal from this process. Only for a
	// single-tenant deployment: in a shared one the tenant belongs on the span, not
	// on the resource.
	Tenant string
}

// Shutdown flushes and stops every provider. Always safe to call, and safe to call
// when Setup reported telemetry disabled.
type Shutdown func(context.Context) error

// Enabled reports whether any OTLP endpoint is configured.
//
// The standard variables are honoured rather than invented ones, so an operator who
// knows OpenTelemetry already knows how to point this at their collector. The
// per-signal endpoints count too: exporting traces alone is a normal thing to want.
func Enabled() bool {
	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return false
	}
	for _, key := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

var noopShutdown Shutdown = func(context.Context) error { return nil }

// Setup installs the global tracer, meter and logger providers.
//
// The returned Shutdown must be called before the process exits, or the last batch
// of spans — usually the interesting ones, since a crash is what you came to look at
// — is dropped.
func Setup(ctx context.Context, cfg Config) (Shutdown, error) {
	if cfg.Service == "" {
		return noopShutdown, errors.New("telemetry: Config.Service is required")
	}
	if !Enabled() {
		log.Printf("telemetry: no OTLP endpoint configured, tracing and metrics are off "+
			"(set OTEL_EXPORTER_OTLP_ENDPOINT to enable) [%s]", cfg.Service)
		return noopShutdown, nil
	}

	// One error handler for the SDK, rate limited. An unreachable collector otherwise
	// reports every failed export, which buries the logs that matter under the one
	// fact the operator already knows.
	otel.SetErrorHandler(rateLimited(time.Minute))

	res, err := buildResource(ctx, cfg)
	if err != nil {
		return noopShutdown, fmt.Errorf("telemetry: describing this service: %w", err)
	}

	var closers []func(context.Context) error
	fail := func(err error) (Shutdown, error) {
		// Tear down whatever already started, so a half-built pipeline does not leak
		// a background exporter into a process that is about to report failure.
		shutdownAll(context.Background(), closers)
		return noopShutdown, err
	}

	traceExp, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return fail(fmt.Errorf("telemetry: trace exporter: %w", err))
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExp),
	)
	closers = append(closers, tp.Shutdown)

	metricExp, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		return fail(fmt.Errorf("telemetry: metric reader: %w", err))
	}
	mp := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metricExp),
	)
	closers = append(closers, mp.Shutdown)

	logExp, err := autoexport.NewLogExporter(ctx)
	if err != nil {
		return fail(fmt.Errorf("telemetry: log exporter: %w", err))
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
	)
	closers = append(closers, lp.Shutdown)

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	global.SetLoggerProvider(lp)

	// W3C trace context plus baggage: the pair every other system speaks, so a trace
	// that starts in a reverse proxy or a mail gateway continues here rather than
	// beginning again.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	installLogging(cfg.Service)

	if err := runtime.Start(runtime.WithMeterProvider(mp)); err != nil {
		// Go runtime metrics are a nice-to-have; losing them is not worth refusing to
		// start a mail pipeline over.
		log.Printf("telemetry: runtime metrics unavailable: %v", err)
	}

	log.Printf("telemetry: exporting traces, metrics and logs as %q", cfg.Service)
	return func(ctx context.Context) error { return shutdownAll(ctx, closers) }, nil
}

func shutdownAll(ctx context.Context, closers []func(context.Context) error) error {
	// A shutdown that inherits an already-cancelled context flushes nothing, which is
	// exactly when the last spans matter most.
	if err := ctx.Err(); err != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
	}
	var errs []error
	// Reverse order, so the providers stop before the exporters they write to.
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i](ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func buildResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{semconv.ServiceName(cfg.Service)}
	if cfg.Version != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.Version))
	}
	if cfg.Tenant != "" {
		attrs = append(attrs, attribute.String("lazaret.tenant", cfg.Tenant))
	}
	// Merged with the environment's own detectors last, so OTEL_RESOURCE_ATTRIBUTES
	// can override what this process guessed about itself.
	//
	// Merge refuses to combine two resources with different schema URLs, and
	// resource.Default() carries whichever semconv version the SDK ships. If they
	// ever drift apart again — an SDK upgrade is the likely cause — fall back to
	// the attributes alone rather than starting with no telemetry at all: a
	// resource missing a schema URL is a small loss, and silence is a large one.
	merged, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, attrs...),
	)
	if err != nil {
		log.Printf("telemetry: resource schema mismatch (%v); describing this service without the SDK defaults", err)
		return resource.NewWithAttributes(semconv.SchemaURL, attrs...), nil
	}
	return merged, nil
}

// installLogging routes the standard library logger through slog, and slog through
// OpenTelemetry.
//
// The services were written against log.Printf, 135 call sites of it. Rewriting them
// all would be a large diff with no behaviour change, so instead the default logger
// is pointed at slog and slog is given an OpenTelemetry handler: every existing line
// is exported without being touched. Call sites that have a context can move to
// slog.InfoContext over time and gain trace correlation; the rest keep working.
func installLogging(service string) {
	otelHandler := otelslog.NewHandler(service)
	stderr := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})

	logger := slog.New(fanout{otelHandler, stderr})
	slog.SetDefault(logger)

	// The standard logger keeps working and now also reaches the collector. No prefix
	// or timestamp: slog adds its own, and doubling them makes every line unreadable.
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(writerTo(logger))
}

// fanout sends a record to several handlers, so logs reach the operator's terminal
// and the collector both. Losing the terminal copy the moment a collector is
// configured would be a poor trade.
type fanout []slog.Handler

func (f fanout) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f fanout) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range f {
		if h.Enabled(ctx, r.Level) {
			// Each handler gets its own copy: a handler is allowed to retain the
			// record, and they must not share backing storage for attributes.
			if err := h.Handle(ctx, r.Clone()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (f fanout) WithAttrs(as []slog.Attr) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(as)
	}
	return out
}

func (f fanout) WithGroup(name string) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(name)
	}
	return out
}

type logWriter struct{ l *slog.Logger }

func writerTo(l *slog.Logger) *logWriter { return &logWriter{l: l} }

func (w *logWriter) Write(p []byte) (int, error) {
	w.l.Info(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// rateLimited keeps a broken collector from drowning the log it is meant to help.
func rateLimited(every time.Duration) otel.ErrorHandlerFunc {
	var (
		mu      sync.Mutex
		last    time.Time
		skipped int
	)
	return func(err error) {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(last) < every {
			skipped++
			return
		}
		if skipped > 0 {
			log.Printf("telemetry: %v (%d similar suppressed)", err, skipped)
		} else {
			log.Printf("telemetry: %v", err)
		}
		last, skipped = time.Now(), 0
	}
}
