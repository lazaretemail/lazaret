// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Middleware instruments an HTTP server.
//
// Span names come from the matched route pattern rather than the request path, so a
// message detail request is one span named "GET /v0/messages/{id}" instead of a new
// name per message id. Getting that wrong is the usual cause of a metrics backend
// falling over: every distinct URL becomes its own time series.
func Middleware(service string, h http.Handler) http.Handler {
	return otelhttp.NewHandler(h, service,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			if p := routePattern(r); p != "" {
				return r.Method + " " + p
			}
			return r.Method
		}),
		otelhttp.WithFilter(func(r *http.Request) bool { return !isNoise(r.URL.Path) }),
	)
}

// routePattern is the ServeMux pattern that matched, e.g. "/v0/messages/{id}".
//
// Available only after routing, which is why this reads it inside the handler rather
// than naming the span up front.
func routePattern(r *http.Request) string {
	if r.Pattern == "" {
		return ""
	}
	// The pattern carries the method and optional host ("GET /v0/rules"); the span
	// name already has the method.
	if i := strings.IndexByte(r.Pattern, '/'); i >= 0 {
		return r.Pattern[i:]
	}
	return r.Pattern
}

// isNoise drops the endpoints that would otherwise dominate every trace view.
//
// A liveness probe every few seconds is the single highest-volume request most
// deployments make, and it says nothing about the system that the probe's own
// result does not already say.
func isNoise(path string) bool {
	switch path {
	case "/healthz", "/readyz", "/v0/health", "/v0/readiness", "/v1/health", "/metrics", "/favicon.svg":
		return true
	}
	return strings.HasPrefix(path, "/assets/")
}

// Transport instruments an HTTP client so its calls become child spans and carry
// the trace context to the far side.
//
// Without this an engine → ml call looks like unexplained latency in the engine's
// span; with it the two services appear as one trace.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + r.URL.Path
		}),
	)
}

// Client returns a copy of c with its transport instrumented, leaving timeouts and
// everything else as they were.
func Client(c *http.Client) *http.Client {
	if c == nil {
		return &http.Client{Transport: Transport(nil)}
	}
	out := *c
	out.Transport = Transport(c.Transport)
	return &out
}

// Attrs adds attributes to the span already in ctx, if there is one. A convenience
// for the many call sites that want to annotate rather than start a span.
func Attrs(span trace.Span, kv ...attribute.KeyValue) {
	if span != nil && span.IsRecording() {
		span.SetAttributes(kv...)
	}
}
