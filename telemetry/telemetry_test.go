// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A deployment that has not configured a collector must not be punished for it.
// Exporters retrying against a socket nobody is listening on turn a working install
// into a stream of connection errors, so the default is off.
func TestDisabledWithoutAnEndpoint(t *testing.T) {
	for _, key := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_SDK_DISABLED",
	} {
		t.Setenv(key, "")
	}
	if Enabled() {
		t.Fatal("telemetry reports enabled with no endpoint configured")
	}
	shutdown, err := Setup(context.Background(), Config{Service: "test"})
	if err != nil {
		t.Fatalf("Setup with no collector should succeed quietly: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// A per-signal endpoint is a normal thing to configure on its own: exporting traces
// to one place and nothing else is a supported setup, and it has to count.
func TestPerSignalEndpointEnables(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://localhost:4318/v1/traces")
	if !Enabled() {
		t.Error("a traces-only endpoint should enable telemetry")
	}
}

func TestSDKDisabledWins(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	if Enabled() {
		t.Error("OTEL_SDK_DISABLED must override a configured endpoint")
	}
}

func TestSetupRequiresAServiceName(t *testing.T) {
	if _, err := Setup(context.Background(), Config{}); err == nil {
		t.Error("Setup accepted an empty service name")
	}
}

// Span names must come from the route pattern, never the path.
//
// This is the difference between one span named "GET /v0/messages/{id}" and one per
// message id. Getting it wrong is the classic way to take a metrics backend down,
// and it is invisible until the cardinality bill arrives.
func TestSpanNameUsesTheRoutePatternNotThePath(t *testing.T) {
	mux := http.NewServeMux()
	var seen []string
	record := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if p := routePattern(r); p != "" {
			seen = append(seen, r.Method+" "+p)
		}
	})
	mux.Handle("GET /v0/messages/{id}", record)
	mux.Handle("GET /v0/rules", record)

	for _, path := range []string{
		"/v0/messages/abc@example.com",
		"/v0/messages/totally-different-id",
		"/v0/rules",
	} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}

	want := []string{"GET /v0/messages/{id}", "GET /v0/messages/{id}", "GET /v0/rules"}
	if len(seen) != len(want) {
		t.Fatalf("got %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("span %d = %q, want %q", i, seen[i], want[i])
		}
	}
}

// Health probes are the highest-volume request most deployments make and say
// nothing the probe's own result does not already say.
func TestProbesAreNotTraced(t *testing.T) {
	for _, path := range []string{"/healthz", "/v0/health", "/v1/health", "/assets/index.abc.js"} {
		if !isNoise(path) {
			t.Errorf("%s should be filtered out of traces", path)
		}
	}
	for _, path := range []string{"/v0/messages/x", "/api/triage", "/"} {
		if isNoise(path) {
			t.Errorf("%s should be traced", path)
		}
	}
}

// Configuring a collector must not cost the operator their terminal output.
func TestLogsStillReachTheTerminal(t *testing.T) {
	var captured strings.Builder
	h := fanout{
		slog.NewTextHandler(&captured, &slog.HandlerOptions{Level: slog.LevelInfo}),
		slog.NewTextHandler(&strings.Builder{}, &slog.HandlerOptions{Level: slog.LevelInfo}),
	}
	slog.New(h).Info("mail flowing", "messages", 3)

	if got := captured.String(); !strings.Contains(got, "mail flowing") || !strings.Contains(got, "messages=3") {
		t.Errorf("the terminal handler did not receive the record: %q", got)
	}
}

func TestFanoutReportsEveryHandlersError(t *testing.T) {
	h := fanout{failing{}, failing{}}
	err := h.Handle(context.Background(), slog.Record{Level: slog.LevelInfo})
	if err == nil {
		t.Fatal("a failing handler was not reported")
	}
	if n := strings.Count(err.Error(), "nope"); n != 2 {
		t.Errorf("reported %d failures, want 2 — errors from both handlers must survive", n)
	}
}

type failing struct{}

func (failing) Enabled(context.Context, slog.Level) bool  { return true }
func (failing) Handle(context.Context, slog.Record) error { return errNope }
func (f failing) WithAttrs([]slog.Attr) slog.Handler      { return f }
func (f failing) WithGroup(string) slog.Handler           { return f }

var errNope = errorString("nope")

type errorString string

func (e errorString) Error() string { return string(e) }
