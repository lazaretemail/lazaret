// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/lazaretemail/lazaret/telemetry"
)

var (
	renderTracer = telemetry.Tracer("lazaret/render")
	renderMeter  = telemetry.Meter("lazaret/render")

	metricRenders = telemetry.Counter(renderMeter, "lazaret.render.screenshots",
		metric.WithDescription("Message screenshots produced, by outcome."),
		metric.WithUnit("{screenshot}"))

	metricRenderDuration = telemetry.Histogram(renderMeter, "lazaret.render.duration",
		metric.WithDescription("Time for Chromium to lay out and capture one message."),
		metric.WithUnit(telemetry.Seconds))
)

const attrOutcome = attribute.Key("lazaret.outcome")

// Link fetching, split by whether the browser was needed.
//
// The tiering — plain HTTP unless the page has script in it — is only worth having
// if it actually fires, and there was no way to tell from outside the service.
var (
	metricFetches = telemetry.Counter(renderMeter, "lazaret.render.fetches",
		metric.WithDescription("Link fetches, labelled by whether a browser was launched."),
		metric.WithUnit("{fetch}"))

	metricFetchDuration = telemetry.Histogram(renderMeter, "lazaret.render.fetch.duration",
		metric.WithDescription("Time to fetch one link, browser included when used."),
		metric.WithUnit(telemetry.Seconds))
)

// The cache's own shape, so a deployment can see whether it is working and whether
// the bound is being hit.
var (
	metricCacheEntries = telemetry.Gauge(renderMeter, "lazaret.render.cache.entries",
		metric.WithDescription("Links currently held in the cross-message cache."),
		metric.WithUnit("{entry}"))

	metricCacheBytes = telemetry.Gauge(renderMeter, "lazaret.render.cache.bytes",
		metric.WithDescription("Memory held by the link cache."),
		metric.WithUnit("By"))
)

// The shared store's own shape.
//
// Worth reporting separately from the in-process cache, because they answer different
// questions. The local cache says "did this process already fetch this link"; the
// shared store says "did the deployment". A deployment with several render processes,
// or one that restarts, gets its saving entirely from the second — and a failure count
// that is quietly climbing is the only visible sign that Garnet has gone away, since
// every failure here is deliberately a miss rather than an error.
var (
	metricSharedHits = telemetry.Gauge(renderMeter, "lazaret.render.shared.hits",
		metric.WithDescription("Link results served from the deployment-wide store."),
		metric.WithUnit("{hit}"))

	metricSharedMisses = telemetry.Gauge(renderMeter, "lazaret.render.shared.misses",
		metric.WithDescription("Lookups the deployment-wide store did not have."),
		metric.WithUnit("{miss}"))

	metricSharedStores = telemetry.Gauge(renderMeter, "lazaret.render.shared.stores",
		metric.WithDescription("Link results written to the deployment-wide store."),
		metric.WithUnit("{write}"))

	metricSharedFailures = telemetry.Gauge(renderMeter, "lazaret.render.shared.failures",
		metric.WithDescription("Operations the deployment-wide store did not answer. "+
			"Never an analysis failure — a failure here is a miss."),
		metric.WithUnit("{failure}"))
)
