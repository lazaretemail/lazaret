// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/lazaretemail/lazaret/telemetry"
)

// Inference is the one thing worth measuring here, and the thing that moved most:
// a classification went from seconds on CPU to about one and a half on the GPU, and
// the first call after a load pays a MIGraphX compile that the rest do not. The
// backend is a label so that difference is visible rather than averaged away.
var (
	mlTracer = telemetry.Tracer("lazaret/ml")
	mlMeter  = telemetry.Meter("lazaret/ml")

	metricInferences = telemetry.Counter(mlMeter, "lazaret.ml.inferences",
		metric.WithDescription("Inference requests, by capability and outcome."),
		metric.WithUnit("{inference}"))

	metricInferenceDuration = telemetry.Histogram(mlMeter, "lazaret.ml.inference.duration",
		metric.WithDescription("Time to run one inference."),
		metric.WithUnit(telemetry.Seconds))
)

const (
	attrCapability = attribute.Key("lazaret.capability")
	attrOutcome    = attribute.Key("lazaret.outcome")
	attrBackend    = attribute.Key("lazaret.ml.backend")
)
