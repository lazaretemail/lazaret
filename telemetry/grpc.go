// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
)

// GRPCDialOption instruments an outgoing gRPC connection.
//
// A stats handler rather than the deprecated interceptors: it is the only form that
// reports message sizes and works for streaming calls, and Strelka's scan API is a
// stream.
func GRPCDialOption() grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler())
}

// GRPCServerOption does the same for a server.
func GRPCServerOption() grpc.ServerOption {
	return grpc.StatsHandler(otelgrpc.NewServerHandler())
}
