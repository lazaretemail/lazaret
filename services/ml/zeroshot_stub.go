// SPDX-License-Identifier: AGPL-3.0-only

//go:build !onnx

package main

// Without the onnx build tag there is no inference runtime.
//
// The tag exists for the same reason the yara one does: ONNX Runtime is a large native
// dependency reached through cgo, and a deployment with no models should not need it
// present to start. Returning (nil, nil) rather than an error is deliberate — no model
// is a supported state, and the capabilities that need one report unavailable, which
// is what makes the rules that use them report indeterminate rather than no-match.
func openZeroShot(dir, prefer string) (ZeroShot, error) { return nil, nil }
