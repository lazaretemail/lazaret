// SPDX-License-Identifier: AGPL-3.0-only

package main

import "sync/atomic"

// accelerator names the execution provider inference is actually running on.
//
// Untagged, unlike the code that selects one, because the capabilities endpoint
// reports it in both builds — and a deployment with no inference runtime at all
// still has to be able to say so.
type accelerator struct {
	// Provider is what ended up being used: cuda, tensorrt, rocm, coreml,
	// directml, cpu, or none when no model is loaded.
	Provider string `json:"provider"`

	// Detail explains a surprise, such as a requested provider the runtime would
	// not accept.
	Detail string `json:"detail,omitempty"`

	// Tried lists the providers offered to the runtime before one stuck. An
	// operator who mounted a GPU and is getting CPU speeds needs to see that the
	// attempt was made and refused, rather than guess whether it was tried.
	Tried []string `json:"tried,omitempty"`
}

// activeBackend is the execution provider this process settled on, published for
// telemetry.
//
// Process-wide rather than per-call because it is: the runtime picks one provider
// at load and every inference afterwards uses it. Recording it as a label is what
// makes the GPU and CPU numbers legible instead of averaged into one meaningless
// figure — and what shows, after a deploy, that a box meant to be on the GPU
// quietly fell back to CPU.
var activeBackend atomic.Value

func setActiveBackend(name string) {
	if name != "" {
		activeBackend.Store(name)
	}
}

func currentBackend() string {
	if v, ok := activeBackend.Load().(string); ok {
		return v
	}
	return "none"
}
