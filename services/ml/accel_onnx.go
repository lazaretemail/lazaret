// SPDX-License-Identifier: AGPL-3.0-only

//go:build onnx

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	ort "github.com/yalue/onnxruntime_go"
)

// Hardware acceleration, chosen by trying it.
//
// Not by inspecting the machine. Asking "is there a GPU" is the wrong question and
// answering it is a swamp — an nvidia device node can exist with no driver, a driver
// can exist with no CUDA runtime, the CUDA runtime can be a version this build of
// ONNX Runtime will not load, and a container can see /dev/nvidia0 while the libraries
// it needs live on the host. Every one of those looks like a GPU to a probe and fails
// at the first inference.
//
// So each provider is *appended* to a real session options, and whichever one the
// runtime accepts is the one used. The failure mode is an error string at startup
// rather than a crash on the first message.
//
// Order is fastest-first, and CPU is always last and always works.

// applyAccelerators configures the best execution provider the runtime will accept.
//
// `prefer` overrides the order, for a deployment that has a GPU and wants it left
// alone — an inference box shared with something that actually needs the card.
func applyAccelerators(opts *ort.SessionOptions, prefer string) accelerator {
	acc := accelerator{Provider: "cpu"}

	if prefer == "cpu" {
		acc.Detail = "pinned to CPU by -accelerator=cpu"
		return acc
	}

	type provider struct {
		name  string
		apply func(*ort.SessionOptions) error
		when  bool
	}

	// CoreML on Apple silicon, DirectML on Windows, CUDA/TensorRT on NVIDIA and
	// MIGraphX/ROCm on AMD.
	// Listed rather than detected, because the build tags that would detect them
	// are the same ones that decide whether the symbols exist at all.
	providers := []provider{
		{
			name: "tensorrt",
			when: runtime.GOOS == "linux" && prefer != "cuda",
			apply: func(o *ort.SessionOptions) error {
				trt, err := ort.NewTensorRTProviderOptions()
				if err != nil {
					return err
				}
				defer trt.Destroy()
				return o.AppendExecutionProviderTensorRT(trt)
			},
		},
		{
			name: "cuda",
			when: runtime.GOOS == "linux" || runtime.GOOS == "windows",
			apply: func(o *ort.SessionOptions) error {
				cuda, err := ort.NewCUDAProviderOptions()
				if err != nil {
					return err
				}
				defer cuda.Destroy()
				// device_id 0 unless told otherwise. A box with two cards and two
				// tenants wants to say which.
				if id := os.Getenv("LAZARET_GPU_DEVICE"); id != "" {
					if err := cuda.Update(map[string]string{"device_id": id}); err != nil {
						return err
					}
				}
				return o.AppendExecutionProviderCUDA(cuda)
			},
		},
		{
			// MIGraphX before ROCm, on AMD's own advice and for the practical
			// reason that it is the one they ship: repo.radeon.com publishes
			// onnxruntime_migraphx, not onnxruntime-rocm, and the wheel carries
			// the graph-compiler provider rather than the direct one. It is also
			// the faster of the two — MIGraphX compiles the graph instead of
			// dispatching op by op.
			name: "migraphx",
			when: runtime.GOOS == "linux",
			apply: func(o *ort.SessionOptions) error {
				return o.AppendExecutionProvider("MIGraphXExecutionProvider", nil)
			},
		},
		{
			name:  "rocm",
			when:  runtime.GOOS == "linux",
			apply: func(o *ort.SessionOptions) error { return o.AppendExecutionProvider("ROCMExecutionProvider", nil) },
		},
		{
			name:  "coreml",
			when:  runtime.GOOS == "darwin",
			apply: func(o *ort.SessionOptions) error { return o.AppendExecutionProviderCoreMLV2(nil) },
		},
		{
			name:  "directml",
			when:  runtime.GOOS == "windows",
			apply: func(o *ort.SessionOptions) error { return o.AppendExecutionProviderDirectML(0) },
		},
	}

	for _, p := range providers {
		if !p.when {
			continue
		}
		if prefer != "" && prefer != "auto" && prefer != p.name {
			continue
		}
		acc.Tried = append(acc.Tried, p.name)
		if err := p.apply(opts); err != nil {
			// Expected on most machines, and not worth a warning: a CPU-only build
			// of the runtime refuses every GPU provider by design.
			log.Printf("lazaret-ml: %s unavailable (%s)", p.name, firstLine(err.Error()))
			continue
		}
		acc.Provider = p.name
		return acc
	}

	if prefer != "" && prefer != "auto" && prefer != "cpu" {
		acc.Detail = fmt.Sprintf("%s was requested and the runtime would not accept it", prefer)
	}
	return acc
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
