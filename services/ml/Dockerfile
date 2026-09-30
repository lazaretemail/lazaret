# SPDX-License-Identifier: AGPL-3.0-only
#
# lazaret-ml, in two shapes.
#
# By default there is no inference runtime: a deployment with no weights should not
# need a 200MB native dependency in order to start and report the model-backed
# capabilities unavailable. That build is static and distroless, and it still answers
# everything that needs no model — entity extraction, language identification, the
# macro classifier, brand wordmarks, and the graymail half of the attack score.
#
# Build with --build-arg TAGS=onnx to get the entailment model. That path is cgo and
# needs two native libraries, so it is a different base image; the pinning below is
# load-bearing and explained under "matched pair".

ARG TAGS=none
# Declared before the first FROM so it is in scope for the ROCm base image's tag as
# well as inside the stages. An ARG declared inside a stage is not visible to a FROM.
ARG ROCM_RELEASE=7.2.4

# ---------------------------------------------------------------------------
# Native dependencies, only fetched for the onnx build.
# ---------------------------------------------------------------------------
#
# A matched pair. onnxruntime_go requests a specific ORT API version and refuses a
# runtime older than it: v1.25.0 asks for API 23, which is ONNX Runtime 1.23. A
# mismatch fails at startup with "The requested API version is not available", and the
# service then runs with no model rather than crashing — a quiet failure, so the
# versions here and in go.mod move together or not at all.
#
# 1.23 rather than something newer, and that is AMD's doing. The only prebuilt ONNX
# Runtime with an AMD GPU provider is the onnxruntime_migraphx wheel on
# repo.radeon.com, which is built at 1.23.2 — so pinning the whole project there is
# what makes GPU inference possible at all. The alternative is building ONNX Runtime
# from source with --use_rocm, which is hours of compilation per image.
FROM debian:bookworm-slim AS native
ARG ORT_VERSION=1.23.2
# cpu, gpu or rocm.
#
#   cpu   Microsoft's CPU tarball. Refuses every GPU provider, which is exactly what
#         the accelerator probe reports.
#   gpu   Microsoft's tarball with the CUDA and TensorRT providers, for NVIDIA.
#   rocm  AMD's onnxruntime_migraphx wheel, which carries a full libonnxruntime.so
#         alongside the MIGraphX provider. Not a tarball and not from Microsoft —
#         they publish no ROCm build — so it is fetched and unpacked differently
#         below.
#
# The Go binary is identical in all three. Only the runtime library differs, which is
# the whole reason the provider choice is made by trying rather than by build tag.
ARG ORT_FLAVOR=cpu
# Which ROCm release AMD's wheel was built against. Declared globally above; repeated
# here to bring it into this stage's scope. It has to match the ROCm runtime in the
# image below, and both have to be new enough for the card: RDNA4 (gfx1200, the
# RX 9060 XT) needs ROCm 7.
ARG ROCM_RELEASE
ARG ORT_MIGRAPHX_WHEEL=onnxruntime_migraphx-1.23.2-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl
ARG TOKENIZERS_VERSION=v1.27.0
ARG TARGETARCH=amd64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) ORT_ARCH=x64; TOK_ARCH=amd64 ;; \
      arm64) ORT_ARCH=aarch64; TOK_ARCH=arm64 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    mkdir -p /native/lib; \
    if [ "$ORT_FLAVOR" = "rocm" ]; then \
      # A wheel is a zip. The libraries inside it are what is wanted; the Python
      # around them is not, and nothing in this image can run it anyway.
      curl -fsSL -o /tmp/ort.whl \
        "https://repo.radeon.com/rocm/manylinux/rocm-rel-${ROCM_RELEASE}/${ORT_MIGRAPHX_WHEEL}"; \
      mkdir -p /tmp/whl && cd /tmp/whl && unzip -q /tmp/ort.whl; \
      cp onnxruntime/capi/libonnxruntime.so.* /native/lib/; \
      cp onnxruntime/capi/libonnxruntime_providers_*.so /native/lib/; \
      # The loader wants the unversioned name; the wheel ships only the versioned one.
      ln -sf "$(cd /native/lib && ls libonnxruntime.so.*)" /native/lib/libonnxruntime.so; \
      cd /; \
    else \
      case "$ORT_FLAVOR" in \
        gpu) ORT_NAME="onnxruntime-linux-${ORT_ARCH}-gpu-${ORT_VERSION}" ;; \
        *)   ORT_NAME="onnxruntime-linux-${ORT_ARCH}-${ORT_VERSION}" ;; \
      esac; \
      curl -fsSL -o /tmp/ort.tgz \
        "https://github.com/microsoft/onnxruntime/releases/download/v${ORT_VERSION}/${ORT_NAME}.tgz"; \
      tar -xzf /tmp/ort.tgz -C /tmp; \
      cp /tmp/${ORT_NAME}/lib/libonnxruntime*.so* /native/lib/; \
    fi; \
    curl -fsSL -o /tmp/tok.tar.gz \
      "https://github.com/daulet/tokenizers/releases/download/${TOKENIZERS_VERSION}/libtokenizers.linux-${TOK_ARCH}.tar.gz"; \
    tar -xzf /tmp/tok.tar.gz -C /native/lib

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM golang:1.26-bookworm AS build
ARG TAGS=none
WORKDIR /src

# From the repository root, like the other services: the module is in services/ml,
# so copying *.go from the context root finds nothing.
COPY go.mod go.sum* ./
COPY services/ml/go.mod services/ml/go.sum* ./services/ml/
COPY . .
COPY --from=native /native/lib /native/lib

WORKDIR /src/services/ml
RUN set -eux; \
    if [ "$TAGS" = "onnx" ]; then \
      apt-get update && apt-get install -y --no-install-recommends g++ && rm -rf /var/lib/apt/lists/*; \
      CGO_ENABLED=1 CGO_LDFLAGS="-L/native/lib" \
        go build -tags=onnx -trimpath -ldflags="-s -w" -o /out/lazaret-ml .; \
    else \
      CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lazaret-ml .; \
    fi

# ---------------------------------------------------------------------------
# Runtime: static and distroless without the runtime, glibc-based with it.
# ---------------------------------------------------------------------------
# Stage names, selected by the TAGS build arg at the bottom. "none" rather than an
# empty string, because `FROM runtime-` is not a valid reference and buildkit rejects
# it before it ever reaches the stage lookup.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime-none
COPY --from=build /out/lazaret-ml /usr/local/bin/lazaret-ml

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime-onnx
COPY --from=build /out/lazaret-ml /usr/local/bin/lazaret-ml
COPY --from=native /native/lib/libonnxruntime*.so* /usr/local/lib/
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV ONNXRUNTIME_LIB=/usr/local/lib/libonnxruntime.so

# The GPU variant. Built with:
#
#   docker build -f services/ml/Dockerfile \
#     --build-arg TAGS=onnx --build-arg ORT_FLAVOR=gpu --target runtime-gpu \
#     -t lazaret-ml:gpu .
#
# A CUDA runtime base rather than distroless, because the execution provider
# dlopens libcublas, libcudnn and friends at session creation and they are not
# things to vendor by hand. Run it with the NVIDIA container runtime; without a
# visible device the accelerator probe simply reports what it tried and uses the
# CPU, so the same image is safe to deploy on a node with no card.
FROM nvidia/cuda:12.6.2-cudnn-runtime-ubuntu24.04 AS runtime-gpu
ARG TENSORRT_MAJOR=10

# TensorRT as well as CUDA, because the ONNX Runtime GPU package ships both providers
# and this image only had the libraries for one of them.
#
# The accelerator probe tries tensorrt before cuda — TensorRT compiles the graph and
# is the faster of the two on a transformer — and without libnvinfer it failed to load
# every time and fell through to CUDA. The service then reported
# `tried: [tensorrt, cuda]` with `provider: cuda`, which is accurate and makes it look
# like the hardware refused TensorRT rather than that the image never had it.
#
# Three packages: the runtime, the plugin library, and the ONNX parser. The parser
# is easy to miss — the provider loads without it right up until it is handed a model,
# and ldd reports libnvonnxparser.so.10 as the only unresolved name.
#
# The base image already configures NVIDIA's apt repository, so no second registry.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      libnvinfer${TENSORRT_MAJOR} libnvinfer-plugin${TENSORRT_MAJOR} \
      libnvonnxparsers${TENSORRT_MAJOR}; \
    rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 65532 nonroot
COPY --from=build /out/lazaret-ml /usr/local/bin/lazaret-ml
COPY --from=native /native/lib/libonnxruntime*.so* /usr/local/lib/
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/cuda/lib64
ENV ONNXRUNTIME_LIB=/usr/local/lib/libonnxruntime.so
USER 65532

# The AMD variant. Built with:
#
#   docker build -f services/ml/Dockerfile \
#     --build-arg TAGS=onnx --build-arg ORT_FLAVOR=rocm --target runtime-rocm \
#     -t lazaret-ml:rocm .
#
# A ROCm runtime base, for the same reason the CUDA variant uses one: MIGraphX
# dlopens its own stack at session creation and those are not libraries to vendor by
# hand. Run it with the device nodes and groups in deploy/compose/docker-compose.rocm
# .yml; without a visible device the accelerator probe reports what it tried and uses
# the CPU, so the image is safe to deploy on a node with no card.
# Plain Ubuntu plus the ROCm runtime, not one of AMD's ROCm images.
#
# This used to be rocm/dev-ubuntu-22.04:${ROCM_RELEASE}-complete and produced a 30GB
# image: "-complete" is AMD's everything tag — compilers, headers, debug symbols, the
# HIP SDK — none of which a container that runs one inference binary has any use for.
# It was also more than a hosted CI runner has free, so the image could not be built
# in the open.
#
# Dropping to the plain dev tag got it to 16.8GB, which is better and still a
# development image. Installing the runtime packages onto Ubuntu is the actual answer.
#
# What is left is genuinely large and there is no trick for it: miopen-hip is 2.9GB,
# migraphx 1.7GB and rocblas 0.76GB, almost entirely precompiled GPU kernels for every
# architecture AMD supports. A deployment targeting one card could delete the kernels
# for the others, but a published image does not know which card it will land on.
FROM ubuntu:22.04 AS runtime-rocm
ARG ROCM_RELEASE

# Optionally prune GPU kernels to the architectures this image will actually run on.
#
# hipblaslt alone ships 3,027 precompiled kernel files — one set per AMD architecture
# from gfx90a to gfx1201 — and with rocblas and MIOpen beside it that is most of the
# image. A deployment uses exactly one of those sets.
#
# Empty by default, which keeps all of them, because a published image does not know
# which card it will land on and an image that silently cannot use the GPU it was
# given is worse than a large one. Set it when building for your own hardware:
#
#   --build-arg ROCM_ARCHS=gfx1200          # RX 9000 series
#   --build-arg ROCM_ARCHS='gfx1100 gfx1101'
#
# `rocminfo | grep gfx` on the host says which you need.
ARG ROCM_ARCHS=""

# Install, strip and prune in one layer.
#
# Not three, which is how this was written first and why it did nothing: a layer only
# ever adds, so deleting five gigabytes in a later RUN leaves the image exactly as
# large and adds a whiteout for every file. The prune reported 10549MB going to 4829MB
# and the image stayed at 15.6GB.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    install -d -m 0755 /etc/apt/keyrings; \
    curl -fsSL https://repo.radeon.com/rocm/rocm.gpg.key \
      | gpg --dearmor -o /etc/apt/keyrings/rocm.gpg; \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/rocm.gpg] \
https://repo.radeon.com/rocm/apt/${ROCM_RELEASE} jammy main" \
      > /etc/apt/sources.list.d/rocm.list; \
    # Ubuntu ships its own rocminfo at a higher version number than AMD's, so without
    # a pin apt resolves rocm-hip-runtime's dependency against the distro package and
    # reports held broken packages. AMD documents this pin for exactly this reason.
    printf 'Package: *\nPin: release o=repo.radeon.com\nPin-Priority: 600\n' \
      > /etc/apt/preferences.d/rocm; \
    apt-get update; \
    # rocm-hip-runtime is a metapackage pulling the HIP runtime, HSA and the device
    # libraries. migraphx is the inference graph compiler the provider dlopens; it is
    # not part of the runtime metapackage, and without libmigraphx_c.so.3 the provider
    # fails to load with an error that reads like a broken ONNX Runtime.
    apt-get install -y --no-install-recommends rocm-hip-runtime migraphx; \
    apt-get purge -y curl gnupg; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*; \
    # Nothing here compiles against ROCm, so the development half is dead weight.
    rm -rf /opt/rocm*/include /opt/rocm*/share/doc /opt/rocm*/lib/cmake \
           /opt/rocm*/lib/llvm/lib/clang/*/include /opt/rocm*/llvm/lib/clang/*/include; \
    find /opt/rocm*/ -name '*.a' -delete; \
    if [ -n "$ROCM_ARCHS" ]; then \
      keep=""; \
      for a in $ROCM_ARCHS; do keep="$keep -e $a"; done; \
      for d in /opt/rocm*/lib/hipblaslt/library /opt/rocm*/lib/rocblas/library \
               /opt/rocm*/share/miopen/db; do \
        [ -d "$d" ] || continue; \
        find "$d" -maxdepth 1 -type f -name '*gfx*' | grep -v $keep | xargs -r rm -f; \
      done; \
    fi; \
    du -sh /opt/rocm*/

RUN useradd --system --uid 65532 nonroot
# Seed the compile-cache directories with the right owner.
#
# A named volume mounted here starts empty and root-owned, and the service runs
# unprivileged — so it could not create these itself, and MIGraphX would compile for
# three minutes and then fail to save, once per restart, reporting it only as a line
# in the log. Docker initialises an empty named volume from the image, ownership
# included, so creating them here is what makes the mount usable.
RUN mkdir -p /var/lib/lazaret/gpu-cache/migraphx /var/lib/lazaret/gpu-cache/miopen \
 && chown -R 65532:65532 /var/lib/lazaret/gpu-cache
COPY --from=build /out/lazaret-ml /usr/local/bin/lazaret-ml
COPY --from=native /native/lib/libonnxruntime*.so* /usr/local/lib/
ENV LD_LIBRARY_PATH=/usr/local/lib:/opt/rocm/lib
ENV ONNXRUNTIME_LIB=/usr/local/lib/libonnxruntime.so
USER 65532
VOLUME ["/var/lib/lazaret/models"]
EXPOSE 8720
ENTRYPOINT ["/usr/local/bin/lazaret-ml"]

FROM runtime-${TAGS}
# Models are mounted, never baked in: weights carry their own licence, independent of
# this code, and an AGPL image that bundles them inherits whatever terms they came with.
# The layout is documented in the README — zeroshot.onnx and its tokenizer, plus an
# optional logos/ reference pack.
VOLUME ["/var/lib/lazaret/models"]
EXPOSE 8720
ENTRYPOINT ["/usr/local/bin/lazaret-ml"]
