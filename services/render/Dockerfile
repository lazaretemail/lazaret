# SPDX-License-Identifier: AGPL-3.0-only
#
# lazaret-render. Chromium plus a small Go binary, and nothing else.

FROM golang:1.26-bookworm AS build
WORKDIR /src

# Built from the repository root, like every other service here — compose passes
# `context: ../..` and the Kubernetes manifests build the same way. An earlier version
# copied *.go from the context root, which finds nothing there and fails with "no Go
# files in /src": the module lives in services/render, not at the top.
COPY go.mod go.sum* ./
COPY services/render/go.mod services/render/go.sum* ./services/render/
COPY . .

WORKDIR /src/services/render
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lazaret-render .

FROM debian:bookworm-slim
# chromium pulls its own font and library dependencies; fonts-liberation and the CJK and
# emoji faces matter because a message rendered with missing glyphs OCRs to nothing, and
# "no text found" would read as a clean message.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium \
      fonts-liberation fonts-dejavu-core fonts-noto-core fonts-noto-cjk fonts-noto-color-emoji \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Unprivileged. Chromium runs with --no-sandbox because its own sandbox needs privileges
# this container deliberately does not have; the container and the network are the
# sandbox instead.
RUN useradd --system --create-home --uid 10001 render
USER render
WORKDIR /home/render

COPY --from=build /out/lazaret-render /usr/local/bin/lazaret-render
EXPOSE 8710
ENTRYPOINT ["/usr/local/bin/lazaret-render"]
