# SPDX-License-Identifier: AGPL-3.0-only
#
# lazaret-ingest. No cgo, so a static binary on a distroless base.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY services/ingest/go.mod services/ingest/go.sum* ./services/ingest/
COPY . .
WORKDIR /src/services/ingest
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lazaret-ingest .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lazaret-ingest /usr/local/bin/lazaret-ingest
# 8730 rspamd, 8731 graph notifications.
EXPOSE 8730 8731
ENTRYPOINT ["/usr/local/bin/lazaret-ingest"]
