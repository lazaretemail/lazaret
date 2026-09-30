# SPDX-License-Identifier: AGPL-3.0-only
#
# lazaret-engine. The one image in the tree that needs cgo: DuckDB is linked in, because
# it is the hunt engine and the DuckLake client. See docs/ADR-001-storage.md.

FROM golang:1.26-bookworm AS build
WORKDIR /src

# The service depends on the root module by relative path, so both are copied.
COPY go.mod go.sum ./
COPY services/engine/go.mod services/engine/go.sum* ./services/engine/
COPY . .

WORKDIR /src/services/engine
# CGO_ENABLED=1: duckdb-go links DuckDB's C++ library. Statically linked so the runtime
# image does not need the toolchain that built it.
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/lazaret-engine .

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
 && rm -rf /var/lib/apt/lists/*

# The group id is pinned, not left to useradd.
#
# --system allocates a group id from wherever the distribution's range happens to
# start — 999 here — so the files this process creates end up group-owned by a
# number nothing else can predict. The mail connector reads the token by being a
# member of this group, and "add the group the engine happened to get" is not
# something a compose file can express.
RUN groupadd --system --gid 10002 engine \
 && useradd --system --create-home --uid 10002 --gid 10002 engine
# Seeded here so the state volume is usable.
#
# A named volume mounted at a path the image does not contain starts empty and
# root-owned, and this process runs unprivileged — so it could not create the
# directory it is about to generate a credential key into. Docker initialises an
# empty volume from the image, ownership included, which is what makes this work.
# Without it the engine restarts forever on a fresh deployment, reporting only
# "permission denied" on a path nobody configured.
RUN mkdir -p /var/lib/lazaret/state \
 && chown -R 10002:10002 /var/lib/lazaret
USER engine
WORKDIR /home/engine

COPY --from=build /out/lazaret-engine /usr/local/bin/lazaret-engine
EXPOSE 8700
ENTRYPOINT ["/usr/local/bin/lazaret-engine"]
