# SPDX-License-Identifier: AGPL-3.0-only
#
# lazaret-dashboard. The console is a compiled Vue application embedded in the Go
# binary, so the runtime image is still one static binary with no filesystem
# dependencies — npm exists only in the build stage and never ships.

FROM node:24-bookworm-slim AS console
WORKDIR /web
# Dependencies first, so a change to the application source does not re-resolve them.
COPY services/dashboard/web/package.json services/dashboard/web/package-lock.json ./
RUN npm ci
COPY services/dashboard/web/ ./
# Type-checks as well as bundles: `npm run build` runs vue-tsc first, so a component
# that disagrees with the generated API types fails the image build rather than
# rendering a blank panel in production.
RUN npm run build

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
COPY services/dashboard/go.mod services/dashboard/go.sum* ./services/dashboard/
COPY . .
COPY --from=console /web/dist ./services/dashboard/web/dist
WORKDIR /src/services/dashboard
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/lazaret-dashboard .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lazaret-dashboard /usr/local/bin/lazaret-dashboard
EXPOSE 8740
ENTRYPOINT ["/usr/local/bin/lazaret-dashboard"]
