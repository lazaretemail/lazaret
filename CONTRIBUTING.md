# Contributing

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

## Getting set up

Go 1.26 and a Go workspace. The repository is several modules tied together by
`go.work`, so build and test from the root:

```sh
go work sync
go build ./...
go test ./...
```

That covers the core libraries. The services are separate modules and are not in `./...`
from the root, so run them individually when you touch one:

```sh
cd services/engine && go test ./...
```

Some tests need something running and skip cleanly when it is absent:

```sh
LAZARET_TEST_POSTGRES='postgres://lazaret:lazaret@localhost:5433/lazaret?sslmode=disable' \
  go test ./services/engine/store/
```

The render service's browser tests skip without a Chromium on `PATH`. The easiest way to
run them is against the image:

```sh
cd services/render
CGO_ENABLED=0 go test -c -o /tmp/render.test .
docker run --rm -v /tmp/render.test:/t:ro --entrypoint sh lazaret-render -c 'cd /tmp && HOME=/tmp /t -test.v'
```

The dashboard's front end lives in `services/dashboard/web`:

```sh
cd services/dashboard/web && npm ci && npm run build
```

`npm run build` type-checks. The Go binary embeds `dist/`, so a stale build is a stale UI.

## House rules

**Every file gets an SPDX header.** `// SPDX-License-Identifier: AGPL-3.0-only`, or the
comment syntax of whatever the file is. Retrofitting a licence across contributors later
is miserable.

Two exceptions, both about not claiming what is not ours. `api/proto/strelka/v1/` is
vendored from Strelka and carries Apache-2.0, and `strelka/strelkapb/*.pb.go` is
generated from it, so it is Apache-2.0 as well — putting an AGPL header on either would
be a licensing mistake rather than a tidy-up. Anything under `testdata/` is somebody
else's content and keeps their terms.

**Comments explain why, not what.** The codebase leans heavily on this and it is the main
thing to match. A comment that restates the line below it is noise; a comment recording
the measurement, the bug or the specification sentence that made the code look like that
is the reason anyone can change it safely later. Where a number was measured, the comment
says what was measured and what the result was. Where a number was guessed, it says so.

**Tests prove the fix.** Before adding a test, break the fix and check the test fails. A
test that passes against the broken version tests nothing, and a surprising number of
them do. If a bug is worth fixing it is worth a test that would have caught it, and the
test's comment should say what the failure looked like.

**Match the surrounding code.** Comment density, naming, error phrasing. The error strings
here are lowercase sentences that say what was being attempted.

## Changing MQL

This is the part with extra rules, because compatibility is the product.

The corpus tests are the gate. `go test ./mql -run Corpus` walks every rule in
`testdata/sublime-rules` and reports lex, parse, round-trip, type-check and evaluate
rates. CI fails on regression. If your change moves those numbers, say so in the pull
request and say which way.

**Any change to observable MQL behaviour needs a line in
[`docs/SEMANTICS.md`](docs/SEMANTICS.md)**, under one of its existing headings, marked
either specified (with the doc sentence it comes from) or inferred (with the reasoning).
The register exists because the published syntax reference is incomplete — `is null` is
used 413 times in the corpus and appears in no operator table — and the difference
between "the documentation says so" and "we decided this" is the difference between a
compatible implementation and a lookalike.

Deliberate divergences get reported by `mql.PortabilityWarnings` so `lazaret lint` can
tell an author their rule will not run on Sublime's engine. If you add one, add it there
too.

## Changing what a message model contains

`mdm` types are generated from the vendored OpenAPI spec in `mdm/mdm.openapi.json`, and
the type checker's field table is derived from those structs by reflection. Edit the
spec, regenerate, do not hand-edit the generated file — otherwise the schema, the Go
types and the checker drift apart and nothing tells you.

## Adopting another service's wire format

There is a scar here worth reading before you do it. `docs/ARCHITECTURE.md` ends with two
Strelka divergences that were not findable from the published schemas and not findable
from unit tests, because fixtures written from a schema agree with a fake built from the
same schema and the suite stays green. The failure mode was rules quietly matching
nothing.

So: write fixtures from captured output of the real service, keep a live test that
exercises a **non-empty** result for each field that matters, and make a decode failure
loud by default.

## Pull requests

Small and single-purpose. Say what you measured, not what you expect.

If you found a real problem with the approach while implementing it, put that in the
description rather than silently working around it — the working around is usually the
interesting part.

Good first contributions, if you are looking for one:

- A TLD whose RDAP behaviour differs from the bootstrap registry's claim. `rdap/` has
  per-registry quirks and they were found one at a time.
- A `.eml` that parses wrongly. Real mail is stranger than the RFCs, and `eml/eml_test.go`
  grows from exactly this — a message that comes out wrong plus the field that is wrong
  is a complete report.
- A rule in the corpus that behaves differently here than on Sublime's engine. Their
  rule-validate endpoint needs no authentication, so a differential case is cheap to
  produce and is the most valuable thing anyone can send.

## What will get pushed back on

- New dependencies in the root module. It is cgo-free and links seven third-party
  modules, and it stays that way so people can `go get` the MQL engine alone.
- A capability that returns `false` when it means "I could not tell". See the README.
- MinIO or anything named after it, Redis, and legacy WHOIS as anything other than a
  fallback for TLDs with no RDAP service. These are settled.
