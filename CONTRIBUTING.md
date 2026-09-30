# Contributing

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

## Getting set up

You need Go 1.26 and a Go workspace. The repository is several modules tied together by
`go.work`, so build and test from the root:

```sh
go work sync
go build ./...
go test ./...
```

That covers the core libraries. The services are separate modules and don't appear in
`./...` from the root, so run them individually when you touch one:

```sh
cd services/engine && go test ./...
```

Some tests need something running, and skip cleanly when it isn't:

```sh
LAZARET_TEST_POSTGRES='postgres://lazaret:lazaret@localhost:5433/lazaret?sslmode=disable' \
  go test ./services/engine/store/
```

The render service's browser tests skip without a Chromium on `PATH`. Easiest way to run
them is against the image:

```sh
cd services/render
CGO_ENABLED=0 go test -c -o /tmp/render.test .
docker run --rm -v /tmp/render.test:/t:ro --entrypoint sh lazaret-render -c 'cd /tmp && HOME=/tmp /t -test.v'
```

The dashboard's front end lives in `services/dashboard/web`:

```sh
cd services/dashboard/web && npm ci && npm run build
```

`npm run build` type-checks as it goes. The Go binary embeds `dist/`, so a stale build
means a stale UI.

## House rules

**Every file gets an SPDX header.** `// SPDX-License-Identifier: AGPL-3.0-only`, in
whatever comment syntax the file uses. Retrofitting a licence across contributors later is
miserable.

There are two exceptions, both about not claiming what isn't ours.
`api/proto/strelka/v1/` is vendored from Strelka and carries Apache-2.0, and
`strelka/strelkapb/*.pb.go` is generated from it, so it's Apache-2.0 too. Putting an AGPL
header on either would be a licensing mistake dressed up as tidying. Anything under
`testdata/` is somebody else's content and keeps their terms.

**Comments explain why, not what.** The codebase leans on this heavily and it's the main
thing to match. A comment restating the line below it is noise. A comment recording the
measurement, the bug or the specification sentence that made the code look the way it does
is what lets someone change it safely a year later. Where a number was measured, say what
was measured and what came back. Where a number was guessed, say that too.

**Tests prove the fix.** Before you add a test, break the fix and check the test fails
without it. A test that passes against the broken version tests nothing, and a surprising
number of them do. If a bug is worth fixing it's worth a test that would have caught it,
and that test's comment should describe what the failure looked like.

**Match the surrounding code.** Comment density, naming, error phrasing. Error strings here
are lowercase sentences describing what was being attempted.

## Changing MQL

This part has extra rules, because compatibility is the product.

The corpus tests are the gate. `go test ./mql -run Corpus` walks every rule in
`testdata/sublime-rules` and reports lex, parse, round-trip, type-check and evaluate rates.
CI fails on any regression. If your change moves those numbers, say so in the pull request,
and say which direction.

**Any change to observable MQL behaviour needs a line in
[`docs/SEMANTICS.md`](docs/SEMANTICS.md)**, under one of the existing headings, marked
either specified (quote the doc sentence) or inferred (give the reasoning). That register
exists because the published syntax reference is incomplete. `is null` is used 413 times in
the corpus and appears in no operator table. Keeping "the documentation says so" separate
from "we decided this" is what separates a compatible implementation from a lookalike.

Deliberate divergences get reported by `mql.PortabilityWarnings`, so `lazaret lint` can
warn an author that their rule won't run on Sublime's engine. If you add one, add it there
as well.

## Changing what a message model contains

The `mdm` types are generated from the vendored OpenAPI spec in `mdm/mdm.openapi.json`, and
the type checker's field table is derived from those structs by reflection. Edit the spec
and regenerate. Don't hand-edit the generated file, or the schema, the Go types and the
checker will drift apart with nothing to tell you.

## Adopting another service's wire format

There's a scar here worth reading first. `docs/ARCHITECTURE.md` ends with two Strelka
divergences that weren't findable from the published schemas and weren't findable from unit
tests either, because fixtures written from a schema agree with a fake built from the same
schema and the suite stays green throughout. What it actually looked like was rules quietly
matching nothing.

So: write fixtures from captured output of the real service, keep a live test that
exercises a **non-empty** result for every field that matters, and make decode failures
loud by default.

## Pull requests

Keep them small and single-purpose. Say what you measured rather than what you expect.

If you hit a real problem with the approach while implementing it, put that in the
description instead of silently working around it. The working around is usually the
interesting part.

If you're looking for somewhere to start:

- A TLD whose RDAP behaviour differs from what the bootstrap registry claims. `rdap/` has
  per-registry quirks and they were found one at a time.
- A `.eml` that parses wrongly. Real mail is stranger than the RFCs, and `eml/eml_test.go`
  grows from exactly this. A message that comes out wrong, plus the field that's wrong, is
  a complete report.
- A corpus rule that behaves differently here than on Sublime's engine. Their rule-validate
  endpoint needs no authentication, so a differential case is cheap to produce and about
  the most valuable thing anyone can send us.

## What will get pushed back on

- New dependencies in the root module. It's cgo-free and links seven third-party modules,
  and it stays that way so people can `go get` the MQL engine on its own.
- A capability returning `false` when it means "I couldn't tell". See the README.
- MinIO or anything named after it, Redis, and legacy WHOIS as anything other than a
  fallback for TLDs with no RDAP service. Those are settled.
