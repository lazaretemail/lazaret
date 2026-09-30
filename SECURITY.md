# Security

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

## Reporting a vulnerability

Email **security@lazaret.email**, or open a private advisory through GitHub's
[Report a vulnerability](https://github.com/lazaretemail/lazaret/security/advisories/new)
form. Please don't open a public issue for anything exploitable.

Tell us what you did, what happened, and what you expected instead. A sample message that
triggers the bug beats a description of one. This parser's entire job is untrusted input,
and a `.eml` reproduces in a single command.

There's no bounty. This is one person's project. You'll get an acknowledgement and a
straight answer about whether and when it'll be fixed.

## What's in scope

Everything in this repository, plus the deployment in `deploy/`. The parts most worth
pointing a fuzzer at:

- **`eml/`** — RFC 822 parsing. Easily the most attacker-exposed code here. Real phishing
  rarely parses cleanly, and every byte of it was chosen by someone hostile.
- **`mql/`** — lexer, parser, checker, evaluator. Rules are usually trusted input, but a
  crafted rule arriving from a feed and reaching `lazaret lint` isn't.
- **`services/render/`** — a headless Chromium that loads attacker-controlled HTML and,
  once link analysis is on, visits attacker-chosen URLs. The SSRF guards are in `fetch.go`.
- **`services/ingest/`** — holds mailbox credentials and performs deletions.
- **`services/dashboard/`** — renders attacker-written strings into an operator's browser.

`eml/` and `mql/` have `go test -fuzz` targets. If you find a crasher, the corpus entry on
its own is a complete report.

## Out of scope

- Missing hardening on the bundled Garage, Postgres or Garnet as shipped for evaluation.
  `deploy/compose/README.md` lists what to change before production. The default Postgres
  password being `lazaret` is already documented there.
- The `analysis` Docker network reaching the internet **when link analysis is enabled**.
  That's the documented trade you make by turning it on. Leave it off and the network is
  `internal: true`.
- Denial of service through a deliberately expensive message, unless it's cheap to produce
  and disproportionately expensive to handle. Layout is slow, and we know it.

## Correctness bugs we treat as security bugs

Worth spelling out, because these are the ones that go unreported.

**A capability failing open.** If an unavailable model, list or lookup makes a rule
evaluate to `false` instead of `indeterminate`, that's a vulnerability. It silently turns a
partial deployment into a confident all-clear. Same goes for a decode that yields empty
fields where it should have returned an error.

**A remediation that quietly does less than it claims.** A permanent delete that downgrades
to a recoverable one, a quarantine that reports success without removing the message, a
release that loses the only copy. We've already had one bug in this class, and it logged a
perfectly plausible reason while doing the wrong thing.

**Custody loss.** Anything that can delete a message from a mailbox before the bytes are
safely held, or that lets a compaction remove mail under legal hold.

## Supply chain

The root Go module is cgo-free and links seven third-party modules: htmlquery, xpath,
go-message, go-msgauth, groupcache, `x/net` and `x/text`. CI fails the build if that goes
above twelve, so adding a dependency to the core is a decision someone has to make on
purpose.

Services carry much heavier dependency graphs, and that's intentional. An ONNX runtime, a
headless browser, npm for the dashboard. Those are the places to look for dependency risk.

Model weights aren't distributed here. `services/ml/fetch-models.sh` downloads them from
Hugging Face, and they come with their own licences and their own trust assumptions.
