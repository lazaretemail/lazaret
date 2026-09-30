# Security

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

## Reporting a vulnerability

Email **security@lazaret.email**, or open a private advisory through GitHub's
[Report a vulnerability](https://github.com/lazaretemail/lazaret/security/advisories/new)
form. Please do not open a public issue for anything exploitable.

Include what you did, what happened, and what you expected. A sample message that
triggers it is worth more than a description of it — this parser's whole job is
untrusted input, and a `.eml` reproduces in one command.

There is no bounty. This is one person's project. You will get an acknowledgement and an
honest answer about whether and when it will be fixed.

## What is in scope

Everything in this repository, and the deployment in `deploy/`. The parts worth pointing
a fuzzer at:

- **`eml/`** — RFC 822 parsing. The most attacker-exposed code here by a distance: real
  phishing rarely parses cleanly, and every byte of it was chosen by someone hostile.
- **`mql/`** — lexer, parser, checker, evaluator. A rule is usually trusted input, but a
  crafted rule reaching `lazaret lint` from a feed is not.
- **`services/render/`** — a headless Chromium that loads attacker-controlled HTML and,
  with link analysis on, visits attacker-chosen URLs. SSRF guards live in `fetch.go`.
- **`services/ingest/`** — holds mailbox credentials and performs deletions.
- **`services/dashboard/`** — renders attacker-written strings to an operator's browser.

`eml/` and `mql/` have `go test -fuzz` targets. If you find a crasher, the corpus entry
alone is a complete report.

## Out of scope

- Missing hardening on the bundled Garage, Postgres or Garnet as shipped for evaluation.
  `deploy/compose/README.md` says what to change before production; a report that the
  default Postgres password is `lazaret` is already written down there.
- The `analysis` Docker network reaching the internet **when link analysis is enabled**.
  That is the documented trade of turning it on, not a bug. Without it, that network is
  `internal: true`.
- Denial of service through a deliberately expensive message, unless it is cheap to
  produce and expensive out of proportion. Layout is slow; that is known.

## Things this project treats as security bugs even though they look like correctness bugs

Worth stating, because they are the ones that go unreported.

**A capability failing open.** If an unavailable model, list or lookup causes a rule to
evaluate to `false` instead of `indeterminate`, that is a vulnerability: it silently
turns a partial deployment into a confident all-clear. The same goes for a decode that
yields empty fields rather than an error.

**A remediation that quietly does less than it says.** A permanent delete that downgrades
to a recoverable one, a quarantine that reports success without removing the message, a
release that loses the only copy. There has already been one bug in this class and it
logged a plausible-looking reason while doing the wrong thing.

**Custody loss.** Anything that can delete a message from a mailbox without the bytes
being safely held first, or that lets a compaction remove mail under legal hold.

## Supply chain

The root Go module is cgo-free and links seven third-party modules — htmlquery, xpath,
go-message, go-msgauth, groupcache, `x/net`, `x/text`. CI fails the build above twelve,
so a new dependency in the core is a decision somebody makes on purpose.

Services carry much heavier graphs deliberately — an ONNX runtime, a headless browser,
npm for the dashboard — and those are the places to look for dependency risk.

Model weights are not distributed here. `services/ml/fetch-models.sh` downloads them
from Hugging Face and they carry their own licences and their own trust assumptions.
