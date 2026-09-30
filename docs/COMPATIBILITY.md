# Compatibility

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

The claim this project makes is falsifiable: the MIT-licensed rules in
[`sublime-security/sublime-rules`](https://github.com/sublime-security/sublime-rules) should
run here unmodified. This page holds the number.

`go test ./mql -run TestCorpus` walks the corpus and reports, per entity type, how many
rules **parse**, how many **type-check**, and how many **evaluate** without error against
the sample messages. CI fails on regression.

## Current

1,521 rule entities across five types, from the corpus at the pinned commit in
`testdata/sublime-rules`.

| Stage | rule | query | dlp | exclusion | triage_rule | total |
|---|---|---|---|---|---|---|
| Lex        | 1285/1285 | 133/133 | 77/77 | 10/10 | 16/16 | **100%** |
| Parse      | 1285/1285 | 133/133 | 77/77 | 10/10 | 16/16 | **100%** |
| Round-trip | 1285/1285 | 133/133 | 77/77 | 10/10 | 16/16 | **100%** |
| Type-check | 1285/1285 | 133/133 | 77/77 | 10/10 | 16/16 | **100%** |
| Evaluate   | 1285/1285 | 133/133 | 77/77 | 10/10 | n/a | **100%** |

Evaluation runs every rule against the six real phishing samples in the corpus's `emls/`
and requires that each reaches a verdict without error. Automations are excluded: they run
over triage state rather than over a message.

**Five entities fire on the samples, using only the pure functions — no model, no
network, no file explosion:**

| Entity | Type |
|---|---|
| `punycode_sender_domain` | detection rule |
| `link_contains_punycode_characters` | detection rule |
| `impersonation_sublime_security` | detection rule |
| `suspicious_subject` | insight query |
| `sender_domain_matches_no_body_domains` | insight query |

Eight matches across 9,030 rule-message pairs, because some entities fire on more than one
sample. This is the whole claim demonstrated end to end: Sublime's rules, unmodified,
catching real phishing on an open engine. The punycode matches are **exactly** what
Sublime's own engine reports for that message — see the differential section below.

It was five until that differential run, which showed *Brand impersonation: Robinhood* was
a false positive: it fired only because an unavailable ML classifier was being read as an
empty result rather than an unknown one.

`network.whois` is implemented (over RDAP) and can be enabled with `lazaret run -rdap`,
which moves the 116 rules that read `days_old` from indeterminate to a real verdict. It is
off by default: running a tool over a message should not reach the network unasked.

The same flag also enables two **extension** functions, `rdap.ip` and `rdap.asn`, which
MQL does not have. They are registered only on an extended registry, never on the standard
one, so a rule using them will not run on Sublime's engine — and the corpus pass rates
above are measured against the unextended surface, so they keep meaning what they say.

Of the 9,030 rule-message evaluations the library performs with no enrichment
configured, **1,309 report indeterminate** — the rule needed a model, a network lookup,
file explosion or a named list that this build does not provide, and said so. Those are
passes. Reporting them as no-match is the failure this design exists to avoid.

That number has moved twice and both moves are worth recording. It was 1,182 until the
differential run below, which found 420 evaluations answering a confident no-match over
something they could not see, and pushed it up to 1,602. It came back down to 1,309 as
capabilities were implemented. A number that only ever falls would mean the engine was
getting better at guessing.

Round-trip means: parse a rule, render it back to MQL, parse that, and get identical
text. It is what makes `lazaret fmt` safe to run across someone's rule library, and it is
a sharp check on the parser — a misplaced precedence or a dropped pair of parentheses
shows up as text that does not survive a second pass, even when the first parse
succeeded.

Every construct is exercised by what the corpus actually contains rather than by what
the docs describe. Nodes seen: 54,740 field accesses, 32,222 names, 27,273 strings,
21,623 binary operators, 19,454 calls, 11,855 scope references, 5,114 explicit
parenthesis groups, 3,589 membership tests, 2,093 list references, 1,507 tuples, 553
subscripts, 413 `is null`, 229 keyword arguments, 222 thresholds, 120 ranges.

Type-checking resolves every field path against the data model and every call against the
function registry. It started at 83% and the gap was closed from evidence rather than by
loosening the checker: the failures were grouped by cause, and each cause was a real thing
the published schemas do not say. Notably —

- `ml.logo_detect` returns one result, not an array. The published signature says
  `-> [LogoDetectOutput]`, but all 127 calls in the corpus read `.brands` directly off it.
- `$org_vips` holds people, not strings. Typing every named list as an array of strings
  rejected 75 rules that read `.display_name` and `.email` off list elements.
- `network.whois(...).name_servers` holds domains, not strings — rules read `.root_domain`
  off them to catch a whole hosting provider at once.
- Four functions exist only in the corpus: `beta.file.parse_ics`, `beta.profile.by_reply_to`,
  the `hash.*` namespace, and an unqualified `ilike`.
- `strings.parse_domain(...)` has an `error` field that the published Domain schema omits.

Three constructs absent from the published syntax reference are confirmed necessary:
`is null` (413 uses), keyword arguments (229), and scope climbing past `..` — the
corpus reaches `...`, so the generalisation to N dots is earned rather than
speculative.

## Enrichment coverage

Every capability MQL declares, and what answers it.

| Capability | Corpus calls | Answered by | Needs |
|---|---|---|---|
| `beta.ml_extract_sensitive_information` | 304 | `sensitive` — patterns and checksums | nothing |
| `$list` data (22 of 32 lists) | 1,300+ | `lists`, embedded | nothing |
| `beta.ocr` | 311 | Strelka `ScanOcr` | Strelka |
| `beta.parse_exif` | 104 | Strelka `ScanExiftool` | Strelka |
| `beta.scan_qr` | 30 | Strelka `ScanQr` | Strelka |
| `file.explode`, `file.expand_archives` | 519 | Strelka | Strelka |
| `network.whois` | 157 | `rdap`, in-repo | `-rdap` |
| `profile.*` | 898 | `profile`, event log | `-history` |
| `file.message_screenshot`, `file.html_screenshot` | 355 | `lazaret-render` | Chromium |
| `ml.link_analysis` | 382 | `lazaret-render` — all but `credphish` | Chromium + egress |
| ranked domain lists (tranco, umbrella, …) | 72 | `lists`, fetched | `-fetch-lists` |
| `ml.nlu_classifier` | 731 | `lazaret-ml` | a model |
| `ml.logo_detect` | 127 | `lazaret-ml` | a model |
| `beta.ml_topic`, `ml.attack_score`, `ml.macro_classifier`, `beta.ml_translate`, `beta.fuzzy_attack_score` | 33 | `lazaret-ml` | a model |
| `file.oletools` | 16 | `oletools`, in-repo | nothing |

### Most of the ml.* namespace is not machine learning

That is the finding that shaped module 5, and it is why `lazaret-ml` is small. Of the
capabilities that live in the `ml.*` and `beta.ml_*` namespaces:

- **`beta.ml_extract_sensitive_information`** (304 calls) is patterns and checksums. All
  75 types the corpus names are formats, and most carry a checksum — a credit card
  number is not something a model recognises, it is something Luhn validates. It runs
  in-process with nothing to configure, and fires seven corpus DLP rules on an outbound
  message carrying a card, an IBAN, a routing number, an SSN and an AWS key.
- **`ml.link_analysis`** (382) is three-quarters a browser. `final_dom` (133),
  `effective_url` (60), `redirect_history` (28), `unique_urls_accessed` (16),
  `files_downloaded` (17) and `screenshot` (15) are observations. Only `credphish` (66)
  is a model's opinion, and it stays absent rather than guessed.
- **`beta.ocr`, `beta.scan_qr`, `beta.parse_exif`** (445 between them) are Strelka
  scanners — tesseract, zbar and exiftool, already running over every file.

What is irreducibly a model's opinion is `ml.nlu_classifier` and the small tail beside
it. `lazaret-ml` serves those, and ships no weights.

### Why no weights ship

**Licensing.** Model weights carry their own licence independent of this code, and an
AGPL-3.0 project that bundles them inherits whatever terms they arrived with.

**Honesty, demonstrated rather than asserted.** The corpus is full of clauses shaped
like `not any(ml.nlu_classifier(...).topics, .name in (...) and .confidence == "high")`,
written to *exclude* benign mail. A classifier that cannot confidently recognise benign
mail makes that negation true and the rule fires **because** the model was weak. This
engine already shipped exactly that bug once — folding a null array into an empty one
produced a false positive on `Brand impersonation: Robinhood`, caught only by
differential testing against Sublime. An unavailable capability yields null, the rule
reports indeterminate, and nobody is misled. The service returns 501 rather than 200
with an empty result for the same reason.

### `file.oletools` is reimplemented, not mapped

This one was declined first and then built, and the reason for both is the same
evidence.

Scanning a real OLE2 compound document, Strelka emits `"ole": {"total": {"extracted": 1,
"streams": 1}}` and `"vba": {"total": {"extracted": 0, "files": 0}}` — counts, plus the
extracted streams as child records. What the corpus reads is `.relationships` (8 uses),
`.indicators.*` (5) and `.macros.keywords` (2): the OOXML relationship targets that
remote template injection uses, and oletools' own risk assessment. None of that is on
Strelka's wire. Strelka runs olefile-style extraction, not oletools' analysis, and a
mapping would have to invent `indicators.vba_macros.exists` from a stream count and
`relationships` from nothing — rules that appear to work while reading fields nobody
populated, which is the failure this project keeps getting caught by.

So `oletools/` is a Go reimplementation of the parts the corpus actually reads. The name
describes the interface, not the implementation: no Python, no service, no network. An
Office document is a zip or a compound file, and everything asked about is in the bytes.
It runs in-process, so a deployment with no file-analysis service at all still answers
these 16 calls.

### Enrichment has to be cached

MQL gives a rule no way to share a result with another rule, so each of the ~500 corpus
rules that wants an exploded attachment writes `file.explode(.)` itself. Uncached, one
two-attachment message issues on the order of a thousand identical scans: the corpus
measurement above takes 8 seconds with `mql.NewCache` and does not finish inside a
ten-minute timeout without it.

The cache is scoped to a single message, which is what makes it free of invalidation
questions — within one analysis an enrichment is a pure function of its arguments.
Failures are cached too: a service that is down at the start of a message is down for
that message, and retrying it once per rule turns one outage into a thousand timeouts.

## What counts as a failure

- **Parse failure** is always our bug.
- **Type-check failure** is our bug if the field or function exists in Sublime's schema, and
  expected if the rule uses a capability not yet implemented.
- **Evaluate failure** means a panic or an internal error. A rule returning `indeterminate`
  because an enrichment capability is unavailable is a *pass* — the engine behaved correctly
  and said so.

## Message parsing

The MDM side has no corpus to score against — Sublime publishes rules, not parsed models —
so it is measured by golden tests instead. The six real phishing samples in the corpus's
`emls/` all parse with correct senders, subjects, routing and link extraction, and the
suite in `eml/` covers the message shapes that break naive parsers: bare LF line endings,
missing and unterminated MIME boundaries, unknown charsets and transfer encodings,
malformed address lists, 8-bit header bytes, and messages with no header block at all.

Thread splitting has its own suite, because it is the largest single risk in the parser:
Gmail, Outlook, `-----Original Message-----`, HTML blockquote, three-deep chains, and the
two cases where splitting would be wrong — a single inline quoted line, and prose that
happens to contain "wrote:".

## End to end

The claim, run as one command. Message direction is defined against your own domains, so
the org config is what turns `type.inbound` from null into true:

```sh
$ cat org.yaml
domains:
  - sublimesecurity.com

$ lazaret run -rules ./testdata/sublime-rules/detection-rules -org org.yaml \
              ./testdata/sublime-rules/emls/punycode_robinhood.eml

1257 rules evaluated

FLAGGED (high)
  high       Punycode sender domain
  medium     Link to a domain with punycode characters

UNDECIDED: 178 rules could not run
  missing $abuse_ch_urlhaus_domains_trusted_reporters
  missing $recipient_emails
  missing $tranco_1m
  missing beta.fuzzy_attack_score
  missing beta.ocr
  missing file.explode
  missing ml.link_analysis
  missing ml.nlu_classifier
  missing profile.by_sender_email
  ...

NOTE: 10 referenced lists are not configured, so rules using them
      are undecided rather than false.

verdict: malicious
```

1,257 unmodified Sublime detection rules, an open engine, a real phishing sample, and a
correct verdict — with the 178 rules that could not run named rather than counted as
clean, each saying *what* it was missing.

Drop the `-org` flag and the same command reports
`inconclusive — nothing fired, but not everything could run`. That is the design working:
without verified domains `type.inbound` is unknown, both punycode rules open with it, and
an engine that cannot tell whether a message is inbound should not claim it is clean. A
benign internal message reports `verdict: clean`, because the ML-dependent rules are all
gated behind `type.inbound` and short-circuit before reaching an enricher.

## YARA

The scanner is YARA-X behind a `yara` build tag, so the core stays cgo-free: someone who
only wants to lint a rule should not need a Rust toolchain. Without the tag, scanning
returns `ErrUnsupported` rather than reporting a clean scan — a build that cannot look at
a file has not cleared it.

Matches are shaped as `.scan.yara.matches` with `.name` and `.meta`, which is the format
Sublime publishes and the corpus is written against, so a signature behaves the same
whether it runs here or inside `file.explode`.

Strelka itself does not emit that shape. Its `ScanYara` appends the bare rule name and
puts metadata in a separate parallel list keyed by rule — `{"matches": ["rule_name"],
"meta": [{"rule": "rule_name", "identifier": "author", "value": "..."}]}` — so the
published schema is a *joined* view of two wire fields, exactly as `FileExplodeOutput` is
a flattened view of Strelka's nested `file` object. `mdm.StrelkaYARA` accepts both and
normalises to the published one.

That was found by a live scan, not by reading: until a signature actually matched, the
match list was always empty and the two shapes were indistinguishable. It is the second
instance of the same trap, and the general lesson is in
[ARCHITECTURE.md](ARCHITECTURE.md#the-published-schema-is-not-the-wire-format).

Without `file.explode`, YARA scans attachments as delivered: **archives are not opened**,
so a signature matching a file inside a zip will not fire. That is the gap `file.explode`
closes, and the CLI says so on every run rather than leaving it to be discovered.

## Differential testing against Sublime's engine

Run on **2026-09-18** against `analyzer.sublime.security`, Sublime's free EML Analyzer API,
which needs no credentials:

```sh
LAZARET_DIFFERENTIAL=1 go test ./mql/ -run Differential -v
```

**24 of 24 evaluation probes now agree.** They cover the entire "Inferred: needs a
decision" section that [SEMANTICS.md](SEMANTICS.md) had been carrying — three-valued
`and`/`or`/`not`, comparison and membership against null, `is null` precedence, glob
escaping, null propagation through the regex and distance functions, and the verdict of a
rule whose source evaluates to null.

**One was wrong.** `X of (...)` does not treat a null clause as merely failing to
contribute; it is three-valued like `and` and `or`. If the true clauses alone reach the
threshold the answer is true, otherwise any undecided clause makes the whole thing null,
and only then is it false. Fixed in `mql/eval.go`.

The corpus numbers above did not move, and that is the point worth noting: at the top
level `null` and `false` both mean no-match, so the corpus could never have caught this.
It only changes a verdict when an `of` sits underneath an `and` or an `or` — and there are
222 `of` nodes in the corpus. This is the same class of defect as the two Strelka
wire-format bugs: a green suite over a wrong answer.

### Whole-message verdicts

`run_all_detection_rules` makes the analyzer evaluate Sublime's entire feed — 1,259 rules
— over a raw message, unauthenticated and with nothing uploaded. Close enough to our 1,285
detection rules to compare matched sets directly:

```sh
LAZARET_DIFFERENTIAL=1 go test ./mql/ -run DifferentialCorpus -v
```

Where the probes above isolate the evaluator, this runs the whole pipeline — MIME,
headers, thread splitting, the MDM — so a disagreement is as likely to be a parsing
difference as a semantic one. Three outcomes, and only two of them fail:

- **We match, they evaluated the same rule and did not.** A false positive. Fails.
- **They match, we report a definite no-match.** A missed detection. Fails.
- **They match, we report indeterminate.** Expected — they have ML, file explosion and
  sender profiles; this build has none of them. Logged, not failed.

**Current state: passes on all six samples.** On `punycode_robinhood.eml` the matched sets
are identical. Everywhere else the only difference is a rule they match and we correctly
report as indeterminate.

Getting there took two fixes, both instances of the same invariant failing:

**A null array was being read as an empty array.** `ml.nlu_classifier(x).topics` with no
ML service is null, and the corpus is full of `not any(ml.…(…), …)` clauses written to
exclude newsletters and benign mail. Folding null to empty made `any` false, `not any`
true, and *Brand impersonation: Robinhood* fired **because** the classifier was missing.
Not a degraded answer — an inverted one, and a false positive. Fixed in `mql/builtins.go`.

**An unresolvable `$list` recorded nothing.** The `lists` package was already careful to
answer "I do not know" rather than "no", but the evaluator dropped that and returned a
bare null, which reads as a clean no-match because no capability was marked missing.
`$high_trust_sender_root_domains` gates 683 corpus rules and `$org_domains` another 202.
Fixed with `enrich.ListCapability`, so the verdict is indeterminate and the report names
the list as written.

Together those moved **420 evaluations** from a confident no-match to an honest
indeterminate, and removed the engine's only false positive.

### One place we accept more than Sublime

`any of (...)`, `all of (...)` and `none of (...)` parse here and are **rejected by
Sublime** ("Unknown attribute `any`"). They were added on the belief that the corpus used
them. It does not: all 25 occurrences of those phrases are inside `//` comments, and the
corpus contains zero uses as syntax.

So this is an extension, and it is the one divergence that runs in the permissive
direction — a rule written with these forms works here and fails there.
`TestDifferentialRejectsOurExtensions` pins the divergence so it cannot become an
unnoticed dialect. Unlike `rdap.ip` and `rdap.asn`, which are gated to an extended
registry, this one is in the grammar and so is always on.

## What this does not measure

End-to-end verdict agreement on real messages. The probes above settle the *evaluator's*
semantics, using a message chosen so that only one absent scalar matters. They say nothing
about whether our MDM matches Sublime's for a real message — thread splitting, MIME
handling and header parsing are all still unverified against their engine, and a
difference there changes verdicts without any disagreement about semantics.

That is the natural next differential exercise: post the corpus's own `emls/` to the same
endpoint with `run_all_detection_rules`, and compare matched rule sets. Those risks are
tracked in [SEMANTICS.md](SEMANTICS.md) and, for thread splitting, in the golden tests
under `eml/testdata`.
