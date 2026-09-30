# Lazaret

`lazaret.email`

A lazaret is the quarantine station at a port. Arriving ships were held there, inspected,
and then either cleared into the city or detained. That is what this does, for mail.

Lazaret is an open-source email security platform that runs Sublime Security's detection
rules unmodified. Sublime publishes the rules, the language reference and the data
schemas, all MIT; every service that actually executes them ships as a closed container.
This is an independent implementation of those services, so the open rule ecosystem has an
open engine to run on.

**AGPL-3.0.** Not affiliated with Sublime Security — see the bottom of this file.

## Status

All seven planned modules are built and running. The compatibility claim is a number
rather than an adjective: 1,521 rule entities from the public corpus, 100% lexed, parsed,
round-tripped, type-checked and evaluated. [COMPATIBILITY.md](docs/COMPATIBILITY.md) has
the table, and says what it does not cover.

| | |
|---|---|
| `lazaret-engine` | MDM parsing, MQL evaluation, rules, hunt, API, actions |
| `lazaret-ml` | NLU classification, link analysis, logo detection, OCR, QR |
| `lazaret-render` | headless screenshots of message HTML, and link fetching |
| `lazaret-ingest` | Microsoft 365, Google, IMAP, inline SMTP, and remediation |
| `lazaret-dashboard` | triage, hunt, rule authoring, insights |
| Strelka | file explosion and scanners — [adopted](third_party/strelka/README.md), not rewritten |
| Postgres, Garage, Garnet | state and the DuckLake catalog, blobs, queue |

What it has not had is production time. One person has been running it against real
mailboxes for a few days. Treat the numbers as measured and the reliability as unproven.

## Running it

```sh
git clone https://github.com/lazaretemail/lazaret
cd lazaret
cp deploy/compose/.env.example deploy/compose/.env    # set ADMIN_PASSWORD
docker compose -f deploy/compose/docker-compose.yml up -d --build
docker compose -f third_party/strelka/docker-compose.yml up -d
```

Drop `--build` to pull published images instead of building them. They are on GHCR for
`linux/amd64` and `linux/arm64`:

| | |
|---|---|
| `ghcr.io/lazaretemail/lazaret-engine` | and `-ml`, `-render`, `-ingest`, `-dashboard`, `-garage-init` |
| `:latest` | the most recent tagged release |
| `:nightly` | last night's `main` |
| `:1`, `:1.4`, `:1.4.2` | a release, pinned as loosely or as tightly as you want |

GPU inference is a separate image, amd64 only, because ROCm and CUDA are different
builds and neither exists for arm64:

| | | |
|---|---|---|
| `lazaret-ml-rocm` | AMD, via MIGraphX | 14.8GB |
| `lazaret-ml-nvidia` | NVIDIA, TensorRT where the card supports it, CUDA otherwise | 10.8GB |

Both are mostly precompiled GPU kernels for every architecture the vendor supports.
Building for the card you have is much smaller — 6.9GB for one AMD architecture — see
`ROCM_ARCHS` in `services/ml/Dockerfile`.

Without one of these the classifier runs on the CPU. That works, and it is roughly
twenty-five times slower: 0.33s a message becomes 8s alone and 82s under real
concurrency, which is past the engine's analysis budget. See
[services/ml/README.md](services/ml/README.md).

Then open http://127.0.0.1:8740 and sign in with the address and password from `.env`.

One file, one command. Object storage bootstraps itself — cluster layout, buckets, access
key, permissions — before the engine starts, and the credential it generates goes onto a
volume the engine reads rather than into output for you to paste back into `.env`.

Everything after that is done in the browser: verified domains, mailboxes and their
credentials, lists, users, retrospective scans. Nothing else needs a config file.

Model weights are not bundled. `services/ml/fetch-models.sh` downloads them into
`deploy/compose/models/`, and without them the ML capabilities report unavailable rather
than guessing. See [services/ml/README.md](services/ml/README.md).

## The CLI

The engine's libraries also build as one binary with no daemon and no database, which is
the fastest way to see what the thing actually does.

```sh
go build ./cmd/lazaret

git clone --depth 1 https://github.com/sublime-security/sublime-rules
./lazaret run --rules ./sublime-rules/detection-rules \
              ./sublime-rules/emls/punycode_robinhood.eml

./lazaret parse message.eml | jq .sender   # the model a rule sees
./lazaret lint -rule my-rule.mql           # type-check before shipping
./lazaret fmt my-rule.mql                  # reformat
./lazaret rdap example.com                 # registration data, RDAP not WHOIS
./lazaret yara --rules ./yara message.eml  # needs -tags yara
```

`lazaret run` takes `-strelka localhost:57314` to turn on file explosion, and `-rdap` to
allow registration lookups. Both are off by default: running a tool over a message should
not reach the network unless you said so.

## Unavailable is not the same as clean

This is the design decision the rest of the project hangs off.

A rule that needs something the deployment cannot provide — a model, a network lookup,
file explosion, sender history — does not quietly evaluate to false. It reports
**indeterminate**, and names what was missing. A message is only called clean when
everything the rules asked for actually ran.

It sounds pedantic until you watch the alternative. During differential testing against
Sublime's own engine we found a rule firing on a sample it should not have, because an
unavailable ML classifier was being read as an empty result instead of an unknown one.
That is a false positive from a missing service. The inverse — a confident "no match" over
something the engine could not see — is the same bug pointed at the other risk, and it is
the one that loses you mail.

The dashboard has a coverage page showing which rules cannot currently run and why. The
engine logs the same thing at startup and whenever a capability drops.

## Yesterday's verdict is not final

Most phishing is attributed hours after it is delivered. A pipeline that only judges mail
on the way in is therefore permanently one feed update and one re-registered link behind,
and nothing about that is visible from inside a delivery decision.

Every enrichment answer a message received is frozen beside it. That one column is what
makes the rest possible, and it makes it cheap: replaying a rule over ninety days is a
columnar scan and no network at all.

- **Backtest a rule before enabling it.** Run it over stored mail and get three numbers —
  would have fired, would not have, and could not be decided because the evidence it
  wanted was never kept. The third is never folded into the second. Where analysts had
  already judged the messages it would have caught, you also get a real precision figure
  for a rule nobody has ever run.
- **New detection content is checked against delivered mail.** A feed gaining rules, or a
  threat-intel list gaining entries, triggers a sweep of the affected rules over the last
  thirty days.
- **Links are visited again.** Serving something harmless until the mail has landed is
  the cheapest evasion there is. Links from delivered mail are re-checked over the
  following day and reported when where they go changes.
- **One attack is one decision.** Messages are fingerprinted at ingest and grouped by
  near-duplicate detection, so a campaign that arrived thirty times is triaged once.

None of it acts. A finding is surfaced under **Found later** and a person decides — the
same rule a retrospective scan follows, because a message delivered two months ago is not
a delivery decision today. [docs/DETECTION.md](docs/DETECTION.md) has the reasoning and
the thresholds.

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The services, the seams between them, and why the core is a library |
| [docs/DETECTION.md](docs/DETECTION.md) | How a verdict is reached: rules, capabilities, the ML, the lists |
| [docs/MAIL-HANDLING.md](docs/MAIL-HANDLING.md) | What this does to people's mail. Read before enabling removal |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Corpus pass rates, and what they do not measure |
| [docs/SEMANTICS.md](docs/SEMANTICS.md) | Every MQL behaviour we inferred rather than read |
| [docs/ADR-001-storage.md](docs/ADR-001-storage.md) | Why DuckLake and Postgres, and what building it taught |
| [deploy/compose/README.md](deploy/compose/README.md) | Deployment, networks, secrets, backups |

Each service directory has its own README covering its contract and its trade-offs.

## Layout

```
mdm/ eml/ mql/ rules/ lists/ enrich/ yara/   core libraries — root Go module, cgo-free
rdap/ strelka/ render/ ml/ profile/          enrichment clients
cmd/lazaret/                                 the CLI
telemetry/                                   OpenTelemetry setup, its own module
services/                                    one directory, one Go module, one container
api/                                         cross-service contracts (OpenAPI, protobuf)
deploy/                                      compose and Kubernetes manifests
content/rules/                               rules written here rather than upstream
docs/
```

The root module stays small and cgo-free on purpose, so you can `go get` the MQL engine on
its own — to lint rules in CI, or to check the compatibility claim yourself without
running any of this. Services get their own `go.mod` so that an ONNX runtime or a headless
Chromium cannot leak back into the library.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: `go test ./...` across the
workspace, every file carries an SPDX header, and a change to MQL behaviour needs a line in
`docs/SEMANTICS.md` saying whether it is specified or inferred.

Security reports: [SECURITY.md](SECURITY.md).

## Licence

[AGPL-3.0](LICENSE), chosen so the platform cannot be run as a closed service without
contributing back. Third-party inputs keep their own terms: the Sublime rule corpus and
list data are MIT, Strelka is Apache-2.0, Garnet is MIT, Garage is AGPL-3.0. Model weights
are not distributed here and carry their own licences.

## Not affiliated with Sublime Security

Lazaret is an independent implementation that aims to be compatible. "Sublime Security"
and "MQL" belong to Sublime Security, Inc. This project is not endorsed by, sponsored by
or connected with them, and nothing here derives from their closed source — only from
their published rules, schemas and documentation.
