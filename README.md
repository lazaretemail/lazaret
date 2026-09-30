# Lazaret

`lazaret.email`

A lazaret is the quarantine station at a port. Ships were held there and inspected before
they were let into the city. That's roughly what this does, for mail.

Lazaret is an open-source email security platform that runs Sublime Security's detection
rules unmodified. Sublime publishes the rules, the language reference and the data schemas
under MIT, but every service that actually executes them ships as a closed container. This
is an independent implementation of those services, so the open rule ecosystem has an open
engine to run on.

**AGPL-3.0.** Not affiliated with Sublime Security; see the bottom of this file.

## Status

All seven planned modules are built and running. On compatibility we can give you a
number: 1,521 rule entities from the public corpus, 100% lexed, parsed, round-tripped,
type-checked and evaluated. [COMPATIBILITY.md](docs/COMPATIBILITY.md) has the full table
and is honest about what it doesn't cover.

| | |
|---|---|
| `lazaret-engine` | MDM parsing, MQL evaluation, rules, hunt, API, actions |
| `lazaret-ml` | NLU classification, link analysis, logo detection, OCR, QR |
| `lazaret-render` | headless screenshots of message HTML, and link fetching |
| `lazaret-ingest` | Microsoft 365, Google, IMAP, inline SMTP, and remediation |
| `lazaret-dashboard` | triage, hunt, rule authoring, insights |
| Strelka | file explosion and scanners, [adopted](third_party/strelka/README.md) rather than rewritten |
| Postgres, Garage, Garnet | state and the DuckLake catalog, blobs, queue |

What it hasn't had is production time. One person has been running it against real
mailboxes for a few days. The numbers below were measured; the reliability is unproven.

## Running it

```sh
git clone https://github.com/lazaretemail/lazaret
cd lazaret
cp deploy/compose/.env.example deploy/compose/.env    # set ADMIN_PASSWORD
docker compose -f deploy/compose/docker-compose.yml up -d --build
docker compose -f third_party/strelka/docker-compose.yml up -d
```

Drop `--build` to pull published images instead. They're on GHCR for `linux/amd64` and
`linux/arm64`:

| | |
|---|---|
| `ghcr.io/lazaretemail/lazaret-engine` | and `-ml`, `-render`, `-ingest`, `-dashboard`, `-garage-init` |
| `:latest` | the most recent tagged release |
| `:nightly` | last night's `main` |
| `:1`, `:1.4`, `:1.4.2` | a release, pinned as loosely or as tightly as you want |

GPU inference needs a separate image, and it's amd64 only, because ROCm and CUDA are
different builds and neither has an arm64 release.

| | | |
|---|---|---|
| `lazaret-ml-rocm` | AMD, via MIGraphX | 14.8GB |
| `lazaret-ml-nvidia` | NVIDIA, TensorRT where the card supports it, CUDA otherwise | 10.8GB |

Most of that size is precompiled GPU kernels for every architecture the vendor supports.
If you build for the card you actually have it comes out far smaller, around 6.9GB for a
single AMD architecture. See `ROCM_ARCHS` in `services/ml/Dockerfile`.

Without a GPU the classifier falls back to the CPU. It works, but it's about twenty-five
times slower: 0.33s a message becomes 8s on its own, and 82s once there's real concurrency,
which overruns the engine's analysis budget. [services/ml/README.md](services/ml/README.md)
goes into this.

Then open http://127.0.0.1:8740 and sign in with the address and password from `.env`.

Object storage sets itself up before the engine starts: cluster layout, buckets, access
key, permissions. The credential it generates is written to a volume the engine reads, so
there's nothing to copy back into `.env`.

Everything else happens in the browser. Verified domains, mailboxes and their credentials,
lists, users, retrospective scans: none of it needs a config file.

Model weights aren't bundled. `services/ml/fetch-models.sh` downloads them into
`deploy/compose/models/`. Without them the ML capabilities report unavailable instead of
guessing.

## The CLI

The engine's libraries also build as a single binary with no daemon and no database. It's
the quickest way to see what the thing actually does.

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

`lazaret run` takes `-strelka localhost:57314` to turn on file explosion and `-rdap` to
allow registration lookups. Both are off unless you ask for them, since running a tool over
a message shouldn't quietly reach the network.

## Unavailable is not the same as clean

The rest of the project hangs off this one.

When a rule needs something the deployment can't provide (a model, a network lookup, file
explosion, sender history) it doesn't quietly evaluate to false. It reports
**indeterminate** and names what was missing. A message only gets called clean once
everything its rules asked for actually ran.

This sounds pedantic until you see the alternative. While testing against Sublime's own
engine we found a rule firing on a sample it shouldn't have, because an unavailable ML
classifier was being read as an empty result instead of an unknown one. That's a false
positive caused by a missing service. Point the same bug the other way and you get a
confident "no match" over something the engine never saw, which is how you lose mail.

The dashboard's coverage page lists which rules can't currently run and why. The engine
logs the same thing at startup, and again whenever a capability drops.

## Yesterday's verdict isn't final

Most phishing gets attributed hours after it lands. If you only judge mail on the way in,
you're permanently one feed update and one re-registered link behind, and none of that is
visible from inside a delivery decision.

So every enrichment answer a message received is frozen beside it. That one column is what
makes the features below possible, and it's what makes them cheap: replaying a rule over
ninety days is a columnar scan with no network access at all.

- **Backtest a rule before you enable it.** Run it over stored mail and you get three
  numbers: would have fired, would not have, and couldn't be decided because the evidence
  it wanted was never kept. The third never gets folded into the second. If analysts had
  already judged the messages it would have caught, you also get a real precision figure
  for a rule nobody has ever run.
- **New detection content gets checked against delivered mail.** When a feed gains rules,
  or a threat-intel list gains entries, the affected rules are swept over the last thirty
  days.
- **Links get visited again.** Serving something harmless until the mail has landed is
  about the cheapest evasion there is, so links from delivered mail are re-checked over the
  following day and reported if where they go changes.
- **One attack is one decision.** Messages are fingerprinted at ingest and grouped by
  near-duplicate detection, so a campaign that arrived thirty times gets triaged once.

None of this acts on its own. Findings show up under **Found later** and a person decides.
Retrospective scans work the same way, for the same reason: a message delivered two months
ago isn't a delivery decision today. [docs/DETECTION.md](docs/DETECTION.md) covers the
reasoning and the thresholds.

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The services, the seams between them, and why the core is a library |
| [docs/DETECTION.md](docs/DETECTION.md) | How a verdict is reached: rules, capabilities, the ML, the lists |
| [docs/MAIL-HANDLING.md](docs/MAIL-HANDLING.md) | What this does to people's mail. Read it before enabling removal |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Corpus pass rates, and what they don't measure |
| [docs/SEMANTICS.md](docs/SEMANTICS.md) | Every MQL behaviour we inferred rather than read |
| [docs/ADR-001-storage.md](docs/ADR-001-storage.md) | Why DuckLake and Postgres, and what building it taught us |
| [deploy/compose/README.md](deploy/compose/README.md) | Deployment, networks, secrets, backups |

Each service directory has its own README covering its contract and its trade-offs.

## Layout

```
mdm/ eml/ mql/ rules/ lists/ enrich/ yara/   core libraries, root Go module, cgo-free
rdap/ strelka/ render/ ml/ profile/          enrichment clients
cmd/lazaret/                                 the CLI
telemetry/                                   OpenTelemetry setup, its own module
services/                                    one directory, one Go module, one container
api/                                         cross-service contracts (OpenAPI, protobuf)
deploy/                                      compose and Kubernetes manifests
content/rules/                               rules written here rather than upstream
docs/
```

The root module is deliberately small and cgo-free so you can `go get` the MQL engine by
itself, to lint rules in CI or to check the compatibility claim without running any of the
rest. Services each get their own `go.mod`, which keeps an ONNX runtime or a headless
Chromium from leaking back into the library.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: `go test ./...` across the
workspace, every file carries an SPDX header, and if you change MQL behaviour add a line to
`docs/SEMANTICS.md` saying whether it's specified or inferred.

Security reports go to [SECURITY.md](SECURITY.md).

## Licence

[AGPL-3.0](LICENSE), chosen so the platform can't be run as a closed service without
contributing back. Third-party inputs keep their own terms: the Sublime rule corpus and
list data are MIT, Strelka is Apache-2.0, Garnet is MIT, Garage is AGPL-3.0. Model weights
aren't distributed here and carry their own licences.

## Not affiliated with Sublime Security

Lazaret is an independent implementation that aims to be compatible with theirs. "Sublime
Security" and "MQL" belong to Sublime Security, Inc. This project isn't endorsed by,
sponsored by or connected with them, and nothing here derives from their closed source,
only from their published rules, schemas and documentation.
