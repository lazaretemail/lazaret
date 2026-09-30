# Lazaret

**Open-source email security you can actually run.** Catch phishing in Microsoft 365 or any
IMAP mailbox, Gmail and Workspace included, using the 1,500-rule detection corpus that
Sublime Security publishes under MIT.

`lazaret.email` · [AGPL-3.0](LICENSE) · [Docs](docs/) · Not affiliated with Sublime
Security

A lazaret is the quarantine station at a port. Ships were held there and inspected before
they were let into the city. That's roughly what this does, for mail.

## Why it exists

Sublime Security open-sourced the good part: the rules, the query language, the data
schemas. What they didn't open-source is anything that runs them. Every service in their
platform ships as a closed container, so the rules are free and the engine is not.

Lazaret is that engine, written from their published specs. Point it at your mail and you
get a phishing detection platform where every part is readable, self-hostable, and yours.

## What you get

- **Detection that arrives on its own.** A fresh install subscribes to Sublime's rule
  corpus and to Lazaret's own, refreshes both every six hours, and starts detecting
  immediately. No rule writing required to get value on day one.
- **Real triage.** Message view with a rendered screenshot, every link resolved, every
  attachment exploded, and the exact rule text that fired.
- **Quarantine that actually quarantines.** Pull a message out of the mailbox and hold the
  only copy. Release puts it back. No "Junk folder" theatre.
- **Hunt over ninety days.** Write one MQL expression, scan your whole stored corpus with
  it. Columnar, so it's fast and it never touches the network.
- **Answers that change.** Links get re-visited, new rules get swept over delivered mail,
  and campaigns get grouped so thirty copies of one attack are one decision.
- **Write and test your own rules.** Type-check in the editor, backtest against real
  stored mail, and see a precision figure before you turn anything on.
- **Bring your own everything.** Postgres, S3, models, rules and lists are all swappable,
  and the MQL engine is a Go library you can `go get` on its own.

## Get it running

The only thing you have to decide is a password.

```sh
git clone https://github.com/lazaretemail/lazaret
cd lazaret

cp deploy/compose/.env.example deploy/compose/.env
# Set ADMIN_EMAIL and ADMIN_PASSWORD. That's the whole file.

docker compose -f deploy/compose/docker-compose.yml up -d --build
docker compose -f third_party/strelka/docker-compose.yml up -d
```

Then open **http://127.0.0.1:8740** and sign in with the address and password you just set.

The compose file builds from source, so put the kettle on for the first run. After that
`up -d` is quick. If you'd rather not build at all, the Kubernetes manifests in `deploy/k8s`
use the published images, and the [Images](#images) section below lists them.

There's no second compose file to remember and no storage to prepare. Object storage
configures itself before the engine starts, so there's no bucket to create, no access key to
copy and nothing to paste back into `.env`.

Optional, and worth doing: `./services/ml/fetch-models.sh` downloads the classifier weights
into `deploy/compose/models/`. Skip it and the model-backed checks report themselves
unavailable rather than guessing, which is safe but leaves 358 rules on the bench.

## Your first ten minutes

**1. Try it on a message before you connect anything.** Go to **Analyzer** and drop in a
`.eml` file. You'll get the full verdict, screenshot, links, attachments and rule hits.
Nothing is connected yet, so this is a completely safe way to see what the platform does.

**2. Tell it who you are.** **Settings → Organisation** takes your verified domains, VIP
names and display names. This is what makes "inbound", "outbound" and "internal" mean
anything, and `type.inbound` gates most of the corpus. Two minutes of typing, and skipping
it weakens detection noticeably.

**3. Connect mail.** **Settings → Mailboxes** for any IMAP server, which covers Gmail and
Workspace. For Microsoft 365, go to **Settings → Microsoft 365**, add your app registration
once, then let it walk your directory and add the whole estate in a couple of clicks.
Mailboxes can be enabled and disabled individually at any time.

**4. Watch Triage fill up.** New mail lands in the triage queues in the sidebar. Click a
message for the full picture.

**5. Decide what it's allowed to do.** **Settings → Actions**. This is covered next,
because it's the part worth understanding properly.

Prefer Kubernetes? `kubectl apply -k deploy/k8s/base`, and
[deploy/k8s/README.md](deploy/k8s/README.md) walks through the four steps that have to
happen in order.

## It won't touch anyone's mail until you say so

Removal is **off by default on every mailbox**. Connect a production inbox to see what
Lazaret finds and it will find things and do nothing about them, which is what you want
while you're still deciding whether to trust it.

When you do turn removal on, here's what happens. Quarantine takes the message out of the
mailbox and keeps the only copy in Lazaret's custody store. It doesn't move it to a folder,
because a folder is still the recipient's mailbox and a credential phishing page is one
click away from there. Release puts the message back, and agreeing with the verdict just
means never doing that.

Two consequences follow, both deliberate. The engine refuses to quarantine a message it
can't reproduce, so it will never delete something it can't give back. And the custody
bucket holds mail that exists nowhere else, so it belongs in your backup policy next to the
database. [docs/MAIL-HANDLING.md](docs/MAIL-HANDLING.md) is the full picture, and it's the
one doc to read before enabling removal.

## Two ideas the whole thing is built on

### "I couldn't check" is not "it's fine"

When a rule needs something your deployment can't give it, whether that's a model, a
network lookup, file explosion or sender history, it doesn't quietly evaluate to false. It
reports **indeterminate** and names what was missing. A message is only called clean once
everything its rules asked for actually ran.

This matters more than it sounds. While testing against Sublime's own engine we found a
rule firing on a sample it shouldn't have, because an unavailable ML classifier was being
read as an empty answer instead of an unknown one. That's a false positive caused by a
missing service. Point the same bug the other way and you get a confident "no match" over
something the engine never looked at, which is how you lose mail.

**Detections → Coverage** shows you exactly which rules can't run right now and why. The
engine logs the same thing at startup and whenever a capability drops.

### Yesterday's verdict isn't final

Most phishing gets attributed hours after it lands. If you only judge mail on the way in,
you're permanently one feed update and one re-registered link behind.

So Lazaret freezes every enrichment answer a message received right next to the message.
That one design choice is what makes all of this possible, and cheap, because replaying a
rule over ninety days becomes a columnar scan with no network access at all.

- **Backtest before you enable.** Run a draft rule over stored mail and get three numbers:
  would have fired, would not have, and couldn't be decided because the evidence it wanted
  was never kept. The third never gets quietly folded into the second.
- **New content gets checked against delivered mail.** When a feed gains rules or a list
  gains entries, the affected rules sweep the last thirty days.
- **Links get visited again.** Serving something harmless until the mail has landed is
  about the cheapest evasion there is, so links from delivered mail are re-checked over the
  following day and reported if their destination changes.
- **One attack is one decision.** Messages are fingerprinted at ingest and grouped by
  near-duplicate detection, so a campaign that arrived thirty times gets triaged once.

None of this acts on its own. Findings appear under **Found later** and a person decides.
[docs/DETECTION.md](docs/DETECTION.md) has the reasoning and the thresholds.

## The CLI

The engine's libraries also build as a single binary with no daemon and no database. It's
the fastest way to see what Lazaret does, and it's what you want in CI for rule authoring.

```sh
go build ./cmd/lazaret

git clone --depth 1 https://github.com/sublime-security/sublime-rules
./lazaret run --rules ./sublime-rules/detection-rules \
              ./sublime-rules/emls/punycode_robinhood.eml
```

That's an open-source engine running open-source rules over a known-malicious sample, with
anything it couldn't check named rather than hidden.

| Command | What it does |
|---|---|
| `lazaret run --rules <dir> <msg.eml>` | Run detection content over a message. Reports what fired, what was suppressed and what couldn't be decided |
| `lazaret parse <msg.eml>` | Print the Message Data Model, which is exactly what a rule sees |
| `lazaret lint -rule <rule.mql>` | Type-check a rule. Catches unknown fields, bad arguments and misspellings before they ship |
| `lazaret fmt <rule.mql>` | Reformat an expression |
| `lazaret rdap <domain\|ip\|ASnnn>` | Registration data over RDAP, falling back to WHOIS only where no RDAP service exists |
| `lazaret yara --rules <dir> <msg.eml>` | Scan attachments with YARA signatures. Needs `-tags yara` |

`lazaret run` takes `-strelka localhost:57314` to enable file explosion and `-rdap` to allow
registration lookups. Both are off unless you ask, because running a tool over a message
shouldn't quietly reach the network. `-org config.yaml` supplies your domains so message
direction is populated.

## Images

Published to GHCR for `linux/amd64` and `linux/arm64`. These are what the Kubernetes
manifests pull, and what to reference if you'd rather pin a release than build one:

```
ghcr.io/lazaretemail/lazaret-engine     :latest    the most recent tagged release
                    -ml                 :nightly   last night's main
                    -render             :1         pin as loosely
                    -ingest             :1.4       or as tightly
                    -dashboard          :1.4.2     as you like
                    -garage-init
```

GPU inference needs a separate image and is amd64 only, because CUDA and ROCm are different
builds and neither ships arm64.

| Image | Hardware | Size |
|---|---|---|
| `lazaret-ml-rocm` | AMD, via MIGraphX | 14.8GB |
| `lazaret-ml-nvidia` | NVIDIA, TensorRT where the card supports it, CUDA otherwise | 10.8GB |

Most of that is precompiled kernels for every architecture the vendor supports. Build for
the card you actually own and it drops a lot, to around 6.9GB for a single AMD
architecture. See `ROCM_ARCHS` in `services/ml/Dockerfile`.

Without a GPU the classifier runs on CPU. It works, but it's roughly twenty-five times
slower: 0.33s a message becomes 8s alone and 82s once there's real concurrency, which
overruns the engine's analysis budget. [services/ml/README.md](services/ml/README.md) goes
into this properly.

## What's in the box

| Service | Job |
|---|---|
| `lazaret-engine` | MDM parsing, MQL evaluation, rules, hunt, API, actions |
| `lazaret-ml` | NLU classification, link analysis, logo detection, OCR, QR |
| `lazaret-render` | Headless screenshots of message HTML, and link fetching |
| `lazaret-ingest` | Microsoft 365 via Graph, IMAP, inline SMTP via rspamd, and remediation |
| `lazaret-dashboard` | Triage, hunt, rule authoring, insights |
| Strelka | File explosion and scanners, [adopted](third_party/strelka/README.md) rather than rewritten |
| Postgres, Garage, Garnet | State and the DuckLake catalog, blobs, queue |

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

The root module is deliberately small and cgo-free, so you can `go get` the MQL engine by
itself to lint rules in CI or to check our compatibility claim without running any of the
rest. Each service gets its own `go.mod`, which keeps an ONNX runtime or a headless
Chromium from leaking back into the library.

## Where it's up to

Compatibility we can put a number on: **1,521 rule entities from the public corpus, 100%
lexed, parsed, round-tripped, type-checked and evaluated.**
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) has the full table and is honest about what
that doesn't measure.

All seven planned modules are built and running. What the project hasn't had is production
time: one person has been running it against real mailboxes for a few days. The numbers
throughout these docs were measured. The reliability is unproven, and we'd rather say so
than let you find out.

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
| [deploy/k8s/README.md](deploy/k8s/README.md) | Kubernetes, and the steps that have to happen in order |

Every service directory has its own README covering its contract and its trade-offs.

## Contributing

New detections are the easiest way in, and they don't live in this repository. Send them to
[lazaretemail/rules](https://github.com/lazaretemail/rules), which every install pulls as a
feed, so a new rule doesn't need a new release.

For the platform itself, see [CONTRIBUTING.md](CONTRIBUTING.md). Short version:
`go test ./...` across the workspace, every file carries an SPDX header, and if you change
MQL behaviour add a line to `docs/SEMANTICS.md` saying whether it's specified or inferred.

Found a security issue? [SECURITY.md](SECURITY.md).

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
