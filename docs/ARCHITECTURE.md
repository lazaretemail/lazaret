# Architecture

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

## What we are replacing

Sublime's self-hosted `docker-compose.yml` is the clearest statement of what is closed:

| Sublime container | Role | Our answer |
|---|---|---|
| `sublimesec/mantis` | MDM parsing, MQL evaluation, rules, API | `lazaret-engine` (modules 1–2) ✓ |
| `sublimesec/bora-lite` | ML: NLU, link analysis | `lazaret-ml` (module 5) ✓ |
| `sublimesec/hydra-cpu` | ML: logos, OCR, QR | `lazaret-ml` (module 5) ✓ |
| `sublimesec/render-email-html` | headless screenshots | `lazaret-render` (module 4) ✓ |
| `sublimesec/dashboard` | web UI | `lazaret-dashboard` (module 7) ✓ |
| `sublimesec/strelka-*` | file explosion + scanners | adopt [Strelka](https://github.com/target/strelka) as-is (module 3) ✓ |
| `nginx` | ingress | unchanged |
| `postgres` | state | kept for relational state — and given a second job as the DuckLake catalog. The message corpus moves out; see [ADR-001](ADR-001-storage.md) |
| `redis` | queue, cache | **Garnet** (MIT) — Redis relicensed to SSPL in 2024; Valkey is the BSD-3 alternative |
| `minio` | S3-compatible blob storage | **Garage** (AGPL-3.0) — MinIO's repo was archived in Feb 2026; SeaweedFS is the swap at volume |

## The shape

```
                  ingest (M365 Graph / Google / IMAP / SMTP inline)
                                    |
 feeds  ------------->      lazaret-engine     <----> postgres  (rules, config, audit,
(git rules,                MDM parse + MQL eval                 profiles, DuckLake catalog)
 static-files,             rules, actions, API        garnet    (queue, cache)
 threat intel)             + DuckDB (hunt)            garage    (EML, attachments,
                             |      |      |                    Parquet corpus)
                +------------+      |      +-------------+
                |                   |                    |
          strelka (OSS)        lazaret-ml         lazaret-render
          file.explode         nlu, link         screenshots of email
          + YARA               analysis, logos,  HTML and of links
                               OCR, QR
                                    |
                            lazaret-dashboard
```

## The core is a library, not a program

`mdm`, `eml`, `mql`, `rules`, `lists`, `enrich` and `yara` live in the root Go module and
have no daemon, no database and no network of their own. `lazaret-engine` embeds them.

This is deliberate. The root module's dependency graph must stay small and cgo-free so that
anyone can `go get` the MQL engine alone — to lint rules in CI, to build a different
product, or to check the compatibility claim for themselves. Each service gets its own
`go.mod` precisely so that heavy dependencies (an ONNX runtime in `ml`, headless Chromium
in `render`) cannot leak back into the library.

CI budgets what the core actually links — seven third-party modules today — rather than
the module graph, so that an optional capability behind a build tag does not count against
a library that never loads it. If that number starts growing, something has leaked.

## Enrichment is the seam

MQL's function surface splits cleanly:

- **Pure** — `strings.*`, `regex.*`, the array and map builtins, `html.xpath`,
  `file.parse_*`, `beta.ip_in`. Computable from the message alone. These live in the library.
- **Everything else** — `file.explode`, `ml.*`, `network.whois`, `profile.*`, the screenshot
  pair. These are declared in `enrich/` as `context.Context`-aware interfaces and
  implemented by services.

`network.whois` is the first of those with an implementation in this repo (`whois/`),
because it needs no model and no state — just a careful HTTP client. Providers compose
through `mql.MuxEnricher`, so wiring one up does not imply having the rest.

The interfaces in `enrich/` and the protobufs in `api/proto/enrich/v1/` describe the same
boundaries. Defining both in module 1, before any service exists, is what stops them being
retrofitted badly later.

### Unavailable is not false

The default implementation of every enrichment interface returns `enrich.ErrUnavailable`.
The evaluator turns that into `null` *and* records which capability was missing. A rule that
depended on one is reported `indeterminate`, distinct from `no-match`.

This matters beyond module 1's partial state: in production it is the difference between
"this message is clean" and "the ML container is down and we do not know".

## Storage

Full reasoning and the rejected alternatives are in [ADR-001](ADR-001-storage.md). The
shape:

- **Postgres** — relational state (tenants, rules, org config, users), the action and
  remediation audit log, the materialised `profile.*` table, and the DuckLake catalog.
  One database, two jobs. It is also the only component here that structurally cannot be
  relicensed: no copyright assignment, no company holding the IP.
- **DuckLake + Parquet in the blob store** — the message corpus and the verdicts. Append-
  only, immutable, scanned rather than point-queried, and an order of magnitude too wide
  for a row store: 1,521 rule entities against every message is 228 million (message,
  rule) pairs a day at 150,000 messages. Matches are stored; so is the *indeterminate*
  set, because re-evaluating a message when a downed service returns is the whole point
  of the invariant above.
- **DuckDB, embedded in `lazaret-engine`** — the hunt engine. No extra container.
- **Garage** — raw EML, attachments and the Parquet files.
- **Garnet** — queue and cache, and nothing durable.

Two consequences worth stating here rather than only in the ADR.

**Hunt is a scan, not a search engine.** The corpus issues 6,223 substring, RE2 and glob
predicates (`strings.icontains` 2,671, `regex.icontains` 1,796, `strings.ilike` 1,108, and
the rest) and exactly zero ranked-relevance queries — MQL has no BM25, no scoring and no
`match` operator. An inverted index cannot answer an arbitrary RE2 regex, so it would be
paid for and then bypassed. Partition-pruned columnar scans are the right shape, and that
removes a search cluster from the deployment.

**`profile.*` must not be cached in Garnet.** A cold cache does not report "unavailable";
it reports *this sender has never written to you before* — a confident, wrong and
maximally suspicious answer that would fire every first-contact rule after a restart.
That is the exact inverse of the section above, and it is the one place in the storage
design where the invariant can be broken silently.

## The engine is the thing that remembers

Module 1 is a library and a CLI that forget everything between runs. `lazaret-engine`
is what makes the difference, and the difference is larger than it sounds:

- **`profile.*` becomes answerable.** 898 corpus calls, second only to the ML
  classifier, and until there was a service recording messages it could only be fed
  from a hand-written file. Ingesting six sample messages is enough to change verdicts:
  a first-contact rule fires on a sender's first message and stops firing on their
  second, which is the behaviour the corpus is written against.
- **Hunt exists at all.** Re-running an expression over history is impossible without
  history.
- **An indeterminate verdict becomes re-runnable.** The engine records *which*
  capabilities were missing, so when a downed service returns, the messages worth
  re-evaluating are exactly the ones that named it — `MessagesMissing` asks that
  question directly.
- **Quarantine is custody, not filing.** A flagged message is removed from the mailbox
  and the engine holds the only copy; releasing puts it back. A Quarantine folder would
  leave the message in the recipient's mailbox, one click away. The consequence is that
  the raw store is load-bearing, and the engine refuses to quarantine a message whose
  bytes it does not hold.
- **Dispositions get an audit trail.** Quarantine, release, trash, with an actor and a
  reason and no update path. This is the part the project is named for.
- **A verdict can be revisited.** Every enrichment answer a message received is frozen
  beside it, so a rule can be replayed over old mail without re-fetching anything —
  which is not merely cheaper but the only correct way to do it, since a re-fetch
  answers a question about March with October's facts. Everything retrospective rests
  on this one column: hunting, backtesting a proposed rule, and sweeping delivered mail
  when new detection content arrives. See `docs/DETECTION.md`.
- **One attack stops being thirty decisions.** Messages are fingerprinted at ingest and
  grouped by near-duplicate detection, so a campaign is triaged once.

Two behaviours in the service are security properties rather than conveniences, and
both are tested:

**`/v0/messages/analyze` does not write.** Only `/v0/messages/ingest` does. If analysis
recorded, anyone with API access could build a sender a reputation by submitting mail
that was never delivered — making a target look like an established correspondent
before sending the real thing.

**Ingest is idempotent by `(tenant, message_id)`.** A retried delivery that appended a
second row would inflate the sender's count, moving `prevalence` from `new` to
`outlier`, and silently stop every first-contact rule from firing.

## Two browsers, because they are two different jobs

The renderer runs a Chromium with no DNS at all to screenshot message bodies, and a
second browser to visit links. Those look like the same job and are not, which is why
they are no longer the same engine.

**Screenshots need a browser that lays out and paints correctly**, because the picture is
fed to OCR, logo matching and a QR decoder. A renderer that gets layout wrong still emits
a valid PNG, so every one of those reports "found nothing" instead of "could not look" —
a false negative manufactured by the renderer that nothing downstream can detect. That
path stays on Chromium and is not a candidate for replacement.

**Visiting a link needs no rendering at all.** Redirects, status codes and content types
come from an ordinary HTTP client, where the SSRF guards live. Of the browser, exactly
one thing is asked: the document after its script has run. `inner_text`, `display_text`
and links are derived from that string in Go. No layout is read, no pixels are painted,
no fonts are used.

Links are nevertheless visited by the same Chromium, and the reason is worth stating
because the measurement pointed the other way. [Lightpanda](https://github.com/lightpanda-io/browser)
did the job **1.8× faster and about sixty times lighter** — 8.6s against 15.6s over ten
links from a real email, at 3.7 MiB against 222 MiB. Six of the ten produced
byte-identical extracted links and text.

It is not used, because it cannot be disguised, and see below for why that decides it.

### What a link visit says it is

A visit has two halves — an HTTP client for the redirect chain and status, a browser for
what script builds — and until recently they introduced themselves as two different
clients. The HTTP client claimed Chrome 120; the browser, milliseconds later on the same
URL, announced itself as **HeadlessChrome**, which is one of the oldest and most widely
deployed headless signals there is.

Cloaking is in every phishing kit worth the name: serve a benign page to anything that
looks like a scanner, serve the credential form to everyone else. So this is not
politeness, it is whether the answer is the real one. Both halves now present as the same
ordinary Chrome, with the `Sec-CH-UA` headers real Chrome sends. Over the same ten links
that turned **three 403s into 200s**, and one of them returned ten times more content.

**This is what decided the engine.** A phishing kit that cloaks is not an edge case, it
is the normal case, and it blocks non-browser clients precisely to evade analysis. An
engine that announces itself gets the benign page every time — so the verdict is clean,
and it is clean on exactly the messages worth looking at. A systematic false negative is
not a trade against speed; it is the failure this whole engine is built to refuse.

Lightpanda cannot be disguised by any route, and this was checked rather than assumed:

| | result |
|---|---|
| `--user-agent` with a Mozilla string | **fatal startup error** — "can't contain Mozilla" |
| `Network.setUserAgentOverride` | answers **OK**, ignored |
| `Emulation.setUserAgentOverride` | answers **OK**, ignored |
| `Network.setExtraHTTPHeaders` | answers **OK**, ignored |

It sends `Sec-Ch-Ua: "Lightpanda";v="1"` throughout. Silently accepting an override and
not applying it is worse than refusing, because a client has no way to know. That is a
defensible choice for a scraping tool and disqualifying here.

What a page sees from the link browser now, asserted against a real browser in
`identity_test.go` rather than against the flags we pass it:

```
User-Agent:          Mozilla/5.0 (X11; Linux x86_64) ... Chrome/153.0.0.0 Safari/537.36
Sec-CH-UA:           "Not_A Brand";v="8", "Chromium";v="153", "Google Chrome";v="153"
Sec-CH-UA-Platform:  "Linux"
Accept-Language:     en-US,en;q=0.9
```

Two of those are configurable, because they are not really disguise — they are a claim
about who the recipient is:

| | |
|---|---|
| `LAZARET_ACCEPT_LANGUAGE` | `en-US,en` by default. A bare list; quality values are added. |
| `LAZARET_BROWSER_PLATFORM` | `linux`, `windows` or `macos`. |

A page served in Spanish to a Spanish-speaking recipient is a different page, and a
deployment protecting those recipients should be shown the one they were shown. Worth
considering `windows` if the recipients are a typical corporate population: the aim is to
look like them.

The platform is a *name*, not a set of strings, and that is deliberate. It appears in the
user agent's parenthesised token, in `Sec-CH-UA-Platform`, and in the Client Hints
metadata as a platform, a version and an architecture. An operator able to set those
independently could ship a browser claiming Windows in one header and X11/Linux in
another — and a cloaking check does not need to detect a headless browser, only an
inconsistent one. So everything that has to agree is derived from the one name, and an
unrecognised value is a start-up failure rather than a silent fallback.

That test earned its place twice: `--user-agent` turned out not to reach `Sec-CH-UA` at
all, and supplying quality values to `Accept-Language` produced `en-US,en;q=0.9;q=0.9`,
a malformed header louder than the signal it was meant to quieten. Neither was visible
from the configuration.

### The browser is not allowed to lose

Because the browser makes its own request, it can be shown a different page from the one
the HTTP client was shown. Measured: the HTTP client received 127,760 bytes of a genuine
login page and the browser came back with 28,500 — and that fifth is what reached the
rules. Evidence already in hand was being discarded for less.

A browser result substantially smaller than what was served is now treated as the browser
having been turned away, and the served HTML is kept. **Both engines trigger it**, which
is the point: it is not a workaround for the light one, it is a property the path was
missing.

Switching engines is one environment variable, `LAZARET_LINK_BROWSER`, pointed at any
CDP endpoint. The client behind it is `services/render/cdp.go` and it is deliberately not
chromedp — see that file for the 155-second reason why.

## Getting mail in, and acting on it

`lazaret-ingest` is where a verdict stops being a record and becomes a consequence.
Three connectors, at three different points in a mail system:

- **rspamd**, inline. The Lua plugin in `services/ingest/lua/` calls Lazaret while
  Rspamd is scanning, and the result becomes a score and a symbol alongside SPF, DKIM
  and Bayes. This is the only placement where a verdict can stop a message reaching a
  mailbox at all.
- **imap**, after delivery, against anything that speaks the protocol. IDLE where
  offered, polling where not; `MOVE` where offered, `COPY`-then-delete where not.
- **graph**, Microsoft 365. Webhook preferred, polling as fallback.

### Failure modes are part of the design here

An inline scanner is in the delivery path, so what it does when it breaks is a design
decision rather than an accident. The Rspamd plugin **fails open** — an engine restart
must not stop all mail, which is a more disruptive outage than a window of missed
detection and the kind that gets a system removed — and emits a zero-weight
`LAZARET_FAIL` so the failure is still visible and alertable.

`LAZARET_INDETERMINATE` is a separate symbol from `LAZARET_CLEAN`, which is the same
distinction the engine draws internally: treating "could not evaluate" as clean turns
an outage into delivered phishing, and treating it as malicious turns an outage into a
mail outage.

### Why Graph fails over on silence, not just on error

Every way a Graph webhook fails is environmental and invisible from inside the process:
no public URL, a firewall, a proxy that eats the validation handshake, an admin who has
not granted the permission. A subscription can also be accepted and then quietly stop
delivering. From in here that looks exactly like a quiet mailbox — so silence past a
watchdog window starts polling anyway, while re-subscription keeps being attempted.
Both running briefly is fine: the engine deduplicates by message id, and a gap does
not deduplicate.

Two guards are worth naming. `clientState` is checked in constant time, because it is
the only thing distinguishing a real notification from anyone who has found the
endpoint. And `nextLink`/`deltaLink` are host-checked before being followed: they are
absolute URLs chosen by the server and every request carries a bearer token, so
following one blindly would send that token wherever the response said to.

## The dashboard, and one thing it refuses to hide

`lazaret-dashboard` is a Vue 3 single-page app in TypeScript, built with Vite, embedded
into a Go binary. The Go side serves the bundle, holds the session, proxies to the engine
and does nothing else.

The first version was server-rendered `html/template` with about a hundred lines of
vanilla JavaScript, on the argument that npm in a security product is a large attack
surface for a nicer interaction model on four views. Two things changed that. It stopped
being four views — there are now twenty-odd, including a rule editor — and the templates
were unpleasant enough to work in that they were shaping what got built. Both are
legitimate reasons and neither makes the original argument wrong, so the dependency count
is watched rather than ignored.

It talks to the engine's public HTTP API and nothing else — no database handle, no shared
Go types beyond JSON, which is generated from the engine's wire structs by `tygo` so the
two cannot drift. That keeps the API exercised by a real consumer rather than only by its
own tests, and means anything the UI can do a script can do too.

**The coverage view shows what could not be evaluated, beside what fired.** A report
listing detections without saying that nine hundred rule evaluations were blocked on a
model nobody deployed makes a partial system look complete. That table is the honest
counterpart to the numbers above it, and it is the same distinction the evaluator draws
internally: `indeterminate` is not `no match`.

Every string the triage page renders was written by someone hostile — a subject line is
attacker-controlled by definition. The page runs under
`default-src 'none'; script-src 'self'; style-src 'self' 'nonce-...'` with a per-request
nonce, and there is a test that feeds it a real XSS payload rather than trusting the
framework to escape.

Authentication is local accounts, or OIDC when the `-oidc-*` flags are set. Sessions
belong to the engine, so the dashboard holds no user database of its own.

## Registration data: RDAP, not WHOIS

`network.whois` is answered over RDAP (RFC 9083), discovered per-TLD through IANA
(`https://rdap.iana.org/domain/<tld>`, whose response carries the registry's own RDAP base
as a link typed `application/rdap+json`). Legacy port-43 WHOIS is the fallback, used only
where a TLD publishes no RDAP service — which is a real set, `.de` among them.

The reason is `days_old`. It is the most-used WHOIS field in the rule corpus by a wide
margin, because a domain registered last week is the cheapest reliable phishing signal
there is. RDAP gives a date in a specified format with an HTTP status code to say whether
the domain exists at all. WHOIS gives free text where the same two facts have to be
recovered by recognising a phrase and guessing a date layout — and a layout this parser
does not know means `days_old` is silently absent for every domain under that registry,
which looks exactly like a clean result.

RDAP also covers addresses and AS numbers, which is worth having in an email engine: a
Received chain is a list of addresses, and the interesting question about each one is
rarely which address it is but whose network it belongs to. Attackers rotate addresses
freely and netblocks slowly, so the allocation outlives any individual host. The corpus
already reaches for this indirectly — its largest single rule is a 242 KB list of Spamhaus
CIDR ranges compiled into one `beta.ip_in` call, which is a frozen snapshot of exactly
this attribution.

Addresses and AS numbers discover differently: IANA's RDAP server answers for the root
zone only and returns 501 for anything else, so those use the RFC 9224 bootstrap
registries (`data.iana.org/rdap/{ipv4,ipv6,asn}.json`), fetched once and cached.

MQL has no IP or ASN function, so these are **extensions**: `rdap.ip` and `rdap.asn`,
registered only on a registry that has opted in via `rdap.Extend`. `mql.NewRegistry()`
stays exactly Sublime's surface, so the corpus compatibility numbers keep meaning what
they say, and a strict registry refuses the extensions outright.

Because every lookup is triggered by something an attacker chose, the set of hosts
contacted is bounded by IANA's registries rather than by anything in the message,
discovered bases must be HTTPS, redirects are capped and must stay on TLS, responses are
size-limited, requests are serialised per host, and results are cached for a day.
Registries rate-limit, and a mail pipeline looking up every sender domain is the traffic
shape that gets an IP blocked.

### Relevant specifications

RFC 7480 (HTTP usage), RFC 7481 (security), RFC 9082 (query format), RFC 9083 (JSON
responses), RFC 9224 (finding authoritative services), RFC 9537 (redacted fields). The
aggregator at `rdap.org` is deliberately not used: it is a single point of failure with a
published rate limit of ten requests per ten seconds, and doing the bootstrap ourselves
costs one cached fetch.

## Data model provenance

The MDM is not reverse-engineered. Sublime publishes the full OpenAPI definition — 44 schema
components — inlined in the markdown of their API reference (append `.md` to a docs URL).
`mdm/mdm.openapi.json` is that spec, vendored, and `mdm/types.gen.go` is generated from it.
The type checker's field table is derived from those structs by reflection, so the schema,
the Go types and the checker cannot drift apart.

The same trick yields `FileExplodeOutput` (as `StrelkaResponse`) and `LinkAnalysisOutput`,
which is why modules 3 and 5 have exact output shapes to build against.

### The published schema is not the wire format

A caveat learned twice, expensively, and worth stating once for every module that
integrates an upstream service.

Sublime's published schemas describe what *their API returns*, which is a processed view
of what the underlying service emits. Both divergences found so far are in `file.explode`:

- **Flattening.** Strelka nests file metadata under `file` and names the tree
  `file.tree.{node,parent}`. The schema lifts all of it a level and renames it, so rules
  read `.file_name`, `.depth`, `.node_id`. `strelka/convert.go` does that translation.
- **Joining.** Strelka emits `matches` as bare rule names and metadata as a separate
  parallel list keyed by rule. The schema presents one array of `{name, meta}` objects.
  `mdm.StrelkaYARA` does that join.

What makes this a genuine trap rather than an ordinary bug is the failure mode. Decoding
the wire format into the generated struct *compiles, raises no error, and yields records
whose fields are simply empty* — so rules keep evaluating and quietly match nothing. There
is no crash to investigate and no log line to read.

Neither divergence was findable from the documents, and neither was findable from unit
tests: fixtures written from the published schema agree with a fake built from the same
schema, and the suite stays green. The YARA one survived even a live scan, because until a
signature actually matched, an empty match list decodes fine under either reading.

So, for every service adopted from here on:

1. Write fixtures from **captured output of the real service**, never from the schema.
2. Keep a live test that exercises a **non-empty** result for each field that matters — an
   empty list proves nothing about its element type.
3. Make a decode failure **loud by default**. `strelka.Options.SkipUndecodable` exists for
   callers who prefer a partial tree in production, but silence is not the default,
   because it was silence that hid both of these.
