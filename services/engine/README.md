# lazaret-engine (module 2)

The API and pipeline service. Embeds the root module's libraries (`mdm`, `eml`, `mql`,
`rules`, `lists`) and adds everything that needs state.

## Contract

Serves the public HTTP API defined in `api/openapi/`, aiming at compatibility with the
documented Sublime surface:

- `POST /v0/messages/analyze`: raw message in, rule results out
- `POST /v0/rules/validate`: MQL + YAML validation
- `POST /v0/hunt-jobs`, `GET /v0/hunt-jobs/:id`: historical search
- `GET  /v0/messages/:id/message_data_model`: the parsed MDM

## Implements

- `enrich.Profiler`, covering `profile.by_sender`, `by_sender_domain`, `by_sender_email`
  and `by_reply_to`. These need message history, so they live here rather than in the
  library. Results have to be **time-relative to the message being evaluated**, so
  backtests only ever see what was known then.
- `lists.Provider` for history-backed lists (`$sender_emails`, `$recipient_domains`, …).

## Depends on

- **postgres** for rules, tenant config, users, the action audit log, the materialised
  `profile.*` table, and the DuckLake catalog.
- **DuckLake**, with Parquet in the blob store, for the message corpus, the verdicts, and
  the sender-event history that answers as-of profile queries. Read and written through
  **DuckDB, linked into this service**, which doubles as the hunt engine. This is the one
  cgo dependency in the tree, and it stays here rather than reaching the root module.
- **garnet** for queue and cache. Nothing durable, and in particular not profiles.
- **garage** (or SeaweedFS at volume) for raw EML, attachment bytes and Parquet files.
- the other services, via `api/proto/enrich/v1`.

See [`docs/ADR-001-storage.md`](../../docs/ADR-001-storage.md) for why, and for the
alternatives that were rejected.

Two things this service must get right, both recorded in the ADR:

- **The profile store is two stores.** DuckLake holds the append-only sender history and
  answers as-of queries. Postgres holds the current profile for the delivery path,
  rebuildable from that history. A single mutable table can't satisfy the time-relative
  requirement above, and a backtest reading one will silently see the future.
- **A missing profile is not an empty profile.** If the profile store can't be reached,
  `enrich.Profiler` returns `ErrUnavailable`, never a zero-count profile. A zero-count
  profile reads as a brand-new sender and fires every first-contact rule in the corpus.

## Running it

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --build
```

Or directly, against a Postgres and a local directory. A single node needs no object
store:

```sh
lazaret-engine -postgres 'postgres://lazaret:lazaret@localhost:5432/lazaret?sslmode=disable' \
               -data ./data/corpus -rules ./sublime-rules/detection-rules -org org.yaml
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/v0/messages/ingest` | analyse **and record**: the delivery path |
| POST | `/v0/messages/analyze` | analyse without recording |
| GET | `/v0/messages/{id}/message_data_model` | the stored model |
| POST | `/v0/messages/{id}/actions` | quarantine, release, trash, restore, flag |
| GET | `/v0/remediations` | what has been decided and not yet carried out |
| GET | `/v0/lists`, `/v0/lists/{name}` | the named lists and what resolves |
| GET/POST | `/v0/mailboxes` | the mailboxes that are collected from |
| GET/PUT | `/v0/org` | verified domains, VIPs, display names |
| GET | `/v0/messages/{id}/actions` | the audit trail |
| POST | `/v0/rules/validate` | compile a rule, report what it needs |
| POST | `/v0/hunt-jobs`, GET `/v0/hunt-jobs/{id}` | historical search |
| GET | `/v0/stats`, `/v0/capabilities`, `/v0/health` | what is stored, what can be answered |

### Quarantine means custody

An action is recorded here and carried out by a connector, since the mailbox is reachable
only from there. Two endpoints exist for that, and both refuse anything that isn't an API
token. Not merely anything unprivileged, but specifically anything holding a browser
session, because that's what an XSS in the dashboard would have:

- `GET /v0/mailboxes/secrets`, the credentials a connector logs in with.
- `GET /v0/mailboxes/{id}/remediations`, the queue, and for a release the whole original
  message.

Quarantine deletes the message from the mailbox, so `-raw` isn't optional in any deployment
that remediates. It's where the only remaining copy lives. The action endpoint returns 409
for a message whose bytes aren't held, rather than deleting something that could never be
released.

`-raw` takes a local directory or `s3://bucket/prefix`. Object storage is the real answer
for anything with more than one engine, since held copies on one node's disk turn that
node's failure into data loss rather than an outage. The local path exists for a single
node with no blob store.

The S3 client here is deliberately not the one DuckLake uses. DuckDB reaches the blob
store through its own httpfs extension for Parquet, which is a different access
pattern with a different lifecycle: the compactor rewrites and expires what it owns.
Custody objects get written once, read rarely, and deleted only when a person decides to.
**Give custody its own prefix, and never the corpus prefix.** A compaction mustn't be able
to expire mail under legal hold.

Two operational notes, both learned the hard way:

- **Set `-s3-region`.** Garage's default region is `garage`, not `us-east-1`. SigV4
  signs the region into the request, so a wrong one is rejected as
  `AuthorizationHeaderMalformed`, which reads like a credentials problem and is not.
- **An unreachable blob store isn't fatal at startup.** The engine logs and starts,
  because refusing to boot would turn a slow Garage during a rolling restart into an engine
  outage. That's safe rather than dangerous: `HasRaw` answers "no" on any error and every
  destructive path is gated on it, so quarantine gets refused instead of deleting mail
  nobody could release. `GET /v0/readiness` reports whether a message could be held right
  now, by actually trying it.

### Learning from reviews

Every triage decision is a labelled example, and the reviews are the only signal here that
knows what *this* organisation considers a problem. The rules are shared; the judgements
aren't. `POST /v0/model/train` fits a logistic regression over features drawn from the
stored analysis, and `GET /v0/model` reports it.

Three things about it are deliberate:

- **Linear, so it's arguable.** Every score decomposes into a list of features and weights
  an administrator can read on one page and disagree with. A gradient-boosted ensemble
  would score better and be unauditable by the person whose job is to trust it, which in a
  tool that quarantines mail is disqualifying.
- **Advisory, never a verdict.** It's trained on messages analysts chose to review, and
  analysts review what the rules flagged, so what it predicts is *whether you'll agree with
  a detection* rather than whether a message is dangerous. It can't find what the rules
  never surfaced. Letting it suppress detections would close a loop where the system learns
  to stop reporting whatever nobody got round to reviewing.
- **It refuses to speak too early.** Fewer than 50 reviews, or fewer than 10 of either
  answer, and it declines to train and says what's missing. A model that doesn't beat
  guessing the commoner answer is reported as not useful and isn't applied.

Features come from the analysis stored *at the time of review*, not recomputed. Using
today's rules against yesterday's decisions would teach it that a rule since fixed used to
be wrong.

### Releasing asks why

A release records a disposition alongside the action: `false_positive` when the rule was
wrong, `accepted_risk` when it was right and the message was wanted anyway. Those are
different facts about the rule and only the first should count against it. Scoring a
phishing simulation the rules correctly caught as a failure every month teaches an operator
to tune away a working detection. Accepted risk counts as confirmed in the precision
figure.

A message whose bytes aren't held can still be removed, with `{"force": true}` and an admin
role. It's separate from the action rather than implied by the role, because it's the one
operation here that destroys mail irrecoverably, and the audit trail records it as forced.

### analyze doesn't write, and that's a security property

Recording messages submitted to `/v0/messages/analyze` would let anyone with API access
build a sender a reputation by submitting mail that was never delivered. That's a cheap way
to make a target look like an established correspondent before sending the real thing.
`ingest` is the only path that writes.

### Ingest is idempotent

By `(tenant, message_id)`. A retried delivery that appended a second row would inflate the
sender's message count, move `prevalence` from `new` to `outlier`, and silently stop every
first-contact rule from firing. DuckLake has no unique constraints, so this is a read
before the write, and it earns its cost.

## Hunt evaluates MQL in Go, not in SQL

The corpus is Parquet and the query engine is DuckDB, so compiling MQL to SQL is the
obvious optimisation. It's also the one worth refusing.

MQL's semantics are this project's entire claim, and they're subtle in exactly the places a
translation would paper over: three-valued logic through `and`, `or` and `X of (...)`, the
difference between a null array and an empty one, `is null` binding as a comparison. Every
one of those was settled by running expressions against Sublime's own engine, and several
were wrong beforehand. A SQL compiler would be a second implementation of all of it, free
to disagree with the first, and a hunt that disagrees with live evaluation quietly tells an
analyst that a rule wouldn't have caught something it would have.

So DuckLake does what a columnar store is uniquely good at, pruning partitions and reading
one column, and the evaluator does the semantics.

## Compaction is not optional

DuckLake *inlines* small writes into the catalog, which is what makes message-at-a-time
ingest viable. Inlined data lives in **Postgres** until it is flushed. Without
`ducklake_flush_inlined_data` the corpus never reaches the blob store and the storage
design inverts itself, with Postgres holding the message bodies it was specifically chosen
not to hold. Merging alone doesn't do it, because there are no files yet to merge.

The engine runs flush, merge, expire and cleanup on `-compact-every` (6h by default).

## One operational constraint worth knowing

A DuckLake catalog is **bound to its data path**. Attaching with a different `DATA_PATH`
than the catalog was created with is a configuration error rather than a migration, so
moving the corpus means rebuilding the catalog.

## Testing

The storage and API tests run against a real Postgres and a real DuckLake rather than a
fake. What's worth testing here is whether DuckLake actually attaches with a Postgres
catalog, whether an inlined write reaches Parquet, and whether an as-of query respects its
boundary. A mock tells you nothing about any of that.

```sh
docker run -d --name lazaret-pg -e POSTGRES_PASSWORD=lazaret -e POSTGRES_USER=lazaret \
  -e POSTGRES_DB=lazaret -p 5433:5432 postgres:17-alpine
LAZARET_TEST_POSTGRES='postgres://lazaret:lazaret@localhost:5433/lazaret?sslmode=disable' \
  go test ./... -v
```

Each test gets its own database, because of the data-path binding above.
