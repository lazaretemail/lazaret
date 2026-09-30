# ADR-001: Storage

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

**Accepted, 2026-09-18.** Supersedes the single line `postgres (messages, history, rules)`
in the original plan.

## Context

That line hid three workloads with different shapes. Separating them is cheap now and
expensive once module 2 has a schema.

| Workload | Shape | Fits Postgres? |
|---|---|---|
| Tenants, rules, org config, users | small, mutable, relational, needs foreign keys and migrations | yes |
| Action and remediation audit log | append-only, small rows, must be durable and defensible | yes |
| Message corpus (one MDM each) | wide, immutable, 10^7–10^8 rows/year, scanned not point-queried | no |
| Detection verdicts | 1,521 rule entities against every message | no |
| Hunt | arbitrary MQL over 90 days of history | no |
| `profile.*` | 898 corpus uses, synchronous in the delivery path | yes, but as a materialised store |

Two numbers set the scale. A 5,000-seat tenant at 30 messages per user per day is 150,000
messages a day; against 1,521 rule entities that is 228 million (message, rule) pairs a
day if the cross product is stored. And the corpus calls `profile.*` 898 times —
`by_sender` 678, `by_sender_email` 163, `by_reply_to` 52, `by_sender_domain` 5 — every one
of them inline while a message is being delivered.

The selection filter is this project's own, learned twice: Redis relicensed to SSPL in
2024 and MinIO was archived in February 2026. Prefer foundation-governed or copyleft
projects over single-vendor ones, and prefer a component whose data survives the component.

## Decision

| Workload | Technology | Licence / governance |
|---|---|---|
| Message corpus, verdicts | DuckLake tables (Parquet files) | MIT, DuckLake Foundation (Amsterdam) |
| Hunt / analytics engine | DuckDB, embedded in `lazaret-engine` | MIT, DuckDB Foundation |
| DuckLake catalog | Postgres — the instance already deployed | PostgreSQL Licence |
| Relational state, audit log | Postgres | PostgreSQL Licence |
| Blob store (EML, attachments, Parquet) | Garage; SeaweedFS at volume | AGPL-3.0 / Apache-2.0 |
| `profile.*` hot path | Postgres materialised table | PostgreSQL Licence |
| Queue, cache | Garnet (already decided) | MIT |
| Full-text search engine | **none — not needed, see below** | — |

Net: one new dependency, no new containers.

### Postgres stays, and the governance argument is the strongest one for it

PostgreSQL Licence, no copyright assignment, no company holding the IP, thirty years of
it. It is the one database that structurally cannot be relicensed out from under this
project, which by the filter above makes it the safest component on the page. The question
was never whether to keep it — only what else, and when.

### DuckLake for the corpus, with Postgres as its catalog

DuckLake reached v1.0 in April 2026. Its central design decision is that the catalog —
file lists, statistics, snapshots — lives in an ordinary SQL database rather than in a
tree of metadata files in object storage. Postgres qualifies. So the deployment is:

- **Postgres** — relational state *and* the DuckLake catalog. One database, two jobs.
- **Garage** — raw EML, attachments, and the Parquet data files. Needed for the first two
  regardless.
- **DuckDB in-process** — the hunt engine. No new container, no daemon, no network hop.

Three properties answer the standing objections to writing Parquet to object storage from
a streaming mail pipeline:

**Data inlining.** Small writes land in the catalog database and are serialised into
Parquet on compaction. This is the small-file problem, which is what kills naive
Parquet-per-message ingest.

**Deletion vectors.** Erasure requests and per-tenant retention without rewriting files.
For a platform holding other people's mail this is not optional.

**Multiple concurrent writers**, which plain DuckDB does not support — so ingest and hunt
workers can share a dataset.

Go access is `github.com/duckdb/duckdb-go`, formerly `marcboeker/go-duckdb` and now under
the DuckDB organisation. It requires cgo. That is acceptable here and only here: the
architecture already permits services to carry heavy dependencies (an ONNX runtime in
`ml`, headless Chromium in `render`) precisely so the root module does not have to. The
core library stays cgo-free and its dependency budget is unaffected.

**The escape hatch is the reason to accept a five-month-old format.** If DuckLake is
abandoned tomorrow, the data is plain Parquet in object storage and the metadata is plain
SQL tables in Postgres — both readable with neither DuckLake nor DuckDB installed. Very
few storage decisions leave the data behind in a form that outlives the tool that wrote
it, and for a project that has been burned twice that property is worth as much as the
licence.

### Verdicts are columnar, and the indeterminate set is a column

Store matches, not the cross product. But the set of rules that evaluated
**indeterminate** must be stored too, because `Unavailable is not false` is load-bearing:
it is what lets a message be re-evaluated when a downed service returns. Store it as a
compressed rule-id set on the message row — run-length encoding over a wide sparse matrix
is exactly what a columnar format is good at — not as one row per rule.

### `profile.*` is two stores, and one of them must not be a cache

The engine contract requires results **time-relative to the message being evaluated**, so
that backtests see only what was known then. A single mutable profile table can answer
"now" quickly but cannot answer "as of last March" at all, so every backtest would
silently leak the future. Hence:

- **DuckLake** holds the append-only sender-event history and answers as-of queries for
  backtests and hunt.
- **Postgres** holds a materialised current profile per (tenant, sender) for the delivery
  path: one indexed lookup, updated on ingest, fully rebuildable from the history.

**The profile store must not live in Garnet.** A cold cache does not report
"unavailable" — it reports *this sender has never written to you before*, which is a
confident, wrong, and maximally suspicious answer. Every first-contact rule would fire
across the board after a restart. That is the exact inverse of the invariant this engine
is built around, and it is the one place in the storage design where the invariant can be
violated silently. A cache in front of the durable table is fine, but it must be able to
say it does not know.

### Blob store: Garage by default

Both candidates pass the filter; Garage fits better. AGPL-3.0 — the same licence as this
project — a single binary with no external dependencies, run by Deuxfleurs, a French
non-profit collective, in production since 2020, and designed for self-hosters on modest
hardware, which is the target operator here.

SeaweedFS (Apache-2.0, twelve years old, built on the Haystack small-file design) has the
higher ceiling and is the documented swap once object counts reach the hundreds of
millions. Its risk is not relicensing but concentration: development is heavily dependent
on one maintainer.

Everything speaks S3 through one interface, so this is the least consequential decision
recorded here. It is written down to stop it being reopened.

## Hunt needs a scan, not a search engine

The earlier plan assumed full-text search over `body.current_thread.text` — the most-used
field in the corpus at 2,499 uses — would need a search engine. It does not, and the
corpus is unambiguous about why:

```
strings.icontains   2671     regex.icontains   1796     strings.ilike   1108
strings.contains     246     regex.contains     140     strings.like      36
strings.starts_with  121     strings.ends_with  105
```

That is 6,223 substring, RE2 and glob predicates and **zero** ranked-relevance queries.
MQL has no BM25, no scoring and no `match` operator. An inverted index cannot answer
`regex.icontains(body.current_thread.text, "urgent.{0,20}wire")`; the engine would fall
back to a scan anyway, while still paying for index maintenance and for keeping that index
consistent with the corpus.

So hunt is a partition-pruned columnar scan — bounded by tenant and date, which is how
hunt queries are actually issued — over zstd-compressed Parquet. This removes an entire
container, a JVM, and a consistency problem from the design.

## Rejected

**ClickHouse.** Apache-2.0, and that is not changing. Rejected on open-core drift rather
than licence: SharedMergeTree — the engine that separates storage from compute over object
storage — is ClickHouse Cloud only, as are lightweight `UPDATE`s and S3 role-based access
control. Object-storage improvements promised in the 2022–23 open-source roadmaps went
into the private fork instead. The capability this project would adopt ClickHouse *for* is
the withheld one. That is the Redis shape before the relicense, not after.

**TimescaleDB.** The columnar and hypercore features are under the Timescale Licence, not
an open-source licence. The same trap in Postgres colours.

**OpenSearch, Quickwit, ParadeDB `pg_search`.** All three are the wrong category, per the
section above. Additionally: Quickwit was acquired by Datadog in January 2025 and moved
AGPL-3.0 → Apache-2.0, leaving it owned by a company selling the product it competes with;
`pg_search` is AGPL-3.0 and licence-matched but is BM25 over Tantivy and is single-vendor
with a commercial dual-licence, which is the structure that makes a relicense possible.

**Elasticsearch.** SSPL / Elastic Licence. Fails on the licence before anything else.

**MinIO.** Community edition gutted in 2025, repository archived February 2026.

## Consequences

- `lazaret-engine` links cgo. Its image gains a DuckDB build; static linking is available
  via `-tags=duckdb_use_static_lib`. The root module is untouched and stays cgo-free.
- Postgres carries the DuckLake catalog, so catalog growth is now a Postgres capacity
  question. DuckLake's stated limit is the catalog database's performance, and a modest
  Postgres handles terabytes of data and millions of snapshots.
- Compaction is an operational task the engine owns. It is not automatic.
- DuckLake v1.0 is five months old. This is the real cost of the decision; the escape
  hatch above is the mitigation, and it is why the format was accepted anyway.
- Retention and erasure become per-tenant, per-day operations over Parquet files and
  deletion vectors rather than heap rewrites in Postgres.

## Implemented, and what building it taught

Module 2 implements this ADR as written. Three things are worth recording because they
were not obvious from the design.

**DuckLake inlines small writes, and inlined data lives in Postgres.** That is the
feature that makes message-at-a-time ingest viable — a Parquet file per message would
be unusable — but it means `ducklake_flush_inlined_data` is not an optimisation, it is
the step that moves the corpus out of Postgres at all. Merging alone does nothing,
because there are no files yet to merge. Omit the flush and the design inverts itself:
Postgres ends up holding exactly the message bodies it was chosen not to hold. The
engine runs flush, merge, expire and cleanup on a schedule; `TestCompactFlushesInlined
DataToParquet` asserts a Parquet file appears and the data is still readable after.

**A DuckLake catalog is bound to its data path.** Attaching with a different
`DATA_PATH` than the catalog was created with is a configuration error, not a
migration. Moving the corpus means rebuilding the catalog, and tests cannot share a
database however carefully they name their tables.

**Hunt evaluates MQL in Go rather than compiling it to SQL**, which is a deliberate
refusal of the obvious optimisation. The semantics settled by differential testing —
three-valued `of`, null arrays that are not empty arrays, `is null` precedence — would
have to be reimplemented in the translation, free to disagree with the evaluator. A
hunt that disagrees with live evaluation quietly tells an analyst that a rule would not
have caught something it would have. DuckLake prunes partitions and projects columns;
the evaluator does the semantics.

## For module 5

Vector search for campaign clustering and NLU is **pgvector** — PostgreSQL Licence, inside
the Postgres already deployed, HNSW adequate into the tens of millions of vectors. No
additional datastore.

## Sources

- [DuckLake v1.0](https://ducklake.select/2026/04/13/ducklake-10/) and the
  [DuckLake FAQ](https://ducklake.select/faq)
- [`duckdb/duckdb-go`](https://github.com/duckdb/duckdb-go)
- [Altinity, *Is ClickHouse Moving Away from Open Source?*](https://altinity.com/blog/is-clickhouse-moving-away-from-open-source)
- [Datadog acquires Quickwit](https://www.datadoghq.com/blog/datadog-acquires-quickwit/)
- [Garage](https://garagehq.deuxfleurs.fr/), [SeaweedFS](https://github.com/seaweedfs/seaweedfs)
