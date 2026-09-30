# Deployment

One file, one command, from a clean checkout:

```sh
cp deploy/compose/.env.example deploy/compose/.env   # set ADMIN_PASSWORD
docker compose -f deploy/compose/docker-compose.yml up -d --build
docker compose -f third_party/strelka/docker-compose.yml up -d
```

There is no second compose file to remember and no storage to prepare by hand. The
blob store bootstraps itself — cluster layout, buckets, access key, permissions —
before the engine starts, and the credential it generates goes onto a volume the
engine reads rather than into output for someone to paste back into `.env`.

That is not tidiness. When object storage lived in an overlay, a `docker compose up
-d engine` that forgot `-f docker-compose.garage.yml` silently repointed the corpus
at a local directory; DuckLake refuses a data path that does not match its catalog,
so the engine crash-looped until someone worked out which argument was missing.

| Service | Role | Module |
|---|---|---|
| `engine` | API, pipeline, hunt, actions | 2 |
| `postgres` | relational state **and** the DuckLake catalog | — |
| `garage` | Parquet corpus and raw message bytes | — |
| `garage-init` | one-shot: layout, buckets, key, permissions | — |
| `garnet` | queue and cache | — |
| `render` | screenshots, page fetch | 4 |
| `ml` | model inference | 5 |
| `strelka` *(separate file)* | file explosion, OCR, QR, exif | 3 |

Storage decisions are recorded in [`docs/ADR-001-storage.md`](../../docs/ADR-001-storage.md).
In brief:

- **postgres** — relational state and the DuckLake catalog. One database, two jobs,
  which is the reason DuckLake was chosen over a format whose catalog is a tree of
  files in object storage.
- **garage** (AGPL-3.0, Deuxfleurs) rather than MinIO, whose community edition was
  gutted in 2025 and whose repository was archived in February 2026. SeaweedFS is the
  swap once object counts reach the hundreds of millions.
- **garnet** (MIT, Microsoft Research) rather than redis, relicensed to SSPL in 2024.
  Valkey (BSD-3) is the drop-in alternative.
- **no search cluster.** Hunt is a columnar scan over Parquet, run by a DuckDB linked
  into the engine. MQL has no ranked-relevance operator, so an inverted index would be
  paid for and then bypassed.

## The custody bucket

Quarantine removes a message from the mailbox and keeps the only copy, so the blob
store is not just where Parquet goes — it holds mail that exists nowhere else.

Garage needs a cluster layout, two buckets and a key before the engine can write
there, and `garage-init` does all of it on first start
([`garage-init/bootstrap.sh`](garage-init/bootstrap.sh)). It is idempotent, so it runs
on every `up` and does nothing on the second one. To use your own credential rather
than a generated one, set `S3_ACCESS_KEY` and `S3_SECRET_KEY` in `.env` and it will
import those instead.

To point at someone else's S3 — AWS, SeaweedFS, an appliance — set `LAZARET_DATA`,
`LAZARET_RAW`, `LAZARET_S3_ENDPOINT`, `LAZARET_S3_REGION` and the key pair on the
engine, and delete the `garage` and `garage-init` services. Nothing in the engine
knows the difference.

**Two buckets, not one.** DuckLake owns the corpus prefix and rewrites and expires it
during compaction; custody objects must survive untouched until a person releases or
purges them. Sharing a prefix would let a compaction remove mail under legal hold.

**Back up the custody bucket with the database, not with the caches.** Losing it makes
every quarantined message unreleasable.

`LAZARET_S3_REGION` is `garage`, which is Garage's default and not `us-east-1`. SigV4
signs the region into the request, so a wrong one is rejected as
`AuthorizationHeaderMalformed` — an error that reads like a credentials problem and is
not one.

## Before this leaves a laptop

`ADMIN_PASSWORD` is the only value with no default: there is no safe one, and a
product that ships with `admin/admin` ships compromised. Everything else starts
usable and should not stay that way.

```sh
POSTGRES_PASSWORD=$(openssl rand -hex 16)           # defaults to "lazaret"
LAZARET_SECRET_KEY=$(openssl rand -hex 32)          # encrypts mailbox credentials
```

`LAZARET_SECRET_KEY` is generated into the `state` volume if you leave it unset, which
is fine for one host and wrong the moment you want to restore onto another. The blob
store credential is generated the same way and needs nothing from you.

`garage.toml` ships an `rpc_secret` of all zeroes. It guards node-to-node RPC, of
which there is none while Garage is a single node on an `internal: true` network, so
it is inert here — but replace it (`openssl rand -hex 32`) before adding a second
node, and replace it before Garage is reachable from anywhere else.

## Networks

`analysis` is `internal: true`, so nothing on it reaches the internet. That contains a
renderer which has just executed hostile HTML and an engine which has just parsed a
hostile message — and it stops analysing a message from telling its sender it was read,
because remote images and tracking pixels simply fail to load.

Enabling `ml.link_analysis` means deliberately giving the renderer egress. That is a
separate decision with a separate flag; see [`services/render/README.md`](../../services/render/README.md).

## Rules and models

- `rules/` is mounted read-only into the engine. Put a checkout of
  [`sublime-security/sublime-rules`](https://github.com/sublime-security/sublime-rules)'s
  `detection-rules` there, or your own content.
- `models/` is mounted read-only into `lazaret-ml`. Empty is a valid state: every
  model-backed capability reports unavailable and the rules that wanted one report
  indeterminate, which is the designed behaviour rather than an outage.
