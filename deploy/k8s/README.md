# Kubernetes

Kustomize, no Helm. The manifests are meant to be read, because what this deployment gets
wrong will be a containment or a custody decision, and those should be visible in the YAML
rather than assembled from values at template time.

```sh
kubectl apply -k deploy/k8s/base            # or an overlay below
```

Verified end to end on kind 1.31: all seven pods running, 1,257 rules loaded, custody
writable on Garage, a message ingested and flagged in 762ms.

Images are pinned to a version tag rather than `latest`. An unpinned tag means you can't
say what's running, which for a platform that quarantines mail is the first question after
anything goes wrong. Kubernetes also defaults `imagePullPolicy` to `Always` for `latest`,
so a locally built image is ignored in favour of a registry pull that fails.

## What has to happen in order

The engine will start before any of this and report itself unhealthy in specific ways,
which is intended, but it can't quarantine anything until steps 2 and 3 are done.

**1. Secrets.** Copy `base/secrets.example.yaml`, fill it in, apply it. Three secrets
rather than one, so no pod is handed a credential it has no use for. Don't commit the
result.

**2. Object storage.** A fresh Garage has no layout, no key and no buckets:

```sh
kubectl -n lazaret create -f base/garage-bootstrap.yaml
kubectl -n lazaret logs -f job/garage-bootstrap
```

It prints an access key and secret. Put them in `lazaret-engine` and restart the engine.
They aren't written for you: a Job that can write Secrets needs RBAC to do it, which is a
larger grant than typing two values once.

**3. Check custody is writable.**

```sh
kubectl -n lazaret exec deploy/engine -- \
  wget -qO- --header "Authorization: Bearer $TOKEN" localhost:8700/v0/readiness
```

`"writable": true` means a quarantine can be carried out. `false` means the engine is
running, detecting, and refusing every quarantine, which is the safe failure and a silent
one if nobody looks. The usual cause is the region: Garage's is `garage` rather than
`us-east-1`, and SigV4 signs it into the request, so a wrong one is rejected as
`AuthorizationHeaderMalformed`, which reads like a credentials problem and isn't.

**4. Model weights, if you want the model-backed capabilities.**

```sh
kubectl -n lazaret create -f base/ml-fetch-models.yaml
kubectl -n lazaret wait --for=condition=complete job/ml-fetch-models --timeout=30m
kubectl -n lazaret rollout restart deployment/ml
```

Optional and deliberately manual. No weights ship with this project, since a model's
licence is independent of this code, and 358 rules read `ml.nlu_classifier`. Without it
they report indeterminate, while entity extraction, language identification, the macro
classifier and brand wordmarks all still work.

**5. Mail.** `kubectl -n lazaret scale deployment/ingest --replicas=1`, after
creating an admin API token in the dashboard and putting it in `lazaret-ingest`.
Mailboxes are added in the UI, not here.

## Two things worth knowing before the first start

**The engine downloads DuckDB extensions on every cold start.** `ducklake`, `postgres` and
`httpfs`, into an emptyDir at `$HOME/.duckdb`. It already has egress for the list
downloads, so this costs a few seconds and keeps the pod disposable. It does mean a fully
air-gapped cluster needs those extensions baked into the image.

**Nothing works until Garage has a layout.** A fresh one accepts connections and stores
nothing, so the engine starts, reports custody unwritable and refuses every quarantine.
That's the safe failure and a quiet one, so step 2 above isn't optional.

## Two settings that are constraints rather than defaults

**The engine is `replicas: 1` with `strategy: Recreate`.** A DuckLake catalog is bound to
its data path and the engine holds a write lock on it, with DuckDB linked into the process
on a single connection. A second replica doesn't share the work, it fights for the catalog.
A rolling update starts the new pod before the old one exits, which is that same case with
a corrupted catalog as the result rather than a crash.

Hunt is the part that would benefit from scaling out, and it can, because a hunt worker
opens its own read-only store. That's a Deployment to add rather than a replica count to
raise.

**The renderer has no internet egress**, and neither does `ml`. That's the `internal: true`
network from the compose file, spelled out as NetworkPolicy. It contains a browser that has
just executed hostile HTML, and it stops analysing a message from telling its sender it was
read, because remote images can't load.

> **Your CNI must enforce NetworkPolicy.** Calico, Cilium and Antrea do. Flannel alone
> doesn't, and these policies will be accepted by the API server and enforce nothing,
> which is indistinguishable from working. Check it:
>
> ```sh
> kubectl -n lazaret exec deploy/render -- wget -T3 -O- https://example.com
> ```
>
> That should fail. If it returns a page, you have no containment.

Egress is granted by label, one boolean key per destination (`egress-internet`,
`egress-data`) rather than one `egress` key with values. A pod holds one value per key, so
a single key means an overlay that adds database access silently removes internet access,
and the symptom is threat feeds that stop refreshing with nothing in the logs.

## Overlays

| Overlay | For |
|---|---|
| `base` | the whole stack, in-cluster Postgres and Garage |
| `overlays/minimal` | kind, k3s, a laptop. Smaller everything, no ONNX runtime |
| `overlays/external-data` | managed Postgres and a real bucket store |
| `overlays/link-analysis` | `ml.link_analysis`, and the containment trade it costs |

`external-data` is the right shape for anything real. The base runs one Postgres pod
holding the rules, tenants, users, audit log, materialised profiles *and* the DuckLake
catalog that makes the corpus readable at all. An operator or a managed instance takes that
class of problem away.

## Backups

Two things, and they fail differently.

**Postgres** holds the catalog. Without it, the Parquet in object storage is a pile of
files nothing can interpret.

**The custody bucket** holds the only remaining copy of every quarantined message.
Quarantine deletes the message from the mailbox rather than moving it to a folder, so
losing that bucket doesn't degrade the platform, it destroys mail. It belongs in a backup
policy with the database, never with the caches.

The corpus bucket is rebuildable in principle and painful in practice. Back it up too,
though it isn't the one that keeps you up.

## What is not here

**Strelka**, which answers `file.explode`, `beta.ocr`, `beta.scan_qr` and
`beta.parse_exif`, about 440 rules. It's upstream's deployment, Apache-2.0, and we run it
rather than fork it. See `third_party/strelka`, then set `LAZARET_STRELKA` in the ConfigMap
to its frontend.

**Rspamd**, the inline path and the only placement where a verdict can stop a message
reaching a mailbox at all. It sits in your MTA rather than in this namespace, and
`services/ingest/lua/lazaret.lua` points it here.

**TLS.** `ingress.yaml` assumes nginx and cert-manager. Replace it with whatever you
already run; nothing else depends on it.
