# Strelka

[`target/strelka`](https://github.com/target/strelka), Apache-2.0, is the file analysis
engine behind MQL's `file.explode`. Sublime runs it too: their published
`FileExplodeOutput` schema is literally Strelka's `StrelkaResponse`, which is why
`mdm/enrichment.gen.go` is generated from it rather than hand-written.

So we deploy it. We don't fork it and we don't reimplement it.

## What is here

- `docker-compose.yml`, a pinned deployment. Frontend on gRPC 57314, backend doing the
  scanning, Garnet coordinating, all on an internal network with no egress.
- `configs/backend/`, `configs/frontend/` and `configs/manager/` hold upstream's
  configuration trees, vendored verbatim from `target/strelka@4a133da`. Don't edit these.
  They're the reference copy, and keeping them byte-identical is what makes the next bump a
  clean `diff`.
- `configs/lazaret/backend.yaml` is the one file we override, bind-mounted over the vendored
  `backend.yaml`. `diff configs/backend/backend.yaml configs/lazaret/backend.yaml` is the
  complete and only list of Lazaret's deviations from upstream.
- `signatures/` holds Lazaret's YARA signatures, mounted over the vendored `yara/`. It's the
  same directory `lazaret yara` reads, so a signature behaves the same inside an explosion
  as over a top-level attachment.
- `../../api/proto/strelka/v1/strelka.proto` is the vendored protocol, from which
  `strelka/strelkapb` is generated.

Upstream mounts each config *directory* at `/etc/strelka` rather than individual files, and
that matters. `backend.yaml` is one of eight files the backend expects to find there, the
rest being the "taste" signatures that decide which scanners run, the TLSH family hashes,
`passwords.dat`, `logging.yaml` and the Suricata rules. Mounting `backend.yaml` on its own
shadows the others with nothing, and the scanners that need them then fail one at a time at
scan time rather than at boot, which is a much harder thing to notice.

## Running it

```sh
docker compose -f third_party/strelka/docker-compose.yml up -d
lazaret run --rules ./sublime-rules/detection-rules --strelka localhost:57314 message.eml
```

Ready about three seconds after `up`. To check it end to end:

```sh
LAZARET_STRELKA=localhost:57314 go test ./strelka/ -run Live -v
```

## What it answers

| MQL capability | Strelka scanner |
|---|---|
| `file.explode` | the whole scan tree |
| `file.expand_archives` | archive members, without their scan results |
| `beta.ocr` | `ScanOcr` (tesseract) |
| `beta.scan_qr` | `ScanQr` (zbar) |
| `beta.parse_exif` | `ScanExiftool` |

The last three sit among the `ml.*` functions in rule text but need no model. Strelka
already runs them over every file, so the answers are in the scan `file.explode` was
fetching anyway.

Their reach is narrower than the raw corpus counts suggest. `beta.ocr` appears 311 times,
but 231 of those are `beta.ocr(file.message_screenshot())` and need module 4, so only the
~70 calls on an attachment are answered here. `beta.parse_exif` is the opposite: 90 of its
104 calls are on an attachment. The nested fields reached through `file.explode` matter more
than either, and `.scan.ocr.raw` alone is read by 505 rules, more than any other enrichment
field in the corpus.

## Three wire-format divergences, and one that was breaking scans

Each was found by scanning a real file, and each is absorbed in `mdm/enrichment.go`:

- **`scan.qr.data` is an array**, where the published schema declares a string. This wasn't
  a lossy translation but a hard decode failure (*cannot unmarshal array into Go struct
  field StrelkaQR.scan.qr.data*), so **every scan of a QR-bearing attachment failed
  outright, taking all of `file.explode` with it**. QR codes are current phishing practice,
  so that's a file this engine meets rather than an edge case. `type` and the parsed `url`
  are absent from the wire and derived.
- **`scan.ocr` sends only `text`, an array of words.** The schema also declares `raw`, "full
  text including whitespace", and 505 rules read it. This build never sends it, and neither
  `extract_text` nor `split_words` changes that, so `raw` is reconstructed by joining the
  words with single spaces. It's lossy in exactly one way: original line breaks are gone.
- **`scan.exiftool` is a flat object of lowercased keys**, where the schema declares a
  `fields` array of `{key, value}` plus named conveniences. Both are filled from the flat
  map. The lowercasing matters, because the corpus compares tag names literally: `.key ==
  "Software"` (10 uses), `"Model"` (10), `"DeviceManufacturer"` (9). So exiftool's canonical
  casing is restored from a table. exiftool's filesystem entries are dropped, since
  `sourcefile: /tmp/tmpuw7vkgpn` is Strelka's temporary copy rather than document
  metadata.

## Enrichment must be cached

Around 500 corpus rules each write `file.explode(.)` for themselves, because MQL has no way
for one rule to share a result with another. Uncached, analysing a single two-attachment
message issues on the order of a thousand identical scans of the same bytes. A corpus
measurement that takes 8 seconds with `mql.NewCache` didn't finish inside a ten-minute
timeout without it.

`lazaret run` wraps its providers in one, scoped to a single message. Any other caller
must do the same.

## What it is worth

`go test ./strelka/ -run LiveCorpus -v` runs the whole corpus with and without a Strelka
connection, over messages carrying a real zip, a QR-code PNG and a multi-page PDF.
Connecting Strelka moves **69 evaluations** off indeterminate.

The fixtures matter as much as the number. An earlier version of this measurement used only
the zip, so the image scanners never fired and reported near-zero for capabilities that do
real work. That's the same mistake as counting rules that merely *mention* a function.

What remains, in order of how much of the corpus it blocks: `ml.nlu_classifier` (883
evaluations), the named `$list` data (`$high_trust_sender_root_domains` 589,
`$free_email_providers` 302, `$org_domains` 301, all published as MIT static files and the
cheapest remaining win), `profile.by_sender` (567), and `file.message_screenshot` (398),
which is module 4.

## Deviations from upstream

**`ScanClamav` is disabled.** Upstream runs `freshclam`, a full ClamAV signature download,
*inside the scanner, on every file*, which its own docstring admits is a POC: "The ClamAV
signature database is currently pulled every scan." The backend is single-threaded, so on
the egress-free `analysis` network that call blocks for the whole 150-second scanner timeout
per file and every queued task times out behind it. With it disabled a two-member archive
scans in 0.26s; with it enabled the same scan took 15s when it succeeded at all.

To turn it back on, give the backend a network with egress or point `freshclam` at a
local mirror, and prefer the `clamav-freshclam` daemon over a per-scan download.

**Tracing is off**, via `OTEL_SDK_DISABLED` in the compose file rather than by editing
`backend.yaml`. Upstream points the OTLP exporter at a Jaeger that isn't part of this
deployment, and its retries add seconds to every scan.

## Why the backend is isolated

It opens attacker-chosen files for a living: archives, Office documents, PDFs, LNKs. The
`analysis` network is marked `internal`, so a scanner that has just parsed something hostile
can't reach the internet, and only the frontend port is published, bound to localhost rather
than to every interface.

That isolation is a real constraint on what can be enabled rather than a formality, and it's
exactly why `ScanClamav` above can't work as upstream ships it. A scanner that wants to
phone home during a scan doesn't belong in this network, and the answer is to fetch its data
out of band rather than to open the network up.

## Garnet, not Redis

The coordinator and gatekeeper run [Microsoft Garnet](https://github.com/microsoft/garnet)
(MIT). Redis left open source in 2024 for SSPL, and Redis 8 added AGPL back as an option,
but a single vendor that has already relicensed once is a dependency with a known failure
mode. Garnet speaks RESP and has been verified against this exact deployment for everything
Strelka asks of it: `PING`, `RPUSH`, `BLPOP`, `LPOP`, `ZADD`, `ZPOPMIN`, `BZPOPMIN`,
`EXPIRE` and `DEL`.

It needs `--bind 0.0.0.0`. Garnet listens on localhost by default, and the frontend's
`connection refused` is otherwise the only symptom.

[Valkey](https://github.com/valkey-io/valkey) (BSD-3, Linux Foundation) is the drop-in
alternative if you'd rather have a literal Redis fork: swap the image and drop the `--bind`
argument.

## Updating the vendored configuration

```sh
git clone --depth 1 https://github.com/target/strelka
cp -r strelka/configs/python/backend third_party/strelka/configs/backend
cp -r strelka/configs/go/frontend    third_party/strelka/configs/frontend
cp -r strelka/configs/go/manager     third_party/strelka/configs/manager
```

Then re-apply the `ScanClamav` change to `configs/lazaret/backend.yaml` and check the
diff against the new upstream copy.

## Licensing

Apache-2.0 is one-way compatible into AGPL-3.0, and in any case Strelka runs as a separate
process reached over its own protocol, so no licence question arises. The vendored `.proto`
and the vendored configuration carry upstream's copyright.
