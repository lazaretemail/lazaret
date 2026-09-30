# lazaret-render — module 4

Headless rendering. Replaces Sublime's `render-email-html` container.

## What it answers

| MQL capability | Corpus calls |
|---|---|
| `file.message_screenshot` | 347 |
| `file.html_screenshot` | 8 |

Neither is ever read for its own sake. A screenshot is always fed to something that
looks at pixels, and in the corpus that is `beta.ocr` (161 calls),
`ml.logo_detect` (76), `beta.scan_qr` (11) and `beta.parse_exif` (5). Rendering is what
makes an attack that puts its words inside an image visible to a text engine at all —
and with Strelka also deployed, `beta.ocr(file.message_screenshot()).text` works today.

## Contract

`POST /v1/screenshot` with `{"html": "..."}` returns `{"file_name": "...", "png": "..."}`.
`GET /v1/health` reports whether a browser is present.

The client is `render` in the root module, which is standard-library only: the browser
lives here, and the core stays small enough to `go get` for rule linting.

## Reused browsers, a tab per render

This service used to shell out to `chromium --headless --screenshot` and had no
dependencies beyond the standard library. That was right while a render was a rare
event. It stopped being right when link analysis landed: a message carries around
forty links, each one wanted a browser, and a browser costs roughly three hundred
milliseconds to start before it has looked at anything.

So there are now long-lived browsers, and each render is a tab. Measured on a
sixteen-core host: **467ms per render became 186ms**, two and a half times faster.
Under heavy concurrency the difference mostly disappears — the machine is busy
rendering either way — so the win is in the latency of a single message, which is
the number a person waits on.

Two browsers rather than one, because one command line cannot serve both jobs. The
*document* browser renders message bodies and cannot resolve a hostname; the *link*
browser visits links and has the network. Keeping them apart is what stops the
no-egress guarantee below from depending on a code path being taken.

The cost is `chromedp` and a permanent CDP connection to a process treated as
compromised. Worth it for the above, and the isolation that a fresh process used to
give away for free is bought back explicitly — see the next section.

### Memory is the binding limit

A process that exits gives its memory back; a browser that stays up does not. On a
2GiB container under real mail, one link browser with sixteen tabs climbed from
1.36GiB to 1.91GiB in under two minutes, which is an OOM kill with every render in
flight. Two things follow, both automatic:

- **The tab limit comes from the memory limit, not the core count.** Sixteen cores
  and a 2GiB cap gives eight tabs, not sixteen. Override with `-max-tabs`.
- **A browser that grows past 70% of the container's limit is recycled**, after
  draining every tab so no render is interrupted. Where there is no cgroup limit to
  read, a job count is the backstop.

`-reuse-browsers=false` goes back to a process per render. It is slower and it is
correct, which is also what happens by itself if a browser will not start.

## Security posture

This process exists to open attacker-controlled documents. It is the most exposed thing
in the deployment and is built on that assumption:

- **A browser context per render** — Chromium's own isolation boundary, the one
  incognito uses — created and discarded per job. Nothing survives from one message
  to the next: no cookie, no localStorage entry, no service worker. This is the part
  a process per render gave for free, and it is covered by a test that sets a cookie
  in one job and asserts the next never sends it.
- **The document browser cannot resolve anything.** `--host-resolver-rules=MAP *
  ~NOTFOUND`, which covers a bare IP address as well as a hostname. It used to be
  enough that this container sat on an internal network, but enabling link analysis
  joins it to one with egress, so the guarantee had to stop depending on which
  compose file was used. A remote image, a tracking pixel or a callback in a message
  body simply fails to load — which contains the renderer *and* stops the act of
  analysing a message from telling its sender it was read.
- **Read-only root, tmpfs, no-new-privileges, unprivileged user**, and CPU and memory
  caps: layout is a fine denial of service.
- Chromium runs with `--no-sandbox` because its own sandbox needs privileges this
  container deliberately does not have. The container and the network are the sandbox.

## Fonts are load-bearing

The image installs the Liberation, DejaVu, Noto, Noto CJK and Noto emoji faces. A
message rendered with missing glyphs produces tofu, OCRs to nothing, and "no text found"
reads as a clean message. A missing font package is a silent detection gap.

## Running it

```sh
docker compose -f deploy/compose/docker-compose.yml up -d --build render
lazaret run --rules ./sublime-rules/detection-rules -render http://localhost:8710 \
            -strelka localhost:57314 message.eml
```

End to end, including the OCR chain:

```sh
LAZARET_RENDER=http://localhost:8710 LAZARET_STRELKA=localhost:57314 \
  go test ./render/ -run Live -v
```
