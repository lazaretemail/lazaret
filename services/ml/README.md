# lazaret-ml — module 5

The model-backed capabilities. Replaces Sublime's `bora-lite` and `hydra-cpu`.

| Capability | Corpus rules | Answered by |
|---|---|---|
| `ml.nlu_classifier` | 358 | entailment model + lexical extraction |
| `ml.logo_detect` | 100 | brand wordmarks in OCR text, and shipped perceptual hashes |
| `beta.ml_topic` | 14 | the same entailment model |
| `ml.macro_classifier` | 1 | VBA features |
| `ml.attack_score`, `beta.fuzzy_attack_score` | 2 | composition over other signals |
| `beta.ml_translate` | 1 | LibreTranslate, or the identity case |

Everything in `ml.*` that does **not** need a model was taken out of this service and
implemented elsewhere, which is most of the volume: `beta.ml_extract_sensitive_information`
(304 calls) is patterns and checksums in `sensitive`, `beta.ocr` / `beta.scan_qr` /
`beta.parse_exif` are Strelka scanners, and three-quarters of what the corpus reads off
`ml.link_analysis` is a browser's observations, in `services/render`.

## Capabilities can be half-available, and say so

This is the design the rest of the service is arranged around.

`ml.nlu_classifier` has four accessors and they are four different problems. `.entities`
and `.language` are lexical — an entity *is* the words "wire transfer", and rules read
`.text` on one 209 times, more often than `.confidence`. `.intents`, `.topics` and
`.tags` are judgements and need a model.

So with no weights present the result carries entities and language and **omits** the
rest. Not empty arrays — omits. The corpus is full of clauses written to exclude benign
mail:

```
not any(ml.nlu_classifier(body.current_thread.text).topics,
        .name == "Newsletters and Digests" and .confidence == "high")
```

An empty `topics` array makes that negation true and the rule fires because nobody
deployed a model. An absent field is null, `any` over null is null, and the rule reports
indeterminate — the true answer to "was this a newsletter?" when nothing capable of
deciding was running. This engine shipped that exact bug once, by folding a null array
into an empty one, and it produced a false positive on a real corpus rule.

`GET /v1/capabilities` reports `partial` alongside `available` for the same reason:
"available" stopped being a useful word once a capability could answer half of itself.

## The label vocabulary is extracted from the rules

Nothing publishes the set of intents `ml.nlu_classifier` can return. What exists is 358
rules comparing against them, which is a better specification than a list: a label no
rule reads cannot change a verdict, and a label a rule reads and the classifier never
emits makes that rule dead.

So `labels.go` holds what the corpus asks for — 8 intents, 33 topics, 3 tags, 9 entities
— with the reference counts that produced them. `cred_theft` alone is 162 of the 311
intent references.

Two details that would each silently break everything:

- **Topics are Title Case with exact spacing.** They are compared with `==`, so
  "Charity and Non-Profit" and "Charity and Non Profit" are different labels and one of
  them matches nothing.
- **Languages are lowercase English names**, not ISO codes: `.language == "english"`,
  `!= "japanese"`. Returning `"en"` would be defensible and would match nothing, and no
  error would be raised anywhere.

## Zero-shot, because there is no labelled email set

The classifier is an entailment model asked, for each label, whether the message entails
"This text is *&lt;description&gt;*." Adding a label is writing a sentence rather than
collecting data — which is the only approach available when the vocabulary comes from
someone else's rule corpus.

It costs one forward pass per label. The engine caches enrichment per message, and
intents, topics and tags go in one batch.

### No weights ship

Two reasons, unchanged. Model weights carry their own licence independent of this code,
and an AGPL project that bundles them inherits whatever they came with. And an
unavailable capability is honest, where a weak one is not.

The model is loaded from the model directory:

```
zeroshot.onnx            the exported graph
zeroshot.tokenizer.json  the matching tokenizer
logos/<Brand>/*.png      your own logo images, if any (hashes ship in the binary)
```

Both of the first two or neither: a model with the wrong tokenizer produces token ids
that mean something else and scores that look entirely plausible.

`MoritzLaurer/deberta-v3-base-zeroshot-v2.0` (MIT) is what this was developed against.
It gets 6 of 6 on a hand-written set of one message per intent.
`Xenova/distilbert-base-uncased-mnli` was tried first and got 1 of 6 — which is the
concrete form of the argument above, and the reason the model is a deployment choice
rather than something chosen here on an operator's behalf.

### Hardware acceleration

`-accelerator=auto` (the default) offers TensorRT, then CUDA, then ROCm, CoreML or
DirectML to the runtime, and uses whichever it accepts. CPU is always last and always
works.

Chosen by trying, not by inspecting the machine. "Is there a GPU" is the wrong
question and answering it is a swamp: an nvidia device node can exist with no driver,
a driver with no CUDA runtime, a CUDA runtime the build will not load, and a container
can see `/dev/nvidia0` while the libraries live on the host. Each of those looks like
a GPU to a probe and fails at the first inference. Appending the provider to real
session options either works or returns an error string at startup.

`GET /v1/capabilities` reports what was used and what was tried, because a deployment
that mounted a GPU and is silently on CPU looks identical to one that is not — apart
from being far slower.

```sh
docker build -f services/ml/Dockerfile \
  --build-arg TAGS=onnx --build-arg ORT_FLAVOR=gpu --target runtime-gpu \
  -t lazaret-ml:gpu .
```

The GPU image is CUDA-based rather than distroless, because the execution provider
dlopens libcublas and libcudnn at session creation. It is safe on a node with no card:
the probe reports what it tried and falls back.

### Building with a runtime

ONNX Runtime is cgo and large, so it is behind a build tag:

```sh
go build -tags onnx ./services/ml
```

**The binding and the runtime are a matched pair.** `onnxruntime_go` requests a specific
ORT API version and refuses anything older — v1.30.1 wants API 25, which is ORT 1.25.
A mismatch fails at startup with "The requested API version is not available", and the
service then runs with no model rather than crashing. `go.mod` and the Dockerfile are
pinned together; change one and you change both.

## Benign is not trusted by default

`benign` is the one intent the corpus uses to *suppress* — `not any(intents, .name ==
"benign" and .confidence == "high")` — so a wrong benign does not raise a false
alert, it silently stops a rule that would have fired. Every other intent is used the
other way round.

The cost matrix is therefore lopsided, and measurement bore that out: on the nine real
phishing samples in the rule corpus plus four hand-written benign messages, the
dominance test alone called four of the nine benign. So two things hold benign to a
higher standard:

- it needs absolute evidence as well as a dominant share (`SuppressiveFloor`), because
  on a message whose maliciousness is not in its prose every other intent scores near
  zero and benign wins by default;
- and it is capped at medium unless `-trust-benign-suppression` is passed.

Turn the switch on once you have measured your own mail and decided the suppression
earns its keep. Leaving it off costs noise; turning it on without measuring costs
detections, and silently.

## Logo detection is two signals

Most brands the corpus asks about are **wordmarks** — PayPal, Netflix, Norton, DocuSign,
Geek Squad, eBay, AT&T — whose logo is their name in a typeface. Those are found by
reading the text in the image, which this platform already does with Strelka's `ocr`
scanner; the engine passes that text alongside the image. This half needs no reference
pack and works out of the box.

The rest are **symbols** — the Dropbox box, the Meta loop — and need image comparison.
That is a 64-bit perceptual hash against a set of reference marks.

### Hashes ship; images do not

`logohashes.json` holds 311 hashes across 57 brands — 43 of the 49 the corpus names,
plus 14 impersonation targets it does not — and no pictures. Using a mark to
identify its holder is exactly what a brand-impersonation detector does, but
*redistributing* thirty-seven companies' trademarks inside an AGPL repository is a
different question from using them, and not one to answer on an operator's behalf.

A perceptual hash is not a copy. Sixty-four bits of "is this cell brighter than the one
to its right" cannot be turned back into a logo, has no expressive content of its own,
and does nothing except recognise the mark it came from.

Two things fall out of that which are worth having anyway. The pack is the **same
everywhere**, so two deployments of the same version detect the same things and a
missed detection is reproducible — an earlier version downloaded logos at deploy time
and could not promise that. And **no trademark images land on the operator's disk**,
which is the outcome the exercise was after.

References are the brands' own logos, located through Wikidata — the logo property
(P154), or the seal (P158) for a government agency, whose mail carries a seal rather
than a logo — and rendered from Wikimedia Commons at three widths.

**Every logo, not the current one.** Wikidata holds each mark a brand has used, and
they are all worth having: OneDrive has four (the 2012 SkyDrive wordmark, the
2014–2018 lockup, the 2019 tile and the 2025 icon), Microsoft has its 1980, 1982, 1987
and 2012 marks, X has both the current mark and the Twitter bird. A phishing kit built
from stale assets uses the old one, and an earlier pack that took only the first claim
per brand was matching OneDrive's 2014 wordmark and nothing else. 95 distinct logos
across 43 brands.

Six of the corpus brands have no symbol reference: Gemini Trust, Gusto, Mailgun,
Navan, Robert Half and SendGrid. All are wordmarks, so the OCR half still matches them.

### Brands the corpus does not name

Sublime's vocabulary is almost entirely SaaS and finance. It has SSA and USPS and then
stops, which leaves out a category that is heavily impersonated: a tax authority
demanding payment and a carrier demanding a redelivery fee are two of the most-worn
costumes in phishing. `ExtraBrands` adds them.

| | |
|---|---|
| United States | IRS, US Treasury, FBI, DHS, CISA, USCIS, Medicare, US Dept of Education, E-ZPass |
| United Kingdom | NHS, TV Licensing, DVLA, HMRC, Royal Mail |
| Carriers and post | UPS, An Post, Australia Post, Canada Post, Chronopost, Correos, DPD, La Poste, PostNL, PostNord, Poste Italiane, Swiss Post |

They are a separate list from `Brands`, which is corpus vocabulary and not ours to
edit — a name added there would look like something Sublime's rules compare against,
and would not be. A rule reading one of these will not run on Sublime's engine.

Being in the list does not make a rule fire by itself. It puts the name in the
analyst's view, and it feeds the corpus rules that ask whether *any* brand was found
alongside other signals. `impersonation_ups.yml` is written that way and until now
could never see a UPS logo, because UPS was not a brand this could return.

**Most of the federal seals do not survive as symbols.** An eagle in a circle at nine
by eight pixels is the same picture as another eagle in a circle: IRS, US Treasury,
FBI, DHS, TV Licensing, DVLA and Australia Post all landed inside the margin of each
other or of unrelated marks — Treasury sat 8 bits from Facebook — and the cross-brand
guard dropped all of them. They match by wordmark instead, which for an agency is the
better signal anyway: "Internal Revenue Service" is unmistakable as text and
unremarkable as a shape.

An acronym on its own is not usable as a wordmark. Three letters with word boundaries
still match English, and OCR flattens every layout into prose, so each short form is
paired with its spelled-out name and the ones that are common words — "ups" is the
plural of "up" — are the spelled-out name only.

Six of these have no image on Wikidata at all: HMRC, Royal Mail, Canada Post, Canada
Revenue Agency, the Australian Taxation Office and GOV.UK. Crown-copyright marks
largely are not there. Those are wordmark-only until somebody supplies the assets.

### The source has to be the real logo

Two earlier packs failed, and both failures were the source rather than the method.

**Favicons.** The first version fetched each brand's favicon. A favicon is usually a
letter in a rounded box, and at eight by nine pixels they all look alike: 37 of 47
brands landed inside the match threshold of each other, so the matcher would have
reported a confident wrong brand for almost any mark.

**A monochrome icon set.** The second used Simple Icons, which is CC0 and looked like a
clean answer. Internally it was — no two brands collided. But an icon set is a stylised
single-colour glyph, not the logo a company actually uses, and measured against the
real logos it stood for it matched **1 brand in 31**. X's real logo was closer to
Microsoft's icon than to X's own.

The lesson is about the measurement, not the data. Reference-against-reference says
nothing: the icon pack passed that comfortably. What has to hold is
reference-against-subject.

### The reference has to be flattened onto white

Brand logos are distributed with a transparent background — 108 of these 111 — and Go's
`image.At` returns premultiplied values, so a transparent pixel reads as black. A
reference hashed that way is the mark on black, while the same logo in a message sits
on white, and since dHash compares neighbours, inverting the field inverts nearly every
comparison.

Measured: without flattening, 15 of 111 references matched their own on-white subject.
With it, 111 of 111.

### How a brand is decided

Two independent signals, and neither consults a list of permitted brands.

**By picture.** Every reference is a `(brand, 64-bit hash)` pair. The brand is the
*directory name*, verbatim — `logos/Gringotts Wizarding Bank/mark.png` makes
`ml.logo_detect` able to return `Gringotts Wizarding Bank`. Nothing validates it
against `Brands` or anything else, and a rule can compare against whatever string it
likes. There is a test that does exactly this with a made-up name.

**By name.** The OCR text that comes alongside the image is searched for each brand's
wordmark. The built-in brands have hand-written patterns, because their wordmark is
often not their label — `AT&T` has to match "at and t", `Quickbooks` has to match
"quick books". A brand you add gets a pattern derived from its directory name, so
`logos/Northgate Credit Union/` matches "Northgate Credit Union" in OCR text with
flexible spacing. The name is quoted, not compiled: a bracket or a full stop in it is
a bracket or a full stop.

Names of three characters or fewer get no derived wordmark and match by picture only.
A two-letter pattern fires on ordinary mail constantly, and the built-in list shows
the cost — "ups" is the plural of "up", and `X` is a letter, so both are picture-only
there too.

The lists in `labels.go` therefore do one job: they carry the hand-written wordmark
patterns and record which names Sublime's rules compare against. They are not a
gate on what can be detected.

### Supplying your own

Drop images under `<models>/logos/<Brand>/` and restart:

```
models/logos/
  Chase/                      replaces the shipped Chase hashes
    chase-2007-256.png
    chase-2007-512.png
  Northgate Credit Union/     a brand nothing shipped knows about
    wordmark.png
```

They are hashed in your process and never leave the machine. A directory whose name
matches a shipped brand **replaces** the shipped hashes for it rather than adding to
them — your real asset beats a third-party rendering, and keeping both would let the
worse one go on matching.

Name files `<something>-<width>.png` if you have the same logo at several sizes, and
the stability guard below can check them against each other. A single file is kept as
it is.

To share hashes without sharing the images:

```sh
lazaret-ml -hash-logos ./my-logos -hash-logos-source "in-house brand assets" > pack.json
```

That is also how `logohashes.json` was produced, and how a brand gets added without
anyone sending a trademark anywhere.

Two guards run over any pack, shipped or yours. Both use a fixed margin of 16 bits
rather than the match threshold, so that tuning the threshold does not reshape the pack
it is being tuned against.

**A logo whose own renderings disagree.** `-hash-logos` groups files by name —
`Microsoft-logo-1982-256.png` and `-512.png` are one mark at two widths — and drops any
mark whose renderings spread past the margin. Such a hash is not describing the image.
Gusto is the example: its logo on Wikidata is a solid coloured block with the wordmark
reversed out, 92% ink, so the tight crop finds no border and all 64 comparisons run
over uniform colour, where each is a coin toss. Its three renderings landed 31 bits
apart. A file with no sibling is kept — with one rendering there is nothing to check
against, and inventing a verdict would be worse.

Grouped per logo, never per brand. An earlier version grouped by brand and would have
thrown away Microsoft's 1980 wordmark for disagreeing with its 2012 squares, which are
39 bits apart and both correct.

**Two brands that share a mark.** Any two references from different brands within the
margin are both dropped, because a mark landing between them reports both and nothing
in the hashes says which is right. These are almost always wordmark lockups — Block's
black wordmark sat 13 bits from Slack's, dark text on white being dark text on white at
nine by eight pixels. Losing them costs little, since a wordmark is what OCR reads
anyway.

Separately, every service start re-checks the assembled references — shipped plus yours
— and logs any brand pair inside the match threshold.

### The threshold is measured against distorted subjects

Two marks match when fewer than **14** of the 64 bits differ.

Each reference was put through six things a logo picks up on its way into a mailbox —
rescaled to half and to double, cropped four pixels in, padded, composited on a grey
background, and JPEG-recompressed at quality 60 — giving 558 images to look up:

| bits differing | recall | variants reporting a brand that is not there |
|---|---|---|
| < 8 | 89% | 0 / 558 |
| < 10 | 91% | 0 / 558 |
| < 12 | 93% | 0 / 558 |
| < 14 | 94% | 0 / 558 |
| < 16 | 96% | 2 / 558 |

Fourteen is the last threshold that never reports a brand that is not there. The
matcher returns every brand inside the threshold rather than only the closest, so a
spurious match is not outvoted by a better one — it is simply reported.

The hash is taken after a **tight crop to the ink**. Without it the hash is largely a
description of how much white space the sender left around the logo, and the same mark
with a different margin lands nowhere near itself.

Three of the "brands" are not brands: `FakeAttachment`, `Generic Webmail` and
`Invite Company` are shapes a detector recognises, and can only come from a pack
somebody builds.

## The parts that are features rather than models

`ml.macro_classifier` is feature-based, and here that is the stronger choice. What makes
a VBA macro malicious is not a matter of tone: it runs without being asked, it reaches
the network or the shell, and it hides what it is doing. Each is individually rare in a
legitimate document macro and jointly almost unheard of, so the scoring requires
behaviour from more than one family before it will say high — and the one corpus rule
that reads this also requires `.confidence in ("high")`.

`ml.attack_score` and `beta.fuzzy_attack_score` are a stated combination of other
signals rather than a meta-model, because a meta-model needs labelled verdicts to train
against and that is precisely the data an open implementation does not have. A
combination can at least be read and argued with. The corpus reads exactly one thing off
these — `.verdict == "graymail"` — and bulk mail announces itself in its headers.

## Translation delegates

A general translation model is a per-language-pair download in the hundreds of megabytes,
and the rule that uses this feeds the result straight into the NLU classifier, so a bad
translation does not degrade gracefully — it silently changes what the classifier is
shown. `-translate` points at a self-hosted LibreTranslate (AGPL-3.0, the same licence as
this project). Nothing is sent anywhere by default.

Text already in the target language is returned unchanged. That is not a shortcut around
the missing model; it is the correct translation, and in an English-speaking deployment
it is the common case.

## Running it

```sh
lazaret-ml -models /var/lib/lazaret/models -addr :8720 \
           -translate http://libretranslate:5000
```

Empty model directory is a valid state. Every capability that needs weights reports
unavailable, the rules that wanted one report indeterminate, and the half of the NLU
classifier that needs nothing keeps working.
