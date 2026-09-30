# How a verdict is reached

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

A message is parsed into the Message Data Model, every loaded rule is evaluated against
it, and the results are combined. This page covers what happens in between, and where
the judgement calls are.

## Three outcomes, not two

Every rule ends in `match`, `no match`, or `indeterminate`. The third exists because MQL
rules read things an engine may not be able to answer: a model's opinion of the prose, the
registration date of a domain, the contents of a zip, whether this sender has written to
you before.

When one of those is unavailable, the rule reports indeterminate and names the capability.
It does not evaluate to false. A message is only reported clean when everything its rules
asked for actually ran.

The dashboard's coverage page lists which rules cannot currently run, and why. The engine
logs a summary at startup and a line whenever a capability drops or comes back:

```
capability lost: ml.nlu_classifier — 358 rules will now report indeterminate
capability recovered: ml.nlu_classifier — 358 rules can run again
```

### A capability can be half-available

`ml.nlu_classifier` with no model still answers `.entities` and `.language`, because those
are lexical, and omits intents, topics and tags, which are not. The omitted ones read as
null and their rules report indeterminate.

What gets recorded is the pessimistic reading: the whole capability is marked missing
whenever any accessor could not be answered, including for a rule that only read the half
that works. Over-reporting was chosen deliberately — a verdict claiming completeness it
did not have is the worse failure — so "missing capabilities" is slightly gloomier than
reality.

## The classifier is zero-shot entailment

`ml.nlu_classifier` backs 358 corpus rules. There is no trained model behind it and no
weights in this repository.

The labels are not ours to invent: the corpus tells you what they are. Every rule that
reads `.intents`, `.topics` or `.tags` compares against a string, so the vocabulary can be
extracted from the corpus itself. Given the vocabulary, the classification is natural
language inference — does this message entail "the sender is requesting a wire transfer"?
— which off-the-shelf NLI models do without any training on email at all.

Developed against **`MoritzLaurer/deberta-v3-base-zeroshot-v2.0`** (MIT, ~740MB), which
`services/ml/fetch-models.sh` downloads.

The evaluation behind that recommendation is six hand-written messages, one per intent,
and it got six of six. `Xenova/distilbert-base-uncased-mnli` got one of six, which is why
the model is named here at all rather than left to chance. That is a smoke test and a
comparison, not an evaluation. The choice wants trying on real mail before anyone treats
it as settled.

### Confidence, and why it is a ratio

An entailment probability from this model is not comparable between messages. The same
confident answer scores 0.14 on one input and 0.99 on another. Absolute cut-offs were
wrong twice over — wrong in kind, and the particular numbers were not derived from
anything.

- **Intents are judged by dominance.** A label is `high` when it takes at least twice the
  runner-up's share. A ratio is scale-free, so it survives the between-message variation
  an absolute threshold cannot.
- **Topics and tags use an absolute probability**, because there is no runner-up to
  compare against. 0.5 for `medium` is what the NLI head means — more likely entailed than
  not — rather than a guess.

Both are settable (`-high-ratio`, `-high-prob`), and `lazaret-ml -calibrate <
labelled.jsonl` fits them to your own mail and reports precision and recall per candidate.
It needs no training and no GPU.

### `benign` is the dangerous one

`benign` is the only intent the corpus uses to *suppress*:

```
not any(intents, .name == "benign" and .confidence == "high")
```

Every other intent is used the other way round. So a wrong `benign (high)` does not raise
a false alert — it silently stops a rule firing. The cost matrix is lopsided, and scoring
the two mistakes symmetrically treats them as equal when they are not.

Measured on the nine real phishing samples in the rule corpus plus four hand-written
benign messages, the dominance test alone called **four of the nine phishing samples
benign-high**. Any one of those would have suppressed detections. The raw probabilities
separate most of them cleanly — the false ones scored 0.0026 and 0.0139 while genuine
benign mail scored 0.54 to 0.98 — because on a message whose maliciousness is not in its
prose, every other intent scores near zero and `benign` wins the share by default.

So a suppressive label now needs absolute evidence as well as a dominant share
(`SuppressiveFloor`, 0.25, which sits in that gap with room either side). That took it
from four wrong to two, with all four benign controls still correct. The remaining two —
a punycode-domain lure and a generic "outline for new project" — score 0.81 and 0.56, and
the model is not wrong in any way a threshold could fix. Their prose really is ordinary.
They are caught by the rules that read the domain instead.

On top of that, `-trust-benign-suppression` controls whether `benign` may be reported at
high confidence at all. **Off by default**, which caps it at medium. Since the corpus only
suppresses on high, a wrong benign cannot stop a rule firing, while every intent that
*causes* a rule to fire is untouched. The cost is real: those negations exist to keep
ordinary mail out of noisy rules, and capping gives that up until a deployment has
measured its own traffic.

Thirteen messages is a sanity check, not an evaluation. The mechanism holds up; the
numbers want real mail.

### Entities and language use no model at all

`.entities` and `.language` are answered with patterns and stopword frequency. They work
in a deployment with no weights.

That reads as a concession and is not one. An entity *is* the words "wire transfer", and
rules read `.text` off one 209 times in the corpus — more often than they read
`.confidence`. The trade is that those two accessors will never improve by swapping the
model.

Language names are lowercase English words (`"english"`, `"japanese"`) because that is
what the corpus compares against. Returning ISO codes would match nothing and raise no
error anywhere.

### `ml.attack_score` is a stated composition

A meta-model over other models' outputs needs labelled verdicts to train against, which is
exactly the data an open implementation does not have. So the verdict is a written-out
combination of intents, bulk headers and authentication results that an operator can read
and disagree with.

The corpus reads one thing off it — `.verdict == "graymail"` — and bulk mail announces
itself in its headers, so that part should be sound. The other verdicts are less so.

### Brand detection ships hashes, not logos

Wordmarks — PayPal, Netflix, Norton, AT&T — are their name in a typeface, so they are
found by reading the OCR text and need no reference at all.

Symbols need an image comparison, which means knowing what thirty-seven companies' marks
look like. Redistributing their trademarks inside an AGPL repository is a distribution
question, separate from the use question that nominative use answers. So what ships is
`logohashes.json`: 311 perceptual hashes and no pictures, across 57 brands — 43 of the
49 the corpus names — every mark Wikidata holds for each brand,
not just the current one, because a phishing kit built from stale assets uses the old
one. The remaining six are wordmarks the OCR half already reads.

Fourteen more brands are added on top of the corpus vocabulary: tax authorities,
federal agencies and postal carriers — IRS, HMRC, DVLA, Royal Mail, UPS, E-ZPass and
the rest. Sublime's list is almost all SaaS and finance, and a tax demand or a
redelivery fee is two of the most-worn costumes in phishing. Most federal seals are
unusable as symbols (an eagle in a circle looks like every other eagle in a circle, and
the Treasury seal sat 8 bits from Facebook's mark) so those match by wordmark, which is
the better signal for an agency regardless. Sixty-four bits of "is this
cell brighter than the one to its right" cannot be turned back into a logo and does
nothing but recognise the mark it came from.

Operators point `<models>/logos/<Brand>/` at their own images, which are hashed locally,
replace the shipped hashes for that brand, and never leave the machine.
`lazaret-ml -hash-logos <dir>` turns a directory of images into a shareable pack, which
is how the shipped one was made.

Two marks match when fewer than 14 of 64 bits differ: 94% recall with zero spurious
brands, measured over 558 copies of the references put through the rescaling, cropping,
recompression and background changes a logo picks up on its way into a mailbox.

Getting there took two wrong sources. A pack built from favicons put 37 of 47 brands
inside the threshold of each other. A pack built from a monochrome icon set had no
internal collisions at all and still matched the real logo it stood for in 1 case out
of 31 — which is the lesson: reference-against-reference proves nothing, only
reference-against-subject does. See [services/ml/README.md](../services/ml/README.md).

Three names in the corpus's brand list — `FakeAttachment`, `Generic Webmail`,
`Invite Company` — are detector classes rather than brands, and `X` is one letter and
unmatchable in prose without constant false positives. Those four can only ever come
from a pack somebody builds.

### Translation delegates, and answers the identity case locally

`beta.ml_translate` needs a self-hosted LibreTranslate (AGPL-3.0). Nothing is sent
anywhere by default.

Text already in the target language is returned unchanged, which is both the correct
translation and the common case in an English-speaking deployment. Text in another
language with no backend is reported **unavailable rather than passed through
untranslated**: the one rule that uses this feeds the result to the classifier, and a
confident answer about the wrong language is worse than no answer.

## Lists

`$list` references resolve in three tiers: static data vendored from
`sublime-security/static-files`, org-scoped lists from your configuration, and downloaded
threat-intel feeds.

**Disabled means unknown, not empty.** A list turned off reports unresolvable, and its
rules go indeterminate rather than silently changing verdict. A list that resolves to
nothing behaves the same way.

**Local exclusions beat everything**, including local additions and the upstream source.
An exclusion is somebody saying a specific entry is wrong for this deployment, and a
refresh should not undo that.

**Downloaded lists can carry a filter** — a regular expression applied to each raw line
before the value is extracted, so it can test columns the list format is about to discard.
That is the point of it: the reporter and tag metadata live in columns the rules never
see.

Two corpus lists are named `..._trusted_reporters`. "Trusted reporters" is a distinction
Sublime's platform makes and abuse.ch's public export does not expose, so these carry the
**full feed** — 56,448 and 1,478 entries. More coverage, and more chance of a reporter
nobody vetted. Narrowing them is now an operator's decision rather than ours.

**`$alexa_1m` answers through a fallback chain.** The Alexa ranking was discontinued in
2022. Lists gained a `fallback_to`, so `alexa_1m` → `cloudflare_radar_1m` → `tranco_1m`.
Radar is the better successor and is off by default because its dataset API wants a
Cloudflare API token, though a free account provides one. Without a token the chain
reaches Tranco, so the two rules that read `$alexa_1m` are answered either way. The
substitution shows on the settings page rather than hiding in code.

`majestic_million` is 80MB and nothing in the corpus reads it.

## Rule feeds

Rules are cloned from git repositories on a schedule, configured in the dashboard. A
fresh install seeds two:

- **`sublime-security/sublime-rules`** — the MIT corpus this engine exists to run, 1,257
  detections.
- **`lazaretemail/rules`** — Lazaret's own. Rules that use the `rdap.*` extensions MQL
  does not have, and so cannot go upstream.

Its own repository rather than a directory in this one, for the same reason Sublime's is:
rules change on a different clock from the engine, an operator should be able to take a
new detection without taking a new binary, and a contributor should be able to send a
rule without touching the platform.

A feed that fails to sync keeps serving the commit it last had. The engine loads what is
on disk at startup rather than waiting for a sync to change something — an earlier version
only reloaded when the commit moved, so a restart with an already-current clone ran one
rule and said nothing about the other 1,257.

## Sender history

`profile.*` answers from events strictly before the message being analysed, never from the
whole corpus. Processing order is therefore belief order: a message analysed today sees
what was known when it arrived, and a retrospective scan of last month does not get to use
next month's evidence.

That makes replay meaningful and it makes the answers reproducible. It also means a fresh
deployment knows nothing about anybody, and the profile rules will say so rather than
treating an unknown sender as a new one.

## Looking again at mail that has already been delivered

A pipeline that judges mail only on the way in is permanently behind. Most phishing is
attributed hours after it lands: a feed adds the domain at two in the afternoon, and the
message carrying it arrived at nine that morning. And a link is not a constant — serving
something harmless until the mail has cleared the gateway is the cheapest evasion there
is against anything that looks once.

Three things therefore go back over delivered mail. None of them acts.

**New detection content.** When a rule feed brings in rules that were not running before,
or a threat-intel list gains entries, the rules affected are run over the last thirty days
(`-retro-window`) and anything they match is filed as a finding. Only the rules that
actually changed, and only against messages that were not already judged malicious — a
message that was already quarantined has had its decision made, and re-filing it would
bury the findings that are new. A restart never triggers a sweep: the engine starts with
its local rules and the feeds arrive a moment later, so every rule would look new.

**Links.** Every link a message's rules actually fetched is scheduled to be visited again,
half an hour after delivery and then every six hours, up to four times. What is compared
is not the page — a page with a nonce or a rotating advert differs on every load — but
where the link ended up, whether anything was served, and roughly how much. A redirect
target changing, or a dead link coming alive, is a finding. Needs `-render`,
`-link-analysis` and `-link-watch`.

**Hunting and backtesting.** Both run an expression over stored mail on request. A
backtest additionally joins what analysts already decided about the messages it would have
matched, which is a real precision signal for a rule nobody has ever run: "it would have
fired on 34, and you already called 11 of those benign" is the sentence that stops a bad
rule being enabled. The figure is withheld below five reviews, because a rule with two
reviews is unmeasured rather than bad.

Findings appear under **Found later** in the console, with the same three-outcome
discipline as everything else: the page says whether anything is sweeping and how many
links are still being watched, because an empty list otherwise means either "nothing
turned up" or "nothing is looking".

### Why this is affordable

Because the enrichment answers are frozen beside each message. Re-running a rule set over
ninety days is a columnar scan and no network at all — no models, no WHOIS, no browsers.
A 392-message backtest of a rule reading `body.links` finishes in about a third of a
second.

It is also the only *correct* way to do it. Re-fetching would answer a question about
March with October's facts: the link is dead by then, and the domain registered the week
it was used is two years old by the time anyone looks. A question a message was never
asked comes back unavailable rather than null, so the expression reports indeterminate and
the run counts it as undecided — never as a clean no-match. Both the hunt and the backtest
report that count separately and name the capabilities that went unanswered.

## Campaigns

One attack arriving thirty times is thirty triage decisions, and the twenty-ninth is no
faster than the first. Messages are therefore fingerprinted at ingest and grouped by
near-duplicate detection, so the queue collapses into the attacks it actually was.

The fingerprint is a 64-bit SimHash over structure: shingles of the subject with digits
removed (an invoice number is the field a campaign personalises), the sender's display
name, the domains the links reach, and attachment content hashes. Two messages within
three bits of each other are the same campaign; three messages are the smallest group
worth calling one.

**Who sent it is deliberately not in the fingerprint.** The first version weighted the
sender's root domain. Run against four messages that were identical but for the sending
domain, it produced four groups — and rotating the sending domain is the single most
common thing a campaign does. A feature an attacker changes for free must not be able to
split the group. The senders are counted on the group instead, where "nine messages, four
senders, one link host" is the sentence that makes it reviewable.

### Why a hash and not a model

The obvious build is sentence embeddings: encode every message, index the vectors, cluster
by cosine distance. It needs a model loaded in the inference service, a vector index beside
the corpus, a similarity threshold nobody can justify, and a GPU to be quick — and it
answers a question about wording, when what identifies a campaign is mostly structure.

SimHash is deterministic, costs microseconds, needs nothing running, and groups the case
that matters. What it does not do is find two campaigns that say the same thing in
different words. A model would. That is a real limit and the trade is deliberate: this is
a system whose value is that it works on a laptop with no GPU.
