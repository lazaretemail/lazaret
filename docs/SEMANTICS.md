# MQL semantics register

<!-- SPDX-License-Identifier: AGPL-3.0-only -->

Three kinds of entry live here.

**Specified** — behaviour Sublime documents. We cite the sentence. If we disagree with the
docs, we are wrong.

**Specified by observation** — behaviour no page defines, settled by running the
expression on Sublime's own engine. Dated, because an engine can change and an undated
assertion hides that.

**Inferred** — behaviour no published page defines and no experiment has settled, where we
had to choose. Each one is a live compatibility risk.

All three have a corresponding test. Changing a row here means changing a test, which makes
the blast radius visible.

## How to settle an inferred entry

`analyzer.sublime.security` is Sublime's free EML Analyzer API and needs no credentials.
Its `/v0/messages/analyze` endpoint takes `queries`, which return a **value** rather than a
verdict — and that is the whole trick, because it makes `null` observable where a rule
verdict would flatten it to no-match.

`mql/differential_test.go` holds the harness:

```sh
LAZARET_DIFFERENTIAL=1 go test ./mql/ -run Differential -v
```

Add a probe there rather than running a one-off, so the answer keeps being checked. Then
move the row to **Specified by observation** and record the date.

Two practical notes, learned doing this:

- MQL has no null literal that type-checks as a boolean. `strings.contains(x, "s")` over a
  null `x` is the lever — it is a boolean-typed null, and every three-valued probe is built
  on it.
- Keep probes dependent on exactly one absent scalar (`headers.in_reply_to`). Anything that
  leans on richer parsing risks reading a difference in *EML parsing* as a difference in
  *evaluation semantics*.

---

## Specified: null propagation

| Expression | Result | Source |
|---|---|---|
| `length(null)` on a string | `null` | functions — "If the input string is `null`, the function returns `null`." |
| `length(null)` on an array | `0` — but see below | functions — "If the input array is `null`, the function returns `0`." The docs mean an *absent* array, which the MDM represents as `[]`. A genuinely null array, as an enrichment result is, gives `null`; see "A null array is not an empty array". |
| `length(null)` on a map | `0` | functions — "If the input map is `null`, the function returns `0`." |
| `length(null)` on json | `null` | functions — "If the input is `null`, the function returns `null`." |
| `coalesce(null, …)` all null | `null` | functions — "If all arguments are `null` then `null` is returned." |
| `all([], expr)` | `true` | functions — "If the array is empty, then `all` is vacuously `true`." |
| `ratio([], expr)` | `null` | functions — "If the array is empty, `ratio` returns `null`." |
| `ratio([1,2,null,null], . > 0)` | `0.5` | functions — nulls count toward the denominator |
| `s[a:b]` with any null operand | `null` | syntax — "If the string, start position, or end position is `null`, the slice returns `null`." |
| `arr[-1]`, `arr[oob]` | `null` | composite types — "negative indexes will always return `null`" |
| `arr[100:200]` out of range | `[]` | composite types — slice bounds clamp |
| `regex.match(null, …)` | `null` | regex — "If `input` is `null`, then `match` and `imatch` will return null." |
| unmatched capture group | `""` | regex — "individual captures are never `null` but `\"\"`" |
| `strings.contains(null, …)` | `null` | strings — null source, or all substrings null |
| `strings.parse_domain` / `parse_email` / `parse_json` on unparseable input | `null` | strings |
| `strings.scan_base64` finding nothing | `[]` | strings — empty array, *not* null |
| JSON compared across mismatched types | `null` | composite types — "mismatching types will result in a `null` result" |

## Specified: evaluation

| Rule | Detail | Source |
|---|---|---|
| Precedence, high to low | `()` · `* / %` · `+ -` · comparisons incl. `in` · `of` · `not` · `and` · `or` | syntax |
| Numeric promotion | mixed int/float promotes to float; `3 == 3.14` is therefore false | syntax |
| Integer division | `5 / 2` is `2`; `5 / 2.0` is `2.5` | syntax |
| String comparison | case-sensitive by default; `=~` and `!~` are the only case-insensitive operators; ordering comparisons are always case-sensitive | syntax |
| Range chaining | only `<` and `<=` chain | syntax |
| `X of (...)` | true when at least X clauses are true; X between 1 and the clause count | syntax |
| `x in array` | sugar for `any(array, . == x)` | syntax |
| Glob | `*` any run of characters, `?` exactly one; matches the **entire** string | strings |
| No truthiness | JSON booleans need `== true`; `not .json[k]` is a syntax error | composite types |

---

## Specified by observation

Settled on **2026-09-18** by running the equivalent expression on Sublime's own engine at
`analyzer.sublime.security`, which needs no credentials. Re-runnable:

```sh
LAZARET_DIFFERENTIAL=1 go test ./mql/ -run Differential -v
```

Every row below is also a case in `TestNullSemanticsConfirmedAgainstSublime`. A date, not
an assertion: Sublime may change, and `mql/differential_test.go` is what would notice.

| Expression | Result | Note |
|---|---|---|
| `null and false` | `false` | Kleene three-valued logic, confirmed in full |
| `null and true` | `null` | |
| `null or true` | `true` | |
| `null or false` | `null` | |
| `not null` | `null` | |
| `null and null`, `null or null` | `null` | |
| `x == "s"`, `x != "s"`, `x < "s"` with `x` null | `null` | never `false` |
| `x in (...)` with `x` null | `null` | membership inherits equality |
| `x not in (...)` with `x` null | `null` | negation does **not** turn it into `true` |
| `1 of (null, true)` | `true` | trues alone reach the threshold |
| `1 of (null, false)` | `null` | the null could have reached it |
| `2 of (null, false, false)` | `null` | likewise |
| `1 of (false, false)` | `false` | nothing undecided, threshold unmet |
| `not x is null` | `false` | `is null` binds as a comparison, tighter than `not` |
| `regex.contains/count/extract(null, …)` | `null` | matches the documented `regex.match` |
| `strings.levenshtein(null, …)` | `null` | |
| `strings.like` with `\*` | **a lex error** | "Invalid escape sequence" — there is no escape, and the star is not silently literal |
| a rule whose source evaluates to null | no match | upstream reports `matched: false` with no reason; `indeterminate` is our addition |

The `of` rule, stated once: **if the true clauses alone reach the threshold the answer is
true; otherwise any undecided clause makes it null; otherwise false.** This is the one
entry the differential run contradicted. The engine previously treated `of` as a plain
count in which a null simply failed to contribute, answering `false` for the middle three
rows above. Corrected in `mql/eval.go`.

### Also found, not previously recorded

| Behaviour | Detail |
|---|---|
| `is null` is scalar-only | `body.links is null` is a **type error** upstream — "Expected a scalar, got [Link]". Arrays are never null in the MDM; an absent one is `[]`. |
| `any of` / `all of` / `none of` are not MQL | Sublime's parser rejects all three: "Unknown attribute `any`". See the parsing section below. |

### A null array is not an empty array

The sharpest distinction in the language, and the one that produced this engine's only
false positive against Sublime's own verdicts. MDM arrays are never null — an absent one
is `[]` — but **enrichment results are**: `ml.nlu_classifier(x).topics` with no ML service
is a null array, and so is `regex.extract(null, …)`, which is how these were probed
without needing a service.

Which builtins propagate the null and which absorb it is irregular, so every one was
measured rather than derived.

| Over a **null** array | Result | | Over an **empty** array |
|---|---|---|---|
| `length` | `null` | | `0` |
| `any` | `null` | | `false` |
| `all` | `true` | | `true` |
| `ratio` | `null` | | `null` |
| `map` | `null` | | `[]` |
| `filter` | `[]` | | `[]` |
| `distinct`, `flatten` | `[]` | | `[]` |
| `sum` | `0` | | `0` |
| `arr[0]` | `null` | | `null` |

`any` is the one that matters. The corpus is full of `not any(ml.…(…), …)` written to
exclude newsletters and benign mail, so folding null to empty makes `any` false, `not any`
true, and a brand-impersonation rule fires **because** the classifier was unavailable.
That is this project's one invariant inverted — not degraded to false, but promoted to
true — and it is a false positive rather than a lost detection. Fixed in
`mql/builtins.go`; pinned by `TestNullArrayIsNotEmptyArray`.

### An unresolvable `$list` is a missing capability

Not a Sublime observation — a consequence of the same invariant, found by the same run.

The `lists` package already answers "I do not know" for a list nobody configured rather
than "no". The evaluator used to discard that and return a bare null, which reads as a
clean no-match at the top level because nothing was recorded as missing. Since
`$high_trust_sender_root_domains` gates 683 corpus rules and `$org_domains` another 202,
that silently switched off a large part of the corpus while reporting full confidence.

Unresolvable lists are now recorded through `enrich.ListCapability`, so the verdict is
`indeterminate` and the report names the list as written — `missing: $recipient_emails`.

## Inferred: still unsettled

What the differential run could not reach, because the construct does not exist upstream.

| Question | Our choice | Reasoning | Why not settled |
|---|---|---|---|
| a null clause in `none of (...)` | `null`, consistent with the confirmed `of` rule | `none of` is ours, so its edges are ours to define | the form is a parse error upstream |

## Known divergence

| Behaviour | Ours | Sublime |
|---|---|---|
| slicing a **null array**, `a[0:1]` | `null` | `[]` |

A null carries no type at evaluation time, and the documented rule for slicing a null
*string* is `null`. Telling them apart needs the checker's static type threaded onto the
AST — real work for no corpus benefit, since the only genuine MQL slice in the corpus is
`[0:39]` over a string, where our answer is already the documented one. Pinned by
`TestDifferentialKnownSliceDivergence`, which fails if upstream ever agrees with us.

## Inferred: building the model from a message

Nothing published says how to turn a raw message into the Message Data Model. The schema
fixes the *shape* of the output and the corpus shows what rules expect to find in it, but
every decision below is ours.

| Question | Our choice | Reasoning |
|---|---|---|
| splitting current from quoted threads | anchored attribution patterns per client (`On … wrote:`, Outlook header blocks, `-----Original Message-----`, Gmail/Outlook wrappers), else a run of two or more `>`-quoted lines | The single largest risk in the parser — `body.current_thread.text` has 2,499 uses. Split too eagerly and the sender's own words vanish; too reluctantly and every reply inherits the words of the conversation it quotes. Kept in one file, `eml/thread.go`, so it can be replaced wholesale. |
| a single `>` line | not a split | People quote one line inline and keep writing around it. Treating that as the end of the message truncates what the sender said, which is what most rules are looking for. |
| prose containing "wrote:" | not a split | Patterns are anchored to the start of a line, so "As I wrote: …" does not truncate a message. |
| `previous_threads` ordering | index 0 is the most recent quoted message | Matches the corpus idiom `body.previous_threads[length(...) - 1]` for "the oldest message in the chain". |
| which hop's verdict becomes `auth_summary` | the most recent hop that reported one | Hop 0 is our own MTA. An attacker can inject a favourable `Authentication-Results` further down the path, so believing the earliest hop means believing the attacker. |
| `dmarc=bestguesspass` | not a pass | It is what an MTA reports when the domain publishes no DMARC record. Treating it as a pass lets any domain without a policy inherit the trust of one that has it. |
| `mismatched` on a link whose text is prose | null, not false | There is nothing to compare, so no finding was made. Reporting `false` would claim a check that did not happen. |
| `mismatched` comparison depth | registrable domain | Comparing full URLs would flag every tracking parameter and shortened form as deceptive. |
| `display_text` vs `inner_text` | `display_text` omits content hidden by inline CSS, `inner_text` keeps it | Attackers hide keyword stuffing to poison classifiers, so rules need to see both and compare. |
| attachment `file_type` | sniffed from the leading bytes, refined by extension for container formats | The declared Content-Type is whatever the sender chose. Keeping the declared type, the extension and the sniffed type separate is what lets rules notice they disagree. |
| message direction with no org configured | null, and recorded in `_errors` | `type.inbound` gates most of the corpus. Guessing would silently change verdicts; saying nothing is the safer failure. |
| quoted `Sent:` dates | best-effort against a list of display formats | Outlook writes a localised human-readable date, not a timestamp. Non-English month names will not parse, and the result carries no meaningful timezone. |
| an unreadable header block | treat the whole input as a bare body | A message we refuse to parse is a message no rule inspects. Truncated spool files and pasted fragments still carry content worth matching. |

## Inferred: the type system

The checker is deliberately permissive, because the two mistakes it can make do not cost
the same. Rejecting a rule Sublime accepts breaks a detection someone depends on; accepting
one we might have rejected only means the mistake surfaces at evaluation as null. So
anything genuinely ambiguous is allowed through.

| Question | Our choice | Reasoning |
|---|---|---|
| `null` in any position | assignable to and from everything | Null propagation would otherwise need mentioning in every signature. |
| a JSON value anywhere | compatible with everything | JSON is dynamic by definition, and the docs say a mismatched comparison yields null rather than an error. |
| an under-described enrichment result | `any`, permissive both ways | These types are reconstructed. Being strict about a shape we inferred would reject rules over our own uncertainty. |
| raw file bytes where text is wanted | allowed | Rules pass attachment content straight to the string functions. |
| `int` where `float` is wanted | allowed | Documented promotion. |
| reading a field off an array | an error | MQL has no implicit iteration, and accepting it would hide a missing `any()`. |
| `+` on strings | an error | Concatenation is `strings.concat`. Silently allowing `+` would produce something no author intended. |
| a threshold above its clause count | an error | The rule can never fire, and nothing else would ever tell anyone. |
| element type of a named `$list` | unknown, not string | `$org_vips` holds people. See COMPATIBILITY.md. |

## Inferred: parsing

| Question | Our choice | Reasoning |
|---|---|---|
| `...` and deeper scope climbing | each additional `.` climbs one lexical scope | Documented for `..`; the corpus uses `...` for the grandparent, so the rule generalises. |
| `any of (...)` / `all of (...)` / `none of (...)` | thresholds of 1, N, and 0 respectively — **an extension, not compatibility** | Believed to be undocumented word forms used in the corpus. They are not: all 25 occurrences of "any of", "all of" and "none of" in the corpus are inside `//` comments, and Sublime's parser rejects the syntax outright ("Unknown attribute `any`"). We accept a superset of MQL here. A rule written with these forms runs on this engine and fails on Sublime, so `docs/COMPATIBILITY.md` records it and `TestDifferentialRejectsOurExtensions` pins it. |
| escape handling inside `'raw strings'` | no escapes at all; only `''` is special | Documented — and load-bearing: the corpus contains `'\'`, a raw string holding one backslash. Treating `\'` as an escape breaks the parse. |
| keyword arguments | positional arguments first, then `name=value`, with per-function defaults | Undocumented but used throughout the corpus. |
