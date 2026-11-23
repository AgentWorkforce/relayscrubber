# Agent Relay Desktop over-redaction: alpha.10 diagnosis

These are audit notes for the 0.5.0-alpha.11 implementation owner. `src/` is
unchanged on this branch. Every input is invented; no session bodies were read.

- Fixture: `eval/desktop_false_positive_cases.json`
- Native tests: `tests/desktop_false_positives.rs`
- WASM mirror: `js/test/desktop-false-positives.test.mjs`

## 1. Type positions after `...Key:` members

On alpha.10, 17 of the 25 precision cases are redacted, and all 16 recall
controls redact. Every native API gives the same output (checked, text, long,
report, JSON, JSON text and NDJSON records). The hosted alpha.10 WASM
(`relayscrubber_bg.wasm` sha256 `491fc18e…4528b`, verified against the
release's SHA256SUMS) gives the same bytes as native for every case. All
outputs are idempotent.

`code_value` (`src/engine.rs`, around line 837) keeps a type-looking value
after a bare colon only when two conditions hold:

1. A recognized context surrounds the key. That is `type_context` (`fn name(`,
   `struct|interface Name {`, `type Name = {`) or a `let`/`const`/`var`
   declaration.
2. The value matches the `simple` list (`string boolean number bool &str`),
   the `generic` grammar (`[A-Za-z0-9_.:<>()[], &']`, balanced `<>`, and it
   must end on `>`), or a code expression.

The result does not depend on the key name. `apiKey`, `accessKey` and
`sessionKey` were kept only because they sit inside `interface X {` or
`type A = {` and have values `string`, `boolean` or `Record<…>`. The same
`apiKey: string` inside `context: {` is redacted too (`anon-apikey-string`).

| Shape | Why it is redacted |
|---|---|
| `context: { poolKey: string; … }` (the Desktop witness) | An anonymous object type has no recognized context |
| `function f(opts: { poolKey: string })` | `type_context` stops at `{`, because its fn arm forbids `{` |
| `privateKey: string \| null` (also in an interface) | `\|` is in neither grammar |
| `poolKey: string[]`, `readonly string[]` | The generic grammar must end on `>`, and `readonly ` is not allowed |
| `unknown`, `PoolKey` with no context | No context |

Two cosmetic span defects show up along the way. Neither leaks anything:

- `poolKey: string[]` gives `[REDACTED]]`, leaving a stray `]`.
- A union value swallows the `;` that ends its member: `privateKey: [REDACTED]\n`.

Suggested patch shape (recall is held by the fixture's controls):

- Treat `{` as a type context when it is directly preceded by a member or
  parameter annotation colon (`name: {` or `name?: {`). Also accept the
  existing anonymous-type form when its members are separated by `;`.
- Within a type context, accept:
  - primitive keywords: `string number boolean bigint symbol unknown any never void object null undefined`
  - PascalCase type names
  - `T[]`, `readonly T[]` and balanced generics
  - `|` or `&` unions of the above
- Keep failing closed on quoted literals, on bare lowercase non-keywords
  (`string | hunter2`), on glued keyword prefixes (`string1234…`) and on a
  `= <literal>` initializer.

## 2. Whole bodies replaced by one `[REDACTED]`

There are three mechanisms that can replace a whole input with the marker.

**A. Fixed-point pass-budget exhaustion (`engine::analyze`, around line 5336).
This is the likely Desktop cause.** After the first pass, `analyze` re-scans
its own output up to 4 more times. If the text is still changing after that,
it returns `0..len`. A quoted value whose closing quote is glued to word
characters (`' let's`) is redacted together with that quote. On re-scan, the
output `pwd: '[REDACTED] I'll …` has an unterminated quote again, so the next
apostrophe closes it. Each pass consumes one apostrophe word:

```
pwd: ' let's I'll you're won't here
pass: pwd: '[REDACTED] I'll you're won't here -> pwd: '[REDACTED] you're won't here
pass: …                                       -> pwd: '[REDACTED] won't here
pass: …                                       -> pwd: '[REDACTED] here
pass: …                                       -> pwd: '[REDACTED]
budget exhausted                              => [REDACTED]  (whole input)
```

With one apostrophe fewer, the text converges to `pwd: '[REDACTED]`, which
still swallows the rest of the prose. Ordinary assistant prose does this
easily:

```
Summary: the deploy worked. I didn't touch the PASSWORD=' line because it's
generated, and that's fine; we'll revisit it once you're back and I've
rotated the key.                                    -> [REDACTED]
```

In a synthetic fuzz of prose (apostrophes plus credential cues plus quotes),
about 6% of bodies (4,698 of 80,000) became the whole marker. Every one of
them was budget exhaustion.

Suggested patch shapes:

- (a) On exhaustion, fail closed from the start of the earliest span that
  changed in the last pass to the end of the input, instead of from 0. The
  prefix before that span was stable on every pass.
- (b) Give a quoted value its final extent in a single pass, so that
  re-scanning cannot reopen it.
- (c) Optionally, treat `'` between two letters as an apostrophe rather than a
  closing quote, while keeping `'abc'def'`-style recall.

**B. Over-16-MiB compatibility.** `scrub_text` and `scrub_long` return exactly
`[REDACTED]`, while `scrub_text_checked` refuses with `text_too_large` and the
JSON text APIs refuse with `record_too_large`. This is covered by an active
test. It is implausible for single prose replies.

**C. JSON sensitive keys (`json::visit`).** The whole string value under a
sensitive key is replaced, whatever its content. With a prose value this
happens for `auth`, `authorization`, `credential(s)`, `passphrase`, `secret`,
`password`, `pwd`, `pin`, `sessionKey`, `session_id`, `cacheKey` and
`primaryKey`. Transcript prose fields (`text`, `content`, `message`,
`thinking`) are not affected. relay-app should confirm that its event schema
never puts prose under one of those keys.

## 3. Python `key=lambda`

This is clean on alpha.10. It is pinned by `python-lambda-key` and
`python-lambda-key-reverse`, with a nearby `api_key = "…"` recall control.

## Running the evidence

The `#[ignore]`d Rust tests and the alpha.10-skipped JS tests state the
desired alpha.11 behaviour. Remove the ignore, and bump the crate version for
JS, together with the fix. `alpha10_whole_body_witnesses_reproduce` documents
today's behaviour and is meant to fail once the fallback is fixed.
