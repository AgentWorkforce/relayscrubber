# Desktop over-redaction: what 0.5.0-alpha.11 changes

Three shapes of desktop session text were over-redacted by 0.5.0-alpha.10.
This note records each shape, the rule that now applies and where it is
tested. Every input in the fixture and tests is invented.

- Fixture: `eval/desktop_false_positive_cases.json` (also exported to the
  WASM vectors by `examples/wasm_vectors.rs`)
- Native tests: `tests/desktop_false_positives.rs`,
  `tests/type_member_alpha11.rs`, `tests/pass_budget_alpha11.rs`,
  `tests/session_events_alpha11.rs`
- WASM mirror: `js/test/desktop-false-positives.test.mjs`

Every native API gives the same output for these inputs (checked, text, long,
report, JSON, JSON text and NDJSON records), the WASM build gives the same
bytes, and every output is idempotent.

## 1. Type positions after credential-named members

`code_value` keeps a type-looking value after a bare colon only in a
recognized source context. In alpha.10 that was a function signature, a
`struct`, `interface` or `type Name = {` body, or a `let`/`const`/`var`
declaration, and the value had to be a simple primitive, a generic ending on
`>` or a code expression. An anonymous object type, a union with `null`, and
`T[]` or `readonly T[]` failed that test, so `context: { poolKey: string }`
became `context: { poolKey: [REDACTED] }`.

Now a member of an object type also keeps a closed type vocabulary when the
`{` is opened by an annotation colon (`name: {`, `name?: {`), an `interface`,
`class` or `type Name = {` body, a function return type (`): {`) or a type
argument of `Array`, `ReadonlyArray`, `Promise`, `Set`, `Map` or `Record`.
The vocabulary is `string`, `number`, `boolean`, `bigint`, `unknown`, `null`
and `undefined`, their arrays and `readonly` arrays, those generics over them,
and `|` unions of these. The value must be complete (ended by `;`, `,`, `}` or
a line break) and a `}` must close the body within the 512-byte view.

The decision depends on the context, not on a `Key` suffix:

- Kept: `context: { poolKey: string; targetSize: number }`,
  `interface X { privateKey: string | null }`,
  `function f(): { poolKey: readonly string[] }`,
  `Promise<{ apiKey: string }>`, multi-line interface and type bodies.
- Still redacted: `{ poolKey: string }` and `poolKey: string` with no context,
  quoted literals, opaque values, PascalCase names in the new contexts,
  unions with a bare word (`string | hunter2`), and initializers
  (`apiKey: string = "..."`).
- Python annotations are unchanged. `key=lambda` arguments were already kept
  and stay pinned next to an `api_key = "..."` recall control.

## 2. Whole bodies replaced by one `[REDACTED]`

Three paths can turn a whole input into the marker. The first two are
deliberate; the third was the over-redaction.

**Over 16 MiB.** `scrub_text` and `scrub_long` return exactly `[REDACTED]`;
`scrub_text_checked` refuses with `text_too_large` and the JSON text APIs
refuse with `record_too_large`.

**A whole-input credential.** A recognizer whose extent is the whole input
gives one span.

**Pass-budget exhaustion.** After its first pass, the engine re-scans its
own output so that removing a malformed delimiter cannot expose new scope
changes. In alpha.10, an unmatched quote after a cue paired with the next
apostrophe (`pwd: ' let's`), the redacted output had an unmatched quote again,
and each re-scan consumed one more contraction. With enough contractions the
budget ran out and the whole input became the marker:

```
Summary: the deploy worked. I didn't touch the PASSWORD=' line because it's
generated, and that's fine; we'll revisit it once you're back and I've
rotated the key.
```

Two quote-pairing rules now settle such text in one pass:

- A `'` between two ASCII letters or digits is an apostrophe. It neither opens
  nor closes a quote. A quoted value that contains one (`password='ab'cd'`)
  still runs to its last quote.
- A quote on the same line that directly opens a value after `=`, `:` or `>`
  (`PASSWORD='x`) does not close an earlier quote. A quote opening a later
  line's assignment already did not.

The example above now gives `Summary: the deploy worked. I didn't touch the
PASSWORD='[REDACTED]`: the cue's unmatched quote still fails closed to the end
of the input, and the prose before it is kept.

If an input still changes after one pass and five re-scans, the bytes before
the earliest change of the last re-scan are kept, a redaction that touches
that point joins the tail, and one marker replaces the rest. That result is
used only if a further pass leaves it unchanged; otherwise the whole input is
the marker. At most seven analysis passes run on any input.

## 3. Session-shaped JSON

In JSON, the whole string under a sensitive key is replaced whatever its
content. Prose fields such as `text`, `content`, `message` and `thinking` are
not sensitive keys and are scrubbed as text. Two metadata values under
sensitive keys are now recognized as identifiers:

- `session_id`: `ses_` or `cse_` followed by 1 to 48 ASCII letters and digits,
  next to the existing UUID, lowercase/digit/dash, `exec-`, `call_` and
  `toolu_` forms.
- `project_key`: a bare `owner/repo` with no `.` in the owner and both segments
  passing the hosted form's segment rules, next to `host.tld/owner/repo` and
  group paths.

Any other value under those keys, every other sensitive key, and a credential
in the event's `text` still redact.
