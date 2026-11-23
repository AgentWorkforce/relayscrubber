# Changelog

## 0.5.0-alpha.11

Security fix: 0.5.0-alpha.10 leaked password disclosures with a descriptor
between the noun and its cue. `the password for the box is
Tr0ub4dor-Example-91` and `the pw for the box is ab` came out unchanged,
while `the password is Tr0ub4dor-Example-91` redacted. All eight password
nouns now disclose through a same-clause relational descriptor that starts
with a preposition, optionally after a participle (`for the box`, `on
db-01.example`, `used by the CI runner`, `assigned to ops`, `belonging to
root`), before `is`, `was`, `is now`, `set to`, `is set to`, `was set to`, a
colon or `=`: `the password for the box is [REDACTED]`, `the password for the
box is '[REDACTED]'`. The descriptor bound is `DESCRIPTOR_TOKENS`, 16 words.
Within it the descriptor ends at a sentence end, a blank line, code
operators and words that start a new construction (`but`, `because`, `whose`,
`will` and the like). Past the bound the search fails closed: brackets,
quotes and those words no longer end it, so a longer descriptor still
redacts, and only a sentence end, a blank line or code stops it. Documentary
values keep the alpha.10 policy with no new allowlist (`the password for the
box is required` is unchanged, as `the password is required` is), and every
input outside this class scrubs exactly as in alpha.10.

The same release widens the class to forms the first alpha.11 candidate
still left unchanged:

- A cue glued into the descriptor: `pw for box=x`, `Password for root:x` and
  `the password for the box=x` redact the value. A later cue wins (`the
  password for db:5432 is x` redacts `x` only); URLs, `::`, `==` and the
  comparison operators are not glued cues.
- Coordination and parentheticals: `and`, `or`, `&`, `+`, a spaced hyphen,
  en and em dashes, commas and relative clauses no longer end a descriptor,
  so `the password for staging and prod is x`, `the password for the box,
  which is new, is x`, `the password for the box that I set is x` and `the
  password, for the box, is x` redact the final value only.
- New cues for all eight nouns, with or without a descriptor: `is still`,
  `is now set to`, `has been set to`, `has now been set to`, `has still
  been set to`, `has changed to`, `had changed to`, `was reset to`,
  `changed to`, plural nouns with `are`, `were` and `have changed to` (`the
  passwords are x`), and contact clauses (`the password Bob uses is x`, `the
  password that I use is x`). Punctuation right after a contact clause is
  read as after a relative clause: `the password Bob uses, which is new, is
  x`, `the password Bob uses: x` and `the password Bob uses=x` redact the
  final value only.

`is not`, `isn't`, `will be` and `should be`, documentary values and code
stay unchanged. Accepted over-redactions: with no later cue the glued value
or the relative clause's value redacts (`the password for db:5432`, `the
password with user=admin`, `the password for the box, which is new`), and a
second clause joined by `and` or a comma is read as the descriptor (`the
password for the box expired and the user is bob` redacts `bob`). The colon
over-redactions stay (`Reset the password for your account: click the link`
redacts `click the link`).

Precision fix: a credential-named member of an inline TypeScript object type
keeps its type. `context: { poolKey: string; targetSize: number }` came out
as `context: { poolKey: [REDACTED]; targetSize: number }`, while the same
member in an `interface` or `type X = {` body was kept. An unquoted `name: {`
or `name?: {` opener is now source context for a closed type vocabulary
(primitives, their arrays, `Array`/`ReadonlyArray`/`Promise`/`Set`/`Map`/
`Record` over them and `|` unions), terminated and inside a closed body.
Quoted and opaque values, references and context-free forms (`{ poolKey:
string }`, `poolKey: string`, `pw: string`) still redact.

## 0.5.0-alpha.10

Redact natural-language password disclosures such as `my password is x`, `the
passcode was '#'` and `my pwd: !`, with no minimum value length, for password,
passcode, passphrase, passwd, pwd, pw, `pass code` and `pass phrase` after
`is`, `was`, `is now`, `set to`, `is set to`, a colon, or `=` after a
determiner (`my pw = x`). Quoted values keep their
quotes and an unmatched quote is redacted through its line. Documentary
sentences (`the password is required`), references (`$PASSWORD`,
`{{password}}`), masks, placeholders and type annotations in source context (`struct X {
pw: Vec<u8> }`, `fn f(pw: String)`, `const pw: string`) are unchanged. `passcode` is now a sensitive assignment name.

Security fixes to the alpha.10 candidate, before any release:

- Colon and equals cues: `:` and `=` now disclose for all eight nouns with or
  without a determiner (`pw: Q`, `pass code: 4711`, `pass phrase = x`), and
  redact the whole value, conjunctions and documentary first words included
  (`password = velvet river lantern` no longer keeps `river lantern`). Type
  annotations in source context, references, a lone `None`
  and the operators `==`, `=>`, `::`, `!=` are unchanged. The value ends at
  an enclosing quote, at the close matching by type the innermost bracket
  left open before the noun in the noun's own string layer, or before the
  next `Key=` when the noun follows a `key=value` item and the same `;` or
  `&` (`Server=db;Password=x;Encrypt=true`). Any other close bracket, `;` or
  `&` is part of the value, so `pw: x]yq zq`, `(note pw: x]yq zq`,
  `{"note":"pw: x}yq zq"}`, `pw: abc&def=ghi`, `R&D pw: abc&def=ghi` and
  `note; my pw: abc;host=y` no longer keep any of the value.
- Type-looking values: after a bare colon a type annotation is kept only
  with source context, a fn signature, a struct, interface or type body
  around the key, or a `let`/`const`/`var` declaration naming it (`struct X
  { pw: Vec<u8> }`, `fn f(pw: String)`, `const pw: string`). Without it a
  type-looking value is credential data, so `pw: abcq<defq>`, `passcode:
  hunter2<secret>`, `pw: Vec<u8>`, `password: Option<String>,` and `pw:
  string` now redact, as they already did after `=` and `is`. This is an
  accepted precision tradeoff: the engine looks back at most 512 bytes in
  the same string, so a field line alone (`    pw: Vec<u8>,`), in its own
  NDJSON record, or more than 512 bytes below its `struct X {` opener
  redacts. A comma or semicolon inside brackets the value opened no longer
  ends it, so `pw: Map<String, u8>,` keeps no `u8>`.
- Code-looking values after a bare colon: for every credential key, a `match`
  expression, call, member chain, arrow function, `function() {…}` or
  `??`/`||` fallback is kept only with source context: a type body or fn
  signature, an object literal assigned or passed to `json!`, or a labelled
  argument of an unclosed call whose `(` directly follows a callee
  (`login(password: orchid.river)`). A source-shaped value no longer counts
  as context, so `password: match option {…};`, `token: async () =>
  getToken()`, `password: options.value ?? fallback`, `auth: config.auth ||
  defaultAuth`, `auth: function() { return buildAuth(); }`, `{ pw:
  orchid.river }` and `(password: orchid.river)` now redact. Precision
  tradeoffs: struct literals (`let x = Foo { pw: orchid.river }`), class
  members (`private token: vscode.CancellationToken;`) and calls with a space
  before `(` now redact. Prose shaped like a call (`Note(see below, password:
  orchid.river`) is still kept. The evaluation fixtures that pinned the old
  output moved to the positive sets, and each one has a sibling with source
  context that keeps its output.
- Borrows: after a word prefix (`admin password: &abcq`, `note: password:
  &Secret1`), a value starting with `&` is no longer kept by the assignment
  engine's reference exemption; it redacts whole, as the bare form did. After a bare colon it is
  kept only as a type in a type body or fn signature (`fn f(pwd: &str)`,
  `fn cancel(token: &CancellationToken) {}`).
- Match arms: an arrow's `>` no longer closes a bracket, so `pw: match a { b
  => c, d => e }` no longer keeps `d => e }`.
- Escaped quotes: a `"`, `'` or `` ` `` preceded by an odd number of
  backslashes at the opener's escape level no longer ends a quoted value
  (`"abc\"def"`), including inside JSON-escaped strings; the 1024-byte bound
  and the unmatched-quote rule are unchanged.
- Contiguous quoted segments: a quoted segment that starts right at the
  value's close quote is part of the value, with the same or another quote,
  so `my password is "abc""defq"` no longer keeps `"defq"`. Unquoted text
  touching the close quote is part of the value too, up to the next
  whitespace, so `"abc"defq`, `""abcq` and `password=""abcq` no longer keep
  `defq` or `abcq`; trailing punctuation alone (`"abc".`) and a quoted string
  after whitespace still end the value. A touching segment may open with any
  quote mark or escape level, so `pw: "abc"\"defq\"`, `my password is
  "abc"\'defq\'` and `{"note":"my password is \"abc\"'defq'"}` no longer keep
  `defq`; only the close of a quote or bracket the line opened before the
  noun ends the run. After a quoted value, a `,`, `;` or `&` before a
  key-like field, or the close of a tag opened before the noun, ends it, so
  `password="abc",user="bob"` and `<a password="abc">text</a>` keep the next
  field.
- Enclosing closes: a redaction no longer removes the closing quote of the
  JSON string that holds the disclosure; an unterminated value inside it
  redacts up to that quote, so the line stays valid JSON with the same keys
  (`{"note":"password:\"abc\"defq","user":"bob"}` kept `password:\"` and
  dropped `","user":"bob"}`). When a value ends at the close of a quote
  opened before the noun and a quote, letter, digit, `_` or `$` touches
  that close, the touching run is part of the value up to the next
  whitespace or the close of a further enclosing layer, and the close is
  redacted with it: `he said 'pw: abc'defq`, `x "pw: abc""defq"` and
  `echo "pw: abc"$X` no longer keep `defq` or `$X`, and
  `{"note":"he said \"pw: abc\"defq","user":"bob"}` keeps the `user` field.
  Punctuation, whitespace or a field after that close ends the value as
  before (`He said "pw: abc".`, `1,"pw: abc",3`).
- Separators: every Rust/WHATWG whitespace character (including U+1680,
  U+205F and U+0085) and one line break may separate the words, so `my
  pass\ncode is x` redacts; HTML character references (`&#32;`, `&#x20;`,
  `&nbsp;` and the named spaces), percent, `%u` and `\u`/`\x` spellings of
  whitespace count as separators too.
- Prefixed colon and equals cues: words before the noun no longer redact less
  than the bare cue. `The new password: x`, `Please use pw = x`, `- note: my
  pass code: x` and `We discussed password: x` were left whole and now redact
  the value; after a determiner the whole value is redacted, so `my password:
  correct horse battery` no longer keeps `horse battery` and `the password: see
  vault` no longer keeps `vault`. With words or a bullet before the noun a
  close bracket is part of the value unless the line opened it before the
  noun (`The new password: ab)cd`, `* password: ab)cd`), and so is a `;` or
  `&` unless the line was already a `;`/`&` list before the noun (`my pw:
  abc&def=ghi`). `# ` and `// ` comment lines are unchanged.
- References and placeholders as parts of a value: the exemption for
  references, placeholders, masks and `[REDACTED]` now applies only when the
  whole value, contiguous quoted segments and glued text together, is one of
  them or a run made only of them (`"$A""$B"`, `${A}${B}`). A value with any
  literal contiguous part is redacted whole, so `pw: "abc""$defq"`,
  `my password is "abc""${defq}"`, `password="$defq""abc"`,
  `pw: ${defq}abc`, `x "pw: abc""<defq>"`, `x "pw: abc"%DEFQ%` and
  `{"note":"pw: \"abc\"\"$defq\""}` no longer keep either part; JSON lines keep
  their keys. Pure references (`pw: "$defq"`, `password=${defq}`) and a
  reference after whitespace (`pw: "abc" "$defq"`) are unchanged.

## 0.5.0-alpha.9

Preserve an exact `project_key` whose value is a normalized repository identity
(`github.com/owner/repo`), so session capture can record which project a session
belongs to. Other `project_key` values, prefixed names and composite values stay
sensitive; credentials beside or inside a kept identity still redact. Only the
exact spellings qualify, segments with long letter-and-digit pieces stay
sensitive, and an unquoted identity followed by another assignment on its line
is redacted with it.

## 0.5.0-alpha.5 (unreleased)

Preserve complete query references, awaited calls and Rust reference type aliases while retaining literal-secret redaction across URL decoding layers. Avoid unnecessary normalization lookups outside newlines.

0.5.0-alpha.4: releases the security-reviewed engine from PR #15 head 77b89c60 (closes unmatched-quote recovery, HTML-entity and semicolonless separators, entity-encoded URL punctuation, scheme-less attribute URLs, percent-encoded reserved characters in values and userinfo, fully encoded userinfo authorities, nested multi-layer values). Precision: non-zero false positives remain.
