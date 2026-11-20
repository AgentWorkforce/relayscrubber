# Canonical scrubber specification (candidate ruleset 10)

Status: design and implementation candidate; **not approved for adoption**. Ruleset
8 and the abandoned TypeScript candidate 9 are historical evidence, not oracles.
The security owner must approve an immutable commit before adoption. No version
number alone authorizes adoption or publishing.

## Threat model

Inputs are untrusted UTF-8 session text, code, shell commands, logs, HTTP headers,
JSON and NDJSON. An attacker may control quoting, escaping, token lengths,
nesting and truncation. The engine is deterministic and offline. It never checks
whether a token is live, performs network requests, logs inputs or returns
credential-bearing diagnostic messages. Native and WASM run the same Rust code.

The objective is to remove recognizable credential bytes before any persistence
or upload while preserving useful normal information. This is a recognizer,
not a proof that arbitrary text contains no secrets: an unlabelled human password,
arbitrary cipher, custom encoding, image or compressed archive is indistinguishable
from benign data. Consumers must not claim universal recall.

## Default policy: secrets

Redact these independently of entropy:

* Provider-prefixed secret tokens: OpenAI/Anthropic `sk-` families, GitHub classic
  and fine-grained tokens, GitLab, AWS access IDs, Stripe secret/restricted and
  webhook keys, Slack bot/user/app tokens and incoming webhooks, npm, PyPI,
  Google API/OAuth, SendGrid, DigitalOcean, Cloudflare user tokens, Vercel and
  Hugging Face. The implementation's versioned pattern table is the exact
  executable list; published format references are in `PROVIDERS.md`.
* JWT/JWS compact tokens with an `alg` JSON base64url header and three segments
  (including unsigned tokens), and JWE compact tokens with five segments;
  signatures are not verified. Private PEM/OpenSSH key blocks, including an
  unterminated block, are removed through their end or end of input.
* Values assigned to password, passwd, pwd, passphrase, passcode, secret,
  client_secret, api_key/apikey, access_key, secret_key, private_key,
  access_token, auth_token, refresh_token, id_token, session_token/session_id,
  credential(s), token, account_key and provider-prefixed equivalents.
  Connection-string and database URL fields are inspected without removing
  unauthenticated URLs. Underscore,
  hyphen and camel spellings are recognized. Separated key suffixes and credential suffixes such as
  dbPassword/githubToken/stripeSecret are sensitive. Bare `key` requires
  credential structure/context or a reviewed provider value shape. Exact public_key and
  idempotency_key spellings, token_count/token_budget and credential identifiers
  used without a value are preserved. A prefixed public-like name is sensitive.
* Assignments in code, env, YAML, JSON and CLI flags. `:` and `=` and their
  percent, percent-u, backslash-u and backslash-x spellings are recognized,
  including repeated percent-25 and backslash escape chains. Encoded delimiters
  are interpreted for recognition; surviving original bytes are not decoded.
* Authorization/Proxy-Authorization values; standalone Bearer credentials;
  Cookie and Set-Cookie values; labelled session IDs; passwords in URL userinfo
  and database/ADO connection strings; signed URL signature, SAS `sig`, and
  credential/security-token query parameters. Ordinary query `state`, `code`,
  `id` and `code_challenge` are preserved unless explicitly credentialled. Generic
  `key` alone is preserved, including in a query; reviewed provider shapes
  remain sensitive regardless of their label.

A quote opening a later line's assignment is not accepted as a credential closer;
that malformed extent fails closed through EOF. A fixed budget of at most five
scanner passes closes over lexical changes caused by redaction; failure to
stabilize returns exactly `[REDACTED]`. Reports map every removed range back to
original UTF-8 bytes.

A quoted credential includes whitespace and newlines through the matching
delimiter. If the quote is malformed, remove through the enclosing value's end
or end of input. There is no 4096-byte leak window. A public replay value containing
an embedded credential is not exempt: its enclosing extent applies to an
unquoted nested credential, including all trailing words. JSON public-property
context follows every descendant, at every supported depth. Redaction markers
are ordinary strings: a marker prefix never exempts a surviving tail. A second
scrub must be byte-identical to the first.

Unquoted ordinary assignments end at whitespace or a structural separator.
Source-shaped values do not establish source context for a bare credential
reassignment. Spaced ` = ` and a terminal semicolon cannot exempt it. References
may remain visible in an independently recognized declaration; literal siblings
still redact. Word prefixes cannot waive an equals assignment.
Unquoted YAML block scalars are sensitive through their indented body. Header
values end at the next physical line unless quoted; sensitive JSON properties
redact their entire value, including numbers, booleans, arrays and descendants.
Empty env/header values end at their physical line. Cross-line values require an
explicit quoted literal, quoted JSON key, inherited public-value context, code
assignment literal, or indented YAML value. YAML blocks stop at sibling/outer
indentation. Empty values stay empty. Redaction uses `[REDACTED]`.

Prose disclosures of the nouns password, passcode, passphrase, passwd, pwd, pw,
`pass code` and `pass phrase` (any case, optionally after my/our/your/his/her/
their/its/the) redact the value after `is`, `was`, `is now`, `set to`, `is set
to` or `was set to` (optionally followed by `:`), or after `:` or a single `=`
with or without a determiner; `==`, `=>`, `::` and `!=` are operators, not cues.
Words may be separated by any run of Unicode whitespace (Rust
`char::is_whitespace`, a superset of WHATWG ASCII whitespace that includes
U+0085, U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F and U+3000;
U+000A-U+000D, U+0085, U+2028 and U+2029 are line breaks) containing at most
one line break (`\r\n` counts as one), also when the whitespace is spelled as an HTML
character reference (`&#32;`, `&#x20;`, `&nbsp;`, `&ensp;` and the other named
spaces), percent or `%u` encoding, or a `\u`/`\x` escape: `my pass\ncode is x`
and `my&#32;password&#32;is&#32;x` redact `x`. After a bare `:` or `=` the value
must start on the cue's line, and a value has no minimum length: `my password
is x`, `pw: Q` and `the password is #` redact `x`, `Q` and `#`. A value opened by
`'`, `"`, `` ` ``, `“` or `‘` is the content up to its matching close on the
same line, otherwise within the next 1024 bytes; an unmatched quote redacts from
the quote through the end of its line (after a bare `:` or `=` the opening quote
stays visible, as for an assignment). Text that touches the close quote with
no whitespace continues the value up to the next whitespace (`"abc"defq`,
`""abcq` and `'abc'-defq` are one value each), unless it is only sentence or
list punctuation (`"abc".` and `"abc", ok` keep `.` and `, ok`); a quoted
segment in that text continues it too, with the same or another quote
(`"abc""defq"` and `"abc"'defq'` are one value), and an unmatched one fails
closed as above. A segment may open with any quote mark at the opener's escape
level or another (`"abc"\"defq\"`, and `\"abc\"'defq'` or `\"abc\"\\\"defq\\\"`
inside a JSON string, are one value each). The run ends only at whitespace, at
a quote that closes a layer the line opened before the noun (the close of an
enclosing JSON string, the `"` of `echo "pw is 'x'"`: the same mark at the same
escape level), and at the close of the innermost bracket the line opened before
it; a quoted string after whitespace is not part of it. After a quoted value, a
`,`, `;` or `&` followed by a key-like field (an identifier or quoted key, then
`=` or `:`, not `==` or `::`) ends the value (`password="abc",user="bob"`,
`password="abc"&user=bob`), as does a `>` or `/>` when the line opened a tag
before the noun (`<a password="abc">text</a>`); otherwise the text touching the
close stays part of the value (`password="abc",defq`). No value, quoted,
unterminated or bare, runs past the close of a layer the line opened before
the noun: a bare value after `:` or `=` ends at the first such close, and any
other value at the first one that structure follows (the end of the line,
whitespace, a bracket, `:`, or a separator before a key-like field), so an
unterminated segment in a JSON string redacts up to, never including, the
string's close. When a value ends at the close of a quote the line opened
before the noun and that close is touched by a quote of any mark or escape
level, a letter, a digit, `_` or `$`, the touching run is part of the value as
the text touching the value's own close is: it runs to the next whitespace, or
up to and never including the close of a further enclosing layer, and the
close is redacted with it (`he said 'pw: abc'defq` gives `he said 'pw:
[REDACTED]`, `{"note":"he said \"pw: abc\"defq","user":"bob"}` keeps the
`user` field). Sentence or list punctuation, whitespace or a field after that
close ends the value there (`He said "pw: abc".`, `1,"pw: abc",3`). An empty quoted segment followed by text
(`password=""abc`) is not an empty assignment. A
straight quote preceded by an odd number of backslashes at the opener's escape
level is escaped and does not close the
value (`"abc\"def"` is one value; `"abc\\"` closes after the backslashes,
which belong to the value); inside a JSON-escaped string the opener's own
escape sets that level. An unquoted value runs to the end of its
line and stops before `, `, `; `, `. ` or a following conjunction (and, but, so,
then, because, which, or, though, although, while, when, if, unless, until,
since); one trailing `.`, `,` or `;` stays visible, as does the close of the
innermost bracket the line left open before the disclosure. After a `:` or `=`,
bare or after a determiner, the whole rest of the value is redacted,
conjunctions and documentary first words included (`my password: correct horse
battery`, `the password: see vault`), and it ends at an enclosing quote, at
the close that matches by type the innermost bracket the line left open before
the noun in the noun's own string layer (a JSON object's or array's brackets
outside the string that holds the noun never count), or at a `;` or `&` that
starts the next `Key=` entry when the noun starts right after a `key=value`
item ended by that same separator (`Server=db;Password=x;Encrypt=true`). Any
other close bracket, `;` or `&` is part of the value, after the bare cue too
(`pw: x]yq zq`, `(note pw: x]yq zq`, `{"note":"pw: x}yq zq"}`, `pw:
abc&def=ghi`, `R&D pw: abc&def=ghi` and `note; my pw: abc;host=y` redact
everything after the cue). Anything before the noun on
its line never redacts less than the bare cue: an adjective, a verb phrase, a
conjunction, a bullet or a label (`The new password: x`, `Please use pw = x`,
`and my passcode: x`, `- note: the new pass code: x`, `We discussed password:
x`) redacts the same value, and a close bracket the line did not open before
the noun is part of it (`The new password: ab)cd` and `* password: ab)cd`
redact `ab)cd`; `(my password: abc) see docs` keeps `)`), as is a `;` or `&`
unless the noun follows a `key=value` item and that separator (`my pw: abc&def=ghi`
redacts `abc&def=ghi`; `host=db;my password=abc;user=x` keeps `;user=x`).
A `#` or `//` comment line before the noun, a `Bearer` value and a `{{ }}`
template placeholder keep their own rulings.
Documentary text after a word cue is not a value: an unquoted value whose
first word is a predicate or participle (required, optional, stored, hashed, wrong, case-sensitive and the reviewed list
in the engine), an `-able`/`-ible` adjective, an `-ed` participle followed by a
preposition, a determiner, preposition or adverb followed by more words (`the
password is at least 8 characters`), or a count followed by a unit (`8
characters long`). References and placeholders are not values, quoted or not:
`$PASSWORD`, `${PASSWORD}`, `process.env.PASSWORD`, `{{password}}`,
`${{ secrets.PASSWORD }}`,
`<password>`, `%PASSWORD%`, `$env:PASSWORD`, `YOUR_PASSWORD`, `op://` paths,
masks of three or more `*`/`•`, and `[REDACTED]`, which keeps a second scrub
byte-identical. The exemption applies only when the whole value, all its
contiguous quoted segments and glued text taken together, is one reference
or placeholder, or a run made only of them (`"$A""$B"`, `${A}${B}`). When any
contiguous part is literal, every part is value and the whole run becomes one
marker, whatever its shape or first character: `pw: "abc""$defq"`,
`password="$defq""abc"`, `pw: ${defq}abc`, `x "pw: abc""<defq>"`,
`x "pw: abc"%DEFQ%` and `pw: "[REDACTED]""abc"` keep nothing. Whitespace still
separates (`pw: "abc" "$defq"` keeps `"$defq"`). After a bare `:` or `=` only references, a lone `None`/`null`/
`nil`/`undefined` and type annotations in source context are not values;
documentary words are (`pw: required` redacts, as `password: required` always
has). A type annotation needs independently recognisable source context: a fn
signature or a struct, interface or type body around the key, or a
`let`/`const`/`var` declaration naming it (`struct X { pw: Vec<u8> }`,
`fn f(pw: String)`, `const pw: string`). Without it a type-looking value is
credential data and fails closed, so `pw: abcq<defq>`, `pw: Vec<u8>`,
`password: Option<String>,` and `pw: string` redact, and a comma or semicolon
does not make a value a type. This is an accepted precision tradeoff: without
source context in the engine's bounded view (at most 512 bytes back in the
same string), a type-looking value fails closed, so a body field on its own
line (`    pw: Vec<u8>,`), in its own NDJSON record or more than 512 bytes
below its opener redacts. A comma or semicolon inside a bracket the value
opened does not end it (`pw: Map<String, u8>,` redacts to `pw: [REDACTED],`). Code is not
prose: a noun preceded by `.`, `$`, `@`, `-`, `/` or
`\`, or directly by if/elif/while/assert/and/or/not/return/lambda (`if password
is None`), is skipped. These spans merge with assignment spans and stay within
the five-pass budget. pass, PIN, secret, key and token are not prose-disclosure
nouns (`the key is pressed`, `a token is a unit of text`).

## Information preserved and PII policy

Default scrubbing preserves email addresses, telephone numbers, home-directory
names, postal addresses, names and standalone numeric identifiers. These are
useful normal session information and cannot safely be inferred to be private.
This is an explicit change from v8's default email/path/phone redaction.
The explicit PII policy additionally redacts email addresses and SSN shapes;
its manifest policy must be stored alongside the ruleset. Phone numbers and
payment cards are not inferred by the current policy.
No consumer may silently imply that default scrubbing anonymizes people.

Keep git SHAs, UUIDs, content hashes and lockfile integrity values, base64 assets,
ordinary prose, code identifiers, file paths, unauthenticated URLs, public SSH
keys, Stripe publishable keys, versions, timestamps and PR/issue numbers.
Do not use entropy alone or generic long-string rules. Code comparisons/assertions,
explicit code references/calls/types and pure shell variable references are
preserved; literal credential assignments and variable expansion defaults remain
sensitive. Symbolic `<name>` placeholders, `xxx` and explicit redacted words
are preserved; embedded assignments and provider shapes remain sensitive.
Type annotations use a fixed 512-byte syntax lookbehind, including lowercase
type aliases and mutable parameters. Quoted-property call references remain code.
Unicode whitespace (including BOM) around assignment separators is
recognized without changing its original bytes.

## Interfaces and errors

`scrub_text` and `scrub_long` process the complete string with identical rules;
neither truncates or independently scrubs arbitrary chunks. `scrub_json` processes
every key and value, returns a changed-node count, and resolves scrubbed-key
collisions deterministically without dropping values. Excess depth fails closed.
`scrub_json_text` rejects invalid JSON; callers must discard the original on error.
`scrub_records` accepts UTF-8 NDJSON bytes, returns scrubbed bytes and record count,
and is atomic: invalid UTF-8, malformed JSON, excessive depth or size returns a
stable code and one-based record number **with no partial output or input text**.
Blank physical lines are ignored; a final newline is optional.

Admission is at most 16 MiB UTF-8 per text or serialized logical JSON record and
64 MiB aggregate NDJSON, including record delimiters. `scrub_text_checked`,
`scrub_json_checked` and `scrub_json_text_checked` return deterministic errors.
Compatibility text/policy/report wrappers fail closed to exactly `[REDACTED]`;
structured wrappers return the marker node or `None`. JS preflights UTF-8 bytes
before the WASM allocator; Rust rechecks every direct WASM export.

The manifest identifies the ruleset family, version, policy, source SHA-256, ABI
version and crate version. Build artifacts have a separate SHA-256. Consumers
verify both; a source digest is not a WASM digest. Historical markers must never
be relabelled. Error paths never fall back to original input.

## Resource bounds and acceptance

Recognition uses Rust's finite-automaton regex engine for fixed patterns and
monotone lexical cursors for contextual spans. No backtracking regex, per-byte
suffix search or unbounded recursive decode is permitted. Normalization is a
single input pass with source-offset mapping; percent/backslash chains consume
their bytes once. Span merging is O(n log n); the fixed number of regex passes
is O(n). JSON traversal is limited to 128 levels; byte-stream APIs have documented
record and total bounds. Large text must retain secret-boundary coverage.

Tests must cover 64 KiB and 256 KiB adversarial inputs, deep escape chains,
repeated incomplete openers, nested public values, malformed UTF-8/JSON, all
entry points, idempotence and preserved normal classes. Report observed timing
and throughput separately from the algorithmic bound.

Evaluation uses generated secrets with reproducible seeds, realistic wrappers
and expected secret spans. Report recall per class, false positives per MB and
benign class, and excess removed bytes. Public fixtures are synthetic. Private
session samples live only in `~/scrubber-eval` (0700, files 0600), are split by
session before inspection, never printed, and must be deleted by 2026-11-16.
Tune on dev only. Held-out is read once after the candidate is frozen; a failure
requires a newly acquired held-out set, never relabelling the same set as unseen.

## Ruleset 10 review refinements

An existing unquoted `[REDACTED]` marker ends its assignment value at the marker;
following punctuation and explanatory words remain byte-identical. Independently
recognizable credentials later on the line are still scanned. Quoted credentials
containing a marker plus a secret tail remain credentials.

A bare `key` name alone does not establish credential semantics. Recognized
provider values and structural credential contexts such as `aws`/`credentials`
do. Exact public idempotency selectors retain nested generic `key` values;
nested explicit credentials and `request_idempotency_key` remain sensitive.
An exact `project_key` (any underscore, hyphen, camel or case spelling) whose string
value is a normalized repository identity, `host.tld/owner/repo` with at most six
further group segments, is preserved: session capture records the project this way,
and it names no credential. Any other value (a vendor project key, an opaque token, a
local path, a URL with scheme, userinfo, port or query, a generated-looking segment),
a composite value, any other spelling (`project__key`) and every prefixed name
(`deta_project_key`) remain sensitive. A path segment piece of 16 or more characters
with a digit in it is token material. An unquoted identity followed by another
assignment on the same line is judged with it and redacted (fail closed); quoted and
structured values keep the identity.
UUID-shaped session IDs, symbolic placeholders, configuration references,
resource names, language literals, code expressions and type annotations with
source context are preserved. Placeholder URL passwords are preserved only on reserved example or
local hosts; ordinary credentials on those hosts remain sensitive.

The crate owns manifest schema 3, JS ABI 2 and `scrubProfile`. Error disposition
is `call_refusal` for deterministic admission failures and `instance_poison` for
unexpected JS/WASM failures. See `MIGRATION.md` for the tagged-code contract.
Independent re-audit pending. Named invented regression tests are behavioral
checks, not evidence of production precision.

## Alpha.6 source precision and independent review correction

Complete bounded source expressions may contain reference calls, member chains,
operators, symbolic arrays/objects and borrow expressions. Numeric object values
require a non-credential field. Strings and regex literal bodies under credential
keys remain sensitive; regex source under non-credential keys stays visible.
Candidates are at most 512 bytes with parser nesting at most 32. Every accepted
reference consumes the whole candidate and delimiter. Rejected source values
retain their complete extent, including comment tails after an inserted marker.
Adjacent `//` and `/*` openers are lexical comments, never division plus regex.

PascalCase scalar text alone does not establish a type declaration. Source types
use the existing bounded declaration/field context. Bare scalar `Key` values
retain alpha.5 redaction: path shape, case or extension is not an exemption.
Malformed quoted postfix values retain their full rejection extent. Type aliases
retain their strict prior grammar and bypass the new expression recognizer.

An independent review blocked `1c86b849` for three recall regressions. Fifteen
invented preservation expectations were explicitly corrected to sensitive:
eight credential-key regex assignments, six standalone PascalCase fragments and
one bare `Key` path. These ambiguous cases do not prove safe source/resource
context. The original PR #11 bare-Key path precision request remains unresolved
without an approved contextual rule; this repair does not substitute a value or
filename allowlist. This is a public invented-policy correction, not relabelling
private held-out data. No existing security matrix or timing limit was changed.

Complete source-case return references, grep/rg directory tails, omitted CLI
values before flags, destructuring binds, cased identifiers and Rust relay `use`
symbols retain their reviewed syntax bounds. No version alone grants adoption;
replacement engine/artifact PASS requires independent review after exact-head CI.

### Alpha.7 boundary and passphrase correction

Rejected unquoted source values stop before delimiter-adjacent trailing whitespace; internal literal/comment tails remain covered. Quoted scalar contents retain their whitespace. Explicit sensitive assignments in Markdown bullets own the complete value regardless of surrounding documentary wording or the words/case of a passphrase. The earlier prose-shortening rule is withdrawn. Entity-aware rejection bounds keep complete entity punctuation in that value; they apply only after existing preservation decisions and never admit an exemption. Prefix inspection remains bounded, with exhausted indentation context failing closed. CLI flag values retain their argument grammar. All alpha.6 recall rulings remain in force.
