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
* Values assigned to password, passwd, pwd, passphrase, secret, client_secret,
  api_key/apikey, access_key, secret_key, private_key, access_token, auth_token,
  refresh_token, id_token, session_token/session_id, credential(s), token,
  account_key and provider-prefixed equivalents. Connection-string and database
  URL fields are inspected without removing unauthenticated URLs. Underscore,
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
UUID-shaped session IDs, symbolic placeholders, configuration references,
resource names, language literals, code expressions and type annotations are
preserved. Placeholder URL passwords are preserved only on reserved example or
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
