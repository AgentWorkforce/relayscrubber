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
  hyphen and camel spellings are recognized. Generic `key`, public_key,
  idempotency_key, token_count/token_budget and credential identifiers used
  without a value are preserved.
* Assignments in code, env, YAML, JSON and CLI flags. `:` and `=` and their
  percent, percent-u, backslash-u and backslash-x spellings are recognized,
  including repeated percent-25 and backslash escape chains. Encoded delimiters
  are interpreted for recognition; surviving original bytes are not decoded.
* Authorization/Proxy-Authorization values; standalone Bearer credentials;
  Cookie and Set-Cookie values; labelled session IDs; passwords in URL userinfo
  and database/ADO connection strings; signed URL signature, SAS `sig`, and
  credential/security-token query parameters. Ordinary query `state`, `code`,
  `key`, `id` and `code_challenge` are preserved unless explicitly credentialled.

A quoted credential includes whitespace and newlines through the matching
delimiter. If the quote is malformed, remove through the enclosing value's end
or end of input. There is no 4096-byte leak window. A public replay value containing
an embedded credential is not exempt: its enclosing extent applies to an
unquoted nested credential, including all trailing words. JSON public-property
context follows every descendant, at every supported depth. Redaction markers
are ordinary strings: a marker prefix never exempts a surviving tail. A second
scrub must be byte-identical to the first.

Unquoted ordinary assignments end at whitespace or a structural separator.
Unquoted YAML block scalars are sensitive through their indented body. Header
values end at the next physical line unless quoted; sensitive JSON properties
redact their entire value, including numbers, booleans, arrays and descendants.
Empty values stay empty. Redaction uses the single literal `[REDACTED]`.

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
Do not use entropy alone, generic long-string or generic `key=` rules.

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
session before inspection, never printed, and must be deleted by 2026-11-17.
Tune on dev only. Held-out is read once after the candidate is frozen; a failure
requires a newly acquired held-out set, never relabelling the same set as unseen.
