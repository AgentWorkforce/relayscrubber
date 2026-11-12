# relayscrubber evals: accuracy and performance benchmark

Best-in-class redaction is measured, not asserted. This file records what the
eval suite (`tests/redaction_evals.rs`) proves, what relay history taught us,
and what the throughput benchmark (`examples/bench_redaction.rs`) reports.

All secrets in the evals are synthetic (runtime-built filler). No live
credential appears anywhere in this repository.

## Entry points

- `scrub_long` — the canonical engine: complete-string scan, no truncation.
- `scrub_enhanced` — the recommended upload-safe entry point: precise
  query/fragment-parameter and empty-user-URL pre-passes, then the canonical
  engine, then one fused whole-output post-pass. The post-pass covers
  chat-webhook URLs (Discord, Teams, webhook.site, requestbin), provider
  prefixes beyond the engine table (Groq, age, Slack `xoxc`, Mailchimp,
  Databricks, Notion, Docker Hub, Linear, Telegram, and others),
  any-length CLI-flag secrets, XML secret elements, session cookies,
  the Elastic `ApiKey` scheme, kubeconfig key data, Ansible Vaults,
  validated SSNs, private-range IPv4, and long mixed-class password-less
  URL userinfo (registry-style tokens). Never truncates; idempotent;
  fail-closed. Empty parameter values stay empty.
- `scrub_enhanced_with_policy` / `scrub_json_enhanced_with_policy` /
  `scrub_json_text_enhanced_with_policy` — the same treatment with an
  explicit [`Policy`](src/lib.rs). Use `Policy::Pii` when email addresses
  and SSN shapes must not survive; the default policy preserves contact
  details by contract.
- `scrub_json_enhanced` / `scrub_json_text_enhanced` — the same treatment for
  JSON values and JSON text (collision suffixes and counts preserved; counts
  cover pre-pass swaps plus canonical and post-pass redactions, with
  already-redacted spans counting zero so second runs stay quiet). The
  value entry point runs both pre-passes over every string value and key
  before the canonical scrub, so it matches the text entry point exactly
  (pinned by parity tests for query parameters and empty-user Redis URLs).
  The text entry point scans values escape-aware, so `\"` inside a JSON
  string cannot corrupt the document.

## Accuracy

`cargo test --test redaction_evals` (12 tests, all green):

| suite | cases | canonical engine | enhanced | false positives |
|---|---|---|---|---|
| relay history replays | 7 | 7/7 | 7/7 | — |
| canonical providers + PII + contexts | 31 | 31/31 | 31/31 | — |
| batch-1 shapes (webhooks, prefixes, CLI, SSN, IP) | 23 | 10/23 | 23/23 | — |
| base behavior, pinned (ex-ruleset-8) | 9 | 8/9 | 9/9 | — |
| batch-2 shapes (providers, XML, cookies, URLs) | 38 | 9/38 | 38/38 | — |
| must-preserve (no-FP guard) | 46 | 46/46 | 46/46 | 0/46 |
| JSON entry points + long segments + idempotence + PII policy | — | — | pass | — |
| adversarial runs + JSON parity + escaped quotes | — | — | pass | — |
| benign corpus differential (30 lines) | 7 altered | 2 marginal | — | — |
| **total** | **108 + 46** | **65/108** | **108/108** | **0/46** |

Run with `-- --nocapture` on the summary test to reprint the line:
`accuracy: base 65/108 enhanced 108/108 false-positives 0/46`.

The engine absorbed a large share of the old gap list (all batch-1 CLI
shapes, DigitalOcean, Google OAuth, PyPI, Redis, and more); the post-pass
keeps them as defense-in-depth and carries the remaining 43. The single
engine miss with full context preserved is the password-less userinfo token,
which the post-pass redacts.

## Relay-history proof

Shared-session transcripts were mined for leak shapes; each row below was
replayed with synthetic values in the evals:

| history signal | finding | replay case |
|---|---|---|
| `postgresql://neondb_owner:…@ep-…` | userinfo passwords captured | `relay/neon-url` |
| `Authorization: Bearer …` | Bearer values captured (scheme word is engine-redacted) | `relay/bearer` |
| `BEGIN PRIVATE KEY` in prose (no dashes) | correctly kept, no FP | `fp/pem-prose` |
| `RELAYAUTH_SIGNING_KEY_PEM` env names in docs | labeled key material captured | `relay/env-key` |
| `op://…` 1Password references | correctly kept | `fp/op-ref`, `fp/op-env` |
| agent addresses (`name@machine`) | correctly kept (no `@`-FP) | `fp/agent-addr` |
| `?api_key=SECRET&mode=1` callbacks | credential tails fail closed through the URL tail | `relay/query-tail` |
| `AKIA…` in stored history | no raw key material found | `prov/aws` |
| Discord webhooks | absent from history, probed | `new/discord*` |
| compact JWT | requires an `alg` JSON header per the engine contract | `prov/jwt` |
| registry `token@host` URLs | engine keeps them; post-pass redacts 12+ mixed-class users | `base/token-user-url` |

Gap probes confirmed before the fix: short CLI-flag values, Discord/Teams
webhook URLs, `gsk_`/`AGE-SECRET-KEY-`/`xoxc-` and 24 more provider prefixes,
`#fragment` credentials, SSNs, private IPv4, Mailchimp/Telegram/Terraform
shapes, webhook.site/requestbin paths, XML secret elements, session cookies,
the Elastic `ApiKey` scheme, kubeconfig key data, Ansible Vaults, `sig`/
`oauth_token`/Amz/Google query names, and empty-user (`redis://:pass@`) URLs.

## Benign-corpus differential

`benign_corpus_differential_is_pinned` runs 30 realistic benign lines
(prose, dashboards, contacts, code, configs, paths, identifiers) through
both stages and pins the marginal set, so any behavior change fails loudly
instead of slipping through. Latest reading (`-- --nocapture` prints it):

- 21/30 pass through both stages byte-identical (greetings, dashboard URLs,
  emails, phones, mailto, home paths, semver, UUIDs, SHAs, agent addresses,
  dotted/short userinfo, env refs, Mailgun-shaped `key-` hex, dashed cards,
  invalid SSNs, bare 40-hex after `token`, ports, markers, JSON nulls,
  ordinary `state`/`id` params, version quads).
- 7/30 altered by the engine, unchanged by the layer: `grep`/`switch`/
  `cli-alone`/`key-path` (filed as SPEC violations, see below) and
  `theme-cookie`/`max-token`/`bearer-short` (contracted engine behavior).
- 2/30 marginally altered by the layer, both by design: `private-ip`
  (internal-IP anonymization is the feature, not a bug) and `long-user`
  (a 12+ mixed-class password-less userinfo user is treated as a registry
  token; dotted and short users are pinned as preserved controls).
- Version-shaped private quads (`version 10.1.2.3`, `v10.1.2.3`,
  `version: 10.1.2.3`) are preserved by a `version`/`ver`/bare-`v`
  lookbehind; `server`/`subversion`/typos and `password=v10…` values still
  redact (fail-closed).

## Upstream precision reports (engine-owned)

The following over-redactions were found in the canonical engine while
re-baselining. They contradict the cited SPEC lines, were left out of the
must-preserve guard (a superset cannot un-redact), and were reported to the
engine team instead of being worked around here:

| shape | engine behavior | contract |
|---|---|---|
| `case "token": return parseToken(input);` | redacts the call | code calls are preserved |
| `grep -rn "access token": src/ \| head` | redacts `src/ \| head` | file paths are preserved |
| `{"Key": "raw/v1/…jsonl.zst"}` | redacts the path value | bare `key` needs credential context |
| `mysql --password -h db` | redacts `-h` | a flag is not a value |

Intended engine behaviors pinned as-is (SPEC, recognition section):
whole `Cookie`/`Set-Cookie` values, all `Authorization` values, `max_token`
credential-suffix keys (values including numbers), credential query tails
failing closed through trailing words, and default-policy preservation of
emails, phones, cards, and home paths.

## Performance

`cargo run --release --example bench_redaction` (Apple Silicon, release):

| workload | `scrub_long` | `scrub_enhanced` | overhead |
|---|---|---|---|
| clean 1 MB log | 124.79 MB/s | 28.88 MB/s | ~4.3x |
| mixed 1 MB (tokens + URLs) | 48.76 MB/s | 23.29 MB/s | ~2.1x |
| mixed 256 KB | 49.01 MB/s | 23.28 MB/s | ~2.1x |
| mixed 300 KB | 49.24 MB/s | 23.40 MB/s | ~2.1x |
| commas 256 KB (regression) | 108.13 MB/s | 16.35 MB/s | ~6.6x |

The enhanced layer costs two linear pre-passes plus one fused post-pass on
top of the engine, so budget roughly 2x on secret-bearing input. Two
quadratic scans found in review (Atlas run rescans, cookie-name scans) are
fixed — run-end caching and a 16-byte name cap — and pinned by an
adversarial test plus the commas workload; what remains on pathological
inputs is linear per-byte matcher overhead, not blowup. Bulk scrubbing of
known-clean logs should call `scrub_long` directly; session uploads (tens
to hundreds of KB of untrusted text) cost single-digit milliseconds either
way. Machine noise applies; re-run on the host you care about. The
enhanced output is smaller on mixed input (0.72 vs 0.86 MB out per 1 MB
in): the extra time is spent catching 43 more leak classes.

## Canonical code untouched

`src/engine.rs`, `src/json.rs`, and `src/normalize.rs` are byte-identical to
the merge base (`git diff origin/main` shows only `src/lib.rs` exports plus
the new `src/enhanced.rs`). All upstream suites pass unmodified, including
the frozen ruleset-8 parity vectors under `vendor/`.

## Deliberate non-goals

Bare hex runs (indistinguishable from digests), short/ambiguous prefixes
(`re_`, Twilio `AC`-SIDs that collide with MD5 fragments), public IPv4
(collides with four-part versions), compressed IPv6 (`::` collides with Rust
paths), single-dash flags (`-p` is usually a port), public counterparts
(`phc_`, `sb_publishable_`, `client_id`, age `age1` recipients, PGP public
blocks, plist `<key>`, SAS `se`/`sp`/`sv` fields, Tunnel/Deploy preview
hostnames), and — following the canonical contract — emails, phone numbers,
payment cards, and home paths under the default policy (email and SSN are
covered under `Policy::Pii`; phones and cards are not inferred by any
current policy). Each has a comment at its decision site. Roadmap:
full-form IPv6 ULA, NATS seeds, Okta `00`-tokens, more long-prefix
providers as they are evidenced in history.
