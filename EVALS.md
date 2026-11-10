# relayscrubber evals: accuracy and performance benchmark

Best-in-class redaction is measured, not asserted. This file records what the
eval suite (`tests/redaction_evals.rs`) proves, what relay history taught us,
and what the throughput benchmark (`examples/bench_redaction.rs`) reports.

All secrets in the evals are synthetic (`"Ab1"`-style filler built at
runtime). No live credential appears anywhere in this repository.

## Entry points

- `scrub_long` — ruleset 8, the lockstep canonical pipeline. Unchanged.
- `scrub_enhanced` — the recommended upload-safe entry point: precise
  query/fragment-parameter and empty-user-URL pre-passes, then `scrub_long`,
  then one fused whole-output post-pass. The post-pass covers chat-webhook
  URLs (Discord, Teams, webhook.site, requestbin), 30 provider prefixes
  (DigitalOcean, Google OAuth, Groq, age, Slack `xoxc`, Databricks, PyPI,
  Replicate, Tailscale, Doppler, Vault, 1Password, Pulumi, Postman, Brevo,
  New Relic, Sentry, SonarQube, Supabase, xAI, Perplexity, GitLab deploy/
  runner, Mailchimp, Terraform Cloud, Notion, Docker Hub, Linear, Telegram),
  any-length CLI-flag secrets, XML secret elements, session cookies,
  the Elastic `ApiKey` scheme, kubeconfig key data, Ansible Vaults,
  validated SSNs and private-range IPv4. Never truncates; idempotent;
  fail-closed.
- `scrub_json_enhanced` / `scrub_json_text_enhanced` — the same treatment for
  JSON values and JSON text (collision suffixes and counts preserved).

## Accuracy

`cargo test --test redaction_evals` (7 tests, all green):

| suite | cases | ruleset 8 | enhanced | false positives |
|---|---|---|---|---|
| relay history replays | 7 | 6/7 | 7/7 | — |
| canonical providers + PII + contexts | 30 | 30/30 | 30/30 | — |
| batch-1 shapes (webhooks, prefixes, CLI, SSN, IP) | 28 | 0/28 | 28/28 | — |
| batch-2: verified v8 behavior, pinned | 9 | 9/9 | 9/9 | — |
| batch-2 shapes (providers, XML, cookies, URLs) | 36 | 0/36 | 36/36 | — |
| must-preserve (no-FP guard) | 48 | 48/48 | 48/48 | 0/48 |
| JSON entry points + long segments + idempotence | — | — | pass | — |
| **total** | **110 + 48** | **51/110** | **110/110** | **0/48** |

Run with `-- --nocapture` on the summary test to reprint the line:
`accuracy: v8 51/110 enhanced 110/110 false-positives 0/48`.

## Relay-history proof

Shared-session transcripts (post-scrub index) were mined for leak shapes;
each row below was replayed with synthetic values in the evals:

| history signal | finding | replay case |
|---|---|---|
| `postgresql://neondb_owner:[REDACTED]@ep-…` | userinfo passwords captured | `relay/neon-url` |
| `Authorization: Bearer [REDACTED]` | bearer tokens captured | `relay/bearer` |
| `BEGIN PRIVATE KEY` in prose (no dashes) | correctly kept, no FP | `fp/pem-prose` |
| `RELAYAUTH_SIGNING_KEY_PEM` env names in docs | labeled key material captured | `relay/env-key` |
| `op://…` 1Password references | correctly kept | `fp/op-ref`, `fp/op-env` |
| agent addresses (`name@machine`) | correctly kept (no `@`-FP) | `fp/agent-addr` |
| `?api_key=SECRET&mode=1` callbacks | v8 ate `&mode=1`; enhanced keeps it | `relay/query-tail` |
| `AKIA…` in stored history | no raw key material found | `prov/aws` |
| Discord webhooks | absent from history, missed by v8 when probed | `new/discord*` |

Gap probes against ruleset 8 (all confirmed misses before the fix).
Batch 1: short CLI-flag values (`--password hunter2`), Discord/Teams webhook
URLs, `dop_v1_`/`ya29.`/`gsk_`/`AGE-SECRET-KEY-`/`xoxc-` prefixes, `#fragment`
credentials beyond the 8 OAuth names, SSNs, private IPv4. Batch 2: 24 more
provider prefixes, Mailchimp/Telegram/Terraform-Cloud shapes, webhook.site/
requestbin paths, XML secret elements, session cookies, the Elastic `ApiKey`
scheme, kubeconfig key data, Ansible Vaults, empty-user (`redis://:pass@`)
URLs, and `sig`/`oauth_token`/`consumer_secret`/Amz/Google query names.
Probes that refuted a gap (PGP/EC blocks, proxy auth, `*-Token:`/`*-Key:`
headers, Docker auths, JAAS, token-user URLs) became pinned v8 cases instead.

## Performance

`cargo run --release --example bench_redaction` (Apple Silicon, release):

| workload | `scrub_long` | `scrub_enhanced` | overhead |
|---|---|---|---|
| clean 1 MB log | 11.41 MB/s | 8.74 MB/s | ~23% |
| mixed 1 MB (PII + tokens + URLs) | 6.63 MB/s | 5.87 MB/s | ~11% |
| mixed 256 KB | 6.91 MB/s | 6.08 MB/s | ~12% |
| mixed 300 KB (crosses segment bound) | 6.73 MB/s | 5.98 MB/s | ~11% |

The enhanced layer costs two linear pre-passes plus one fused post-pass over
output the canonical 32-rule pipeline already walked. Session uploads are
tens to hundreds of KB, so this is single-digit milliseconds in practice.
Machine noise applies; re-run on the host you care about.

## Lockstep

Ruleset 8 is byte-for-byte intact: `cargo test --all-targets` passes the
source/corpus digest locks, all 199 corpus vectors, and the parity example
(`--long` / `--json-text` paths unchanged; `--enhanced` is additive). The
enhanced module touches no hashed file (`src/rules/**`, `src/rules.rs`).

## Deliberate non-goals

Bare hex runs (a 37-hex key is indistinguishable from a digest the corpus
requires keeping), short/ambiguous prefixes (`re_`, bare `key-`, Twilio
`AC`-SIDs that collide with MD5 fragments), public IPv4 (collides with
four-part versions), compressed IPv6 (`::` collides with Rust paths),
single-dash flags (`-p` is usually a port), public counterparts (`phc_`,
`sb_publishable_`, `client_id`, `consumer_key`, age `age1` recipients, PGP
public blocks, plist `<key>`, cookie names like `theme`, SAS `se`/`sp`/`sv`
policy fields, Tunnel/Deploy preview hostnames). Each has a comment at its
decision site. Roadmap: full-form IPv6 ULA, NATS seeds, Okta `00`-tokens,
more long-prefix providers as they are evidenced in history.
