# Candidate evaluation results

Frozen text-evaluation source: `71a30576f5684eeb6fdef7bd90e45423965a502ba82a67b05bd936704e3e5c80`.
Current distribution source: `ea1c893de008556ef65104960ad3fa1f67aac5299b8442e4e04c1211405ca3b7`.
Mac development WASM: `b631d6a9a82b4636b2127b0a1b066961c46b7c4ff902e5db4861345ff4ddd588` (1,564,899 bytes).

Candidate 10 is not approved for adoption. Ruleset reservation and independent
relayscrubber-lead exact-commit PASS are pending. Veto host-assisted review passed
with warnings about production precision evidence and Workers build verification;
it does not replace that independent review. No registry publish or deployment occurred.

## Recall and synthetic precision

Seed 24301: **8,320/8,320 complete secret-span coverage**, 45 classes.
Alternate seed 987654321: 8,320/8,320.
Four-seed tests also pass full coverage/idempotence. Alternate seeds vary bodies;
they are not held-out provider families. Historical-input audit added extended
Google bodies and multilingual boundaries independently of held-out observations.

| Secret class | Complete / cases | Recall | Excess removed bytes |
| --- | ---: | ---: | ---: |
| anthropic | 128 / 128 | 100% | 0 |
| authorization | 128 / 128 | 100% | 896 |
| aws | 128 / 128 | 100% | 0 |
| bearer | 128 / 128 | 100% | 0 |
| capy | 128 / 128 | 100% | 0 |
| cli | 128 / 128 | 100% | 0 |
| cloudflare | 128 / 128 | 100% | 0 |
| cloudflare_account | 128 / 128 | 100% | 0 |
| cloudflare_global | 128 / 128 | 100% | 0 |
| connection_string | 128 / 128 | 100% | 0 |
| cookie | 128 / 128 | 100% | 1152 |
| cursor | 128 / 128 | 100% | 0 |
| digitalocean | 128 / 128 | 100% | 0 |
| github | 128 / 128 | 100% | 0 |
| github_fine | 128 / 128 | 100% | 0 |
| gitlab | 128 / 128 | 100% | 0 |
| google | 128 / 128 | 100% | 0 |
| google_embedded_prefix | 128 / 128 | 100% | 0 |
| google_extended | 128 / 128 | 100% | 0 |
| google_oauth | 128 / 128 | 100% | 0 |
| huggingface | 128 / 128 | 100% | 0 |
| jwt | 128 / 128 | 100% | 0 |
| malformed_quote | 768 / 768 | 100% | 0 |
| newline_credential | 768 / 768 | 100% | 0 |
| npm | 128 / 128 | 100% | 0 |
| openai | 128 / 128 | 100% | 0 |
| pem | 128 / 128 | 100% | 0 |
| public_nested | 768 / 768 | 100% | 0 |
| pypi | 128 / 128 | 100% | 0 |
| quoted_assignment | 768 / 768 | 100% | 0 |
| relay | 128 / 128 | 100% | 0 |
| relayhistory | 128 / 128 | 100% | 0 |
| sendgrid | 128 / 128 | 100% | 0 |
| signed_url | 128 / 128 | 100% | 0 |
| slack | 128 / 128 | 100% | 0 |
| slack_app | 128 / 128 | 100% | 0 |
| slack_refresh | 128 / 128 | 100% | 0 |
| slack_webhook | 128 / 128 | 100% | 0 |
| stripe | 128 / 128 | 100% | 0 |
| stripe_restricted | 128 / 128 | 100% | 0 |
| stripe_webhook | 128 / 128 | 100% | 0 |
| url_userinfo | 128 / 128 | 100% | 0 |
| vercel | 128 / 128 | 100% | 0 |
| yaml_nested_block | 128 / 128 | 100% | 768 |
| yaml_plain_continuation | 128 / 128 | 100% | 0 |

Excess removed: 2,816 bytes, from intentional whole headers and YAML block syntax.
This measures removed syntax separately from annotated secret bytes. Malformed
quoted credentials can require additional removal through the enclosing end.

| Synthetic benign class | Cases | Bytes | Changed cases / MB |
| --- | ---: | ---: | ---: |
| base64_assets | 512 | 142,848 | 0.00 |
| empty_env | 512 | 13,202 | 0.00 |
| hashes | 512 | 115,712 | 0.00 |
| identifiers | 512 | 38,802 | 0.00 |
| paths | 512 | 41,252 | 0.00 |
| prose | 512 | 44,836 | 0.00 |
| public_selectors | 512 | 62,354 | 0.00 |
| urls | 512 | 31,524 | 0.00 |
| uuid | 512 | 18,944 | 0.00 |
| yaml_empty | 512 | 22,418 | 0.00 |

## Current real benign text: dev and fresh held-out

| Split / class | Bytes | Changed spans | False-positive spans / MB | Removed bytes |
| --- | ---: | ---: | ---: | ---: |
| dev / prose | 772,386 | 0 | 0.00 | 0 |
| dev / technical | 28,576 | 0 | 0.00 | 0 |
| heldout / prose | 448,885 | 0 | 0.00 | 0 |
| heldout / technical | 35,232 | 0 | 0.00 | 0 |

The fresh held-out set was selected/downloaded before reading, then evaluated
once on the frozen digest above. It contains Git reset/stash manuals and
public-domain Frankenstein prose. Previously evaluated source sets are retired
with their old source digests after independent grammar/provider audits changed
the engine. Their once-only observations remain in
`results/precision.json`; it is not reused as unseen evidence for this candidate.
Dev sources were reacquired with byte-identical hashes. No engine changes
followed this final held-out evaluation. All source URLs/checksums are recorded.
Zero observed changes in a finite sample does not prove universal zero false
positives or represent every production code/log distribution.

## Retired private workspace sample: unlabelled diagnostic only

These observations belong to source `0f40608394d5caf75b56eff09956ca34492844bf72de26756449cceb8176da42`;
they are not current production precision evidence. The two-dev/two-held-out
split was fixed before reading. No transcript content or session ID is retained.

| Split | Sessions | Complete-event bytes | Candidate spans | Changed events | Removed bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| dev | 2 | 45,914 | 4 | 4 | 709 |
| heldout | 2 | 64,356 | 4 | 1 | 83 |

Each split requested 100 bounded events; 10 dev and 4 held-out truncated events
were excluded. Counts are candidate rate, **not false-positive rate**. No raw
sample was inspected or copied into tests. Production-session precision remains
unqualified pending independently labelled evaluation. All owned raw inputs and
generated parity vectors were deleted locally ahead of the 2026-11-17 deadline.

## Timing and runtime checks

Host: Darwin arm64, Rust 1.88.0 release, five warm samples per family.
Recall corpus: 798,397 bytes, 22.24 MB/s including many short calls.
Observed worst times and mean throughput are not a service guarantee.

| Family | 64 KiB worst ms | 256 KiB worst ms | 256 KiB mean MB/s |
| --- | ---: | ---: | ---: |
| unclosed_quotes | 0.664 | 2.654 | 101.23 |
| escape_chain | 0.220 | 0.855 | 306.80 |
| percent_chain | 0.377 | 1.511 | 173.88 |
| quoted_names | 0.730 | 2.737 | 97.37 |
| url_authorities | 0.821 | 3.378 | 78.44 |
| identifiers | 0.544 | 2.131 | 123.12 |
| public_context_chain | 0.796 | 3.189 | 82.44 |
| pem_openers | 3.785 | 13.891 | 19.04 |

Native tests, clippy, packaging, Node 26.13.0, Bun 1.3.14 and local Cloudflare
workerd (Wrangler 4.77.0) pass. Node/Bun compare 4,800 native-generated vectors,
exercise all APIs, error/pin mismatch paths and adversarial inputs. Native
preserve_order feature-unification tests pass. Independent target-directory
builds reproduce WASM, glue, types and adapter digests. Hosted Linux/Windows CI
and exact-commit owner approval remain required.

[Algorithmic bound](PERFORMANCE.md) and [evaluation protocol](EVALUATION.md).

The additive JSON transport revision preserves Rust `jsonText` for storing large
integer identifiers. Native recognition/parser sources, dependencies and toolchain
are byte-identical to the frozen evaluation commit, verified in `precision.json`.
Held-out input was not re-read. The parsed JS `.value` is a convenience view;
persist `jsonText` or NDJSON bytes. Synthetic uint64 fidelity assertions pass.
