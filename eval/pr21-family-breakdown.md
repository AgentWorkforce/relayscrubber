# PR21 synthetic family breakdown

Candidate: `b54745161cade161318e6e1dc9ca5486b91c474d`, alpha.9, **DRAFT**. No merge or publication approval.

The complete matrix contains **7148 positive** and **60 benign** cases: 7,126 generated positives + 22 frozen author positives, and 45 generated + 15 author benign controls. Each runs as text, JSON and NDJSON on four paths: 86,496 observations. All 60 benign controls remain unchanged.

Generator: seed 24301; 1,024 seeded mutations. The core cross-product is 9 nouns × 7 separators × 3 casing modes × 3 quotes × 9 value shapes = 5,103 cases. Extra families cover gap/split-connector line breaks, quoted multiline values, unmatched quotes, and two disclosures on a line. Complete dimensions and identities are in the machine report below.

**Scope correction:** explicit password/passcode/passphrase/pw disclosure cues with is/was/possessive-colon have **no minimum value length**. The 216 one-character cases are required PR21 cases; their **162 candidate misses keep b547451 BLOCKED**. The 728 other intent-aligned cases and all 37 author fixtures still pass. Only the other 6,182 generated positive cases / 5,092 misses remain `expanded_policy_pending_direct_authorization`. Historical 6,398-case aggregate buckets include the 216 required cases; do not add them twice. This reporting-only correction changes no measurements, hashes, harness execution, or runtime state.

Tables count unique **generated positive cases** failing any form; each axis partitions the same 7,126 positives. Axes overlap each other and do not identify the cause of a miss. Author fixtures and benign controls are counted separately. Native and real pipeline-adapter counts match exactly, so each version has one displayed failure column.

## noun

| Family | Positive cases | alpha.5 failed | alpha.9 failed |
| --- | ---: | ---: | ---: |
| `password` | 798 | 593 | 453 |
| `passcode` | 766 | 766 | 431 |
| `passphrase` | 786 | 581 | 440 |
| `pw` | 792 | 792 | 583 |
| `pass` | 759 | 759 | 759 |
| `pin` | 755 | 563 | 563 |
| `secret` | 765 | 575 | 575 |
| `key` | 776 | 776 | 776 |
| `token` | 767 | 577 | 577 |
| `multiple_nouns_see_multiplicity` | 162 | 137 | 97 |

## separator

| Family | Positive cases | alpha.5 failed | alpha.9 failed |
| --- | ---: | ---: | ---: |
| `is` | 1121 | 1121 | 829 |
| `was` | 999 | 999 | 727 |
| `=` | 979 | 486 | 383 |
| `:` | 1074 | 560 | 362 |
| `is now` | 971 | 971 | 971 |
| `set to` | 967 | 967 | 967 |
| `is set to` | 988 | 988 | 988 |
| `is\nnow` | 9 | 9 | 9 |
| `set\nto` | 9 | 9 | 9 |
| `is\nset\nto` | 9 | 9 | 9 |

## value shape

| Family | Positive cases | alpha.5 failed | alpha.9 failed |
| --- | ---: | ---: | ---: |
| `fixed/short_letter` | 567 | 477 | 459 |
| `fixed/short_symbol` | 567 | 477 | 459 |
| `fixed/digits` | 567 | 477 | 378 |
| `fixed/symbols` | 567 | 477 | 378 |
| `fixed/ordinary_word` | 567 | 477 | 378 |
| `fixed/type_word` | 567 | 492 | 387 |
| `fixed/spaces` | 567 | 507 | 441 |
| `fixed/unicode` | 567 | 477 | 378 |
| `fixed/long` | 567 | 477 | 378 |
| `fixed_symbols_with_gap_break` | 756 | 666 | 648 |
| `fixed_symbols_with_connector_break` | 27 | 27 | 27 |
| `quoted_multiline_value` | 36 | 36 | 36 |
| `unclosed_multiword_value` | 18 | 18 | 10 |
| `two_fixed_symbol_values` | 162 | 137 | 97 |
| `seeded/codepoints_257` | 128 | 114 | 96 |
| `seeded/codepoints_1024` | 125 | 107 | 90 |
| `seeded/codepoints_1` | 112 | 100 | 95 |
| `seeded/codepoints_64` | 134 | 119 | 104 |
| `seeded/codepoints_8` | 122 | 107 | 94 |
| `seeded/codepoints_31` | 144 | 127 | 113 |
| `seeded/codepoints_3` | 132 | 115 | 101 |
| `seeded/codepoints_2` | 127 | 108 | 107 |

## quoting

| Family | Positive cases | alpha.5 failed | alpha.9 failed |
| --- | ---: | ---: | ---: |
| `unquoted` | 2319 | 2069 | 1823 |
| `single` | 2300 | 1940 | 1651 |
| `double` | 2309 | 1937 | 1655 |
| `backtick` | 9 | 9 | 9 |
| `curly_double` | 9 | 9 | 9 |
| `unmatched_single` | 9 | 9 | 5 |
| `unmatched_double` | 9 | 9 | 5 |
| `double_and_single` | 162 | 137 | 97 |

## multiline

| Family | Positive cases | alpha.5 failed | alpha.9 failed |
| --- | ---: | ---: | ---: |
| `inline` | 5686 | 4838 | 4004 |
| `before_connector` | 189 | 159 | 153 |
| `before_value` | 189 | 169 | 165 |
| `crlf` | 189 | 169 | 165 |
| `unicode_space` | 189 | 169 | 165 |
| `split_connector` | 27 | 27 | 27 |
| `inside_quoted_value` | 36 | 36 | 36 |
| `seeded_gap_lf` | 382 | 339 | 328 |
| `seeded_gap_crlf` | 239 | 213 | 211 |

## multiplicity

| Family | Positive cases | alpha.5 failed | alpha.9 failed |
| --- | ---: | ---: | ---: |
| `one_disclosure` | 6964 | 5982 | 5157 |
| `two_disclosures` | 162 | 137 | 97 |

## generator family

| Family | Positive cases | alpha.5 failed | alpha.9 failed |
| --- | ---: | ---: | ---: |
| `grammar` | 5103 | 4338 | 3636 |
| `line_break` | 756 | 666 | 648 |
| `split_connector` | 27 | 27 | 27 |
| `multiline_value` | 36 | 36 | 36 |
| `unmatched_quote` | 18 | 18 | 10 |
| `multiple` | 162 | 137 | 97 |
| `seeded_mutation` | 1024 | 897 | 800 |

## scope

| Family | Positive cases | alpha.5 failed | alpha.9 failed |
| --- | ---: | ---: | ---: |
| `pr21_required_short_values` | 216 | 180 | 162 |
| `pr21_intent_subset` | 728 | 614 | 0 |
| `expanded_policy_pending_direct_authorization` | 6182 | 5325 | 5092 |

## Bounded witnesses, hashes, and parity

The [machine report](../docs/results/pr21-family-breakdown-b547451.json) contains 48 deduplicated invented witnesses covering every listed family, including their scope labels, protected spans, input hashes, and four variant output hashes/previews. Long inputs/outputs are capped previews with full hashes and deterministic regeneration recipes. No session bodies are included.

Each witness has independently measured native alpha.5/alpha.9 output hashes and saved actual pipeline-adapter alpha.5/hosted-alpha.9 hashes. Hashes cover UTF-8 decoded content, including the public context marker; all three forms yield the same decoded content for these witnesses. All 288 bounded native calls match adapter hashes. Full-matrix parity is 0 differences / 21,624 comparisons for alpha.5, and 0 / 21,624 for alpha.9. The native and adapter paths are separate executions, not aliases.

The exact package/WASM/manifest/source hashes and adapter/source limitations are recorded in the [scoped hosted audit](pr21-hosted-scoped-audit.md). Its native probes were already built; the candidate WASM is the downloaded hosted artifact, not the earlier local WASM build. The candidate adapter identity is in-memory test-only with an unreleased CI schema label; no consumer pin file changed.

Harness: `scripts/summarize-pr21-families.mjs`; original runner: `scripts/audit-pr21-disclosures.mjs`; generator: `eval/disclosure-coverage.mjs`. File SHA-256 identities are in the machine report. Run the summarizer after the scoped audit; it reads only ignored synthetic results and makes bounded calls to existing native probes.

No session access, fixture search/change, rule edit, re-pin, engine build, tag, publish, or deployment. Finite property-style tests do not prove detection of every natural-language disclosure.

Scope ruling: relayscrubber-lead message `246932985776848896`. Historical harness hashes remain the identities of the executed test-only harness; no tests or engine code were rerun or changed for this amendment.
