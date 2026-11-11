# Candidate validation results

Candidate version is `0.5.0-alpha.5`. Only invented inputs were used; no
sampled data, labels or private re-audit directories were accessed. No merge,
tag, publication or consumer adoption is authorized by these results.

HTML entities establish the outer URL structure. Percent escapes stay inside
their components: a sensitive outer parameter is redacted through the next
literal or entity separator, including every encoded credential tail. Public
values open one percent-decoding layer at a time for nested URL/query discovery.
Each nested sensitive value stays opaque at its own layer. Original source
ranges compose through decoding, preserving every surrounding spelling.

Userinfo discovery separates authority delimiter encoding from password data.
Fully encoded protocol-relative and absolute authorities, including percent
encodings of HTML entity spellings, retain their complete password source span.
Reserved slashes, question marks, fragments, equals signs and at-signs cannot
truncate a password. Public usernames with encoded colons survive unchanged.
The layer budget is four percent layers and four entity layers; credential-bearing
public values fail closed if their nested percent budget is exhausted.

Disjoint lexical URL regions and cached parameter ends avoid overlapping suffix
scans. Source provenance keeps encoded whitespace, quotes and angle brackets
inside data. Non-rendering authority guards protect benign public userinfo from
flattened recovery scans, while sensitive assignments such as
`password=SYNTH@host` still redact. Known URL-valued public fields retain bare
userinfo recognition; arbitrary benign search values remain unchanged.

Test-only commit `307ff0f` records the initial failure on `69a7435d`: all four
reviewer witnesses fail across text/JSON/NDJSON, with 25,155 failing case/API
pairs in the initial outer-component cross-product. Test-only `d81085a` exposes
the nested credential-tail loss on the previous artifact. Test-only `4fee11b`
exposes the encoded-authority blocker on `7a08bee` before source edits: 42,765
failing case/API pairs in its initial cross-product. Additional relative-query
and assignment-guard regressions also have failing-before/passing-after evidence.

Coverage includes 84,840 outer component cases, 23,002 nested cases and 26,873
encoded-userinfo cases. The userinfo matrix has 25,821 positives and 1,052 benign
controls, crossing 22 authority delimiter spellings with seven reserved password
escapes, seven data styles, additional whole-URL encoding and four contexts.
Styles cover upper/lower hex, double encoding, numeric/named entity percent
signs, repeated percent prefixes and mixed reserved data. Five exact reviewer
encoded-authority witnesses, lexical data escapes and budget controls also run.
The property test includes both component data and fully encoded authorities.
Every API checks second-pass stability and original surrounding spelling.

All earlier gates remain unchanged: HTML punctuation 63,906; separator 12,512
including 188 benign controls; fix13 754; fix12 371+58 and exact 16 MiB; fix11 257;
matrix 1186/ruling 43/residual 19+17; earlier 27; Bearer 43+9;
complete 141/numeric 45; tables 34+13; frozen 199. There are zero fixture
expectation changes. Self-attacks cover percent-prefixed escapes, plus,
semicolon separators, fragments, encoded username colons, entity separators
without assignments and repeated nested prefixes. The original HTML timing
inputs, API calls, assertions and ten-second bounds remain unchanged.

Hosted Rust 1.88 passes 96 tests on each of Linux and Windows, plus fmt/clippy.
Node and Bun each pass 725 tests using 218,160 native text vectors and 218,165
structured vectors, with all 199 frozen witnesses. Contiguous 8,192-case parity
batches preserve every assertion and Bun's default watchdog. Frozen witnesses have zero
missed secrets or second-pass changes; Workers and independent-target
reproducibility pass. Normalization copies ordinary runs in bulk and clones
unchanged UTF-8 once; impossible userinfo/HTML scans return early. These changes
retain the unchanged 16 MiB test and Bun watchdog. The SHA256-verified hosted
package repeats Node725/Bun725 and Workers locally.

Hosted source, archive/package hashes, runtime counts and platform timings are
recorded in [the encoded-userinfo repair receipt](results/review-fixes.json)
under `encodedUserinfoLayerRepair`; historical receipts remain intact.
The version-only alpha.4 cut from reviewed head `77b89c60` is recorded under
`alpha4Release`, with new hosted artifact identities and unchanged engine/tests.
Its downloaded archive, embedded manifest and every payload digest were verified.
Precision: non-zero false positives remain.
[The artifact pin](results/artifact.json) and [CI receipt](results/ci.json)
identify the verified hosted package. Handoff requires one immutable exact-head
Linux, Windows and WASM CI run repeating every gate, including source, WASM,
glue, declarations, adapter and package pin equality.

The alpha.5 precision follow-up starts at published alpha.4 main `ba262739`.
Its test-first additions and source are recorded in `alpha5PrecisionRepair`.
All 194 unchanged benign cases fail on the published base; 491 positive/mixed
controls also fail per API. The 2,355-case shared fixture covers complete query
references, awaited calls and Rust reference aliases, with literal/encoding/tail
siblings and mixed literal-userinfo/query-reference controls. The successor
passes all precision cases and second-pass checks. Complete attribute guards
propagate through nested component/userinfo views; standalone URL recovery
remains active so whitespace tails cannot gain a prefix exemption.

The newline-only lookup optimization changes no compared output bytes across
220,515 native text and 220,520 JSON/NDJSON cases. Exact length-prefixed aggregate
hashes and the reconstruction recipe are in [the byte proof](results/alpha5-newline-proof.json).
The source/version manifest identities change as expected. No matrix input,
fixture expectation, API assertion, Bun watchdog or ten-second limit is relaxed.

The alpha.5 portable pin is the independently SHA256-verified [hosted implementation artifact](https://github.com/AgentWorkforce/relayscrubber/actions/runs/42941589608)
at `5843309e0d9bd0859c17736fb8f84bb5699ce3af`. Linux/Windows Rust98/fmt/clippy,
Node726/Bun726, Workers, independent WASM reproduction and packaging pass;
WASM fails only comparison with the superseded alpha.4 pin. Windows and Linux
timings pass unchanged ten-second limits; the receipt records every measurement.
Downloaded-package Node726/Bun726
and Workers replay pass with fresh 220,515 text and 220,520 structured vectors,
and frozen199 has zero misses or second-pass changes. The 63,906/84,840/26,873/
23,002 matrices and every earlier gate remain intact. Final handoff requires
ALL-green exact-head Linux, Windows and WASM, including equality with these
precise source/WASM/glue/declaration/adapter/package pins. No merge or publish.
