# Candidate validation results

Independent re-audit pending. Zero false positives is a release gate owned by
relayscrubber-lead; these invented regression tests do not certify precision.
No private session samples were accessed for this revision. No adoption, merge,
publication, tag, deployment or consumer change is authorized by these results.

The behavioral receipt is [results/review-fixes.json](results/review-fixes.json).
Test-only commit `258e7d2` precedes the implementation; `408ac1e` adds
failing-before generalized placeholder/member/type variants. All 14 named families fail
on base `5a1afa4428bbc73371ffb07d784821cbf266005c` natively and in the actual pinned
Linux WASM package. The expanded matrix covers 80 invented benign variants over
text, JSON `{text: ...}` and NDJSON. All variants remain byte-identical at head.
Some original literal examples already passed; every family has failing base
variants. The receipt records exact before/after counts rather than claiming
every original literal failed.

The shared fixtures include 23 positive controls and three structured cases.
The final bare-key policy preserves a generic key unless structure/context or a
reviewed provider shape establishes credential semantics. Exact public selectors
preserve nested generic keys; nested explicit credentials and
`request_idempotency_key` remain sensitive. The seven earlier review witnesses
remain exercised with this superseding bare-key policy.

Rust 1.88 all-target/all-feature tests (78), fmt, clippy and crate packaging pass. Node
and Bun pass 73 tests each, covering native/WASM text and structured byte parity,
second passes, multibyte 16 MiB text/record admission, 64 MiB stream admission,
tagged call refusals and poisoned-instance refusal. Independent target-directory
WASM reproduction and local Workers checks pass. Resource probes remain bounded.
The strict frozen gate runs in native and WASM CI and requires `headMissedSecretCases = 0`: all 199 witnesses
are exercised with zero annotated secret misses and zero second-pass changes.
Historical exact output formatting is not the current contract.

Manifest schema 3 / ABI 2 includes the crate-owned `scrubProfile`. The proposed
crate/npm release is `0.5.0-alpha.3`, npm `private: false`; it is not published.
The portable Linux pin is rebuilt through hosted CI. Final source, binary, glue,
adapter and package equality must pass before reviewer handoff; see the receipt
for the final immutable build links and digests.

The separator-class repair is recorded in `querySeparatorClassRepair` in the
behavioral receipt. Test-only commits `ca12fd1` and `db9beeb` precede implementation
`ca27985`. The generated property crosses 54 separator spellings, 38 sensitive
keys and six key encodings, plus the reviewer's exact 12-case matrix and six
benign controls: 12,330 cases over text, JSON and NDJSON with second-pass checks.
Base `b4f0252` fails 7,548 cases per API; the successor fails zero. Optional
semicolons, arbitrary leading zeros, nested named/numeric/percent layers and
encoded sensitive keys retain their original spelling around the replaced value.
Long key/entity/recovery probes pass unchanged ten-second limits on Linux and
Windows; entity atoms advance together to prevent overlapping suffix lookahead.

The refreshed pin comes from the SHA256-verified [hosted implementation artifact](https://github.com/AgentWorkforce/relayscrubber/actions/runs/42872959587).
Its Node73/Bun73, reproducibility and Workers checks pass; its only failed step
was comparison with the superseded pin. The hosted package was independently
hash-checked and replayed locally with fresh 19,357 text and 19,362 structured
vectors and all 199 frozen witnesses. Final handoff requires one immutable
exact-head ALL-green Linux, Windows and WASM CI run reproducing this pin.
