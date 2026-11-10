# Candidate validation results

Independent re-audit pending. Zero false positives is a release gate owned by
relayscrubber-lead; these invented regression tests do not certify precision.
No private session samples were accessed for this revision. No adoption, merge,
publication, tag, deployment or consumer change is authorized by these results.

The behavioral receipt is [results/review-fixes.json](results/review-fixes.json).
Test-only commit `258e7d2` precedes the implementation. All 14 named families fail
on base `5a1afa4428bbc73371ffb07d784821cbf266005c` natively and in the actual pinned
Linux WASM package. The expanded matrix covers 72 invented benign variants over
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

Native all-target/all-feature tests, fmt, clippy and crate packaging pass. Node
and Bun pass 36 tests each, covering native/WASM text and structured byte parity,
second passes, multibyte 16 MiB text/record admission, 64 MiB stream admission,
tagged call refusals and poisoned-instance refusal. Independent target-directory
WASM reproduction and local Workers checks pass. Resource probes remain bounded.
The strict frozen gate runs in native and WASM CI and requires `headMissedSecretCases = 0`: all 199 witnesses
are exercised with zero annotated secret misses and zero second-pass changes.
Historical exact output formatting is not the current contract.

Manifest schema 3 / ABI 2 includes the crate-owned `scrubProfile`. The proposed
crate/npm release is `0.5.0-alpha.2`, npm `private: false`; it is not published.
The portable Linux pin is rebuilt through hosted CI. Final source, binary, glue,
adapter and package equality must pass before reviewer handoff; see the receipt
for the final immutable build links and digests.
