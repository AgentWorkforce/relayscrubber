# Evaluation protocol

`eval/generate.rs` is independent of engine patterns. It builds synthetic provider
formats and credential leak families from stable xorshift seeds, surrounds them
with code/log/JSON/shell/chat text, and records exact original secret byte ranges.
Complete recall requires a removed range to cover every annotated byte; merely
not finding the full original token is insufficient. Tests use four seeds and
check idempotence. Providers and encoded malformed/public tails are reported
separately. New formats require both positive and benign boundary controls.

Benign synthetic classes cover hashes/digests, UUIDs, identifiers, paths, URLs,
public replay selectors, base64 assets and prose containing contacts/timestamps.
The generator never classifies a high-entropy string as a secret by itself.
`cargo run --release --example evaluate -- 24301` emits counts and timings only.
Excess removed bytes are reported separately from missed-secret bytes, including
intentional whole-header removal.

Real data is kept only in `~/scrubber-eval` (directory 0700, files 0600). No raw
sample, session ID, quote, credential or matched excerpt belongs in git, tool
output, reports or messages. `eval/collect-public.py` fixes its source-level
public dev/held-out split before downloading: Git v2.51.0 manuals and public-domain
literature. It records source hashes privately. The public dataset measures real
benign prose/technical text; it does not represent every production code/log mix.

An additional four-session workspace sample was split into two dev and two
held-out sessions before reading. Only bounded complete events are measured;
truncated events are excluded. No sample is inspected or copied to create a test.
Unlabelled session detection counts are **candidate rate, not false-positive
rate**: real credentials and intended credential-labelled examples may occur.
Do not claim production-session precision from those counts. Any future inspected
finding must become a newly written synthetic case and must never copy a sample.

Freeze the engine source digest before evaluating held-out data. Evaluate held-out
once, report its result even if unfavorable, and do not tune on it. An engine
change after that point requires a fresh held-out set for a new unseen-data claim.
Synthetic alternate seeds test body variation, not unseen secret-format families.

A transport-only serializer change may retain text observations when all native
recognition/parser/dependency sources are verified byte-identical. Record both
the original evaluation digest and new artifact digest; do not relabel the old
observation as a new held-out run or re-read that set. Transport fidelity requires
its own synthetic assertions, including integer identifiers above JavaScript's
exact-number range.

Private precision tools:

```sh
python3 eval/collect-public.py
cargo +1.88.0 run --release --example evaluate -- --public "$HOME/scrubber-eval/public-split.json" dev
# Only after freezing the candidate:
cargo +1.88.0 run --release --example evaluate -- --public "$HOME/scrubber-eval/public-split.json" heldout
```

Delete all owned raw evaluation samples and parity-vector files by 2026-11-16;
this run deletes its private inputs after aggregating final metrics. Keep only
aggregate results, public source URLs/checksums and source/artifact identities.

Review-fix session audit: `session_precision` emits counts only. The newly
collected four-session dev and one-session held-out sample is unlabelled; report
candidate counts separately from measured false positives on synthetic benign
controls. Code-reference, constant, shell-reference and malformed quote/YAML
shapes found during dev auditing have new synthetic controls. Never equate an
unlabelled candidate rate with ground-truth session precision.

The follow-up local content audit classifies each changed span as confirmed
false positive, confirmed real secret, or ambiguous. It uses conservative lexical
evidence and per-rule private native traces with canonical byte/range parity; it
is not independent human or live-credential ground truth. Report all ambiguous
spans by rule, and never count them as proven true secrets. Initial type/call and
placeholder findings have synthetic controls and fixes. After any engine fix,
the previously evaluated held-out sample is regression evidence; a new unseen
set is needed for renewed held-out acceptance. Counts are in
`docs/results/review-fixes.json`; private values and span records stay outside git.
