# ar-lap disclosure qualification (offline)

The expanded disclosure contract **fails** at relayscrubber PR #21 candidate
`b54745161cade161318e6e1dc9ca5486b91c474d`. This harness makes no engine changes,
reads no session stores, and does not deploy or re-pin the ar-lap fixture.

The fixture identity snapshot is Desktop Kind `2026.11.1-beta.6`, build 306,
source `06164e88bcf7bd77f49d5979527f0d5aafb8b450`, and sessions-pipeline
`sha256:77022c5b6a1d30f96f921d703eb27a1acada8ec273ad84aebdde24f8eddce305`,
source `7e9b2f0f6b1af7af9b49087c4f4677f5d6d1a496`. Both carry **alpha.5**.
The proposed upgrade is alpha.5 to alpha.9; it is not deployed by this work.
The later [exact hosted-artifact audit](pr21-hosted-scoped-audit.md) separates
PR21's tested intent subset from this broader grammar and records the 162
short-value misses as required fixes with no minimum length. Its subset pass
does not qualify PR21 or supersede this broad FAIL.
The literal/session-body trace is closed by request. No earliest leaking
upload layer is inferred from this offline test.

## Results

The deterministic corpus contains 7,126 invented disclosures and 45 benign
controls. Every case runs as text, JSON, and NDJSON against native alpha.5,
native alpha.9, WASM alpha.5, and WASM alpha.9: 86,052 observations total.
Counts below are unique corpus cases per engine, not three-form totals.

| Engine | Disclosures with incomplete redaction | Benign changed |
| --- | ---: | ---: |
| Desktop native alpha.5 | 6,119 / 7,126 | 0 / 45 |
| Pipeline WASM alpha.5 | 6,119 / 7,126 | 0 / 45 |
| Desktop native alpha.9 | 5,254 / 7,126 | 0 / 45 |
| Pipeline WASM alpha.9 | 5,254 / 7,126 | 0 / 45 |

Native/WASM decoded outputs match exactly for each version. No refusals,
structural corruption, public-marker loss, or idempotence failures occurred.
All seven oracle/generator tests pass. The qualification command exits 1
because the candidate misses disclosure coverage; this is the expected
failure signal, not a tool crash.

Representative **invented** counterexamples, on both alpha.9 paths:

| Input after public marker | Observed result |
| --- | --- |
| `my password is q` | Unchanged |
| `my password is !` | Unchanged |
| `my password is velvet river lantern` | `my password is [REDACTED] river lantern` |
| `my password\nis synthetic-amber#47` | Unchanged |
| `my password is\nnow synthetic-cobalt#53` | Unchanged |
| Two quoted disclosures using `password` then `pass` | First redacted; second retained |

The native alpha.9 distinct-case miss counts by group are: grammar 3,636,
line breaks 648, split connectors 27, quoted multiline values 36,
unmatched quotes 10, multiple disclosures 97, seeded mutations 800.

The machine report is
[`../docs/results/arlap-disclosure-qualification-b547451.json`](../docs/results/arlap-disclosure-qualification-b547451.json).
It contains dimensions, hashes, observed artifact identities, and a few
invented counterexamples. Full synthetic corpus and per-observation failures
are regenerated locally into ignored `.task-tmp/qualification/`.

## Reproduce

Use the candidate source above plus these test-only harness files. Dependencies:
Rust 1.88.0 with `wasm32-unknown-unknown`, wasm-bindgen CLI 0.2.104, Python 3,
and Node. The native seam preparation requires authorized read access to the
Desktop repository at the pinned source. It copies private source only into
ignored `.task-tmp/`; **do not commit or distribute those copies**.

1. Place the published alpha.5 JS package under
   `.task-tmp/alpha5-release/package/`. Its release archive
   `agentworkforce-relayscrubber-0.5.0-alpha.5.tgz` SHA-256 is
   `bc4101df467ba520e16b8b8d766c63a9017631a6551a369ee100b34e47de441b`.
   The runner independently validates the WASM against its artifact manifest.
2. Run `python3 scripts/prepare-arlap-probes.py --desktop-repo /path/to/relay-desktop`.
3. Build both generated projects:

   ```sh
   CARGO_TARGET_DIR="$PWD/.task-tmp/native-target" cargo +1.88.0 build --manifest-path .task-tmp/native-alpha5/Cargo.toml
   CARGO_TARGET_DIR="$PWD/.task-tmp/native-target" cargo +1.88.0 build --manifest-path .task-tmp/native-alpha9/Cargo.toml
   bash scripts/build-wasm.sh
   node --test js/test/disclosure-coverage-oracle.test.mjs
   node scripts/qualify-arlap-disclosures.mjs --seed 24301 --fuzz-count 1024
   ```

The native probe calls the shipped Desktop `ScrubEngine` upload seam with its
original alpha.5 crate, or a candidate crate and a test-only version marker
adjustment. It does not exercise the Desktop delivery queue or transport.
WASM uses `scrubTextChecked`, `scrubJson`, and `scrubRecords`; these exercise
engine APIs, not a deployed pipeline or S3 persistence. Alpha.9 WASM was built
locally; the reported hash is not claimed to be a published artifact. The
candidate's last commit changed documentation only, so the engine binaries
built at parent `8213b34` have the same engine source tree.

The oracle requires protected input spans to disappear completely, catching
partial suffix leaks and short values even when the same character occurs in
public text. Benign controls separately measure precision and retain valid
case-sensitive code syntax. Seeded generation samples the requested grammar;
it cannot prove detection of every possible natural-language disclosure.
