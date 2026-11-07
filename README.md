# relayscrubber

`relayscrubber` is the standalone Rust implementation of Agent Relay’s
**Technical Foul** secret and PII scrubber. It is library-first, deterministic,
offline at runtime, and shared by clients that must produce the same sanitized
history bytes as the server-side relayhistory ingest path.

The current compatibility tuple is:

- ruleset: `relayhistory-scrub`
- version: `3`
- rules/source SHA-256: `e7607073a3afca3db6b015945f0b5fab256202f355b740f515987ec162bf3076`
- Rust port SHA-256: `5ceb3661f10c6e5f8004b23c8e7bcfbad915947422bebf04a4b4d252a201ba15`
- corpus SHA-256: `9a80b081d2ab1a2be7a9f36e73bcf6f27861b7096418a372ce12b567be52a860`
- replacement: `[REDACTED]`
- per-string bound: 262,144 UTF-16 code units

## Use

Until a crates.io release is desired, consumers should pin a release tag:

```toml
[dependencies]
relayscrubber = { git = "https://github.com/AgentWorkforce/relayscrubber", tag = "v0.1.0" }
```

```rust
use relayscrubber::{manifest, scrub_text, CORPUS_SHA256, SCRUB_RULESET_VERSION};

let clean = scrub_text(r#"Authorization: Bearer synthetic-token-value-123456"#);
assert_eq!(clean, "Authorization: Bearer [REDACTED]");

let compatibility = manifest();
assert_eq!(compatibility.ruleset_version, SCRUB_RULESET_VERSION);
assert_eq!(compatibility.corpus_sha256, CORPUS_SHA256);
```

`scrub_text` returns `Cow<str>`: unchanged input remains borrowed. Regex passes
use Rust’s finite-automata engine, scans and custom lookups are bounded, and the
implementation performs no I/O or network access. Inputs beyond the canonical
bound follow the same safe-whitespace truncation contract as `scrub.ts` and
announce truncation in-band. `scrub_json` recursively scrubs JSON keys, string
values, and card-shaped integral numbers; scrubbed key collisions are preserved
with numbered suffixes.

## History schema and contract

This crate has exactly two integration boundaries:

1. The relayhistory schema records the scrub marker. A sealed history chunk
   writes `raw.scrub.ruleset = "relayhistory-scrub"` and
   `raw.scrub.version = 3`; object metadata uses `scrub-ruleset` and
   `scrub-version` with the same values. Existing chunks are never relabeled.
2. The history database contract uses that marker to distinguish scrubbed and
   unsanitized history. Callers must persist the exported ruleset/version only
   after this crate has successfully scrubbed the bytes they store.

There is intentionally no database driver, relayhistory runtime dependency,
desktop dependency, transport, telemetry, or network client in this crate.
Schema owners map the exported constants into their own generated schema types.

## Canonical artifact and lockstep policy

`vendor/canonical/technical-foul.json` is the schema-1 manifest agreed with
relayhistory-pipeline. The repository also vendors the canonical `scrub.ts`,
the marked segmenter’s containing source, and the secret corpus for provenance
and offline verification. Runtime code does not import those files.

Changes are atomic across owners:

1. relayhistory-pipeline changes `scrub.ts` and/or its marked segmenter, bumps
   `SCRUB_RULESET_VERSION`, updates digest pins and `technical-foul.json`, and
   updates the corpus when needed.
2. relayscrubber vendors those exact artifacts, ports the behavior, and updates
   its exported constants in one release.
3. `cargo test` must pass the source/corpus digest locks and every corpus vector.
   `bun scripts/parity-with-typescript.ts /path/to/relayhistory-pipeline` then
   runs a direct byte-for-byte comparison against canonical `scrub.ts`.
4. relay-desktop updates its Cargo tag only after that release is available.

The TypeScript server remains canonical for version 3. It may later consume
this crate through WASM or a native binding, but this crate does not require or
assume that migration.

## Development

```sh
export TMPDIR="$PWD/.task-tmp"
mkdir -p "$TMPDIR"
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
bun scripts/parity-with-typescript.ts ../relayhistory-pipeline
```

The corpus contains placeholders and generators, not live credentials. Never
replace those placeholders with real or secret material.
