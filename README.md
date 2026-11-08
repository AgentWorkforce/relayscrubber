# relayscrubber

`relayscrubber` is the standalone Rust implementation of Agent Relay’s
**Technical Foul** secret and PII scrubber. It is library-first, deterministic,
offline at runtime, and shared by clients that must produce the same sanitized
history bytes as the server-side relayhistory ingest path.

The crate uses Rust 2021, has an MSRV of 1.88, and CI builds and tests it on
Linux and Windows. Its runtime dependencies are only `serde` and `serde_json`.

The current compatibility tuple is:

- ruleset: `relayhistory-scrub`
- version: `3`
- rules/source SHA-256: `e7607073a3afca3db6b015945f0b5fab256202f355b740f515987ec162bf3076`
- corpus SHA-256: `9a80b081d2ab1a2be7a9f36e73bcf6f27861b7096418a372ce12b567be52a860`
- replacement: `[REDACTED]`
- per-string bound: 262,144 UTF-16 code units

## Use

Consumers should pin the exact crates.io release:

```toml
[dependencies]
relayscrubber = "=0.2.1"
```

```rust
use relayscrubber::{manifest, raw_scrub_marker, scrub_long, CORPUS_SHA256, SCRUB_RULESET_VERSION};

let clean = scrub_long(r#"Authorization: Bearer synthetic-token-value-123456"#);
assert_eq!(clean, "Authorization: Bearer [REDACTED]");

let compatibility = manifest();
assert_eq!(compatibility.ruleset_version, SCRUB_RULESET_VERSION);
assert_eq!(compatibility.corpus_sha256, CORPUS_SHA256);

let stored_marker = raw_scrub_marker();
assert_eq!(stored_marker.ruleset, "relayhistory-scrub");
assert_eq!(stored_marker.version, 3);
```

Use `scrub_long` for uploads. It handles arbitrary input in segments proven
safe against the complete rule pipeline. If a remainder has no safe cut, the
entire remainder becomes `[REDACTED]`; no partial scrub is returned or sent.
`scrub_text` is the bounded Cloud-compatible primitive: input past 262,144
UTF-16 units is cut after safe whitespace (and before an open private-key
block), with the canonical truncation note appended.

The implementation hand-ports the 31 rules in canonical order over UTF-16,
including JavaScript whitespace, word-boundary and case semantics. It uses no
regex engine, unsafe code, async runtime, platform-specific code, I/O, or
network access. All scans and cut-search budgets are bounded.

`scrub_json` returns `(Value, redaction_count)` after scrubbing every key,
string value and card-shaped integral number. Key collisions receive numbered
suffixes in JavaScript `Object.entries` order. `scrub_json_text` parses with
document order preserved, applies collision suffixes in that order, and
returns `None` for invalid, out-of-range, or more-than-128-level JSON. The crate does not enable
`serde_json`'s `preserve_order` or `arbitrary_precision` features, so adding it
does not change JSON behavior elsewhere in a consumer's dependency graph.
The returned `Value` serializes in the map order selected by the consumer's
`serde_json` features; document order controls collision naming, not output
byte order.

## History schema and contract

This crate has exactly two integration boundaries:

1. The relayhistory schema records the scrub marker. A sealed history chunk
   writes `raw.scrub.ruleset = "relayhistory-scrub"` and
   `raw.scrub.version = 3`; object metadata uses `scrub-ruleset` and
   `scrub-version` with the same values. Existing chunks are never relabeled.
2. The history database contract uses that marker to distinguish scrubbed and
   unsanitized history. Callers must persist the exported ruleset/version only
   after this crate has successfully scrubbed the bytes they store.

`raw_scrub_marker()` returns exactly the persisted two-field marker
`{"ruleset":"relayhistory-scrub","version":3}`. It is separate from
`manifest()`, which returns the ten-field Technical Foul distribution manifest
used by independent implementations to pin source, segmenter, and corpus.

There is intentionally no database driver, relayhistory runtime dependency,
desktop dependency, transport, telemetry, or network client in this crate.
Schema owners map the exported constants into their own generated schema types.

## Canonical artifact and lockstep policy

`vendor/canonical/technical-foul.json` is the schema-1 manifest agreed with
relayhistory-pipeline. The repository also vendors the canonical `scrub.ts`,
the marked segmenter’s containing source, and the secret corpus for provenance
and offline verification. The scrub implementation performs no fixture I/O;
the manifest and corpus are compiled only into the explicit public exports.

The public `manifest()` exposes all ten schema-1 fields. `MANIFEST_BYTES`,
`MANIFEST_JSON`, `CORPUS_BYTES`, and `CORPUS_JSON` let consumers run the same
lockstep and corpus cases without maintaining another private fixture copy.

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

For upload safety the crate deliberately matches the reviewed Desktop behavior
where the Cloud currently refuses input: it also tries a verified comma cut for
compact text, and replaces an uncuttable remainder wholesale. The comma
fallback is disabled when a URL scheme occurs before the cut because unbounded
userinfo cannot be proven safe with finite context. Until the canonical rule
owns the same regression, an over-cap quoted secret also makes `scrub_long`
redact the whole input rather than expose its suffix. The crate additionally
checks exact unsigned JSON integers for cards and retains `__proto__` as an
ordinary key. Each divergence has a dedicated test.

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
