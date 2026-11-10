# relayscrubber

The canonical offline Rust secret scrubber for Agent Relay, compiled unchanged
for native clients and WASM hosts. JavaScript contains transport and identity
checks only. This branch is **0.5.0-alpha.1 / candidate ruleset 10**. It is not
approved for adoption or publishing. See [SPEC](docs/SPEC.md),
[MIGRATION](MIGRATION.md), [performance](docs/PERFORMANCE.md) and
[evaluation](docs/RESULTS.md).

Default policy removes recognizable provider tokens, compact JWT/JWE tokens,
private keys and credential-labelled values in code, env, JSON, YAML, flags,
headers, cookies, connection strings and signed URLs. It preserves ordinary
prose, hashes, UUIDs, public identifiers, file paths, contact details and URLs
without credentials. `Policy::Pii` explicitly adds email and SSN shapes.
No detector can identify arbitrary unlabelled passwords or custom encodings.

```rust
use relayscrubber::{scrub_text, scrub_json, scrub_records, manifest};

// Intentionally invalid synthetic example.
assert_eq!(scrub_text("password=\"SYNTH_ALPHA SYNTH_BETA\""),
           "password=\"[REDACTED]\"");
let (value, changes) = scrub_json(&serde_json::json!({"password":"SYNTHETIC"}));
assert_eq!(changes, 1);
let records = scrub_records(b"{\"status\":\"ok\"}\n").unwrap();
assert_eq!(records.record_count, 1);
assert_eq!(manifest().ruleset_version, 10);
```

`scrub_text` and `scrub_long` scan the complete input identically. They do not
truncate or split secrets across chunks. `scrub_json` scrubs every key and value,
retains public-property context through descendants and resolves key collisions.
`scrub_json_text` returns `None` for invalid JSON: discard the original. Always
serialize returned JSON, even when the redaction count is zero. `scrub_records`
is an atomic UTF-8 NDJSON interface with deterministic, content-free errors;
limits are 16 MiB per record and 64 MiB per operation. No partial output escapes
an error. JSON recursion is bounded at 128 levels.

`manifest()` returns ruleset family/version, source digest, ABI, crate version
and policy. The source digest includes ordered Rust sources, build script,
pinned toolchain, original Cargo manifest and lockfile with LF normalization and
path sentinels. A compiled WASM artifact has its own SHA-256. Consumers pin both
independently of the downloaded package. Native consumers commit and audit their
resolved dependency lockfile as well.

The former TypeScript oracle and Rust v8 port are frozen under `vendor/` for
provenance; they are not compiled or included in the new crate package. Existing
stored data must never be relabelled as ruleset 10. Ruleset 9 is reserved for the
abandoned pipeline candidate. Security-owner confirmation of candidate 10 and an
exact-commit PASS remain required before merging or publishing.

Development (Rust 1.88.0 and wasm-bindgen CLI 0.2.104):

```sh
cargo +1.88.0 fmt --all -- --check
cargo +1.88.0 clippy --all-targets --all-features -- -D warnings
cargo +1.88.0 test --all-targets --all-features --locked
bash scripts/build-wasm.sh
mkdir -p "$HOME/scrubber-eval"
chmod 700 "$HOME/scrubber-eval"
(umask 077; cargo +1.88.0 run --release --example wasm_vectors > "$HOME/scrubber-eval/wasm-vectors.json")
node --test js/test/wasm.test.mjs
bun test js/test/wasm.test.mjs
cargo +1.88.0 run --release --example evaluate -- 24301
```

No publish command is part of this workflow. Never put real credentials or
transcript excerpts in fixtures, commits, CI output, reports or relay messages.
