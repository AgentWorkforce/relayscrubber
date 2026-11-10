# Migration to one Rust engine

Candidate only. Integration owners must wait for an immutable relayscrubber-lead
PASS and green CI before adoption. Registry publication additionally requires
Khaliq's own authorization. This work changes neither relay-desktop nor
relayhistory-pipeline. No registry release is assumed.

## Identity and compatibility

Use the exact reviewed Git commit during development; later pin the exact approved
crate/package release and checksums. Rule semantics originate in this repository.
Stop porting or comparing new behavior to `scrub.ts`. Historical TS fixtures are
regression evidence only. Rule changes need a new ruleset version and source digest;
never reuse 8/9 or rewrite sealed metadata. Candidate version 10 still needs owner
reservation confirmation. Store crate-owned `scrubProfile`, policy and source digest alongside family/version.
The secrets profile is `relayhistory-secrets-v10`; native PII policy uses
`relayhistory-pii-v10`. Consumers must never invent or substitute this field.

The new manifest is schema 3 / transport ABI 2; old TS source, segmenter and corpus digest exports
are removed. `scrub_text` no longer truncates at a UTF-16 limit. `scrub_long` uses
the same complete-string scan. JSON key order/collisions are deterministic; do not
compare raw object insertion order to v8. Changed-node count never certifies raw
JSON safety. Duplicate keys use last-value parsing semantics. Serialize the result.
Default emails, paths, phones and standalone numbers are preserved; email/SSN
redaction requires explicit native `Policy::Pii` and its policy identity. The JS
ABI currently exposes the default secrets policy only.

Errors mean discard original bytes. Never catch a scrub error and return the
original input. Native `scrub_json_text` returns `None`; WASM throws serialized tagged errors; the JS adapter throws `ScrubberError`
with stable `code`, `disposition` and optional `record` fields.
NDJSON returns `Result<RecordOutput, RecordError>` with count, bytes and stable
one-based physical line numbers. No partial output is supplied. `call_refusal` rejects only that operation; a
subsequent independent call may proceed. Admission codes are `text_too_large`,
`record_too_large`, `stream_too_large`, `json_too_deep`, `invalid_json`,
`invalid_utf8`; invalid JS argument types use `scrubber_invalid_input`.
Unexpected engine/transport failures use `scrubber_engine_failure` with
`disposition: "instance_poison"`; every later call refuses with
`scrubber_instance_poisoned`. Initialization traps use
`scrubber_initialization_failure` and poison the loader. Artifact, module and
manifest validation mismatches refuse the load call without poisoning a verified
existing instance. A poisoned adapter must be discarded and recreated in a fresh
runtime/module realm; retrying original input through the poisoned instance is
not supported. Empty physical
lines are ignored. A final newline is optional. Stream/record limits are 64/16 MiB.

The JS `scrubJson` result includes `jsonText`, the Rust-serialized output. Persist
that string rather than reserializing `.value`: the convenience JS view uses
IEEE-754 numbers and can round integers above 2^53. Rust's supported `u64`/`i64`
integer domain remains exact in `jsonText` and NDJSON bytes. This is not arbitrary
precision JSON; inputs outside serde_json's numeric domain can normalize or fail.

## Desktop owner

Pin the approved crate and resolved Cargo.lock before integration. Call the crate
at the capture boundary **before the first local database write**, including text,
messages, titles, tool arguments/results and metadata keys/values. Store only the
returned JSON or scrubbed text plus its manifest identity. Do not retain raw input
in indexes, caches, retries, diagnostics, crash payloads or background queues.

Scrub the upload representation again with the same approved identity immediately
before queueing/uploading. Idempotence makes this safe and covers derived text.
For record input, validate UTF-8 and JSON through `scrub_records` atomically before
opening the persistence transaction. Record count is available only on success.
Treat binary attachments separately: this text engine does not inspect images,
archives, compressed data or arbitrary file formats. Never label them scrubbed by
this text ruleset. Storage/backfill/schema changes belong to Desktop's owner.

## Bun and Node pipeline owner

Build once with `bash scripts/build-wasm.sh`. This pins Rust 1.88.0,
wasm32-unknown-unknown, Cargo.lock and wasm-bindgen 0.2.104. The generated ESM glue,
types, WASM and `artifact.json` are under `js/generated`. `npm pack --ignore-scripts`
in `js/` creates a local package; it does not authorize registry publishing.

```js
import { readFile } from 'node:fs/promises';
import { loadScrubber } from '@agentworkforce/relayscrubber';

const scrubber = await loadScrubber({
  bytes: new Uint8Array(await readFile(wasmPath)),
  expectedManifest: approvedManifest,       // pinned in trusted application config
  expectedWasmSha256: approvedWasmSha256,  // pinned independently of the package
});
const { bytes, recordCount } = scrubber.scrubRecords(inputBytes);
// Only now may the caller persist or upload bytes and the manifest identity.
```

Use this canonical JS loader and its generated wasm-bindgen glue. This artifact
imports `wbg` functions; it cannot be instantiated with empty imports. It does
not implement the placeholder raw `scrub_alloc` / `scrub_result_*` interface.
Replace that consumer adapter rather than changing only its artifact pins.

Initialization hashes bytes using WebCrypto and checks every manifest field. No
network fetch occurs. Failure blocks startup/admission. Do not derive expected
pins exclusively from the same downloaded artifact you are trying to verify.
Commit the approved pins to the consuming application; verify the package/glue
hashes from the review receipt too. Keep the WASM instance private to the adapter.

The portable Linux CI package is the pipeline artifact candidate; its pins are
in `docs/results/ci.json`. Native Mac development WASM builds have matching source
identity and parity but different binary bytes. Reproduction is verified within
a builder environment; cross-host byte identity is not claimed. Use the same
reviewed CI binary everywhere and pin its digest, not a local development digest.

Replace all server scrub paths (normalization, raw chunks, task fields, exports,
replays and NDJSON ingestion) together. Segment only **after** complete scrubbing;
never scrub independent arbitrary windows. Preserve JSON public context through
normalization and never bypass the adapter for a zero-change result. Review
sealed-object version acceptance and rollout/rollback rules with pipeline owners:
old readers may reject version-10 objects, so a plain image rollback may be unsafe.

## Cloudflare Workers owner

Workers use a statically imported WebAssembly.Module; runtime compilation from
arbitrary byte buffers is unavailable. Verify the exact `.wasm` SHA-256 against
the approved pin **before bundling** with `scripts/verify-artifact.mjs`, then import
that same file. Call `loadCompiledScrubber({module, expectedManifest})` at startup.
The embedded ruleset/source/ABI/policy identity is checked at startup.

A compiled Module is opaque: JavaScript cannot recover and hash its original
bytes. This API does not claim runtime artifact-byte verification for a Module.
The build must enforce the binary pin and startup must enforce the source pin.
`js/worker/` is a local workerd smoke fixture, not a deployment configuration for
the product. No deployment is performed by this repository's verification.

## Adoption checklist owned by integrators

Require exact-commit security PASS and passing native/WASM/Node/Bun/Workers tests;
verify reproducible binary and source pins; exercise malformed record rejection
and storage ordering; verify every storage/upload path; canary only with the
owner's rollout plan. No fail-open compatibility shim, relabelling, registry
publish, tag, yank, main push or cross-repository edits are authorized here.

## Proposed release

Crate and npm candidate version: **0.5.0-alpha.2**, with npm `private: false` so
this head is packageable for an authorized release. This version is proposed for
review only. No registry publish, tag, merge, deployment or consumer edit is
performed. Independent re-audit pending; zero false positives is a release gate.
