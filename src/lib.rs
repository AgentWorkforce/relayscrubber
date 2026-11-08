// Preserve the reviewed rule expressions byte-for-byte with the Desktop port.
#![allow(clippy::nonminimal_bool)]

//! Technical Foul: deterministic, offline secret and PII scrubbing shared by
//! Agent Relay clients and the relayhistory ingest contract.
//!
//! [`scrub_long`] is the upload-safe entry point. It segments arbitrarily long
//! text at boundaries proven safe against the canonical rule set and replaces
//! an uncuttable remainder wholesale rather than uploading a partial scrub.
//! [`scrub_text`] is the bounded Cloud-compatible primitive and may truncate.

mod rules;

use serde::Serialize;

pub use rules::{
    scrub_json, scrub_json_text, scrub_long, scrub_text, MAX_SCRUB_CHARS,
    PINNED_RULESET_SOURCE_SHA256, REDACTION_TOKEN, RULESET_VERSION,
};

/// Stable history contract name written as `raw.scrub.ruleset`.
pub const SCRUB_RULESET: &str = "relayhistory-scrub";

/// Compatibility alias for the Cloud's exported constant name.
pub const SCRUB_RULESET_VERSION: u32 = RULESET_VERSION;

/// Compatibility alias for the canonical combined rule-and-segmenter digest.
pub const RULESET_SOURCE_SHA256: &str = PINNED_RULESET_SOURCE_SHA256;

/// SHA-256 of the ordered Rust rule-module sources, including path sentinels.
/// This detects accidental port drift separately from the canonical TS digest.
pub const RUST_PORT_SHA256: &str =
    "38c67e2373be5be72c9272ff543a06749474964a3419c8755b213a6c56dad18f";

/// SHA-256 of the canonical secret corpus after CRLF-to-LF normalization.
pub const CORPUS_SHA256: &str = "9a80b081d2ab1a2be7a9f36e73bcf6f27861b7096418a372ce12b567be52a860";

/// SHA-256 of the canonical marked raw-chunk segmenter alone.
pub const SEGMENTER_SHA256: &str =
    "83392705f4d8c06e745a56f5bd549c890cc82404d06bfdc37a7937ad967f7fed";

/// Canonical corpus bytes, vendored byte-for-byte for consumer lockstep tests.
pub const CORPUS_BYTES: &[u8] = include_bytes!("../vendor/corpus/scrub-secret-corpus.json");

/// Canonical corpus text, vendored byte-for-byte for consumer case runners.
pub const CORPUS_JSON: &str = include_str!("../vendor/corpus/scrub-secret-corpus.json");

/// Canonical schema-1 manifest bytes.
pub const MANIFEST_BYTES: &[u8] = include_bytes!("../vendor/canonical/technical-foul.json");

/// Canonical schema-1 manifest text.
pub const MANIFEST_JSON: &str = include_str!("../vendor/canonical/technical-foul.json");

/// Ten-field distribution manifest exchanged by Technical Foul implementors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TechnicalFoulManifest {
    /// Manifest schema version.
    pub schema: u32,
    /// Canonical ruleset version stored in the history contract.
    pub ruleset_version: u32,
    /// SHA-256 of canonical `scrub.ts` plus the marked segmenter.
    pub ruleset_source_sha256: &'static str,
    /// Canonical repository-relative rules source path.
    pub ruleset_path: &'static str,
    /// Canonical repository-relative marked segmenter path.
    pub segmenter_path: &'static str,
    /// SHA-256 of the marked segmenter alone.
    pub segmenter_sha256: &'static str,
    /// SHA-256 of the canonical corpus.
    pub corpus_sha256: &'static str,
    /// Canonical repository-relative corpus path.
    pub corpus_path: &'static str,
    /// Stable replacement token.
    pub redaction_token: &'static str,
    /// Per-segment bound in UTF-16 code units.
    pub max_scrub_chars: usize,
}

/// Return the complete compile-time Technical Foul compatibility manifest.
///
/// This distribution manifest is intentionally distinct from the two-field
/// [`RawScrubMarker`] persisted in history chunk manifests.
#[must_use]
pub const fn manifest() -> TechnicalFoulManifest {
    TechnicalFoulManifest {
        schema: 1,
        ruleset_version: RULESET_VERSION,
        ruleset_source_sha256: PINNED_RULESET_SOURCE_SHA256,
        ruleset_path: "packages/pipeline/src/lib/scrub.ts",
        segmenter_path: "packages/pipeline/src/lib/pipeline/raw-chunks.ts#scrub-segmenter",
        segmenter_sha256: SEGMENTER_SHA256,
        corpus_sha256: CORPUS_SHA256,
        corpus_path: "packages/pipeline/test/fixtures/scrub-secret-corpus.json",
        redaction_token: REDACTION_TOKEN,
        max_scrub_chars: MAX_SCRUB_CHARS,
    }
}

/// The exact `raw.scrub` marker persisted in a sealed history chunk manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RawScrubMarker {
    /// Stable scrubber family name.
    pub ruleset: &'static str,
    /// Version of the rules and segmenter applied to the stored bytes.
    pub version: u32,
}

/// Return the exact two-field marker for successfully scrubbed history bytes.
///
/// Callers must persist this marker only after scrubbing the corresponding
/// bytes. It serializes as `{"ruleset":"relayhistory-scrub","version":3}`.
#[must_use]
pub const fn raw_scrub_marker() -> RawScrubMarker {
    RawScrubMarker {
        ruleset: SCRUB_RULESET,
        version: SCRUB_RULESET_VERSION,
    }
}
