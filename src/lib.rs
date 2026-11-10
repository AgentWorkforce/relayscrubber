//! Deterministic offline secret scrubbing, canonical in Rust on native and WASM.
//! See `docs/SPEC.md` for the recognition and precision contract.

mod engine;
mod json;
mod normalize;
#[cfg(feature = "wasm")]
mod wasm;

pub use json::{
    scrub_json, scrub_json_checked, scrub_json_text, scrub_json_text_checked,
    scrub_json_with_policy, scrub_records, RecordError, RecordOutput,
};
use serde::{Deserialize, Serialize};

/// Stable scrubber family persisted with successfully scrubbed bytes.
pub const SCRUB_RULESET: &str = "relayhistory-scrub";
/// Candidate version; adoption requires independent exact-commit approval.
pub const RULESET_VERSION: u32 = 10;
/// Compatibility spelling for the history contract.
pub const SCRUB_RULESET_VERSION: u32 = RULESET_VERSION;
/// Replacement for every recognized credential.
pub const REDACTION_TOKEN: &str = "[REDACTED]";
/// Crate-owned default policy profile persisted with successful output.
pub const SCRUB_PROFILE: &str = "relayhistory-secrets-v10";
/// Serialized manifest schema version.
pub const MANIFEST_SCHEMA: u32 = 3;
/// Tagged-error JS transport ABI version.
pub const ABI_VERSION: u32 = 2;
/// SHA-256 of ordered Rust sources with path sentinels, generated at build time.
pub const RULESET_SOURCE_SHA256: &str = env!("RELAY_SCRUB_SOURCE_SHA256");
/// Maximum JSON nesting; excessive nesting never returns original content.
pub const MAX_JSON_DEPTH: usize = 128;
/// Maximum bytes in one NDJSON record, excluding its newline delimiter.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes in one atomic record operation.
pub const MAX_STREAM_BYTES: usize = 64 * 1024 * 1024;

/// PII redaction is explicit; default secrets mode preserves contact details.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// Recognizable credentials only; preserve ordinary personal information.
    #[default]
    Secrets,
    /// Also redact email and SSN shapes. Does not promise anonymization.
    Pii,
}

/// Deterministic admission/parse error; never contains input bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "TaggedError")]
pub struct AdmissionError {
    /// Stable machine-readable reason.
    pub code: &'static str,
}
impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for AdmissionError {}

/// Stable serialized failure contract. Refused calls produce no output and do
/// not poison the engine. Unexpected WASM traps poison the JS adapter instance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaggedError {
    /// Stable machine-readable reason, never input content.
    pub code: &'static str,
    /// `call_refusal` means the next independent call may safely proceed.
    pub disposition: &'static str,
    /// One-based physical record, when a record call was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record: Option<usize>,
}
impl From<AdmissionError> for TaggedError {
    fn from(error: AdmissionError) -> Self {
        Self {
            code: error.code,
            disposition: "call_refusal",
            record: None,
        }
    }
}
impl From<RecordError> for TaggedError {
    fn from(error: RecordError) -> Self {
        Self {
            code: error.code,
            disposition: "call_refusal",
            record: Some(error.record),
        }
    }
}

/// Check UTF-8 text admission before allocating scanner state.
pub fn scrub_text_checked(input: &str) -> Result<String, AdmissionError> {
    if input.len() > MAX_RECORD_BYTES {
        return Err(AdmissionError {
            code: "text_too_large",
        });
    }
    Ok(engine::scrub(input, false, Policy::Secrets))
}

/// Scrub a complete string without truncating or exposing segment boundaries.
#[must_use]
pub fn scrub_text(input: &str) -> String {
    scrub_text_with_policy(input, Policy::Secrets)
}

/// Compatibility entry point; uses the identical complete-string scan.
#[must_use]
pub fn scrub_long(input: &str) -> String {
    scrub_text(input)
}

/// Scrub text with an explicit, persistable privacy policy.
#[must_use]
pub fn scrub_text_with_policy(input: &str, policy: Policy) -> String {
    engine::scrub(input, false, policy)
}

/// Scrubbed text plus original byte ranges; ranges contain no copied credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScrubReport {
    /// Scrubbed output.
    pub text: String,
    /// Sorted, disjoint ranges removed from the original UTF-8 input.
    pub redactions: Vec<std::ops::Range<usize>>,
}

/// Inspect redaction coverage without returning original credential text.
#[must_use]
pub fn scrub_report(input: &str, policy: Policy) -> ScrubReport {
    engine::analyze(input, false, policy)
}

/// Distribution identity, distinct from the digest of a compiled WASM artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// Manifest schema.
    pub schema: u32,
    /// Family name.
    pub ruleset: String,
    /// Ruleset semantics version.
    pub ruleset_version: u32,
    /// Ordered source digest, independent of target platform.
    pub ruleset_source_sha256: String,
    /// Rust crate version.
    pub crate_version: String,
    /// JS transport ABI version.
    pub abi_version: u32,
    /// Redaction policy applied to text.
    pub policy: Policy,
    /// Stable replacement text.
    pub redaction_token: String,
    /// Crate-owned recognition/privacy profile; never synthesized by consumers.
    pub scrub_profile: String,
}

/// Return the canonical default-policy build identity.
#[must_use]
pub fn manifest() -> Manifest {
    manifest_with_policy(Policy::Secrets)
}

/// Return the identity to persist when using a nondefault PII policy.
#[must_use]
pub fn manifest_with_policy(policy: Policy) -> Manifest {
    Manifest {
        schema: MANIFEST_SCHEMA,
        ruleset: SCRUB_RULESET.into(),
        ruleset_version: RULESET_VERSION,
        ruleset_source_sha256: RULESET_SOURCE_SHA256.into(),
        crate_version: env!("CARGO_PKG_VERSION").into(),
        abi_version: ABI_VERSION,
        policy,
        redaction_token: REDACTION_TOKEN.into(),
        scrub_profile: match policy {
            Policy::Secrets => SCRUB_PROFILE,
            Policy::Pii => "relayhistory-pii-v10",
        }
        .into(),
    }
}

/// Historical two-field marker. New integrations must also persist policy/digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RawScrubMarker {
    /// Family name.
    pub ruleset: &'static str,
    /// Semantics version.
    pub version: u32,
}

/// Return the default-policy history marker, only after successful scrubbing.
#[must_use]
pub const fn raw_scrub_marker() -> RawScrubMarker {
    RawScrubMarker {
        ruleset: SCRUB_RULESET,
        version: RULESET_VERSION,
    }
}
