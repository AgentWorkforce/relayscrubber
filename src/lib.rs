//! Technical Foul: deterministic secret and PII scrubbing shared by Agent Relay.
//!
//! [`scrub_text`] is the allocation-aware entry point. It returns a borrowed
//! value when no rule matches and an owned value only when redaction or the
//! canonical size bound changes the input.

mod rules;

use serde::Serialize;
use serde_json::{Map, Value};
use std::borrow::Cow;

pub use rules::{exceeds_scrub_bound, is_card_number, is_secret_key_name, scrub_text};

/// The replacement token used by every complete redaction.
pub const REDACTION_TOKEN: &str = "[REDACTED]";

/// Stable history contract name written as `raw.scrub.ruleset`.
pub const SCRUB_RULESET: &str = "relayhistory-scrub";

/// Canonical `SCRUB_RULESET_VERSION` from relayhistory-pipeline.
pub const SCRUB_RULESET_VERSION: u32 = 3;

/// SHA-256 of canonical `scrub.ts` plus the marked raw-chunk segmenter.
pub const RULESET_SOURCE_SHA256: &str =
    "e7607073a3afca3db6b015945f0b5fab256202f355b740f515987ec162bf3076";

/// SHA-256 of the LF-normalized Rust rules port for accidental-drift detection.
pub const RUST_PORT_SHA256: &str =
    "5ceb3661f10c6e5f8004b23c8e7bcfbad915947422bebf04a4b4d252a201ba15";

/// SHA-256 of the canonical scrub corpus, after CRLF-to-LF normalization.
pub const CORPUS_SHA256: &str = "9a80b081d2ab1a2be7a9f36e73bcf6f27861b7096418a372ce12b567be52a860";

/// SHA-256 of the canonical marked raw-chunk segmenter alone.
pub const SEGMENTER_SHA256: &str =
    "83392705f4d8c06e745a56f5bd549c890cc82404d06bfdc37a7937ad967f7fed";

/// Maximum UTF-16 code-unit length accepted by the bounded string scrubber.
pub const MAX_SCRUB_CHARS: usize = 262_144;

/// Stable manifest exchanged by relayhistory-pipeline and consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TechnicalFoulManifest {
    /// Manifest schema version.
    pub schema: u32,
    /// Canonical ruleset version stored in the history database contract.
    pub ruleset_version: u32,
    /// Canonical rules plus segmenter source digest.
    pub ruleset_source_sha256: &'static str,
    /// Canonical segmenter source digest.
    pub segmenter_sha256: &'static str,
    /// Canonical corpus digest.
    pub corpus_sha256: &'static str,
    /// Stable replacement token.
    pub redaction_token: &'static str,
    /// Per-string UTF-16 code-unit bound.
    pub max_scrub_chars: usize,
}

/// Return the compile-time Technical Foul compatibility manifest.
#[must_use]
pub const fn manifest() -> TechnicalFoulManifest {
    TechnicalFoulManifest {
        schema: 1,
        ruleset_version: SCRUB_RULESET_VERSION,
        ruleset_source_sha256: RULESET_SOURCE_SHA256,
        segmenter_sha256: SEGMENTER_SHA256,
        corpus_sha256: CORPUS_SHA256,
        redaction_token: REDACTION_TOKEN,
        max_scrub_chars: MAX_SCRUB_CHARS,
    }
}

/// Recursively scrub every string key and value and card-shaped JSON number.
///
/// If scrubbed object keys collide, later values receive ` (2)`, ` (3)`, and
/// so on, matching the canonical TypeScript behavior without discarding data.
#[must_use]
pub fn scrub_json(value: &Value) -> Value {
    match value {
        Value::String(value) => Value::String(scrub_text(value).into_owned()),
        Value::Number(value) => value.as_i64().map_or_else(
            || Value::Number(value.clone()),
            |number| {
                if number > 0 && is_card_number(&number.to_string()) {
                    Value::String(REDACTION_TOKEN.to_owned())
                } else {
                    Value::Number(value.clone())
                }
            },
        ),
        Value::Array(values) => Value::Array(values.iter().map(scrub_json).collect()),
        Value::Object(values) => {
            let mut output = Map::new();
            let mut next_suffix = std::collections::HashMap::<String, usize>::new();
            for (key, value) in values {
                let base = scrub_text(key).into_owned();
                let mut name = base.clone();
                if output.contains_key(&name) {
                    let next = next_suffix.entry(base.clone()).or_insert(2);
                    while output.contains_key(&format!("{base} ({next})")) {
                        *next += 1;
                    }
                    name = format!("{base} ({next})");
                    *next += 1;
                }
                output.insert(name, scrub_json(value));
            }
            Value::Object(output)
        }
        _ => value.clone(),
    }
}

/// Scrub an optional string without allocating when it is absent or unchanged.
#[must_use]
pub fn scrub_optional(value: Option<&str>) -> Option<Cow<'_, str>> {
    value.map(scrub_text)
}
