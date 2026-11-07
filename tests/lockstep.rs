#![allow(missing_docs)]

use relayscrubber::{
    CORPUS_SHA256, MAX_SCRUB_CHARS, REDACTION_TOKEN, RULESET_SOURCE_SHA256, RUST_PORT_SHA256,
    SCRUB_RULESET_VERSION, SEGMENTER_SHA256, manifest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn sha256(text: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(text.replace("\r\n", "\n").as_bytes())
    )
}

#[test]
fn vendored_canonical_sources_match_the_shared_manifest() {
    let scrub = include_str!("../vendor/canonical/scrub.ts").replace("\r\n", "\n");
    let raw = include_str!("../vendor/canonical/raw-chunks.ts").replace("\r\n", "\n");
    let start = raw
        .find("// <scrub-segmenter>")
        .expect("segmenter start marker");
    let end_marker = "// </scrub-segmenter>";
    let end =
        raw[start..].find(end_marker).expect("segmenter end marker") + start + end_marker.len();
    let segmenter = &raw[start..end];
    assert_eq!(sha256(segmenter), SEGMENTER_SHA256);
    assert_eq!(
        sha256(&format!("{scrub}\n{segmenter}")),
        RULESET_SOURCE_SHA256
    );

    let corpus = include_str!("../vendor/corpus/scrub-secret-corpus.json");
    assert_eq!(sha256(corpus), CORPUS_SHA256);
}

#[test]
fn rust_rules_port_is_pinned_to_ruleset_three() {
    let rules = include_str!("../src/rules.rs");
    assert_eq!(sha256(rules), RUST_PORT_SHA256);
    assert_eq!(SCRUB_RULESET_VERSION, 3);
}

#[test]
fn exported_contract_matches_technical_foul_schema_one() {
    let checked_in: Value =
        serde_json::from_str(include_str!("../vendor/canonical/technical-foul.json"))
            .expect("valid shared manifest");
    let current = manifest();
    assert_eq!(checked_in["schema"], current.schema);
    assert_eq!(checked_in["rulesetVersion"], SCRUB_RULESET_VERSION);
    assert_eq!(checked_in["rulesetSourceSha256"], RULESET_SOURCE_SHA256);
    assert_eq!(checked_in["segmenterSha256"], SEGMENTER_SHA256);
    assert_eq!(checked_in["corpusSha256"], CORPUS_SHA256);
    assert_eq!(checked_in["redactionToken"], REDACTION_TOKEN);
    assert_eq!(checked_in["maxScrubChars"], MAX_SCRUB_CHARS);
}
