#![allow(missing_docs)]

use relayscrubber::{
    manifest, raw_scrub_marker, CORPUS_BYTES, CORPUS_SHA256, MANIFEST_JSON, MAX_SCRUB_CHARS,
    REDACTION_TOKEN, RULESET_SOURCE_SHA256, RUST_PORT_SHA256, SCRUB_RULESET_VERSION,
    SEGMENTER_SHA256,
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
fn history_marker_is_exactly_the_two_field_raw_scrub_contract() {
    let marker = serde_json::to_value(raw_scrub_marker()).expect("serialize raw.scrub marker");
    assert_eq!(
        marker,
        serde_json::json!({
            "ruleset": "relayhistory-scrub",
            "version": 7,
        })
    );
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
fn rust_rule_modules_match_the_reviewed_port_digest() {
    let files = [
        ("src/rules.rs", include_str!("../src/rules.rs")),
        (
            "src/rules/assign.rs",
            include_str!("../src/rules/assign.rs"),
        ),
        ("src/rules/js.rs", include_str!("../src/rules/js.rs")),
        ("src/rules/json.rs", include_str!("../src/rules/json.rs")),
        (
            "src/rules/numbers.rs",
            include_str!("../src/rules/numbers.rs"),
        ),
        ("src/rules/pem.rs", include_str!("../src/rules/pem.rs")),
        (
            "src/rules/quoted.rs",
            include_str!("../src/rules/quoted.rs"),
        ),
        (
            "src/rules/segment.rs",
            include_str!("../src/rules/segment.rs"),
        ),
        (
            "src/rules/tokens.rs",
            include_str!("../src/rules/tokens.rs"),
        ),
        ("src/rules/web.rs", include_str!("../src/rules/web.rs")),
    ];
    let mut source = String::new();
    for (path, text) in files {
        source.push_str(path);
        source.push('\n');
        source.push_str(&text.replace("\r\n", "\n"));
        source.push('\n');
    }
    assert_eq!(sha256(&source), RUST_PORT_SHA256);
}

#[test]
fn the_frozen_v6_ledger_is_not_relabelled_as_v7() {
    let ledger: Value =
        serde_json::from_str(include_str!("../vendor/frozen-v6/ledger.json")).unwrap();
    assert_eq!(ledger["rulesetVersion"], 6);
    assert_eq!(ledger["crateVersion"], "0.3.0");
    assert_eq!(
        ledger["registryCrateSha256"],
        "a128db65eb324386bc1b789028ec6b8db2cdefb209fb20bfb3aa70fb0b16dfc5"
    );
    assert_eq!(
        ledger["sourceCommit"],
        "0bf9aeda76b7ae6b7ff55923a84f3ea60c15d686"
    );
    assert_eq!(
        ledger["rustPortSha256"],
        "b1d153e336c127dd568ed470c30beea7e8786bfcde1c4507803f06e35dfecfaa"
    );
    let files = [
        ("scrub.ts", include_str!("../vendor/frozen-v6/scrub.ts")),
        (
            "raw-chunks.ts",
            include_str!("../vendor/frozen-v6/raw-chunks.ts"),
        ),
        (
            "technical-foul.json",
            include_str!("../vendor/frozen-v6/technical-foul.json"),
        ),
        (
            "scrub-secret-corpus.json",
            include_str!("../vendor/frozen-v6/scrub-secret-corpus.json"),
        ),
    ];
    for (name, bytes) in files {
        assert_eq!(sha256(bytes), ledger["files"][name].as_str().unwrap());
    }
    let old: Value = serde_json::from_str(files[2].1).unwrap();
    let raw = files[1].1.replace("\r\n", "\n");
    let start = raw.find("// <scrub-segmenter>").unwrap();
    let end_marker = "// </scrub-segmenter>";
    let end = raw[start..].find(end_marker).unwrap() + start + end_marker.len();
    assert_eq!(
        sha256(&format!(
            "{}\n{}",
            files[0].1.replace("\r\n", "\n"),
            &raw[start..end]
        )),
        old["rulesetSourceSha256"]
    );
    assert_eq!(old["rulesetVersion"], 6);
    assert_eq!(
        old["rulesetSourceSha256"],
        "28edb23b9ff94299d530213a04026210eb848399475b740e026ecc85980b3a11"
    );
    assert_eq!(old["corpusSha256"], CORPUS_SHA256);
    assert_eq!(old["segmenterSha256"], SEGMENTER_SHA256);
    assert_ne!(old["rulesetSourceSha256"], RULESET_SOURCE_SHA256);
}

#[test]
fn public_serde_json_dependency_does_not_change_consumer_semantics() {
    let manifest = include_str!("../Cargo.toml");
    let dependency = manifest
        .lines()
        .find(|line| line.starts_with("serde_json ="))
        .expect("serde_json dependency");
    assert_eq!(dependency, "serde_json = \"1.0\"");
    assert!(!manifest.contains("arbitrary_precision"));
    assert!(!manifest.contains("preserve_order"));
}

#[test]
fn exported_contract_matches_technical_foul_schema_one() {
    let checked_in: Value = serde_json::from_str(MANIFEST_JSON).expect("valid shared manifest");
    let current = manifest();
    assert_eq!(
        serde_json::to_value(current).expect("serialize manifest"),
        checked_in
    );
    assert_eq!(checked_in["schema"], current.schema);
    assert_eq!(checked_in["rulesetVersion"], SCRUB_RULESET_VERSION);
    assert_eq!(checked_in["rulesetSourceSha256"], RULESET_SOURCE_SHA256);
    assert_eq!(checked_in["segmenterSha256"], SEGMENTER_SHA256);
    assert_eq!(checked_in["corpusSha256"], CORPUS_SHA256);
    assert_eq!(checked_in["redactionToken"], REDACTION_TOKEN);
    assert_eq!(checked_in["maxScrubChars"], MAX_SCRUB_CHARS);
    assert_eq!(
        sha256(std::str::from_utf8(CORPUS_BYTES).expect("UTF-8 corpus")),
        CORPUS_SHA256
    );
}
