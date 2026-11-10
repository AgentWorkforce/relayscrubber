#![allow(missing_docs)]
#[path = "../eval/review_cases.rs"]
mod cases;
use relayscrubber::*;
use serde_json::json;
fn check(index: usize) {
    let (_, input, expected) = &cases::findings()[index];
    assert_eq!(&scrub_text(input), expected, "text");
    assert_eq!(&scrub_long(input), expected, "compatibility");
    assert_eq!(scrub_text(expected), *expected, "second pass");
    let value = json!({"text":input});
    let clean = scrub_json(&value).0;
    assert_eq!(clean["text"], *expected, "JSON");
    assert_eq!(scrub_json(&clean).0, clean, "JSON second pass");
    let raw = serde_json::to_vec(&value).unwrap();
    let records = scrub_records(&raw).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&records.bytes).unwrap();
    assert_eq!(parsed["text"], *expected, "records");
    assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
}
#[test] fn direct_intervening_quote() { check(0); }
#[test] fn public_property_intervening_quote() { check(1); }
#[test] fn generic_key() { check(2); }
#[test] fn prefixed_credential_key() { check(3); }
#[test] fn prefixed_public_like_name() { check(4); }
#[test] fn unicode_space() { check(5); }
#[test] fn comparison_precision() { check(6); }
#[test]
fn credential_name_and_unicode_variants() {
    for name in ["githubToken", "stripeSecret", "encryption_key", "aws={key"] {
        let input = format!("{name}=SYNTH_ALPHA");
        assert!(!scrub_text(&input).contains("SYNTH_ALPHA"));
    }
    assert_eq!(scrub_text("aws={key:SYNTH_ALPHA}"), "aws={key:[REDACTED]}");
    for space in ['\u{a0}', '\u{feff}', '\u{2003}'] {
        assert_eq!(scrub_text(&format!("password{space}=SYNTH_ALPHA")), format!("password{space}=[REDACTED]"));
    }
}
#[test]
fn benign_code_and_identifiers() {
    for input in cases::benign() { assert_eq!(scrub_text(&input), input); }
}
