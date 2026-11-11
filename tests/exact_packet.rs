#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};
fn verify(input: &str, expected: &str) -> bool {
    let value = json!({"text":input});
    let records = scrub_records(&serde_json::to_vec(&value).unwrap()).unwrap();
    let clean: Value = serde_json::from_slice(&records.bytes).unwrap();
    scrub_text(input) == expected
        && scrub_json(&value).0["text"] == expected
        && clean["text"] == expected
        && scrub_text(expected) == expected
}
#[test]
fn exact_reviewer_matrix() {
    let cases: Vec<(String, String)> =
        serde_json::from_str(include_str!("../eval/exact_packet_cases.json")).unwrap();
    let failed: Vec<_> = cases
        .iter()
        .enumerate()
        .filter_map(|(i, (input, expected))| (!verify(input, expected)).then_some(i))
        .collect();
    assert!(failed.is_empty(), "case indices {failed:?}");
}
#[test]
fn invented_residuals_and_positive_controls() {
    let raw = include_str!("../eval/residual_cases.json")
        .replace("OPENAI_PREFIX_", &["sk", "-proj-"].concat())
        .replace("GITHUB_PREFIX_", &["gh", "p_"].concat())
        .replace("AWS_PREFIX_", &["AK", "IA"].concat())
        .replace("SLACK_PREFIX_", &["xo", "xb-"].concat())
        .replace("STRIPE_PREFIX_", &["sk", "_live_"].concat());
    let cases: Value = serde_json::from_str(&raw).unwrap();
    let failed: Vec<_> = cases["benign"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter_map(|(i, x)| {
            let input = x.as_str().or_else(|| x["input"].as_str()).unwrap();
            let expected = x["expected"].as_str().unwrap_or(input);
            (!verify(input, expected)).then_some(i)
        })
        .collect();
    assert!(failed.is_empty(), "benign case indices {failed:?}");
    for item in cases["positive"].as_array().unwrap() {
        let input = item["input"].as_str().unwrap();
        let output = scrub_text(input);
        assert_ne!(input, output, "positive shape {}", item["shape"]);
        assert!(verify(input, &output));
    }
}
#[test]
fn newly_established_credentials_override_public_selector() {
    let value = json!({"idempotency_key":{"aws":{"key":"SYNTH_ALPHA"},"ordinary":{"key":"public-replay-42"},"password":"SYNTH_BETA"}});
    let expected = json!({"idempotency_key":{"aws":{"key":"[REDACTED]"},"ordinary":{"key":"public-replay-42"},"password":"[REDACTED]"}});
    assert_eq!(scrub_json(&value).0, expected);
}

#[test]
fn final_reviewer_syntax_and_context_ruling() {
    let cases: Vec<(String, String)> =
        serde_json::from_str(include_str!("../eval/ruling_cases.json")).unwrap();
    let failed: Vec<_> = cases
        .iter()
        .enumerate()
        .filter_map(|(i, (input, expected))| (!verify(input, expected)).then_some(i))
        .collect();
    assert!(failed.is_empty(), "ruling case indices {failed:?}");
}
