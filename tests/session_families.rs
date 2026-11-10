#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};
fn paths(input: &str) -> [String; 3] {
    let value = json!({"text": input});
    let records = scrub_records(&serde_json::to_vec(&value).unwrap()).unwrap();
    let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
    [
        scrub_text(input),
        scrub_json(&value).0["text"].as_str().unwrap().into(),
        parsed["text"].as_str().unwrap().into(),
    ]
}
#[test]
fn invented_session_families_all_apis() {
    let cases: Value = serde_json::from_str(
        &include_str!("../eval/session_cases.json")
            .replace("STRIPE_LIVE_PREFIX_", &["sk", "_live_"].concat()),
    )
    .unwrap();
    let mut failures = Vec::new();
    for (family, inputs) in cases["benign"].as_object().unwrap() {
        for (n, input) in inputs.as_array().unwrap().iter().enumerate() {
            let input = input.as_str().unwrap();
            for (api, output) in paths(input).iter().enumerate() {
                if output != input {
                    failures.push(format!("{family}/{n}/{api}"));
                }
            }
        }
    }
    for (n, case) in cases["positive"].as_array().unwrap().iter().enumerate() {
        let input = case[0].as_str().unwrap();
        let secret = case[1].as_str().unwrap();
        for (api, output) in paths(input).iter().enumerate() {
            if output.contains(secret)
                || !output.contains(REDACTION_TOKEN)
                || scrub_text(output) != *output
            {
                failures.push(format!("positive/{n}/{api}"));
            }
        }
    }
    assert!(failures.is_empty(), "case/API mismatches: {failures:?}");
}
