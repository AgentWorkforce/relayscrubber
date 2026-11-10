#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

fn check(source: &str) {
    let cases: Vec<Value> = serde_json::from_str(source).unwrap();
    let mut failures = Vec::new();
    for (id, case) in cases.iter().enumerate() {
        let input = case["input"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        let value = json!({"text": input});
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        for (api, actual) in [
            scrub_text_checked(input).unwrap(),
            scrub_json(&value).0["text"].as_str().unwrap().into(),
            parsed["text"].as_str().unwrap().into(),
        ].iter().enumerate() {
            if actual != expected || scrub_text(actual) != *actual {
                failures.push((id, api));
            }
        }
        assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
    }
    assert!(failures.is_empty(), "failed case/API indices: {failures:?}");
}

#[test]
fn entity_query_all_apis() {
    check(include_str!("../eval/entity_query_cases.json"));
}
