#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

fn check(source: &str) {
    let cases: Value = serde_json::from_str(source).unwrap();
    let mut failures = Vec::new();
    for (id, case) in cases.as_array().unwrap().iter().enumerate() {
        let input = case["input"].as_str().unwrap();
        let value = json!({"text": input});
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        let outputs = [
            scrub_text_checked(input).unwrap(),
            scrub_json(&value).0["text"].as_str().unwrap().into(),
            parsed["text"].as_str().unwrap().into(),
        ];
        for (api, output) in outputs.iter().enumerate() {
            let valid = if let Some(expected) = case["expected"].as_str() {
                output == expected
            } else {
                !output.contains(case["secret"].as_str().unwrap())
                    && output.contains(REDACTION_TOKEN)
            };
            if !valid || scrub_text(output) != *output {
                failures.push(format!("{id}/{}/{api}: {output:?}", case["family"]));
            }
        }
        assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn alpha4_precision_all_apis() {
    check(include_str!("../eval/alpha4_precision_cases.json"));
}

#[test]
fn alpha5_component_references_all_apis() {
    check(include_str!("../eval/alpha5_query_reference_cases.json"));
}
