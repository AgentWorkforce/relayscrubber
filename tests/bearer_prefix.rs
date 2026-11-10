#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

#[test]
fn standalone_bearer_prefixes_and_reference_controls_all_apis() {
    let cases: Value = serde_json::from_str(include_str!("../eval/bearer_cases.json")).unwrap();
    let mut failures = Vec::new();
    for family in ["positive", "benign"] {
        for (id, case) in cases[family].as_array().unwrap().iter().enumerate() {
            let (input, expected) = if family == "positive" {
                (case[0].as_str().unwrap(), case[1].as_str().unwrap())
            } else {
                let input = case.as_str().unwrap();
                (input, input)
            };
            let value = json!({"text": input});
            // Check an actual multi-record stream, including escaped quotes in strings.
            let raw = format!("{value}\n{}\n{value}\n", json!({"text": "ordinary"}));
            let records = scrub_records(raw.as_bytes()).unwrap();
            let parsed: Vec<Value> = std::str::from_utf8(&records.bytes)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let outputs = [
                scrub_text_checked(input).unwrap(),
                scrub_json(&value).0["text"].as_str().unwrap().into(),
                parsed[0]["text"].as_str().unwrap().into(),
                parsed[2]["text"].as_str().unwrap().into(),
                scrub_text(expected),
            ];
            for (api, output) in outputs.iter().enumerate() {
                if output != expected {
                    failures.push(format!("{family}/{id}/{api}"));
                }
            }
            assert_eq!(parsed[1], json!({"text": "ordinary"}));
            assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
        }
    }
    assert!(failures.is_empty(), "case/API mismatches: {failures:?}");
}
