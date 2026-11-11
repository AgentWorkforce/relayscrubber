#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

#[test]
fn review_blocker_recall_and_source_controls_all_apis() {
    let cases: Value =
        serde_json::from_str(include_str!("../eval/alpha6_review_recall_cases.json")).unwrap();
    let mut failures = Vec::new();
    for (id, case) in cases.as_array().unwrap().iter().enumerate() {
        let input = case["input"].as_str().unwrap();
        let value = json!({"text": input});
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        let outputs = [
            scrub_text_checked(input).unwrap(),
            scrub_long(input),
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
fn bare_key_review_cases_are_sensitive_in_structured_input() {
    let cases: Value =
        serde_json::from_str(include_str!("../eval/alpha6_review_recall_cases.json")).unwrap();
    for case in cases
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["family"].as_str().unwrap().starts_with("bare_key"))
    {
        let input: Value = serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
        let expected = if input.get("wrapper").is_some() {
            json!({"wrapper":{"Key":REDACTION_TOKEN}})
        } else {
            json!({"Key":REDACTION_TOKEN})
        };
        assert_eq!(scrub_json(&input).0, expected);
        assert_eq!(scrub_json_text(&input.to_string()).unwrap().0, expected);
        let records = scrub_records(input.to_string().as_bytes()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&records.bytes).unwrap(),
            expected
        );
    }
}
