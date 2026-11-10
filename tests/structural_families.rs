#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

#[test]
fn structural_families_and_literal_siblings_all_apis() {
    let cases: Value = serde_json::from_str(
        &include_str!("../eval/structural_cases.json")
            .replace("OPENAI_PREFIX_", &["sk", "-"].concat())
            .replace("CLOUDFLARE_PREFIX_", &["cf", "k_"].concat()),
    )
    .unwrap();
    let mut failures = Vec::new();
    for (id, case) in cases.as_array().unwrap().iter().enumerate() {
        let input = case["input"].as_str().unwrap();
        let value = json!({"text": input});
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        let outputs = [
            scrub_text(input),
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
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn numeric_json_scalars_preserve_type_and_string_siblings_redact() {
    let value =
        json!({"session_id":57243,"password":12,"accessToken":-12.5,"token":"M8zR4vK7nP2qW6xAq9"});
    let expected =
        json!({"session_id":57243,"password":12,"accessToken":-12.5,"token":REDACTION_TOKEN});
    assert_eq!(scrub_json(&value).0, expected);
    let records = scrub_records(value.to_string().as_bytes()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&records.bytes).unwrap(),
        expected
    );
}
