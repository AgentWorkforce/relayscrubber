#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

#[test]
fn query_recovery_all_apis() {
    let cases: Value = serde_json::from_str(
        &include_str!("../eval/query_recovery_cases.json").replace("OPENAI_PREFIX_", "sk-"),
    )
    .unwrap();
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
fn query_recovery_at_admission_boundary() {
    let prefix = "https://media.example.invalid/render?caption=\"";
    let tail = "&page=2&sig=7e3b15c97e3b15c97e3b15c97e3b15c9";
    let padding = "a".repeat(MAX_RECORD_BYTES - prefix.len() - tail.len());
    let input = format!("{prefix}{padding}{tail}");
    let expected = format!("{prefix}{padding}&page=2&sig=[REDACTED]");
    assert_eq!(input.len(), MAX_RECORD_BYTES);
    assert_eq!(scrub_text_checked(&input).unwrap(), expected);
    assert_eq!(scrub_text_checked(&expected).unwrap(), expected);
    let benign = format!("{prefix}{}", "a".repeat(MAX_RECORD_BYTES - prefix.len()));
    assert_eq!(scrub_text_checked(&benign).unwrap(), benign);
    assert_eq!(
        scrub_text_checked(&(input + "x")).unwrap_err().code,
        "text_too_large"
    );
}
