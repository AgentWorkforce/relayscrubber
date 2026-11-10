#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

#[test]
fn exemptions_cover_complete_values_all_apis() {
    let cases: Value = serde_json::from_str(
        &include_str!("../eval/complete_cases.json").replace("OPENAI_PREFIX_", "sk-"),
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
fn numeric_credentials_all_apis_and_identifier_controls() {
    for number in ["123456", "-246810", "12.375", "6.02e23", "0"] {
        let mut failures = Vec::new();
        for key in [
            "password",
            "passwd",
            "pin",
            "secret",
            "client_secret",
            "token",
            "accessToken",
            "refreshToken",
            "api_key",
        ] {
            let input = format!(
                "{{\"{key}\":{number},\"session_id\":57243,\"pid\":42,\"port\":8080,\"count\":0}}"
            );
            let expected =
                json!({key:REDACTION_TOKEN,"session_id":57243,"pid":42,"port":8080,"count":0});
            let value: Value = serde_json::from_str(&input).unwrap();
            let records = scrub_records(input.as_bytes()).unwrap();
            let text = scrub_text_checked(&input).unwrap();
            let parsed = serde_json::from_str::<Value>(&text).ok();
            let structured = scrub_json(&value);
            if parsed.as_ref() != Some(&expected)
                || structured.0 != expected
                || serde_json::from_slice::<Value>(&records.bytes).unwrap() != expected
                || structured.1 != 1
                || records.redaction_count != 1
            {
                failures.push(key);
            }
            assert_eq!(scrub_text(&text), text);
            assert_eq!(scrub_json(&structured.0).0, structured.0);
            assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
        }
        assert!(failures.is_empty(), "numeric {number}: {failures:?}");
    }
}
