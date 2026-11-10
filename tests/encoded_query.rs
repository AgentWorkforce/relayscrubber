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
        ]
        .iter()
        .enumerate()
        {
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

#[test]
fn percent_query_all_apis() {
    check(include_str!("../eval/percent_query_cases.json"));
}

#[test]
fn encoded_query_recovery_time_is_bounded() {
    use std::time::{Duration, Instant};
    for count in [2048, 16384] {
        for (family, prefix, padding, tail) in [
            (
                "nested percent queries",
                "https%3A%2F%2Fproxy.example.invalid%2F%3Furl%3D",
                "https%3A%2F%2Fproxy.example.invalid%2F%3Furl%3D",
                "%26signature%3D7e3b15c97e3b15c9%26sort%3Dasc",
            ),
            (
                "malformed entity recovery",
                "https://media.example.invalid/?caption=\"unfinished\n",
                "&amp;amp;page=ordinary",
                "&#X000026;signature=7e3b15c97e3b15c9&amp;sort=asc",
            ),
            (
                "nested entity layers",
                "https://media.example.invalid/?caption=audit&",
                "amp;",
                "signature=7e3b15c97e3b15c9&sort=asc",
            ),
            (
                "numeric leading zeros",
                "https://media.example.invalid/?caption=audit&#x",
                "0",
                "26;signature=7e3b15c97e3b15c9&sort=asc",
            ),
        ] {
            let input = format!("{prefix}{}{tail}", padding.repeat(count));
            let expected = input.replace("7e3b15c97e3b15c9", REDACTION_TOKEN);
            let start = Instant::now();
            let actual = scrub_text_checked(&input).unwrap();
            let elapsed = start.elapsed();
            eprintln!(
                "{family}: count={count} bytes={} seconds={:.3}",
                input.len(),
                elapsed.as_secs_f64()
            );
            assert!(
                elapsed < Duration::from_secs(10),
                "encoded query exceeded ten seconds"
            );
            assert_eq!(actual, expected);
            assert_eq!(scrub_text_checked(&actual).unwrap(), actual);
        }
    }
}

#[path = "../eval/query_separator_cases.rs"]
mod query_separator_cases;

#[test]
fn query_separator_property_all_apis() {
    let cases = query_separator_cases::cases();
    let mut failures = Vec::new();
    for (id, (input, expected)) in cases.iter().enumerate() {
        let value = json!({"text": input});
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        let outputs = [
            scrub_text_checked(input).unwrap(),
            scrub_json(&value).0["text"].as_str().unwrap().into(),
            parsed["text"].as_str().unwrap().into(),
        ];
        for (api, output) in outputs.iter().enumerate() {
            if output != expected || scrub_text(output) != *output {
                failures.push((id, api));
            }
        }
        assert_eq!(scrub_json(&scrub_json(&value).0).0, scrub_json(&value).0);
        assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
    }
    eprintln!(
        "separator property: {} cases, {} failing case/API pairs; first {:?}",
        cases.len(),
        failures.len(),
        &failures[..failures.len().min(24)]
    );
    assert!(failures.is_empty());
}
