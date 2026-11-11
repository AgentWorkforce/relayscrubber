#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

#[test]
fn alpha7_boundaries_and_complete_extents_all_apis() {
    let cases: Value =
        serde_json::from_str(include_str!("../eval/alpha7_boundary_cases.json")).unwrap();
    let mut failures = Vec::new();
    for (id, case) in cases.as_array().unwrap().iter().enumerate() {
        let input = case["input"].as_str().unwrap();
        if let Some(spans) = case["spans"].as_array() {
            let report = scrub_report(input, Policy::Secrets);
            let expected: Vec<_> = spans
                .iter()
                .map(|s| s["start"].as_u64().unwrap() as usize..s["end"].as_u64().unwrap() as usize)
                .collect();
            if report.redactions != expected {
                failures.push(format!(
                    "{id}/{} spans: {:?} != {:?}",
                    case["family"], report.redactions, expected
                ));
            }
        }
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
fn long_markdown_label_keeps_repeated_key_scans_bounded() {
    let input = format!(
        "- {} {}",
        "a".repeat(2 * 1024 * 1024),
        "token: The fox, ".repeat(4096)
    );
    let started = std::time::Instant::now();
    let output = scrub_text_checked(&input).unwrap();
    let seconds = started.elapsed().as_secs_f64();
    eprintln!(
        "markdown label prefix: count=4096 bytes={} seconds={seconds:.3}",
        input.len()
    );
    assert!(seconds < 10.0);
    assert_eq!(output.matches(REDACTION_TOKEN).count(), 4096);
    assert!(!output.contains("The fox"));
}
