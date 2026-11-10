#![allow(missing_docs)]
#[path = "../eval/p0_cases.rs"]
mod cases;
use relayscrubber::*;
use serde_json::json;
fn check(cases: Vec<(String, String)>) {
    let mut failures = Vec::new();
    for (n, (input, expected)) in cases.into_iter().enumerate() {
        let value = json!({"text": input});
        let records = scrub_records(&serde_json::to_vec(&value).unwrap()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&records.bytes).unwrap();
        for (api, actual) in [
            ("text", scrub_text(&input)),
            (
                "JSON",
                scrub_json(&value).0["text"].as_str().unwrap().to_string(),
            ),
            ("NDJSON", parsed["text"].as_str().unwrap().to_string()),
        ] {
            if actual != expected {
                failures.push((n, api));
            }
        }
        if scrub_text(&expected) != expected {
            failures.push((n, "second pass"));
        }
    }
    assert!(
        failures.is_empty(),
        "mismatching case/API indices: {failures:?}"
    );
}
#[test]
fn explicit_yaml_prose_values() {
    check(cases::prose());
}
#[test]
fn credential_container_distance_and_scope() {
    let start = std::time::Instant::now();
    check(cases::containers());
    eprintln!(
        "credential container scope/all APIs: {:.3}s",
        start.elapsed().as_secs_f64()
    );
}
#[test]
fn adversarial_container_time_is_bounded() {
    use std::time::{Duration, Instant};
    for count in [4096, 65536] {
        let input = format!(
            "aws={{ {} key:SYNTH_ALPHA }}",
            "nested:{key:SYNTH_ALPHA}, ".repeat(count)
        );
        let start = Instant::now();
        let output = scrub_text(&input);
        let elapsed = start.elapsed();
        eprintln!(
            "container keys={} bytes={} seconds={:.3}",
            count + 1,
            input.len(),
            elapsed.as_secs_f64()
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "large container exceeded ten seconds"
        );
        assert!(!output.contains("SYNTH_ALPHA"));
        assert_eq!(output.matches(REDACTION_TOKEN).count(), count + 1);
    }
}
