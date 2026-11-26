#![allow(missing_docs)]
use relayscrubber::{scrub_json, scrub_long, scrub_records, scrub_report, scrub_text, Policy};
use serde_json::{json, Value};

#[test]
fn quoted_assignment_preserves_its_neighbors_across_entry_points() {
    let input = "前\npassword='fixture-violet'\n後";
    let expected = "前\npassword='[REDACTED]'\n後";
    let report = scrub_report(input, Policy::Secrets);
    assert_eq!(report.text, expected);
    assert_eq!(report.redactions.len(), 1);
    assert_eq!(&input[report.redactions[0].clone()], "fixture-violet");
    for text in [input, expected] {
        assert_eq!(scrub_text(text), expected);
        assert_eq!(scrub_long(text), expected);
        let envelope = json!({"text": text, "title": "public"});
        let result = json!({"text": expected, "title": "public"});
        assert_eq!(scrub_json(&envelope).0, result);
        let records = scrub_records(envelope.to_string().as_bytes()).unwrap();
        assert_eq!(records.record_count, 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&records.bytes).unwrap(),
            result
        );
    }
}

#[test]
fn ordinary_large_records_match_the_shared_native_and_wasm_contract() {
    let cases: Value =
        serde_json::from_str(include_str!("../eval/assignment_bound_cases.json")).unwrap();
    let padding = cases["padding"]
        .as_str()
        .unwrap()
        .repeat(cases["repeats"].as_u64().unwrap() as usize);
    let expected = format!("{padding}{}", cases["expected"].as_str().unwrap());
    for tail in cases["cases"].as_array().unwrap() {
        let text = format!("{padding}{}", tail.as_str().unwrap());
        assert!((14 * 1024..16 * 1024).contains(&text.len()));
        assert_eq!(scrub_text(&text), expected);
        assert_eq!(relayscrubber::scrub_text_checked(&text).unwrap(), expected);
        assert_eq!(scrub_long(&text), expected);
        assert_eq!(scrub_report(&text, Policy::Secrets).text, expected);
        let envelope = json!({"text":text});
        let clean = json!({"text":expected});
        assert_eq!(scrub_json(&envelope).0, clean);
        assert_eq!(
            relayscrubber::scrub_json_text_checked(&envelope.to_string())
                .unwrap()
                .0,
            clean
        );
        let records = scrub_records(envelope.to_string().as_bytes()).unwrap();
        assert_eq!(records.bytes, format!("{clean}\n").into_bytes());
    }
}
