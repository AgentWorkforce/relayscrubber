#![allow(missing_docs)]

use relayscrubber::{scrub_json, scrub_long, scrub_records, scrub_text, scrub_text_checked};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Case {
    id: String,
    kind: String,
    input: String,
    expected: String,
}

fn cases() -> Vec<Case> {
    serde_json::from_str(include_str!("../eval/alpha9_prose_credential_cases.json"))
        .expect("valid alpha9 prose credential cases")
}

#[test]
fn natural_language_credentials_are_consistent_and_idempotent() {
    let cases = cases();
    assert!(cases.iter().any(|case| case.kind == "positive"));
    assert!(cases.iter().any(|case| case.kind == "benign"));

    for case in cases {
        let outputs = [
            scrub_text_checked(&case.input).expect("admitted text"),
            scrub_text(&case.input),
            scrub_long(&case.input),
            scrub_json(&json!({"text": case.input})).0["text"]
                .as_str()
                .expect("JSON text")
                .to_owned(),
        ];
        for output in outputs {
            assert_eq!(output, case.expected, "{}", case.id);
            assert_eq!(scrub_text(&output), output, "{} second pass", case.id);
        }

        let record = serde_json::to_vec(&json!({"text": case.input})).unwrap();
        let first = scrub_records(&record).expect("valid record");
        let parsed: serde_json::Value = serde_json::from_slice(&first.bytes).unwrap();
        assert_eq!(parsed["text"], case.expected, "{} records", case.id);
        assert_eq!(
            scrub_records(&first.bytes).expect("second record pass").bytes,
            first.bytes,
            "{} records second pass",
            case.id
        );
    }
}
