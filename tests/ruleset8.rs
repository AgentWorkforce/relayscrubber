#![allow(missing_docs)]
use relayscrubber::{scrub_json, scrub_json_text, scrub_long, scrub_text};
use serde_json::json;

#[test]
fn nested_labelled_credentials_are_not_consumed_by_public_assignments() {
    for key in ["idempotency_key", "IDEMPOTENCY_KEY"] {
        for sep in ["=", ":", " : ", "\t=\t", "\u{a0}=\u{feff}"] {
            for quote in ["", "\"", "'", "`"] {
                for label in [
                    "password",
                    "token",
                    "api_key",
                    "client_secret",
                    "credentials",
                ] {
                    let input = format!("{key}{sep}{quote}{label}=fixture-only{quote}");
                    for clean in [scrub_text(&input), scrub_long(&input)] {
                        assert!(!clean.contains("fixture-only"), "{input}");
                        assert!(clean.contains("[REDACTED]"));
                    }
                    let value = json!({"text": input});
                    assert!(!scrub_json(&value).0.to_string().contains("fixture-only"));
                    assert!(!scrub_json_text(&value.to_string())
                        .unwrap()
                        .0
                        .to_string()
                        .contains("fixture-only"));
                }
            }
        }
    }
}

#[test]
fn nested_public_assignments_have_no_recursive_depth_cutoff() {
    let prefix = "idempotency_key=".repeat(512);
    let input = format!("{prefix}password=fixture-only");
    assert_eq!(scrub_text(&input), format!("{prefix}password=[REDACTED]"));
    let benign = format!("{prefix}public-replay-42");
    assert_eq!(scrub_text(&benign), benign);
}

#[test]
fn escaped_and_segmented_nested_credentials_stay_redacted() {
    let mut input = "idempotency_key=password=fixture-only".to_owned();
    for _ in 0..5 {
        assert!(!scrub_text(&input).contains("fixture-only"));
        input = serde_json::to_string(&input).unwrap();
    }
    let long = format!(
        "{}idempotency_key=password=fixture-only after",
        "ordinary ".repeat(262144 / 9)
    );
    let clean = scrub_long(&long);
    assert!(!clean.contains("fixture-only"));
    assert!(clean.contains("idempotency_key=password=[REDACTED]"));
    assert_eq!(scrub_long(&clean), clean);
}
