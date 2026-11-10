#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::json;
#[test]
fn text_utf8_boundary_and_fail_closed_compatibility() {
    // Multibyte exactly at 16 MiB, then one byte over.
    let at = "é".repeat(MAX_RECORD_BYTES / 2);
    assert_eq!(scrub_text_checked(&at).unwrap(), at);
    let over = format!("{at}x");
    assert_eq!(
        scrub_text_checked(&over).unwrap_err().code,
        "text_too_large"
    );
    assert_eq!(scrub_text(&over), REDACTION_TOKEN);
    assert_eq!(scrub_long(&over), REDACTION_TOKEN);
    assert_eq!(scrub_text_with_policy(&over, Policy::Pii), REDACTION_TOKEN);
    assert_eq!(scrub_report(&over, Policy::Secrets).text, REDACTION_TOKEN);
}
#[test]
fn json_and_record_utf8_boundaries() {
    let at = format!("\"{}\"", "é".repeat((MAX_RECORD_BYTES - 2) / 2));
    assert_eq!(at.len(), MAX_RECORD_BYTES);
    assert!(scrub_json_text_checked(&at).is_ok());
    assert!(scrub_records(at.as_bytes()).is_ok());
    let over = format!("{at} ");
    assert_eq!(
        scrub_json_text_checked(&over).unwrap_err().code,
        "record_too_large"
    );
    assert!(scrub_json_text(&over).is_none());
    assert_eq!(
        scrub_records(over.as_bytes()).unwrap_err(),
        RecordError {
            code: "record_too_large",
            record: 1
        }
    );
    let large = json!({"text":"x".repeat(MAX_RECORD_BYTES)});
    assert_eq!(
        scrub_json_checked(&large).unwrap_err().code,
        "record_too_large"
    );
    assert_eq!(scrub_json(&large).0, json!(REDACTION_TOKEN));
}
#[test]
fn aggregate_admission_is_atomic_at_64_mib() {
    let mut input = vec![b' '; MAX_STREAM_BYTES];
    for i in (MAX_RECORD_BYTES - 1..MAX_STREAM_BYTES).step_by(MAX_RECORD_BYTES) {
        input[i] = b'\n';
    }
    assert!(scrub_records(&input).is_ok());
    input.push(b' ');
    assert_eq!(
        scrub_records(&input).unwrap_err(),
        RecordError {
            code: "stream_too_large",
            record: 0
        }
    );
}
