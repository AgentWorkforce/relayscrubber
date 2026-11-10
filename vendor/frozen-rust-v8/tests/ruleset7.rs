#![allow(missing_docs)]

use relayscrubber::{scrub_json, scrub_json_text, scrub_long, scrub_text, REDACTION_TOKEN};
use serde_json::json;

#[test]
fn public_idempotency_assignments_keep_their_replay_identity() {
    for key in ["idempotency_key", "IDEMPOTENCY_KEY", "Idempotency_Key"] {
        for gap in ["", " ", "\t", "\u{a0}", "\u{feff}"] {
            for separator in [":", "="] {
                let input = format!("{key}{gap}{separator}{gap}public-replay-42");
                assert_eq!(scrub_text(&input), input);
                assert_eq!(scrub_long(&input), input);
            }
        }
    }
}

#[test]
fn the_exception_does_not_cover_prefixed_or_suffixed_secret_names() {
    for key in [
        "request_idempotency_key",
        "idempotency_key_secret",
        "idempotency_key_token",
    ] {
        let input = format!("{key}=synthetic-credential-value");
        assert_eq!(scrub_text(&input), format!("{key}={REDACTION_TOKEN}"));
    }
    assert_eq!(
        scrub_text("idempotency_key=public-replay-42; api_key=synthetic-credential-value"),
        "idempotency_key=public-replay-42; api_key=[REDACTED]"
    );
}

#[test]
fn credential_shaped_replay_values_are_still_redacted() {
    for token in [
        format!("ghp_{}", "Ab1".repeat(16)),
        format!("sk-proj-{}", "Ab1".repeat(24)),
        format!("rth_at_{}", "Ab1".repeat(24)),
    ] {
        let text = format!("idempotency_key={token}");
        for clean in [scrub_text(&text), scrub_long(&text)] {
            assert!(!clean.contains(&token));
            assert!(clean.contains(REDACTION_TOKEN));
        }
        let value = json!({"idempotency_key": token});
        let clean = scrub_json(&value).0;
        assert_eq!(clean["idempotency_key"], REDACTION_TOKEN);
        let from_text = scrub_json_text(&value.to_string()).unwrap().0;
        assert_eq!(from_text, clean);
    }
}

#[test]
fn json_payloads_keep_public_ids_and_scrub_assigned_credentials() {
    let input = json!({
        "idempotency_key": "public-replay-42",
        "content": "idempotency_key=public-replay-42 api_key=synthetic-credential-value"
    });
    let expected = json!({
        "idempotency_key": "public-replay-42",
        "content": "idempotency_key=public-replay-42 api_key=[REDACTED]"
    });
    assert_eq!(scrub_json(&input).0, expected);
    assert_eq!(scrub_json_text(&input.to_string()).unwrap().0, expected);
    assert_eq!(scrub_json(&expected), (expected.clone(), 0));
}

#[test]
fn zero_redactions_do_not_mean_the_original_json_text_can_be_reused() {
    let input =
        r#"{"content":"api_key=synthetic-credential-value","content":"ordinary last value"}"#;
    let (clean, count) = scrub_json_text(input).unwrap();
    assert_eq!(clean, json!({"content": "ordinary last value"}));
    assert_eq!(count, 0);
    assert!(!clean.to_string().contains("synthetic-credential-value"));
    // JSON.parse semantics discard the first duplicate value. A consumer must
    // serialize the returned tree even when no surviving leaf was redacted.
    assert_ne!(input, clean.to_string());
}

#[test]
fn idempotency_and_credential_rules_stay_stable_across_segment_boundaries() {
    let prefix = "ordinary ".repeat(relayscrubber::MAX_SCRUB_CHARS / 9);
    let input =
        format!("{prefix}idempotency_key=public-replay-42 api_key=synthetic-credential-value tail");
    let clean = scrub_long(&input);
    assert!(clean.contains("idempotency_key=public-replay-42"));
    assert!(!clean.contains("synthetic-credential-value"));
    assert_eq!(scrub_long(&clean), clean);
}
