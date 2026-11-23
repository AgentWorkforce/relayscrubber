#![allow(missing_docs)]
//! Whole-input markers. Exactly three ways turn a complete input into the
//! single `[REDACTED]` marker, and each is a deliberate fail-closed choice:
//!
//! 1. Text over `MAX_RECORD_BYTES` reaching the compatibility text APIs
//!    (`scrub_text`, `scrub_long`, `scrub_text_with_policy`, `scrub_report`).
//!    The checked text API refuses it with `text_too_large` instead.
//! 2. The post-redaction fixed point not settling within its pass budget
//!    (one pass plus four re-scans of the redacted text).
//! 3. A recognizer whose credential extent is the whole input.
//!
//! The unchecked JSON API has the JSON counterpart of path 1: a value deeper
//! than `MAX_JSON_DEPTH` or serializing to more than `MAX_RECORD_BYTES` becomes
//! the marker string. Every other refusal is an error, never a marker.
//!
//! Benign prose, lists, fenced code and long documents under the size limit
//! must never come back as the whole marker.

use relayscrubber::*;
use serde_json::json;

const PARAGRAPHS: [&str; 10] = [
    "The build finished after the cache was warmed. I moved the retry loop into its own function so that the timeout applies once per request instead of once per batch, and the logs now name the step that failed.",
    "Could you check whether the migration keeps the old column until the backfill is done? The rollout plan says we drop it a week later, after the dashboards stop reading from it.",
    "Here is what changed:\n\n- the parser accepts a trailing comma\n- the config loader reads `settings.toml` before the environment\n- errors carry the line number\n\n1. Run the tests.\n2. Open the report.\n3. Compare the totals with yesterday.",
    "```rust\nfn total(items: &[Item]) -> u64 {\n    items.iter().map(|item| item.size).sum()\n}\n```",
    "```ts\ninterface CacheOptions { cacheKey: string; maxAttempts: number }\nconst options: CacheOptions = { cacheKey: name, maxAttempts: 3 };\n```",
    "The password reset page now explains the rules before the form, and the key insight from the review is that the token count is a unit of text, not a credential.",
    "> Quoted from the design note: keep the public API small and the error codes stable.\n\nI agree with that, and the new function only takes a path and a limit.",
    "| step | owner | status |\n| --- | --- | --- |\n| build | ci | done |\n| deploy | ops | waiting |",
    "If the request fails, wait two seconds and try again; after five failures, stop and report the status code. The queue keeps the order of the remaining jobs.",
    "Thanks, that fixed it. The next thing is the flaky test in the uploader suite, which fails about once in forty runs on the slow machines.",
];

fn assert_no_whole_marker(input: &str) {
    let report = scrub_report(input, Policy::Secrets);
    assert_ne!(report.text, REDACTION_TOKEN, "whole marker for {input:?}");
    assert!(
        !report.redactions.contains(&(0..input.len())),
        "whole-input span for {input:?}"
    );
    assert_eq!(scrub_text(input), input, "benign text changed: {input:?}");
}

#[test]
fn each_benign_paragraph_is_unchanged() {
    for paragraph in PARAGRAPHS {
        assert_no_whole_marker(paragraph);
    }
}

#[test]
fn benign_documents_never_become_the_whole_marker() {
    // Deterministic mix of prose, lists, tables and fenced code.
    let mut seed = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..200 {
        let parts = 1 + (next() % 8) as usize;
        let document = (0..parts)
            .map(|_| PARAGRAPHS[(next() % PARAGRAPHS.len() as u64) as usize])
            .collect::<Vec<_>>()
            .join("\n\n");
        assert_no_whole_marker(&document);
    }
}

#[test]
fn long_paragraph_is_unchanged() {
    let paragraph = PARAGRAPHS[0].repeat(400);
    assert!(paragraph.len() > 64 * 1024);
    assert_no_whole_marker(&paragraph);
}

#[test]
fn benign_text_just_under_the_size_limit_is_unchanged() {
    let block = PARAGRAPHS.join("\n\n") + "\n\n";
    let mut input = block.repeat(MAX_RECORD_BYTES / block.len());
    input.push_str(&" ".repeat(MAX_RECORD_BYTES - input.len()));
    assert_eq!(input.len(), MAX_RECORD_BYTES);
    assert_eq!(scrub_text_checked(&input).unwrap(), input);
    let report = scrub_report(&input, Policy::Secrets);
    assert!(report.redactions.is_empty());
    assert_eq!(report.text, input);
}

// Cause: path 1, `analyze_once` sees more than `MAX_RECORD_BYTES` and returns
// the marker with the span 0..len; the checked API refuses before scanning.
#[test]
fn oversize_text_is_the_whole_marker_or_refused() {
    let block = PARAGRAPHS.join("\n\n") + "\n\n";
    let mut input = block.repeat(MAX_RECORD_BYTES / block.len());
    input.push_str(&" ".repeat(MAX_RECORD_BYTES + 1 - input.len()));
    assert_eq!(input.len(), MAX_RECORD_BYTES + 1);
    assert_eq!(
        scrub_text_checked(&input).unwrap_err().code,
        "text_too_large"
    );
    assert_eq!(scrub_text(&input), REDACTION_TOKEN);
    assert_eq!(scrub_long(&input), REDACTION_TOKEN);
    let report = scrub_report(&input, Policy::Secrets);
    assert_eq!(report.text, REDACTION_TOKEN);
    assert_eq!(report.redactions, vec![0..input.len()]);
}

// Cause: the JSON counterpart of path 1. `scrub_json` fails admission
// (`json_too_deep` here) and returns the marker string; the checked JSON API
// returns the error.
#[test]
fn over_deep_json_is_the_whole_marker_or_refused() {
    let mut value = json!("benign leaf");
    for _ in 0..=MAX_JSON_DEPTH {
        value = json!([value]);
    }
    assert_eq!(scrub_json(&value).0, json!(REDACTION_TOKEN));
    assert_eq!(
        scrub_json_checked(&value).unwrap_err().code,
        "json_too_deep"
    );
}

// Cause: path 3. A recognizer's credential extent is the whole input, so the
// only span is 0..len. These are credentials, not benign text.
#[test]
fn a_whole_input_credential_is_one_span() {
    let access_key = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    for input in [
        access_key.as_str(),
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
    ] {
        let report = scrub_report(input, Policy::Secrets);
        assert_eq!(report.text, REDACTION_TOKEN);
        assert_eq!(report.redactions, vec![0..input.len()]);
    }
}
