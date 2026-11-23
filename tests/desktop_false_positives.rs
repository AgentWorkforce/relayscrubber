#![allow(missing_docs)]
//! Agent Relay Desktop over-redaction evidence for 0.5.0-alpha.11.
//!
//! Fixture: `eval/desktop_false_positive_cases.json` (invented inputs only).
//!
//! - `precision`: TypeScript/Rust type positions after a `...Key:` member.
//!   The desired output is the byte-identical input. `alpha10` records what
//!   0.5.0-alpha.10 produced; entries where it differs are the reported false
//!   positives and are checked by the `#[ignore]`d tests until alpha.11 lands.
//! - `recall`: the same positions carrying quoted, opaque, symbol-heavy or
//!   bare credential values. `secret` must never survive, on any API.
//! - `whole_body`: prose whose quote/apostrophe layout makes the fixed-point
//!   pass loop in `engine::analyze` exhaust its budget, which replaces the
//!   whole input with a single marker. The output must keep `prefix`.
//!
//! Every output must also be idempotent and identical across the checked,
//! text, long, report, JSON and NDJSON record paths.

use relayscrubber::{
    scrub_json, scrub_json_text, scrub_json_text_checked, scrub_long, scrub_records, scrub_report,
    scrub_text, scrub_text_checked, Policy, MAX_RECORD_BYTES,
};
use serde::Deserialize;
use serde_json::json;

const R: &str = "[REDACTED]";

#[derive(Deserialize)]
struct Precision {
    id: String,
    input: String,
    alpha10: String,
}

#[derive(Deserialize)]
struct Recall {
    id: String,
    input: String,
    secret: String,
}

#[derive(Deserialize)]
struct WholeBody {
    id: String,
    input: String,
    prefix: String,
}

#[derive(Deserialize)]
struct Fixture {
    precision: Vec<Precision>,
    recall: Vec<Recall>,
    whole_body: Vec<WholeBody>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../eval/desktop_false_positive_cases.json"))
        .expect("desktop false-positive fixture")
}

/// Every public text surface for one input, labelled by API.
fn outputs(input: &str) -> Vec<(&'static str, String)> {
    let value = json!({ "text": input });
    let records = scrub_records(format!("{value}\n").as_bytes()).expect("valid record");
    let record: serde_json::Value =
        serde_json::from_slice(records.bytes.trim_ascii_end()).expect("record JSON");
    vec![
        ("checked", scrub_text_checked(input).expect("admitted text")),
        ("text", scrub_text(input)),
        ("long", scrub_long(input)),
        ("report", scrub_report(input, Policy::Secrets).text),
        (
            "json",
            scrub_json(&value).0["text"].as_str().expect("text").into(),
        ),
        (
            "json_text",
            scrub_json_text(&value.to_string()).expect("valid JSON").0["text"]
                .as_str()
                .expect("text")
                .into(),
        ),
        ("records", record["text"].as_str().expect("text").into()),
    ]
}

fn check(id: &str, input: &str, accept: impl Fn(&str) -> Result<(), String>) -> Vec<String> {
    let mut failures = Vec::new();
    let all = outputs(input);
    let first = &all[0].1;
    for (api, output) in &all {
        if output != first {
            failures.push(format!(
                "{id}/{api}: parity {output:?} != checked {first:?}"
            ));
        }
        if let Err(why) = accept(output) {
            failures.push(format!("{id}/{api}: {input:?} -> {output:?}: {why}"));
        }
        if scrub_text(output) != *output {
            failures.push(format!("{id}/{api}: second pass changed {output:?}"));
        }
    }
    failures
}

fn finish(name: &str, failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{name}: {} failures\n{}",
        failures.len(),
        failures[..failures.len().min(40)].join("\n")
    );
}

fn preserved(input: &str) -> impl Fn(&str) -> Result<(), String> + '_ {
    move |output| {
        if output == input {
            Ok(())
        } else {
            Err("type position must be byte identical".into())
        }
    }
}

#[test]
fn recall_controls_redact_on_every_api() {
    let mut failures = Vec::new();
    for case in fixture().recall {
        failures.extend(check(&case.id, &case.input, |output| {
            if output.contains(&case.secret) {
                Err(format!("secret {:?} survived", case.secret))
            } else if !output.contains(R) {
                Err("no marker".into())
            } else {
                Ok(())
            }
        }));
    }
    finish("recall", &failures);
}

#[test]
fn precision_controls_already_preserved_stay_preserved() {
    let mut failures = Vec::new();
    for case in fixture().precision {
        if case.alpha10 == case.input {
            failures.extend(check(&case.id, &case.input, preserved(&case.input)));
        }
    }
    finish("precision controls", &failures);
}

#[test]
#[ignore = "alpha.10 false positives; alpha.11 owner removes this ignore with the fix"]
fn type_positions_after_key_members_are_preserved() {
    let mut failures = Vec::new();
    for case in fixture().precision {
        if case.alpha10 != case.input {
            failures.extend(check(&case.id, &case.input, preserved(&case.input)));
        }
    }
    finish("type positions", &failures);
}

#[test]
#[ignore = "alpha.10 pass-budget exhaustion; alpha.11 owner removes this ignore with the fix"]
fn prose_is_never_replaced_wholesale() {
    let mut failures = Vec::new();
    for case in fixture().whole_body {
        failures.extend(check(&case.id, &case.input, |output| {
            if output == R {
                Err("whole body replaced by one marker".into())
            } else if !output.starts_with(&case.prefix) {
                Err(format!("benign prefix {:?} lost", case.prefix))
            } else if !output.contains(R) {
                Err("credential cue no longer redacts anything".into())
            } else {
                Ok(())
            }
        }));
    }
    finish("whole body", &failures);
}

/// The fixture's whole-body entries are real budget exhaustions today: the
/// report is one range over the entire input. Kept separate so the fixture
/// cannot silently drift into inputs that are simply wholly secret.
#[test]
#[ignore = "documents alpha.10 behaviour; fails once alpha.11 fixes the fallback"]
fn alpha10_whole_body_witnesses_reproduce() {
    for case in fixture().whole_body {
        let report = scrub_report(&case.input, Policy::Secrets);
        assert_eq!(report.text, R, "{}", case.id);
        assert_eq!(report.redactions, vec![0..case.input.len()], "{}", case.id);
    }
}

/// Over-16-MiB text: the unchecked compatibility entry points fail closed to a
/// single marker, the checked entry points refuse. Neither returns input bytes.
#[test]
fn oversize_compatibility_marker_versus_checked_refusal() {
    let input = "benign prose. ".repeat(MAX_RECORD_BYTES / 14 + 1);
    assert!(input.len() > MAX_RECORD_BYTES);
    assert_eq!(scrub_text(&input), R);
    assert_eq!(scrub_long(&input), R);
    let report = scrub_report(&input, Policy::Secrets);
    assert_eq!(report.text, R);
    assert_eq!(report.redactions, vec![0..input.len()]);
    assert_eq!(
        scrub_text_checked(&input).expect_err("refused").code,
        "text_too_large"
    );
    let encoded = json!({ "text": input }).to_string();
    assert_eq!(
        scrub_json_text_checked(&encoded).expect_err("refused").code,
        "record_too_large"
    );
    assert!(scrub_json_text(&encoded).is_none());
}
