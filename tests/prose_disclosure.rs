#![allow(missing_docs)]
//! Natural-language password disclosures (`my password is x`) are redacted with
//! no minimum value length, while documentary and reference forms stay byte
//! identical. Every case runs through the text, long, JSON and record paths and
//! must be idempotent.

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

const R: &str = "[REDACTED]";
const PUBLIC: &str = "QUALIFICATION_PUBLIC_CONTEXT";

fn check(id: &str, input: &str, expected: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let value = json!({ "text": input });
    let records = scrub_records(value.to_string().as_bytes()).expect("valid record");
    let outputs = [
        ("checked", scrub_text_checked(input).expect("admitted text")),
        ("text", scrub_text(input)),
        ("long", scrub_long(input)),
        (
            "json",
            scrub_json(&value).0["text"]
                .as_str()
                .expect("JSON text")
                .to_owned(),
        ),
        (
            "records",
            serde_json::from_slice::<serde_json::Value>(&records.bytes).unwrap()["text"]
                .as_str()
                .expect("record text")
                .to_owned(),
        ),
    ];
    for (api, output) in outputs {
        if output != expected {
            failures.push(format!(
                "{id}/{api}: {input:?} -> {output:?}, want {expected:?}"
            ));
        } else if scrub_text(&output) != output {
            failures.push(format!("{id}/{api}: second pass changed {output:?}"));
        }
    }
    if scrub_records(&records.bytes).expect("second pass").bytes != records.bytes {
        failures.push(format!("{id}/records: second pass changed"));
    }
    failures
}

#[test]
fn reviewer_documentary_and_reference_cases() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../eval/prose_disclosure_cases.json")).unwrap();
    assert!(
        cases
            .iter()
            .filter(|c| c.id.starts_with("reviewer"))
            .count()
            == 6
    );
    let failures: Vec<String> = cases
        .iter()
        .inspect(|c| assert!(c.kind == "positive" || c.input == c.expected))
        .flat_map(|c| check(&c.id, &c.input, &c.expected))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `eval/disclosure-coverage.mjs` casing, applied to each phrase separately.
fn casing(text: &str, mode: &str) -> String {
    match mode {
        "upper" => text.to_uppercase(),
        "mixed" => text
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 1 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect(),
        _ => text.to_lowercase(),
    }
}

/// The 216 `pr21_required_short_values` generated cases (password, passcode,
/// passphrase, pw) extended with passwd, pwd and the spaced `pass code` and
/// `pass phrase`: every noun x is/was/colon x casing x quote x one letter or
/// one symbol, with the exact expected output.
#[test]
fn one_character_values_are_required() {
    let mut failures = Vec::new();
    let mut count = 0;
    for noun in [
        "password",
        "passcode",
        "passphrase",
        "pw",
        "passwd",
        "pwd",
        "pass code",
        "pass phrase",
    ] {
        for connector in ["is", "was", ":"] {
            for mode in ["lower", "upper", "mixed"] {
                for quote in ["", "'", "\""] {
                    for value in ["q", "!"] {
                        let left = format!(
                            "{PUBLIC}\n{} {} {} {quote}",
                            casing("my", mode),
                            casing(noun, mode),
                            casing(connector, mode)
                        );
                        let input = format!("{left}{value}{quote}");
                        let expected = format!("{left}{R}{quote}");
                        failures.extend(check(&format!("{noun}/{connector}"), &input, &expected));
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 432);
    assert!(
        failures.is_empty(),
        "{}\n{} failures",
        failures.join("\n"),
        failures.len()
    );
}
