#![allow(missing_docs)]
//! Reviewer-required coverage for the prose-disclosure pass: every cue against
//! same-position documentary, reference and code controls; the bounded
//! documentary allowlist and its literal siblings; the unquoted extent rule;
//! quoted values and the 1024-byte close-quote window; idempotence; and the
//! inherited alpha.9 assignment behaviour. Every oracle is the exact full
//! output, checked on the text, long, JSON and record paths with a second pass.
//! js/test/prose-disclosure-coverage.test.mjs mirrors this file on WASM.

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

fn assert_cases(cases: &[(String, String, String)]) {
    let failures: Vec<String> = cases
        .iter()
        .flat_map(|(id, input, expected)| check(id, input, expected))
        .collect();
    assert!(
        failures.is_empty(),
        "{}\n{} failures",
        failures.join("\n"),
        failures.len()
    );
}

fn fixtures(source: &str) -> Vec<Case> {
    serde_json::from_str(source).expect("valid prose fixtures")
}

const WORD_CUES: [&str; 12] = [
    "is",
    "is:",
    "was",
    "was:",
    "is now",
    "is now:",
    "set to",
    "set to:",
    "is set to",
    "is set to:",
    "was set to",
    "was set to:",
];

/// Item 1: each cue with the same value positions filled by a secret, a quoted
/// secret, a documentary word, a reference and code. Shared with
/// js/test/prose-disclosure-coverage.test.mjs.
fn cue_matrix() -> Vec<(String, String, String)> {
    let mut cases = Vec::new();
    let mut add = |input: String, expected: String| {
        cases.push((format!("cue/{input:?}"), input, expected));
    };
    for det in ["my ", "the ", ""] {
        for cue in WORD_CUES {
            let left = format!("{det}password {cue} ");
            add(format!("{left}x"), format!("{left}{R}"));
            add(format!("{left}hunter2."), format!("{left}{R}."));
            add(format!("{left}'x'"), format!("{left}'{R}'"));
            add(format!("{left}required"), format!("{left}required"));
            add(format!("{left}$PASSWORD"), format!("{left}$PASSWORD"));
        }
    }
    for cue in WORD_CUES {
        for code in [
            format!("if password {cue} None"),
            format!("assert password {cue} x"),
            format!("while password {cue} hunter2"),
            format!("self.password {cue} x"),
        ] {
            add(code.clone(), code);
        }
    }
    for det in ["my ", "the "] {
        for sep in [":", " ="] {
            let left = format!("{det}password{sep} ");
            add(format!("{left}x"), format!("{left}{R}"));
            add(format!("{left}'x'"), format!("{left}'{R}'"));
            add(format!("{left}$PASSWORD"), format!("{left}$PASSWORD"));
            // Inherited from alpha.9: after `:`/`=` the assignment scanner
            // redacts the first word even when the prose pass would call it
            // documentary, and its value takes a trailing period with it.
            // Pinned, not introduced by the prose pass.
            add(format!("{left}required"), format!("{left}{R}"));
            add(format!("{left}hunter2."), format!("{left}{R}"));
        }
        // `==` is a comparison, not a disclosure.
        for value in ["x", "hunter2", "'x'"] {
            let input = format!("{det}password == {value}");
            add(input.clone(), input);
        }
    }
    for code in [
        "password == x",
        "if password == x",
        "assert password == 'x'",
        "password: string",
    ] {
        add(code.to_owned(), code.to_owned());
    }
    cases
}

#[test]
fn every_cue_against_same_position_controls() {
    let cases = cue_matrix();
    assert_eq!(cases.len(), 3 * 12 * 5 + 12 * 4 + 2 * (2 * 5 + 3) + 4);
    assert_cases(&cases);
}

#[test]
fn allowlist_extent_quote_and_inherited_fixtures() {
    let cases = fixtures(include_str!("../eval/prose_disclosure_coverage_cases.json"));
    for family in [
        "allowlist",
        "extent_multiword",
        "extent_punctuation",
        "extent_brackets",
        "extent_conjunction",
        "extent_two_disclosures",
        "extent_line_boundary",
        "extent_no_suffix",
        "quoted",
        "inherited_assignment",
    ] {
        assert!(
            cases
                .iter()
                .any(|c| c.id.starts_with(&format!("{family}-"))),
            "{family}"
        );
    }
    for c in &cases {
        assert!(c.kind == "positive" || c.input == c.expected, "{}", c.id);
        assert!(c.kind != "positive" || c.input != c.expected, "{}", c.id);
    }
    assert_cases(
        &cases
            .into_iter()
            .map(|c| (c.id, c.input, c.expected))
            .collect::<Vec<_>>(),
    );
}

/// Two disclosures on one line are two separate spans, not one merged span.
#[test]
fn two_disclosures_on_one_line_redact_separately() {
    let output = scrub_text("my password is x and your password is y");
    assert_eq!(output.matches(R).count(), 2);
    assert_eq!(
        output,
        format!("my password is {R} and your password is {R}")
    );
}

const QUOTES: [(&str, &str); 5] = [
    ("'", "'"),
    ("\"", "\""),
    ("`", "`"),
    ("\u{201c}", "\u{201d}"),
    ("\u{2018}", "\u{2019}"),
];

/// Item 4: a close quote on a later line is honoured while it lies wholly within
/// the 1024 bytes after the opening quote (a three-byte curly close must end by
/// byte 1024); beyond that the unmatched quote redacts only through the end of
/// its own line. Shared with the JS mirror.
fn quote_window_cases() -> Vec<(String, String, String)> {
    let mut cases = Vec::new();
    for (open, close) in QUOTES {
        for interior in [1020, 1021, 1022, 1023, 1024, 1025] {
            // `abc\n` then filler, so the close always sits on a later line.
            let filler = "x".repeat(interior - 4);
            let input = format!("my password is {open}abc\n{filler}{close} tail\nlast");
            let expected = if interior + close.len() <= 1024 {
                format!("my password is {open}{R}{close} tail\nlast")
            } else {
                format!("my password is {R}\n{filler}{close} tail\nlast")
            };
            cases.push((format!("window/{open}/{interior}"), input, expected));
        }
    }
    cases
}

#[test]
fn quoted_close_within_1024_bytes_is_honoured() {
    let cases = quote_window_cases();
    assert_eq!(cases.len(), 30);
    assert_cases(&cases);
}

/// Item 5: every positive case in every prose fixture file and generated
/// matrix, scrubbed twice, is byte-identical to scrubbed once.
#[test]
fn every_positive_case_is_idempotent() {
    let mut inputs: Vec<String> = Vec::new();
    for source in [
        include_str!("../eval/prose_disclosure_cases.json"),
        include_str!("../eval/alpha9_prose_credential_cases.json"),
        include_str!("../eval/prose_disclosure_coverage_cases.json"),
    ] {
        inputs.extend(
            fixtures(source)
                .into_iter()
                .filter(|c| c.kind == "positive")
                .map(|c| c.input),
        );
    }
    inputs.extend(
        cue_matrix()
            .into_iter()
            .chain(quote_window_cases())
            .filter(|(_, input, expected)| input != expected)
            .map(|(_, input, _)| input),
    );
    assert_eq!(inputs.len(), 431);
    for input in inputs {
        let once = scrub_text(&input);
        assert_ne!(once, input, "{input:?} was not redacted");
        assert_eq!(scrub_text(&once), once, "{input:?}");
        assert_eq!(scrub_long(&once), scrub_long(&input), "{input:?} long");
    }
}

/// Item 6: `the password: see vault` comes from the alpha.9 assignment scanner,
/// unchanged by the prose-disclosure pass. The prose pass treats `see vault` as
/// documentary (a lead word followed by more words) and leaves it; the
/// assignment scanner then redacts the first word after `password:`. Pinned so
/// a later change to either pass is a visible decision.
#[test]
fn inherited_assignment_output_for_see_vault_is_pinned() {
    assert_cases(&[(
        "inherited/see-vault".to_owned(),
        "the password: see vault".to_owned(),
        format!("the password: {R} vault"),
    )]);
}
