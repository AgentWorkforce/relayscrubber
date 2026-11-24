#![allow(missing_docs)]
//! Pass-budget exhaustion (0.5.0-alpha.11). Prose whose apostrophes and
//! stray quotes kept the post-redaction fixed point from settling used to come
//! back as the single whole-input marker. A `'` between two letters or digits
//! is an apostrophe and pairs with no quote, and a quote that directly opens a
//! value (`key='value`) never closes an earlier quote, so these inputs settle
//! in one pass. Inputs that still do not settle keep every byte before the
//! earliest unstable span and fail closed from there to the end.
//!
//! All inputs are invented. `SYNTH...` strings stand for credentials.

use relayscrubber::{
    scrub_json, scrub_json_text, scrub_long, scrub_records, scrub_report, scrub_text,
    scrub_text_checked, Policy, REDACTION_TOKEN,
};
use serde_json::json;
use std::time::{Duration, Instant};

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

fn assert_exact(input: &str, expected: &str) {
    for (api, output) in outputs(input) {
        assert_eq!(output, expected, "{api}: {input:?}");
    }
    assert_eq!(scrub_text(expected), expected, "second pass: {input:?}");
}

#[test]
fn whole_body_witnesses_keep_their_benign_prefix() {
    for (input, expected) in [
        (
            "pwd: ' let's I'll you're won't here",
            "pwd: '[REDACTED]",
        ),
        (
            "Summary: the deploy worked. I didn't touch the PASSWORD=' line because it's generated, and that's fine; we'll revisit it once you're back and I've rotated the key.",
            "Summary: the deploy worked. I didn't touch the PASSWORD='[REDACTED]",
        ),
        (
            "Here's what I found. The login form's pwd: ' placeholder isn't rendered, so it's blank. I'll fix that; we're close and you're unblocked.",
            "Here's what I found. The login form's pwd: '[REDACTED]",
        ),
        (
            "The password: ' it's in 1Password, I'll share it, don't worry, we're fine, you're set",
            "The password: '[REDACTED]",
        ),
        (
            "Note: the deploy finished and tests pass.\npassword=\"\"D\"\"\n=\n\"= ",
            "Note: the deploy finished and tests pass.\npassword=\"[REDACTED]",
        ),
    ] {
        assert_exact(input, expected);
        let report = scrub_report(input, Policy::Secrets);
        assert!(!report.redactions.contains(&(0..input.len())), "{input:?}");
    }
}

/// Credentials inside quoted extents that contain apostrophes, or whose
/// opening quote could pair with an earlier quote, still redact.
#[test]
fn credentials_in_apostrophe_and_reused_quote_extents_redact() {
    for (input, expected) in [
        ("password='ab'cd' and more", "password='[REDACTED]"),
        ("The password: 'Zx9q's7Lm' ok", "The password: '[REDACTED]"),
        ("password = 'it's-a-SYNTHsecret9'", "password = '[REDACTED]"),
        (
            "token: 'pass key we and placeholder PASSWORD='SYNTHq8Zr4TfX2wLm key form the back",
            "token: '[REDACTED]",
        ),
        (
            "token: 'pass key we and I've placeholder PASSWORD='SYNTHq8Zr4TfX2wLm key",
            "token: '[REDACTED]",
        ),
        (
            "it's fine. secret = '\"SYNTHq8Zr4TfX2wLm I'll check",
            "it's fine. secret = '[REDACTED]",
        ),
        (
            "pw 'Here's because back secret = '\"SYNTHq8Zr4TfX2wLm I'll check",
            "pw 'Here's because back secret = '[REDACTED]",
        ),
        (
            "note 'revisit password: \"'SYNTHzX9kLm2Qp7Rt blank",
            "note 'revisit password: \"[REDACTED]",
        ),
        (
            "We're done. password: 'SYNTHq8Zr4TfX2wLm' and that's it",
            "We're done. password: '[REDACTED]' and that's it",
        ),
        (
            "We're done. password: \"SYNTHq8Zr4TfX2wLm\" and that's it",
            "We're done. password: \"[REDACTED]\" and that's it",
        ),
    ] {
        assert_exact(input, expected);
    }
}

#[test]
fn apostrophes_and_closed_quotes_stay_unchanged() {
    for input in [
        "I said 'don't' here",
        "<a href=\"https://media.example.invalid/?caption=audit&#;sig=\">open</a>",
        "sep = ':'\nname = 'it's'",
        "{\"a\":\"b\",\"c\":\"it's\"}",
        "x = '=' + y; z = 'a: ' + w",
        "It's the team's call; we'll ship when it's ready and they're back.",
    ] {
        assert_exact(input, input);
    }
}

/// Adversarial quote and apostrophe layouts stay within the CI bound: at
/// most seven analysis passes run on any input.
#[test]
fn bounded_work_on_quote_and_apostrophe_runs() {
    let _ = scrub_text("warmup");
    for size in [65_536, 262_144] {
        for unit in [
            "pwd: ' let's I'll ",
            "it's 'a' don't ",
            "password='' it's ",
            "PASSWORD=' x' y's ",
            "'\"'\" it's ",
            "token: 'a b=' c's ",
            "password=\"\"D\"\"\n=\n\"= ",
            "a's b's c's ",
        ] {
            let input = unit.repeat(size / unit.len() + 1);
            let input = &input[..size];
            let start = Instant::now();
            let output = std::hint::black_box(scrub_text(input));
            let elapsed = start.elapsed();
            eprintln!("pass budget {size} {unit:?} {elapsed:?}");
            assert!(
                elapsed < Duration::from_secs(5),
                "quote layout {unit:?} exceeded the CI bound"
            );
            assert_eq!(scrub_text(&output), output, "{unit:?} not idempotent");
        }
    }
}

const WORDS: [&str; 16] = [
    "the",
    "deploy",
    "worked",
    "and",
    "tests",
    "pass",
    "line",
    "because",
    "generated",
    "fine",
    "revisit",
    "once",
    "rotated",
    "key",
    "form",
    "blank",
];
const APOSTROPHES: [&str; 10] = [
    "it's", "I'll", "don't", "we're", "you're", "won't", "let's", "didn't", "that's", "I've",
];
const CUES: [&str; 10] = [
    "password: '",
    "pwd: '",
    "PASSWORD='",
    "password=\"",
    "token: '",
    "secret = '",
    "api_key='",
    "password: \"",
    "password=''",
    "password=\"\"",
];
const QUOTES: [&str; 5] = ["'", "\"", "''", "\"\"", "`"];
const PUNCT: [&str; 5] = [".", ",", ";", ":", "\n"];
const SECRET: &str = "SYNTHq8Zr4TfX2wLm";

fn prose(next: &mut impl FnMut() -> u64) -> String {
    let mut text = String::new();
    for _ in 0..4 + next() % 36 {
        let r = next() % 100;
        let part = if r < 45 {
            WORDS[(next() % 16) as usize]
        } else if r < 70 {
            APOSTROPHES[(next() % 10) as usize]
        } else if r < 80 {
            CUES[(next() % 10) as usize]
        } else if r < 88 {
            QUOTES[(next() % 5) as usize]
        } else if r < 97 {
            PUNCT[(next() % 5) as usize]
        } else {
            SECRET
        };
        if !text.is_empty() && !text.ends_with(['\'', '"', '\n']) && !PUNCT.contains(&part) {
            text.push(' ');
        }
        text.push_str(part);
    }
    text
}

/// Generated prose with apostrophes, credential cues and stray quotes: every
/// output is idempotent, identical on the text, long and report paths, keeps
/// a leading benign sentence, and never keeps a cue directly followed by the
/// invented credential.
#[test]
fn generated_prose_is_stable_and_keeps_its_prefix() {
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let prefix = "Plain words come first.\n";
    for _ in 0..4_000 {
        let body = prose(&mut next);
        for input in [body.clone(), format!("{prefix}{body}")] {
            let output = scrub_text(&input);
            assert_eq!(scrub_long(&input), output, "long: {input:?}");
            assert_eq!(
                scrub_report(&input, Policy::Secrets).text,
                output,
                "report: {input:?}"
            );
            assert_eq!(scrub_text(&output), output, "second pass: {input:?}");
            for cue in CUES {
                let leaked = format!("{cue}{SECRET}");
                assert!(
                    !(input.contains(&leaked) && output.contains(&leaked)),
                    "{input:?} -> {output:?}"
                );
            }
            if input.starts_with(prefix) {
                assert!(output.starts_with(prefix), "{input:?} -> {output:?}");
                assert_ne!(output, REDACTION_TOKEN);
            }
        }
    }
}
