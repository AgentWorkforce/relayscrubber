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

/// A quote glued to a letter or digit that opens a literal (`f'x'`, `b'abc'`,
/// `-m'wip'`) still opens it, so every later single quote keeps its role and
/// a later space-separated cue's quoted value still redacts, with the output
/// 0.5.0-alpha.10 gave.
#[test]
fn glued_quote_openers_keep_later_quotes_paired() {
    for (input, expected) in [
        (
            "echo f'x'\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "echo f'x'\nlogin --password '[REDACTED]' --note 'hello'",
        ),
        (
            "echo f'x'\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm'",
            "echo f'x'\nlogin --password '[REDACTED]'",
        ),
        (
            "x = b'abc'\ny = 2\n\nlogin --token 'correct horse SYNTHq8Zr4TfX2wLm' end",
            "x = b'abc'\ny = 2\n\nlogin --token '[REDACTED]' end",
        ),
        (
            "git commit -m'wip'\nmysql -u root --password 'SYNTHq8Zr4TfX2wLm' -e 'select 1' db",
            "git commit -m'wip'\nmysql -u root --password '[REDACTED]' -e 'select 1' db",
        ),
        (
            "print(f'hi')\nAuthorization: Bearer 'SYNTHq8Zr4TfX2wLm' 'x' trailing",
            "print(f'hi')\nAuthorization: [REDACTED]",
        ),
        (
            "echo f'x' && login --password 'correct horse SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "echo f'x' && login --password '[REDACTED]' --note 'hello'",
        ),
        (
            "sed -i's/a/b/' f\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm' 'second' 'third' end",
            "sed -i's/a/b/' f\nlogin --password '[REDACTED]' 'second' 'third' end",
        ),
        (
            "x = b's'\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "x = b's'\nlogin --password '[REDACTED]' --note 'hello'",
        ),
        (
            "y = f'd'\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "y = f'd'\nlogin --password '[REDACTED]' --note 'hello'",
        ),
        (
            "git commit -m'wip\n\nmore'\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "git commit -m'wip\n\nmore'\nlogin --password '[REDACTED]' --note 'hello'",
        ),
        (
            "it's the dogs' bowl\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "it's the dogs' bowl\nlogin --password '[REDACTED]' --note 'hello'",
        ),
        (
            "curl -H'Accept: text/plain' -H 'Authorization: Bearer SYNTHq8Zr4TfX2wLm' https://example.test/a\necho done",
            "curl -H'Accept: text/plain' -H 'Authorization: [REDACTED]' https://example.test/a\necho done",
        ),
        (
            "x = b'abc'\nrun('password=SYNTHq8Zr4TfX2wLm', 1)\nprint('ok')",
            "x = b'abc'\nrun('password=[REDACTED]', 1)\nprint('ok')",
        ),
    ] {
        assert_exact(input, expected);
    }
}

/// Contractions, possessives and names keep reading as apostrophes, so a
/// later quoted value still redacts.
#[test]
fn contractions_before_quoted_values_still_redact() {
    for (input, expected) in [
        (
            "it's\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "it's\nlogin --password '[REDACTED]' --note 'hello'",
        ),
        (
            "I can't\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "I can't\nlogin --password '[REDACTED]' --note 'hello'",
        ),
        (
            "I'm sure. I'd say I've\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "I'm sure. I'd say I've\nlogin --password '[REDACTED]' --note 'hello'",
        ),
        (
            "{'user':'o'neil','password':'a b SYNTHq8Zr4TfX2wLm','x':1}",
            "{'user':'o'neil','password':'[REDACTED]','x':1}",
        ),
        (
            "I can't log in, password: 'a b SYNTHq8Zr4TfX2wLm' doesn't work",
            "I can't log in, password: '[REDACTED]' doesn't work",
        ),
        (
            "api_key='I've got SYNTHq8Zr4TfX2wLm",
            "api_key='[REDACTED]",
        ),
        (
            "token: 'abc'def'SYNTHq8Zr4TfX2wLm'",
            "token: '[REDACTED]'",
        ),
        ("db_password='3'SYNTHq8Zr4TfX2wLm", "db_password='[REDACTED]"),
        (
            "the 90's were fine. password='SYNTHq8Zr4TfX2wLm' and more text here",
            "the 90's were fine. password='[REDACTED]' and more text here",
        ),
        (
            "the dogs' bowl. password='SYNTHq8Zr4TfX2wLm' and more text here",
            "the dogs' bowl. password='[REDACTED]' and more text here",
        ),
        (
            "He said 'it's fine' and password='SYNTHq8Zr4TfX2wLm' and more text here",
            "He said 'it's fine' and password='[REDACTED]' and more text here",
        ),
    ] {
        assert_exact(input, expected);
    }
}

/// A possessive, a literal glued to a prefix and a contraction inside a
/// quoted argument can each be read two ways; no reading leaves the value.
#[test]
fn possessives_and_quoted_contractions_never_leave_a_value() {
    for (input, expected) in [
        (
            "echo 'token=I've got SYNTHYcyRiBDEwjsYZa'",
            "echo 'token=[REDACTED]'",
        ),
        (
            "curl -H 'X-Api-Key: I've got SYNTHYcyRiBDEwjsYZa' https://example.test",
            "curl -H 'X-Api-Key: [REDACTED]' https://example.test",
        ),
        (
            "echo 'token=I've got SYNTHq8Zr4TfX2wLm'",
            "echo 'token=[REDACTED]'",
        ),
        (
            "echo 'token=I've got SYNTHq8Zr4TfX2wLm' --note 'hello'",
            "echo 'token=[REDACTED]' --note 'hello'",
        ),
        (
            "curl -H 'X-Api-Key: I've got SYNTHq8Zr4TfX2wLm' https://example.test/a\necho done",
            "curl -H 'X-Api-Key: [REDACTED]' https://example.test/a\necho done",
        ),
        (
            "SELECT N'nchar'\n\nthe dogs' bowl && login --token 'SYNTHq8Zr4TfX2wLm' 'x' trailing",
            "SELECT N'nchar'\n\nthe dogs' bowl && login --token '[REDACTED]' 'x' trailing",
        ),
        (
            "y = f'd'\nthe users' list tool --secret 'SYNTHq8Zr4TfX2wLm' and it's fine",
            "y = f'd'\nthe users' list tool --secret '[REDACTED]' and it's fine",
        ),
        (
            "you'll see; x = 'a' + 'b'; the dogs' bowl\nlogin --token 'SYNTHq8Zr4TfX2wLm'",
            "you'll see; x = 'a' + 'b'; the dogs' bowl\nlogin --token '[REDACTED]'",
        ),
    ] {
        assert_exact(input, expected);
    }
}

/// An unquoted value holding a `'` (`we'll`, `O'Brien`, `abc'def`) can be a
/// word with an apostrophe or a value with a quote opened inside it that is
/// never closed. Ambiguous means redact: as in 0.5.0-alpha.10, the value
/// fails closed through the open quote, so the text after its terminator
/// (`;`, `)`, `,`, a blank, a newline in a backtick) stays hidden.
#[test]
fn unquoted_values_with_an_apostrophe_fail_closed_past_their_end() {
    for (input, expected) in [
        ("token= we'll;1 SYNTHPsJzLYjnYFyv", "token= [REDACTED]"),
        ("secret=it'sok) SYNTHq8Zr4TfX2wLm", "secret=[REDACTED]"),
        ("api_key=O'Brien, SYNTHq8Zr4TfX2wLm", "api_key=[REDACTED]"),
        ("token=abc'def; echo SYNTHq8Zr4TfX2wLm", "token=[REDACTED]"),
        (
            "--password I've)SYNTHq8Zr4TfX2wLm(",
            "--password [REDACTED]",
        ),
        ("token=it's form) SYNTHRfgFvArVWSR5", "token=[REDACTED]"),
        (
            "f'x', token= don't, \"; SYNTHMtHmcJt5a8TZ",
            "f'x', token= [REDACTED]",
        ),
        (
            "secret=we'll, `SYNTHPPCGxJuAUuif\nI've",
            "secret=[REDACTED]\nI've",
        ),
        (
            "ok and;secret= y's)PASSWORD= it's; SYNTHYpzXs96bXwbu",
            "ok and;secret= [REDACTED]",
        ),
    ] {
        assert_exact(input, expected);
    }
}

/// Doubled and tripled quotes after a quoted contraction: read with every
/// `'` as a quote, the empty-looking `""` opens a value that runs on, as in
/// 0.5.0-alpha.10, so the credential after it stays hidden.
#[test]
fn doubled_quotes_after_a_contraction_keep_every_quote_reading() {
    for (input, expected) in [
        (
            "api_key='I've password=\"\"we'll '''form SYNTHq8Zr4TfX2wLm",
            "api_key='[REDACTED]",
        ),
        (
            "api_key='I've password=\"\"we'll ''form SYNTHq8Zr4TfX2wLm",
            "api_key='[REDACTED]",
        ),
        (
            "api_key='I've token=\"we'll '''form SYNTHq8Zr4TfX2wLm\"",
            "api_key='[REDACTED]",
        ),
        (
            "note='it's' secret=\"\"don't '''SYNTHq8Zr4TfX2wLm",
            "note='it's' secret=\"[REDACTED]",
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
