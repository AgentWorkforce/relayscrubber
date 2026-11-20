#![allow(missing_docs)]
use relayscrubber::scrub_text;
use std::time::{Duration, Instant};

#[test]
fn bounded_adversarial_work_at_64_and_256_kib() {
    let _ = scrub_text("warmup");
    for size in [65_536, 262_144] {
        for unit in [
            "\\",
            "\\u00e9",
            "%252525",
            "idempotency_key=",
            "password=\"",
            "\"password\" ",
            "x://u:",
            "-----BEGIN PRIVATE KEY-----",
            "[[[[[[",
            "eyJ...........",
        ] {
            let input = unit.repeat(size / unit.len() + 1);
            let input = &input[..size];
            let start = Instant::now();
            std::hint::black_box(scrub_text(input));
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "adversarial family exceeded the CI bound"
            );
        }
    }
}

// Prose disclosure families: the line's quote, bracket and list state is
// built once per line, so each family stays linear with every prefix.
#[test]
fn bounded_prose_disclosure_work_at_64_and_256_kib() {
    let _ = scrub_text("warmup");
    for size in [65_536, 262_144] {
        for unit in [
            "pw: \"x\" ",
            "x \"pw: a\" ",
            "{\"note\":\"pw: \\\"a\\\"'b'",
            "\"pw=\"",
            "\\\"password=\\\"",
            "pw: \"a\"\\\"b\\\"",
            "password=\"$a\"\"b\" ",
            "pw: \"a\"\"$b\" ",
            "x \"pw: a\"<b> ",
            "pw: ${a}b ",
        ] {
            for prefix in ["", "x \"", "{\"note\":\""] {
                let input = format!("{prefix}{}", unit.repeat(size / unit.len() + 1));
                let input = &input[..size];
                let start = Instant::now();
                std::hint::black_box(scrub_text(input));
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "prose disclosure family {unit:?} after {prefix:?} exceeded the CI bound"
                );
            }
        }
    }
}

// Where a bare value ends: at the close of the bracket the line opened, at
// the next key of a `;` or `&` list, or at text glued to a quote close. Each
// is found from per-line state, not by scanning to the line end per key.
#[test]
fn bounded_prose_value_end_work_at_64_and_256_kib() {
    let _ = scrub_text("warmup");
    for size in [65_536, 262_144] {
        for unit in [
            "pw: a, (",
            "pw: a, {",
            "pw: a, f(",
            "f(pw: a, ",
            "pw: a, Note(",
            "pw: a, x = {",
            "password=a, f(",
            "pw: asee below, Note(",
            "; a=b&pw: ",
            "a=b; pwd:\t",
            "\\u0022]; a=b&passcode: =",
            "\\\"&'pw:\\u0022\"x",
            "\"pw:a\"<b",
            "\"pw:a\"{{b",
        ] {
            for prefix in ["", "x \"", "{\"note\":\""] {
                let input = format!("{prefix}{}", unit.repeat(size / unit.len() + 1));
                let input = &input[..size];
                let start = Instant::now();
                std::hint::black_box(scrub_text(input));
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "prose value end family {unit:?} after {prefix:?} exceeded the CI bound"
                );
            }
        }
    }
}
