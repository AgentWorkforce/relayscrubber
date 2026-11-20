#![allow(missing_docs)]
//! Bounded work for descriptor-separated disclosures (0.5.0-alpha.11). Each
//! noun reads at most `DESCRIPTOR_TOKENS` words with the descriptor grammar;
//! the fail-closed search past the bound depends only on where it starts and
//! is reused by every later noun that starts inside it, so long descriptors,
//! long prefixes and runs of nouns stay linear.
use relayscrubber::scrub_text;
use std::time::{Duration, Instant};

#[test]
fn bounded_descriptor_work_at_64_and_256_kib() {
    let _ = scrub_text("warmup");
    for size in [65_536, 262_144] {
        for unit in [
            "the password for a ",
            "pw for pw for ",
            "password used by a.b-c ",
            "pw for (a ",
            "pw for \"a ",
            "pw for 'a b' ",
            "pw for [a] (b) ",
            "pw for a\n",
            "pw for a\n\n",
            "pw for a: ",
            "pw for a is ",
            "pw for a = b ",
            "pw for a, ",
            "pw for a and ",
            "pw in pw in ",
            "pw for a). ",
            "pw for a\\\" ",
            "pw for x:: ",
        ] {
            for prefix in ["", "x \"", "{\"note\":\"", "the password for "] {
                let input = format!("{prefix}{}", unit.repeat(size / unit.len() + 1));
                let input = &input[..size];
                let start = Instant::now();
                std::hint::black_box(scrub_text(input));
                let elapsed = start.elapsed();
                eprintln!("descriptor {size} {unit:?} {prefix:?} {elapsed:?}");
                assert!(
                    elapsed < Duration::from_secs(5),
                    "descriptor family {unit:?} after {prefix:?} exceeded the CI bound"
                );
            }
        }
    }
}

// One descriptor that never reaches a cue: a single noun, then words up to
// the size; and a long prefix of prose before one descriptor.
#[test]
fn bounded_long_descriptor_and_long_prefix_work_at_64_and_256_kib() {
    let _ = scrub_text("warmup");
    for size in [65_536, 262_144] {
        for (head, unit, tail) in [
            ("the password for ", "a ", " is x"),
            ("the password for ", "(a ", " is x"),
            ("the password for ", "\"a ", " is x"),
            ("the password for ", "a, ", " is x"),
            ("the password for ", "a\n", " is x"),
            ("", "word ", "the password for the box is x"),
            ("", "pw ", "the password for the box is x"),
            ("", "for ", "the password for the box is x"),
            ("x \"", "the box ", "the password for the box is x"),
        ] {
            let body = unit.repeat((size - head.len() - tail.len()) / unit.len());
            let input = format!("{head}{body}{tail}");
            let start = Instant::now();
            std::hint::black_box(scrub_text(&input));
            let elapsed = start.elapsed();
            eprintln!("long {size} {head:?} {unit:?} {elapsed:?}");
            assert!(
                elapsed < Duration::from_secs(5),
                "long descriptor {head:?} {unit:?} exceeded the CI bound"
            );
        }
    }
}
