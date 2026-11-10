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
