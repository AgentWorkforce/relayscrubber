#![allow(missing_docs)]

use relayscrubber::{MAX_SCRUB_CHARS, exceeds_scrub_bound, scrub_text};
use std::borrow::Cow;

#[test]
fn unchanged_inputs_stay_borrowed_even_when_custom_scanners_inspect_them() {
    let sha = "a".repeat(40);
    let input = format!("commit {sha} (HEAD -> main)");
    assert!(matches!(scrub_text(&input), Cow::Borrowed(_)));

    let large = "ordinary transcript text\n".repeat(10_000);
    assert!(!exceeds_scrub_bound(&large));
    assert!(matches!(scrub_text(&large), Cow::Borrowed(_)));
}

#[test]
fn oversized_input_is_bounded_and_announced() {
    let input = format!("{} tail", "safe ".repeat(MAX_SCRUB_CHARS / 5 + 10));
    let output = scrub_text(&input);
    assert!(matches!(output, Cow::Owned(_)));
    assert!(output.contains("[relayhistory: truncated"));
}
