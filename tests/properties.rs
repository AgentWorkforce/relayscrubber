#![allow(missing_docs)]

use proptest::prelude::*;
use relayscrubber::{REDACTION_TOKEN, scrub_text};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn scrub_is_idempotent(input in ".{0,8192}") {
        let once = scrub_text(&input);
        let twice = scrub_text(once.as_ref());
        prop_assert_eq!(twice.as_ref(), once.as_ref());
    }

    #[test]
    fn provider_tokens_never_survive(
        prefix in prop_oneof![Just("sk-proj-"), Just("ghp_"), Just("glpat-"), Just("cfut_")],
        body in "[A-Za-z0-9]{48,96}",
        left in "[^A-Za-z0-9_-]{0,4}",
        right in "[^A-Za-z0-9_-]{0,4}",
    ) {
        let token = format!("{prefix}{body}");
        let input = format!("{left}{token}{right}");
        let output = scrub_text(&input);
        prop_assert!(!output.contains(&token));
        prop_assert!(output.contains(REDACTION_TOKEN));
    }
}
