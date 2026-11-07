#![allow(missing_docs)]

use proptest::prelude::*;
use relayscrubber::{scrub_json_text, scrub_long, scrub_text, REDACTION_TOKEN};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn bounded_and_segmented_scrubs_are_idempotent(input in ".{0,2048}") {
        let once = scrub_text(&input);
        let twice = scrub_text(&once);
        prop_assert_eq!(twice, once);

        let long_once = scrub_long(&input);
        let long_twice = scrub_long(&long_once);
        prop_assert_eq!(long_twice, long_once);

        let _ = scrub_json_text(&input);
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
