#![allow(missing_docs)]

use proptest::prelude::*;
use relayscrubber::{scrub_json, scrub_json_text, scrub_long, scrub_text, REDACTION_TOKEN};
use serde_json::{Map, Number, Value};

fn json_value() -> BoxedStrategy<Value> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| Value::Number(Number::from(n))),
        "[A-Za-z0-9_@. :/=-]{0,80}".prop_map(Value::String),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::vec(("[A-Za-z0-9_@.-]{1,24}", inner), 0..8).prop_map(|entries| {
                let mut map = Map::new();
                for (key, value) in entries {
                    map.insert(key, value);
                }
                Value::Object(map)
            }),
        ]
    })
    .boxed()
}

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

    }

    #[test]
    fn json_entry_points_agree_and_are_idempotent(value in json_value()) {
        let text = serde_json::to_string(&value).unwrap();
        let from_text = scrub_json_text(&text).unwrap();
        prop_assert_eq!(&from_text, &scrub_json(&value));

        let clean_text = serde_json::to_string(&from_text.0).unwrap();
        let twice = scrub_json_text(&clean_text).unwrap();
        prop_assert_eq!(&twice.0, &from_text.0);
        prop_assert_eq!(twice.1, 0);
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
