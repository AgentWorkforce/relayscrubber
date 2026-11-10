#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};
fn paths(input: &str) -> Vec<String> {
    let value = json!({"text":input});
    let records = scrub_records(value.to_string().as_bytes()).unwrap();
    vec![
        scrub_text(input),
        scrub_json(&value).0["text"].as_str().unwrap().into(),
        serde_json::from_slice::<Value>(&records.bytes).unwrap()["text"]
            .as_str()
            .unwrap()
            .into(),
    ]
}
fn family(name: &str) {
    let cases: Value = serde_json::from_str(
        &include_str!("../eval/family_cases.json")
            .replace("STRIPE_LIVE_PREFIX_", &["sk", "_live_"].concat()),
    )
    .unwrap();
    for input in cases["benign"][name].as_array().unwrap() {
        let input = input.as_str().unwrap();
        for output in paths(input) {
            assert_eq!(output, input, "{name}");
        }
    }
}
macro_rules! families { ($($name:ident),*) => { $(#[test] fn $name() { family(stringify!($name)); })* }; }
families!(
    marker_plus_syntax,
    marker_scope_overrun,
    uuid_session_identifier,
    synthetic_test_literal,
    secret_resource_reference,
    angle_placeholder,
    authorization_reference_or_scheme,
    shell_default_reference,
    nonsecret_language_literal,
    url_documentation_placeholder,
    type_declaration_or_syntax,
    operator_or_regex_syntax,
    prose_or_comment,
    code_expression_or_reference
);
#[test]
fn positive_controls_remain_redacted() {
    let cases: Value = serde_json::from_str(
        &include_str!("../eval/family_cases.json")
            .replace("STRIPE_LIVE_PREFIX_", &["sk", "_live_"].concat()),
    )
    .unwrap();
    for case in cases["positive"].as_array().unwrap() {
        for output in paths(case[1].as_str().unwrap()) {
            assert!(!output.contains(case[2].as_str().unwrap()), "{}", case[0]);
            assert_eq!(scrub_text(&output), output);
        }
    }
}
#[test]
fn bare_key_requires_credential_semantics() {
    for text in [
        "key=SYNTH_ALPHA",
        "key: the dashboard column name",
        "key=normal",
        "idempotency_key=\"key=public-selector\"",
    ] {
        for output in paths(text) {
            assert_eq!(output, text);
        }
    }
    let input = json!({"key":"normal", "idempotency_key":{"key":"public-selector", "password":"SYNTH_ALPHA"}, "aws":{"key":"SYNTH_BETA"}, "request_idempotency_key":"SYNTH_GAMMA"});
    let expected = json!({"key":"normal", "idempotency_key":{"key":"public-selector", "password":REDACTION_TOKEN}, "aws":{"key":REDACTION_TOKEN}, "request_idempotency_key":REDACTION_TOKEN});
    assert_eq!(scrub_json(&input).0, expected);
    let raw = scrub_records(input.to_string().as_bytes()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&raw.bytes).unwrap(),
        expected
    );
}
#[test]
fn profile_and_error_schema_are_crate_owned() {
    let identity = serde_json::to_value(manifest()).unwrap();
    assert_eq!(identity["schema"], 3);
    assert_eq!(identity["abiVersion"], 2);
    assert_eq!(identity["scrubProfile"], "relayhistory-secrets-v10");
    let error = scrub_json_text_checked("{broken}").unwrap_err();
    assert_eq!(
        serde_json::to_value(error).unwrap(),
        json!({"code":"invalid_json","disposition":"call_refusal"})
    );
}
