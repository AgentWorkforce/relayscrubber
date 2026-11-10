#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};
#[test]
fn config_evidence_survives_comments_blanks_and_quoted_keys() {
    for (key, value) in [
        ("auth", "the production credential"),
        ("password", "the actual secret value"),
    ] {
        for quote in ["", "\"", "'"] {
            for input in [
                format!("{quote}{key}{quote}: {value}\n\n# explanation\nnext: unchanged"),
                format!("next: unchanged\n# explanation\n\n{quote}{key}{quote}: {value}"),
                format!("```yaml\n\n{quote}{key}{quote}: {value}\n```"),
                format!("# app.yaml\n\n{quote}{key}{quote}: {value}"),
            ] {
                let expected = input.replace(value, REDACTION_TOKEN);
                let wrapper = json!({"text":input});
                assert_eq!(scrub_text(&input), expected);
                assert_eq!(scrub_json(&wrapper).0["text"], expected);
                let out = scrub_records(&serde_json::to_vec(&wrapper).unwrap()).unwrap();
                assert_eq!(
                    serde_json::from_slice::<Value>(&out.bytes).unwrap()["text"],
                    expected
                );
            }
        }
    }
}
#[test]
fn structured_config_and_identifiers_preserve_nested_secret_scanning() {
    let input = json!({"auth":{"scheme":"oidc","audience":"demo-ui","enabled":true},"session_id":"exec-7f3a2b1c","credentialsSecret":"catalog-access-store","password":"[REDACTED] (already removed)","api_key":"process.env.APP_KEY"});
    assert_eq!(scrub_json(&input).0, input);
    let output = scrub_records(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.bytes).unwrap(),
        input
    );
    let input = json!({"auth":{"scheme":"oidc","password":"SYNTH_ALPHA","key":"SYNTH_BETA"}});
    let expected =
        json!({"auth":{"scheme":"oidc","password":REDACTION_TOKEN,"key":REDACTION_TOKEN}});
    assert_eq!(scrub_json(&input).0, expected);
    let output = scrub_records(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output.bytes).unwrap(),
        expected
    );
}
