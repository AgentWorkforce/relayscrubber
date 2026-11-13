#![allow(missing_docs)]
//! An exact `project_key` whose value is a normalized repository identity
//! (`host.tld/owner/repo`) is preserved on every path; any other value, any
//! prefixed name and any independently recognized credential stays redacted.
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

fn both_structured(input: Value, expected: Value) {
    assert_eq!(scrub_json(&input).0, expected, "scrub_json {input}");
    let raw = scrub_records(format!("{input}\n").as_bytes()).unwrap();
    let line = String::from_utf8(raw.bytes).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(line.trim_end()).unwrap(),
        expected,
        "scrub_records {input}"
    );
}

const IDENTITIES: &[&str] = &[
    "github.com/example/overlap-sandbox",
    "github.com/AgentWorkforce/relayhistory-pipeline",
    "gitlab.com/group/subgroup/project.name",
    "git.internal.example/team_a/repo-2",
    "bitbucket.org/owner/repo.git",
];

#[test]
fn repository_identity_is_kept_in_every_spelling_and_path() {
    for id in IDENTITIES {
        for text in [
            format!("project_key: {id}"),
            format!("project_key={id}"),
            format!("PROJECT_KEY={id}"),
            format!("project-key: \"{id}\""),
            format!("\"project_key\":\"{id}\""),
            format!("{{\"projectKey\":\"{id}\",\"repo_url\":\"https://{id}\"}}"),
            format!("projectKey: '{id}'"),
        ] {
            for output in paths(&text) {
                assert_eq!(output, text);
            }
        }
        both_structured(
            json!({"project_key": id, "nested": {"projectKey": id}}),
            json!({"project_key": id, "nested": {"projectKey": id}}),
        );
    }
}

#[test]
fn other_project_key_values_stay_redacted() {
    for value in [
        // Vendor project keys and opaque tokens.
        "c0ab12cd_SYNTHaZ91bY82cX73dW64eV55",
        "SYNTHETICaZ91bY82cX73dW64eV55",
        "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        // Local paths and anything that is not host/owner/repo.
        "/Users/someone/Projects/app",
        "~/src/app",
        "C:/src/app",
        "github.com/only-owner",
        "github.com",
        "localhost/owner/repo",
        "github.com/owner/../repo",
        "github.com//repo",
        "https://github.com/owner/repo",
        "user:pw@github.com/owner/repo",
        "github.com:443/owner/repo",
        "github.com/owner/repo?token=abc",
        "github.com/owner/repo name",
        "github.com/a/b/c/d/e/f/g/h/i",
        // A generated-looking atom inside an otherwise path-shaped value.
        "github.com/owner/a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "github.com/a94a8fe5ccb19ba61c4c/repo",
        "github.com/owner/SYNTHETICaZ91bY82cX73dW64eV55",
    ] {
        let text = format!("project_key={value}");
        for output in paths(&text) {
            assert!(!output.contains(value), "{text} -> {output}");
        }
        both_structured(
            json!({"project_key": value}),
            json!({"project_key": REDACTION_TOKEN}),
        );
    }
}

#[test]
fn only_the_exact_name_is_exempt() {
    let id = "github.com/example/overlap-sandbox";
    for name in [
        "deta_project_key",
        "DETA_PROJECT_KEY",
        "request_project_key",
        "projectKeySecret",
    ] {
        let text = format!("{name}={id}");
        for output in paths(&text) {
            assert!(!output.contains(id), "{text} -> {output}");
        }
        both_structured(json!({ name: id }), json!({ name: REDACTION_TOKEN }));
    }
}

#[test]
fn credentials_inside_or_beside_a_kept_identity_still_redact() {
    let stripe = ["sk", "_live_", "SYNTHETICaZ91bY82cX73dW64eV55"].concat();
    for text in [
        format!("project_key=github.com/o/r password=\"{stripe}\""),
        format!("{{\"project_key\":\"github.com/o/r\",\"api_key\":\"{stripe}\"}}"),
        format!("project_key: {stripe}"),
        format!("project_key=github.com/o/{stripe}"),
    ] {
        for output in paths(&text) {
            assert!(
                !output.contains("SYNTHETICaZ91bY82cX73dW64eV55"),
                "{text} -> {output}"
            );
            assert_eq!(scrub_text(&output), output, "idempotent: {text}");
        }
    }
    // A sensitive key's composite value is redacted whole; the exemption is for a string.
    both_structured(
        json!({"project_key": {"value": "github.com/o/r"}, "api_key": stripe}),
        json!({"project_key": REDACTION_TOKEN, "api_key": REDACTION_TOKEN}),
    );
}

#[test]
fn encoded_identity_is_judged_on_each_paths_own_view() {
    // Text recognition decodes percent spellings (as for every field reference), so an
    // encoded repository path is still a repository path there and is kept. A structured
    // property value is judged literally, and `%` keeps it sensitive. Neither emits
    // credential bytes.
    for value in ["github.com/owner/repo%2Fx", "github.com%2Fowner%2Frepo"] {
        let text = format!("project_key={value}");
        assert_eq!(scrub_text(&text), text);
        both_structured(
            json!({"project_key": value}),
            json!({"project_key": REDACTION_TOKEN}),
        );
    }
    let text = "project_key=github.com/o/r%20password=SYNTHaZ91bY82cX73dW64";
    assert!(!scrub_text(text).contains("SYNTHaZ91bY82cX73dW64"));
}
