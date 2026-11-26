#![allow(missing_docs)]
//! Session-shaped JSON (0.5.0-alpha.11). Under an exact `session_id` key, ids
//! with the `ses_` and `cse_` prefixes and an ASCII letters-and-digits body of
//! 1 to 48 bytes are identifiers, like `exec-`, `call_` and `toolu_` ids.
//! Under an exact `project_key`, a bare `owner/repo` is a repository identity
//! like `host.tld/owner/repo`. Every other value under those keys stays
//! redacted, and prose under `text` is scrubbed as before.
//!
//! All values are invented. `SYNTH...` strings stand for credentials.

use relayscrubber::*;
use serde_json::{json, Value};

/// The value under `key` after `scrub_json`, `scrub_json_text` and
/// `scrub_records`, and after `scrub_text` of its JSON spelling.
fn structured(input: &Value) -> Vec<(&'static str, Value)> {
    let raw = scrub_records(format!("{input}\n").as_bytes()).expect("valid record");
    vec![
        ("json", scrub_json(input).0),
        (
            "json_text",
            scrub_json_text(&input.to_string()).expect("valid JSON").0,
        ),
        (
            "records",
            serde_json::from_slice(raw.bytes.trim_ascii_end()).expect("record JSON"),
        ),
    ]
}

fn assert_kept(key: &str, value: &str) {
    let input = json!({ key: value });
    for (api, output) in structured(&input) {
        assert_eq!(output, input, "{api}: {key} = {value:?}");
    }
    for text in [
        input.to_string(),
        format!("{key}: \"{value}\""),
        format!("{key}={value}"),
    ] {
        assert_eq!(scrub_text(&text), text, "text: {text}");
    }
}

fn assert_redacted(key: &str, value: &str) {
    let input = json!({ key: value });
    for (api, output) in structured(&input) {
        assert_eq!(
            output,
            json!({ key: REDACTION_TOKEN }),
            "{api}: {key} = {value:?}"
        );
    }
    let text = input.to_string();
    let output = scrub_text(&text);
    assert!(output.contains(REDACTION_TOKEN), "text: {text} -> {output}");
}

#[test]
fn prefixed_session_ids_are_identifiers() {
    for value in [
        "ses_ab1c23704dff3XyzqBtgHVwp41",
        "cse_018b6TwnrgeCh5Z7akcqnCvx",
        "ses_a",
        "cse_7",
        &format!("ses_{}", "aB3".repeat(16)),
        &format!("cse_{}", "Z9".repeat(24)),
    ] {
        assert_kept("session_id", value);
        assert_kept("sessionId", value);
    }
}

#[test]
fn existing_session_id_shapes_are_unchanged() {
    for value in [
        "3f2b8c1e-9d4a-4e7b-8a6c-1b2d3e4f5a6b",
        "3F2B8C1E-9D4A-4E7B-8A6C-1B2D3E4F5A6B",
        "run-42-alpha",
        "abcdefghijklmnopqrstuvwxyz012345",
        "exec-7f3a2b1c",
        "call_Ab12Cd34Ef56",
        "toolu_01AbCdEfGhIjKlMnOpQrStUv",
        "toolu_snake_case_body",
        // A lowercase id may end with a dash.
        "exec-",
    ] {
        assert_kept("session_id", value);
    }
    for value in [
        "abcdefghijklmnopqrstuvwxyz0123456",
        "Run-42",
        "call_",
        &format!("toolu_{}", "a".repeat(49)),
    ] {
        assert_redacted("session_id", value);
    }
}

#[test]
fn other_prefixed_session_ids_stay_redacted() {
    for value in [
        // Empty body.
        "ses_",
        "cse_",
        // Punctuation, separators and whitespace in the body.
        "ses_ab1c-23704dff",
        "ses_ab1c_23704dff",
        "cse_018b.6Twnrge",
        "ses_ab1c/23704dff",
        "ses_ab1c 23704dff",
        "cse_018b\t6Twnrge",
        "ses_ab1c\n23704dff",
        "ses_ab1c=",
        // Non-ASCII.
        "ses_ab1c\u{e9}23704dff",
        "cse_\u{ff10}18b6Twnrge",
        // Over the 48-byte body limit.
        &format!("ses_{}", "aB3".repeat(16) + "x"),
        &format!("cse_{}", "Z9".repeat(25)),
        // Wrong prefix or case.
        "SES_ab1c23704dff3XyzqBtgHVwp41",
        "Ses_ab1c23704dff3XyzqBtgHVwp41",
        "sess_ab1c23704dff3XyzqBtgHVwp41",
        "se_ab1c23704dff3XyzqBtgHVwp41",
        "cs_018b6TwnrgeCh5Z7akcqnCvx",
        "xses_ab1c23704dff3XyzqBtgHVwp41",
        "ses-ab1c23704dff3XyzqBtgHVwp41",
        // Opaque secrets.
        "SYNTHaZ91bY82cX73dW64eV55",
        &["sk", "_live_", "SYNTHETICaZ91bY82cX73dW64eV55"].concat(),
        &["ses_", "sk", "_live_", "SYNTHETICaZ91bY82cX73dW64eV55"].concat(),
    ] {
        assert_redacted("session_id", value);
    }
}

#[test]
fn bare_owner_repo_project_keys_are_identities() {
    for value in [
        "example/overlap-sandbox",
        "AgentWorkforce/relayhistory-pipeline",
        "team_a/repo-2",
        "owner/repo.git",
        "o/r",
        "Example-Org/project.name",
    ] {
        assert_kept("project_key", value);
        assert_kept("projectKey", value);
    }
    // Hosted and group forms are unchanged.
    for value in [
        "github.com/example/overlap-sandbox",
        "gitlab.com/group/subgroup/project.name",
    ] {
        assert_kept("project_key", value);
    }
}

#[test]
fn other_bare_project_keys_stay_redacted() {
    for value in [
        // One segment, or an empty segment.
        "overlap-sandbox",
        "owner/",
        "/repo",
        "owner//repo",
        // Three bare segments, or a dotted owner that is not a host.
        "owner/repo/extra",
        "github.com/only-owner",
        "my.org/repo",
        "C:/src/app",
        "~/src/app",
        "./repo",
        // `.` and `..`.
        "./.",
        "owner/..",
        "../repo",
        // Overlong segments.
        &format!("{}/repo", "o".repeat(101)),
        &format!("owner/{}", "r".repeat(101)),
        // Digest-like or token-like segments.
        "owner/a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "a94a8fe5ccb19ba61c4c/repo",
        "owner/abc12def34ghi56jkl78mnop90",
        "owner/SYNTHETICaZ91bY82cX73dW64eV55",
        "SYNTHaZ91bY82cX73dW64/repo",
        // Other characters and spellings.
        "owner/repo name",
        "owner:repo",
        "owner/repo?token=abc",
        // A secret.
        &["sk", "_live_", "SYNTHETICaZ91bY82cX73dW64eV55"].concat(),
        &["owner/", "sk", "_live_", "SYNTHETICaZ91bY82cX73dW64eV55"].concat(),
    ] {
        assert_redacted("project_key", value);
    }
}

const CREDENTIAL: &str = "SYNTHq8Zr4TfX2wLm7Pk";

fn event(session_id: &str, project_key: &str, text: &str) -> Value {
    json!({
        "source": "claude",
        "project": "overlap-sandbox",
        "cwd": "/work/overlap-sandbox",
        "git_branch": "feature/session-ids",
        "message_id": "msg_01AbCdEfGhIjKlMn",
        "parent_id": "3f2b8c1e-9d4a-4e7b-8a6c-1b2d3e4f5a6b",
        "ts_ms": 1_766_000_000_123_u64,
        "role": "assistant",
        "kind": "message",
        "model": "model-large-4",
        "token_json": "{\"input\":1200,\"output\":340}",
        "provider": "anthropic",
        "event_uid": "evt-5d1c2b3a",
        "raw_kind": "assistant_message",
        "session_id": session_id,
        "project_key": project_key,
        "text": text,
    })
}

const SESSION_IDS: [&str; 4] = [
    "ses_ab1c23704dff3XyzqBtgHVwp41",
    "cse_018b6TwnrgeCh5Z7akcqnCvx",
    "3f2b8c1e-9d4a-4e7b-8a6c-1b2d3e4f5a6b",
    "toolu_01AbCdEfGhIjKlMnOpQrStUv",
];
const PROJECT_KEYS: [&str; 2] = [
    "example/overlap-sandbox",
    "github.com/example/overlap-sandbox",
];

#[test]
fn session_events_keep_their_metadata() {
    for session_id in SESSION_IDS {
        for project_key in PROJECT_KEYS {
            let input = event(
                session_id,
                project_key,
                "I moved the retry loop into its own function; it's ready for review.",
            );
            for (api, output) in structured(&input) {
                assert_eq!(output, input, "{api}: {session_id} {project_key}");
            }
        }
    }
}

#[test]
fn a_credential_in_session_event_text_still_redacts() {
    for session_id in SESSION_IDS {
        for project_key in PROJECT_KEYS {
            for (text, expected) in [
                (
                    format!("Set it with password: \"{CREDENTIAL}\" and restart."),
                    "Set it with password: \"[REDACTED]\" and restart.".to_owned(),
                ),
                (
                    format!("export API_KEY={CREDENTIAL}"),
                    "export API_KEY=[REDACTED]".to_owned(),
                ),
            ] {
                let input = event(session_id, project_key, &text);
                let mut want = input.clone();
                want["text"] = json!(expected);
                for (api, output) in structured(&input) {
                    assert_eq!(output, want, "{api}: {text}");
                    assert!(!output.to_string().contains(CREDENTIAL));
                }
            }
        }
    }
}

#[test]
fn invalid_ids_in_session_events_redact_only_their_own_value() {
    let input = event(
        "ses_ab1c/23704dff",
        "owner/a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "Plain text.",
    );
    let mut want = input.clone();
    want["session_id"] = json!(REDACTION_TOKEN);
    want["project_key"] = json!(REDACTION_TOKEN);
    for (api, output) in structured(&input) {
        assert_eq!(output, want, "{api}");
    }
}
