#![allow(missing_docs)]
#[path = "../eval/review_cases.rs"]
mod cases;
use relayscrubber::*;
use serde_json::json;
fn check(index: usize) {
    let (_, input, expected) = &cases::findings()[index];
    assert_eq!(&scrub_text(input), expected, "text");
    assert_eq!(&scrub_long(input), expected, "compatibility");
    assert_eq!(scrub_text(expected), *expected, "second pass");
    let value = json!({"text":input});
    let clean = scrub_json(&value).0;
    assert_eq!(clean["text"], *expected, "JSON");
    assert_eq!(scrub_json(&clean).0, clean, "JSON second pass");
    let raw = serde_json::to_vec(&value).unwrap();
    let records = scrub_records(&raw).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&records.bytes).unwrap();
    assert_eq!(parsed["text"], *expected, "records");
    assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
}
#[test]
fn direct_intervening_quote() {
    check(0);
}
#[test]
fn public_property_intervening_quote() {
    check(1);
}
#[test]
fn generic_key() {
    check(2);
}
#[test]
fn prefixed_credential_key() {
    check(3);
}
#[test]
fn prefixed_public_like_name() {
    check(4);
}
#[test]
fn unicode_space() {
    check(5);
}
#[test]
fn comparison_precision() {
    check(6);
}
#[test]
fn credential_name_and_unicode_variants() {
    for name in ["githubToken", "stripeSecret", "encryption_key", "aws={key"] {
        let input = format!("{name}=SYNTH_ALPHA");
        assert!(!scrub_text(&input).contains("SYNTH_ALPHA"));
    }
    assert_eq!(scrub_text("aws={key:SYNTH_ALPHA}"), "aws={key:[REDACTED]}");
    for space in ['\u{a0}', '\u{feff}', '\u{2003}'] {
        assert_eq!(
            scrub_text(&format!("password{space}=SYNTH_ALPHA")),
            format!("password{space}=[REDACTED]")
        );
    }
}
#[test]
fn benign_code_and_identifiers() {
    for input in cases::benign() {
        assert_eq!(scrub_text(&input), input);
    }
}

#[test]
fn benign_expression_reference_and_type_shapes() {
    for input in [
        "const token = process.env.SYNTH_TOKEN;",
        "const token = config.credential;",
        "const token = createCredential();",
        "const token = false;",
        "struct Context { token: Mutex<Option<String>>, secret: bool }",
        "fn run(token: &str) {}",
        "const options = { token: env.SYNTH_TOKEN! };",
        "let token = undefined;",
        "TOKEN=$SYNTH_TOKEN command --api-key $SYNTH_KEY",
        "TOKEN=\"${SYNTH_TOKEN}\"",
    ] {
        assert_eq!(scrub_text(input), input);
    }
}

#[test]
fn embedded_code_and_shell_shapes_are_idempotent() {
    for input in [
        "let cases = [\"password: false\", \"secret = undefined\", \"token: config.credential\", \"const token = new Credential()\"];",
        "env | rg '^TOKEN='; TOKEN=$SYNTH_TOKEN command --api-key $SYNTH_KEY; echo ordinary",
        "password=\"SYNTH_ALPHA\" >/dev/null && echo ordinary",
        "fn run(token: &str) {}\nstruct Context { token: Mutex<Option<String>> }",
        "const cases = [\"password=foo\", `password=${\"password=bar\".repeat(4)}(`];",
    ] {
        let once = scrub_text(input);
        assert_eq!(scrub_text(&once), once);
    }
}

#[test]
fn quote_repair_and_marker_yaml_are_stable() {
    for input in ["'''token='\"'token=SYNTH\"", "'\ntoken:,\nSYNTH"] {
        let report = scrub_report(input, Policy::Secrets);
        assert_eq!(scrub_text(&report.text), report.text);
        let mut reconstructed = String::new();
        let mut at = 0;
        for span in report.redactions {
            reconstructed.push_str(&input[at..span.start]);
            reconstructed.push_str(REDACTION_TOKEN);
            at = span.end;
        }
        reconstructed.push_str(&input[at..]);
        assert_eq!(reconstructed, report.text);
    }
}
#[test]
fn expression_exceptions_do_not_exempt_literal_credential_tails() {
    for input in [
        "password=env.SYNTH_ALPHA",
        "password=\"${TOKEN:-SYNTH_ALPHA}\"",
        "key=std::SYNTH_ALPHA",
        "password=config.SYNTH_ALPHA",
    ] {
        assert!(!scrub_text(input).contains("SYNTH_ALPHA"));
    }
}

#[test]
fn private_audit_type_call_and_placeholder_shapes_stay_unchanged() {
    for input in [
        "fn cancel(token: CancellationToken) {}",
        "struct State { token: Arc<CancellationToken> }",
        "fn cancel(token: &CancellationToken) {}",
        "fn cancel(mut token: CancellationToken) {}",
        "const options = { \"token\": cancellation.clone() };",
        "const options = { token: cancellation.clone() };",
        "const options = { token: Some(cancellation) };",
        "password=<token>",
        "password=xxx",
        "token=\"<api-key>\"",
    ] {
        assert_eq!(scrub_text(input), input);
        let value = json!({"text":input});
        assert_eq!(scrub_json(&value).0, value);
    }
    for placeholder in ["<token>", "xxx", "<api-key>"] {
        let value = json!({"password":placeholder});
        assert_eq!(scrub_json(&value).0, value);
    }
}

#[test]
fn symbolic_placeholder_and_type_exceptions_do_not_hide_credentials() {
    for input in [
        "password=\"<password=SYNTH_ALPHA>\"",
        "idempotency_key=\"password=<token> SYNTH_ALPHA\"",
        "aws={key:SYNTH_ALPHA}",
        "const options = { token: generate(password=SYNTH_ALPHA) };",
        "password=\"<sk-proj-SYNTHETICnotARealProviderCredential00000000>\"",
    ] {
        let output = scrub_text(input);
        assert!(
            !output.contains("SYNTH_ALPHA")
                && !output.contains("SYNTHETICnotARealProviderCredential")
        );
        assert_eq!(scrub_text(&output), output);
    }
}

#[test]
fn sensitive_parameter_names_preserve_primitive_type_annotations() {
    for input in [
        "fn run(mut token: usize) {}",
        "fn run(mut token: bool) {}",
        "fn run(mut token: u64) {}",
        "fn run(mut token: credential_type) {}",
    ] {
        assert_eq!(scrub_text(input), input);
    }
}
