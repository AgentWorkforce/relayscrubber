#![allow(missing_docs)]
//! 0.5.0-alpha.11 inline object-type members. alpha.10 redacted the type of a
//! credential-named member of an inline TypeScript object type
//! (`context: { poolKey: string; targetSize: number }` became
//! `context: { poolKey: [REDACTED]; targetSize: number }`), while the same
//! member in an `interface` or `type X = {` body was kept.
//!
//! - An unquoted `name: {` or `name?: {` opener with only complete members
//!   (ended by `;`, `,` or a line break) between it and the key is source
//!   context for a type value, as an interface body is.
//! - Only a closed TypeScript type vocabulary counts as a type there:
//!   `string`, `number`, `boolean`, `bigint`, `null`, `undefined`, each with
//!   optional `[]`, the generics `Array`, `ReadonlyArray`, `Promise`, `Set`,
//!   `Map` and `Record` over those, and `|` unions of them. The type must be
//!   followed by `;`, `,`, `}` or a line break, and a `}` must close the body.
//! - Everything else in that position is still a value: quoted literals,
//!   opaque or symbol-heavy words, references (`poolKeyFromEnv`,
//!   `config.poolKey`), `String`, and any type followed by more bytes.
//! - Context-free forms are unchanged: `poolKey: string`, `{ poolKey: string }`
//!   and `pw: string` still redact.
//!
//! Each case runs through the checked, text, long, JSON and NDJSON record
//! paths and must be idempotent.

use relayscrubber::{scrub_json, scrub_long, scrub_records, scrub_text, scrub_text_checked};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Case {
    id: String,
    family: String,
    kind: String,
    input: String,
    expected: String,
}

fn check(id: &str, input: &str, expected: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let value = json!({ "text": input });
    let record = value.to_string();
    let ndjson = format!("{record}\n{record}\n");
    let records = scrub_records(ndjson.as_bytes()).expect("valid records");
    let lines: Vec<String> = String::from_utf8(records.bytes.clone())
        .expect("UTF-8 records")
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["text"]
                .as_str()
                .expect("record text")
                .to_owned()
        })
        .collect();
    assert_eq!(lines.len(), 2, "{id}: record count");
    let mut outputs = vec![
        ("checked", scrub_text_checked(input).expect("admitted text")),
        ("text", scrub_text(input)),
        ("long", scrub_long(input)),
        (
            "json",
            scrub_json(&value).0["text"]
                .as_str()
                .expect("JSON text")
                .to_owned(),
        ),
    ];
    outputs.extend(lines.into_iter().map(|line| ("ndjson", line)));
    for (api, output) in outputs {
        if output != expected {
            failures.push(format!(
                "{id}/{api}: {input:?} -> {output:?}, want {expected:?}"
            ));
        } else if scrub_text(&output) != output {
            failures.push(format!("{id}/{api}: second pass changed {output:?}"));
        }
    }
    if scrub_records(&records.bytes).expect("second pass").bytes != records.bytes {
        failures.push(format!("{id}/ndjson: second pass changed"));
    }
    failures
}

fn report(name: &str, cases: usize, failures: &[String]) {
    let failed: std::collections::BTreeSet<&str> = failures
        .iter()
        .map(|f| {
            ["checked", "text", "long", "json", "ndjson"]
                .iter()
                .filter_map(|api| f.find(&format!("/{api}:")))
                .min()
                .map_or(f.as_str(), |end| &f[..end])
        })
        .collect();
    eprintln!(
        "{name}: {cases} cases, {} failing cases, {} failing case/API pairs",
        failed.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{}",
        failures[..failures.len().min(60)].join("\n")
    );
}

fn run(name: &str, cases: &[(&str, &str)]) {
    let failures: Vec<String> = cases
        .iter()
        .flat_map(|(input, expected)| check(input, input, expected))
        .collect();
    report(name, cases.len(), &failures);
}

#[test]
fn eval_fixture_cases() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../eval/type_member_alpha11_cases.json")).unwrap();
    assert!(cases.len() >= 70);
    let mut failures = Vec::new();
    for c in &cases {
        assert_eq!(c.family, "type-member", "{}", c.id);
        assert!(c.kind == "positive" || c.kind == "benign", "{}", c.id);
        assert_eq!(c.kind == "benign", c.input == c.expected, "{}", c.id);
        failures.extend(check(&c.id, &c.input, &c.expected));
    }
    report("eval fixture", cases.len(), &failures);
}

/// The two reproducers and the type vocabulary for every member key and
/// separator, on one line and across lines.
#[test]
fn inline_member_types_are_kept() {
    let keys = [
        "apiKey",
        "secretKey",
        "publicKey",
        "primaryKey",
        "sortKey",
        "cacheKey",
        "poolKey",
        "token",
        "password",
    ];
    let types = [
        "string",
        "number",
        "boolean",
        "bigint",
        "string | null",
        "string | undefined",
        "null | string",
        "string[]",
        "string[] | null",
        "Array<string>",
        "ReadonlyArray<string>",
        "Promise<string>",
        "Set<string>",
        "Map<string, number>",
        "Record<string, string>",
        "Array<string> | undefined",
    ];
    let mut inputs = Vec::new();
    for key in keys {
        for ty in types {
            for optional in ["", "?"] {
                inputs.push(format!(
                    "context: {{ {key}{optional}: {ty}; size: number }}"
                ));
                inputs.push(format!(
                    "context: {{ size: number, {key}{optional}: {ty} }}"
                ));
                inputs.push(format!(
                    "options?: {{\n  retries: number;\n  {key}{optional}: {ty}\n}}"
                ));
            }
        }
    }
    let cases: Vec<(&str, &str)> = inputs.iter().map(|s| (s.as_str(), s.as_str())).collect();
    run("inline member types", &cases);
}

/// A value in the same position that is not a complete type from the closed
/// vocabulary stays a value.
#[test]
fn inline_member_values_still_redact() {
    const V: &str = "SYNTH_ALPHA_q8Zr4TfX2wLm";
    let cases = [
        (
            format!("context: {{ poolKey: \"{V}\" }}"),
            "context: { poolKey: \"[REDACTED]\" }",
        ),
        (
            format!("context: {{ poolKey: '{V}'; size: number }}"),
            "context: { poolKey: '[REDACTED]'; size: number }",
        ),
        (
            format!("context: {{ poolKey: {V} }}"),
            "context: { poolKey: [REDACTED] }",
        ),
        (
            format!("context: {{ apiKey: {V}; size: number }}"),
            "context: { apiKey: [REDACTED]; size: number }",
        ),
        (
            format!("context: {{ poolKey: string {V} }}"),
            "context: { poolKey: [REDACTED] }",
        ),
        (
            format!("context: {{ poolKey: string | {V} }}"),
            "context: { poolKey: [REDACTED] }",
        ),
        (
            format!("context: {{ poolKey: Array<{V}> }}"),
            "context: { poolKey: [REDACTED] }",
        ),
        (
            "context: { poolKey: String }".to_owned(),
            "context: { poolKey: [REDACTED] }",
        ),
        (
            "context: { poolKey: stringy }".to_owned(),
            "context: { poolKey: [REDACTED] }",
        ),
        (
            "context: { poolKey: string1 }".to_owned(),
            "context: { poolKey: [REDACTED] }",
        ),
        (
            "context: { poolKey: abc$def!ghi }".to_owned(),
            "context: { poolKey: [REDACTED] }",
        ),
        (
            "context: { poolKey: string".to_owned(),
            "context: { poolKey: [REDACTED]",
        ),
        (
            format!("const context = {{ poolKey: \"{V}\" }};"),
            "const context = { poolKey: \"[REDACTED]\" };",
        ),
        (format!("poolKey: {V}"), "poolKey: [REDACTED]"),
    ];
    let cases: Vec<(&str, &str)> = cases.iter().map(|(i, e)| (i.as_str(), *e)).collect();
    run("inline member values", &cases);
}

/// Context-free forms and the earlier type-annotation rulings are unchanged.
#[test]
fn context_free_forms_and_rulings_are_unchanged() {
    run(
        "rulings",
        &[
            ("poolKey: string", "poolKey: [REDACTED]"),
            ("{ poolKey: string }", "{ poolKey: [REDACTED] }"),
            ("{ pw: string }", "{ pw: [REDACTED] }"),
            ("pw: string", "pw: [REDACTED]"),
            ("pw: Vec<u8>", "pw: [REDACTED]"),
            ("password: Option<String>,", "password: [REDACTED]"),
            ("pw: abcq<defq>", "pw: [REDACTED]"),
            ("{password: String}", "{password: [REDACTED]}"),
            ("{token: String}", "{token: [REDACTED]}"),
            ("struct X { pw: Vec<u8> }", "struct X { pw: Vec<u8> }"),
            ("fn f(pw: String)", "fn f(pw: String)"),
            ("const pw: string", "const pw: string"),
            (
                "interface Config { apiKey: string; token: boolean }",
                "interface Config { apiKey: string; token: boolean }",
            ),
            (
                "type Config = { password?: string; token: credential_type }",
                "type Config = { password?: string; token: credential_type }",
            ),
            (
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_secret_access_key = [REDACTED]",
            ),
            // A quoted key is JSON or YAML data, not a TypeScript member.
            (
                "context: { \"poolKey\": \"string\" }",
                "context: { \"poolKey\": \"[REDACTED]\" }",
            ),
        ],
    );
}

/// Bare references keep the established policy: kept in an object literal
/// assigned to a name, redacted after a bare `name: {` opener.
#[test]
fn source_references_keep_their_policy() {
    run(
        "source references",
        &[
            (
                "const context = { poolKey: value, targetSize: 1 };",
                "const context = { poolKey: value, targetSize: 1 };",
            ),
            (
                "const context = { poolKey: process.env.POOL_KEY };",
                "const context = { poolKey: process.env.POOL_KEY };",
            ),
            (
                "context: { poolKey: poolKeyFromEnv }",
                "context: { poolKey: [REDACTED] }",
            ),
            (
                "context: { poolKey: config.poolKey; targetSize: number }",
                "context: { poolKey: [REDACTED]; targetSize: number }",
            ),
        ],
    );
}
