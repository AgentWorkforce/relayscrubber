#![allow(missing_docs)]

use relayscrubber::{CORPUS_SHA256, REDACTION_TOKEN, scrub_json, scrub_text};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write;

const CORPUS_TEXT: &str = include_str!("../vendor/corpus/scrub-secret-corpus.json");

#[derive(Deserialize)]
struct Corpus {
    generators: HashMap<String, Generator>,
    secrets: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Generator {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    suffix: String,
    parts: Vec<(String, PartLength)>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PartLength {
    Number(usize),
    Text(String),
}

#[derive(Deserialize)]
struct Case {
    id: String,
    input: String,
    expected: String,
}

fn sha256(text: &str) -> String {
    format!(
        "{:x}",
        Sha256::digest(text.replace("\r\n", "\n").as_bytes())
    )
}

fn charset(kind: &str) -> &'static [u8] {
    match kind {
        "alnum" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "upper_alnum" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "letters" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "digits" => b"0123456789",
        "hex" => b"0123456789abcdef",
        "urlsafe" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
        "b64" => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        unknown => panic!("unknown charset {unknown}"),
    }
}

fn generate(generator: &Generator, seed: usize) -> String {
    let mut output = generator.prefix.clone();
    for (part_index, (kind, length)) in generator.parts.iter().enumerate() {
        match (kind.as_str(), length) {
            ("lit", PartLength::Text(text)) => output.push_str(text),
            ("uuid", PartLength::Number(_)) => {
                write!(
                    output,
                    "{seed:08x}-{:04x}-4{:03x}-a{:03x}-{seed:012x}",
                    seed & 0xffff,
                    seed & 0xfff,
                    (seed * 3) & 0xfff,
                )
                .expect("write UUID");
            }
            (kind, PartLength::Number(length)) => {
                let alphabet = charset(kind);
                for index in 0..*length {
                    let selected = (index * 17 + seed * 31 + part_index * 7) % alphabet.len();
                    output.push(char::from(alphabet[selected]));
                }
            }
            _ => panic!("invalid generator part"),
        }
    }
    output.push_str(&generator.suffix);
    output
}

fn instantiate(corpus: &Corpus, case: &Case, round: usize) -> (String, String, Vec<String>) {
    let mut values = HashMap::<String, String>::new();
    let mut fill = |template: &str| {
        let placeholder = regex::Regex::new(r"\{\{([a-z0-9_]+)\}\}").expect("placeholder regex");
        placeholder
            .replace_all(template, |caps: &regex::Captures<'_>| {
                let name = &caps[1];
                values
                    .entry(name.to_owned())
                    .or_insert_with(|| {
                        generate(
                            corpus.generators.get(name).expect("known generator"),
                            round + case.id.len(),
                        )
                    })
                    .clone()
            })
            .into_owned()
    };
    let input = fill(&case.input);
    let expected = fill(&case.expected);
    let secrets = values
        .into_iter()
        .filter_map(|(name, value)| corpus.secrets.contains(&name).then_some(value))
        .collect();
    (input, expected, secrets)
}

#[test]
fn canonical_corpus_is_pinned() {
    assert_eq!(sha256(CORPUS_TEXT), CORPUS_SHA256);
}

#[test]
fn every_canonical_case_is_byte_identical_and_idempotent() {
    let corpus: Corpus = serde_json::from_str(CORPUS_TEXT).expect("valid canonical corpus");
    assert_eq!(corpus.cases.len(), 144);
    for case in &corpus.cases {
        for round in 0..5 {
            let (input, expected, secrets) = instantiate(&corpus, case, round);
            let once = scrub_text(&input);
            assert_eq!(once.as_ref(), expected, "{} round {round}", case.id);
            assert_eq!(
                scrub_text(once.as_ref()).as_ref(),
                once.as_ref(),
                "{}",
                case.id
            );
            for secret in secrets {
                for line in secret.lines() {
                    for start in (0..line.len().saturating_sub(11)).step_by(4) {
                        let fragment = &line[start..start + 12];
                        assert!(
                            !once.contains(fragment),
                            "{} leaked a secret fragment",
                            case.id
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn scrub_json_matches_the_record_path() {
    let corpus: Corpus = serde_json::from_str(CORPUS_TEXT).expect("valid canonical corpus");
    let token = generate(&corpus.generators["cf_user_token"], 29);
    let record = serde_json::json!({
        "type": "user",
        "message": {"content": [{
            "type": "tool_result",
            "content": serde_json::json!({"username": "ops", "password": token}).to_string()
        }]}
    });
    let output = scrub_json(&record).to_string();
    assert!(!output.contains(&token));
    assert!(output.contains(&format!(r#"\"password\":\"{REDACTION_TOKEN}\""#)));
}
