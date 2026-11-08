//! Lockstep with the Cloud: the vendored manifest and corpus, every corpus
//! case, the segmenter, and each deliberate divergence.

use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Vendored byte for byte from pipeline merge bfab2d4b (#356; head bb0bb0f8).
const CORPUS: &str = include_str!("../../vendor/corpus/scrub-secret-corpus.json");
const MANIFEST: &str = include_str!("../../vendor/canonical/technical-foul.json");
/// The corpus digest the Cloud's corpus test pins (`CORPUS_SHA256`).
const CORPUS_SHA256: &str = "d4589b4d008ef9bc1fdfc385f4aa209aef8044c9e3cd5abc14114544faa6ca49";

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn manifest() -> Value {
    serde_json::from_str(MANIFEST).unwrap()
}

fn corpus() -> Value {
    serde_json::from_str(CORPUS).unwrap()
}

#[test]
fn the_vendored_rule_set_is_the_one_the_cloud_pins() {
    let manifest = manifest();
    assert!(!CORPUS.contains('\r') && !MANIFEST.contains('\r'));
    assert_eq!(sha256_hex(CORPUS.as_bytes()), CORPUS_SHA256);
    assert_eq!(manifest["corpusSha256"], CORPUS_SHA256);
    assert_eq!(
        manifest["rulesetSourceSha256"],
        PINNED_RULESET_SOURCE_SHA256
    );
    assert_eq!(manifest["rulesetVersion"], RULESET_VERSION);
    assert_eq!(manifest["redactionToken"], REDACTION_TOKEN);
    assert_eq!(manifest["maxScrubChars"], MAX_SCRUB_CHARS);
    assert_eq!(manifest["schema"], 1);
}

/// splitmix64: a seeded source, so every run meets the same values and a
/// failure reproduces.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn from(&mut self, charset: &str, n: usize) -> String {
        let chars: Vec<char> = charset.chars().collect();
        (0..n)
            .map(|_| chars[(self.next() % chars.len() as u64) as usize])
            .collect()
    }

    fn uuid(&mut self) -> String {
        let hex = self.from("0123456789abcdef", 32);
        let variant = self.from("89ab", 1);
        format!(
            "{}-{}-4{}-{}{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[13..16],
            variant,
            &hex[17..20],
            &hex[20..32]
        )
    }
}

fn charset(kind: &str) -> &'static str {
    match kind {
        "alnum" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "upper_alnum" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "letters" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "digits" => "0123456789",
        "hex" => "0123456789abcdef",
        "urlsafe" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
        "b64" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        other => panic!("unknown charset {other}"),
    }
}

/// One value from a corpus generator, as the Cloud's test builds it.
fn generate(generator: &Value, random: &mut Random) -> String {
    let mut body = String::new();
    for part in generator["parts"].as_array().unwrap() {
        let kind = part[0].as_str().unwrap();
        match kind {
            "lit" => match &part[1] {
                Value::String(s) => body.push_str(s),
                other => body.push_str(&other.to_string()),
            },
            "uuid" => body.push_str(&random.uuid()),
            _ => body.push_str(&random.from(charset(kind), part[1].as_u64().unwrap() as usize)),
        }
    }
    format!(
        "{}{body}{}",
        generator["prefix"].as_str().unwrap_or(""),
        generator["suffix"].as_str().unwrap_or("")
    )
}

/// `input` and `expected` with every `{{name}}` filled (one value per name),
/// and the values of the names the corpus lists as secrets.
fn instantiate(corpus: &Value, case: &Value, random: &mut Random) -> (String, String, Vec<String>) {
    let mut values: Vec<(String, String)> = Vec::new();
    let mut fill = |s: &str| {
        let mut out = String::new();
        let mut rest = s;
        while let Some(open) = rest.find("{{") {
            let Some(close) = rest[open..].find("}}") else {
                break;
            };
            let name = &rest[open + 2..open + close];
            let valid = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if !valid {
                out.push_str(&rest[..open + 2]);
                rest = &rest[open + 2..];
                continue;
            }
            out.push_str(&rest[..open]);
            let value = match values.iter().find(|(n, _)| n == name) {
                Some((_, v)) => v.clone(),
                None => {
                    let generator = &corpus["generators"][name];
                    assert!(
                        generator.is_object(),
                        "{}: unknown placeholder {name}",
                        case["id"]
                    );
                    let v = generate(generator, random);
                    values.push((name.to_owned(), v.clone()));
                    v
                }
            };
            out.push_str(&value);
            rest = &rest[open + close + 2..];
        }
        out.push_str(rest);
        out
    };
    let input = fill(case["input"].as_str().unwrap());
    let expected = fill(case["expected"].as_str().unwrap());
    let secrets = corpus["secrets"].as_array().unwrap();
    let secret_values = values
        .into_iter()
        .filter(|(name, _)| secrets.iter().any(|s| s == name))
        .map(|(_, v)| v)
        .collect();
    (input, expected, secret_values)
}

/// Every 12-character window (step 4) of each line of a secret.
fn fragments(secret: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in secret.split('\n') {
        let units: Vec<u16> = line.encode_utf16().collect();
        let mut i = 0;
        while units.len() >= 12 && i + 12 <= units.len() {
            out.push(String::from_utf16_lossy(&units[i..i + 12]));
            i += 4;
        }
    }
    out
}

#[test]
fn every_corpus_case_scrubs_to_its_expected_output_and_is_idempotent() {
    let corpus = corpus();
    let cases = corpus["cases"].as_array().unwrap();
    assert!(cases.len() > 100);
    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        for round in 0..5u64 {
            let mut random = Random(index as u64 * 31 + round);
            let (input, expected, secrets) = instantiate(&corpus, case, &mut random);
            let once = scrub_text(&input);
            if once != expected {
                failures.push(format!("{id} round {round}\n  input:    {input:?}\n  expected: {expected:?}\n  got:      {once:?}"));
                break;
            }
            for secret in &secrets {
                for fragment in fragments(secret) {
                    assert!(!once.contains(&fragment), "{id} leaked {fragment:?}");
                }
            }
            assert_eq!(scrub_text(&once), once, "{id} is not idempotent");
            assert_eq!(scrub_long(&input), once, "{id} scrub_long differs");
        }
    }
    assert!(
        failures.is_empty(),
        "{} cases differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn the_escaped_json_tool_result_is_scrubbed_through_scrub_json() {
    let corpus = corpus();
    let token = generate(&corpus["generators"]["cf_user_token"], &mut Random(7));
    let inner = json!({ "username": "ops", "password": token }).to_string();
    let record = json!({
        "type": "user",
        "message": { "content": [{ "type": "tool_result", "content": inner }] }
    });
    let line = record.to_string();
    assert!(line.contains(r#"\"password\":\""#));
    let (clean, redactions) = scrub_json(&record);
    let scrubbed = clean.to_string();
    assert!(!scrubbed.contains(&token));
    assert!(scrubbed.contains(r#"\"password\":\"[REDACTED]\""#));
    assert_eq!(redactions, 1);
    assert!(!scrub_text(&line).contains(&token));
    assert_eq!(scrub_json(&clean), (clean.clone(), 0));
}

#[test]
fn scrub_json_redacts_keys_card_numbers_and_suffixes_collisions() {
    let corpus = corpus();
    let pw = generate(&corpus["generators"]["pw"], &mut Random(11));
    let a = format!("user@example.com {pw}");
    let value = json!({
        "card": 4111111111111111u64,
        "count": 4111111111111112u64,
        "float": 4111111111111111.0,
        "negative": -4111111111111111i64,
        "list": ["alice@example.com", 12, true, null],
        "x [REDACTED]": 1,
        "x bob@example.com": 2,
        a.clone(): 3,
    });
    let (clean, redactions) = scrub_json(&value);
    assert_eq!(clean["card"], REDACTION_TOKEN);
    assert_eq!(clean["count"], 4111111111111112u64);
    assert_eq!(clean["float"], REDACTION_TOKEN);
    assert_eq!(clean["negative"], -4111111111111111i64);
    assert_eq!(clean["list"], json!(["[REDACTED]", 12, true, null]));
    // `x [REDACTED]` comes first in `Object.entries` order and keeps its
    // name; the scrubbed `x bob@…` takes the suffix.
    assert_eq!(clean["x [REDACTED]"], 1);
    assert_eq!(clean["x [REDACTED] (2)"], 2);
    assert_eq!(clean[format!("[REDACTED] {pw}")], 3);
    // card, float, alice@…, the `x bob@…` key and the key holding an email.
    assert_eq!(redactions, 5);
}

#[test]
fn divergence_unsigned_card_numbers_past_2_53_are_checked_exactly() {
    // JavaScript holds no exact integer this large, so the Cloud never
    // checks it; serde_json keeps the digits, so the desktop redacts it.
    let card = 6_200_000_000_000_000_000u64;
    assert!(card > (1 << 53));
    assert!(numbers::is_card_digits(card.to_string().as_bytes()));
    assert_eq!(scrub_json(&json!(card)).0, REDACTION_TOKEN);
    // A float past 2^53 is not checked, as in JavaScript.
    assert_eq!(scrub_json(&json!(6.2e18)).0, json!(6.2e18));
}

#[test]
fn divergence_proto_keys_are_kept_and_scrubbed() {
    // A `__proto__` key assigned on a JavaScript object sets its prototype
    // and is lost; the desktop keeps it as an ordinary key.
    let (clean, _) = scrub_json(&json!({ "__proto__": "mail bob@example.com" }));
    assert_eq!(clean, json!({ "__proto__": "mail [REDACTED]" }));
}

/// Keys of an object in the order the scrub walks them.
fn walk_order(text: &str) -> Vec<(String, Value)> {
    let json::Node::Object(entries) = json::parse_text(text).unwrap() else {
        panic!("not an object");
    };
    let mut count = 0;
    entries
        .iter()
        .map(|(k, v)| (k.clone(), json::scrub_node(v, &mut count)))
        .collect()
}

#[test]
fn key_collisions_are_suffixed_in_document_order() {
    // `JSON.parse` then `Object.entries` lists `b@x.io` first: it keeps the
    // bare name and `a@x.io` takes ` (2)`, whatever the sorted order.
    let text = r#"{"b@x.io": "b", "c": 1, "a@x.io": "a", "b+1@x.io": "b1"}"#;
    let (clean, redactions) = scrub_json_text(text).unwrap();
    assert_eq!(
        clean,
        json!({ "[REDACTED]": "b", "c": 1, "[REDACTED] (2)": "a", "[REDACTED] (3)": "b1" })
    );
    assert_eq!(redactions, 3);
    // A programmatic serde_json value uses its consumer-selected map order;
    // only the text entry point promises JSON.parse document order.
    let value: Value = serde_json::from_str(text).unwrap();
    let first_collision_value = value
        .as_object()
        .unwrap()
        .iter()
        .find(|(key, _)| key.contains("@x.io"))
        .map(|(_, value)| value)
        .unwrap();
    assert_eq!(scrub_json(&value).0["[REDACTED]"], *first_collision_value);
}

#[test]
fn finite_large_numbers_follow_default_serde_json_semantics() {
    let text = r#"{"huge":123456789012345678901234567890,"decimal":1.234567890123456789}"#;
    let (clean, redactions) = scrub_json_text(text).unwrap();
    assert_eq!(redactions, 0);
    assert!(clean["huge"].is_number() && clean["decimal"].is_number());
    assert_eq!(clean["huge"], json!(1.2345678901234568e29));
    assert_eq!(clean["decimal"], json!(1.2345678901234567));
}

#[test]
fn text_json_preserves_negative_zero() {
    let (clean, redactions) =
        scrub_json_text(r#"{"offset":-0,"decimal":-0.0,"exponent":-0e1}"#).unwrap();
    assert_eq!(redactions, 0);
    for key in ["offset", "decimal", "exponent"] {
        let number = clean[key].as_f64().unwrap();
        assert_eq!(number, 0.0);
        assert!(number.is_sign_negative(), "{key} lost its negative sign");
    }
}

#[test]
fn text_json_rejects_unpaired_surrogates_but_accepts_pairs() {
    // JSON.parse can produce a JavaScript string with an unpaired UTF-16
    // surrogate, but Rust String/serde_json::Value cannot represent it.
    assert!(scrub_json_text(r#"{"value":"\ud800"}"#).is_none());
    assert!(scrub_json_text(r#"{"value":"\udc00"}"#).is_none());
    let (clean, redactions) = scrub_json_text(r#"{"value":"\ud83d\udca3"}"#).unwrap();
    assert_eq!(redactions, 0);
    assert_eq!(clean["value"], "💣");
}

#[test]
fn text_json_matches_serde_json_container_depth_boundary() {
    let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
    assert!(serde_json::from_str::<Value>(&nested(127)).is_ok());
    assert!(scrub_json_text(&nested(127)).is_some());
    assert!(serde_json::from_str::<Value>(&nested(128)).is_err());
    assert!(scrub_json_text(&nested(128)).is_none());
}

#[test]
fn decimal_card_numbers_are_redacted_by_the_text_entry_point() {
    let (clean, redactions) = scrub_json_text(r#"{"card":4111111111111111.0}"#).unwrap();
    assert_eq!(clean["card"], REDACTION_TOKEN);
    assert_eq!(redactions, 1);
}

#[test]
fn out_of_range_numbers_fail_without_global_arbitrary_precision() {
    let text = format!(r#"{{"too_large":{}}}"#, "9".repeat(10_000));
    assert!(scrub_json_text(&text).is_none());
}

#[test]
fn serde_json_private_number_marker_remains_an_ordinary_object_key() {
    let marker = "$serde_json::private::Number";
    let text = format!(
        r#"{{"{marker}":"123","nested":{{"$serde_json::private::\u004eumber":"456"}},"{marker}\u0000":"kept"}}"#
    );
    let (clean, redactions) = scrub_json_text(&text).unwrap();
    assert_eq!(redactions, 0);
    assert_eq!(clean[marker], "123");
    assert_eq!(clean["nested"][marker], "456");
    assert_eq!(clean[format!("{marker}\0")], "kept");
    assert!(clean.is_object() && clean["nested"].is_object());
}

#[test]
fn assignment_one_password_references_remain_allowed() {
    let reference = format!("op://{}", "a".repeat(4_097));
    let text = format!(r#"CF_TOKEN_REF="{reference}" unrelated text"#);
    assert_eq!(scrub_long(&text), text);
}

#[test]
fn v5_redacts_an_over_cap_quoted_one_password_reference() {
    let long = format!("op://{}", "a".repeat(8_192));
    assert_eq!(
        scrub_long(&format!(r#""password": "{long}""#)),
        r#""password": "[REDACTED]""#
    );
    assert_eq!(
        scrub_long(r#""password": "op://vault/item/field""#),
        r#""password": "op://vault/item/field""#
    );
}

#[test]
fn v5_redacts_an_invalid_unquoted_one_password_reference() {
    let reference = format!("op://{}", "aB3dE5fG7hJ9".repeat(350));
    let head = "x".repeat(MAX_SCRUB_CHARS - 19);
    let text = format!(r#"{head} "token": {reference}"#);
    let out = scrub_long(&text);
    assert!(out.ends_with(r#" "token": [REDACTED]"#));
    assert!(!out.contains(&reference));
}

#[test]
fn v5_keeps_only_complete_three_or_four_segment_one_password_references() {
    for reference in [
        "op://vault/item/field",
        "op://Team Vault/Item Name/section/field",
    ] {
        let text = format!(r#""password":"{reference}""#);
        assert_eq!(scrub_text(&text), text);
        assert_eq!(
            scrub_json(&json!({ "password": reference })).0,
            json!({ "password": reference })
        );
    }
    for reference in [
        "op://vault/item",
        "op://vault/item/section/field/tail",
        "op://vault/item/field?x=1",
        "op://vault/item/double  space",
        r"op://vault/item/field\nSECRETTAIL",
        "op://vault/item/field/",
        "op://vault//field",
        "op://váult/item/field",
    ] {
        let text = format!(r#""password":"{reference}""#);
        assert_eq!(
            scrub_text(&text),
            r#""password":"[REDACTED]""#,
            "{reference:?}"
        );
        assert_eq!(
            scrub_json(&json!({ "password": reference })).0,
            json!({ "password": REDACTION_TOKEN }),
            "{reference:?}"
        );
    }
}

#[test]
fn v5_inherits_secret_context_through_composite_json_values() {
    let value = json!({
        "password": {
            "nested": [
                "ordinary words",
                { "leaf": "still ordinary words", "empty": "", "ref": "op://vault/item/field" },
                7,
                true,
                null
            ]
        },
        "safe": { "nested": "ordinary words" }
    });
    let (clean, redactions) = scrub_json(&value);
    assert_eq!(clean["password"]["nested"][0], REDACTION_TOKEN);
    assert_eq!(clean["password"]["nested"][1]["leaf"], REDACTION_TOKEN);
    assert_eq!(clean["password"]["nested"][1]["empty"], "");
    assert_eq!(
        clean["password"]["nested"][1]["ref"],
        "op://vault/item/field"
    );
    assert_eq!(clean["password"]["nested"][2], 7);
    assert_eq!(clean["safe"]["nested"], "ordinary words");
    assert_eq!(redactions, 2);
}

#[test]
fn v5_redacts_multiline_quoted_values_through_close_or_end() {
    for separator in ["\r", "\n", "\r\n", "\u{2028}", "\u{2029}", "\u{0085}"] {
        for quote in ['"', '\'', '`'] {
            let value = format!("short{separator}SECRETTAIL");
            let closed = format!("{quote}password{quote}: {quote}{value}{quote} after");
            assert_eq!(
                scrub_text(&closed),
                format!("{quote}password{quote}: {quote}{REDACTION_TOKEN}{quote} after")
            );
            let open = format!("{quote}password{quote}: {quote}{value}");
            assert_eq!(
                scrub_text(&open),
                format!("{quote}password{quote}: {quote}{REDACTION_TOKEN}")
            );
        }
    }
}

#[test]
fn v5_measures_over_cap_values_before_token_rules_shrink_them() {
    let capy = format!("capy_{}", "Ab1".repeat(12));
    let value = format!("{}\nSECRETTAILMARK", format!("{capy} ").repeat(130));
    assert!(value.encode_utf16().count() > 4096);
    assert!(value.replace(&capy, REDACTION_TOKEN).encode_utf16().count() < 4096);
    for text in [
        format!(r#""password": "{value}" after"#),
        format!(r#"'secret': '{value}' after"#),
        format!("`secret`: `{value}` after"),
        format!(r#"{{\"api_key\": \"{value}\"}}"#),
    ] {
        let out = scrub_text(&text);
        assert!(!out.contains("SECRETTAILMARK"), "{out:?}");
        assert_eq!(out.matches(REDACTION_TOKEN).count(), 1, "{out:?}");
    }
}

#[test]
fn v6_redacts_every_complete_over_cap_bare_value() {
    let prefix = format!("{}012345", "0123456789".repeat(409));
    let tail = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".repeat(100);
    assert_eq!(prefix.encode_utf16().count(), 4096);
    let input = format!(r#""token": {prefix}{tail} after"#);
    assert_eq!(scrub_text(&input), r#""token": [REDACTED] after"#);
    assert_eq!(scrub_long(&input), r#""token": [REDACTED] after"#);

    let number = format!(r#""token": {} after"#, "1".repeat(4196));
    assert_eq!(scrub_text(&number), r#""token": [REDACTED] after"#);
}

#[test]
fn v5_preserves_an_embedded_pem_footer_without_exposing_a_suffix() {
    let value = format!(
        "{}-----END PRIVATE KEY-----",
        "A".repeat(quoted::MAX_QUOTED_VALUE + 1)
    );
    let input = format!("-----BEGIN PRIVATE KEY-----\n\"password\": \"{value}\" KEEPTRAIL");
    let out = scrub_text(&input);
    assert!(out.contains("KEEPTRAIL"));
    assert!(!out.contains("BEGIN PRIVATE KEY"));
    assert!(!out.contains("END PRIVATE KEY"));
    assert_eq!(scrub_long(&input), out);

    let with_suffix =
        format!("-----BEGIN PRIVATE KEY-----\n\"password\": \"{value}SECRETTAIL\" KEEPTRAIL");
    let suffix_out = scrub_text(&with_suffix);
    assert!(!suffix_out.contains("SECRETTAIL"));
    assert!(suffix_out.contains("KEEPTRAIL"));
    assert_eq!(scrub_long(&with_suffix), suffix_out);

    let chained = format!(
        "-----BEGIN PRIVATE KEY-----\n\"password\": \"{value}\n-----BEGIN PRIVATE KEY-----\"\nSECRETBODY\n-----END PRIVATE KEY-----\nKEEPTRAIL"
    );
    let chained_out = scrub_text(&chained);
    assert!(!chained_out.contains("SECRETBODY"));
    assert!(!chained_out.contains("BEGIN PRIVATE KEY"));
    assert!(!chained_out.contains("END PRIVATE KEY"));
    assert!(chained_out.contains("KEEPTRAIL"));
    assert_eq!(scrub_long(&chained), chained_out);
}

#[test]
fn v6_private_key_prepass_consumes_later_unquoted_credential_tails() {
    let suffix = "Ab3dE5fG7hJ9K2mN4pQ6rS8tU0vW1xY3zA5cB7dE";
    for later in [
        format!("token=abc-----END PRIVATE KEY-----SECRETTAIL{suffix}"),
        format!("Authorization: Bearer abc-----END PRIVATE KEY-----SECRETTAIL{suffix}"),
        format!(
            "https://example.test/cb?access_token=abc-----END PRIVATE KEY-----SECRETTAIL{suffix}"
        ),
    ] {
        let input =
            format!(r#""password": "abc-----BEGIN PRIVATE KEY-----" KEEPMID {later} KEEPTRAIL"#);
        let expected = r#""password": "[REDACTED]" KEEPTRAIL"#;
        assert_eq!(scrub_text(&input), expected, "{later}");
        assert_eq!(scrub_long(&input), expected, "{later}");

        let record = json!({ "content": input });
        let (clean, redactions) = scrub_json(&record);
        assert_eq!(clean["content"], expected, "{later}");
        assert_eq!(redactions, 1, "{later}");
    }
}

#[test]
fn v5_segmenter_never_cuts_inside_a_multiline_quoted_value() {
    let head = filler(MAX_SCRUB_CHARS - 2_000);
    let value = format!("SECRETTAIL one\n{}\nSECRETTAIL two", "word ".repeat(1_000));
    let text = format!(r#"{head}"password":"{value}" after {}"#, filler(4_000));
    let out = scrub_long(&text);
    assert!(!out.contains("SECRETTAIL"));
    assert!(out.contains(r#""password":"[REDACTED]" after "#));
    assert!(out.len() > head.len());
    assert_eq!(scrub_long(&out), out);
}

#[test]
fn programmatic_json_beyond_the_parser_depth_limit_fails_closed() {
    let mut value = Value::Null;
    for _ in 0..129 {
        value = Value::Array(vec![value]);
    }
    assert_eq!(scrub_json(&value), (json!(REDACTION_TOKEN), 1));
}

#[test]
fn integer_like_keys_are_walked_first_in_ascending_order() {
    // `Object.entries`: array-index keys (canonical, below 2^32 - 1)
    // ascending, then every other key in document order; a repeated key
    // keeps its first place and its last value, as `JSON.parse` does.
    let text = r#"{"z@x.io": 0, "10": 1, "b": 2, "2": 3, "02": 4,
        "4294967295": 5, "4294967294": 6, "a@x.io": 7, "b": 8, "-1": 9}"#;
    let keys: Vec<(String, Value)> = walk_order(text);
    let names: Vec<&str> = keys.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "2",
            "10",
            "4294967294",
            "z@x.io",
            "b",
            "02",
            "4294967295",
            "a@x.io",
            "-1"
        ]
    );
    assert_eq!(keys[4].1, 8);
    // Integer keys ahead of colliding ones do not move the suffix, which
    // follows the document order of the rest.
    let (clean, _) = scrub_json_text(text).unwrap();
    assert_eq!(clean["[REDACTED]"], 0);
    assert_eq!(clean["[REDACTED] (2)"], 7);
    // The same for nested objects and inside arrays.
    let nested = format!(r#"[{{"o": {text}}}]"#);
    assert_eq!(scrub_json_text(&nested).unwrap().0[0]["o"], clean);
}

fn filler(len: usize) -> String {
    let unit = "lorem ipsum dolor sit amet ";
    unit.repeat(len / unit.len() + 1)[..len].to_owned()
}

#[test]
fn scrub_text_truncates_past_the_bound_after_whitespace_and_says_so() {
    let text = format!("{}tail", filler(MAX_SCRUB_CHARS));
    let out = scrub_text(&text);
    assert!(
        out.ends_with("-character scrub limit]"),
        "{}",
        &out[out.len() - 120..]
    );
    assert!(out.contains("\n[relayhistory: truncated "));
    assert!(!out.contains("tail"));
}

#[test]
fn the_segmenter_keeps_a_secret_near_the_cut_whole_and_redacts_it() {
    let corpus = corpus();
    let mut random = Random(23);
    let pw = generate(&corpus["generators"]["pw"], &mut random);
    let token = generate(&corpus["generators"]["tok40"], &mut random);
    let cf = generate(&corpus["generators"]["cf_user_token"], &mut random);
    for offset in [40usize, 25, 12, 4, 1] {
        for secret in [
            format!("password = {pw}"),
            format!("Authorization: Bearer {token}"),
            format!("\"api_key\": \"{pw}\""),
            format!("token\n\n {cf}"),
        ] {
            // A space ahead of the secret: glued to the filler's last word,
            // `\b` would not hold and the Cloud would not redact it either.
            let head = filler(MAX_SCRUB_CHARS - offset - 1);
            let text = format!("{head} {secret} and {} done", filler(5000));
            assert!(text.encode_utf16().count() > MAX_SCRUB_CHARS);
            let out = scrub_long(&text);
            for value in [&pw, &token, &cf] {
                for fragment in fragments(value) {
                    assert!(
                        !out.contains(&fragment),
                        "{secret:?} at -{offset} leaked {fragment:?}"
                    );
                }
            }
            assert!(out.contains(REDACTION_TOKEN), "{secret:?} at -{offset}");
            assert!(!out.contains("[relayhistory: truncated"));
            assert!(out.ends_with(" done"));
            assert_eq!(
                scrub_long(&out),
                out,
                "{secret:?} at -{offset} is not idempotent"
            );
        }
    }
}

#[test]
fn the_segmenter_never_cuts_inside_a_private_key_block() {
    let corpus = corpus();
    let body = generate(&corpus["generators"]["pem_body"], &mut Random(29));
    let block = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----");
    for offset in [10usize, 100, 2000] {
        let text = format!(
            "{}{block} after {}",
            filler(MAX_SCRUB_CHARS - offset),
            filler(3000)
        );
        let out = scrub_long(&text);
        for fragment in fragments(&body) {
            assert!(!out.contains(&fragment), "-{offset} leaked {fragment:?}");
        }
        assert!(out.contains(" after "));
        assert!(!out.contains("[relayhistory: truncated"));
    }
}

#[test]
fn divergence_a_remainder_with_no_safe_cut_is_redacted_not_refused() {
    // The Cloud refuses an unbroken run past the bound; the desktop sends
    // the redaction token in its place, never a part of it.
    let corpus = corpus();
    let pw = generate(&corpus["generators"]["pw"], &mut Random(31));
    let run = "A1b2C3".repeat(MAX_SCRUB_CHARS / 6 + 10);
    let text = format!("password={pw} {run}{pw}");
    let out = scrub_long(&text);
    assert_eq!(out, REDACTION_TOKEN);
    assert_eq!(scrub_long(&out), out);
    // Segments cut off safely are kept; only the remainder is redacted.
    let head = format!("{}user@example.com ", filler(MAX_SCRUB_CHARS - 1000));
    let out = scrub_long(&format!("{head}{run}"));
    assert_eq!(out, scrub_long(&format!("{head}{REDACTION_TOKEN}")));
    assert!(out.ends_with(" [REDACTED] [REDACTED]"));
    assert!(!out.contains("A1b2C3A1b2C3") && !out.contains("[relayhistory: truncated"));
    assert_eq!(scrub_long(&out), out);
}

#[test]
fn a_secret_straddling_every_candidate_cut_is_never_sent_in_part() {
    // Prefix-plus-length secrets glued into one unbroken run, one of them
    // across the bound and one across every point a search could try: no
    // cut exists, so nothing of the run is sent.
    let corpus = corpus();
    let mut random = Random(37);
    let secrets: Vec<String> = (0..8)
        .map(|_| generate(&corpus["generators"]["tok40"], &mut random))
        .map(|tok| format!("ghp_{}", &tok[..36]))
        .collect();
    // Text with whitespace only below where a cut is searched for, then
    // the run: secrets joined by dots from there to past the bound.
    let floor = MAX_SCRUB_CHARS - 65_536;
    let mut text = filler(floor - 100);
    while !(MAX_SCRUB_CHARS - 20 - text.len()).is_multiple_of(41) {
        text.push('.');
    }
    let mut i = 0;
    while text.len() < MAX_SCRUB_CHARS + 5_000 {
        text.push_str(&secrets[i % secrets.len()]);
        text.push('.');
        i += 1;
    }
    assert_eq!(&text[MAX_SCRUB_CHARS - 20..MAX_SCRUB_CHARS - 16], "ghp_");
    // Whole, every one of them would be redacted.
    assert!(!scrub_text(&text[floor..MAX_SCRUB_CHARS - 21]).contains("ghp_"));
    let out = scrub_long(&text);
    assert_eq!(out, REDACTION_TOKEN);
    for secret in &secrets {
        for fragment in fragments(secret) {
            assert!(!out.contains(&fragment), "leaked {fragment:?}");
        }
        assert!(!out.contains(&secret[..8]), "leaked a prefix");
    }
}

#[test]
fn text_at_the_bound_is_scrubbed_whole() {
    let text = format!("{} bob@example.com", filler(MAX_SCRUB_CHARS - 16));
    assert_eq!(text.len(), MAX_SCRUB_CHARS);
    let out = scrub_text(&text);
    assert!(out.ends_with(" [REDACTED]"));
    assert_eq!(scrub_long(&text), out);
}

#[test]
fn utf16_lengths_bound_the_scrub_as_in_javascript() {
    // An astral character is two UTF-16 units: the bound counts units, as
    // JavaScript's `length` does, not bytes or chars.
    let face = "\u{1F600} ";
    let text = face.repeat(MAX_SCRUB_CHARS / 3 + 1);
    assert!(text.chars().count() < MAX_SCRUB_CHARS);
    assert!(text.encode_utf16().count() > MAX_SCRUB_CHARS);
    assert!(scrub_text(&text).contains("[relayhistory: truncated "));
    assert_eq!(scrub_long(&text), text);
}

#[test]
fn adversarial_inputs_stay_linear() {
    let unit = "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"tool_use\",\"input\":{\"command\":\"git log 0123456789abcdef0123456789abcdef01234567\"}},{\"type\":\"text\",\"text\":\"ok \\\"key\\\": \\\"value\\\", \\\"name\\\": \\\"x\\\" token usage 123\"}]}}\n";
    let n = MAX_SCRUB_CHARS;
    let inputs = [
        unit.repeat(n / unit.len()),
        "\\".repeat(n),
        "\"".repeat(n),
        format!("\"token\": \"{}", "a".repeat(n - 20)),
        "\"password\":".repeat(n / 11),
        "\\\"token\\\": \\\"x".repeat(n / 14),
        "token-".repeat(n / 6),
        format!("{}token\": \"x\" ", "a".repeat(63)).repeat(n / 76),
        format!("'token': \"{}", "'token': 'x' ".repeat(n / 14)),
        format!("'token': \"{}", "'token':'x'".repeat(n / 11)),
        "-----BEGIN PRIVATE KEY-----".repeat(n / 27),
        "a@".repeat(n / 2),
        "+1 ".repeat(n / 3),
        "1 ".repeat(n / 2),
        "https://".repeat(n / 8),
    ];
    for input in &inputs {
        let start = std::time::Instant::now();
        let _ = scrub_text(input);
        let elapsed = start.elapsed();
        // Generous for an unoptimized test build on a loaded host; quadratic
        // behaviour on these inputs takes minutes.
        assert!(
            elapsed.as_secs() < 20,
            "{:?}… took {elapsed:?}",
            &input[..24]
        );
    }
    assert_eq!(scrub_text(&inputs[0]), inputs[0]);
}

#[test]
fn divergence_compact_json_past_the_bound_is_cut_after_a_safe_comma() {
    // No whitespace anywhere: the Cloud refuses this; the desktop cuts after
    // a comma where `cutIsSafe` holds and scrubs both sides whole.
    let mut leaves: Vec<String> = (0..2_000)
        .map(|i| format!("{i:08}{}", "s".repeat(200)))
        .collect();
    leaves[1_240] = "bob@example.com".to_owned();
    leaves[1_999] = "alice@example.com".to_owned();
    let text = serde_json::to_string(&leaves).unwrap();
    assert!(text.len() > MAX_SCRUB_CHARS && !text.contains(' '));
    let out = scrub_long(&text);
    assert!(!out.contains("[relayhistory: truncated"));
    let kept: Vec<String> = serde_json::from_str(&out).unwrap();
    assert_eq!(kept.len(), leaves.len());
    assert_eq!(kept[1_240], REDACTION_TOKEN);
    assert_eq!(kept[1_999], REDACTION_TOKEN);
    assert_eq!(kept[0], leaves[0]);
    assert_eq!(scrub_long(&out), out);
}

#[test]
fn a_comma_inside_a_secret_is_never_a_cut() {
    // Compact text past the bound whose secrets hold commas (URL credentials
    // with query commas, a quoted free-text value), each placed so a comma
    // inside it sits just below the bound: that comma is a candidate only,
    // the context check refuses it, and the secret is redacted whole.
    let corpus = corpus();
    let pw = generate(&corpus["generators"]["pw"], &mut Random(43));
    let secrets = [
        format!("https://deploy:{pw},a,b@db.example.com/x?a=1,b=2"),
        format!("{{\"api_key\":\"{pw},free,text,{pw}\"}}"),
    ];
    for secret in &secrets {
        let whole = scrub_text(secret);
        assert!(!whole.contains(&pw), "{secret:?} is not a secret whole");
        for comma in secret.match_indices(',').map(|(i, _)| i + 1) {
            for below in [1usize, 7, 30] {
                let start = MAX_SCRUB_CHARS - below - comma;
                let mut head = String::new();
                while head.len() + 203 < start {
                    head.push_str(&format!("\"{}\",", "s".repeat(200)));
                }
                head.push_str(&"s".repeat(start - 1 - head.len()));
                head.push(',');
                let tail = format!(",\"{}\"]", "t".repeat(4000));
                let text = format!("[{}{secret}{tail}", &head[1..]);
                assert_eq!(text.find(secret.as_str()), Some(start));
                let out = scrub_long(&text);
                assert!(
                    !out.contains(&pw),
                    "{secret:?} cut at {comma}-{below} leaked"
                );
                for fragment in fragments(&pw) {
                    assert!(
                        !out.contains(&fragment),
                        "{secret:?} cut at {comma}-{below} leaked {fragment:?}"
                    );
                }
                if secret.starts_with("https://") {
                    assert_eq!(out, REDACTION_TOKEN, "{secret:?} cut at {comma}-{below}");
                } else {
                    assert!(out.contains(&whole), "{secret:?} cut at {comma}-{below}");
                }
                assert!(!out.contains("[relayhistory: truncated"));
                assert_eq!(scrub_long(&out), out);
            }
        }
    }
}

#[test]
fn a_long_url_userinfo_password_is_never_split_at_a_distant_comma() {
    let mut password = "a".repeat(MAX_SCRUB_CHARS + 4096);
    password.replace_range(MAX_SCRUB_CHARS - 20..MAX_SCRUB_CHARS - 19, ",");
    let text = format!("https://deploy:{password}@db.example.test/path");
    assert!(text.encode_utf16().count() > MAX_SCRUB_CHARS);
    // The Desktop-only comma fallback cannot prove a cut safe once a URL
    // scheme is in the candidate prefix, so the upload path fails closed.
    assert_eq!(scrub_long(&text), REDACTION_TOKEN);
}

#[test]
fn an_over_cap_quoted_secret_is_redacted_through_its_close() {
    let value = "A1b2C3d4".repeat(600);
    assert!(value.encode_utf16().count() > 4096);
    let text = format!(r#"{{"password":"{value}","safe":"kept"}}"#);
    assert_eq!(
        scrub_long(&text),
        r#"{"password":"[REDACTED]","safe":"kept"}"#
    );

    let crossing = format!(
        r#"{} {{"password":"{value}"}}"#,
        filler(MAX_SCRUB_CHARS - 2000)
    );
    assert!(crossing.encode_utf16().count() > MAX_SCRUB_CHARS);
    let out = scrub_long(&crossing);
    assert!(!out.contains(&value));
    assert!(out.ends_with(r#" {"password":"[REDACTED]"}"#));
}

#[test]
fn v5_counts_total_quoted_value_length_across_every_separator() {
    for separator in ["\r", "\n", "\r\n", "\u{2028}", "\u{2029}", "\u{0085}"] {
        for quote in ['"', '\'', '`'] {
            let value = format!("short{separator}{}UNIQUE_TAIL", "v".repeat(4097));
            let text = format!("{quote}token{quote}: {quote}{value}{quote} after");
            assert_eq!(
                scrub_long(&text),
                format!("{quote}token{quote}: {quote}{REDACTION_TOKEN}{quote} after"),
                "separator={separator:?} quote={quote:?}"
            );

            let open = format!("{quote}token{quote}: {quote}{value}");
            assert_eq!(
                scrub_long(&open),
                format!("{quote}token{quote}: {quote}{REDACTION_TOKEN}"),
                "open separator={separator:?} quote={quote:?}"
            );
        }
    }
}

#[test]
fn v5_segmenter_never_cuts_inside_an_over_cap_quoted_value() {
    let value = format!("short\n{}UNIQUE_TAIL", "v".repeat(MAX_SCRUB_CHARS + 100));
    let text = format!("`token`: `{value}` after");
    assert_eq!(scrub_long(&text), REDACTION_TOKEN);
}
