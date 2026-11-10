#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

// Every credential here is synthetic and intentionally invalid. No production
// values are copied into fixtures. Sentinels distinguish partial-tail leaks.
fn assert_all_paths(input: &str) {
    for output in [
        scrub_text(input),
        scrub_long(input),
        scrub_json(&json!({"text":input})).0["text"]
            .as_str()
            .unwrap()
            .to_owned(),
    ] {
        assert!(
            !output.contains("SYNTH_ALPHA"),
            "first sentinel: {output:?}"
        );
        assert!(!output.contains("SYNTH_BETA"), "tail sentinel: {output:?}");
        assert_eq!(scrub_text(&output), output, "idempotence");
    }
    let line = serde_json::to_string(&json!({"text":input})).unwrap();
    let records = scrub_records(line.as_bytes()).unwrap();
    assert_eq!(records.record_count, 1);
    let out = String::from_utf8(records.bytes).unwrap();
    assert!(!out.contains("SYNTH_ALPHA") && !out.contains("SYNTH_BETA"));
}

#[test]
fn known_leak_families_across_all_entry_points() {
    assert_all_paths(r"password\u005c\u003d\u005c\u0022SYNTH_ALPHA SYNTH_BETA\u005c\u0022");
    assert_all_paths(r"password%5C%u003D%5C%u0022SYNTH_ALPHA SYNTH_BETA%5C%u0022");
    assert_all_paths(r"password\%3D\%22SYNTH_ALPHA SYNTH_BETA\%22");
    for sep in [
        "=", ":", "%3D", "%253d", "%25253D", "%u003d", "\\u003d", "\\x3d",
    ] {
        for quote in [
            "\"", "'", "`", "\\\"", "%22", "%2522", "%u0022", "\\u0022", "\\x22",
        ] {
            assert_all_paths(&format!(
                "password{sep}{quote}SYNTH_ALPHA SYNTH_BETA{quote}"
            ));
            assert_all_paths(&format!(
                "password{sep}{quote}SYNTH_ALPHA\nSYNTH_BETA{quote}"
            ));
            assert_all_paths(&format!("password{sep}{quote}SYNTH_ALPHA SYNTH_BETA"));
            assert_all_paths(&format!(
                "idempotency_key={quote}password{sep}SYNTH_ALPHA SYNTH_BETA{quote}"
            ));
        }
    }
    assert_all_paths("idempotency_key=password=SYNTH_ALPHA SYNTH_BETA");
    for depth in [5, 17, 64, 4096] {
        let slashes = "\\".repeat(depth);
        assert_all_paths(&format!(
            "password{slashes}u003d{slashes}u0022SYNTH_ALPHA SYNTH_BETA{slashes}u0022"
        ));
        let percent = format!("%{}", "25".repeat(depth));
        assert_all_paths(&format!(
            "password{percent}3d{percent}22SYNTH_ALPHA SYNTH_BETA{percent}22"
        ));
    }
    assert_all_paths(&format!(
        "password=\"SYNTH_ALPHA {} SYNTH_BETA\"",
        "x".repeat(270_000)
    ));
    assert_all_paths("password=\"[REDACTED]SYNTH_ALPHA SYNTH_BETA\"");
    assert_all_paths("password=\"[REDACTED] SYNTH_ALPHA SYNTH_BETA\"");
}

#[test]
fn public_context_survives_all_json_descendants() {
    for depth in [0, 1, 5, 16, 64, 100] {
        let mut node = json!({"text":"password=SYNTH_ALPHA SYNTH_BETA"});
        for _ in 0..depth {
            node = json!({"children":[node]});
        }
        let value = json!({"idempotency_key":node});
        let clean = scrub_json(&value).0;
        let text = serde_json::to_string(&clean).unwrap();
        assert!(!text.contains("SYNTH_ALPHA") && !text.contains("SYNTH_BETA"));
        assert_eq!(scrub_json(&clean), (clean.clone(), 0));
        // Serialized entry points reject a tree beyond serde's parsing bound.
        if depth < 50 {
            let raw = serde_json::to_string(&value).unwrap();
            assert_eq!(scrub_json_text(&raw).unwrap().0, clean);
            assert!(scrub_records(raw.as_bytes()).is_ok());
        }
    }
}

#[test]
fn headers_flags_connection_strings_and_private_keys() {
    for input in [
        "--password SYNTH_ALPHA",
        "let password =\n\"SYNTH_ALPHA SYNTH_BETA\";",
        "password:\n  SYNTH_ALPHA\n  SYNTH_BETA\nstatus: preserved",
        "password: SYNTH_ALPHA\n  SYNTH_BETA\nstatus: preserved",
        "PASSWORD==SYNTH_ALPHA",
        "--password==SYNTH_ALPHA",
        "password=SYNTH_ALPHA%20SYNTH_BETA",
        "password=SYNTH_ALPHA%0ASYNTH_BETA",
        "https://storage.test/item?sig=SYNTH_ALPHA%26SYNTH_BETA&ok=1",
        "https://config.test/?database_url=postgres://user:SYNTH_ALPHA@db/path",
        "Cookie: sid=SYNTH_ALPHA%0ASYNTH_BETA\n",
        r#"config["password"] = "SYNTH_ALPHA SYNTH_BETA";"#,
        r#"'password' => 'SYNTH_ALPHA SYNTH_BETA'"#,
        "password: SYNTH_ALPHA SYNTH_BETA\nother: preserved",
        r#"credentials={"user":"SYNTH_ALPHA","pass":"SYNTH_BETA"}"#,
        r#"token=["SYNTH_ALPHA","SYNTH_BETA"]"#,
        "--api-key=SYNTH_ALPHA",
        "PASSWORD=SYNTH_ALPHA",
        "Authorization: Basic SYNTH_ALPHA SYNTH_BETA",
        "Cookie: sid=SYNTH_ALPHA; auth=SYNTH_BETA",
        "Set-Cookie: session=SYNTH_ALPHA; HttpOnly",
        "Server=db;Password=SYNTH_ALPHA;User=app",
        "postgres://user:SYNTH_ALPHA@localhost/db",
        "https://host.test/path?X-Amz-Signature=SYNTH_ALPHA&ok=1",
        "password: |\n  SYNTH_ALPHA\n  SYNTH_BETA\nother: preserved",
        "-----BEGIN PRIVATE KEY-----\nSYNTH_ALPHA SYNTH_BETA\n-----END PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTH_ALPHA SYNTH_BETA",
    ] {
        assert_all_paths(input);
    }
}

#[test]
fn preserve_normal_information() {
    for input in [
        "idempotency_key=public-replay-42",
        "PASSWORD=\nSTATUS=ok\n",
        "PASSWORD=\n2026-11-10T00:00:00Z event\n",
        "PASSWORD=\n{\"event\":\"normal\"}\n",
        "password:\nstatus: okay\n",
        "Authorization:\nstatus: okay\n",
        "IDEMPOTENCY_KEY : \"public-replay-42\"",
        "key=arrow-up",
        "public_key=ssh-ed25519 AAAATEST user@example.test",
        "token_count=8192 token_budget=4000",
        "Call person@example.test from /Users/example/project at 2026-11-10T09:00:00Z",
        "version 1.2.3 issue #479 PR 42 /home/example/path C:\\Users\\example\\code",
        "https://example.test/path?state=public&code=1234&key=arrow&code_challenge=public",
        "database_url=postgres://localhost/database",
        "connection_string=Server=localhost;Database=normal",
        "git@github.com:AgentWorkforce/relay.git",
        "ssh://git@github.com/repo",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
        "uuid 12345678-1234-4234-8234-123456789abc git 0123456789abcdef0123456789abcdef01234567",
        "const passwordLength = 12; const tokenizer = new Tokenizer(); function getApiKey() {}",
        "if (token == expected) return true; if(password===candidate) return false;",
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8TEST",
    ] {
        assert_eq!(scrub_text(input), input);
    }
}

#[test]
fn errors_are_atomic_and_deterministic() {
    assert_eq!(
        scrub_records(b"{}\n{broken}").unwrap_err(),
        RecordError {
            code: "invalid_json",
            record: 2
        }
    );
    assert_eq!(
        scrub_records(b"{}\n\xff").unwrap_err(),
        RecordError {
            code: "invalid_utf8",
            record: 2
        }
    );
    assert_eq!(scrub_records(b"\r\n{}\n\n[]").unwrap().record_count, 2);
    assert!(scrub_json_text("{broken}").is_none());
    let mut deep = json!("SYNTH_ALPHA");
    for _ in 0..150 {
        deep = json!([deep]);
    }
    assert_eq!(scrub_json(&deep).0, Value::String(REDACTION_TOKEN.into()));
    assert!(scrub_records("[".repeat(150).as_bytes()).is_err());
}

#[test]
fn keyed_json_values_and_collision_handling() {
    let clean = scrub_json(
        &json!({"password":12,"apiKey":[true,{"nested":"SYNTH_ALPHA"}], "key":"normal"}),
    )
    .0;
    assert_eq!(
        clean,
        json!({"password":REDACTION_TOKEN,"apiKey":REDACTION_TOKEN,"key":"normal"})
    );
    let mut map = serde_json::Map::new();
    map.insert("password=SYNTH_ALPHA".into(), json!(1));
    map.insert("password=SYNTH_BETA".into(), json!(2));
    map.insert("password=[REDACTED] (2)".into(), json!(3));
    let output = scrub_json(&Value::Object(map)).0;
    assert_eq!(output.as_object().unwrap().len(), 3);
    assert_eq!(scrub_json(&output).0, output);
}

#[test]
fn pii_requires_explicit_policy() {
    let text = "person@example.test 123-45-6789";
    assert_eq!(scrub_text(text), text);
    let clean = scrub_text_with_policy(text, Policy::Pii);
    assert_eq!(clean, "[REDACTED] [REDACTED]");
    assert_eq!(manifest_with_policy(Policy::Pii).policy, Policy::Pii);
}

#[test]
fn yaml_secret_blocks_preserve_sibling_fields() {
    let input =
        "config:\n  password: |\n    SYNTH_ALPHA\n    SYNTH_BETA\n  retries: 3\nnext: okay\n";
    let clean = scrub_text(input);
    assert!(!clean.contains("SYNTH_ALPHA") && !clean.contains("SYNTH_BETA"));
    assert!(clean.contains("  retries: 3\nnext: okay\n"));
    assert_eq!(scrub_text(&clean), clean);
}

#[test]
fn compact_tokens_accept_json_header_whitespace_jwe_and_unsigned_jwt() {
    use base64::Engine;
    let encode = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
    for header in [r#"{ "alg": "HS256", "typ": "JWT" }"#, r#"{"alg":"none"}"#] {
        let token = format!(
            "{}.{}.{}",
            encode(header),
            encode(r#"{"sub":"SYNTH_ALPHA"}"#),
            encode("SYNTH_BETA")
        );
        assert_eq!(scrub_text(&token), REDACTION_TOKEN);
    }
    let token = format!(
        "{}.{}.{}",
        encode(r#"{"alg":"none"}"#),
        encode(r#"{"sub":"SYNTH_ALPHA"}"#),
        ""
    );
    assert_eq!(scrub_text(&token), REDACTION_TOKEN);
    let token = format!(
        "{}.{}.{}.{}.{}",
        encode(r#"{"alg":"dir","enc":"A256GCM"}"#),
        "",
        encode("nonce"),
        encode("SYNTH_ALPHA"),
        encode("SYNTH_BETA")
    );
    assert_eq!(scrub_text(&token), REDACTION_TOKEN);
}

#[test]
fn provider_bodies_and_unicode_boundaries_never_leave_tails() {
    let body = "SYNTHETIC".repeat(8);
    let google = format!("AIza{body}-ghp_{body}");
    let input = format!("値{google}次");
    assert_eq!(scrub_text(&input), "値[REDACTED]次");
    let aws = format!("AKIASYNTHETIC{}", "A".repeat(7));
    let input = format!("値{aws}次");
    assert_eq!(scrub_text(&input), "値[REDACTED]次");
}

#[test]
fn strict_secret_manager_references_are_not_credentials() {
    for text in [
        "op://vault/item/field",
        "op://My Vault/item name/field",
        "op://vault/item/section/field",
    ] {
        assert_eq!(
            scrub_text(&format!("api_key=\"{text}\"")),
            format!("api_key=\"{text}\"")
        );
        let value = json!({"api_key":text});
        assert_eq!(scrub_json(&value).0, value);
    }
    assert_all_paths("api_key=\"op://vault/item/password=SYNTH_ALPHA SYNTH_BETA\"");
    assert_all_paths("api_key=\"op://vault/item/field/extra/SYNTH_ALPHA SYNTH_BETA\"");
}
