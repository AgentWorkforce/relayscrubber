//! Synthetic review witnesses shared by native and WASM parity tests.
#![allow(dead_code)]
pub fn findings() -> Vec<(&'static str, String, String)> {
    vec![
        (
            "direct_intervening_quote",
            "password=\"SYNTH_ALPHA\nnote=\"SYNTH_BETA\"".into(),
            "password=\"[REDACTED]".into(),
        ),
        (
            "public_property_intervening_quote",
            "idempotency_key=\"password=SYNTH_ALPHA\nnote=\"SYNTH_BETA\"".into(),
            "idempotency_key=\"password=[REDACTED]".into(),
        ),
        (
            "generic_key",
            "key=SYNTH_ALPHA".into(),
            "key=[REDACTED]".into(),
        ),
        (
            "prefixed_credential_key",
            "dbPassword=SYNTH_ALPHA".into(),
            "dbPassword=[REDACTED]".into(),
        ),
        (
            "prefixed_public_like_name",
            "request_idempotency_key=SYNTH_ALPHA".into(),
            "request_idempotency_key=[REDACTED]".into(),
        ),
        (
            "unicode_space",
            "password\u{a0}=SYNTH_ALPHA".into(),
            "password\u{a0}=[REDACTED]".into(),
        ),
        (
            "comparison_precision",
            "const ok = password === candidate;".into(),
            "const ok = password === candidate;".into(),
        ),
    ]
}
pub fn benign() -> Vec<String> {
    [
        "fn cancel(token: CancellationToken) {}",
        "fn cancel(token: &CancellationToken) {}",
        "const options = { token: cancellation.clone() };",
        "const options = { token: Some(cancellation) };",
        "password=<token>",
        "password=xxx",
        "token=\"<api-key>\"",
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
        "const ok = password === candidate;",
        "return password == expected;",
        "assert password == fixture",
        "if (token == expected) return true;",
        "assert password != fixture",
        "assert password !== fixture",
        "git 0123456789abcdef0123456789abcdef01234567",
        "uuid 12345678-1234-4234-8234-123456789abc",
        "integrity sha512-c3ludGhldGljLWJlbmlnbi1pbnRlZ3JpdHk=",
        "image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
        "base64 c3ludGhldGljLWJlbmlnbi1ibG9i",
        "log hex=abcdef0123456789abcdef0123456789",
        "arn:aws:iam::123456789012:role/synthetic-worker",
        "https://example.test/path?q=ordinary#fragment",
        "const passwordLength = 12; const tokenizer = new Tokenizer(); function getApiKey() {}",
        "token_count=8192 token_budget=4000 secret_name=fixture",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
