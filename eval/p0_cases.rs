//! Invented P0 leak regressions shared by native tests and WASM parity vectors.
#[allow(dead_code)]
pub fn prose() -> Vec<(String, String)> {
    let mut cases = Vec::new();
    for (key, value) in [
        ("password", "correct horse battery staple"),
        ("auth", "open sesame please"),
        ("db_password", "my dog has fleas"),
        ("password", "a correct horse battery staple"),
        ("auth", "the open sesame phrase"),
        ("db_password", "use my dog has fleas"),
        ("password", "see you later"),
        ("auth", "the phrase used for birds"),
    ] {
        for quote in ["", "\"", "'"] {
            for prefix in ["", "database:\n  "] {
                let input = format!("{prefix}{key}: {quote}{value}{quote}\nnext: unchanged\n");
                let expected = input.replace(value, "[REDACTED]");
                cases.push((input, expected));
            }
        }
    }
    for value in ["false", "none", "<token>", "${DB_PASSWORD}", "example"] {
        for key in ["password", "auth"] {
            let input = format!("{key}: {value}\nnext: unchanged\n");
            cases.push((input.clone(), input));
        }
    }
    let input = "# the password field is optional\nnext: unchanged\n".to_string();
    cases.push((input.clone(), input));
    cases
}
#[allow(dead_code)]
pub fn containers() -> Vec<(String, String)> {
    let mut cases = Vec::new();
    for distance in [0, 511, 512, 513, 4096, 1024 * 1024] {
        let pad = "x".repeat(distance);
        // Exact gap from the opening brace to the key (in addition to fields).
        for open in ["aws={", "aws = {", "\"aws\": {"] {
            let input = format!("{open}{}key:SYNTH_ALPHA}}", " ".repeat(distance));
            cases.push((input.clone(), input.replace("SYNTH_ALPHA", "[REDACTED]")));
        }
        for nested in [false, true] {
            for (open, filler, key, close) in [
                (
                    "aws: \n",
                    format!("  filler: {pad}\n"),
                    "  key: SYNTH_ALPHA",
                    "\nnext: unchanged",
                ),
                (
                    "aws = {",
                    format!("filler = \"{pad}\", "),
                    "key = SYNTH_ALPHA",
                    "}\nnext = unchanged",
                ),
                (
                    "\"aws\": {",
                    format!("\"filler\": \"{pad}\", "),
                    "\"key\": \"SYNTH_ALPHA\"",
                    "}, \"next\": \"unchanged\"",
                ),
            ] {
                let (nested_open, nested_close, key) = if nested {
                    if open.contains('{') {
                        ("nested: {", "}", key.to_string())
                    } else {
                        ("  nested:\n", "", format!("  {key}"))
                    }
                } else {
                    ("", "", key.to_string())
                };
                let input = format!("{open}{filler}{nested_open}{key}{nested_close}{close}");
                cases.push((input.clone(), input.replace("SYNTH_ALPHA", "[REDACTED]")));
            }
        }
        for input in [
            format!("data={{filler:\"{pad}\", key:SYNTH_ALPHA}}"),
            format!("aws={{filler:\"{pad}\"}}; key=SYNTH_ALPHA"),
            format!("aws:\n  filler: {pad}\nkey: SYNTH_ALPHA"),
            format!("aws={{idempotency_key:{{filler:\"{pad}\", key:SYNTH_ALPHA}}}}"),
            format!("idempotency_key:\n  aws:\n    filler: {pad}\n    key: SYNTH_ALPHA"),
        ] {
            cases.push((input.clone(), input));
        }
    }
    cases
}
