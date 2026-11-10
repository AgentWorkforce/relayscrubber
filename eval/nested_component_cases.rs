//! Invented nested URL values; expected bytes do not use the scanner.
#![allow(dead_code)]
use serde_json::Value;
pub fn encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
pub fn cases() -> Vec<(String, String)> {
    let spec: Value =
        serde_json::from_str(include_str!("html_url_punctuation_property.json")).unwrap();
    let mut cases = Vec::new();
    for escape in spec["componentEscapes"].as_array().unwrap() {
        let escape = escape.as_str().unwrap();
        for data in [
            escape.to_string(),
            escape.to_ascii_lowercase(),
            escape.replacen('%', "%25", 1),
            format!("{escape}%252f%3f%23%40%3a%3d+%25"),
        ] {
            let secret = format!("SYNTH{data}ALPHA");
            for (shape, (prefix, public)) in [
                ("download", "caption"),
                ("/download", "redirect_uri"),
                ("//host/download", "url"),
                ("", "next"),
                ("https://host/download", "return_to"),
            ]
            .into_iter()
            .enumerate()
            {
                for key in spec["keys"].as_array().unwrap() {
                    let key = key.as_str().unwrap();
                    let nested = format!("{prefix}?caption=audit&{key}={secret}&sort=asc");
                    let value = format!("/outer?{public}={}&page=2", encode(&nested));
                    for wrapper in 0..3 {
                        let input = match wrapper {
                            0 => format!("<a href=\"{value}\">x</a>"),
                            1 => format!("<a src='{value}'>x</a>"),
                            _ => format!("<a data-endpoint={value}>x</a>"),
                        };
                        let expected = input.replace(&encode(&secret), "[REDACTED]");
                        cases.push((input, expected));
                    }
                    if shape == 0 {
                        // Another independently encoded public redirect layer.
                        let twice = format!(
                            "/outer?url={}&page=2",
                            encode(&format!("/middle?next={}", encode(&nested)))
                        );
                        let input = format!("<a href=\"{twice}\">x</a>");
                        let expected = input.replace(&encode(&encode(&secret)), "[REDACTED]");
                        cases.push((input, expected));
                    }
                }
            }
            for prefix in ["//", "https://", ""] {
                let nested = format!("{prefix}al%3Aice:{secret}@host/download");
                let input = format!("<a href=\"/outer?url={}&page=2\">x</a>", encode(&nested));
                let expected = input.replace(&encode(&secret), "[REDACTED]");
                cases.push((input, expected));
            }
            let input = format!(
                "<a href=\"/outer?caption={}&page=2\">x</a>",
                encode(&format!("?q=a{data}b&page=2"))
            );
            cases.push((input.clone(), input));
        }
    }
    for (inner, secret) in [
        (
            "audit%26signature=SYNTH%2526ALPHA%26sort=asc",
            "SYNTH%2526ALPHA",
        ),
        (
            "https://host/download?caption=audit%26signature=SYNTH%2526ALPHA%26sort=asc",
            "SYNTH%2526ALPHA",
        ),
        ("signature%3DSYNTH%2526ALPHA", "SYNTH%2526ALPHA"),
        ("%2F%2Falice%3ASYNTH%252FALPHA%40host", "SYNTH%252FALPHA"),
    ] {
        let input = format!("<a href=\"/outer?caption={inner}&page=2\">x</a>");
        cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
    }
    cases
}
