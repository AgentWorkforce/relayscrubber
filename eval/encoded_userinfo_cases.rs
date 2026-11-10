//! Independent encoded-authority x password-data layer coverage.
#![allow(dead_code)]
use serde_json::Value;
#[path = "nested_component_cases.rs"]
mod nested;
#[path = "html_url_punctuation_cases.rs"]
mod punctuation;
fn wrap(url: &str, secret: &str, context: usize) -> (String, String) {
    let (url, secret) = if context >= 3 {
        (nested::encode(url), nested::encode(secret))
    } else {
        (url.to_owned(), secret.to_owned())
    };
    let input = match context {
        0 => url.clone(),
        1 => format!("<a href=\"{url}\">x</a>"),
        2 => format!("<a data-endpoint={url}>x</a>"),
        3 => format!("<a href=\"/outer?url={url}&page=2\">x</a>"),
        _ => unreachable!(),
    };
    let expected = if secret.is_empty() {
        input.clone()
    } else {
        input.replace(&secret, "[REDACTED]")
    };
    (input, expected)
}
pub fn cases() -> Vec<(String, String)> {
    let spec: Value =
        serde_json::from_str(include_str!("html_url_punctuation_property.json")).unwrap();
    let mut cases = Vec::new();
    for style in spec["styles"].as_array().unwrap() {
        let style = style.as_str().unwrap();
        let enc = |ch| punctuation::encode(ch, style);
        for scheme in [false, true] {
            let prefix = if scheme {
                format!("https{}{}{}", enc(':'), enc('/'), enc('/'))
            } else {
                format!("{}{}", enc('/'), enc('/'))
            };
            for escape in spec["componentEscapes"].as_array().unwrap() {
                let escape = escape.as_str().unwrap();
                for data in [
                    escape.to_string(),
                    escape.to_ascii_lowercase(),
                    escape.replacen('%', "%25", 1),
                    escape.replacen('%', "&#37;", 1),
                    escape.replacen('%', "&percnt;", 1),
                    escape.replacen('%', "%252525", 1),
                    format!("{escape}%2F%3F%23%40%3A%3D%26"),
                ] {
                    let mut secret = format!("SYNTH{data}ALPHA");
                    let mut uri = format!(
                        "{prefix}alice{}{secret}{}host{}download",
                        enc(':'),
                        enc('@'),
                        enc('/')
                    );
                    for depth in 0..3 {
                        if depth > 0 {
                            uri = nested::encode(&uri);
                            secret = nested::encode(&secret);
                        }
                        for context in 0..4 {
                            cases.push(wrap(&uri, &secret, context));
                        }
                    }
                }
            }
            for username in ["alice", "al%25253Aice"] {
                let mut uri = format!("{prefix}{username}{}host{}download", enc('@'), enc('/'));
                for depth in 0..3 {
                    if depth > 0 {
                        uri = nested::encode(&uri);
                    }
                    for context in 0..4 {
                        cases.push(wrap(&uri, "", context));
                    }
                }
            }
        }
    }
    for (input, secret) in [
        (
            "%2F%2Falice%3ASYNTH%2FALPHA%40host%2Fdownload",
            "SYNTH%2FALPHA",
        ),
        (
            "%2F%2Falice%3ASYNTH%3FALPHA%40host%2Fdownload",
            "SYNTH%3FALPHA",
        ),
        (
            "%2F%2Falice%3ASYNTH%23ALPHA%40host%2Fdownload",
            "SYNTH%23ALPHA",
        ),
        (
            "%252F%252Falice%253ASYNTH%252FALPHA%2540host%252Fdownload",
            "SYNTH%252FALPHA",
        ),
        (
            "&percnt;2F&percnt;2Falice&percnt;3ASYNTH&percnt;2FALPHA&percnt;40host",
            "SYNTH&percnt;2FALPHA",
        ),
    ] {
        cases.push((input.to_string(), input.replace(secret, "[REDACTED]")));
    }
    cases
}
