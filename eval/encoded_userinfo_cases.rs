//! Independent encoded-authority x password-data layer coverage.
#![allow(dead_code)]
use super::html_url_punctuation_cases as punctuation;
use super::nested_component_cases as nested;
use serde_json::Value;
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
                            // Context 3 adds one URL encoding layer. Keep the
                            // authority itself within the four-layer contract.
                            if style == "double-percent" && depth == 2 && context == 3 {
                                continue;
                            }
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
                        if style == "double-percent" && depth == 2 && context == 3 {
                            continue;
                        }
                        cases.push(wrap(&uri, "", context));
                    }
                }
            }
        }
    }
    for escape in ["%20", "%22", "%27", "%3E", "%09"] {
        let secret = format!("SYNTH{escape}ALPHA");
        for depth in 1..=4 {
            let enc = |ch: &str| {
                let mut text = ch.to_owned();
                for _ in 0..depth {
                    text = nested::encode(&text);
                }
                text
            };
            let uri = format!(
                "{}{}alice{}{secret}{}host{}download",
                enc("/"),
                enc("/"),
                enc(":"),
                enc("@"),
                enc("/")
            );
            for context in 0..2 {
                cases.push(wrap(&uri, &secret, context));
            }
        }
    }
    for input in [
        "<a href=\"password=SYNTH@host\">",
        "<a href=\"//password=SYNTH@host\">",
    ] {
        cases.push((input.to_string(), input.replace("SYNTH@host", "[REDACTED]")));
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
