//! Invented URL component data; expected spans are independent of recognition.
#![allow(dead_code)]
use serde_json::Value;
pub fn cases() -> Vec<(String, String)> {
    let spec: Value =
        serde_json::from_str(include_str!("html_url_punctuation_property.json")).unwrap();
    let mut cases = Vec::new();
    for escape in spec["componentEscapes"].as_array().unwrap() {
        let escape = escape.as_str().unwrap();
        for style in spec["componentStyles"].as_array().unwrap() {
            let data = match style.as_str().unwrap() {
                "upper" => escape.to_string(),
                "lower" => escape.to_ascii_lowercase(),
                "double" => escape.replacen('%', "%25", 1),
                "entity" => escape.replacen('%', "&#37;", 1),
                "entity-double" => escape.replacen('%', "&#37;25", 1),
                "mix" => format!("{escape}%252f&#37;3f%23%40%3a%3d+%25"),
                "percent-prefix" => format!("%252525{}", &escape[1..]),
                _ => unreachable!(),
            };
            let secret = format!("SYNTH{data}ALPHA");
            for prefix in [
                "download",
                "/download",
                "//host/download",
                "",
                "https://host/download",
            ] {
                for key in spec["keys"].as_array().unwrap() {
                    let key = key.as_str().unwrap();
                    for (question, equals, separator) in [
                        ("?", "=", "&"),
                        ("&quest;", "&equals;", "&amp;"),
                        ("&#63;", "&#61;", "&#38;"),
                    ] {
                        for wrapper in 0..3 {
                            let url = format!(
                                "{prefix}{question}{key}{equals}{secret}{separator}sort{equals}asc"
                            );
                            let input = match wrapper {
                                0 => format!("<a href=\"{url}\">x</a>"),
                                1 => format!("<img src='{url}'>"),
                                _ => format!("<a data-endpoint={url}>x</a>"),
                            };
                            let expected = input.replace(&secret, "[REDACTED]");
                            cases.push((input, expected));
                        }
                    }
                }
                let input = format!("<a href=\"{prefix}?q=a{data}b&page=2\">x</a>");
                cases.push((input.clone(), input));
            }
            for prefix in ["//", "https://", "", "/", "https:\\"] {
                for (colon, at) in [(":", "@"), ("&colon;", "&commat;"), ("&#58;", "&#64;")] {
                    let input =
                        format!("<a href=\"{prefix}alice{colon}{secret}{at}host/download\">x</a>");
                    cases.push((input.clone(), input.replace(&secret, "[REDACTED]")));
                }
            }
            let input = format!("//alice:{secret}@host");
            cases.push((input.clone(), input.replace(&secret, "[REDACTED]")));
        }
    }
    // Layer attacks: encoded delimiters that LOOK like assignments remain data;
    // literal/entity separators split values; plus, semicolons and fragments.
    for secret in [
        "SYNTH%26sort=asc",
        "SYNTH%2526sort%3Dasc",
        "SYNTH&#37;26sort=asc",
        "SYNTH%23fragment",
        "SYNTH+ALPHA",
        "SYNTH%253Bpage=2",
        "SYNTH%25%26ALPHA",
        "SYNTH#fragment",
    ] {
        let input = format!("<a href=\"/download?signature={secret}&sort=asc\">x</a>");
        cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
    }
    for separator in ["&", "&amp;", "&#38;", ";"] {
        let input =
            format!("<a href=\"/download?signature=SYNTH%26ALPHA{separator}sort=asc\">x</a>");
        cases.push((input.clone(), input.replace("SYNTH%26ALPHA", "[REDACTED]")));
    }
    cases
}
