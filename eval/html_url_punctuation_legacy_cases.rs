// Historical 3,718 witnesses retained unchanged beside the full 38-key matrix.
//! Independent invented HTML-attribute URL punctuation properties.
#![allow(dead_code)]
use serde_json::Value;
fn encode(ch: char, style: &str) -> String {
    let n = ch as u8;
    let name = match ch {
        ':' => "colon",
        '/' => "sol",
        '?' => "quest",
        '&' => "amp",
        '=' => "equals",
        _ => unreachable!(),
    };
    match style {
        "literal" => ch.to_string(),
        "decimal" => format!("&#{n};"),
        "decimal-bare" => format!("&#{n}"),
        "decimal-zero" => format!("&#000{n};"),
        "decimal-zero-bare" => format!("&#000{n}"),
        "hex" => format!("&#x{n:x};"),
        "hex-bare" => format!("&#x{n:x}"),
        "HEX" => format!("&#X{n:X};"),
        "HEX-bare" => format!("&#X{n:X}"),
        "hex-zero" => format!("&#x000{n:x};"),
        "hex-zero-bare" => format!("&#x000{n:x}"),
        "named" => format!("&{name};"),
        "NAMED" => format!("&{};", name.to_ascii_uppercase()),
        "double-named" => format!("&amp;{name};"),
        "triple-named" => format!("&amp;amp;{name};"),
        "double-decimal" => format!("&amp;#{n};"),
        "triple-hex" => format!("&amp;amp;#x{n:X};"),
        "percent" => format!("%{n:02X}"),
        "double-percent" => format!("%25{n:02X}"),
        "percent-entity" => format!("&#{n};")
            .bytes()
            .map(|b| format!("%{b:02X}"))
            .collect(),
        "entity-percent" => format!("&#37;{n:02X}"),
        "mixed" => format!("&amp;%23x000{n:x};"),
        _ => unreachable!(),
    }
}
fn attribute(url: &str, wrapper: usize) -> String {
    match wrapper {
        0 => format!("<a href=\"{url}\">open</a>"),
        1 => format!("<img src='{url}'>"),
        _ => format!("<a data-endpoint={url}>open</a>"),
    }
}
pub fn cases() -> Vec<(String, String)> {
    let spec: Value =
        serde_json::from_str(include_str!("html_url_punctuation_legacy_property.json")).unwrap();
    let styles: Vec<_> = spec["styles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let keys: Vec<_> = spec["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let secret = spec["secret"].as_str().unwrap();
    let mut cases = Vec::new();
    for (id, style) in styles.iter().enumerate() {
        for key in &keys {
            for wrapper in 0..3 {
                let equal = encode('=', style);
                let url = format!(
                    "https://media.example.invalid/?caption=audit&amp;{key}{equal}{secret}"
                );
                let input = attribute(&url, wrapper);
                cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
                for mixed in [false, true] {
                    let punctuation: Vec<_> = [':', '/', '?', '&', '=']
                        .iter()
                        .enumerate()
                        .map(|(i, ch)| {
                            encode(
                                *ch,
                                if mixed {
                                    styles[(id + i) % styles.len()]
                                } else {
                                    style
                                },
                            )
                        })
                        .collect();
                    let url = format!("https{}{}{}media.example.invalid/{}caption{}audit{}{key}{}{secret}{}sort{}asc", punctuation[0],punctuation[1],punctuation[1],punctuation[2],punctuation[4],punctuation[3],punctuation[4],punctuation[3],punctuation[4]);
                    let input = attribute(&url, wrapper);
                    cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
                }
            }
        }
        for key in spec["benignKeys"].as_array().unwrap() {
            for wrapper in 0..3 {
                let url = format!(
                    "https{}{}{}media.example.invalid/{}{}{}{secret}",
                    encode(':', style),
                    encode('/', style),
                    encode('/', style),
                    encode('?', style),
                    key.as_str().unwrap(),
                    encode('=', style)
                );
                let input = attribute(&url, wrapper);
                cases.push((input.clone(), input));
            }
        }
    }
    for opener in &styles {
        for equal in &styles {
            for key in &keys[..4] {
                let url = format!(
                    "https://media.example.invalid/{}{key}{}{secret}",
                    encode('?', opener),
                    encode('=', equal)
                );
                let input = attribute(&url, 0);
                cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
            }
        }
    }
    cases
}
