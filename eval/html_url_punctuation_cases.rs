//! Independent invented HTML-attribute URL punctuation properties.
#![allow(dead_code)]
use serde_json::Value;
#[path = "html_url_punctuation_legacy_cases.rs"]
mod legacy;
pub fn encode(ch: char, style: &str) -> String {
    let n = ch as u8;
    let name = match ch {
        ':' => "colon",
        '/' => "sol",
        '?' => "quest",
        '&' => "amp",
        '=' => "equals",
        '@' => "commat",
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
const PUNCTUATION: [char; 7] = [':', '/', '/', '/', '?', '&', '='];

// Over prime23, each pair of distinct columns is an invertible linear map
// from (a,b) to two symbols. Map the extra symbol22 to literal encoding0.
// The explicit coverage assertions also guard future catalog changes.
fn permutations(styles: usize, prime: usize) -> Vec<[usize; 7]> {
    assert_eq!(styles, 22);
    assert_eq!(prime, 23);
    let mut rows = Vec::new();
    for a in 0..prime {
        for b in 0..prime {
            rows.push(std::array::from_fn(|column| {
                let symbol = (a + column * b) % prime;
                if symbol < styles {
                    symbol
                } else {
                    0
                }
            }));
        }
    }
    for left in 0..PUNCTUATION.len() {
        for right in left + 1..PUNCTUATION.len() {
            let mut seen = vec![false; styles * styles];
            for row in &rows {
                seen[row[left] * styles + row[right]] = true;
            }
            assert!(
                seen.into_iter().all(|covered| covered),
                "missing punctuation pair"
            );
        }
    }
    rows
}
fn url(indices: &[usize; 7], styles: &[&str], key: &str, secret: &str) -> String {
    let p: Vec<_> = PUNCTUATION
        .iter()
        .enumerate()
        .map(|(i, ch)| encode(*ch, styles[indices[i]]))
        .collect();
    format!(
        "https{}{}{}media.example.invalid{}{}caption{}audit{}{key}{}{secret}{}sort{}asc",
        p[0], p[1], p[2], p[3], p[4], p[6], p[5], p[6], p[5], p[6]
    )
}
pub fn cases() -> Vec<(String, String)> {
    let spec: Value =
        serde_json::from_str(include_str!("html_url_punctuation_property.json")).unwrap();
    let shared: Value =
        serde_json::from_str(include_str!("query_separator_property.json")).unwrap();
    assert_eq!(
        spec["keys"], shared["keys"],
        "use the complete sensitive-key catalog"
    );
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
    assert_eq!(keys.len(), 38);
    assert_eq!(
        spec["positions"].as_array().unwrap().len(),
        PUNCTUATION.len()
    );
    let secret = spec["secret"].as_str().unwrap();
    let mut cases = legacy::cases();
    assert_eq!(
        cases.len(),
        3718,
        "retain every earlier punctuation witness"
    );
    for (style_id, style) in styles.iter().enumerate() {
        for key in &keys {
            for wrapper in 0..3 {
                let equals_only = format!(
                    "https://media.example.invalid/?caption=audit&amp;{key}{}{secret}",
                    encode('=', style)
                );
                let input = attribute(&equals_only, wrapper);
                cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
                let input = attribute(&url(&[style_id; 7], &styles, key, secret), wrapper);
                cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
            }
        }
        for position in 0..PUNCTUATION.len() {
            let mut indices = [0; 7];
            indices[position] = style_id;
            for key in &keys {
                let input = attribute(&url(&indices, &styles, key, secret), 0);
                cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
            }
        }
        for key in spec["benignKeys"].as_array().unwrap() {
            for wrapper in 0..3 {
                let input = attribute(
                    &url(&[style_id; 7], &styles, key.as_str().unwrap(), secret),
                    wrapper,
                );
                cases.push((input.clone(), input));
            }
        }
    }
    for indices in permutations(
        styles.len(),
        spec["coveringPrime"].as_u64().unwrap() as usize,
    ) {
        for key in &keys {
            let input = attribute(&url(&indices, &styles, key, secret), 0);
            cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
        }
        for key in spec["benignKeys"].as_array().unwrap() {
            let input = attribute(&url(&indices, &styles, key.as_str().unwrap(), secret), 0);
            cases.push((input.clone(), input));
        }
    }
    assert_eq!(cases.len(), 36473, "retain the full schemeful matrix");
    cases.extend(relative_cases());
    cases
}

pub fn relative_cases() -> Vec<(String, String)> {
    let spec: Value =
        serde_json::from_str(include_str!("html_url_punctuation_property.json")).unwrap();
    let styles: Vec<_> = spec["styles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let secret = spec["secret"].as_str().unwrap();
    let mut cases = Vec::new();
    for (style_id, _) in styles.iter().enumerate() {
        for (shape, positions) in [
            ("relative", &[4, 5, 6][..]),
            ("root", &[3, 4, 5, 6][..]),
            ("protocol", &[1, 2, 3, 4, 5, 6][..]),
            ("query", &[4, 5, 6][..]),
        ] {
            let make = |indices: [usize; 7], key: &str| {
                let p: Vec<_> = PUNCTUATION
                    .iter()
                    .enumerate()
                    .map(|(i, ch)| encode(*ch, styles[indices[i]]))
                    .collect();
                let prefix = match shape {
                    "relative" => "download".to_string(),
                    "root" => format!("{}download", p[3]),
                    "protocol" => format!("{}{}media.example.invalid{}download", p[1], p[2], p[3]),
                    _ => String::new(),
                };
                format!(
                    "{prefix}{}caption{}audit{}{key}{}{secret}{}sort{}asc",
                    p[4], p[6], p[5], p[6], p[5], p[6]
                )
            };
            for key in spec["keys"].as_array().unwrap() {
                let key = key.as_str().unwrap();
                for wrapper in 0..3 {
                    let input = attribute(&make([style_id; 7], key), wrapper);
                    cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
                }
                for position in positions {
                    let mut indices = [0; 7];
                    indices[*position] = style_id;
                    let input = attribute(&make(indices, key), 0);
                    cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
                }
                let input = attribute(
                    &make(std::array::from_fn(|i| (style_id + i) % styles.len()), key),
                    0,
                );
                cases.push((input.clone(), input.replace(secret, "[REDACTED]")));
            }
            for key in spec["benignKeys"].as_array().unwrap() {
                let input = attribute(&make([style_id; 7], key.as_str().unwrap()), 0);
                cases.push((input.clone(), input));
            }
        }
        for mixed in [false, true] {
            let enc = |ch, i| {
                encode(
                    ch,
                    styles[if mixed {
                        (style_id + i) % styles.len()
                    } else {
                        style_id
                    }],
                )
            };
            let url = format!(
                "{}{}alice{}SYNTH_ALPHA{}media.example.invalid{}download",
                enc('/', 1),
                enc('/', 2),
                enc(':', 0),
                enc('@', 5),
                enc('/', 3)
            );
            for wrapper in 0..3 {
                let input = attribute(&url, wrapper);
                cases.push((input.clone(), input.replace("SYNTH_ALPHA", "[REDACTED]")));
            }
        }
    }
    for prefix in [
        "./download",
        "../download",
        "?",
        "#fragment?",
        "https:\\media.example.invalid/download",
        " /download",
        "\t../download",
        "//media.example.invalid",
        "//alice:SYNTH_ALPHA@media.example.invalid/download",
    ] {
        for name in [
            "href",
            "src",
            "action",
            "formaction",
            "data",
            "poster",
            "cite",
            "background",
            "srcset",
            "data-endpoint",
        ] {
            for wrapper in 0..3 {
                let value = format!("{prefix}?signature={secret}&sort=asc ");
                let input = match wrapper {
                    0 => format!("<a {name}=\"{value}\">open</a>"),
                    1 => format!("<a {name}='{value}'>open</a>"),
                    _ => format!("<a {name}={} >open</a>", value.trim()),
                };
                let expected = input
                    .replace(secret, "[REDACTED]")
                    .replace("SYNTH_ALPHA", "[REDACTED]");
                cases.push((input, expected));
            }
        }
    }
    for input in [
        "//alice:SYNTH_ALPHA@media.example.invalid/download".to_string(),
        "<a href=\"https:\\alice:SYNTH_ALPHA@media.example.invalid/download\">x</a>".to_string(),
        "<a href=\"alice:SYNTH_ALPHA@media.example.invalid\">x</a>".to_string(),
        format!("<meta http-equiv=\"refresh\" content=\"0; url=../download&quest;signature&equals;{secret}\">"),
        format!("<img srcset=\"img.png 1x, ../download?signature={secret} 2x\">"),
        "<a href=\"&sol;&sol;alice&colon;SYNTH_ALPHA&commat;media.example.invalid&sol;download\">x</a>".to_string(),
    ] { let expected=input.replace(secret,"[REDACTED]").replace("SYNTH_ALPHA","[REDACTED]"); cases.push((input,expected)); }
    for input in [
        "<a href=\"/docs?page=2\">docs</a>",
        "<img src=\"img.png?v=3\">",
        "<a href=\"#section\">jump</a>",
        "<a href=\"mailto:a@example.invalid\">mail</a>",
        "plain prose /path?x=y",
        "// comment about /path?x=y",
        "const example = '/path?x=y';",
        "<!-- <a href=\"/path?signature=7e3b15c97e3b15c9\">example</a> -->",
        "<script>const example = '<a href=\"/path?signature=7e3b15c97e3b15c9\">';</script>",
    ] {
        cases.push((input.to_string(), input.to_string()));
    }
    cases
}
