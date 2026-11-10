//! Invented property inputs; expected bytes are independent of the scanner.
#![allow(dead_code)]
use serde_json::Value;
pub fn cases() -> Vec<(String, String)> {
    let spec: Value = serde_json::from_str(include_str!("query_separator_property.json")).unwrap();
    let secret = spec["secret"].as_str().unwrap();
    let mut cases = Vec::new();
    for separator in spec["separators"].as_array().unwrap() {
        for key in spec["keys"].as_array().unwrap() {
            let key = key.as_str().unwrap();
            for encoding in spec["keyEncodings"].as_array().unwrap() {
                let key: String = match encoding.as_str().unwrap() {
                    "literal" => key.into(),
                    "upper" => key.to_ascii_uppercase(),
                    "percent" => key.bytes().map(|b| format!("%{b:02X}")).collect(),
                    "decimal" => key.bytes().map(|b| format!("&#{b};")).collect(),
                    "hex" => key.bytes().map(|b| format!("&#X0{b:X};")).collect(),
                    "nested" => key.bytes().map(|b| format!("&amp;#{};", b)).collect(),
                    _ => unreachable!(),
                };
                let input = format!(
                    "https://media.example.invalid/?a=b{}{key}={secret}&sort=asc",
                    separator.as_str().unwrap()
                );
                let expected = input.replace(secret, "[REDACTED]");
                cases.push((input, expected));
            }
        }
    }
    // The reviewer's exact HTML input and 12-case minimal reproducer matrix.
    for separator in ["&#38", "&#038", "&#x26", "&#X026"] {
        for key in ["sig", "signature", "X-Amz-Signature"] {
            let input = format!("<a href=\"https://media.example.invalid/?caption=audit{separator}{key}={secret}\">open</a>");
            let expected = input.replace(secret, "[REDACTED]");
            cases.push((input, expected));
        }
    }
    for input in spec["benign"].as_array().unwrap() {
        let input = input.as_str().unwrap().to_owned();
        cases.push((input.clone(), input));
    }
    cases
}
