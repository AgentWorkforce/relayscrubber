#![allow(missing_docs)]
use relayscrubber::*;
use serde_json::{json, Value};

fn check(source: &str) {
    let cases: Vec<Value> = serde_json::from_str(source).unwrap();
    let mut failures = Vec::new();
    for (id, case) in cases.iter().enumerate() {
        let input = case["input"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();
        let transport_start = std::time::Instant::now();
        let value = json!({"text": input});
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        let records_elapsed = transport_start.elapsed();
        let text_start = std::time::Instant::now();
        let text = scrub_text_checked(input).unwrap();
        let text_elapsed = text_start.elapsed();
        let json_start = std::time::Instant::now();
        let structured = scrub_json(&value).0["text"].as_str().unwrap().to_owned();
        let json_elapsed = json_start.elapsed();
        let stability_start = std::time::Instant::now();
        for (api, actual) in [text, structured, parsed["text"].as_str().unwrap().into()]
            .iter()
            .enumerate()
        {
            if actual != expected || scrub_text(actual) != *actual {
                failures.push((id, api));
            }
        }
        assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
        if input.len() > 1_000_000 {
            eprintln!(
                "all-API phases: bytes={} records={:.3} text={:.3} JSON={:.3} second-pass={:.3}",
                input.len(),
                records_elapsed.as_secs_f64(),
                text_elapsed.as_secs_f64(),
                json_elapsed.as_secs_f64(),
                stability_start.elapsed().as_secs_f64()
            );
        }
    }
    assert!(failures.is_empty(), "failed case/API indices: {failures:?}");
}

#[test]
fn entity_query_all_apis() {
    check(include_str!("../eval/entity_query_cases.json"));
}

#[test]
fn percent_query_all_apis() {
    check(include_str!("../eval/percent_query_cases.json"));
}

#[test]
fn encoded_query_recovery_time_is_bounded() {
    use std::time::{Duration, Instant};
    for count in [2048, 16384] {
        for (family, prefix, padding, tail) in [
            (
                "nested percent queries",
                "https%3A%2F%2Fproxy.example.invalid%2F%3Furl%3D",
                "https%3A%2F%2Fproxy.example.invalid%2F%3Furl%3D",
                "%26signature%3D7e3b15c97e3b15c9%26sort%3Dasc",
            ),
            (
                "malformed entity recovery",
                "https://media.example.invalid/?caption=\"unfinished\n",
                "&amp;amp;page=ordinary",
                "&#X000026;signature=7e3b15c97e3b15c9&amp;sort=asc",
            ),
            (
                "nested entity layers",
                "https://media.example.invalid/?caption=audit&",
                "amp;",
                "signature=7e3b15c97e3b15c9&sort=asc",
            ),
            (
                "numeric leading zeros",
                "https://media.example.invalid/?caption=audit&#x",
                "0",
                "26;signature=7e3b15c97e3b15c9&sort=asc",
            ),
        ] {
            let input = format!("{prefix}{}{tail}", padding.repeat(count));
            let expected = input.replace("7e3b15c97e3b15c9", REDACTION_TOKEN);
            let start = Instant::now();
            let actual = scrub_text_checked(&input).unwrap();
            let elapsed = start.elapsed();
            eprintln!(
                "{family}: count={count} bytes={} seconds={:.3}",
                input.len(),
                elapsed.as_secs_f64()
            );
            assert!(
                elapsed < Duration::from_secs(10),
                "encoded query exceeded ten seconds"
            );
            assert_eq!(actual, expected);
            assert_eq!(scrub_text_checked(&actual).unwrap(), actual);
        }
    }
}

#[path = "../eval/query_separator_cases.rs"]
mod query_separator_cases;

#[test]
fn query_separator_property_all_apis() {
    let cases = query_separator_cases::cases();
    let mut failures = Vec::new();
    for (id, (input, expected)) in cases.iter().enumerate() {
        let value = json!({"text": input});
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        let outputs = [
            scrub_text_checked(input).unwrap(),
            scrub_json(&value).0["text"].as_str().unwrap().into(),
            parsed["text"].as_str().unwrap().into(),
        ];
        for (api, output) in outputs.iter().enumerate() {
            if output != expected || scrub_text(output) != *output {
                failures.push((id, api));
            }
        }
        assert_eq!(scrub_json(&scrub_json(&value).0).0, scrub_json(&value).0);
        assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
    }
    eprintln!(
        "separator property: {} cases, {} failing case/API pairs; first {:?}",
        cases.len(),
        failures.len(),
        &failures[..failures.len().min(24)]
    );
    assert!(failures.is_empty());
}

#[test]
fn semicolonless_query_time_is_bounded() {
    use std::time::{Duration, Instant};
    for count in [2048, 16384] {
        for (family, separator, key) in [
            (
                "semicolonless decimal zeros",
                format!("&#{}38", "0".repeat(count)),
                "X-Amz-Signature".to_owned(),
            ),
            (
                "semicolonless hex zeros",
                format!("&#X{}26", "0".repeat(count)),
                "access_token".to_owned(),
            ),
            (
                "semicolonless nested names",
                format!("&{}", "amp".repeat(count)),
                "signature".to_owned(),
            ),
            (
                "nested entity key",
                "&amp;#38".to_owned(),
                format!("&{}#115;ignature", "amp;".repeat(count)),
            ),
            (
                "long encoded key",
                "&amp;".to_owned(),
                format!("{}_token", "&#97;".repeat(count)),
            ),
            (
                "malformed recovery",
                "\n".to_owned(),
                format!("{}&#38signature", "&amp;sort=asc".repeat(count)),
            ),
        ] {
            let secret = "7e3b15c97e3b15c9";
            let input = format!(
                "https://media.example.invalid/?caption=audit{separator}{key}={secret}&sort=asc"
            );
            let expected = input.replace(secret, REDACTION_TOKEN);
            let start = Instant::now();
            let actual = scrub_text_checked(&input).unwrap();
            let elapsed = start.elapsed();
            eprintln!(
                "{family}: count={count} bytes={} seconds={:.3}",
                input.len(),
                elapsed.as_secs_f64()
            );
            assert!(elapsed < Duration::from_secs(10));
            assert_eq!(actual, expected);
            assert_eq!(scrub_text(&actual), actual);
        }
    }
}

#[test]
fn long_encoded_key_without_assignment_is_linear_and_unchanged() {
    use std::time::{Duration, Instant};
    for count in [2048, 16384] {
        let input = format!(
            "https://media.example.invalid/?caption=audit%26amp;{}",
            "%26#97;".repeat(count)
        );
        let start = Instant::now();
        assert_eq!(scrub_text_checked(&input).unwrap(), input);
        let elapsed = start.elapsed();
        eprintln!(
            "unassigned encoded key: count={count} bytes={} seconds={:.3}",
            input.len(),
            elapsed.as_secs_f64()
        );
        assert!(elapsed < Duration::from_secs(10));
    }
}

#[test]
fn benign_entity_lookahead_all_apis_stays_bounded() {
    use std::time::{Duration, Instant};
    for count in [2048, 16384] {
        for unit in [
            "&#38sort=asc",
            "&amp;page=2",
            "&#x26caption=ordinary",
            "&#39x",
            "&#x2Gsig=",
            "&#;sig=",
        ] {
            let input = format!(
                "https://media.example.invalid/?caption=audit{}",
                unit.repeat(count)
            );
            let source = json!([{ "input": input, "expected": input }]).to_string();
            let start = Instant::now();
            check(&source);
            let elapsed = start.elapsed();
            eprintln!(
                "benign entity lookahead: unit={unit} count={count} bytes={} seconds={:.3}",
                input.len(),
                elapsed.as_secs_f64()
            );
            assert!(elapsed < Duration::from_secs(10));
        }
    }
}

#[path = "../eval/html_url_punctuation_cases.rs"]
mod html_url_punctuation_cases;
// The enlarged correctness matrix and its timing probe run separately so the
// matrix itself cannot consume the probe's CPU budget. Limits/calls stay fixed.
static HTML_PUNCTUATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn html_attribute_url_punctuation_property_all_apis() {
    let _guard = HTML_PUNCTUATION_TEST_LOCK.lock().unwrap();
    let cases = html_url_punctuation_cases::cases();
    let mut failures = Vec::new();
    for (id, (input, expected)) in cases.iter().enumerate() {
        let value = json!({"text":input});
        let json = scrub_json(&value).0;
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        for (api, output) in [
            scrub_text(input),
            json["text"].as_str().unwrap().into(),
            parsed["text"].as_str().unwrap().into(),
        ]
        .iter()
        .enumerate()
        {
            if output != expected || scrub_text(output) != *output {
                failures.push((id, api));
            }
        }
        assert_eq!(scrub_json(&json).0, json);
        assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
    }
    eprintln!(
        "HTML attribute punctuation: {} cases; {} failing case/API pairs; first {:?}",
        cases.len(),
        failures.len(),
        &failures[..failures.len().min(24)]
    );
    assert!(failures.is_empty());
}
#[test]
fn html_attribute_punctuation_long_all_apis_is_bounded() {
    let _guard = HTML_PUNCTUATION_TEST_LOCK.lock().unwrap();
    use std::time::{Duration, Instant};
    for count in [2048, 16384] {
        let secret = "7e3b15c97e3b15c9";
        for (family, input) in [
            ("numeric equals zeros",format!("<a href=\"https://media.example.invalid/&#63;signature&#{}61{secret}\">open</a>","0".repeat(count))),
            ("nested named equals",format!("<a href=\"https&colon;&sol;&sol;media.example.invalid/&quest;signature&{}equals;{secret}\">open</a>","amp;".repeat(count))),
            ("many HTML attributes",format!("{}<a href=\"https&colon;&sol;&sol;media.example.invalid/&quest;signature&equals;{secret}\">open</a>","<a href=\"https&colon;&sol;&sol;media.example.invalid/&quest;sort&equals;asc\">open</a>".repeat(count))),
        ] {
            let expected=input.replace(secret,REDACTION_TOKEN);
            let source=json!([{ "input":input,"expected":expected }]).to_string();
            let start=Instant::now();check(&source);let elapsed=start.elapsed();
            eprintln!("HTML punctuation {family}: count={count} bytes={} seconds={:.3}",input.len(),elapsed.as_secs_f64());
            assert!(elapsed<Duration::from_secs(10));
        }
    }
}

#[test]
fn relative_attribute_url_blockers_all_apis() {
    let inputs = [
        "<a href=\"&sol;download&quest;signature&equals;7e3b15c97e3b15c9\">open</a>",
        "<a href=\"&sol;&sol;media.example.invalid&sol;&quest;X-Amz-Signature&equals;7e3b15c97e3b15c9\">open</a>",
        "<a href=\"download&quest;access_token&equals;7e3b15c97e3b15c9\">open</a>",
        "<a href=\"&sol;&sol;alice&colon;SYNTH_ALPHA&commat;media.example.invalid&sol;download\">x</a>",
        "//alice:SYNTH_ALPHA@media.example.invalid/download",
    ];
    let cases: Vec<_> = inputs
        .into_iter()
        .map(|input| {
            let expected = input
                .replace("7e3b15c97e3b15c9", REDACTION_TOKEN)
                .replace("SYNTH_ALPHA", REDACTION_TOKEN);
            json!({"input":input,"expected":expected})
        })
        .collect();
    check(&serde_json::to_string(&cases).unwrap());
}

#[path = "../eval/html_url_component_cases.rs"]
mod html_url_component_cases;

#[test]
fn reserved_component_reviewer_witnesses_all_apis() {
    let cases = [
        "<a href=\"/download?signature=SYNTH%26ALPHA&sort=asc\">",
        "//alice:SYNTH%2FALPHA@host",
        "//alice:SYNTH%3FALPHA@host",
        "//alice:SYNTH%23ALPHA@host",
    ].map(|input| {
        let start = input.find("SYNTH").unwrap();
        let end = input[start..].find(if input.starts_with("//") { '@' } else { '&' }).unwrap() + start;
        json!({"input": input, "expected": format!("{}[REDACTED]{}", &input[..start], &input[end..])})
    });
    check(&serde_json::to_string(&cases).unwrap());
}

#[test]
fn reserved_component_property_all_apis() {
    let _guard = HTML_PUNCTUATION_TEST_LOCK.lock().unwrap();
    let cases = html_url_component_cases::cases();
    let mut failures = Vec::new();
    for (id, (input, expected)) in cases.iter().enumerate() {
        let value = json!({"text": input});
        let json = scrub_json(&value).0;
        let records = scrub_records(value.to_string().as_bytes()).unwrap();
        let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
        for (api, out) in [
            scrub_text_checked(input).unwrap(),
            json["text"].as_str().unwrap().into(),
            parsed["text"].as_str().unwrap().into(),
        ]
        .iter()
        .enumerate()
        {
            if out != expected || scrub_text(out) != *out {
                failures.push((id, api));
            }
        }
        assert_eq!(scrub_json(&json).0, json);
        assert_eq!(scrub_records(&records.bytes).unwrap().bytes, records.bytes);
    }
    eprintln!(
        "reserved component property: {} cases; {} failing case/API pairs; first {:?}",
        cases.len(),
        failures.len(),
        &failures[..failures.len().min(24)]
    );
    assert!(failures.is_empty());
}

#[test]
fn reserved_component_long_all_apis_is_bounded() {
    let _guard = HTML_PUNCTUATION_TEST_LOCK.lock().unwrap();
    for count in [2048, 16384] {
        let secret = format!("SYNTH{}ALPHA", "%25252526%2f%3f%23%40%3a%3d+".repeat(count));
        let input = format!("<a href=\"/download?signature={secret}&sort=asc\">x</a>");
        let expected = input.replace(&secret, REDACTION_TOKEN);
        let source = json!([{ "input": input, "expected": expected }]).to_string();
        let start = std::time::Instant::now();
        check(&source);
        let elapsed = start.elapsed();
        eprintln!(
            "reserved component all APIs: count={count} bytes={} seconds={:.3}",
            input.len(),
            elapsed.as_secs_f64()
        );
        assert!(elapsed < std::time::Duration::from_secs(10));
    }
}

#[test]
fn entity_layer_boundaries_without_assignment_all_apis() {
    let cases: Vec<_> = ["&amp;", "&#38;", "&#x26;", ";"]
        .into_iter()
        .map(|separator| {
            let input =
                format!("<a href=\"/download?signature=SYNTH{separator}ALPHA&sort=asc\">x</a>");
            let expected = input.replace("SYNTH", REDACTION_TOKEN);
            json!({"input": input, "expected": expected})
        })
        .collect();
    check(&serde_json::to_string(&cases).unwrap());
}

#[test]
fn percent_quote_does_not_open_attribute_all_apis() {
    let input = "<a href=%22/download?signature=SYNTH%22ALPHA%22&sort=asc>x</a>";
    check(&json!([{ "input": input, "expected": input.replace("SYNTH%22ALPHA%22", REDACTION_TOKEN) }]).to_string());
}
