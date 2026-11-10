//! Synthetic exact-packet and final-ruling receipt; no session samples.
use relayscrubber::*;
use serde_json::{json, Value};
fn paths(input: &str) -> [String; 3] {
    let wrapper = json!({"text":input});
    let records = scrub_records(&serde_json::to_vec(&wrapper).unwrap()).unwrap();
    let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
    [
        scrub_text(input),
        scrub_json(&wrapper).0["text"].as_str().unwrap().into(),
        parsed["text"].as_str().unwrap().into(),
    ]
}
fn group(cases: Vec<(String, String)>) -> Value {
    let failures: Vec<_> = cases.iter().enumerate().filter_map(|(id,(input,expected))| {
        let outputs = paths(input);
        let matches = outputs.each_ref().map(|out| out == expected);
        let second_pass = paths(expected).each_ref().map(|out| out == expected);
        (matches != [true;3] || second_pass != [true;3]).then(|| json!({"id":id,"matchesTextJsonRecords":matches,"secondPassTextJsonRecords":second_pass}))
    }).collect();
    json!({"cases":cases.len(),"failures":failures})
}
fn main() {
    let exact =
        group(serde_json::from_str(include_str!("../eval/exact_packet_cases.json")).unwrap());
    let ruling = group(serde_json::from_str(include_str!("../eval/ruling_cases.json")).unwrap());
    let residual: Value = serde_json::from_str(
        &include_str!("../eval/residual_cases.json")
            .replace("OPENAI_PREFIX_", &["sk", "-proj-"].concat())
            .replace("GITHUB_PREFIX_", &["gh", "p_"].concat())
            .replace("AWS_PREFIX_", &["AK", "IA"].concat())
            .replace("SLACK_PREFIX_", &["xo", "xb-"].concat())
            .replace("STRIPE_PREFIX_", &["sk", "_live_"].concat()),
    )
    .unwrap();
    let benign = group(
        residual["benign"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let s = s.as_str().unwrap().to_string();
                (s.clone(), s)
            })
            .collect(),
    );
    let positive_failures: Vec<_> = residual["positive"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter_map(|(id, x)| {
            let input = x["input"].as_str().unwrap();
            let matches = paths(input).each_ref().map(|out| {
                out != input && out.contains(REDACTION_TOKEN) && scrub_text(out) == *out
            });
            (matches != [true; 3]).then(|| json!({"id":id,"redactedTextJsonRecords":matches}))
        })
        .collect();
    let value = json!({"idempotency_key":{"aws":{"key":"SYNTH_ALPHA"},"ordinary":{"key":"public-replay-42"},"password":"SYNTH_BETA"}});
    let expected = json!({"idempotency_key":{"aws":{"key":REDACTION_TOKEN},"ordinary":{"key":"public-replay-42"},"password":REDACTION_TOKEN}});
    let records = scrub_records(&serde_json::to_vec(&value).unwrap()).unwrap();
    println!(
        "{}",
        json!({"schema":1,"source":manifest().ruleset_source_sha256,"exactPacket":exact,"finalRuling":ruling,"residualBenign":benign,"residualPositive":{"cases":residual["positive"].as_array().unwrap().len(),"failures":positive_failures},"nestedStructuredJsonRecords":[scrub_json(&value).0==expected,serde_json::from_slice::<Value>(&records.bytes).unwrap()==expected]})
    );
}
