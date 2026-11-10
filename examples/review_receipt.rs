//! Synthetic before/after matrix; contains no session inputs.
#[path = "../eval/review_cases.rs"]
mod review_cases;
use relayscrubber::{scrub_json, scrub_records, scrub_text};
use serde_json::json;
fn main() {
    let rows: Vec<_> = review_cases::findings().into_iter().map(|(name, input, expected)| {
        let value = json!({"text":input});
        let raw = value.to_string();
        let records = scrub_records(raw.as_bytes()).unwrap();
        let record: serde_json::Value = serde_json::from_slice(&records.bytes).unwrap();
        json!({"name":name,"text":scrub_text(&input)==expected,"json":scrub_json(&value).0["text"]==expected,"records":record["text"]==expected})
    }).collect();
    println!(
        "{}",
        json!({"source":relayscrubber::RULESET_SOURCE_SHA256,"cases":rows})
    );
}
