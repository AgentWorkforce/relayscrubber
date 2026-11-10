//! Synthetic before/after checks, without values or session material.
fn main() {
    let cases: serde_json::Value = serde_json::from_str(
        &include_str!("../eval/family_cases.json")
            .replace("STRIPE_LIVE_PREFIX_", &["sk", "_live_"].concat()),
    )
    .unwrap();
    let rows: Vec<_> = cases["benign"].as_object().unwrap().iter().map(|(name, cases)| {
        let mut same = [0;3];
        for input in cases.as_array().unwrap() {
            let input = input.as_str().unwrap();
            let value = serde_json::json!({"text":input});
            let record = relayscrubber::scrub_records(value.to_string().as_bytes()).unwrap();
            let record: serde_json::Value = serde_json::from_slice(&record.bytes).unwrap();
            same[0] += usize::from(relayscrubber::scrub_text(input) == input);
            same[1] += usize::from(relayscrubber::scrub_json(&value).0["text"] == input);
            same[2] += usize::from(record["text"] == input);
        }
        serde_json::json!({"name":name,"cases":cases.as_array().unwrap().len(),"unchangedTextJsonRecords":same})
    }).collect();
    println!(
        "{}",
        serde_json::json!({"source":relayscrubber::RULESET_SOURCE_SHA256,"families":rows})
    );
}
