//! Counts only invented fixture outcomes, without emitting matched input or output.
use relayscrubber::*;
use serde_json::{json, Value};
fn paths(input: &str) -> [String; 3] {
    let value = json!({"text": input});
    let records = scrub_records(&serde_json::to_vec(&value).unwrap()).unwrap();
    let parsed: Value = serde_json::from_slice(&records.bytes).unwrap();
    [
        scrub_text(input),
        scrub_json(&value).0["text"].as_str().unwrap().into(),
        parsed["text"].as_str().unwrap().into(),
    ]
}
fn main() {
    let cases: Value = serde_json::from_str(
        &include_str!("../eval/session_cases.json")
            .replace("STRIPE_LIVE_PREFIX_", &["sk", "_live_"].concat()),
    )
    .unwrap();
    let families: Vec<_> = cases["benign"].as_object().unwrap().iter().map(|(name, inputs)| {
        let mut same = [0;3];
        let per_case: Vec<_> = inputs.as_array().unwrap().iter().map(|input| {
            let out = paths(input.as_str().unwrap());
            std::array::from_fn::<_,3,_>(|api| { let ok = out[api] == input.as_str().unwrap(); same[api] += usize::from(ok); ok })
        }).collect();
        json!({"name":name,"cases":inputs.as_array().unwrap().len(),"unchangedTextJsonRecords":same,"perCase":per_case})
    }).collect();
    let mut positives = [0; 3];
    for case in cases["positive"].as_array().unwrap() {
        for (api, out) in paths(case[0].as_str().unwrap()).iter().enumerate() {
            positives[api] += usize::from(
                !out.contains(case[1].as_str().unwrap())
                    && out.contains(REDACTION_TOKEN)
                    && scrub_text(out) == *out,
            );
        }
    }
    println!(
        "{}",
        json!({"source":manifest().ruleset_source_sha256,"families":families,"positiveCases":cases["positive"].as_array().unwrap().len(),"redactedTextJsonRecords":positives})
    );
}
