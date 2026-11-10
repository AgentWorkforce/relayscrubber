//! Export only synthetic native reference results for cross-runtime checks.
#[path = "../eval/generate.rs"]
mod generate;
#[path = "../eval/review_cases.rs"]
mod review_cases;
fn main() {
    let mut text = Vec::new();
    for seed in [24301, 659918] {
        for c in generate::recall(seed, 32) {
            text.push(
                serde_json::json!({"input":c.text,"output":relayscrubber::scrub_text(&c.text)}),
            );
        }
        for (_, input) in generate::benign(seed, 32) {
            text.push(
                serde_json::json!({"output":relayscrubber::scrub_text(&input),"input":input}),
            );
        }
    }
    for (_, input, expected) in review_cases::findings() {
        assert_eq!(relayscrubber::scrub_text(&input), expected);
        text.push(serde_json::json!({"input":input,"output":expected}));
    }
    for input in review_cases::benign() {
        assert_eq!(relayscrubber::scrub_text(&input), input);
        text.push(serde_json::json!({"input":input,"output":input}));
    }
    let families: serde_json::Value = serde_json::from_str(
        &include_str!("../eval/family_cases.json")
            .replace("STRIPE_LIVE_PREFIX_", &["sk", "_live_"].concat()),
    )
    .unwrap();
    for inputs in families["benign"].as_object().unwrap().values() {
        for input in inputs.as_array().unwrap() {
            let input = input.as_str().unwrap();
            text.push(serde_json::json!({"input":input,"output":relayscrubber::scrub_text(input)}));
        }
    }
    for case in families["positive"].as_array().unwrap() {
        let input = case[1].as_str().unwrap();
        text.push(serde_json::json!({"input":input,"output":relayscrubber::scrub_text(input)}));
    }
    let sessions: serde_json::Value = serde_json::from_str(
        &include_str!("../eval/session_cases.json")
            .replace("STRIPE_LIVE_PREFIX_", &["sk", "_live_"].concat()),
    )
    .unwrap();
    for inputs in sessions["benign"].as_object().unwrap().values() {
        for input in inputs.as_array().unwrap() {
            let input = input.as_str().unwrap();
            assert_eq!(relayscrubber::scrub_text(input), input);
            text.push(serde_json::json!({"input":input,"output":input}));
        }
    }
    for case in sessions["positive"].as_array().unwrap() {
        let input = case[0].as_str().unwrap();
        let output = relayscrubber::scrub_text(input);
        assert!(!output.contains(case[1].as_str().unwrap()));
        text.push(serde_json::json!({"input":input,"output":output}));
    }
    let structural: serde_json::Value = serde_json::from_str(
        &include_str!("../eval/structural_cases.json")
            .replace("OPENAI_PREFIX_", &["sk", "-"].concat())
            .replace("CLOUDFLARE_PREFIX_", &["cf", "k_"].concat()),
    )
    .unwrap();
    for case in structural.as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let output = relayscrubber::scrub_text(input);
        if let Some(expected) = case["expected"].as_str() {
            assert_eq!(output, expected);
        } else {
            assert!(!output.contains(case["secret"].as_str().unwrap()));
        }
        text.push(serde_json::json!({"input":input,"output":output}));
    }
    let bearer: serde_json::Value =
        serde_json::from_str(include_str!("../eval/bearer_cases.json")).unwrap();
    for case in bearer["positive"].as_array().unwrap() {
        text.push(serde_json::json!({"input":case[0],"output":relayscrubber::scrub_text(case[0].as_str().unwrap())}));
    }
    let structured: Vec<_> = text.iter().map(|case| {
        let value = serde_json::json!({"text":case["input"]});
        let json = relayscrubber::scrub_json(&value).0;
        let records = relayscrubber::scrub_records(serde_json::to_string(&value).unwrap().as_bytes()).unwrap();
        serde_json::json!({"input":value.to_string(), "jsonText":json.to_string(), "records":String::from_utf8(records.bytes).unwrap()})
    }).collect();
    println!(
        "{}",
        serde_json::json!({"manifest":relayscrubber::manifest(),"text":text,"structured":structured})
    );
}
