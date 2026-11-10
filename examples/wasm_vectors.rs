//! Export only synthetic native reference results for cross-runtime checks.
#[path = "../eval/generate.rs"]
mod generate;
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
    println!(
        "{}",
        serde_json::json!({"manifest":relayscrubber::manifest(),"text":text})
    );
}
