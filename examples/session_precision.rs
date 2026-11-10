//! Counts-only private-session audit. Never prints text, identifiers or excerpts.
use relayscrubber::{scrub_report, scrub_text, Policy, REDACTION_TOKEN};
use serde_json::{json, Value};
use std::{collections::BTreeMap, io::BufRead};
fn main() {
    let mut events = 0;
    let mut bytes = 0;
    let mut changed = 0;
    let mut removed = 0;
    let mut unstable = 0;
    let mut shapes = BTreeMap::<&str, usize>::new();
    for path in std::env::args().skip(1) {
        let file = std::fs::File::open(path).expect("private input unavailable");
        for line in std::io::BufReader::new(file).lines() {
            let row: Value = serde_json::from_str(&line.expect("private read failed"))
                .expect("private format invalid");
            for event in row["events"].as_array().expect("private events missing") {
                let text = event["text"].as_str().expect("private text missing");
                events += 1;
                bytes += text.len();
                let report = scrub_report(text, Policy::Secrets);
                changed += usize::from(report.text != text);
                unstable += usize::from(scrub_text(&report.text) != report.text);
                for span in report.redactions {
                    let value = &text[span.clone()];
                    if value == REDACTION_TOKEN {
                        continue;
                    }
                    removed += span.len();
                    let shape = if value.contains("SYNTH") {
                        "synthetic_example"
                    } else if value.starts_with("process.env.")
                        || value.starts_with("std::env::")
                        || value.starts_with("os.environ")
                        || value.starts_with("env.")
                        || value.starts_with("config.")
                    {
                        "code_reference_candidate"
                    } else if value.starts_with("${") || value.starts_with('$') {
                        "shell_reference_or_default_candidate"
                    } else if ["null", "None", "true", "false", "undefined"].contains(&value) {
                        "nonstring_literal_candidate"
                    } else if value.starts_with("function")
                        || value.starts_with("async")
                        || value.starts_with("(")
                        || value.starts_with("new ")
                    {
                        "code_expression_candidate"
                    } else if value.starts_with(REDACTION_TOKEN) {
                        "marker_with_tail_candidate"
                    } else if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        "identifier_or_credential_candidate"
                    } else {
                        "unlabelled_candidate"
                    };
                    *shapes.entry(shape).or_default() += 1;
                }
            }
        }
    }
    println!(
        "{}",
        json!({"source":relayscrubber::RULESET_SOURCE_SHA256,"events":events,"utf8Bytes":bytes,"changedEvents":changed,"removedBytes":removed,"secondPassChangedEvents":unstable,"candidateShapes":shapes,"classification":"shape audit; unlabelled detections are not ground-truth false positives"})
    );
}
