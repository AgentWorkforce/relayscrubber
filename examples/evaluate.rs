//! Synthetic evaluation and private corpus metrics; never emits source text.
#[path = "../eval/generate.rs"]
mod generate;
use relayscrubber::{scrub_report, scrub_text, Policy};
use serde_json::json;
use std::{collections::BTreeMap, time::Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|s| s == "--public") {
        let path = args.get(2).expect("private corpus manifest");
        let split = args.get(3).expect("dev or heldout");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("private corpus manifest"))
                .expect("manifest JSON");
        let mut classes = BTreeMap::<String, (usize, usize, usize)>::new();
        for item in manifest["sources"].as_array().expect("source list") {
            if item["split"].as_str() != Some(split) {
                continue;
            }
            let text = std::fs::read_to_string(item["path"].as_str().expect("private file"))
                .expect("corpus UTF-8");
            let report = scrub_report(&text, Policy::Secrets);
            let e = classes
                .entry(item["class"].as_str().unwrap().to_owned())
                .or_default();
            e.0 += text.len();
            e.1 += report.redactions.len();
            e.2 += report.redactions.iter().map(|r| r.len()).sum::<usize>();
        }
        let stats:BTreeMap<_,_>=classes.into_iter().map(|(k,(bytes,spans,removed))|(k,json!({"bytes":bytes,"changed_spans":spans,"removed_bytes":removed,"spans_per_mb":spans as f64/(bytes as f64/1_000_000.0)}))).collect();
        println!("{}", json!({"split":split,"classes":stats}));
        return;
    }
    if args.get(1).is_some_and(|s| s == "--private") {
        // Inputs stay outside git. Output is aggregate counts only. This is
        // candidate rate until the input has independently been labelled benign.
        let path = args.get(2).expect("private JSON input path");
        let items: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(path).expect("private input"))
                .expect("private JSON");
        let mut bytes = 0;
        let mut changed = 0;
        let mut spans = 0;
        let mut removed = 0;
        for item in &items {
            if item["truncated"] == true {
                continue;
            }
            let text = item["text"].as_str().unwrap_or("");
            let r = scrub_report(text, Policy::Secrets);
            bytes += text.len();
            changed += usize::from(r.text != text);
            spans += r.redactions.len();
            removed += r.redactions.iter().map(|s| s.len()).sum::<usize>();
        }
        println!(
            "{}",
            json!({"bytes":bytes,"changed_events":changed,"redaction_spans":spans,"removed_bytes":removed,"candidate_spans_per_mb":spans as f64/(bytes as f64/1_000_000.0)})
        );
        return;
    }
    let seed = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(24301);
    let mut classes = BTreeMap::<&str, (usize, usize, usize)>::new();
    let mut excess = 0;
    let mut bytes = 0;
    let start = Instant::now();
    for case in generate::recall(seed, 128) {
        let r = scrub_report(&case.text, Policy::Secrets);
        let hit = case.secrets.iter().all(|s| {
            r.redactions
                .iter()
                .any(|p| p.start <= s.start && p.end >= s.end)
        });
        let entry = classes.entry(case.class).or_default();
        entry.0 += 1;
        entry.1 += usize::from(hit);
        let intended = case.secrets.iter().map(|s| s.len()).sum::<usize>();
        let removed = r.redactions.iter().map(|s| s.len()).sum::<usize>();
        excess += removed.saturating_sub(intended);
        entry.2 += removed.saturating_sub(intended);
        bytes += case.text.len();
    }
    let elapsed = start.elapsed().as_secs_f64();
    let mut benign = BTreeMap::<&str, (usize, usize, usize)>::new();
    for (class, text) in generate::benign(seed ^ 0xbeef, 512) {
        let e = benign.entry(class).or_default();
        e.0 += text.len();
        e.1 += usize::from(scrub_text(&text) != text);
        e.2 += 1;
    }
    let recall:BTreeMap<_,_>=classes.into_iter().map(|(k,(n,h,over))|(k,json!({"cases":n,"complete":h,"recall":h as f64/n as f64,"excess_removed_bytes":over}))).collect();
    let benign:BTreeMap<_,_>=benign.into_iter().map(|(k,(b,fp,n))|(k,json!({"bytes":b,"cases":n,"false_positive_cases":fp,"false_positive_cases_per_mb":fp as f64/(b as f64/1_000_000.0)}))).collect();
    let mut timing = Vec::new();
    // Warm the compiled automata before measuring steady-state adversarial work.
    let _ = scrub_text("warmup");
    for size in [65_536, 262_144] {
        for (class, unit) in [
            ("unclosed_quotes", "password=\""),
            ("escape_chain", "\\"),
            ("percent_chain", "%252525"),
            ("quoted_names", "\"password\" "),
            ("url_authorities", "x://u:"),
            ("identifiers", "tokenizer_"),
            ("public_context_chain", "idempotency_key="),
            ("pem_openers", "-----BEGIN PRIVATE KEY-----"),
        ] {
            let input = unit.repeat(size / unit.len() + 1);
            let input = &input[..size];
            let mut worst = 0.0f64;
            let mut total = 0.0;
            for _ in 0..5 {
                let t = Instant::now();
                std::hint::black_box(scrub_text(input));
                let ms = t.elapsed().as_secs_f64() * 1000.0;
                worst = worst.max(ms);
                total += ms;
            }
            timing.push(json!({"class":class,"bytes":size,"worst_ms":worst,"mean_ms":total/5.0,"mb_per_s":(size as f64/1_000_000.0)/(total/5000.0)}));
        }
    }
    println!(
        "{}",
        json!({"seed":seed,"recall":recall,"benign":benign,"excess_removed_bytes":excess,"recall_corpus_bytes":bytes,"recall_throughput_mb_s":(bytes as f64/1_000_000.0)/elapsed,"timing":timing,"manifest":relayscrubber::manifest()})
    );
}
