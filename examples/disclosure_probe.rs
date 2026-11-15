//! Test-only native probe for `scripts/qualify-prose-disclosures.mjs`.
//!
//! Reads a JSON array of `{id, form, body}` invented requests on stdin and
//! applies the native API matching the hosted one the runner compares against:
//! `text` -> `scrub_text_checked`, `json` -> `scrub_json_text_checked` (compact
//! serialization, as the WASM `jsonText`), `ndjson` -> `scrub_records`. Each
//! output is scrubbed a second time to report idempotence.
use relayscrubber::{scrub_json_text_checked, scrub_records, scrub_text_checked};
use serde_json::{json, Value};
use std::io::{self, Read};

fn apply(form: &str, body: &str) -> Result<String, String> {
    match form {
        "text" => scrub_text_checked(body).map_err(|e| e.code.to_string()),
        "json" => scrub_json_text_checked(body)
            .map(|(value, _)| serde_json::to_string(&value).expect("serialize JSON"))
            .map_err(|e| e.code.to_string()),
        "ndjson" => scrub_records(body.as_bytes())
            .map(|out| String::from_utf8(out.bytes).expect("UTF-8 records"))
            .map_err(|e| serde_json::to_string(&e).expect("record error")),
        other => panic!("unknown form {other}"),
    }
}

fn main() {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("read requests");
    let requests: Vec<Value> = serde_json::from_str(&input).expect("request array");
    let rows: Vec<Value> = requests
        .iter()
        .map(|request| {
            let id = request["id"].as_str().expect("id");
            let form = request["form"].as_str().expect("form");
            let body = request["body"].as_str().expect("body");
            match apply(form, body) {
                Ok(output) => {
                    let idempotent = apply(form, &output).is_ok_and(|second| second == output);
                    json!({"id": id, "output": output, "idempotent": idempotent})
                }
                Err(error) => json!({"id": id, "error": error}),
            }
        })
        .collect();
    let engine = format!("relayscrubber-{}", relayscrubber::manifest().crate_version);
    serde_json::to_writer(io::stdout(), &json!({"engineName": engine, "rows": rows}))
        .expect("write results");
}
