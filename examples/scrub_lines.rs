//! Test-only JSON transport used by the TypeScript parity script.

use relayscrubber::{scrub_long, scrub_text};
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("read stdin");
    let values: Vec<String> = serde_json::from_str(&input).expect("JSON string array");
    let long = std::env::args().any(|arg| arg == "--long");
    let output: Vec<String> = values
        .iter()
        .map(|value| {
            if long {
                scrub_long(value)
            } else {
                scrub_text(value)
            }
        })
        .collect();
    serde_json::to_writer(io::stdout(), &output).expect("write JSON result");
}
