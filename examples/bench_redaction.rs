//! Throughput benchmark: `scrub_long` (canonical engine) vs `scrub_enhanced`.
//!
//! Run with `cargo run --release --example bench_redaction`. All content is
//! synthetic. Prints a small table of MB/s per workload; use it to record
//! numbers into EVALS.md, not as a CI gate (machine noise).

use relayscrubber::{scrub_enhanced, scrub_long};
use std::time::Instant;

fn workload_clean(size: usize) -> String {
    let line =
        "ordinary log line 200000 token budget ok session 550e8400-e29b-41d4-a716-446655440000\n";
    line.repeat(size.div_ceil(line.len()))
}

fn workload_mixed(size: usize) -> String {
    let lines = [
        "ordinary log line 200000 token budget ok\n",
        "user jane.doe@example.com called +1 (415) 555-0132\n",
        "found sk-proj-Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1 in output\n",
        "db at 10.1.2.3:5432 route 192.168.1.10/24\n",
        "deploy --token Ab1c2D3eF4 --verbose\n",
        "see https://discord.com/api/webhooks/1234567890/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC ok\n",
        "{\"password\": \"Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1\", \"user\": \"ops\"}\n",
    ];
    let mut out = String::new();
    let mut i = 0;
    while out.len() < size {
        out.push_str(lines[i % lines.len()]);
        i += 1;
    }
    out
}

fn bench(name: &str, input: &str) {
    for (label, f) in [
        ("scrub_long    ", scrub_long as fn(&str) -> String),
        ("scrub_enhanced", scrub_enhanced as fn(&str) -> String),
    ] {
        // Warm up, then time enough iterations for a stable reading.
        let once = f(input);
        assert_eq!(f(&once), once, "{name}: enhanced/long must be idempotent");
        let mut iters = 0;
        let mut elapsed = std::time::Duration::ZERO;
        while elapsed.as_secs_f64() < 0.5 && iters < 50 {
            let start = Instant::now();
            let _ = f(input);
            elapsed += start.elapsed();
            iters += 1;
        }
        let secs = elapsed.as_secs_f64() / f64::from(iters);
        let mbps = (input.len() as f64 / 1_048_576.0) / secs;
        println!(
            "{label}  {name:<14} {:>8.2} MB/s  {:>9.1} µs/op  ({:.2} MB in, {:.2} MB out)",
            mbps,
            secs * 1e6,
            input.len() as f64 / 1_048_576.0,
            once.len() as f64 / 1_048_576.0,
        );
    }
}

/// Long delimiter-free runs with commas: the shape that made the cookie-name
/// scan quadratic before its 16-byte cap (regression workload, not a secret).
fn workload_commas(size: usize) -> String {
    "a,".repeat(size.div_ceil(2))
}

fn main() {
    println!("workload sizes are input MB; `out` shows redaction shrink");
    bench("clean-1MB", &workload_clean(1_048_576));
    bench("mixed-1MB", &workload_mixed(1_048_576));
    bench("mixed-256KB", &workload_mixed(262_144));
    bench("mixed-300KB", &workload_mixed(307_200));
    bench("commas-256KB", &workload_commas(262_144));
}
