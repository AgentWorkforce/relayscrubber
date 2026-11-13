#!/usr/bin/env python3
"""Prepare ignored native probes; never publish the private Desktop source copy."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--desktop-repo", type=Path, required=True)
parser.add_argument("--desktop-source", default="06164e88bcf7bd77f49d5979527f0d5aafb8b450")
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
scratch = root / ".task-tmp"
source = subprocess.check_output(["git", "show", args.desktop_source + ":desktop-core/src/history/scrub.rs"], cwd=args.desktop_repo)
old_marker = b'pub const DEFAULT_ENGINE: &str = "relayscrubber-0.5.0-alpha.5";'
assert source.count(old_marker) == 1, "unexpected Desktop seam; review before adapting"
main = r'''#![allow(dead_code)]
#[path = "desktop.rs"]
mod desktop;
use std::io::{self, Read};
use desktop::{ScrubContext, ScrubEngine, ScrubSurface};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("read synthetic inputs");
    let requests: Vec<serde_json::Value> = serde_json::from_str(&input).expect("synthetic request array");
    let engine = ScrubEngine::default_engine();
    let context = ScrubContext::new(ScrubSurface::Upload).source("codex");
    let rows: Vec<serde_json::Value> = requests.iter().map(|request| {
        let id = request["id"].as_str().expect("case id");
        let body = request["body"].as_str().expect("synthetic body");
        match engine.scrub_text(body, &context) {
            Ok(output) => match engine.scrub_text(&output, &context) {
                Ok(second) => serde_json::json!({"id":id,"output":output,"idempotent":second==output}),
                Err(error) => serde_json::json!({"id":id,"output":output,"idempotent":false,"secondError":error.reason()}),
            },
            Err(error) => serde_json::json!({"id":id,"error":error.reason()}),
        }
    }).collect();
    serde_json::to_writer(io::stdout(), &serde_json::json!({"engineName":engine.name(),"rows":rows})).expect("write synthetic results");
}
'''
provenance = {"desktopSource": args.desktop_source, "originalSeamSha256": hashlib.sha256(source).hexdigest(), "variants": {}}
for label, version in [("alpha5", "0.5.0-alpha.5"), ("alpha9", "0.5.0-alpha.9")]:
    project = scratch / ("native-" + label)
    (project / "src").mkdir(parents=True, exist_ok=True)
    copied = source if label == "alpha5" else source.replace(old_marker, old_marker.replace(b"alpha.5", b"alpha.9"))
    (project / "src/desktop.rs").write_bytes(copied)
    (project / "src/main.rs").write_text(main)
    dependency = 'version = "=0.5.0-alpha.5"' if label == "alpha5" else "path = " + json.dumps(str(root))
    (project / "Cargo.toml").write_text(
        '[package]\nname = "arlap-desktop-' + label + '-qualification"\nversion = "0.0.0"\nedition = "2021"\n'
        '[dependencies]\nrelayscrubber = { ' + dependency + ' }\nserde = { version = "1", features = ["derive"] }\nserde_json = "1"\n')
    provenance["variants"][label] = {"crateVersion": version, "copiedSeamSha256": hashlib.sha256(copied).hexdigest(),
        "sourceAdjustment": "none" if label == "alpha5" else "test-only DEFAULT_ENGINE version marker alpha.5 -> alpha.9; behavior unchanged"}
(scratch / "native-probe-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
print(json.dumps(provenance))
