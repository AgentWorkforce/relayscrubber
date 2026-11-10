#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export RUSTUP_TOOLCHAIN=1.88.0
if [[ "$(wasm-bindgen --version)" != "wasm-bindgen 0.2.104" ]]; then
  echo 'Requires wasm-bindgen-cli 0.2.104 (cargo +1.88.0 install wasm-bindgen-cli --version 0.2.104 --locked)' >&2
  exit 1
fi
export CARGO_TARGET_DIR="${RELAY_SCRUB_TARGET_DIR:-target/wasm-build}"
export RUSTFLAGS="--remap-path-prefix=$PWD=/relayscrubber"
cargo build --locked --release --target wasm32-unknown-unknown --features wasm
mkdir -p js/generated
wasm-bindgen "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/relayscrubber.wasm" --target web --out-dir js/generated --out-name relayscrubber
node scripts/wasm-manifest.mjs
