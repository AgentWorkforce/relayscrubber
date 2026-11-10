#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .task-tmp
first=$(node -e 'const a=JSON.parse(require("fs").readFileSync("js/generated/artifact.json")); console.log(JSON.stringify({files:a.files,adapterFiles:a.adapterFiles}))')
isolated=$(mktemp -d "$PWD/.task-tmp/repro.XXXXXXXX")
RELAY_SCRUB_TARGET_DIR="$isolated" bash scripts/build-wasm.sh
second=$(node -e 'const a=JSON.parse(require("fs").readFileSync("js/generated/artifact.json")); console.log(JSON.stringify({files:a.files,adapterFiles:a.adapterFiles}))')
if [[ "$first" != "$second" ]]; then
  echo 'WASM build is not reproducible' >&2
  exit 1
fi
echo 'Independent target-directory build reproduced every artifact digest'
