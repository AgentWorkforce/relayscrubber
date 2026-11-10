#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .task-tmp
export WRANGLER_SEND_METRICS=false
port="${SCRUBBER_WORKER_PORT:-8793}"
if curl --silent --fail "http://localhost:$port" > /dev/null; then
  echo 'Workers test port is already in use' >&2
  exit 1
fi
npx --yes wrangler@4.77.0 dev --local --port "$port" --config js/worker/wrangler.jsonc > .task-tmp/workers.log 2>&1 &
worker_pid=$!
stop_tree() {
  for child in $(pgrep -P "$1" || true); do stop_tree "$child"; done
  kill "$1" 2>/dev/null || true
}
trap 'stop_tree "$worker_pid"' EXIT
for attempt in $(seq 1 60); do
  if ! kill -0 "$worker_pid" 2>/dev/null; then echo 'Workers failed to start' >&2; exit 1; fi
  if curl --silent --fail "http://localhost:$port" > /dev/null; then break; fi
  sleep 1
done
curl --silent --show-error --fail --data-binary 'idempotency_key="password=SYNTH_ALPHA SYNTH_BETA"' "http://localhost:$port" | node --input-type=module -e '
import {readFileSync} from "node:fs";
let input=""; for await (const part of process.stdin) input+=part;
const result=JSON.parse(input);
if(result.text!=="idempotency_key=\"password=[REDACTED]\"") throw Error("Workers scrub mismatch");
const approved=JSON.parse(readFileSync("js/generated/artifact.json")).manifest;
if(result.manifest.rulesetSourceSha256!==approved.rulesetSourceSha256) throw Error("Workers source mismatch");
console.log("Local workerd scrub and startup identity check passed");'
