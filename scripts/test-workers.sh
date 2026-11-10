#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .task-tmp
export WRANGLER_SEND_METRICS=false
npx --yes wrangler@4.77.0 dev --local --port 8792 --config js/worker/wrangler.jsonc > .task-tmp/workers.log 2>&1 &
worker_pid=$!
trap 'kill "$worker_pid" 2>/dev/null || true' EXIT
for attempt in $(seq 1 60); do
  if curl --silent --fail http://localhost:8792 > /dev/null; then break; fi
  sleep 1
done
curl --silent --show-error --fail --data-binary 'idempotency_key="password=SYNTH_ALPHA SYNTH_BETA"' http://localhost:8792 | node --input-type=module -e '
let input=""; for await (const part of process.stdin) input+=part;
const result=JSON.parse(input);
if(result.text!=="idempotency_key=\"password=[REDACTED]\"") throw Error("Workers scrub mismatch");
console.log("Local workerd scrub and startup identity check passed");'
