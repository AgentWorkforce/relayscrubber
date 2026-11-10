import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { loadScrubber } from '../index.js';
const artifact = JSON.parse(readFileSync(new URL('../generated/artifact.json', import.meta.url)));
const bytes = new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm', import.meta.url)));
const options = { bytes, expectedManifest: artifact.manifest, expectedWasmSha256: artifact.files['relayscrubber_bg.wasm'] };
const scrubber = await loadScrubber(options);

test('pinned artifact and source identity are mandatory', async () => {
  await assert.rejects(loadScrubber({ ...options, expectedWasmSha256: '0'.repeat(64) }), /artifact_mismatch/);
  await assert.rejects(loadScrubber({ ...options, expectedManifest: { ...artifact.manifest, rulesetVersion: 8 } }), /manifest_mismatch/);
  const corrupt = bytes.slice(); corrupt[16] ^= 1;
  await assert.rejects(loadScrubber({ ...options, bytes: corrupt }), /artifact_mismatch/);
});
test('all APIs cover public credential tails and fail atomically', () => {
  const text = 'idempotency_key="password=SYNTH_ALPHA SYNTH_BETA"';
  const output = scrubber.scrubText(text);
  assert.equal(output, 'idempotency_key="password=[REDACTED]"');
  assert.equal(scrubber.scrubLong(text), output);
  assert.equal(scrubber.scrubText(output), output);
  assert.deepEqual(scrubber.scrubJson(JSON.stringify({ idempotency_key: { nested: [{ text: 'password=SYNTH_ALPHA SYNTH_BETA' }] } })).value, { idempotency_key: { nested: [{ text: 'password=[REDACTED]' }] } });
  const records = scrubber.scrubRecords(new TextEncoder().encode(JSON.stringify({ text })));
  assert.equal(records.recordCount, 1);
  assert.equal(JSON.parse(new TextDecoder().decode(records.bytes)).text, output);
  assert.throws(() => scrubber.scrubRecords(new Uint8Array([255])), e => String(e).includes('invalid_utf8'));
  assert.throws(() => scrubber.scrubRecords(new TextEncoder().encode('{}\n{broken}')), e => String(e).includes('invalid_json'));
});
test('WASM matches independently generated native vectors', () => {
  const vectors = JSON.parse(readFileSync(`${homedir()}/scrubber-eval/wasm-vectors.json`));
  assert.equal(vectors.manifest.rulesetSourceSha256, scrubber.manifest.rulesetSourceSha256);
  for (const { input, output } of vectors.text) assert.equal(scrubber.scrubText(input), output);
});
test('Rust JSON text preserves large integer identifiers for persistence', () => {
  const text = '{"id":18446744073709551615,"note":"normal"}';
  const result = scrubber.scrubJson(text);
  assert.equal(result.jsonText, text);
  assert.equal(result.redactionCount, 0);
  const records = scrubber.scrubRecords(new TextEncoder().encode(text));
  assert.equal(new TextDecoder().decode(records.bytes), text + '\n');
});
test('64 KiB and 256 KiB adversarial inputs stay bounded', () => {
  for (const size of [65536, 262144]) {
    for (const unit of ['\\', '%252525', '"password" ', 'idempotency_key=', 'x://u:', '-----BEGIN PRIVATE KEY-----']) {
      const input = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
      const start = performance.now(); scrubber.scrubText(input);
      assert.ok(performance.now() - start < 5000, 'adversarial operation exceeded 5 seconds');
    }
  }
});
