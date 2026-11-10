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

const reviewCases = [
  ['direct_intervening_quote', 'password="SYNTH_ALPHA\nnote="SYNTH_BETA"', 'password="[REDACTED]'],
  ['public_property_intervening_quote', 'idempotency_key="password=SYNTH_ALPHA\nnote="SYNTH_BETA"', 'idempotency_key="password=[REDACTED]'],
  ['generic_key', 'key=SYNTH_ALPHA', 'key=[REDACTED]'],
  ['prefixed_credential_key', 'dbPassword=SYNTH_ALPHA', 'dbPassword=[REDACTED]'],
  ['prefixed_public_like_name', 'request_idempotency_key=SYNTH_ALPHA', 'request_idempotency_key=[REDACTED]'],
  ['unicode_space', 'password\u00a0=SYNTH_ALPHA', 'password\u00a0=[REDACTED]'],
  ['comparison_precision', 'const ok = password === candidate;', 'const ok = password === candidate;'],
];
for (const [name, input, expected] of reviewCases) test(`review: ${name}`, () => {
  assert.equal(scrubber.scrubText(input), expected);
  assert.equal(scrubber.scrubText(expected), expected);
  assert.equal(scrubber.scrubJson(JSON.stringify({ text: input })).value.text, expected);
  const result = scrubber.scrubRecords(new TextEncoder().encode(JSON.stringify({ text: input })));
  assert.equal(JSON.parse(new TextDecoder().decode(result.bytes)).text, expected);
  assert.deepEqual(scrubber.scrubRecords(result.bytes).bytes, result.bytes);
});

test('native and pinned WASM JSON/NDJSON bytes agree, including second passes', () => {
  const vectors = JSON.parse(readFileSync(`${homedir()}/scrubber-eval/wasm-vectors.json`));
  for (const { input, jsonText, records } of vectors.structured) {
    assert.equal(scrubber.scrubJson(input).jsonText, jsonText);
    assert.equal(scrubber.scrubJson(jsonText).jsonText, jsonText);
    const output = scrubber.scrubRecords(new TextEncoder().encode(input)).bytes;
    assert.equal(new TextDecoder().decode(output), records);
    assert.deepEqual(scrubber.scrubRecords(output).bytes, output);
  }
});

test('UTF-8 admission boundaries and compatibility are checked in JS and Rust', async () => {
  const raw = await import('../generated/relayscrubber.js');
  const limit = 16 * 1024 * 1024;
  const at = 'é'.repeat(limit / 2);
  assert.equal(scrubber.scrubTextChecked(at), at);
  const over = at + 'x';
  for (const api of [scrubber, raw]) {
    assert.throws(() => api.scrubTextChecked(over), e => String(e).includes('text_too_large'));
    assert.equal(api.scrubText(over), '[REDACTED]');
    assert.equal(api.scrubLong(over), '[REDACTED]');
    const json = '"' + 'é'.repeat((limit - 2) / 2) + '"';
    assert.ok(api.scrubJson(json));
    assert.throws(() => api.scrubJson(json + ' '), e => String(e).includes('record_too_large'));
    assert.throws(() => api.scrubRecords(new TextEncoder().encode(json + ' ')), e => String(e).includes('record_too_large'));
    const records = new Uint8Array(64 * 1024 * 1024).fill(32);
    for (let i = limit - 1; i < records.length; i += limit) records[i] = 10;
    assert.ok(api.scrubRecords(records));
    assert.throws(() => api.scrubRecords(new Uint8Array(records.length + 1)), e => String(e).includes('stream_too_large'));
  }
});

test('credential-name, exact-selector and Unicode-spacing variants agree across APIs', () => {
  const variants = [
    ...['githubToken', 'stripeSecret', 'encryption_key', 'request_idempotency_key', 'idempotency__key'].map(name => [`${name}=SYNTH_ALPHA`, `${name}=[REDACTED]`]),
    ['aws={key:SYNTH_ALPHA}', 'aws={key:[REDACTED]}'],
    ...['\u00a0', '\ufeff', '\u2003'].map(space => [`password${space}=SYNTH_ALPHA`, `password${space}=[REDACTED]`]),
    ...['return password == expected;', 'assert password == fixture', 'idempotency_key=public-replay-42'].map(input => [input, input]),
  ];
  for (const [input, expected] of variants) {
    assert.equal(scrubber.scrubText(input), expected);
    assert.equal(scrubber.scrubLong(input), expected);
    assert.equal(scrubber.scrubText(expected), expected);
    assert.equal(scrubber.scrubJson(JSON.stringify({text: input})).value.text, expected);
    assert.equal(JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(JSON.stringify({text: input}))).bytes)).text, expected);
  }
});
