import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { loadScrubber } from '../index.js';
const artifact = JSON.parse(readFileSync(new URL('../generated/artifact.json', import.meta.url)));
const bytes = new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm', import.meta.url)));
const options = { bytes, expectedManifest: artifact.manifest, expectedWasmSha256: artifact.files['relayscrubber_bg.wasm'] };
const scrubber = await loadScrubber(options);

test('pinned artifact and source identity are mandatory', async () => {
  await assert.rejects(loadScrubber({ ...options, expectedWasmSha256: '0'.repeat(64) }), /artifact_mismatch/);
  await assert.rejects(loadScrubber({ ...options, expectedManifest: { ...artifact.manifest, rulesetVersion: 8 } }), /manifest_mismatch/);
  await assert.rejects(loadScrubber({ ...options, expectedManifest: {...artifact.manifest, scrubProfile:'invented'} }), e => e.code === 'scrubber_manifest_mismatch' && e.disposition === 'call_refusal');
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
  ['generic_key', 'key=SYNTH_ALPHA', 'key=SYNTH_ALPHA'],
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

test('private-audit symbolic placeholders, type annotations and call references stay unchanged', () => {
  for (const text of ['fn cancel(mut token: CancellationToken) {}', 'fn run(mut token: usize) {}', 'const options = { "token": cancellation.clone() };', 'password=<token>', 'password=xxx', 'token="<api-key>"']) {
    assert.equal(scrubber.scrubText(text), text);
    assert.equal(scrubber.scrubJson(JSON.stringify({text})).value.text, text);
    assert.equal(JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(JSON.stringify({text}))).bytes)).text, text);
  }
  for (const password of ['<token>', 'xxx', '<api-key>']) {
    assert.deepEqual(scrubber.scrubJson(JSON.stringify({password})).value, {password});
  }
});

const families = JSON.parse(readFileSync(new URL('../../eval/family_cases.json', import.meta.url), 'utf8').replaceAll('STRIPE_LIVE_PREFIX_', 'sk' + '_live_'));
function familyPaths(input) {
  return [scrubber.scrubText(input), scrubber.scrubJson(JSON.stringify({text: input})).value.text,
    JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(JSON.stringify({text: input}))).bytes)).text];
}
for (const [name, inputs] of Object.entries(families.benign)) test(`benign family: ${name}`, () => {
  for (const input of inputs) for (const output of familyPaths(input)) assert.equal(output, input);
});
test('family positive controls retain recall across all APIs', () => {
  for (const [name, input, secret] of families.positive) for (const output of familyPaths(input)) {
    assert.ok(!output.includes(secret), name);
    assert.equal(scrubber.scrubText(output), output);
  }
});
test('crate-owned profile and versioned errors', () => {
  assert.equal(scrubber.manifest.schema, 3);
  assert.equal(scrubber.manifest.abiVersion, 2);
  assert.equal(scrubber.manifest.scrubProfile, 'relayhistory-secrets-v10');
  assert.throws(() => scrubber.scrubJson('{broken}'), e => e.code === 'invalid_json' && e.disposition === 'call_refusal');
  assert.equal(scrubber.scrubText('ordinary'), 'ordinary');
});

test('tagged refusals preserve record positions and allow the next call', () => {
  for (const action of [() => scrubber.scrubTextChecked(null), () => scrubber.scrubRecords('wrong type')]) {
    assert.throws(action, e => e.code === 'scrubber_invalid_input' && e.disposition === 'call_refusal');
  }
  assert.throws(() => scrubber.scrubRecords(new TextEncoder().encode('{}\n{broken}')),
    e => e.code === 'invalid_json' && e.disposition === 'call_refusal' && e.record === 2);
  assert.equal(scrubber.scrubTextChecked('ordinary'), 'ordinary');
});
test('unexpected transport failure poisons the private instance and refuses subsequent calls', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import {readFileSync} from 'node:fs';
    import {loadScrubber} from './js/index.js';
    const artifact = JSON.parse(readFileSync('./js/generated/artifact.json'));
    const s = await loadScrubber({bytes:new Uint8Array(readFileSync('./js/generated/relayscrubber_bg.wasm')), expectedManifest:artifact.manifest, expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
    const parse = JSON.parse;
    JSON.parse = () => { throw new WebAssembly.RuntimeError('simulated unexpected transport failure'); };
    assert.throws(() => s.scrubJson('{}'), e => e.code === 'scrubber_engine_failure' && e.disposition === 'instance_poison');
    JSON.parse = parse;
    assert.throws(() => s.scrubText('ordinary'), e => e.code === 'scrubber_instance_poisoned' && e.disposition === 'instance_poison');
  `], {cwd: new URL('../..', import.meta.url), encoding:'utf8'});
  assert.equal(result.status, 0, result.stderr);
});

test('structured family variants preserve references and public contexts', () => {
  for (const {input, output} of families.structured) {
    const raw = JSON.stringify(input);
    assert.deepEqual(scrubber.scrubJson(raw).value, output);
    assert.deepEqual(JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(raw)).bytes)), output);
  }
});

test('strict frozen witnesses match native through every pinned WASM API', () => {
  const vectors = JSON.parse(readFileSync(`${homedir()}/scrubber-eval/wasm-vectors.json`));
  assert.equal(vectors.frozen.length, 199);
  for (const {input, output} of vectors.frozen) {
    for (const actual of familyPaths(input)) assert.equal(actual, output);
    assert.equal(scrubber.scrubText(output), output);
  }
});

test('unexpected startup manifest failure is tagged and poisons the loader', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import {readFileSync} from 'node:fs';
    import {loadScrubber} from './js/index.js';
    const artifact = JSON.parse(readFileSync('./js/generated/artifact.json'));
    const options = {bytes:new Uint8Array(readFileSync('./js/generated/relayscrubber_bg.wasm')), expectedManifest:artifact.manifest, expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']};
    const parse = JSON.parse;
    JSON.parse = (text, ...args) => {
      if (typeof text === 'string' && text.includes('scrubProfile')) throw new WebAssembly.RuntimeError('simulated startup manifest failure');
      return parse(text, ...args);
    };
    await assert.rejects(loadScrubber(options), e => e.code === 'scrubber_engine_failure' && e.disposition === 'instance_poison');
    JSON.parse = parse;
    await assert.rejects(loadScrubber(options), e => e.code === 'scrubber_instance_poisoned' && e.disposition === 'instance_poison');
  `], {cwd: new URL('../..', import.meta.url), encoding:'utf8'});
  assert.equal(result.status, 0, result.stderr);
});
