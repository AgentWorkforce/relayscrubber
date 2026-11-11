// Replay invented recall/declaration controls against an extracted hosted package.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const [rootArg, outputPath] = process.argv.slice(2);
assert(rootArg && outputPath, 'usage: node scripts/verify-alpha8-reassignments.mjs PACKAGE_ROOT OUTPUT_JSON');
const root = resolve(rootArg);
const hash = value => createHash('sha256').update(value).digest('hex');
const artifact = JSON.parse(readFileSync(resolve(root, 'generated/artifact.json')));
for (const [file, expected] of Object.entries(artifact.files)) {
  assert.equal(hash(readFileSync(resolve(root, 'generated', file))), expected);
}
for (const [file, expected] of Object.entries(artifact.adapterFiles)) {
  assert.equal(hash(readFileSync(resolve(root, file))), expected);
}
const {loadScrubber} = await import(pathToFileURL(resolve(root, 'index.js')));
const s = await loadScrubber({
  bytes: new Uint8Array(readFileSync(resolve(root, 'generated/relayscrubber_bg.wasm'))),
  expectedManifest: artifact.manifest,
  expectedWasmSha256: artifact.files['relayscrubber_bg.wasm'],
});
const fixture = readFileSync(new URL('../eval/alpha8_reassignment_cases.json', import.meta.url));
const cases = JSON.parse(fixture);
const failedIds = [[], [], [], []];
const families = {};
for (const [i, c] of cases.entries()) {
  const raw = JSON.stringify({text: c.input});
  const records = s.scrubRecords(new TextEncoder().encode(raw)).bytes;
  const outputs = [s.scrubTextChecked(c.input), s.scrubLong(c.input),
    s.scrubJson(raw).value.text, JSON.parse(new TextDecoder().decode(records)).text];
  for (const [api, out] of outputs.entries()) {
    const valid = c.allowedExpected ? c.allowedExpected.includes(out) : out === c.expected;
    if (!valid || s.scrubText(out) !== out) {
      failedIds[api].push(i);
      if (api === 0) families[c.family] = (families[c.family] ?? 0) + 1;
    }
  }
  assert.deepEqual(s.scrubRecords(records).bytes, records, `records idempotence ${i}`);
}
const result = {
  cases: cases.length, fixtureSha256: hash(fixture),
  sourceSha256: artifact.manifest.rulesetSourceSha256,
  wasmSha256: artifact.files['relayscrubber_bg.wasm'],
  allInnerPinsVerified: true,
  failuresPerApi: failedIds.map(ids => ids.length),
  failedIdsSha256: hash(JSON.stringify(failedIds)),
  failedFamilies: families, idempotenceChecked: true,
};
writeFileSync(outputPath, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result));
