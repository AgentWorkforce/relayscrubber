import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadScrubber } from '../index.js';

const read = path => readFileSync(new URL(path, import.meta.url));
const artifact = JSON.parse(read('../generated/artifact.json'));
const scrubber = await loadScrubber({
  bytes: new Uint8Array(read('../generated/relayscrubber_bg.wasm')),
  expectedManifest: artifact.manifest,
  expectedWasmSha256: artifact.files['relayscrubber_bg.wasm'],
});
const fixture = JSON.parse(read('../../eval/assignment_bound_cases.json'));

test('ordinary large assignment records match the native contract', () => {
  const padding = fixture.padding.repeat(fixture.repeats);
  const expected = padding + fixture.expected;
  const encoded = JSON.stringify({ text: expected });
  for (const tail of fixture.cases) {
    const input = padding + tail;
    assert.equal(scrubber.scrubText(input), expected);
    assert.equal(scrubber.scrubTextChecked(input), expected);
    assert.equal(scrubber.scrubLong(input), expected);
    const json = JSON.stringify({ text: input });
    assert.equal(scrubber.scrubJson(json).jsonText, encoded);
    const records = scrubber.scrubRecords(new TextEncoder().encode(json));
    assert.equal(records.recordCount, 1);
    assert.equal(new TextDecoder().decode(records.bytes), encoded + '\n');
  }
});
