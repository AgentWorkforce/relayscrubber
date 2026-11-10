// Invented fixtures only. Test all APIs against expectations, independently of native output.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact = JSON.parse(readFileSync(new URL('../generated/artifact.json', import.meta.url)));
const scrubber = await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm', import.meta.url))), expectedManifest:artifact.manifest, expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const cases = JSON.parse(readFileSync(new URL('../../eval/session_cases.json', import.meta.url),'utf8').replaceAll('STRIPE_LIVE_PREFIX_', 'sk'+'_live_'));
const paths = input => [scrubber.scrubText(input),scrubber.scrubJson(JSON.stringify({text:input})).value.text,JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(JSON.stringify({text:input}))).bytes)).text];
for (const [family, inputs] of Object.entries(cases.benign)) test(`session benign ${family}`, () => {
  const failures=[];
  inputs.forEach((input,n)=>paths(input).forEach((out,api)=>{if(out!==input) failures.push(`${n}/${api}`);}));
  assert.deepEqual(failures,[],'case/API mismatches');
});
test('session positives including YAML/config vs free prose distinction', () => {
  const failures=[];
  cases.positive.forEach(([input,secret],n)=>paths(input).forEach((out,api)=>{if(out.includes(secret)||!out.includes('[REDACTED]')||scrubber.scrubText(out)!==out) failures.push(`${n}/${api}`);}));
  assert.deepEqual(failures,[],'case/API mismatches');
});
