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
test('config evidence survives comments, blank lines and quoted keys', () => {
  for (const [key,value] of [['auth','the production credential'],['password','the actual secret value']]) for (const q of ['', '"', "'"]) {
    for (const input of [`${q}${key}${q}: ${value}\n\n# explanation\nnext: unchanged`,`next: unchanged\n# explanation\n\n${q}${key}${q}: ${value}`,`\`\`\`yaml\n\n${q}${key}${q}: ${value}\n\`\`\``,`# app.yaml\n\n${q}${key}${q}: ${value}`]) assert.deepEqual(paths(input),Array(3).fill(input.replace(value,'[REDACTED]')));
  }
});
test('structured auth config traverses explicit nested credentials', () => {
  const same={auth:{scheme:'oidc',audience:'demo-ui',enabled:true},session_id:'exec-7f3a2b1c',credentialsSecret:'catalog-access-store',password:'[REDACTED] (already removed)',api_key:'process.env.APP_KEY'};
  const secret={auth:{scheme:'oidc',password:'SYNTH_ALPHA',key:'SYNTH_BETA'}};
  for(const [input,expected] of [[same,same],[secret,{auth:{scheme:'oidc',password:'[REDACTED]',key:'[REDACTED]'}}]]) {
    const raw=JSON.stringify(input);
    assert.deepEqual(scrubber.scrubJson(raw).value,expected);
    assert.deepEqual(JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(raw)).bytes)),expected);
  }
});
