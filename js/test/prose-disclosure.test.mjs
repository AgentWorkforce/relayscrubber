import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';

const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const scrubber=await loadScrubber({
  bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),
  expectedManifest:artifact.manifest,
  expectedWasmSha256:artifact.files['relayscrubber_bg.wasm'],
});
const fixtures=JSON.parse(readFileSync(new URL('../../eval/prose_disclosure_cases.json',import.meta.url)));
const R='[REDACTED]';
const casing=(text,mode)=>mode==='upper'?text.toUpperCase():mode==='mixed'?[...text].map((c,i)=>i%2?c.toUpperCase():c.toLowerCase()).join(''):text.toLowerCase();
const generated=[];
for(const noun of ['password','passcode','passphrase','pw','passwd','pwd','pass code','pass phrase'])
  for(const connector of ['is','was',':']) for(const mode of ['lower','upper','mixed'])
    for(const quote of ['',"'",'"']) for(const value of ['q','!']) {
      const left=`QUALIFICATION_PUBLIC_CONTEXT\n${casing('my',mode)} ${casing(noun,mode)} ${casing(connector,mode)} ${quote}`;
      generated.push({id:`${noun}/${connector}/${mode}/${quote}/${value}`,input:left+value+quote,expected:left+R+quote});
    }

function run(cases){
  const failures=[];
  for(const entry of cases){
    const raw=JSON.stringify({text:entry.input});
    const records=scrubber.scrubRecords(new TextEncoder().encode(raw)).bytes;
    const outputs=[
      scrubber.scrubTextChecked(entry.input),
      scrubber.scrubLong(entry.input),
      scrubber.scrubJson(raw).value.text,
      JSON.parse(new TextDecoder().decode(records)).text,
    ];
    outputs.forEach((output,api)=>{
      if(output!==entry.expected||scrubber.scrubText(output)!==output) failures.push(`${entry.id}/${api}: ${JSON.stringify(output)}`);
    });
    if(new TextDecoder().decode(scrubber.scrubRecords(records).bytes)!==new TextDecoder().decode(records)) failures.push(`${entry.id}/records-second-pass`);
  }
  return failures;
}

test('reviewer, mandatory, documentary and reference prose cases agree on every hosted API',()=>{
  assert.equal(fixtures.filter(c=>c.family==='reviewer').length,6);
  assert.deepEqual(run(fixtures),[]);
});
test('one-character disclosures for every mandatory noun, cue, casing and quote are redacted',()=>{
  assert.equal(generated.length,432);
  assert.deepEqual(run(generated),[]);
});
