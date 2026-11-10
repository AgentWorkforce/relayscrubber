// Invented encoding regressions with independently specified expected bytes.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
for (const family of ['entity']) {
 const cases=JSON.parse(readFileSync(new URL(`../../eval/${family}_query_cases.json`,import.meta.url)));
 test(`${family} query all APIs`,()=>{
  const failures=[];
  cases.forEach((c,id)=>{
   const raw=JSON.stringify({text:c.input});
   const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
   const outputs=[s.scrubTextChecked(c.input),s.scrubJson(raw).value.text,JSON.parse(new TextDecoder().decode(records)).text];
   outputs.forEach((out,api)=>{
    if(out!==c.expected || s.scrubText(out)!==out) failures.push([id,api]);
   });
   assert.deepEqual(s.scrubRecords(records).bytes,records);
  });
  assert.deepEqual(failures,[]);
 });
}
