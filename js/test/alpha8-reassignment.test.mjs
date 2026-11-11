import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const a=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:a.manifest,expectedWasmSha256:a.files['relayscrubber_bg.wasm']});
const cases=JSON.parse(readFileSync(new URL('../../eval/alpha8_reassignment_cases.json',import.meta.url)));
for(let start=0;start<cases.length;start+=256)test(`alpha8 bare reassignment and declaration controls ${start}-${Math.min(start+256,cases.length)}`,()=>{
 const failures=[];
 cases.slice(start,start+256).forEach((c,i)=>{
  const raw=JSON.stringify({text:c.input});const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
  const outs=[s.scrubTextChecked(c.input),s.scrubLong(c.input),s.scrubJson(raw).value.text,JSON.parse(new TextDecoder().decode(records)).text];
  outs.forEach((out,api)=>{if(!(c.allowedExpected?c.allowedExpected.includes(out):out===c.expected)||s.scrubText(out)!==out)failures.push(`${start+i}/${c.family}/${api}`);});
  assert.deepEqual(s.scrubRecords(records).bytes,records);
 });
 assert.deepEqual(failures,[]);
});
