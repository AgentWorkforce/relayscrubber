// Synthetic standalone Bearer regressions, independently expected on every API.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const cases=JSON.parse(readFileSync(new URL('../../eval/bearer_cases.json',import.meta.url)));
for(const family of ['positive','benign']) test(`standalone Bearer ${family} across checked text, JSON and NDJSON`,()=>{
 const failures=[];
 cases[family].forEach((item,id)=>{
  const [input,expected]=family==='positive'?item:[item,item];
  const raw=[{text:input},{text:'ordinary'},{text:input}].map(x=>JSON.stringify(x)).join('\n')+'\n';
  const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
  const parsed=new TextDecoder().decode(records).trimEnd().split('\n').map(x=>JSON.parse(x));
  [s.scrubTextChecked(input),s.scrubJson(JSON.stringify({text:input})).value.text,parsed[0].text,parsed[2].text,s.scrubText(expected)].forEach((out,api)=>{if(out!==expected) failures.push(`${id}/${api}`);});
  assert.deepEqual(parsed[1],{text:'ordinary'});
  assert.deepEqual(s.scrubRecords(records).bytes,records);
 });
 assert.deepEqual(failures,[],'case/API mismatches');
});
