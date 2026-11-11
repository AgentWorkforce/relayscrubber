// Invented encoding regressions with independently specified expected bytes.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
for (const family of ['entity', 'percent']) {
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

const spec=JSON.parse(readFileSync(new URL('../../eval/query_separator_property.json',import.meta.url)));
for(let group=0;group<Math.ceil(spec.separators.length/9);group++) test(`query separator generated property all APIs batch ${group+1}`,()=>{
 const failures=[];
 const check=(input,expected,id)=>{
  const raw=JSON.stringify({text:input});
  const json=s.scrubJson(raw).value;
  const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
  const outputs=[s.scrubTextChecked(input),json.text,JSON.parse(new TextDecoder().decode(records)).text];
  outputs.forEach((out,api)=>{if(out!==expected || s.scrubText(out)!==out) failures.push([id,api]);});
  assert.deepEqual(s.scrubJson(JSON.stringify(json)).value,json);
  assert.deepEqual(s.scrubRecords(records).bytes,records);
 };
 let id=group*9*spec.keys.length*spec.keyEncodings.length;
 for(const separator of spec.separators.slice(group*9,(group+1)*9)) for(const plain of spec.keys) for(const encoding of spec.keyEncodings){
  const key=encoding==='literal'?plain:encoding==='upper'?plain.toUpperCase():[...plain].map(c=>{
   const n=c.charCodeAt(0), hex=n.toString(16).toUpperCase();
   return encoding==='percent'?`%${hex}`:encoding==='decimal'?`&#${n};`:encoding==='hex'?`&#X0${hex};`:`&amp;#${n};`;
  }).join('');
  const input=`https://media.example.invalid/?a=b${separator}${key}=${spec.secret}&sort=asc`;
  check(input,input.replace(spec.secret,'[REDACTED]'),id++);
 }
 if(group===0) for(const separator of ['&#38','&#038','&#x26','&#X026']) for(const key of ['sig','signature','X-Amz-Signature']){
  const input=`<a href="https://media.example.invalid/?caption=audit${separator}${key}=${spec.secret}">open</a>`;
  check(input,input.replace(spec.secret,'[REDACTED]'),id++);
 }
 if(group===0) for(const input of spec.benign) check(input,input,id++);
 assert.deepEqual(failures,[],`separator property ${id} cases; failing pairs ${failures.length}; first ${JSON.stringify(failures.slice(0,24))}`);
});

test('benign entity lookahead long all APIs stays bounded',()=>{
 for(const count of [2048,16384]) for(const unit of ['&#38sort=asc','&amp;page=2','&#x26caption=ordinary','&#39x','&#x2Gsig=','&#;sig=']){
  const input=`https://media.example.invalid/?caption=audit${unit.repeat(count)}`;
  const raw=JSON.stringify({text:input}), start=performance.now();
  const json=s.scrubJson(raw).value;
  const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
  assert.equal(s.scrubTextChecked(input),input);
  assert.equal(s.scrubText(input),input);
  assert.equal(json.text,input);
  assert.deepEqual(s.scrubJson(JSON.stringify(json)).value,json);
  assert.equal(JSON.parse(new TextDecoder().decode(records)).text,input);
  assert.deepEqual(s.scrubRecords(records).bytes,records);
  assert.ok(performance.now()-start<10000,`benign entity lookahead ${unit}/${count} exceeded ten seconds`);
 }
});
