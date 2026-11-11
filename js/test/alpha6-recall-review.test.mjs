// Invented recall controls from the three independent review blockers.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const cases=JSON.parse(readFileSync(new URL('../../eval/alpha6_review_recall_cases.json',import.meta.url),'utf8'));
test('review blocker recall and source controls across WASM APIs',()=>{
 const failures=[];
 cases.forEach((c,id)=>{
  const raw=JSON.stringify({text:c.input});
  const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
  const outputs=[s.scrubTextChecked(c.input),s.scrubLong(c.input),s.scrubJson(raw).value.text,JSON.parse(new TextDecoder().decode(records)).text];
  outputs.forEach((out,api)=>{
   const ok=c.expected!==undefined?out===c.expected:!out.includes(c.secret)&&out.includes('[REDACTED]');
   if(!ok || s.scrubText(out)!==out) failures.push(`${id}/${c.family}/${api}`);
  });
  assert.deepEqual(s.scrubRecords(records).bytes,records);
 });
 assert.deepEqual(failures,[]);
});
