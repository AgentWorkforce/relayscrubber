// Invented complete-value regressions, independent of native parity output.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const cases=JSON.parse(readFileSync(new URL('../../eval/complete_cases.json',import.meta.url),'utf8').replaceAll('OPENAI_PREFIX_','sk'+'-'));
test('complete references and embedded literals across WASM APIs',()=>{
 const failures=[];
 cases.forEach((c,id)=>{
  const records=s.scrubRecords(new TextEncoder().encode(JSON.stringify({text:c.input}))).bytes;
  const outputs=[s.scrubTextChecked(c.input),s.scrubJson(JSON.stringify({text:c.input})).value.text,JSON.parse(new TextDecoder().decode(records)).text];
  outputs.forEach((out,api)=>{
   const ok=c.expected!==undefined?out===c.expected:!out.includes(c.secret)&&out.includes('[REDACTED]');
   if(!ok || s.scrubTextChecked(out)!==out) failures.push(`${id}/${c.family}/${api}`);
  });
  assert.deepEqual(s.scrubRecords(records).bytes,records);
 });
 assert.deepEqual(failures,[]);
});
test('numeric credentials redact as strings and numeric identifiers retain their types',()=>{
 for(const n of ['123456','-246810','12.375','6.02e23','0']) for(const key of ['password','passwd','pin','secret','client_secret','token','accessToken','refreshToken','api_key']) {
  const input=`{"${key}":${n},"session_id":57243,"pid":42,"port":8080,"count":0}`;
  const expected={[key]:'[REDACTED]',session_id:57243,pid:42,port:8080,count:0};
  const clean=s.scrubJson(input);
  assert.deepEqual(clean.value,expected);
  assert.equal(clean.redactionCount,1);
  const records=s.scrubRecords(new TextEncoder().encode(input));
  assert.deepEqual(JSON.parse(new TextDecoder().decode(records.bytes)),expected);
  assert.equal(records.redactionCount,1);
  const text=s.scrubTextChecked(input);
  assert.deepEqual(JSON.parse(text),expected);
  assert.equal(s.scrubTextChecked(text),text);
  assert.deepEqual(s.scrubJson(JSON.stringify(clean.value)).value,expected);
  assert.deepEqual(s.scrubRecords(records.bytes).bytes,records.bytes);
 }
});
