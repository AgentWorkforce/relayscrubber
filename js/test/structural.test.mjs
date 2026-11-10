// Invented syntax regressions; expected values are independent of native output.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const cases=JSON.parse(readFileSync(new URL('../../eval/structural_cases.json',import.meta.url),'utf8').replaceAll('OPENAI_PREFIX_','sk'+'-').replaceAll('CLOUDFLARE_PREFIX_','cf'+'k_'));
test('structural exemptions and secret literal siblings across all WASM APIs',()=>{
 const failures=[];
 cases.forEach((c,id)=>{
  const raw=JSON.stringify({text:c.input});
  const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
  const outputs=[s.scrubTextChecked(c.input),s.scrubJson(raw).value.text,JSON.parse(new TextDecoder().decode(records)).text];
  outputs.forEach((out,api)=>{
   const ok=c.expected!==undefined?out===c.expected:!out.includes(c.secret)&&out.includes('[REDACTED]');
   if(!ok || s.scrubText(out)!==out) failures.push(`${id}/${c.family}/${api}`);
  });
  assert.deepEqual(s.scrubRecords(records).bytes,records);
 });
 assert.deepEqual(failures,[]);
});
test('JSON numeric identifiers survive and credentials redact',()=>{
 const input={session_id:57243,password:12,accessToken:-12.5,token:'M8zR4vK7nP2qW6xAq9'};
 const expected={session_id:57243,password:'[REDACTED]',accessToken:'[REDACTED]',token:'[REDACTED]'};
 assert.deepEqual(s.scrubJson(JSON.stringify(input)).value,expected);
 assert.deepEqual(JSON.parse(new TextDecoder().decode(s.scrubRecords(new TextEncoder().encode(JSON.stringify(input))).bytes)),expected);
});
