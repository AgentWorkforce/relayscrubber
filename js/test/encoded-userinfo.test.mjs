import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const a=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:a.manifest,expectedWasmSha256:a.files['relayscrubber_bg.wasm']});
function check(input,expected){
 const value={text:input},json=s.scrubJson(JSON.stringify(value)).value;
 const records=s.scrubRecords(new TextEncoder().encode(JSON.stringify(value))).bytes;
 for(const output of [s.scrubTextChecked(input),json.text,JSON.parse(new TextDecoder().decode(records)).text]){assert.equal(output,expected);assert.equal(s.scrubText(output),output);}
 assert.deepEqual(s.scrubJson(JSON.stringify(json)).value,json);assert.deepEqual(s.scrubRecords(records).bytes,records);
}
test('encoded userinfo reviewer witnesses preserve only the password span',()=>{
 for(const [input,secret] of [
  ['%2F%2Falice%3ASYNTH%2FALPHA%40host%2Fdownload','SYNTH%2FALPHA'],
  ['%2F%2Falice%3ASYNTH%3FALPHA%40host%2Fdownload','SYNTH%3FALPHA'],
  ['%2F%2Falice%3ASYNTH%23ALPHA%40host%2Fdownload','SYNTH%23ALPHA'],
  ['%252F%252Falice%253ASYNTH%252FALPHA%2540host%252Fdownload','SYNTH%252FALPHA'],
  ['&percnt;2F&percnt;2Falice&percnt;3ASYNTH&percnt;2FALPHA&percnt;40host','SYNTH&percnt;2FALPHA'],
 ])check(input,input.replace(secret,'[REDACTED]'));
 for(const input of ['<a href="password=SYNTH@host">','<a href="//password=SYNTH@host">'])check(input,input.replace('SYNTH@host','[REDACTED]'));
 for(const sensitive of [true,false]){
  let uri=sensitive?'//alice:SYNTH%2FALPHA@host/download':'//alice@host/download';
  for(let depth=0;depth<5;depth++)uri=encodeURIComponent(uri);
  const input=`<a href="/outer?url=${uri}&page=2">x</a>`;check(input,sensitive?input.replace(uri,'[REDACTED]'):input);
 }
});
