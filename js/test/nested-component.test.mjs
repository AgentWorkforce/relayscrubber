import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const a=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:a.manifest,expectedWasmSha256:a.files['relayscrubber_bg.wasm']});
function check(input,expected){
 const json=s.scrubJson(JSON.stringify({text:input})).value;
 const records=s.scrubRecords(new TextEncoder().encode(JSON.stringify({text:input}))).bytes;
 for(const output of [s.scrubTextChecked(input),json.text,JSON.parse(new TextDecoder().decode(records)).text]){assert.equal(output,expected);assert.equal(s.scrubText(output),output);}
 assert.deepEqual(s.scrubJson(JSON.stringify(json)).value,json);assert.deepEqual(s.scrubRecords(records).bytes,records);
}
test('each nested public value opens only one percent layer',()=>{
 for(const [input,secret] of [
  ['https://outer.invalid/?caption=audit%26signature=SYNTH%2526ALPHA%26sort=asc','SYNTH%2526ALPHA'],
  ['https://outer.invalid/?url=https%3A%2F%2Falice%3ASYNTH%252FALPHA%40host','SYNTH%252FALPHA'],
  ['redirect_uri=https%3A%2F%2Fhost%2F%3Fsignature%3DSYNTH%2526ALPHA%26sort%3Dasc','SYNTH%2526ALPHA'],
  ['%2F%2Falice%3ASYNTH%252FALPHA%40host','SYNTH%252FALPHA'],
 ]) check(input,input.replace(secret,'[REDACTED]'));

 for(const value of ['download%3Fsignature%3DSYNTH%2526ALPHA%26sort%3Dasc','%3Fsignature%3DSYNTH%2526ALPHA%26sort%3Dasc']){
  const input=`<a href="${value}">x</a>`;check(input,input.replace('SYNTH%2526ALPHA','[REDACTED]'));
 }
 for(const [inner,secret] of [
  ['audit%26signature=SYNTH%2526ALPHA%26sort=asc','SYNTH%2526ALPHA'],
  ['https://host/download?caption=audit%26signature=SYNTH%2526ALPHA%26sort=asc','SYNTH%2526ALPHA'],
  ['signature%3DSYNTH%2526ALPHA','SYNTH%2526ALPHA'],
  ['%2F%2Falice%3ASYNTH%252FALPHA%40host','SYNTH%252FALPHA'],
 ]){const input=`<a href="/outer?caption=${inner}&page=2">x</a>`;check(input,input.replace(secret,'[REDACTED]'));}
 for(const [raw,sensitive] of [['?signature=SYNTH%26ALPHA&sort=asc',true],['?q=a%26b&page=2',false]]){
  let inner=raw;for(let n=0;n<6;n++)inner=encodeURIComponent(inner);
  const input=`<a href="/outer?url=${inner}&page=2">x</a>`;check(input,sensitive?input.replace(inner,'[REDACTED]'):input);
 }
 for(const prefix of ['//','https://','','postgres://','mysql://','redis://']){
  const secret='SYNTH%26ALPHA=TAIL',inner=`${prefix}al%3Aice:${secret}@host/download`;
  const input=`<a href="/outer?url=${encodeURIComponent(inner)}&page=2">x</a>`;check(input,input.replace(encodeURIComponent(secret),'[REDACTED]'));
 }
 for(const layers of [2,3]){
  let inner='?signature=SYNTH%26ALPHA&sort=asc',secret='SYNTH%26ALPHA';
  for(let n=0;n<layers;n++){inner=encodeURIComponent(inner);secret=encodeURIComponent(secret);}
  const input=`<a href="/outer?caption=${inner}&page=2">x</a>`;check(input,input.replace(secret,'[REDACTED]'));
 }
});
for(const count of [2048,16384]) test(`nested prefix scans stay bounded/${count}`,()=>{
 for(const padding of ['ordinary','ordinary%ZZ']){
  const inner=`${'/?url='.repeat(count)}${padding}&signature=SYNTH%26ALPHA&sort=asc`;
  const input=`<a href="/outer?url=${encodeURIComponent(inner)}&page=2">x</a>`;
  const start=performance.now();check(input,input.replace('SYNTH%2526ALPHA','[REDACTED]'));assert.ok(performance.now()-start<10000);
 }
});
