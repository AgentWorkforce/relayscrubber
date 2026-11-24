import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';

// Mirror of tests/desktop_false_positives.rs through the WASM artifact.
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const scrubber=await loadScrubber({
  bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),
  expectedManifest:artifact.manifest,
  expectedWasmSha256:artifact.files['relayscrubber_bg.wasm'],
});
const fixture=JSON.parse(readFileSync(new URL('../../eval/desktop_false_positive_cases.json',import.meta.url)));
const R='[REDACTED]';

function outputs(input){
  const raw=JSON.stringify({text:input});
  const records=scrubber.scrubRecords(new TextEncoder().encode(raw+'\n')).bytes;
  return [
    ['checked',scrubber.scrubTextChecked(input)],
    ['text',scrubber.scrubText(input)],
    ['long',scrubber.scrubLong(input)],
    ['json',scrubber.scrubJson(raw).value.text],
    ['records',JSON.parse(new TextDecoder().decode(records)).text],
  ];
}

function check(id,input,accept){
  const failures=[];
  const all=outputs(input);
  for(const [api,output] of all){
    if(output!==all[0][1]) failures.push(`${id}/${api}: parity ${JSON.stringify(output)}`);
    const why=accept(output);
    if(why) failures.push(`${id}/${api}: ${JSON.stringify(input)} -> ${JSON.stringify(output)}: ${why}`);
    if(scrubber.scrubText(output)!==output) failures.push(`${id}/${api}: second pass changed`);
  }
  return failures;
}
const preserved=input=>output=>output===input?null:'type position must be byte identical';
const finish=failures=>assert.deepEqual(failures.slice(0,40),[]);

test('recall controls redact on every API',()=>{
  finish(fixture.recall.flatMap(c=>check(c.id,c.input,o=>
    o.includes(c.secret)?`secret ${JSON.stringify(c.secret)} survived`:o.includes(R)?null:'no marker')));
});

test('precision controls already preserved stay preserved',()=>{
  finish(fixture.precision.filter(c=>c.alpha10===c.input).flatMap(c=>check(c.id,c.input,preserved(c.input))));
});

test('type positions after Key members are preserved',()=>{
  finish(fixture.precision.filter(c=>c.alpha10!==c.input).flatMap(c=>check(c.id,c.input,preserved(c.input))));
});

test('prose is never replaced wholesale',()=>{
  finish(fixture.whole_body.flatMap(c=>check(c.id,c.input,o=>
    o===R?'whole body replaced by one marker':!o.startsWith(c.prefix)?'benign prefix lost':o.includes(R)?null:'credential cue no longer redacts')));
});
