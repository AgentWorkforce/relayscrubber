import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const scrubber=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
function verify(input,expected) {
 const raw=JSON.stringify({text:input});
 return [scrubber.scrubText(input),scrubber.scrubJson(raw).value.text,JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(raw)).bytes)).text,scrubber.scrubText(expected)].every(x=>x===expected);
}
test('exact reviewer matrix across every pinned WASM API',()=>{
 const cases=JSON.parse(readFileSync(new URL('../../eval/exact_packet_cases.json',import.meta.url)));
 assert.deepEqual(cases.flatMap(([input,expected],i)=>verify(input,expected)?[]:[i]),[]);
});
test('invented residuals stay unchanged while positive controls redact',()=>{
 const cases=JSON.parse(readFileSync(new URL('../../eval/residual_cases.json',import.meta.url),'utf8').replaceAll('OPENAI_PREFIX_','sk'+'-proj-').replaceAll('GITHUB_PREFIX_','gh'+'p_').replaceAll('AWS_PREFIX_','AK'+'IA').replaceAll('SLACK_PREFIX_','xo'+'xb-').replaceAll('STRIPE_PREFIX_','sk'+'_live_'));
 assert.deepEqual(cases.benign.flatMap((input,i)=>verify(input,input)?[]:[i]),[]);
 for(const {shape,input} of cases.positive){const output=scrubber.scrubText(input);assert.notEqual(input,output,shape);assert.ok(verify(input,output),shape);}
});
test('nested credentials override a public selector in structured WASM',()=>{
 const value={idempotency_key:{aws:{key:'SYNTH_ALPHA'},ordinary:{key:'public-replay-42'},password:'SYNTH_BETA'}};
 assert.deepEqual(scrubber.scrubJson(JSON.stringify(value)).value,{idempotency_key:{aws:{key:'[REDACTED]'},ordinary:{key:'public-replay-42'},password:'[REDACTED]'}});
});

test('final reviewer syntax and context ruling across all APIs',()=>{
 const cases=JSON.parse(readFileSync(new URL('../../eval/ruling_cases.json',import.meta.url)));
 assert.deepEqual(cases.flatMap(([input,expected],i)=>verify(input,expected)?[]:[i]),[]);
});
