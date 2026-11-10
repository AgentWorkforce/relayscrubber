// Counts synthetic fixture behavior on the actual pinned package.
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../js/index.js';
const artifact=JSON.parse(readFileSync(new URL('../js/generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../js/generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const cases=JSON.parse(readFileSync(new URL('../eval/session_cases.json',import.meta.url),'utf8').replaceAll('STRIPE_LIVE_PREFIX_','sk'+'_live_'));
const paths=input=>[s.scrubText(input),s.scrubJson(JSON.stringify({text:input})).value.text,JSON.parse(new TextDecoder().decode(s.scrubRecords(new TextEncoder().encode(JSON.stringify({text:input}))).bytes)).text];
const families=Object.entries(cases.benign).map(([name,inputs])=>{const same=[0,0,0];const perCase=inputs.map(input=>paths(input).map((out,api)=>{const ok=out===input;same[api]+=Number(ok);return ok;}));return {name,cases:inputs.length,unchangedTextJsonRecords:same,perCase};});
const positive=[0,0,0];
for(const [input,secret] of cases.positive) paths(input).forEach((out,api)=>{positive[api]+=Number(!out.includes(secret)&&out.includes('[REDACTED]')&&s.scrubText(out)===out);});
console.log(JSON.stringify({source:s.manifest.rulesetSourceSha256,families,positiveCases:cases.positive.length,redactedTextJsonRecords:positive}));
