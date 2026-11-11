// Synthetic packet/ruling evidence from the actual WASM package, across all APIs.
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
const packageRoot=resolve(process.env.SCRUBBER_PACKAGE_PATH ?? 'js');
const fixtureRoot=resolve(process.env.PACKET_FIXTURES_PATH ?? 'eval');
const {loadScrubber}=await import(pathToFileURL(`${packageRoot}/index.js`));
const artifact=JSON.parse(readFileSync(`${packageRoot}/generated/artifact.json`));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(`${packageRoot}/generated/relayscrubber_bg.wasm`)),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const read=name=>JSON.parse(readFileSync(`${fixtureRoot}/${name}`,'utf8').replaceAll('OPENAI_PREFIX_','sk'+'-proj-').replaceAll('GITHUB_PREFIX_','gh'+'p_').replaceAll('AWS_PREFIX_','AK'+'IA').replaceAll('SLACK_PREFIX_','xo'+'xb-').replaceAll('STRIPE_PREFIX_','sk'+'_live_'));
const paths=input=>[s.scrubText(input),s.scrubJson(JSON.stringify({text:input})).value.text,JSON.parse(new TextDecoder().decode(s.scrubRecords(new TextEncoder().encode(JSON.stringify({text:input}))).bytes)).text];
const group=cases=>({cases:cases.length,failures:cases.flatMap(([input,expected],id)=>{const matches=paths(input).map(out=>out===expected),second=paths(expected).map(out=>out===expected);return [...matches,...second].every(Boolean)?[]:[{id,matchesTextJsonRecords:matches,secondPassTextJsonRecords:second}];})});
const residual=read('residual_cases.json');
// Retain legacy row positions, including the explicitly corrected sensitive row.
const residualControls=residual.benign.map(c=>typeof c==='string'?[c,c]:[c.input,c.expected]);
const value={idempotency_key:{aws:{key:'SYNTH_ALPHA'},ordinary:{key:'public-replay-42'},password:'SYNTH_BETA'}};
const expected={idempotency_key:{aws:{key:'[REDACTED]'},ordinary:{key:'public-replay-42'},password:'[REDACTED]'}};
const same=value=>JSON.stringify(value)===JSON.stringify(expected);
console.log(JSON.stringify({schema:1,source:s.manifest.rulesetSourceSha256,exactPacket:group(read('exact_packet_cases.json')),finalRuling:group(read('ruling_cases.json')),residualBenign:group(residualControls),residualPositive:{cases:residual.positive.length,failures:residual.positive.flatMap(({input},id)=>{const matches=paths(input).map(out=>out!==input&&out.includes('[REDACTED]')&&s.scrubText(out)===out);return matches.every(Boolean)?[]:[{id,redactedTextJsonRecords:matches}];})},nestedStructuredJsonRecords:[same(s.scrubJson(JSON.stringify(value)).value),same(JSON.parse(new TextDecoder().decode(s.scrubRecords(new TextEncoder().encode(JSON.stringify(value))).bytes)))]}));
