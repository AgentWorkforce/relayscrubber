// Synthetic checks against the actual pinned package, independent of native output.
import { readFileSync } from 'node:fs';
import { loadScrubber } from '../js/index.js';
const artifact = JSON.parse(readFileSync(new URL('../js/generated/artifact.json', import.meta.url)));
const scrubber = await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../js/generated/relayscrubber_bg.wasm', import.meta.url))), expectedManifest:artifact.manifest, expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const cases = JSON.parse(readFileSync(new URL('../eval/family_cases.json', import.meta.url), 'utf8').replaceAll('STRIPE_LIVE_PREFIX_', 'sk' + '_live_'));
const families = Object.entries(cases.benign).map(([name, inputs]) => {
 const same = [0,0,0];
 for (const input of inputs) {
  const raw = JSON.stringify({text:input});
  same[0] += Number(scrubber.scrubText(input) === input);
  same[1] += Number(scrubber.scrubJson(raw).value.text === input);
  same[2] += Number(JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(raw)).bytes)).text === input);
 }
 return {name,cases:inputs.length,unchangedTextJsonRecords:same};
});
console.log(JSON.stringify({source:scrubber.manifest.rulesetSourceSha256,families}));
