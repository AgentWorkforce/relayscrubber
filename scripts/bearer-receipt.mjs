// Replay invented Bearer cases on the downloaded package, without native-derived expectations.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const root=resolve(process.env.SCRUBBER_PACKAGE_PATH ?? 'js');
const {loadScrubber}=await import(pathToFileURL(`${root}/index.js`));
const artifact=JSON.parse(readFileSync(`${root}/generated/artifact.json`));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(`${root}/generated/relayscrubber_bg.wasm`)),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const cases=JSON.parse(readFileSync(new URL('../eval/bearer_cases.json',import.meta.url)));
const result={source:s.manifest.rulesetSourceSha256,apis:['checkedText','json','ndjsonFirst','ndjsonLast','secondPass']};
for(const family of ['positive','benign']) {
 const matches=Array(5).fill(0), failures=[];
 cases[family].forEach((item,id)=>{
  const [input,expected]=family==='positive'?item:[item,item];
  const raw=[{text:input},{text:'ordinary'},{text:input}].map(x=>JSON.stringify(x)).join('\n')+'\n';
  const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
  const parsed=new TextDecoder().decode(records).trimEnd().split('\n').map(x=>JSON.parse(x));
  const ok=[s.scrubTextChecked(input),s.scrubJson(JSON.stringify({text:input})).value.text,parsed[0].text,parsed[2].text,s.scrubText(expected)].map((out,api)=>{matches[api]+=Number(out===expected);return out===expected;});
  if(!ok.every(Boolean)) failures.push({id,matches:ok});
  if(parsed[1].text!=='ordinary'||Buffer.compare(Buffer.from(s.scrubRecords(records).bytes),Buffer.from(records))) throw Error('NDJSON preservation/idempotence mismatch');
 });
 result[family]={cases:cases[family].length,matches,failures};
}
console.log(JSON.stringify(result));
