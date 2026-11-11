// Invented-only replay against a supplied, hash-verified WASM package.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const root=resolve(process.env.SCRUBBER_PACKAGE_PATH??'js');
const artifact=JSON.parse(readFileSync(`${root}/generated/artifact.json`));
const {loadScrubber}=await import(pathToFileURL(`${root}/index.js`));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(`${root}/generated/relayscrubber_bg.wasm`)),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const expand=s=>s.replaceAll('OPENAI_PREFIX_','sk'+'-');
const paths=input=>[s.scrubTextChecked(input),s.scrubJson(JSON.stringify({text:input})).value.text,JSON.parse(new TextDecoder().decode(s.scrubRecords(new TextEncoder().encode(JSON.stringify({text:input}))).bytes)).text];
const rows=JSON.parse(readFileSync('eval/precision_10_1_cases.json')).map((c,id)=>{
 const input=expand(c.input), outputs=paths(input);
 return {id,family:c.family,reaudit3:c.reaudit3??null,input,outputsTextJsonRecords:outputs,validTextJsonRecords:outputs.map(out=>c.expected===undefined?!out.includes(c.secret)&&out.includes('[REDACTED]'):out===expand(c.expected)),secondPassChanges:outputs.map(out=>paths(out).some(twice=>out!==twice))};
});
console.log(JSON.stringify({manifest:s.manifest,rows}));
