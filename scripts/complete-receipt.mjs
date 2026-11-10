// Replay invented complete-value regressions and the 34-row precision table
// against the supplied, hash-verified WASM package, never private session data.
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const root=resolve(process.env.SCRUBBER_PACKAGE_PATH??'js');
const artifact=JSON.parse(readFileSync(`${root}/generated/artifact.json`));
const {loadScrubber}=await import(pathToFileURL(`${root}/index.js`));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(`${root}/generated/relayscrubber_bg.wasm`)),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const expand=input=>input.replaceAll('OPENAI_PREFIX_','sk'+'-').replaceAll('CLOUDFLARE_PREFIX_','cf'+'k_');
const neutral=input=>input.replaceAll('sk'+'-','OPENAI_PREFIX_').replaceAll('cf'+'k_','CLOUDFLARE_PREFIX_');
const paths=input=>[s.scrubTextChecked(input),s.scrubJson(JSON.stringify({text:input})).value.text,JSON.parse(new TextDecoder().decode(s.scrubRecords(new TextEncoder().encode(JSON.stringify({text:input}))).bytes)).text];
const groups={};
for(const [id,c] of JSON.parse(readFileSync('eval/complete_cases.json')).entries()) {
 const out=paths(expand(c.input));
 const group=groups[c.family]??={cases:0,failures:[],secondPassChanges:[]}; group.cases++;
 const okay=out.map(o=>c.expected===undefined?!o.includes(c.secret)&&o.includes('[REDACTED]'):o===expand(c.expected));
 if(!okay.every(Boolean)) group.failures.push({id,validTextJsonRecords:okay});
 if(out.some(o=>paths(o).some(twice=>o!==twice))) group.secondPassChanges.push(id);
}
const numeric={cases:0,failures:[],secondPassChanges:0};
for(const n of ['123456','-246810','12.375','6.02e23','0']) for(const key of ['password','passwd','pin','secret','client_secret','token','accessToken','refreshToken','api_key']) {
 const input=`{"${key}":${n},"session_id":57243,"pid":42,"port":8080,"count":0}`;
 const expected=JSON.stringify(Object.fromEntries(Object.entries({[key]:'[REDACTED]',session_id:57243,pid:42,port:8080,count:0}).sort(([a],[b])=>a.localeCompare(b))));
 const canonical=v=>JSON.stringify(Object.fromEntries(Object.entries(v).sort(([a],[b])=>a.localeCompare(b))));
 const clean=s.scrubJson(input);
 const records=s.scrubRecords(new TextEncoder().encode(input));
 const text=s.scrubTextChecked(input);
 let textValue;try{textValue=canonical(JSON.parse(text));}catch{textValue=null;}
 const valid=[textValue===expected,canonical(clean.value)===expected&&clean.redactionCount===1,canonical(JSON.parse(new TextDecoder().decode(records.bytes)))===expected&&records.redactionCount===1];
 if(!valid.every(Boolean)) numeric.failures.push({key,number:n,validTextJsonRecords:valid});
 numeric.cases++;
 numeric.secondPassChanges+=Number(s.scrubTextChecked(text)!==text||canonical(s.scrubJson(JSON.stringify(clean.value)).value)!==canonical(clean.value)||Buffer.compare(s.scrubRecords(records.bytes).bytes,records.bytes)!==0);
}
const rows=JSON.parse(readFileSync('docs/results/structural-precision.json')).reaudit2Reproductions.map(row=>({family:row.family,input:row.input,outputsTextJsonRecords:paths(expand(row.input)).map(neutral)}));
console.log(JSON.stringify({source:s.manifest.rulesetSourceSha256,groups,numeric,structuralRows:rows}));
