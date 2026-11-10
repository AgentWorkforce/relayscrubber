// Invented HTML attribute URL punctuation properties; expected bytes never use the scanner.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const spec=JSON.parse(readFileSync(new URL('../../eval/html_url_punctuation_property.json',import.meta.url)));
function encode(ch,style){
 const n=ch.charCodeAt(0), h=n.toString(16), H=h.toUpperCase(), name={':':'colon','/':'sol','?':'quest','&':'amp','=':'equals'}[ch];
 return {'literal':ch,'decimal':`&#${n};`,'decimal-bare':`&#${n}`,'decimal-zero':`&#000${n};`,'decimal-zero-bare':`&#000${n}`,'hex':`&#x${h};`,'hex-bare':`&#x${h}`,'HEX':`&#X${H};`,'HEX-bare':`&#X${H}`,'hex-zero':`&#x000${h};`,'hex-zero-bare':`&#x000${h}`,'named':`&${name};`,'NAMED':`&${name.toUpperCase()};`,'double-named':`&amp;${name};`,'triple-named':`&amp;amp;${name};`,'double-decimal':`&amp;#${n};`,'triple-hex':`&amp;amp;#x${H};`,'percent':`%${H}`,'double-percent':`%25${H}`,'percent-entity':[...`&#${n};`].map(c=>`%${c.charCodeAt(0).toString(16).toUpperCase()}`).join(''),'entity-percent':`&#37;${H}`,'mixed':`&amp;%23x000${h};`}[style];
}
function attribute(url,wrapper){return wrapper===0?`<a href="${url}">open</a>`:wrapper===1?`<img src='${url}'>`:`<a data-endpoint=${url}>open</a>`;}
const cases=[];
const positive=(url,wrapper)=>{const input=attribute(url,wrapper);cases.push([input,input.replace(spec.secret,'[REDACTED]')]);};
for(const [id,style] of spec.styles.entries()){
 for(const key of spec.keys) for(let wrapper=0;wrapper<3;wrapper++){
  positive(`https://media.example.invalid/?caption=audit&amp;${key}${encode('=',style)}${spec.secret}`,wrapper);
  for(const mixed of [false,true]){
   const p=[':','/','?','&','='].map((ch,i)=>encode(ch,mixed?spec.styles[(id+i)%spec.styles.length]:style));
   positive(`https${p[0]}${p[1]}${p[1]}media.example.invalid/${p[2]}caption${p[4]}audit${p[3]}${key}${p[4]}${spec.secret}${p[3]}sort${p[4]}asc`,wrapper);
  }
 }
 for(const key of spec.benignKeys) for(let wrapper=0;wrapper<3;wrapper++){
  const input=attribute(`https${encode(':',style)}${encode('/',style)}${encode('/',style)}media.example.invalid/${encode('?',style)}${key}${encode('=',style)}${spec.secret}`,wrapper);
  cases.push([input,input]);
 }
}
for(const opener of spec.styles) for(const equal of spec.styles) for(const key of spec.keys.slice(0,4)) positive(`https://media.example.invalid/${encode('?',opener)}${key}${encode('=',equal)}${spec.secret}`,0);
function check(input,expected){
 const value={text:input}, raw=JSON.stringify(value), json=s.scrubJson(raw).value;
 const records=s.scrubRecords(new TextEncoder().encode(raw)).bytes;
 const outputs=[s.scrubTextChecked(input),json.text,JSON.parse(new TextDecoder().decode(records)).text];
 outputs.forEach(out=>{assert.equal(out,expected);assert.equal(s.scrubText(out),out);});
 assert.deepEqual(s.scrubJson(JSON.stringify(json)).value,json);
 assert.deepEqual(s.scrubRecords(records).bytes,records);
}
for(let start=0;start<cases.length;start+=256) test(`HTML URL punctuation all APIs cases ${start}-${Math.min(start+256,cases.length)}`,()=>{
 const failures=[];
 cases.slice(start,start+256).forEach(([input,expected],i)=>{try{check(input,expected);}catch{failures.push(start+i);}});
 assert.deepEqual(failures,[]);
});
for(const count of [2048,16384]){
 const secret='7e3b15c97e3b15c9';
 const long=[
  ['numeric equals zeros',`<a href="https://media.example.invalid/&#63;signature&#${'0'.repeat(count)}61${secret}">open</a>`],
  ['nested named equals',`<a href="https&colon;&sol;&sol;media.example.invalid/&quest;signature&${'amp;'.repeat(count)}equals;${secret}">open</a>`],
  ['many HTML attributes',`${'<a href="https&colon;&sol;&sol;media.example.invalid/&quest;sort&equals;asc">open</a>'.repeat(count)}<a href="https&colon;&sol;&sol;media.example.invalid/&quest;signature&equals;${secret}">open</a>`],
 ];
 for(const [family,input] of long) test(`HTML punctuation bounded ${family}/${count}`,()=>{const start=performance.now();check(input,input.replace(secret,'[REDACTED]'));assert.ok(performance.now()-start<10000);});
}
