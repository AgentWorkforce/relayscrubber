// Invented HTML attribute URL punctuation properties; expected bytes never use the scanner.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const s=await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),expectedManifest:artifact.manifest,expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
const spec=JSON.parse(readFileSync(new URL('../../eval/html_url_punctuation_property.json',import.meta.url)));
function encode(ch,style){
 const n=ch.charCodeAt(0), h=n.toString(16), H=h.toUpperCase(), name={':':'colon','/':'sol','?':'quest','&':'amp','=':'equals','@':'commat'}[ch];
 return {'literal':ch,'decimal':`&#${n};`,'decimal-bare':`&#${n}`,'decimal-zero':`&#000${n};`,'decimal-zero-bare':`&#000${n}`,'hex':`&#x${h};`,'hex-bare':`&#x${h}`,'HEX':`&#X${H};`,'HEX-bare':`&#X${H}`,'hex-zero':`&#x000${h};`,'hex-zero-bare':`&#x000${h}`,'named':`&${name};`,'NAMED':`&${name.toUpperCase()};`,'double-named':`&amp;${name};`,'triple-named':`&amp;amp;${name};`,'double-decimal':`&amp;#${n};`,'triple-hex':`&amp;amp;#x${H};`,'percent':`%${H}`,'double-percent':`%25${H}`,'percent-entity':[...`&#${n};`].map(c=>`%${c.charCodeAt(0).toString(16).toUpperCase()}`).join(''),'entity-percent':`&#37;${H}`,'mixed':`&amp;%23x000${h};`}[style];
}
function attribute(url,wrapper){return wrapper===0?`<a href="${url}">open</a>`:wrapper===1?`<img src='${url}'>`:`<a data-endpoint=${url}>open</a>`;}
const shared=JSON.parse(readFileSync(new URL('../../eval/query_separator_property.json',import.meta.url)));
assert.deepEqual(spec.keys,shared.keys,'use the complete sensitive-key catalog');
assert.equal(spec.keys.length,38);
assert.equal(spec.styles.length,22);
assert.equal(spec.coveringPrime,23);
const punctuation=[':','/','/','/','?','&','='];
assert.equal(spec.positions.length,punctuation.length);
const permutations=[];
for(let a=0;a<23;a++) for(let b=0;b<23;b++) permutations.push(punctuation.map((_,column)=>{const symbol=(a+column*b)%23;return symbol<spec.styles.length?symbol:0;}));
for(let left=0;left<7;left++) for(let right=left+1;right<7;right++){
 const seen=new Set(permutations.map(row=>row[left]*22+row[right]));
 assert.equal(seen.size,22*22,`missing punctuation pair ${left}/${right}`);
}
function url(indices,key){
 const p=punctuation.map((ch,i)=>encode(ch,spec.styles[indices[i]]));
 return `https${p[0]}${p[1]}${p[2]}media.example.invalid${p[3]}${p[4]}caption${p[6]}audit${p[5]}${key}${p[6]}${spec.secret}${p[5]}sort${p[6]}asc`;
}
const cases=[];
const positive=(value,wrapper)=>{const input=attribute(value,wrapper);cases.push([input,input.replace(spec.secret,'[REDACTED]')]);};
const benign=(value,wrapper)=>{const input=attribute(value,wrapper);cases.push([input,input]);};
// Preserve the historical 3,718 witnesses before the full 38-key matrix.
const legacy=JSON.parse(readFileSync(new URL('../../eval/html_url_punctuation_legacy_property.json',import.meta.url)));
assert.equal(legacy.secret,spec.secret);
for(const [id,style] of legacy.styles.entries()){
 for(const key of legacy.keys) for(let wrapper=0;wrapper<3;wrapper++){
  positive(`https://media.example.invalid/?caption=audit&amp;${key}${encode('=',style)}${legacy.secret}`,wrapper);
  for(const mixed of [false,true]){
   const p=[':','/','?','&','='].map((ch,j)=>encode(ch,mixed?legacy.styles[(id+j)%legacy.styles.length]:style));
   positive(`https${p[0]}${p[1]}${p[1]}media.example.invalid/${p[2]}caption${p[4]}audit${p[3]}${key}${p[4]}${legacy.secret}${p[3]}sort${p[4]}asc`,wrapper);
  }
 }
 for(const key of legacy.benignKeys) for(let wrapper=0;wrapper<3;wrapper++) benign(`https${encode(':',style)}${encode('/',style)}${encode('/',style)}media.example.invalid/${encode('?',style)}${key}${encode('=',style)}${legacy.secret}`,wrapper);
}
for(const opener of legacy.styles) for(const equal of legacy.styles) for(const key of ['sig','signature','X-Amz-Signature','token']) positive(`https://media.example.invalid/${encode('?',opener)}${key}${encode('=',equal)}${legacy.secret}`,0);
assert.equal(cases.length,3718,'retain every earlier punctuation witness');
for(const [styleId,style] of spec.styles.entries()){
 for(const key of spec.keys) for(let wrapper=0;wrapper<3;wrapper++){
  positive(`https://media.example.invalid/?caption=audit&amp;${key}${encode('=',style)}${spec.secret}`,wrapper);
  positive(url(Array(7).fill(styleId),key),wrapper);
 }
 for(let position=0;position<7;position++){
  const indices=Array(7).fill(0);indices[position]=styleId;
  for(const key of spec.keys) positive(url(indices,key),0);
 }
 for(const key of spec.benignKeys) for(let wrapper=0;wrapper<3;wrapper++) benign(url(Array(7).fill(styleId),key),wrapper);
}
for(const indices of permutations){
 for(const key of spec.keys) positive(url(indices,key),0);
 for(const key of spec.benignKeys) benign(url(indices,key),0);
}
assert.equal(cases.length,36473,'retain the full schemeful matrix');
for(const [styleId] of spec.styles.entries()){
 for(const [shape,positions] of [['relative',[4,5,6]],['root',[3,4,5,6]],['protocol',[1,2,3,4,5,6]],['query',[4,5,6]]]){
  const make=(indices,key)=>{
   const p=punctuation.map((ch,i)=>encode(ch,spec.styles[indices[i]]));
   const prefix=shape==='relative'?'download':shape==='root'?`${p[3]}download`:shape==='protocol'?`${p[1]}${p[2]}media.example.invalid${p[3]}download`:'';
   return `${prefix}${p[4]}caption${p[6]}audit${p[5]}${key}${p[6]}${spec.secret}${p[5]}sort${p[6]}asc`;
  };
  for(const key of spec.keys){
   for(let wrapper=0;wrapper<3;wrapper++) positive(make(Array(7).fill(styleId),key),wrapper);
   for(const position of positions){const indices=Array(7).fill(0);indices[position]=styleId;positive(make(indices,key),0);}
   positive(make(punctuation.map((_,i)=>(styleId+i)%spec.styles.length),key),0);
  }
  for(const key of spec.benignKeys) benign(make(Array(7).fill(styleId),key),0);
 }
 for(const mixed of [false,true]){
  const enc=(ch,i)=>encode(ch,spec.styles[mixed?(styleId+i)%spec.styles.length:styleId]);
  const url=`${enc('/',1)}${enc('/',2)}alice${enc(':',0)}SYNTH_ALPHA${enc('@',5)}media.example.invalid${enc('/',3)}download`;
  for(let wrapper=0;wrapper<3;wrapper++){const input=attribute(url,wrapper);cases.push([input,input.replace('SYNTH_ALPHA','[REDACTED]')]);}
 }
}
for(const prefix of ['./download','../download','?','#fragment?','https:\\media.example.invalid/download',' /download','\t../download','//media.example.invalid','//alice:SYNTH_ALPHA@media.example.invalid/download']){
 for(const name of ['href','src','action','formaction','data','poster','cite','background','srcset','data-endpoint']) for(let wrapper=0;wrapper<3;wrapper++){
  const value=`${prefix}?signature=${spec.secret}&sort=asc `;
  const input=wrapper===0?`<a ${name}="${value}">open</a>`:wrapper===1?`<a ${name}='${value}'>open</a>`:`<a ${name}=${value.trim()} >open</a>`;
  cases.push([input,input.replace(spec.secret,'[REDACTED]').replace('SYNTH_ALPHA','[REDACTED]')]);
 }
}
for(const input of ['//alice:SYNTH_ALPHA@media.example.invalid/download','<a href="https:\\alice:SYNTH_ALPHA@media.example.invalid/download">x</a>','<a href="alice:SYNTH_ALPHA@media.example.invalid">x</a>',`<meta http-equiv="refresh" content="0; url=../download&quest;signature&equals;${spec.secret}">`,`<img srcset="img.png 1x, ../download?signature=${spec.secret} 2x">`,'<a href="&sol;&sol;alice&colon;SYNTH_ALPHA&commat;media.example.invalid&sol;download">x</a>']) cases.push([input,input.replace(spec.secret,'[REDACTED]').replace('SYNTH_ALPHA','[REDACTED]')]);
for(const input of ['<a href="/docs?page=2">docs</a>','<img src="img.png?v=3">','<a href="#section">jump</a>','<a href="mailto:a@example.invalid">mail</a>','plain prose /path?x=y','// comment about /path?x=y',"const example = '/path?x=y';",'<!-- <a href="/path?signature=7e3b15c97e3b15c9">example</a> -->','<script>const example = \'<a href="/path?signature=7e3b15c97e3b15c9">\';</script>']) cases.push([input,input]);
assert.equal(cases.length,63906);
// Component-layer data dimension of the same property specification.
for(const escape of spec.componentEscapes) for(const style of spec.componentStyles){
 const data=({upper:escape,lower:escape.toLowerCase(),double:escape.replace('%','%25'),entity:escape.replace('%','&#37;'),'entity-double':escape.replace('%','&#37;25'),mix:`${escape}%252f&#37;3f%23%40%3a%3d+%25`,'percent-prefix':`%252525${escape.slice(1)}`})[style];
 const secret=`SYNTH${data}ALPHA`;
 for(const prefix of ['download','/download','//host/download','','https://host/download']){
  for(const key of spec.keys) for(const [question,equals,separator] of [['?','=','&'],['&quest;','&equals;','&amp;'],['&#63;','&#61;','&#38;']]) for(let wrapper=0;wrapper<3;wrapper++){
   const input=attribute(`${prefix}${question}${key}${equals}${secret}${separator}sort${equals}asc`,wrapper);
   cases.push([input,input.replace(secret,'[REDACTED]')]);
  }
  const input=`<a href="${prefix}?q=a${data}b&page=2">x</a>`; cases.push([input,input]);
 }
 for(const prefix of ['//','https://','','/','https:\\']) for(const [colon,at] of [[':','@'],['&colon;','&commat;'],['&#58;','&#64;']]){
  const input=`<a href="${prefix}alice${colon}${secret}${at}host/download">x</a>`;cases.push([input,input.replace(secret,'[REDACTED]')]);
 }
 const input=`//alice:${secret}@host`;cases.push([input,input.replace(secret,'[REDACTED]')]);
}
for(const secret of ['SYNTH%26sort=asc','SYNTH%2526sort%3Dasc','SYNTH&#37;26sort=asc','SYNTH%23fragment','SYNTH+ALPHA','SYNTH%253Bpage=2','SYNTH%25%26ALPHA','SYNTH#fragment']){
 const input=`<a href="/download?signature=${secret}&sort=asc">x</a>`;cases.push([input,input.replace(secret,'[REDACTED]')]);
}
for(const separator of ['&','&amp;','&#38;',';']){
 const input=`<a href="/download?signature=SYNTH%26ALPHA${separator}sort=asc">x</a>`;cases.push([input,input.replace('SYNTH%26ALPHA','[REDACTED]')]);
}
for(const input of [
 '<a href="//al%3Aice:SYNTH%2FALPHA@host/download">x</a>',
 '<a href="https://al%3Aice:SYNTH%3FALPHA@host/download">x</a>',
 '<a href=//alice:SYNTH%20ALPHA@host/download>x</a>',
 '<a href=/download?signature=SYNTH%20ALPHA&sort=asc>x</a>',
 '<a href=/download?signature=SYNTH%3EALPHA&sort=asc>x</a>',
 '<a href="//alice:SYNTH%40ALPHA@host/download?q=2">x</a>',
]){const secret=input.match(/SYNTH%[0-9A-F]{2}ALPHA/)[0];cases.push([input,input.replace(secret,'[REDACTED]')]);}
for(const input of ['<a href="//alice%3ASYNTH_ALPHA@host/download">x</a>','<a href="https://alice%3ASYNTH_ALPHA@host/download">x</a>','<a href="//alice%40alias@host/download">x</a>'])cases.push([input,input]);
assert.equal(cases.length,63906+84840);
for(const separator of ['&amp;','&#38;','&#x26;',';']){
 const input=`<a href="/download?signature=SYNTH${separator}ALPHA&sort=asc">x</a>`;
 cases.push([input,input.replace('SYNTH','[REDACTED]')]);
}
{
 const input='<a href=%22/download?signature=SYNTH%22ALPHA%22&sort=asc>x</a>';
 cases.push([input,input.replace('SYNTH%22ALPHA%22','[REDACTED]')]);
}
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

for(const count of [2048,16384]) test(`reserved component bounded all APIs/${count}`,()=>{
 const secret=`SYNTH${'%25252526%2f%3f%23%40%3a%3d+'.repeat(count)}ALPHA`;
 const input=`<a href="/download?signature=${secret}&sort=asc">x</a>`;
 const start=performance.now();check(input,input.replace(secret,'[REDACTED]'));assert.ok(performance.now()-start<10000);
});
