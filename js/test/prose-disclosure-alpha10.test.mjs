import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';

// Mirror of tests/prose_disclosure_alpha10.rs through the WASM artifact.
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const scrubber=await loadScrubber({
  bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),
  expectedManifest:artifact.manifest,
  expectedWasmSha256:artifact.files['relayscrubber_bg.wasm'],
});
const fixtures=JSON.parse(readFileSync(new URL('../../eval/prose_disclosure_alpha10_cases.json',import.meta.url)));
const R='[REDACTED]';
const PUBLIC='QUALIFICATION_PUBLIC_CONTEXT';
const NOUNS=['password','passcode','passphrase','passwd','pwd','pw','pass code','pass phrase'];
const WORD_CUES=['is','was','is now','set to','is set to','was set to'];

function run(cases){
  const failures=[];
  for(const entry of cases){
    const raw=JSON.stringify({text:entry.input});
    const records=scrubber.scrubRecords(new TextEncoder().encode(raw)).bytes;
    const outputs=[
      scrubber.scrubTextChecked(entry.input),
      scrubber.scrubText(entry.input),
      scrubber.scrubLong(entry.input),
      scrubber.scrubJson(raw).value.text,
      JSON.parse(new TextDecoder().decode(records)).text,
    ];
    outputs.forEach((output,api)=>{
      if(output!==entry.expected||scrubber.scrubText(output)!==output) failures.push(`${entry.id}/${api}: ${JSON.stringify(entry.input)} -> ${JSON.stringify(output)}`);
    });
    if(new TextDecoder().decode(scrubber.scrubRecords(records).bytes)!==new TextDecoder().decode(records)) failures.push(`${entry.id}/records-second-pass`);
  }
  return failures;
}

const cueMatrix=[];
{
  const layouts=[];
  for(const cue of WORD_CUES) for(const gap of [' ','  ','\t']) layouts.push([`${gap}${cue.replaceAll(' ',gap)}${gap}`,cue]);
  for(const layout of [': ',':',' : ',':\t',' = ','=','= ',' =']) layouts.push([layout,layout.trim()]);
  const values=[['','Q'],['','orchid'],['','velvet river lantern'],['"','orchid lamp'],["'",'orchid lamp'],['`','orchid lamp'],['','松🔐éж']];
  for(const noun of NOUNS) for(const determiner of ['','my ']) for(const [layout,cue] of layouts) for(const [quote,value] of values){
    const left=`${PUBLIC}\n${determiner}${noun}${layout}${quote}`;
    cueMatrix.push({id:`cue ${determiner}${noun} ${JSON.stringify(layout)} ${quote}${value}${quote}`,input:left+value+quote,expected:left+R+quote});
  }
}
test('every noun, cue and layout redacts the whole value',()=>{
  assert.equal(cueMatrix.length,8*2*26*7);
  assert.deepEqual(run(cueMatrix),[]);
});

const escapeMatrix=[];
for(const noun of NOUNS) for(const cue of WORD_CUES) for(const quote of ['"',"'",'`']) for(let slashes=1;slashes<=4;slashes++){
  const left=`${PUBLIC}\nmy ${noun} ${cue} ${quote}`;
  escapeMatrix.push({
    id:`escape ${noun} ${cue} ${quote} ${slashes}`,
    input:`${left}abc${'\\'.repeat(slashes)}${quote}def${quote}`,
    expected:slashes%2?`${left}${R}${quote}`:`${left}${R}${quote}def${quote}`,
  });
}
test('an escaped close quote does not end the value',()=>{
  assert.equal(escapeMatrix.length,8*6*3*4);
  assert.deepEqual(run(escapeMatrix),[]);
});
test('an escaped quote keeps the unmatched and bounded rules',()=>{
  const long='x'.repeat(1100);
  assert.deepEqual(run([
    {id:'bound 0',input:'my password is "abc\\"def',expected:`my password is ${R}`},
    {id:'bound 1',input:'my password is "abc\\"def\nnext line',expected:`my password is ${R}\nnext line`},
    {id:'bound 2',input:`my password is "abc\\"${long}\n"tail`,expected:`my password is ${R}\n"tail`},
  ]),[]);
});

const SPACES=['\t',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ','　'];
const BREAKS=['\n','\r\n','\r','\u000b','\u000c','\u0085',' ',' '];
const separatorMatrix=[];
for(const s of SPACES) for(const template of ['my{s}password{s}is{s}','my{s}pass{s}code{s}is{s}','my{s}pass{s}phrase{s}was{s}','pass{s}phrase:{s}','pass{s}code{s}={s}','pw{s}is{s}set{s}to{s}']){
  const left=template.replaceAll('{s}',s);
  separatorMatrix.push({id:`space U+${s.codePointAt(0).toString(16)} ${template}`,input:`${PUBLIC}\n${left}velvet${s}river`,expected:`${PUBLIC}\n${left}${R}`});
}
for(const b of BREAKS) for(const template of ['my pass{b}code is ','my pass{b}phrase is ','my password{b}is ','my password is{b}','my{b}password is ']){
  const left=template.replaceAll('{b}',b);
  separatorMatrix.push({id:`break ${JSON.stringify(b)} ${template}`,input:`${PUBLIC}\n${left}orchid`,expected:`${PUBLIC}\n${left}${R}`});
}
test('every whitespace separator and line break joins the disclosure',()=>{
  assert.equal(separatorMatrix.length,18*6+8*5);
  assert.deepEqual(run(separatorMatrix),[]);
});

const ENCODED=['&#32;','&#032;','&#32','&#x20;','&#X20;','&#x020;','&#9;','&#xA0;','&#160;','&nbsp;','&nbsp','&NonBreakingSpace;','&ensp;','&emsp;','&thinsp;','&hairsp;','&MediumSpace;','&#x1680;','&#8287;','%C2%A0','%E1%9A%80','%E2%81%9F',
  '%20','%u0020','%u205F','\\u0020','\\u00a0','\\u205f','\\u{1680}','\\x20'];
const encodedMatrix=[];
for(const e of ENCODED) for(const template of ['my{s}password{s}is{s}','my{s}pass{s}code{s}is{s}','my pass{s}phrase{s}was{s}','pass{s}phrase:{s}','pass{s}code{s}={s}']){
  const left=template.replaceAll('{s}',e);
  encodedMatrix.push({id:`encoded ${e} ${template}`,input:`${PUBLIC}\n${left}orchid`,expected:`${PUBLIC}\n${left}${R}`});
}
for(const b of ['&#10;','&#xA;','&NewLine;','&#13;','&#x2028;','%E2%80%A8','\\u2028']) for(const template of ['my pass{b}code is ','my pass{b}phrase is ']){
  const left=template.replaceAll('{b}',b);
  encodedMatrix.push({id:`encoded break ${b} ${template}`,input:`${PUBLIC}\n${left}orchid`,expected:`${PUBLIC}\n${left}${R}`});
}
test('encoded separators join the disclosure',()=>{
  assert.equal(encodedMatrix.length,30*5+7*2);
  assert.deepEqual(run(encodedMatrix),[]);
});

const CUES=[':',' :',': ',' : ','=',' = ','= ',' ='];
const PREFIXES=['my ','our ','your ','the ','The ','its ','my new ','The new ','the old ','The wifi ',
  'Use this ','Please use ','Enter your ','Use the new ','Here is the ','and my ','and the ','but your ','And the new ',
  '- ','* ','- my ','1. ','* the new ','note: ','Note: my ','FYI: ','note: the new ','x y ','Reset ','admin ',
  'We discussed ','Here is my ','or the '];
const prefixMatrix=[];
{
  const values=[['','Q'],['','zq9Secret'],['','velvet river lantern'],['','correct horse battery'],['','required and then'],
    ['','see vault later'],['','example and then'],['','none and then'],['','orchid7 and tulip'],['','wrong or right'],
    ['','valid but long'],['"','velvet river'],["'",'velvet river'],['`','velvet river'],['','pässwört ünï'],['','密码 秘密']];
  for(const noun of NOUNS) for(const cue of CUES) for(const [quote,value] of values) for(const prefix of PREFIXES){
    const left=`${PUBLIC}\n${prefix}${noun}${cue}${quote}`;
    prefixMatrix.push({id:`prefix ${JSON.stringify(prefix)} ${noun}${JSON.stringify(cue)} ${quote}${value}${quote}`,input:left+value+quote,expected:left+R+quote});
  }
}
test('a prefix never redacts less than the bare cue',()=>{
  assert.equal(prefixMatrix.length,8*8*16*34);
  assert.deepEqual(run(prefixMatrix),[]);
});
test('a prefix redacts a value with a close bracket or separator whole',()=>{
  const cases=[];
  for(const noun of NOUNS) for(const cue of CUES) for(const value of ['ab)cd','x]y z','q}r','6)K','h{E]MT-a','f(x) y','ab&cd=ef','k;host=y'])
    for(const prefix of PREFIXES){
      const left=`${PUBLIC}\n${prefix}${noun}${cue}`;
      cases.push({id:`bracket ${JSON.stringify(prefix)} ${noun}${JSON.stringify(cue)} ${value}`,input:left+value,expected:left+R});
    }
  assert.equal(cases.length,8*8*8*34);
  for(const [input,expected] of [['(my password: abc) see docs','(my password: [REDACTED]) see docs'],
    ['f(the password=abc) more','f(the password=[REDACTED]) more'],['[my pw: x] ok','[my pw: [REDACTED]] ok'],
    ['call(note password: abc) end','call(note password: [REDACTED]) end'],
    ['host=db;my password=abc;user=x','host=db;my password=[REDACTED];user=x'],['?a=1&my pw=abc&b=2','?a=1&my pw=[REDACTED]&b=2']])
    cases.push({id:`enclosed ${JSON.stringify(input)}`,input:`${PUBLIC}\n${input}`,expected:`${PUBLIC}\n${expected}`});
  assert.deepEqual(run(cases),[]);
});
test('a prefix keeps the bare cue outcome for benign controls',()=>{
  const cases=[];
  for(const noun of NOUNS) for(const cue of CUES) for(const value of ['string','$PASSWORD','${{ secrets.PW }}','none','null']){
    const bareInput=`${PUBLIC}\n${noun}${cue}${value}`;
    const bare=scrubber.scrubText(bareInput);
    const tail=bare.slice(PUBLIC.length+1);
    for(const prefix of PREFIXES){
      const input=`${PUBLIC}\n${prefix}${noun}${cue}${value}`;
      const redacted=`${PUBLIC}\n${prefix}${noun}${cue}${R}`;
      const expected=bare!==bareInput?`${PUBLIC}\n${prefix}${tail}`:scrubber.scrubText(input)===redacted?redacted:input;
      cases.push({id:`benign ${JSON.stringify(prefix)} ${noun}${JSON.stringify(cue)} ${value}`,input,expected});
    }
  }
  assert.equal(cases.length,8*8*5*34);
  assert.deepEqual(run(cases),[]);
});

test('named lead examples, benign controls and JSON-escaped quotes agree on every hosted API',()=>{
  for(const kind of ['positive','benign']) assert.ok(fixtures.some(c=>c.kind===kind));
  for(const c of fixtures) assert.ok(c.kind==='positive'||c.input===c.expected,c.id);
  assert.deepEqual(run(fixtures),[]);
});

test('redacted disclosures are stable for every noun and cue',()=>{
  const cases=[];
  for(const noun of NOUNS) for(const cue of [': ',' = ',' is ','=',':']) cases.push({id:`stable ${noun}${cue}`,input:`${noun}${cue}${R}`,expected:`${noun}${cue}${R}`});
  assert.deepEqual(run(cases),[]);
});
