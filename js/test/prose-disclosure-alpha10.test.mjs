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
// One test per noun: Bun's default limit is 5 s a test, and the whole matrix takes longer on hosted runners.
assert.equal(prefixMatrix.length,8*8*16*34);
for(let start=0;start<prefixMatrix.length;start+=8*16*34){
  const rows=prefixMatrix.slice(start,start+8*16*34);
  test(`a prefix never redacts less than the bare cue: ${NOUNS[start/(8*16*34)]}`,()=>{
    assert.equal(rows.length,8*16*34);
    assert.deepEqual(run(rows),[]);
  });
}
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
const DELIMITED_VALUES=['x]yq','x)yq','x}yq','abc&def=ghi','abc;host=y','x]yq zq','x)yq zq','x}yq zq','abc&def=ghi jk','abc;host=y zz',
  '密]码 秘','pä)ss ü','ж}ок','密码&键=值','ünï;host=ж'];
// One test per noun, as for the prefix matrix, to stay inside Bun's 5 s limit.
for(const noun of NOUNS){
  test(`a bare cue redacts a value with a close bracket or separator whole: ${noun}`,()=>{
    const cases=[];
    for(const lead of ['','my ','The new ']) for(const cue of CUES) for(const value of DELIMITED_VALUES){
      const left=`${PUBLIC}\n${lead}${noun}${cue}`;
      cases.push({id:`bare delimiter ${JSON.stringify(lead)} ${noun}${JSON.stringify(cue)} ${value}`,input:left+value,expected:left+R});
    }
    assert.equal(cases.length,3*8*15);
    assert.deepEqual(run(cases),[]);
  });
}
test('a bracket or list opened before a bare cue still ends it',()=>{
  const cases=[];
  for(const [input,expected] of [['(my pw: abc) docs','(my pw: [REDACTED]) docs'],['(pw: abc) docs','(pw: [REDACTED]) docs'],
    ['[pass code: x] ok','[pass code: [REDACTED]] ok'],['{pass phrase=abc} more','{pass phrase=[REDACTED]} more'],
    ['host=db;pw=abc;user=x','host=db;pw=[REDACTED];user=x'],['host=db;pass code=abc;user=x','host=db;pass code=[REDACTED];user=x'],
    ['?a=1&pw=abc&b=2','?a=1&pw=[REDACTED]&b=2'],['a=1&pass phrase=abc&b=2','a=1&pass phrase=[REDACTED]&b=2']])
    cases.push({id:`enclosed bare ${JSON.stringify(input)}`,input:`${PUBLIC}\n${input}`,expected:`${PUBLIC}\n${expected}`});
  assert.deepEqual(run(cases),[]);
});
test('contiguous quoted segments are one value',()=>{
  const segments=[['"abc""defq"','"'],["'abc''defq'","'"],['`abc``defq`','`'],['"abc"\'defq\'',"'"],['\'abc\'"defq"','"'],
    ['"abc"`defq`','`'],['“abc”“defq”','”'],['“abc”‘defq’','’'],['‘abc’"defq"','"'],['"abc""de"\'fq\'',"'"],['"密码""秘ж"','"']];
  const cases=[];
  for(const noun of NOUNS) for(const [lead,cue] of [['my ',' is '],['my ',' was set to '],['',': '],['','='],['my ',': '],['The new ',' = ']]){
    const left=`${PUBLIC}\n${lead}${noun}${cue}`;
    for(const [value,close] of segments){
      // A sensitive assignment may fail closed on mixed quotes through the line; every API must agree on it.
      const open=[...value][0], text=scrubber.scrubText(left+value);
      const expected=[`${left}${open}${R}`,`${left}${R}`].includes(text)?text:`${left}${open}${R}${close}`;
      cases.push({id:`quoted ${lead}${noun}${JSON.stringify(cue)} ${value}`,input:left+value,expected});
    }
    cases.push({id:`quoted spaced ${lead}${noun}${JSON.stringify(cue)}`,input:`${left}"abc" "defq"`,expected:`${left}"${R}" "defq"`});
  }
  for(const [input,expected] of [['my password is "abc""de','my password is "[REDACTED]'],["pw: 'abc''de","pw: '[REDACTED]"],
    ['echo "my password is \'abc\'"','echo "my password is \'[REDACTED]\'"'],['title="pw: \'abc\'" x','title="pw: \'[REDACTED]\'" x'],
    ["Don't forget, my password is 'abc''defq'","Don't forget, my password is '[REDACTED]'"],
    ['{"t":"my password is \\"abc\\"\\"defq\\""}','{"t":"my password is \\"[REDACTED]\\""}'],
    ['{"t":"my password is \\"abc\\""}','{"t":"my password is \\"[REDACTED]\\""}']])
    cases.push({id:`quoted named ${JSON.stringify(input)}`,input:`${PUBLIC}\n${input}`,expected:`${PUBLIC}\n${expected}`});
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

const TAIL_CUES=[['my ',' is '],['my ',' was '],['my ',' was set to '],['',': '],['','='],['my ',': '],['The new ',' = '],['',' is ']];
const QUOTED_TAILS=[['""abcq',''],['""abc"',''],["''abcq",''],['``abcq',''],['"abc"defq',''],['"abc"defq"ghiq"',''],["'abc'defq",''],
  ['`abc`defq',''],['“abc”defq',''],['‘abc’defq',''],['"abc"-defq',''],['"abc"(defq)',''],['"abc".defq',''],['"abc"d',''],
  ['"abc"defq.','.'],['"abc"defq, ok',', ok'],['"abc"defq more',' more'],['"abc"defq\nnext','\nnext'],['"密码"秘ж',''],['“”秘ж',''],
  ["'abc'defq'ghiq'",''],['"abc"defq\'ghiq\'','']];
const TAIL_CONTROLS=[['"abc".','"[REDACTED]".'],['"abc", ok','"[REDACTED]", ok'],['"abc" "defq"','"[REDACTED]" "defq"'],
  ['"abc"; the user is bob','"[REDACTED]"; the user is bob'],['"abc" and user is bob','"[REDACTED]" and user is bob'],
  ['"abc""defq"','"[REDACTED]"'],["'abc'.","'[REDACTED]'."],['`abc`, ok','`[REDACTED]`, ok'],['“abc”.','“[REDACTED]”.'],
  ['"abc"!?','"[REDACTED]"!?'],['"abc"...','"[REDACTED]"...']];
// One test per noun to stay inside Bun's 5 s limit.
for(const noun of NOUNS){
  test(`text that touches a close quote is part of the value: ${noun}`,()=>{
    const cases=[];
    for(const [lead,cue] of TAIL_CUES){
      const left=`${PUBLIC}\n${lead}${noun}${cue}`;
      for(const [value,kept] of QUOTED_TAILS){
        // The quote may stay or go (a sensitive assignment fails closed without it); nothing of the value may.
        const shapes=[`${left}${[...value][0]}${R}${kept}`,`${left}${R}${kept}`], text=scrubber.scrubText(left+value);
        cases.push({id:`tail ${lead}${noun}${JSON.stringify(cue)} ${value}`,input:left+value,expected:shapes.includes(text)?text:shapes[0]});
      }
      for(const [value,expected] of TAIL_CONTROLS) cases.push({id:`tail control ${lead}${noun}${JSON.stringify(cue)} ${value}`,input:left+value,expected:left+expected});
    }
    assert.deepEqual(run(cases),[]);
  });
}
test('a quoted value tail inside a JSON string ends at the string',()=>{
  const cases=[];
  for(const [input,expected] of [['{"note":"my password is \\"abc\\"defq"}','{"note":"my password is \\"[REDACTED]"}'],
    ['{"note":"pw: \\"abc\\"defq"}','{"note":"pw: \\"[REDACTED]"}'],
    ['{"note":"my password is \\"\\"abcq"}','{"note":"my password is \\"[REDACTED]"}'],
    ['{"t":"{\\"note\\":\\"my pw is \\\\\\"abc\\\\\\"defq\\"}"}','{"t":"{\\"note\\":\\"my pw is \\\\\\"[REDACTED]\\"}"}'],
    ['{"note":"my password is \\"abc\\"."}','{"note":"my password is \\"[REDACTED]\\"."}'],
    ['echo "my password is \'abc\'defq"','echo "my password is \'[REDACTED]"']])
    cases.push({id:`tail named ${JSON.stringify(input)}`,input:`${PUBLIC}\n${input}`,expected:`${PUBLIC}\n${expected}`});
  assert.deepEqual(run(cases),[]);
});
test('only the innermost opener\'s close ends the value',()=>{
  const cases=[];
  for(const noun of NOUNS) for(const cue of [': ','=']){
    const k=noun+cue;
    for(const [input,expected] of [
      [`(note ${k}x]yq zq`,`(note ${k}${R}`],[`{a ${k}x)yq zq`,`{a ${k}${R}`],[`[a] (${k}x]yq zq) end`,`[a] (${k}${R}) end`],
      [`log (info: ${k}x]yq zq`,`log (info: ${k}${R}`],[`{"note":"${k}x]yq zq"}`,`{"note":"${k}${R}"}`],
      [`{"note":"${k}x}yq zq"}`,`{"note":"${k}${R}"}`],[`{"a":["${k}x)yq zq"]}`,`{"a":["${k}${R}"]}`],
      [`{"note":"(info: ${k}x]yq zq"}`,`{"note":"(info: ${k}${R}"}`],[`(say "${k}x)yq zq"`,`(say "${k}${R}"`],
      [`[a {b} ${k}x}yq zq`,`[a {b} ${k}${R}`],[`say "(a ${k}x]y) z"`,`say "(a ${k}${R}) z"`],
      // Controls.
      [`[a (b) ${k}x]yq zq`,`[a (b) ${k}${R}]yq zq`],[`(my ${k}abc) docs`,`(my ${k}${R}) docs`],[`[${k}x]yq`,`[${k}${R}]yq`],
      [`{${k}x}yq`,`{${k}${R}}yq`],[`${k}x]yq zq`,`${k}${R}`],[`${k}(x)yq`,`${k}${R}`],[`${k}[x]yq`,`${k}${R}`],[`${k}x}yq`,`${k}${R}`],
      [`[note] ${k}x)yq zq`,`[note] ${k}${R}`],[`(see docs) ${k}x)yq zq`,`(see docs) ${k}${R}`],[`log [info] ${k}x]yq zq`,`log [info] ${k}${R}`],
      [`{"note":"(my ${k}abc) docs"}`,`{"note":"(my ${k}${R}) docs"}`],[`(a ${k}f(x)y) z`,`(a ${k}${R}) z`]])
      cases.push({id:`innermost ${JSON.stringify(input)}`,input:`${PUBLIC}\n${input}`,expected:`${PUBLIC}\n${expected}`});
  }
  assert.deepEqual(run(cases),[]);
});
test('only a list the line already is ends the value at its separator',()=>{
  const cases=[];
  for(const n of NOUNS) for(const [input,expected] of [
    [`a;b ${n}: abc;host=y`,`a;b ${n}: ${R}`],[`note; my ${n}: abc;host=y`,`note; my ${n}: ${R}`],[`R&D ${n}: abc&def=ghi`,`R&D ${n}: ${R}`],
    [`a & b; ${n}: abc;host=y`,`a & b; ${n}: ${R}`],[`a=1;${n}=abc&user=x`,`a=1;${n}=${R}`],[`a=1& b ${n}: abc&def=ghi`,`a=1& b ${n}: ${R}`],
    [`x=1; note ${n}: abc;host=y`,`x=1; note ${n}: ${R}`],
    // Controls.
    [`host=db;${n}=abc;user=x`,`host=db;${n}=${R};user=x`],[`a=1&${n}=abc&user=x`,`a=1&${n}=${R}&user=x`],
    [`host=db; ${n}=abc; user=x`,`host=db; ${n}=${R}; user=x`],[`?a=1&${n}=abc&b=2`,`?a=1&${n}=${R}&b=2`],
    [`x=1 ${n}: abc&def=ghi`,`x=1 ${n}: ${R}`],[`url?a=1 says ${n}: abc&def=ghi`,`url?a=1 says ${n}: ${R}`],
    [`${n}: abc;host=y`,`${n}: ${R}`],[`${n}: a&b`,`${n}: ${R}`]])
    cases.push({id:`list ${JSON.stringify(input)}`,input:`${PUBLIC}\n${input}`,expected:`${PUBLIC}\n${expected}`});
  assert.deepEqual(run(cases),[]);
});
