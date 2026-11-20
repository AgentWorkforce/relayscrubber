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
    // A space before def: text touching a close quote is part of the value, so only a spaced segment shows where
    // an even run closed the quote.
    input:`${left}abc${'\\'.repeat(slashes)}${quote} def${quote}`,
    expected:slashes%2?`${left}${R}${quote}`:`${left}${R}${quote} def${quote}`,
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
        // The quote may stay or go, and the last segment's close may stay; a sensitive assignment may fail closed
        // on the odd quotes through the end of the text. Nothing of the value may stay.
        const open=[...value][0], text=scrubber.scrubText(left+value);
        const shapes=[`${left}${open}${R}${kept}`,`${left}${R}${kept}`,`${left}${open}${R}`,`${left}${R}`,
          ...['"',"'",'`','”','’'].map(close=>`${left}${open}${R}${close}${kept}`)];
        cases.push({id:`tail ${lead}${noun}${JSON.stringify(cue)} ${value}`,input:left+value,expected:shapes.includes(text)?text:shapes[0]});
      }
      for(const [value,expected] of TAIL_CONTROLS){
        // A sensitive assignment already ate a curly-quoted value and its full stop before this pass (95336df prints
        // the same); that over-redaction is kept, it leaks nothing.
        const eaten=left+R, keep=value.startsWith('“')&&scrubber.scrubText(left+value)===eaten;
        cases.push({id:`tail control ${lead}${noun}${JSON.stringify(cue)} ${value}`,input:left+value,expected:keep?eaten:left+expected});
      }
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
const SENSITIVE=['password','passcode','passphrase','passwd','pwd'];
test('only a list the line already is ends the value at its separator',()=>{
  const cases=[];
  for(const n of NOUNS) for(const [input,expected] of [
    [`a;b ${n}: abc;host=y`,`a;b ${n}: ${R}`],[`note; my ${n}: abc;host=y`,`note; my ${n}: ${R}`],[`R&D ${n}: abc&def=ghi`,`R&D ${n}: ${R}`],
    [`a & b; ${n}: abc;host=y`,`a & b; ${n}: ${R}`],[`a=1;${n}=abc&user=x`,`a=1;${n}=${R}`],[`a=1& b ${n}: abc&def=ghi`,`a=1& b ${n}: ${R}`],
    [`x=1; note ${n}: abc;host=y`,`x=1; note ${n}: ${R}`],
    // Controls.
    [`host=db;${n}=abc;user=x`,`host=db;${n}=${R};user=x`],// A sensitive assignment noun fails closed on & (95336df prints the same, here and in the query control).
    [`a=1&${n}=abc&user=x`,SENSITIVE.includes(n)?`a=1&${n}=${R}`:`a=1&${n}=${R}&user=x`],
    [`host=db; ${n}=abc; user=x`,`host=db; ${n}=${R}; user=x`],[`?a=1&${n}=abc&b=2`,SENSITIVE.includes(n)?`?a=1&${n}=${R}`:`?a=1&${n}=${R}&b=2`],
    [`x=1 ${n}: abc&def=ghi`,`x=1 ${n}: ${R}`],[`url?a=1 says ${n}: abc&def=ghi`,`url?a=1 says ${n}: ${R}`],
    [`${n}: abc;host=y`,`${n}: ${R}`],[`${n}: a&b`,`${n}: ${R}`]])
    cases.push({id:`list ${JSON.stringify(input)}`,input:`${PUBLIC}\n${input}`,expected:`${PUBLIC}\n${expected}`});
  assert.deepEqual(run(cases),[]);
});

// A line of the input that parses as JSON must parse in the output with the same keys: a redaction never eats an
// enclosing string's closing quote.
const shape=value=>Array.isArray(value)?value.map(shape):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,shape(v)])):null;
function jsonShapeFailures(id,input,output){
  const ins=input.split('\n'), outs=output.split('\n');
  for(const [n,line] of ins.entries()){
    let before; try{before=JSON.parse(line);}catch{continue;}
    let after=null; try{if(outs.length===ins.length) after=shape(JSON.parse(outs[n]));}catch{}
    if(JSON.stringify(after)!==JSON.stringify(shape(before))) return [`${id}/json-shape: ${JSON.stringify(input)} -> ${JSON.stringify(output)}`];
  }
  return [];
}
// `run` plus the JSON property; a case without an expectation must lose every `defq` and keep the public line.
function runLeakFree(cases){
  const failures=[];
  for(const entry of cases){
    const text=scrubber.scrubText(entry.input);
    if(entry.expected===undefined&&(text.includes('defq')||!text.startsWith(`${PUBLIC}\n`))) failures.push(`${entry.id}/leak: ${JSON.stringify(entry.input)} -> ${JSON.stringify(text)}`);
    failures.push(...run([{...entry,expected:entry.expected??text}]),...jsonShapeFailures(entry.id,entry.input,text));
  }
  return failures;
}
const pinned=(label,pairs)=>pairs.map(([input,expected])=>({id:`${label} ${JSON.stringify(input)}`,input:`${PUBLIC}\n${input}`,expected:`${PUBLIC}\n${expected}`}));

// Leak class E: a contiguous segment that opens with any quote at the noun's escape level or deeper is part of the
// value, on a plain line and inside a JSON string. One test per layout to stay inside Bun's 5 s limit.
for(const layout of ['pw: ','pw=','my password = ','password: ','my pass code is ']){
  test(`a contiguous segment of any quote or deeper escape is part of the value: ${JSON.stringify(layout)}`,()=>{
    const cases=[];
    for(const first of ['abc','"abc"',"'abc'",'`abc`']) for(const quote of ['"',"'",'`']) for(let level=0;level<3;level++){
      const escape='\\'.repeat((1<<level)-1), line=`${layout}${first}${escape}${quote}defq${escape}${quote}`;
      cases.push({id:`class E ${line}`,input:`${PUBLIC}\n${line}`});
      const json=`{"note":${JSON.stringify(line)},"user":"bob"}`;
      cases.push({id:`class E json ${json}`,input:`${PUBLIC}\n${json}`});
    }
    assert.equal(cases.length,4*3*3*2);
    assert.deepEqual(runLeakFree(cases),[]);
  });
}
test('the named class E inputs',()=>{
  assert.deepEqual(runLeakFree(pinned('named class E',[
    [String.raw`pw: "abc"\"defq\"`,String.raw`pw: "[REDACTED]\"`],
    [String.raw`my password is "abc"\'defq\'`,String.raw`my password is "[REDACTED]\'`],
    [String.raw`my password is 'abc'\'defq\'`,String.raw`my password is '[REDACTED]\'`],
    [String.raw`{"note":"my password is \"abc\"'defq'"}`,String.raw`{"note":"my password is \"[REDACTED]'"}`],
    [String.raw`{"note":"my password is 'abc'\"defq\""}`,String.raw`{"note":"my password is '[REDACTED]\""}`],
    [String.raw`{"note":"my password is \"abc\"\\\"defq\\\"","user":"bob"}`,String.raw`{"note":"my password is \"[REDACTED]\\\"","user":"bob"}`],
    [String.raw`{"note":"my password is \"abc\"` + '`defq`' + String.raw`","user":"bob"}`,String.raw`{"note":"my password is \"[REDACTED]` + '`' + String.raw`","user":"bob"}`],
    [String.raw`{"note":"pw: abc\"defq\"","user":"bob"}`,String.raw`{"note":"pw: [REDACTED]","user":"bob"}`],
  ])),[]);
});
test('every fixture JSON line keeps its keys',()=>{
  assert.deepEqual(fixtures.flatMap(c=>jsonShapeFailures(c.id,c.input,scrubber.scrubText(c.input))),[]);
});
test('a key-like field or tag close after a quoted value ends it',()=>{
  assert.deepEqual(runLeakFree(pinned('after quote',[
    ['password="abc",user="bob"','password="[REDACTED]",user="bob"'],['f(password="abc",user="bob")','f(password="[REDACTED]",user="bob")'],
    ['password="abc";user="bob"','password="[REDACTED]";user="bob"'],['password="abc"&user=bob','password="[REDACTED]"&user=bob'],
    ['password: "abc",user: bob','password: "[REDACTED]",user: bob'],['<a password="abc">text</a>','<a password="[REDACTED]">text</a>'],
    ['<a password="abc"/>','<a password="[REDACTED]"/>'],['pw="abc",user="bob"','pw="[REDACTED]",user="bob"'],
    ['my password is "abc",user: bob','my password is "[REDACTED]",user: bob'],[`pw: 'abc'; "user": bob`,`pw: '[REDACTED]'; "user": bob`],
    ['<a pass code="abc">text</a>','<a pass code="[REDACTED]">text</a>'],
    [String.raw`{"note":"password=\"abc\",user=\"bob\""}`,String.raw`{"note":"password=\"[REDACTED]\",user=\"bob\""}`],
    // Controls that stay redacted.
    ['password="abc"def','password="[REDACTED]'],['password="abc""defq"','password="[REDACTED]"'],['password="abc",defq','password="[REDACTED]'],
    ['password="abc";defq','password="[REDACTED]'],['my password is "abc",ok','my password is "[REDACTED]'],['password="abc"><tag','password="[REDACTED]'],
    ['pw: "abc"==user:x','pw: "[REDACTED]'],
    // A bare value keeps its rules.
    ['pw: abc)def','pw: [REDACTED]'],['pw: abc&k=defq','pw: [REDACTED]'],['pw: abc;k=defq','pw: [REDACTED]'],['<a pw: abc>def','<a pw: [REDACTED]'],
  ])),[]);
});
test('an unterminated segment stops at the enclosing close',()=>{
  assert.deepEqual(runLeakFree(pinned('enclosing close',[
    [String.raw`{"note": "my password is \"abc\\\\\"def\""}`,String.raw`{"note": "my password is \"[REDACTED]"}`],
    [String.raw`{"note":"my password is \"abc","user":"bob"}`,String.raw`{"note":"my password is [REDACTED]","user":"bob"}`],
    [String.raw`{"note":"pw: 'abc","user":"bob"}`,String.raw`{"note":"pw: '[REDACTED]","user":"bob"}`],
    [String.raw`{"note":"my password is abc\"defq\""}`,String.raw`{"note":"my password is [REDACTED]"}`],
    [String.raw`{"note":"my password is abc","user":"bob"}`,String.raw`{"note":"my password is [REDACTED]","user":"bob"}`],
    [String.raw`{"note":"password:\"abc\"defq","user":"bob"}`,String.raw`{"note":"password:\"[REDACTED]","user":"bob"}`],
    [String.raw`{"note":"passcode=\"abc\"'defq'","user":"bob"}`,String.raw`{"note":"passcode=\"[REDACTED]","user":"bob"}`],
    ['my password is "abc""de','my password is "[REDACTED]'],
  ])),[]);
});
// Text glued to the closer of a quote opened before the noun is part of the value: a quote of any type, or an
// alphanumeric, `_` or `$`, right after that closer continues the value to the next whitespace or to the closer of a
// further enclosing layer. The closer itself falls inside the redaction, as with the `is` form.
const GLUED=[["x \"pw: abc\"\"defq\"","x \"pw: [REDACTED]\"","defq"],["x 'pw: abc'\"defq\"","x 'pw: [REDACTED]\"","defq"],["he said 'my password is \"abc\"'\"defq\"","he said 'my password is \"[REDACTED]\"","defq"],["he said \"my password is 'abc'\"defq","he said \"my password is '[REDACTED]","defq"],["he said 'pw: abc'defq","he said 'pw: [REDACTED]","defq"],["echo \"pw: abc\"$X","echo \"pw: [REDACTED]","$X"],["echo \"pw: abc\"${SUFFIX} next","echo \"pw: [REDACTED] next","SUFFIX"],["1,\"pw: abc\"\"defq\",3","1,\"pw: [REDACTED]","defq"],["{\"note\":\"he said \\\"pw: abc\\\"\\\"defq\\\"\",\"user\":\"bob\"}","{\"note\":\"he said \\\"pw: [REDACTED]\\\"\",\"user\":\"bob\"}","defq"],["{\"note\":\"he said \\\"pw: abc\\\"defq\",\"user\":\"bob\"}","{\"note\":\"he said \\\"pw: [REDACTED]\",\"user\":\"bob\"}","defq"],["\"pw: abc\"s","\"pw: [REDACTED]","\"s"],["`pw: abc`defq","`pw: [REDACTED]","defq"],["“pw: abc”defq","“pw: [REDACTED]","defq"],["msg=\"pw: abc\"user=\"bob\"","msg=\"pw: [REDACTED]\"","bob"],["<a title=\"pw: abc\"b=\"c\">","<a title=\"pw: [REDACTED]\">","b="]];
test('text glued to an enclosing closer is part of the value',()=>{
  for(const [input,expected,glued] of GLUED) assert.ok(!expected.includes(glued),`${JSON.stringify(input)} keeps ${glued}`);
  assert.deepEqual(runLeakFree(pinned('glued',GLUED.map(([input,expected])=>[input,expected]))),[]);
});
// Controls: punctuation, whitespace, a field, or a bracket opened before the noun after the closer keep their output.
test('text after an enclosing closer that is not glued keeps its output',()=>{
  assert.deepEqual(runLeakFree(pinned('not glued',[["He said \"pw: abc\".","He said \"pw: [REDACTED]\"."],["He said \"pw: abc\". Then left","He said \"pw: [REDACTED]\". Then left"],["\"pw: abc\",next","\"pw: [REDACTED]\",next"],["f(\"pw: abc\")","f(\"pw: [REDACTED]\")"],["1,\"pw: abc\",3","1,\"pw: [REDACTED]\",3"],["\"pw: abc\":1","\"pw: [REDACTED]\":1"],["\"pw: abc\"-x","\"pw: [REDACTED]\"-x"],["{\"note\":\"pw: abc\",\"user\":\"bob\"}","{\"note\":\"pw: [REDACTED]\",\"user\":\"bob\"}"],["{\"note\":\"he said \\\"pw: abc\\\".\",\"user\":\"bob\"}","{\"note\":\"he said \\\"pw: [REDACTED]\\\".\",\"user\":\"bob\"}"],["msg='pw: abc' user='bob'","msg='pw: [REDACTED]' user='bob'"],["msg='pw: abc',user='bob'","msg='pw: [REDACTED]',user='bob'"],["<a title=\"pw: abc\">t</a>","<a title=\"pw: [REDACTED]\">t</a>"],["echo \"my password is abc\"","echo \"my password is [REDACTED]\""],["(my pw: abc) docs","(my pw: [REDACTED]) docs"],["host=db;pw=abc;user=x","host=db;pw=[REDACTED];user=x"],["[my password is \"abc\"]defq","[my password is \"[REDACTED]\"]defq"],["(he said \"pw: abc\")defq","(he said \"pw: [REDACTED]\")defq"],["((pw: x)yq zq","((pw: [REDACTED])yq zq"],["x \"pw: abc\" \"defq\"","x \"pw: [REDACTED]\" \"defq\""],["echo \"my password is abc\"; ls","echo \"my password is [REDACTED]; ls"],["\"pw: abc\"; ls","\"pw: [REDACTED]\"; ls"]])),[]);
});
// The reference and placeholder exemption covers a whole value only: once any contiguous part is literal, every part
// is value, whatever its shape. Each input scrubs exactly as its twin, where the reference-shaped part is the literal
// TWIN, and loses its literal parts and the shape. One test per layout to stay inside Bun's 5 s limit.
const REFERENCE_SHAPES=['$defq','${defq}','$1','$env:DEFQ','${{ secrets.DEFQ }}','process.env.DEFQ','op://v/defq/p','<defq>','%DEFQ%','{{defq}}','YOUR_DEFQ','changeme','example','xxx','${DEFQ:-x}','***',R];
const TWIN='zzzq';
const wrapJson=line=>`{"note":${JSON.stringify(line)},"user":"bob"}`;
const forbiddenFor=shape=>shape===R?['abcq','ghiq']:['abcq','ghiq',shape];
function runWholeValue(cases){
  const failures=[];
  for(const {id,input,twin,forbidden} of cases){
    const text=scrubber.scrubText(input);
    if(!text.startsWith(`${PUBLIC}\n`)||forbidden.some(f=>text.slice(PUBLIC.length+1).includes(f))) failures.push(`${id}/leak: ${JSON.stringify(input)} -> ${JSON.stringify(text)}`);
    const want=scrubber.scrubText(twin);
    if(text!==want) failures.push(`${id}/twin: ${JSON.stringify(input)} -> ${JSON.stringify(text)}, its twin -> ${JSON.stringify(want)}`);
    failures.push(...run([{id,input,expected:text}]),...jsonShapeFailures(id,input,text));
  }
  return failures;
}
const wholeValueForms=s=>[
  [`"abcq""${s}"`,true],[`'abcq'"${s}"`,false],[`"abcq"'${s}'`,false],['`abcq`'+`"${s}"`,false],
  [`"${s}""abcq"`,true],[`'${s}'"abcq"`,false],[`"${s}"'abcq'`,false],
  [`"abcq""${s}""ghiq"`,true],[`abcq"${s}"`,false],[`"${s}"abcq`,false],
];
for(const layout of ['pw: ','pw=','my password = ','password: ','my pass code is ']){
  test(`a reference-shaped part of a value with a literal part is part of the value: ${JSON.stringify(layout)}`,()=>{
    const cases=[];
    for(const shape of REFERENCE_SHAPES) for(const [form,json] of wholeValueForms(shape)){
      const line=`${layout}${form}`, twin=line.replaceAll(shape,TWIN);
      const pairs=json?[[line,twin],[wrapJson(line),wrapJson(twin)]]:[[line,twin]];
      for(const [input,t] of pairs) cases.push({id:`whole value ${input}`,input:`${PUBLIC}\n${input}`,twin:`${PUBLIC}\n${t}`,forbidden:forbiddenFor(shape)});
    }
    assert.deepEqual(runWholeValue(cases),[]);
  });
  test(`a later segment opening with any punctuation is part of the value: ${JSON.stringify(layout)}`,()=>{
    const cases=[];
    for(let c=0x21;c<0x7f;c++){
      const p=String.fromCharCode(c);
      if(!/[\p{P}\p{S}]/u.test(p)) continue;
      for(const quote of ['"',"'"]){
        const line=`${layout}"abcq"${quote}${p}defq${quote}`;
        cases.push({id:`punctuation ${line}`,input:`${PUBLIC}\n${line}`});
        if(quote==='"') cases.push({id:`punctuation json ${line}`,input:`${PUBLIC}\n${wrapJson(line)}`});
      }
    }
    assert.equal(cases.length,32*3);
    const failures=runLeakFree(cases);
    for(const {id,input} of cases) if(scrubber.scrubText(input).includes('abcq')) failures.push(`${id}/leak`);
    assert.deepEqual(failures,[]);
  });
  test(`a bare reference glued to a literal is part of the value: ${JSON.stringify(layout)}`,()=>{
    const cases=[];
    for(const [form,shape] of [['${defq}abcq','${defq}'],['%defq%abcq','%defq%'],['<defq>abcq','<defq>'],['{{defq}}abcq','{{defq}}'],['$(defq)abcq','$(defq)'],['abcq${defq}','${defq}'],['abcq%defq%','%defq%'],['abcq<defq>','<defq>'],['abcq{{defq}}','{{defq}}'],['abcq$defq','$defq'],[`${R}abcq`,R],['${defq}${ghiq}abcq','${defq}${ghiq}'],['$defq"abcq"','$defq'],['${defq}"abcq"','${defq}'],['<defq>"abcq"','<defq>'],['op://v/defq/p"abcq"','op://v/defq/p']]){
      const line=`${layout}${form}`, twin=line.replaceAll(shape,TWIN);
      for(const [input,t] of [[line,twin],[wrapJson(line),wrapJson(twin)]]) cases.push({id:`bare glue ${input}`,input:`${PUBLIC}\n${input}`,twin:`${PUBLIC}\n${t}`,forbidden:['abcq','defq','ghiq']});
    }
    assert.deepEqual(runWholeValue(cases),[]);
  });
}
test('a reference-shaped part across an enclosing closer is part of the value',()=>{
  const forms=['x "pw: {a}""{b}"',`x 'pw: {a}'"{b}"`,`x='pw: {a}'"{b}"`,`msg="pw: {a}"'{b}'`,`he said 'my password is "{a}"'"{b}"`,'x "pw: {a}"{b}','echo "my password is {a}"{b}','1,"pw: {a}""{b}",3'];
  const cases=[];
  for(const shape of REFERENCE_SHAPES) for(const form of forms) for(const [a,b] of [['abcq',shape],[shape,'abcq']]){
    if(shape.includes(' ')&&(a===shape||form.endsWith('{b}'))) continue;
    const line=form.replace('{a}',a).replace('{b}',b), twin=line.replaceAll(shape,TWIN);
    for(const [input,t] of [[line,twin],[wrapJson(line),wrapJson(twin)]]) cases.push({id:`enclosing whole value ${input}`,input:`${PUBLIC}\n${input}`,twin:`${PUBLIC}\n${t}`,forbidden:forbiddenFor(shape)});
  }
  assert.deepEqual(runWholeValue(cases),[]);
});
test('the named whole-value inputs',()=>{
  assert.deepEqual(runLeakFree(pinned('named whole value',[
    ['pw: "abc""$defq"','pw: "[REDACTED]"'],[`pw: "abc"'$defq'`,`pw: "[REDACTED]'`],['password="abc""$defq"','password="[REDACTED]"'],
    [`password='abc'"$defq"`,`password='[REDACTED]`],['my password is "abc""${defq}"','my password is "[REDACTED]"'],
    ['my password is "abc""<defq>"','my password is "[REDACTED]"'],['my password is "abc""%defq%"','my password is "[REDACTED]"'],
    ['my password is "abc""{{defq}}"','my password is "[REDACTED]"'],['x "pw: abc""$defq"','x "pw: [REDACTED]"'],
    [`x 'pw: abc'"$defq"`,`x 'pw: [REDACTED]"`],[`x='pw: abc'"$defq"`,`x='pw: [REDACTED]"`],[`msg="pw: abc"'$defq'`,`msg="pw: [REDACTED]'`],
    ['x "pw: abc""<defq>"','x "pw: [REDACTED]"'],['x "pw: abc""%defq%"','x "pw: [REDACTED]"'],['x "pw: abc""{{defq}}"','x "pw: [REDACTED]"'],
    ['x "pw: abc""${defq}"','x "pw: [REDACTED]"'],['x "pw: abc""$1efq"','x "pw: [REDACTED]"'],['pw: "abc""YOUR_PASSWORD"','pw: "[REDACTED]"'],
    ['pw: "abc""op://v/i"','pw: "[REDACTED]"'],['pw: "abc""process.env.PASSWORD"','pw: "[REDACTED]"'],['pw: "abc""$env:PASSWORD"','pw: "[REDACTED]"'],
    ['pw: "abc""${{ secrets.PASSWORD }}"','pw: "[REDACTED]"'],['pw: "abc""[REDACTED]"','pw: "[REDACTED]"'],
    ['password="$defq""abc"','password="[REDACTED]"'],['password="[REDACTED]""abc"','password="[REDACTED]"'],['password="$defq"abc','password="[REDACTED]'],
    ['pw: ${defq}abc','pw: [REDACTED]'],['pw: [REDACTED]abc','pw: [REDACTED]'],['my password is <defq>abc','my password is [REDACTED]'],
    ['my password is ${defq}abc','my password is [REDACTED]'],['x "pw: $defq""abc"','x "pw: [REDACTED]"'],
    [String.raw`{"note":"pw: \"abc\"\"$defq\"","user":"bob"}`,String.raw`{"note":"pw: \"[REDACTED]\"","user":"bob"}`],
    [String.raw`{"note":"he said \"pw: abc\"\"$defq\"","user":"bob"}`,String.raw`{"note":"he said \"pw: [REDACTED]\"","user":"bob"}`],
    [String.raw`{"note":"password=\"$defq\"\"abc\"","user":"bob"}`,String.raw`{"note":"password=\"[REDACTED]\"","user":"bob"}`],
    // Already right before the whole-value rule; kept.
    ['pw: "abc$defq"','pw: "[REDACTED]"'],['pw: "abc""$defq ghiq"','pw: "[REDACTED]"'],['pw: "abc""$(defq)"','pw: "[REDACTED]"'],
    ['pw: "abc""$$defq"','pw: "[REDACTED]"'],['pw: "$defq""abc"','pw: "[REDACTED]"'],['pw: "<defq>""abc"','pw: "[REDACTED]"'],
    ['pw: "{{defq}}abc"','pw: "[REDACTED]"'],['my password is "$defq""abc"','my password is "[REDACTED]"'],['pw: "abc""xxx"','pw: "[REDACTED]"'],
    ['pw: "abc""changeme"','pw: "[REDACTED]"'],
  ])),[]);
});
// A value that is one pure reference or placeholder, a chain made only of pure references, and a reference separated
// by whitespace keep their output.
test('a pure reference value keeps its output',()=>{
  assert.deepEqual(runLeakFree(pinned('pure reference',[
    ['pw: "$defq"','pw: "$defq"'],['pw: $defq','pw: $defq'],['my password is $defq','my password is $defq'],['password="$defq"','password="$defq"'],
    ['password=${defq}','password=${defq}'],['password="${{ secrets.PASSWORD }}"','password="${{ secrets.PASSWORD }}"'],
    ['password: <password>','password: <password>'],['pw: %PASSWORD%','pw: %PASSWORD%'],['password={{password}}','password=[REDACTED]'],
    ['pw: <password>.','pw: <password>.'],['my password is {{ password }}','my password is {{ password }}'],['pw: [REDACTED]','pw: [REDACTED]'],
    ['pw: "[REDACTED]"','pw: "[REDACTED]"'],['(my pw: abc) docs','(my pw: [REDACTED]) docs'],['host=db;pw=abc;user=x','host=db;pw=[REDACTED];user=x'],
    ['pw: "abc" "$defq"','pw: "[REDACTED]" "$defq"'],['password="abc" "$defq"','password="[REDACTED]" "$defq"'],
    ['pw: ${X:-default}','pw: ${X:-default}'],['password=${X:-default}','password=${X:-default}'],
    ['pw: "$A""$B"','pw: "$A""$B"'],['pw: ${A}${B}','pw: ${A}${B}'],['password="$A""$B"','password="$A""$B"'],
    [`my password is "$A"'\${B}'`,`my password is "$A"'\${B}'`],['x "pw: $A""$B"','x "pw: $A""$B"'],
  ])),[]);
});
// Values that look like types: arbitrary lowercase, Pascal, numeric and nested angle payloads, real-looking generics
// and the simple type names. Without source context such a value after a bare colon is credential data.
const TYPE_PAYLOADS=['abcq<defq>','hunter2<secret>','orchid<river>','Secret<value>','abc<123>','a<b<c>>','abcq<defq<ghiq>>',
  'Vec<u8>','Option<String>','Map<String, u8>','string','boolean','number','bool','&str'];
const TYPE_ENDINGS=['',',',';','\n','\r\n'];
const IDENTIFIER_NOUNS=['password','passcode','passphrase','passwd','pwd','pw'];
const casings=noun=>[noun,noun[0].toUpperCase()+noun.slice(1),noun.toUpperCase()];
// More than the engine's 512-byte look-back of filler before the line.
const longFiller='lorem ipsum dolor sit amet '.repeat(25);
// `run` plus the line as a JSON string value beside another key, and two NDJSON records holding it.
function runEvery(cases){
  const failures=run(cases);
  for(const {id,input,expected} of cases){
    const record=JSON.stringify({note:input,user:'bob'});
    const want=JSON.stringify({note:expected,user:'bob'});
    const json=scrubber.scrubJson(record).value;
    if(JSON.stringify(json)!==want) failures.push(`${id}/json-text: ${JSON.stringify(json)}`);
    const out=scrubber.scrubRecords(new TextEncoder().encode(`${record}\n${record}\n`)).bytes;
    const lines=new TextDecoder().decode(out).trimEnd().split('\n');
    if(lines.length!==2||lines.some(l=>JSON.stringify(JSON.parse(l))!==want)) failures.push(`${id}/ndjson: ${JSON.stringify(lines)}`);
    if(new TextDecoder().decode(scrubber.scrubRecords(out).bytes)!==new TextDecoder().decode(out)) failures.push(`${id}/ndjson second pass`);
  }
  return failures;
}
// One marker for the whole value. `pw` and the spaced nouns keep one closing comma or semicolon after it, as they keep
// sentence punctuation; a line break and the next line are kept.
function bareTypeExpected(left,cased,noun,ending){
  const mark=['pw','pass code','pass phrase'].includes(noun)&&[',',';'].includes(ending)?ending:'';
  return `${left}${cased}: ${R}${mark}${ending.includes('\n')?ending+PUBLIC:''}`;
}
for(const noun of NOUNS) test(`a type-looking value after a bare colon without source context is redacted: ${noun}`,()=>{
  const cases=[];
  for(const cased of casings(noun)) for(const payload of TYPE_PAYLOADS) for(const ending of TYPE_ENDINGS)
    for(const left of [`${PUBLIC}\n`,`${longFiller}\n`]){
      const next=ending.includes('\n')?PUBLIC:'';
      cases.push({id:`bare type ${cased}: ${payload} ${JSON.stringify(ending)} ${left.length}`,input:`${left}${cased}: ${payload}${ending}${next}`,expected:bareTypeExpected(left,cased,noun,ending)});
    }
  assert.equal(cases.length,3*15*5*2);
  assert.deepEqual(runEvery(cases),[]);
});
test('the named context-free type inputs',()=>{
  const cases=[
    ['pw: abcq<defq>','pw: [REDACTED]'],['password: abcq<defq>','password: [REDACTED]'],['PASSWORD: abcq<defq>','PASSWORD: [REDACTED]'],
    ['passcode: hunter2<secret>','passcode: [REDACTED]'],['pass phrase: orchid<river>','pass phrase: [REDACTED]'],
    ['pw: Secret<value>','pw: [REDACTED]'],['pw: abc<123>','pw: [REDACTED]'],['pw: Vec<u8>','pw: [REDACTED]'],
    ['password: Option<String>,','password: [REDACTED]'],['pw: string','pw: [REDACTED]'],['pw: Map<String, u8>,','pw: [REDACTED],'],
    ['pw: abcq<defq, ghiq>;','pw: [REDACTED];'],['pw: (abcq, defq),','pw: [REDACTED],'],['my pw: abcq<defq>','my pw: [REDACTED]'],
    ['The new password: Secret<value>','The new password: [REDACTED]'],['struct X { pw: Vec<u8> }','struct X { pw: Vec<u8> }'],
    ['fn f(pw: String)','fn f(pw: String)'],['const pw: string','const pw: string'],
  ].map(([input,expected])=>({id:`named type ${input}`,input,expected}));
  assert.equal(cases.length,18);
  assert.deepEqual(runEvery(cases),[]);
});
// Source-context siblings stay byte identical. The spaced nouns cannot be identifiers and have no such sibling.
const TYPE_CONTEXT_FORMS=['struct X { {n}: {p} }','struct X { {n}: {p}, }','interface X { {n}: {p}; }','type X = { {n}: {p} }',
  'fn f({n}: {p})','fn f({n}: {p}) {}','const {n}: {p}','let {n}: {p};','struct X {\n    {n}: {p},\n}'];
for(const noun of IDENTIFIER_NOUNS) test(`a type with source context keeps its output: ${noun}`,()=>{
  const cases=[];
  for(const cased of casings(noun)) for(const payload of TYPE_PAYLOADS) for(const form of TYPE_CONTEXT_FORMS){
    const line=form.replace('{n}',cased).replace('{p}',payload);
    for(const input of [line,`${longFiller}\n${line}`]) cases.push({id:`type control ${JSON.stringify(input)}`,input,expected:input});
  }
  assert.equal(cases.length,3*15*9*2);
  assert.deepEqual(runEvery(cases),[]);
});
// A field on its own line in a multi-line body: the engine looks back at most 512 bytes for the body's opener. With the
// opener in view the field is kept; with none (alone, its own NDJSON record, or more than 512 bytes below) it fails closed.
test('a multi-line body field keeps its witnessed output',()=>{
  const many='    a: u8,\n'.repeat(60);
  const cases=[
    ['struct X {\n    pw: Vec<u8>,\n}','struct X {\n    pw: Vec<u8>,\n}'],
    ['struct X {\r\n    pw: Vec<u8>,\r\n}','struct X {\r\n    pw: Vec<u8>,\r\n}'],
    ['interface X {\n    password: string;\n}','interface X {\n    password: string;\n}'],
    ['fn f(\n    pw: Vec<u8>,\n) {}','fn f(\n    pw: Vec<u8>,\n) {}'],
    ['    pw: Vec<u8>,','    pw: [REDACTED],'],
    [`struct X {\n${many}    pw: Vec<u8>,\n}`,`struct X {\n${many}    pw: [REDACTED],\n}`],
    // The same position on one line, with its source context.
    ['struct X { pw: Vec<u8>, }','struct X { pw: Vec<u8>, }'],['fn f(pw: Vec<u8>,) {}','fn f(pw: Vec<u8>,) {}'],
    ['fn f(pw: Vec<u8>, b: u8) {}','fn f(pw: Vec<u8>, b: u8) {}'],['const pw: Vec<u8>','const pw: Vec<u8>'],
  ].map(([input,expected])=>({id:`multi-line ${JSON.stringify(input)}`,input,expected}));
  const failures=runEvery(cases);
  const records='{"line":"struct X {"}\n{"line":"    pw: Vec<u8>,"}\n{"line":"}"}\n';
  const want='{"line":"struct X {"}\n{"line":"    pw: [REDACTED],"}\n{"line":"}"}\n';
  if(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(records)).bytes)!==want) failures.push('per-line NDJSON body');
  assert.deepEqual(failures,[]);
});
// Words before the noun never redact less than the bare colon does. Values that start with `&` are covered by the
// borrow test below.
for(const noun of NOUNS) test(`a prefix never redacts less than the bare colon for a type-looking value: ${noun}`,()=>{
  const cases=[];
  for(const payload of TYPE_PAYLOADS.filter(p=>!p.startsWith('&'))) for(const prefix of PREFIXES){
    const left=`${PUBLIC}\n${prefix}${noun}: `;
    cases.push({id:`prefix type ${JSON.stringify(prefix)} ${noun} ${payload}`,input:`${left}${payload}`,expected:`${left}${R}`});
  }
  assert.equal(cases.length,14*34);
  assert.deepEqual(run(cases),[]);
});
// Code-looking values: dotted paths, calls, optional chains, `??` and `||` expressions, constructors, a leading dot,
// `match` bodies, closures and function literals, and values that start with a borrow. A source-shaped value does not
// establish source context: without a body, a signature, an object literal or a labelled call argument around the key
// it is credential data.
const CODE_PAYLOADS=['orchid.river','Orchid.River99','correct.horse.battery','Orchid(River)','orchid?.river','orchid.river ?? x',
  'new Orchid(river)','hunter2.secret','abc(def)','Hunter2(x)','abcq.defq()','.abcq','match abc { d => e }','config.password',
  'abcdef.ghijkl','&abcq','&Secret1','&mut abcq','options.value ?? fallback','config.auth || defaultAuth','async () => getToken()',
  'function() { return buildAuth(); }','match candidate { Some(x) => x, None => return }'];
const CODE_ENDINGS=['',',',';','!','\n','\r\n'];
const CREDENTIAL_KEYS=[...NOUNS,'token','secret','api_key','auth'];
const IDENTIFIER_KEYS=CREDENTIAL_KEYS.filter(k=>!k.includes(' '));
for(const key of CREDENTIAL_KEYS) test(`a code-looking value after a bare colon without source context is redacted: ${key}`,()=>{
  const cases=[];
  for(const cased of casings(key)) for(const payload of CODE_PAYLOADS) for(const ending of CODE_ENDINGS)
    for(const left of [`${PUBLIC}\n`,`${longFiller}\n`]){
      const next=ending.includes('\n')?PUBLIC:'';
      cases.push({id:`bare code ${cased}: ${payload} ${JSON.stringify(ending)} ${left.length}`,input:`${left}${cased}: ${payload}${ending}${next}`,expected:bareTypeExpected(left,cased,key,ending)});
    }
  assert.equal(cases.length,3*23*6*2);
  assert.deepEqual(runEvery(cases),[]);
});
test('the named context-free code inputs',()=>{
  const cases=[
    ['password: Orchid.River99!','password: [REDACTED]'],['password: Orchid.River99','password: [REDACTED]'],
    ['password: correct.horse.battery','password: [REDACTED]'],['admin password: orchid.river','admin password: [REDACTED]'],
    ['passcode: orchid.river','passcode: [REDACTED]'],['pass phrase: orchid.river','pass phrase: [REDACTED]'],
    ['PASSWORD: Orchid.River','PASSWORD: [REDACTED]'],['password: orchid.river,','password: [REDACTED]'],
    ['password: Orchid(River)','password: [REDACTED]'],['password: orchid?.river','password: [REDACTED]'],
    ['password: orchid.river ?? x','password: [REDACTED]'],['password: new Orchid(river)','password: [REDACTED]'],
    ['pw: hunter2.secret','pw: [REDACTED]'],['pw: abc(def)','pw: [REDACTED]'],['password: Hunter2(x)','password: [REDACTED]'],
    ['pw: abcq.defq()','pw: [REDACTED]'],['pw: .abcq','pw: [REDACTED]'],['pw: match abc { d => e }','pw: [REDACTED]'],
    ['password: config.password','password: [REDACTED]'],['token: abcdef.ghijkl','token: [REDACTED]'],
    ['secret: orchid.river','secret: [REDACTED]'],['api_key: orchid.river','api_key: [REDACTED]'],
    ['admin password: &abcq','admin password: [REDACTED]'],['note: password: &Secret1','note: password: [REDACTED]'],
    ['pw: match a { b => c, d => e }','pw: [REDACTED]'],['pass code: match a { b => c, d => e }','pass code: [REDACTED]'],
    ['pw: f(a -> b, c)','pw: [REDACTED]'],['pw: abcq.defq(),','pw: [REDACTED],'],['pass code: orchid.river;','pass code: [REDACTED];'],
    ['(password: orchid.river)','(password: [REDACTED])'],['say (password: orchid.river)','say (password: [REDACTED])'],
    ['let x = Foo { pw: orchid.river };','let x = Foo { pw: [REDACTED] };'],['1. pw: &abcq','1. pw: [REDACTED]'],
    ['FYI: pw: &mut abcq','FYI: pw: [REDACTED]'],['note: the new pw: &abcq','note: the new pw: [REDACTED]'],
    ['Reset pw: &abcq','Reset pw: [REDACTED]'],
  ].map(([input,expected])=>({id:`named code ${input}`,input,expected}));
  assert.equal(cases.length,36);
  assert.deepEqual(runEvery(cases),[]);
});
// Source-context siblings of every code payload stay byte identical. A borrow is a type, so it stays only in a body or
// a signature.
const CODE_TYPE_FORMS=['struct X { {n}: {p} }','interface X { {n}: {p}; }','fn f({n}: {p}) {}','struct X {\n    {n}: {p},\n}'];
const CODE_VALUE_FORMS=['const x = { {n}: {p} };','const x = {{n}: {p}};','json!({ {n}: {p} })','login({n}: {p})','f(a, {n}: {p})',
  'f(\n    {n}: {p},\n)'];
for(const key of IDENTIFIER_KEYS) test(`a code value with source context keeps its output: ${key}`,()=>{
  const cases=[];
  for(const cased of casings(key)) for(const payload of CODE_PAYLOADS)
    for(const form of [...CODE_TYPE_FORMS,...(payload.startsWith('&')?[]:CODE_VALUE_FORMS)]){
      const line=form.replace('{n}',cased).replace('{p}',payload);
      for(const input of [line,`${longFiller}\n${line}`]) cases.push({id:`code control ${JSON.stringify(input)}`,input,expected:input});
    }
  assert.equal(cases.length,3*(23*4+20*6)*2);
  assert.deepEqual(runEvery(cases),[]);
});
test('the named source-context code controls',()=>{
  const cases=['struct X { pw: hunter2 }','login(password: orchid.river)','fn f(pwd: &str)','fn f(pwd: &mut Secret)',
    'fn cancel(token: &CancellationToken) {}','const opts = {password: match result { Ok(x) => x, Err(_) => return }};',
    'const opts = {password: match candidate { Some(x) => x, None => return }};','const cfg = {token: async () => getToken()};',
    'const cfg = {password: options.value ?? fallback};','const cfg = {auth: config.auth || defaultAuth};',
    'const cfg = {auth: function() { return buildAuth(); }};','let item = Record(contextKey: .workspaceID)',
    'Record(contextKey: .accountID)','const apiKey = settings.clientKey;',
    // A callee glued to the paren is call context, even in prose.
    'Note(see below, password: orchid.river',
  ].map(input=>({id:`named code control ${input}`,input,expected:input}));
  assert.deepEqual(runEvery(cases),[]);
});
// After any prefix, a value that starts with a borrow redacts whole.
for(const noun of NOUNS) test(`a prefix never keeps a value that starts with a borrow: ${noun}`,()=>{
  const cases=[];
  for(const payload of ['&str','&abcq','&Secret1','&mut abcq',"&'a str",'&mut Secret']) for(const prefix of [...PREFIXES,'']){
    const left=`${PUBLIC}\n${prefix}${noun}: `;
    cases.push({id:`prefix borrow ${JSON.stringify(prefix)} ${noun} ${payload}`,input:`${left}${payload}`,expected:`${left}${R}`});
  }
  assert.equal(cases.length,6*35);
  assert.deepEqual(run(cases),[]);
});
