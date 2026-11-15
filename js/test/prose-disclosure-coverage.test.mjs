// WASM mirror of tests/prose_disclosure_coverage.rs: the same fixtures and the
// same generated matrices with exact full-output oracles on every hosted API,
// each with a second-pass check.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';

const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const scrubber=await loadScrubber({
  bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),
  expectedManifest:artifact.manifest,
  expectedWasmSha256:artifact.files['relayscrubber_bg.wasm'],
});
const load=name=>JSON.parse(readFileSync(new URL(`../../eval/${name}`,import.meta.url)));
const coverage=load('prose_disclosure_coverage_cases.json');
const R='[REDACTED]';

const WORD_CUES=['is','is:','was','was:','is now','is now:','set to','set to:','is set to','is set to:','was set to','was set to:'];
function cueMatrix(){
  const cases=[];
  const add=(input,expected)=>cases.push({id:`cue/${JSON.stringify(input)}`,input,expected});
  for(const det of ['my ','the ','']) for(const cue of WORD_CUES){
    const left=`${det}password ${cue} `;
    add(`${left}x`,`${left}${R}`);
    add(`${left}hunter2.`,`${left}${R}.`);
    add(`${left}'x'`,`${left}'${R}'`);
    add(`${left}required`,`${left}required`);
    add(`${left}$PASSWORD`,`${left}$PASSWORD`);
  }
  for(const cue of WORD_CUES)
    for(const code of [`if password ${cue} None`,`assert password ${cue} x`,`while password ${cue} hunter2`,`self.password ${cue} x`]) add(code,code);
  for(const det of ['my ','the ']){
    for(const sep of [':',' =']){
      const left=`${det}password${sep} `;
      add(`${left}x`,`${left}${R}`);
      add(`${left}'x'`,`${left}'${R}'`);
      add(`${left}$PASSWORD`,`${left}$PASSWORD`);
      // Inherited from alpha.9 (assignment scanner), as in the Rust test.
      add(`${left}required`,`${left}${R}`);
      add(`${left}hunter2.`,`${left}${R}`);
    }
    for(const value of ['x','hunter2',"'x'"]) add(`${det}password == ${value}`,`${det}password == ${value}`);
  }
  for(const code of ['password == x','if password == x',"assert password == 'x'",'password: string']) add(code,code);
  return cases;
}
const QUOTES=[["'","'"],['"','"'],['`','`'],['“','”'],['‘','’']];
function quoteWindowCases(){
  const cases=[];
  for(const [open,close] of QUOTES) for(const interior of [1020,1021,1022,1023,1024,1025]){
    const filler='x'.repeat(interior-4);
    const input=`my password is ${open}abc\n${filler}${close} tail\nlast`;
    const expected=interior+new TextEncoder().encode(close).length<=1024
      ?`my password is ${open}${R}${close} tail\nlast`
      :`my password is ${R}\n${filler}${close} tail\nlast`;
    cases.push({id:`window/${open}/${interior}`,input,expected});
  }
  return cases;
}

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
      if(output!==entry.expected) failures.push(`${entry.id}/${api}: ${JSON.stringify(output)} want ${JSON.stringify(entry.expected)}`);
      else if(scrubber.scrubText(output)!==output) failures.push(`${entry.id}/${api}: second pass changed`);
    });
    if(new TextDecoder().decode(scrubber.scrubRecords(records).bytes)!==new TextDecoder().decode(records)) failures.push(`${entry.id}/records-second-pass`);
  }
  return failures;
}

test('every cue against same-position documentary, reference and code controls',()=>{
  const cases=cueMatrix();
  assert.equal(cases.length,3*12*5+12*4+2*(2*5+3)+4);
  assert.deepEqual(run(cases),[]);
});
test('allowlist, extent, quote and inherited fixtures',()=>{
  for(const family of ['allowlist','extent_multiword','extent_punctuation','extent_brackets','extent_conjunction','extent_two_disclosures','extent_line_boundary','extent_no_suffix','quoted','inherited_assignment'])
    assert.ok(coverage.some(c=>c.id.startsWith(`${family}-`)),family);
  for(const c of coverage){
    assert.ok(c.kind==='positive'||c.input===c.expected,c.id);
    assert.ok(c.kind!=='positive'||c.input!==c.expected,c.id);
  }
  assert.deepEqual(run(coverage),[]);
});
test('two disclosures on one line redact separately',()=>{
  const output=scrubber.scrubText('my password is x and your password is y');
  assert.equal(output.split(R).length-1,2);
  assert.equal(output,`my password is ${R} and your password is ${R}`);
});
test('a close quote within 1024 bytes is honoured, beyond it redaction stops at the line end',()=>{
  const cases=quoteWindowCases();
  assert.equal(cases.length,30);
  assert.deepEqual(run(cases),[]);
});
test('every positive prose case is idempotent',()=>{
  const inputs=[];
  for(const name of ['prose_disclosure_cases.json','alpha9_prose_credential_cases.json','prose_disclosure_coverage_cases.json'])
    inputs.push(...load(name).filter(c=>c.kind==='positive').map(c=>c.input));
  inputs.push(...[...cueMatrix(),...quoteWindowCases()].filter(c=>c.input!==c.expected).map(c=>c.input));
  assert.equal(inputs.length,431);
  const failures=[];
  for(const input of inputs){
    const once=scrubber.scrubText(input);
    if(once===input||scrubber.scrubText(once)!==once||scrubber.scrubLong(once)!==scrubber.scrubLong(input)) failures.push(JSON.stringify(input));
  }
  assert.deepEqual(failures,[]);
});
// `the password: see vault` comes from the alpha.9 assignment scanner, unchanged
// by the prose-disclosure pass (which leaves `see vault` as documentary).
test('inherited assignment output for see vault is pinned',()=>{
  assert.deepEqual(run([{id:'inherited/see-vault',input:'the password: see vault',expected:`the password: ${R} vault`}]),[]);
});
