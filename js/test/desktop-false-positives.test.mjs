import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';

// Mirror of tests/desktop_false_positives.rs through the WASM artifact.
const artifact=JSON.parse(readFileSync(new URL('../generated/artifact.json',import.meta.url)));
const scrubber=await loadScrubber({
  bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm',import.meta.url))),
  expectedManifest:artifact.manifest,
  expectedWasmSha256:artifact.files['relayscrubber_bg.wasm'],
});
const fixture=JSON.parse(readFileSync(new URL('../../eval/desktop_false_positive_cases.json',import.meta.url)));
const R='[REDACTED]';

function outputs(input){
  const raw=JSON.stringify({text:input});
  const records=scrubber.scrubRecords(new TextEncoder().encode(raw+'\n')).bytes;
  return [
    ['checked',scrubber.scrubTextChecked(input)],
    ['text',scrubber.scrubText(input)],
    ['long',scrubber.scrubLong(input)],
    ['json',scrubber.scrubJson(raw).value.text],
    ['records',JSON.parse(new TextDecoder().decode(records)).text],
  ];
}

function check(id,input,accept){
  const failures=[];
  const all=outputs(input);
  for(const [api,output] of all){
    if(output!==all[0][1]) failures.push(`${id}/${api}: parity ${JSON.stringify(output)}`);
    const why=accept(output);
    if(why) failures.push(`${id}/${api}: ${JSON.stringify(input)} -> ${JSON.stringify(output)}: ${why}`);
    if(scrubber.scrubText(output)!==output) failures.push(`${id}/${api}: second pass changed`);
  }
  return failures;
}
const preserved=input=>output=>output===input?null:'type position must be byte identical';
const finish=failures=>assert.deepEqual(failures.slice(0,40),[]);

test('recall controls redact on every API',()=>{
  finish(fixture.recall.flatMap(c=>check(c.id,c.input,o=>
    o.includes(c.secret)?`secret ${JSON.stringify(c.secret)} survived`:o.includes(R)?null:'no marker')));
});

test('precision controls already preserved stay preserved',()=>{
  finish(fixture.precision.filter(c=>c.alpha10===c.input).flatMap(c=>check(c.id,c.input,preserved(c.input))));
});

test('type positions after Key members are preserved',()=>{
  finish(fixture.precision.filter(c=>c.alpha10!==c.input).flatMap(c=>check(c.id,c.input,preserved(c.input))));
});

test('prose is never replaced wholesale',()=>{
  finish(fixture.whole_body.flatMap(c=>check(c.id,c.input,o=>
    o===R?'whole body replaced by one marker':!o.startsWith(c.prefix)?'benign prefix lost':o.includes(R)?null:'credential cue no longer redacts')));
});

// Exact outputs, mirrored from tests/pass_budget_alpha11.rs.
const exact=[
  ["pwd: ' let's I'll you're won't here","pwd: '[REDACTED]"],
  ["Summary: the deploy worked. I didn't touch the PASSWORD=' line because it's generated, and that's fine; we'll revisit it once you're back and I've rotated the key.","Summary: the deploy worked. I didn't touch the PASSWORD='[REDACTED]"],
  ["Here's what I found. The login form's pwd: ' placeholder isn't rendered, so it's blank. I'll fix that; we're close and you're unblocked.","Here's what I found. The login form's pwd: '[REDACTED]"],
  ["The password: ' it's in 1Password, I'll share it, don't worry, we're fine, you're set","The password: '[REDACTED]"],
  ['Note: the deploy finished and tests pass.\npassword=""D""\n=\n"= ','Note: the deploy finished and tests pass.\npassword="[REDACTED]'],
  ["password='ab'cd' and more","password='[REDACTED]"],
  ["The password: 'Zx9q's7Lm' ok","The password: '[REDACTED]"],
  ["token: 'pass key we and placeholder PASSWORD='SYNTHq8Zr4TfX2wLm key form the back","token: '[REDACTED]"],
  ["We're done. password: 'SYNTHq8Zr4TfX2wLm' and that's it","We're done. password: '[REDACTED]' and that's it"],
  ["I said 'don't' here","I said 'don't' here"],
  ["sep = ':'\nname = 'it's'","sep = ':'\nname = 'it's'"],
  // Glued quote openers and contractions, mirrored from the same file.
  ["echo f'x'\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'","echo f'x'\nlogin --password '[REDACTED]' --note 'hello'"],
  ["echo f'x'\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm'","echo f'x'\nlogin --password '[REDACTED]'"],
  ["x = b'abc'\ny = 2\n\nlogin --token 'correct horse SYNTHq8Zr4TfX2wLm' end","x = b'abc'\ny = 2\n\nlogin --token '[REDACTED]' end"],
  ["git commit -m'wip'\nmysql -u root --password 'SYNTHq8Zr4TfX2wLm' -e 'select 1' db","git commit -m'wip'\nmysql -u root --password '[REDACTED]' -e 'select 1' db"],
  ["print(f'hi')\nAuthorization: Bearer 'SYNTHq8Zr4TfX2wLm' 'x' trailing","print(f'hi')\nAuthorization: [REDACTED]"],
  ["echo f'x' && login --password 'correct horse SYNTHq8Zr4TfX2wLm' --note 'hello'","echo f'x' && login --password '[REDACTED]' --note 'hello'"],
  ["sed -i's/a/b/' f\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm' 'second' 'third' end","sed -i's/a/b/' f\nlogin --password '[REDACTED]' 'second' 'third' end"],
  ["x = b's'\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'","x = b's'\nlogin --password '[REDACTED]' --note 'hello'"],
  ["y = f'd'\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'","y = f'd'\nlogin --password '[REDACTED]' --note 'hello'"],
  ["git commit -m'wip\n\nmore'\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'","git commit -m'wip\n\nmore'\nlogin --password '[REDACTED]' --note 'hello'"],
  ["it's the dogs' bowl\nlogin --password 'SYNTHq8Zr4TfX2wLm' --note 'hello'","it's the dogs' bowl\nlogin --password '[REDACTED]' --note 'hello'"],
  ["curl -H'Accept: text/plain' -H 'Authorization: Bearer SYNTHq8Zr4TfX2wLm' https://example.test/a\necho done","curl -H'Accept: text/plain' -H 'Authorization: [REDACTED]' https://example.test/a\necho done"],
  ["x = b'abc'\nrun('password=SYNTHq8Zr4TfX2wLm', 1)\nprint('ok')","x = b'abc'\nrun('password=[REDACTED]', 1)\nprint('ok')"],
  ["it's\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm' --note 'hello'","it's\nlogin --password '[REDACTED]' --note 'hello'"],
  ["I can't\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm' --note 'hello'","I can't\nlogin --password '[REDACTED]' --note 'hello'"],
  ["I'm sure. I'd say I've\nlogin --password 'correct horse SYNTHq8Zr4TfX2wLm' --note 'hello'","I'm sure. I'd say I've\nlogin --password '[REDACTED]' --note 'hello'"],
  ["{'user':'o'neil','password':'a b SYNTHq8Zr4TfX2wLm','x':1}","{'user':'o'neil','password':'[REDACTED]','x':1}"],
  ["I can't log in, password: 'a b SYNTHq8Zr4TfX2wLm' doesn't work","I can't log in, password: '[REDACTED]' doesn't work"],
  ["api_key='I've got SYNTHq8Zr4TfX2wLm","api_key='[REDACTED]"],
  ["token: 'abc'def'SYNTHq8Zr4TfX2wLm'","token: '[REDACTED]'"],
  ["db_password='3'SYNTHq8Zr4TfX2wLm","db_password='[REDACTED]"],
  ["the 90's were fine. password='SYNTHq8Zr4TfX2wLm' and more text here","the 90's were fine. password='[REDACTED]' and more text here"],
  ["the dogs' bowl. password='SYNTHq8Zr4TfX2wLm' and more text here","the dogs' bowl. password='[REDACTED]' and more text here"],
  ["He said 'it's fine' and password='SYNTHq8Zr4TfX2wLm' and more text here","He said 'it's fine' and password='[REDACTED]' and more text here"],
  // Possessives and contractions inside quoted arguments.
  ["echo 'token=I've got SYNTHYcyRiBDEwjsYZa'","echo 'token=[REDACTED]'"],
  ["curl -H 'X-Api-Key: I've got SYNTHYcyRiBDEwjsYZa' https://example.test","curl -H 'X-Api-Key: [REDACTED]' https://example.test"],
  ["echo 'token=I've got SYNTHq8Zr4TfX2wLm'","echo 'token=[REDACTED]'"],
  ["echo 'token=I've got SYNTHq8Zr4TfX2wLm' --note 'hello'","echo 'token=[REDACTED]' --note 'hello'"],
  ["curl -H 'X-Api-Key: I've got SYNTHq8Zr4TfX2wLm' https://example.test/a\necho done","curl -H 'X-Api-Key: [REDACTED]' https://example.test/a\necho done"],
  ["SELECT N'nchar'\n\nthe dogs' bowl && login --token 'SYNTHq8Zr4TfX2wLm' 'x' trailing","SELECT N'nchar'\n\nthe dogs' bowl && login --token '[REDACTED]' 'x' trailing"],
  ["y = f'd'\nthe users' list tool --secret 'SYNTHq8Zr4TfX2wLm' and it's fine","y = f'd'\nthe users' list tool --secret '[REDACTED]' and it's fine"],
  ["you'll see; x = 'a' + 'b'; the dogs' bowl\nlogin --token 'SYNTHq8Zr4TfX2wLm'","you'll see; x = 'a' + 'b'; the dogs' bowl\nlogin --token '[REDACTED]'"],
];

test('pass-budget witnesses have exact outputs on every API',()=>{
  finish(exact.flatMap(([input,expected])=>check(input.slice(0,24),input,o=>
    o===expected?null:`expected ${JSON.stringify(expected)}`)));
});
