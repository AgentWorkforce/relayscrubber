import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {loadScrubber} from '../index.js';
const artifact = JSON.parse(readFileSync(new URL('../generated/artifact.json', import.meta.url)));
const scrubber = await loadScrubber({bytes:new Uint8Array(readFileSync(new URL('../generated/relayscrubber_bg.wasm', import.meta.url))), expectedManifest:artifact.manifest, expectedWasmSha256:artifact.files['relayscrubber_bg.wasm']});
function check(input, expected) {
  const actual = [scrubber.scrubText(input), scrubber.scrubJson(JSON.stringify({text:input})).value.text, JSON.parse(new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(JSON.stringify({text:input}))).bytes)).text];
  assert.deepEqual(actual.map(x => x === expected), [true,true,true]);
  assert.equal(scrubber.scrubText(expected), expected);
}
test('P0 explicit YAML lowercase prose preserves only syntax and later fields', () => {
  for (const [key,value] of [['password','correct horse battery staple'], ['auth','open sesame please'], ['db_password','my dog has fleas'], ['password','a correct horse battery staple'], ['auth','the open sesame phrase'], ['db_password','use my dog has fleas'], ['password','see you later'], ['auth','the phrase used for birds']]) {
    for (const quote of ['', '"', "'"]) for (const prefix of ['', 'database:\n  ']) {
      const input = `${prefix}${key}: ${quote}${value}${quote}\nnext: unchanged\n`;
      check(input, input.replace(value, '[REDACTED]'));
    }
  }
  for (const value of ['false','none','<token>','${DB_PASSWORD}','example']) for (const key of ['password','auth']) {
    const input = `${key}: ${value}\nnext: unchanged\n`; check(input,input);
  }
  check('# the password field is optional', '# the password field is optional');
});
test('P0 credential container context survives distance, nesting and scope exits', () => {
  for (const distance of [0,511,512,513,4096,1024*1024]) {
    const pad = 'x'.repeat(distance);
    for (const open of ['aws={','aws = {','"aws": {']) {
      const input = open + ' '.repeat(distance) + 'key:SYNTH_ALPHA}';
      check(input,input.replace('SYNTH_ALPHA','[REDACTED]'));
    }
    for (const nested of [false,true]) {
      for (const [open,filler,key,close] of [
        ['aws: \n',`  filler: ${pad}\n`, '  key: SYNTH_ALPHA','\nnext: unchanged'],
        ['aws = {',`filler = "${pad}", `,'key = SYNTH_ALPHA','}\nnext = unchanged'],
        ['"aws": {',`"filler": "${pad}", `,'"key": "SYNTH_ALPHA"','}, "next": "unchanged"'],
      ]) {
        const braces = open.includes('{');
        const input = open + filler + (nested ? braces ? 'nested: {' : '  nested:\n' : '') + (nested && !braces ? '  ' : '') + key + (nested && braces ? '}' : '') + close;
        check(input,input.replace('SYNTH_ALPHA','[REDACTED]'));
      }
    }
    const scoped = `idempotency_key:\n  aws:\n    filler: ${pad}\n    key: SYNTH_ALPHA`;
    check(scoped,scoped.replace("SYNTH_ALPHA","[REDACTED]"));
    for (const input of [`data={filler:"${pad}", key:SYNTH_ALPHA}`,`aws={filler:"${pad}"}; key=SYNTH_ALPHA`,`aws:\n  filler: ${pad}\nkey: SYNTH_ALPHA`,`aws={idempotency_key:{filler:"${pad}", key:SYNTH_ALPHA}}`]) check(input,input);
  }
});
test('P0 repeated nested credential keys stay bounded on WASM', () => {
  const input = `aws={ ${'nested:{key:SYNTH_ALPHA}, '.repeat(65536)}key:SYNTH_ALPHA }`;
  const start = performance.now(); const output = scrubber.scrubText(input);
  assert.ok(performance.now()-start < 10000);
  assert.ok(!output.includes('SYNTH_ALPHA'));
  assert.equal(output.split('[REDACTED]').length-1,65537);
});
