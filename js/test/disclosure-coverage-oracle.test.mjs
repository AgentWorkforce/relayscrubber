import test from 'node:test';
import assert from 'node:assert/strict';
import {disclosureCases, spansCovered} from '../../eval/disclosure-coverage.mjs';

test('a short secret is distinguished from the same letter in public context', () => {
  const input = 'a password is a';
  assert.equal(spansCovered(input, 'a password is [REDACTED]', [[14, 15]]), true);
  assert.equal(spansCovered(input, input, [[14, 15]]), false);
});
test('partial prefixes and suffixes do not qualify as complete redaction', () => {
  const input = 'password is violet river';
  const spans = [[12, input.length]];
  assert.equal(spansCovered(input, 'password is [REDACTED] river', spans), false);
  assert.equal(spansCovered(input, 'password is violet [REDACTED]', spans), false);
  assert.equal(spansCovered(input, 'password is [REDACTED]', spans), true);
});
test('all disclosures on one line must be covered', () => {
  const input = 'password is aaa; token is bbb';
  const spans = [[12, 15], [26, 29]];
  assert.equal(spansCovered(input, 'password is [REDACTED]; token is bbb', spans), false);
  assert.equal(spansCovered(input, 'password is [REDACTED]; token is [REDACTED]', spans), true);
});
test('broader fail-closed redaction is safe but is measured separately for precision', () => {
  const input = 'public\npassword is abc';
  assert.equal(spansCovered(input, '[REDACTED]', [[19, 22]]), true);
  assert.equal(spansCovered(input, 'public\n[REDACTED]', [[19, 22]]), true);
});
test('unicode and repeated unchanged literals retain positional coverage', () => {
  const input = 'public\nPIN is 松🔐é';
  assert.equal(spansCovered(input, 'public\nPIN is [REDACTED]', [[14, input.length]]), true);
  assert.equal(spansCovered(input, 'public\nPIN is [REDACTED]é', [[14, input.length]]), false);
});
test('generated inputs are deterministic, varied and have valid protected spans', () => {
  const cases = disclosureCases(24301, 32);
  assert.deepEqual(cases, disclosureCases(24301, 32));
  assert.notDeepEqual(cases, disclosureCases(24302, 32));
  for (const c of cases) {
    for (const [start, end] of c.spans) assert.ok(start >= 0 && end > start && end <= c.input.length, c.id);
    if (c.expected === 'redact') assert.equal(spansCovered(c.input, c.input, c.spans), false, c.id);
  }
});
test('benign code references retain valid case-sensitive syntax', () => {
  const cases = disclosureCases(24301, 0);
  for (const c of cases.filter(c => c.expected === 'preserve')) {
    if (c.group === 'type_annotation') assert.match(c.input, /\nconst \w+: string$/);
    if (c.input.includes('process.')) assert.ok(c.input.endsWith('process.env.PASSWORD'));
  }
  assert.ok(cases.some(c => c.input.includes('MY PASSWORD IS')));
});
