// Per-family before/after summary of two prose-disclosure qualification runs
// (scripts/qualify-prose-disclosures.mjs). Reads only the ignored synthetic
// failures.jsonl files; counts unique generated positive cases failing any of
// text/JSON/NDJSON on each engine.
//
// Usage:
//   node scripts/summarize-pr21-families.mjs --before <dir> --after <dir> [--output summary.json]
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {disclosureCases, PUBLIC} from '../eval/disclosure-coverage.mjs';
import {scope} from '../eval/prose-disclosure-scope.mjs';

const args = process.argv.slice(2);
const option = name => {
  const i = args.indexOf(name);
  return i < 0 ? undefined : args[i + 1];
};
const runs = Object.fromEntries(['before', 'after'].filter(k => option(`--${k}`)).map(k => [k, path.resolve(option(`--${k}`))]));
assert.ok(Object.keys(runs).length, 'pass --before and/or --after <qualification output dir>');

const engines = ['native', 'wasm'];
const columns = [];
const failed = {};
for (const [label, dir] of Object.entries(runs)) {
  const report = JSON.parse(await fs.readFile(path.join(dir, 'report.json'), 'utf8'));
  const text = (await fs.readFile(path.join(dir, 'failures.jsonl'), 'utf8')).trim();
  const rows = text ? text.split('\n').map(line => JSON.parse(line)) : [];
  for (const engine of engines) {
    const column = `${label}/${engine}`;
    columns.push(column);
    failed[column] = new Set(rows.filter(r => r.engine === engine).map(r => r.caseId));
  }
  assert.equal(report.seed, 24301);
}
const generated = disclosureCases(24301, 1024);
const positives = generated.filter(c => c.expected === 'redact');
const benign = generated.filter(c => c.expected === 'preserve');

function quote(c) {
  if (c.group === 'multiple') return 'double_and_single';
  if (c.group === 'unmatched_quote') return c.quote === "'" ? 'unmatched_single' : 'unmatched_double';
  const q = c.quote ?? 'none';
  return ({none: 'unquoted', "'": 'single', '"': 'double', '`': 'backtick', '“': 'curly_double'})[q] ?? q;
}
function valueShape(c) {
  if (c.valueKind) return 'fixed/' + c.valueKind;
  if (c.group === 'seeded_mutation') {
    const [a, b] = c.spans[0];
    return 'seeded/codepoints_' + [...c.input.slice(a, b)].length;
  }
  return ({line_break: 'fixed_symbols_with_gap_break', split_connector: 'fixed_symbols_with_connector_break',
    multiline_value: 'quoted_multiline_value', unmatched_quote: 'unclosed_multiword_value', multiple: 'two_fixed_symbol_values'})[c.group];
}
function multiline(c) {
  if (c.group === 'line_break') return c.lineBreak;
  if (c.group === 'split_connector') return 'split_connector';
  if (c.group === 'multiline_value') return 'inside_quoted_value';
  const text = c.input.slice(PUBLIC.length + 1);
  return text.includes('\r\n') ? 'seeded_gap_crlf' : text.includes('\n') ? 'seeded_gap_lf' : 'inline';
}
const axes = {
  scope,
  generator_family: c => c.group,
  noun: c => c.group === 'multiple' ? 'multiple_nouns_see_multiplicity' : c.keyword,
  separator: c => c.connector ?? 'is',
  value_shape: valueShape,
  quoting: quote,
  multiline,
  multiplicity: c => c.spans.length === 2 ? 'two_disclosures' : 'one_disclosure',
};
const breakdowns = {};
for (const [axis, label] of Object.entries(axes)) {
  const groups = new Map();
  for (const c of positives) {
    const key = label(c);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(c);
  }
  breakdowns[axis] = [...groups].map(([family, cases]) => ({family, positiveCases: cases.length,
    failedCases: Object.fromEntries(columns.map(col => [col, cases.filter(c => failed[col].has(c.id)).length]))}));
  assert.equal(breakdowns[axis].reduce((n, r) => n + r.positiveCases, 0), positives.length);
}
const benignChanged = Object.fromEntries(columns.map(col => [col, benign.filter(c => failed[col].has(c.id)).length]));
const summary = {
  schema: 'relayscrubber.pr21-family-breakdown/v2', syntheticOnly: true, seed: 24301, seededMutations: 1024,
  generatedPositive: positives.length, generatedBenign: benign.length, columns, benignChanged, breakdowns,
  countSemantics: 'Unique generated positive cases failing any of text/JSON/NDJSON. Each axis partitions all generated positives; axes overlap and do not attribute cause. Exact fixtures are reported by the qualification run, not here.',
  scopeRules: 'pr21_required_short_values: one-character letters and symbols after is/was/: for the mandatory nouns; there is no minimum value length and these must be redacted. pr21_intent_subset: other inline values for the mandatory nouns plus unmatched quotes. broader_mandatory_nouns: the remaining grammar (=, is now, set to, is set to, line breaks, split connectors, multiline quotes, two disclosures, seeded mutations). optional_nouns_not_required: pass, PIN, secret, key, token.',
};
if (option('--output')) await fs.writeFile(path.resolve(option('--output')), JSON.stringify(summary, null, 2) + '\n');
let md = `Generated positives: ${positives.length}; benign changed: ${columns.map(c => `${c}=${benignChanged[c]}`).join(', ')}\n`;
for (const [axis, rows] of Object.entries(breakdowns)) {
  md += `\n## ${axis.replaceAll('_', ' ')}\n\n| Family | Positive cases | ${columns.map(c => `${c} failed`).join(' | ')} |\n| --- | ---: |${columns.map(() => ' ---: |').join('')}\n`;
  for (const row of rows) md += `| \`${row.family.replaceAll('\n', '\\n')}\` | ${row.positiveCases} | ${columns.map(c => row.failedCases[c]).join(' | ')} |\n`;
}
process.stdout.write(md);
