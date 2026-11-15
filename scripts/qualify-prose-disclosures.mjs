// Offline qualification of invented prose-disclosure inputs on the native and
// WASM engines built from this checkout. Never reads session stores or
// contacts a network service.
//
// Prerequisites (from the repository root):
//   cargo build --example disclosure_probe
//   bash scripts/build-wasm.sh
// Usage:
//   node scripts/qualify-prose-disclosures.mjs [--output .task-tmp/prose-qualification/report.json]
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {disclosureCases, spansCovered, PUBLIC} from '../eval/disclosure-coverage.mjs';
import {SUPPORTED, scope} from '../eval/prose-disclosure-scope.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (name, fallback) => {
  const i = args.indexOf(name);
  if (i < 0) return fallback;
  if (!args[i + 1] || args[i + 1].startsWith('--')) throw Error(`missing ${name}`);
  return args[i + 1];
};
const seed = Number(option('--seed', '24301'));
const fuzzCount = Number(option('--fuzz-count', '1024'));
const output = path.resolve(option('--output', path.join(root, '.task-tmp/prose-qualification/report.json')));
const probe = path.resolve(option('--probe', path.join(root, 'target/debug/examples/disclosure_probe')));
const sha = value => createHash('sha256').update(value).digest('hex');

const generated = disclosureCases(seed, fuzzCount);
const fixtures = [];
for (const file of ['eval/alpha9_prose_credential_cases.json', 'eval/prose_disclosure_cases.json', 'eval/prose_disclosure_coverage_cases.json'])
  for (const f of JSON.parse(await fs.readFile(path.join(root, file), 'utf8')))
    fixtures.push({id: `${path.basename(file, '.json')}/${f.id}`, group: 'exact_fixture', kind: f.kind,
      expected: f.kind === 'positive' ? 'redact' : 'preserve', input: f.input, exact: f.expected});
const cases = [...generated, ...fixtures];

const forms = ['text', 'json', 'ndjson'];
const session = '00000000-0000-4000-8000-000000000091';
const record = content => ({kind: 'session_event', source: 'codex', session_id: session, payload: {content, public_context: PUBLIC}});
function encode(input, form) {
  if (form === 'text') return input;
  if (form === 'json') return JSON.stringify(record(input));
  return JSON.stringify(record(input)) + '\n' + JSON.stringify(record(PUBLIC)) + '\n';
}
function decode(body, form) {
  if (form === 'text') return {content: body, shapeOk: true};
  const records = form === 'json' ? [JSON.parse(body)] : body.trimEnd().split('\n').map(line => JSON.parse(line));
  const shapeOk = records.length === (form === 'json' ? 1 : 2) && records.every(r =>
    r?.kind === 'session_event' && r.source === 'codex' && r.session_id === session &&
    typeof r.payload?.content === 'string' && r.payload.public_context === PUBLIC) &&
    (form !== 'ndjson' || records[1].payload.content === PUBLIC);
  return {content: records[0]?.payload?.content, shapeOk};
}

const counters = () => ({evaluated: 0, failedCases: 0, redactionCoverageFailures: 0, exactMismatches: 0, benignChanges: 0,
  publicContextLost: 0, shapeFailures: 0, idempotenceFailures: 0, refusals: 0});
const engines = {}, raw = new Map(), failures = [];
function evaluate(engine, c, form, result) {
  let content = null, shapeOk = false;
  if (typeof result.output === 'string') {
    try { const d = decode(result.output, form); content = typeof d.content === 'string' ? d.content : null; shapeOk = d.shapeOk; } catch { /* shape failure */ }
  }
  const refused = Boolean(result.error), positive = c.expected === 'redact', fixture = c.group === 'exact_fixture';
  const flags = {
    redactionCoverageFailures: positive && !fixture && !refused && (content === null || !spansCovered(c.input, content, c.spans)),
    exactMismatches: fixture && !refused && content !== c.exact,
    benignChanges: !positive && !refused && content !== c.input,
    publicContextLost: !fixture && !refused && (content === null || !content.includes(PUBLIC)),
    shapeFailures: !refused && !shapeOk,
    idempotenceFailures: !refused && result.idempotent !== true,
    refusals: refused,
  };
  raw.set(`${engine}:${c.id}:${form}`, result.output ?? `error:${result.error}`);
  const failed = Object.keys(flags).filter(k => flags[k]);
  const e = engines[engine];
  for (const bucket of [e.byForm[form] ??= counters(), e.byScope[scope(c)] ??= counters(), e.byGroup[c.group] ??= counters()]) {
    bucket.evaluated++;
    for (const k of failed) bucket[k]++;
  }
  if (failed.length) {
    (e.failed[scope(c)] ??= new Set()).add(c.id);
    (e.failedByGroup[c.group] ??= new Set()).add(c.id);
    failures.push({engine, caseId: c.id, form, scope: scope(c), group: c.group, keyword: c.keyword, connector: c.connector,
      valueKind: c.valueKind, quote: c.quote, failed, input: c.input.length <= 300 ? c.input : `${c.input.slice(0, 200)}...`,
      output: content === null ? null : content.length <= 300 ? content : `${content.slice(0, 200)}...`, error: result.error ?? null});
  }
}
const start = (name, identity) => { engines[name] = {identity, byForm: {}, byScope: {}, byGroup: {}, failed: {}, failedByGroup: {}}; };

const requests = cases.flatMap(c => forms.map(form => ({id: `${c.id}:${form}`, form, body: encode(c.input, form)})));
const run = spawnSync(probe, [], {input: JSON.stringify(requests), encoding: 'utf8', maxBuffer: 512 * 1024 * 1024, timeout: 600_000});
if (run.error || run.status !== 0) throw Error(`native probe failed (status ${run.status}): ${run.error ?? run.stderr}`);
const nativeResult = JSON.parse(run.stdout);
if (nativeResult.rows.length !== requests.length) throw Error('native probe row count mismatch');
start('native', {engineName: nativeResult.engineName, probeSha256: sha(await fs.readFile(probe))});
nativeResult.rows.forEach((row, i) => {
  if (row.id !== requests[i].id) throw Error('native probe row mismatch');
  evaluate('native', cases[Math.floor(i / forms.length)], forms[i % forms.length], row);
});

const pkg = path.join(root, 'js');
const artifact = JSON.parse(await fs.readFile(path.join(pkg, 'generated/artifact.json'), 'utf8'));
const bytes = await fs.readFile(path.join(pkg, 'generated/relayscrubber_bg.wasm'));
if (sha(bytes) !== artifact.files['relayscrubber_bg.wasm']) throw Error('WASM artifact identity mismatch');
const api = await import(pathToFileURL(path.join(pkg, 'index.js')));
const scrubber = await api.loadScrubber({bytes, expectedManifest: artifact.manifest, expectedWasmSha256: artifact.files['relayscrubber_bg.wasm']});
start('wasm', {crateVersion: artifact.manifest.crateVersion, wasmSha256: sha(bytes)});
const apply = (body, form) => form === 'text' ? scrubber.scrubTextChecked(body)
  : form === 'json' ? scrubber.scrubJson(body).jsonText
    : new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(body)).bytes);
for (const c of cases) for (const form of forms) {
  let result;
  try { const out = apply(encode(c.input, form), form); result = {output: out, idempotent: apply(out, form) === out}; }
  catch (error) { result = {error: error.code ?? error.name}; }
  evaluate('wasm', c, form, result);
}

let differences = 0;
const parityExamples = [];
for (const c of cases) for (const form of forms) {
  const a = raw.get(`native:${c.id}:${form}`), b = raw.get(`wasm:${c.id}:${form}`);
  if (a !== b) { differences++; if (parityExamples.length < 5) parityExamples.push({caseId: c.id, form, native: a.slice(0, 200), wasm: b.slice(0, 200)}); }
}
const scopeCases = {};
for (const c of cases) scopeCases[scope(c)] = (scopeCases[scope(c)] ?? 0) + 1;
const report = {
  schema: 'relayscrubber.prose-disclosure-qualification/v1', syntheticOnly: true, generatedAt: new Date().toISOString(),
  seed, fuzzCount, cases: cases.length, generatedCases: generated.length, fixtureCases: fixtures.length,
  corpusSha256: sha(JSON.stringify(cases)), forms, supportedNouns: [...SUPPORTED], scopeCases,
  engines: Object.fromEntries(Object.entries(engines).map(([name, e]) => [name, {
    identity: e.identity, byForm: e.byForm, byScope: e.byScope, byGroup: e.byGroup,
    failedCasesByScope: Object.fromEntries(Object.entries(e.failed).map(([k, v]) => [k, v.size])),
    failedCasesByGroup: Object.fromEntries(Object.entries(e.failedByGroup).map(([k, v]) => [k, v.size])),
  }])),
  parity: {evaluated: requests.length, rawByteDifferences: differences, examples: parityExamples},
};
await fs.mkdir(path.dirname(output), {recursive: true});
await fs.writeFile(output, JSON.stringify(report, null, 2) + '\n');
await fs.writeFile(path.join(path.dirname(output), 'failures.jsonl'), failures.map(x => JSON.stringify(x)).join('\n') + '\n');
for (const name of Object.keys(engines)) console.log(name, JSON.stringify(report.engines[name].failedCasesByScope));
console.log(JSON.stringify({cases: cases.length, scopeCases, parity: report.parity.rawByteDifferences, output}));
