// Offline qualification of invented inputs. Never reads session stores or contacts an ingest service.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {disclosureCases, spansCovered, PUBLIC} from '../eval/disclosure-coverage.mjs';

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
if (!Number.isSafeInteger(seed) || !Number.isSafeInteger(fuzzCount) || fuzzCount < 0) throw Error('invalid matrix options');
const output = path.resolve(option('--output', path.join(root, '.task-tmp/qualification/report.json')));
const cases = disclosureCases(seed, fuzzCount);
const forms = ['text', 'json', 'ndjson'];
const sha = value => createHash('sha256').update(value).digest('hex');
const syntheticSession = '00000000-0000-4000-8000-000000000091';
function record(content) {
  return {kind: 'session_event', source: 'codex', session_id: syntheticSession,
    payload: {content, public_context: PUBLIC}};
}
function encode(input, form) {
  if (form === 'text') return input;
  if (form === 'json') return JSON.stringify(record(input));
  return JSON.stringify(record(input)) + '\n' + JSON.stringify(record(PUBLIC)) + '\n';
}
function decode(body, form) {
  if (form === 'text') return {content: body, shapeOk: true};
  const records = form === 'json' ? [JSON.parse(body)] : body.trimEnd().split('\n').map(line => JSON.parse(line));
  const expectedLength = form === 'json' ? 1 : 2;
  const shapeOk = records.length === expectedLength && records.every(r =>
    r?.kind === 'session_event' && r.source === 'codex' && r.session_id === syntheticSession &&
    typeof r.payload?.content === 'string' && r.payload.public_context === PUBLIC) &&
    (form !== 'ndjson' || records[1]?.payload?.content === PUBLIC);
  return {content: records[0]?.payload?.content, shapeOk};
}
const requests = cases.flatMap(c => forms.map(form => ({id: `${c.id}:${form}`, body: encode(c.input, form)})));
const failureExamples = [];
const allFailures = [];
const engines = {};
const decoded = new Map();
function counters() {
  return {evaluated: 0, positive: 0, benign: 0, redactionCoverageFailures: 0,
    benignChanges: 0, publicContextLost: 0, shapeFailures: 0, idempotenceFailures: 0, refusals: 0};
}
function increment(stats, flags) {
  stats.evaluated++;
  for (const [key, value] of Object.entries(flags)) if (value) stats[key]++;
}
function recordResult(engine, c, form, result) {
  let transformed = null;
  let shapeOk = false;
  if (typeof result.output === 'string') {
    try {
      const value = decode(result.output, form);
      transformed = typeof value.content === 'string' ? value.content : null;
      shapeOk = value.shapeOk;
    } catch { /* recorded below */ }
  }
  const positive = c.expected === 'redact';
  const refused = Boolean(result.error);
  const flags = {
    positive, benign: !positive,
    redactionCoverageFailures: positive && !refused && (typeof transformed !== 'string' || !spansCovered(c.input, transformed, c.spans)),
    benignChanges: !positive && !refused && transformed !== c.input,
    publicContextLost: !refused && (typeof transformed !== 'string' || !transformed.includes(PUBLIC)),
    shapeFailures: !refused && !shapeOk,
    idempotenceFailures: !refused && result.idempotent !== true,
    refusals: refused,
  };
  const state = engines[engine];
  increment(state.total, flags);
  increment(state.byForm[form] ??= counters(), flags);
  increment(state.byGroup[c.group] ??= counters(), flags);
  if (c.keyword) increment(state.byKeyword[c.keyword] ??= counters(), flags);
  if (c.connector) increment(state.byConnector[c.connector] ??= counters(), flags);
  if (c.valueKind) increment(state.byValueKind[c.valueKind] ??= counters(), flags);
  decoded.set(`${engine}:${c.id}:${form}`, {content: transformed, error: result.error ?? null});
  const failures = Object.entries(flags).filter(([k, value]) => value && !['positive', 'benign'].includes(k)).map(([k]) => k);
  if (failures.length) {
    const row = {synthetic: true, engine, caseId: c.id, form, group: c.group,
      keyword: c.keyword, connector: c.connector, valueKind: c.valueKind, quote: c.quote,
      failures, error: result.error ?? null, inputSha256: sha(c.input), outputSha256: transformed === null ? null : sha(transformed)};
    allFailures.push(row);
    const examples = failureExamples.filter(x => x.engine === engine && x.group === c.group);
    if (examples.length < 3 && !examples.some(x => x.caseId === c.id))
      failureExamples.push({...row, inventedInput: c.input, protectedSpans: c.spans, actualOutput: transformed});
  }
}
function startEngine(name, identity) {
  engines[name] = {identity, total: counters(), byForm: {}, byGroup: {}, byKeyword: {}, byConnector: {}, byValueKind: {}};
}

for (const label of ['alpha5', 'alpha9']) {
  const binary = path.join(root, `.task-tmp/native-target/debug/arlap-desktop-${label}-qualification`);
  const engine = `desktop-native-${label}`;
  const began = performance.now();
  const run = spawnSync(binary, [], {input: JSON.stringify(requests), encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: 300_000});
  if (run.error || run.status !== 0) throw Error(`native probe failed (${label}, status ${run.status})`);
  const result = JSON.parse(run.stdout);
  const version = label === 'alpha5' ? '0.5.0-alpha.5' : '0.5.0-alpha.9';
  if (result.engineName !== `relayscrubber-${version}` || result.rows.length !== requests.length) throw Error('native probe identity/count mismatch');
  startEngine(engine, {version, marker: result.engineName, binarySha256: sha(await fs.readFile(binary))});
  for (let i = 0; i < result.rows.length; i++) {
    if (result.rows[i].id !== requests[i].id) throw Error('native probe row mismatch');
    recordResult(engine, cases[Math.floor(i / forms.length)], forms[i % forms.length], result.rows[i]);
  }
  engines[engine].seconds = (performance.now() - began) / 1000;
  console.log(JSON.stringify({engine, ...engines[engine].total}));
}

for (const label of ['alpha5', 'alpha9']) {
  const pkg = label === 'alpha5' ? path.join(root, '.task-tmp/alpha5-release/package') : path.join(root, 'js');
  const artifact = JSON.parse(await fs.readFile(path.join(pkg, 'generated/artifact.json'), 'utf8'));
  const bytes = await fs.readFile(path.join(pkg, 'generated/relayscrubber_bg.wasm'));
  const version = label === 'alpha5' ? '0.5.0-alpha.5' : '0.5.0-alpha.9';
  if (artifact.manifest.crateVersion !== version || sha(bytes) !== artifact.files['relayscrubber_bg.wasm']) throw Error('WASM artifact identity mismatch');
  const api = await import(pathToFileURL(path.join(pkg, 'index.js')));
  const scrubber = await api.loadScrubber({bytes, expectedManifest: artifact.manifest, expectedWasmSha256: artifact.files['relayscrubber_bg.wasm']});
  const engine = `pipeline-wasm-${label}`;
  startEngine(engine, {version, manifest: artifact.manifest, wasmSha256: sha(bytes)});
  const began = performance.now();
  const apply = (body, form) => form === 'text' ? scrubber.scrubTextChecked(body)
    : form === 'json' ? scrubber.scrubJson(body).jsonText
      : new TextDecoder().decode(scrubber.scrubRecords(new TextEncoder().encode(body)).bytes);
  for (const c of cases) for (const form of forms) {
    let result;
    try {
      const outputBody = apply(encode(c.input, form), form);
      result = {output: outputBody, idempotent: apply(outputBody, form) === outputBody};
    } catch (error) { result = {error: error.code ?? error.name}; }
    recordResult(engine, c, form, result);
  }
  engines[engine].seconds = (performance.now() - began) / 1000;
  console.log(JSON.stringify({engine, ...engines[engine].total}));
}

const parity = {};
for (const label of ['alpha5', 'alpha9']) {
  let differences = 0;
  for (const c of cases) for (const form of forms) {
    const native = decoded.get(`desktop-native-${label}:${c.id}:${form}`);
    const wasm = decoded.get(`pipeline-wasm-${label}:${c.id}:${form}`);
    if (JSON.stringify(native) !== JSON.stringify(wasm)) differences++;
  }
  parity[label] = {evaluated: requests.length, differences};
}
const failureKeys = ['redactionCoverageFailures', 'benignChanges', 'publicContextLost', 'shapeFailures', 'idempotenceFailures', 'refusals'];
const candidatePass = ['desktop-native-alpha9', 'pipeline-wasm-alpha9'].every(name => failureKeys.every(key => engines[name].total[key] === 0)) && parity.alpha9.differences === 0;
const report = {
  schema: 'relayscrubber.arlap-disclosure-qualification/v1', syntheticOnly: true,
  candidateSourceRevision: 'b54745161cade161318e6e1dc9ca5486b91c474d',
  generatedAt: new Date().toISOString(), seed, fuzzCount, cases: cases.length,
  corpusSha256: sha(JSON.stringify(cases)), forms,
  fixtureBaseline: {desktopVersion: '2026.11.1-beta.6', desktopBuild: 306,
    desktopSourceRevision: '06164e88bcf7bd77f49d5979527f0d5aafb8b450',
    sessionsImage: 'ghcr.io/agentworkforce/sessions-pipeline@sha256:77022c5b6a1d30f96f921d703eb27a1acada8ec273ad84aebdde24f8eddce305',
    sessionsSourceRevision: '7e9b2f0f6b1af7af9b49087c4f4677f5d6d1a496', actualUpgrade: 'alpha.5 -> alpha.9'},
  nativeProbeProvenance: JSON.parse(await fs.readFile(path.join(root, '.task-tmp/native-probe-provenance.json'), 'utf8')),
  engines, parity, candidatePass, status: candidatePass ? 'pass' : 'fail',
  failureExamples,
  limits: [
    'Offline invented fixtures only; no sessions, account tokens, network ingest, fixture repin or deployment.',
    'Native calls use the shipped Desktop scrub seam; the candidate changes only its version marker and crate dependency in ignored probes. Queue/transport integration is not exercised.',
    'WASM calls exercise the identity-verified package APIs including scrubRecords used by pipeline sealing; S3 persistence, pipeline readers and server invocation wiring are not exercised.',
    'The alpha.9 WASM is built locally from the pinned candidate; its hash is reported and is not relabelled as a published artifact.',
    'Generated tests sample a defined grammar and cannot prove detection of every possible natural-language secret.',
    'Broader span coverage may be safe but lose public context; benign changes and lost public context are separate failures.',
  ],
};
await fs.mkdir(path.dirname(output), {recursive: true});
await fs.writeFile(output, JSON.stringify(report, null, 2) + '\n');
await fs.writeFile(path.join(path.dirname(output), 'failures.jsonl'), allFailures.map(x => JSON.stringify(x)).join('\n') + '\n');
await fs.writeFile(path.join(path.dirname(output), 'synthetic-corpus.json'), JSON.stringify(cases) + '\n');
console.log(JSON.stringify({status: report.status, cases: cases.length, observations: cases.length * forms.length * 4, parity, output}));
process.exitCode = candidatePass ? 0 : 1;
