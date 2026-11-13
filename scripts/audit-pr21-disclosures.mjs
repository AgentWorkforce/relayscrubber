// Synthetic, offline audit. Uses existing native binaries and supplied hosted bytes.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {disclosureCases, spansCovered, PUBLIC, REDACTION} from '../eval/disclosure-coverage.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (key, fallback) => {const i = args.indexOf(key); return i < 0 ? fallback : args[i + 1];};
const worker = option('--adapter-worker', null);
const pipeline = path.resolve(option('--pipeline-source', '.task-tmp/pipeline-7e9b2f0f'));
const candidate = path.resolve(option('--candidate-package', '.task-tmp/hosted-b547451/extracted/package'));
const output = path.resolve(option('--output', '.task-tmp/pr21-hosted-audit/report.json'));
const sha = value => createHash('sha256').update(value).digest('hex');
const supported = new Set(['password', 'passcode', 'passphrase', 'pw']);
const cases = disclosureCases().map(c => ({...c, scope: c.expected === 'preserve' ? 'benign_controls'
  : c.group === 'grammar' && supported.has(c.keyword) && ['is', 'was', ':'].includes(c.connector)
    && !['short_letter', 'short_symbol'].includes(c.valueKind) && !(c.valueKind === 'spaces' && c.quote === 'none')
    || c.group === 'unmatched_quote' && supported.has(c.keyword) ? 'pr21_intent_subset' : 'broader_grammar_pending_authorization'}));
const authors = JSON.parse(await fs.readFile(path.join(root, 'eval/alpha9_prose_credential_cases.json')));
for (const c of authors) {
  const at = c.expected.indexOf(REDACTION), before = at < 0 ? '' : c.expected.slice(0, at), after = at < 0 ? '' : c.expected.slice(at + REDACTION.length);
  if (c.kind === 'positive' && (!c.input.startsWith(before) || !c.input.endsWith(after))) throw Error('author fixture cannot be represented by one span');
  cases.push({id: 'author-' + c.id, input: c.input, expected: c.kind === 'positive' ? 'redact' : 'preserve',
    expectedOutput: c.expected, spans: c.kind === 'positive' ? [[before.length, c.input.length - after.length]] : [],
    group: 'author_fixtures', scope: 'pr21_author_fixtures'});
}
const forms = ['text', 'json', 'ndjson'];
const record = content => ({kind: 'session_event', source: 'codex', payload: {content, public_context: PUBLIC}});
const encode = (c, form) => form === 'text' ? c.input : JSON.stringify(record(c.input)) + (form === 'ndjson' ? '\n' : '');
const decode = (body, form) => form === 'text' ? body : JSON.parse(body.trim()).payload.content;
const requests = cases.flatMap(c => forms.map(form => ({id: `${c.id}:${form}`, body: encode(c, form)})));
const engines = {}, observed = new Map(), failures = [];
function result(name, c, form, r) {
  let content = null;
  try {if (typeof r.output === 'string') content = decode(r.output, form);} catch {}
  const flags = [];
  if (r.error) flags.push('refusal');
  else {
    if (typeof content !== 'string') flags.push('shape');
    if (c.expected === 'redact' && (typeof content !== 'string' || !spansCovered(c.input, content, c.spans))) flags.push('coverage');
    if (c.expected === 'preserve' && content !== c.input) flags.push('benign_changed');
    if (c.expectedOutput !== undefined && content !== c.expectedOutput) flags.push('exact_expected_output');
    if (!r.idempotent) flags.push('idempotence');
  }
  const s = engines[name].scopes[c.scope] ??= {observations: 0, cases: new Set(), failingCases: new Set(), failures: {}};
  s.observations++; s.cases.add(c.id);
  for (const flag of flags) {s.failingCases.add(c.id); s.failures[flag] = (s.failures[flag] ?? 0) + 1;}
  observed.set(`${name}:${c.id}:${form}`, {content, error: r.error ?? null});
  if (flags.length) failures.push({engine: name, caseId: c.id, scope: c.scope, group: c.group, form,
    flags, inputSha256: sha(c.input), outputSha256: content === null ? null : sha(content)});
}
for (const label of worker ? [] : ['alpha5', 'alpha9']) {
  const name = 'desktop-native-' + label, binary = path.join(root, `.task-tmp/native-target/debug/arlap-desktop-${label}-qualification`);
  const r = spawnSync(binary, [], {input: JSON.stringify(requests), encoding: 'utf8', timeout: 300000, maxBuffer: 256 * 1024 * 1024});
  if (r.error || r.status) throw Error('existing native probe failed: ' + label);
  const v = JSON.parse(r.stdout);
  if (v.rows.length !== requests.length || v.engineName !== `relayscrubber-0.5.0-alpha.${label === 'alpha5' ? '5' : '9'}`) throw Error('native identity/count');
  engines[name] = {identity: {marker: v.engineName, binarySha256: sha(await fs.readFile(binary))}, scopes: {}};
  for (let i = 0; i < v.rows.length; i++) {
    if (v.rows[i].id !== requests[i].id) throw Error('native row identity');
    result(name, cases[Math.floor(i / 3)], forms[i % 3], v.rows[i]);
  }
  console.log(name + ' complete');
}
const adapter = worker ? await import(pathToFileURL(path.join(pipeline, 'packages/pipeline/src/lib/scrub-engine/bindgen-engine.ts'))) : null;
const originalPin = worker ? JSON.parse(await fs.readFile(path.join(pipeline, 'packages/pipeline/scrub-bindgen-pin.json'))) : null;
for (const label of worker ? [worker] : []) {
  const pkg = label === 'alpha5' ? path.join(root, '.task-tmp/alpha5-release/package') : candidate;
  const artifactBytes = await fs.readFile(path.join(pkg, 'generated/artifact.json'));
  const artifact = JSON.parse(artifactBytes);
  const pin = label === 'alpha5' ? originalPin : {...originalPin,
    package_version: '0.5.0-alpha.9', manifest: artifact.manifest, scrub_profile: artifact.manifest.scrubProfile,
    wasm_sha256: artifact.files['relayscrubber_bg.wasm'], glue_sha256: artifact.files['relayscrubber.js'], loader_sha256: sha(await fs.readFile(path.join(pkg, 'index.js'))),
    // Test-only schema label: no such GitHub release is asserted or created.
    release: {source: 'github-release', repository: 'AgentWorkforce/relayscrubber', tag: 'UNRELEASED-CI-43394654201',
      tarball: 'agentworkforce-relayscrubber-0.5.0-alpha.9.tgz', tarball_sha256: 'd7eb1702fe73092d6607efe2481d67c1b3a97a06a90505afd2c5d5b6dec7db68',
      sha256sums: {'artifact.json': sha(artifactBytes)}}};
  if (label === 'alpha9' && (sha(artifactBytes) !== 'b6f3f5b93f58e9fb0725825cc6fc85e046221d5ded006e3cb8f27a91318659ef'
    || pin.wasm_sha256 !== '008406d7ed78ff85bea510544ceaf0818477f277f0705a4d61a56783ef7117f4'
    || pin.manifest.rulesetSourceSha256 !== '291a6b373388b7bc5295091d1bcbc13a2e8c64e37b2bfe0d06b2dc4f12df32c9')) throw Error('hosted candidate identity');
  const engine = await adapter.initBindgenScrubEngine({pin, readerMaxRuleset: 10, readArtifact: (_, relative) => fs.readFile(path.join(pkg, relative))});
  const name = 'pipeline-adapter-' + label;
  engines[name] = {identity: {version: pin.package_version, manifest: pin.manifest, marker: engine.marker, wasmSha256: pin.wasm_sha256}, scopes: {}};
  const apply = (body, form) => form === 'text' ? engine.scrubText(body)
    : form === 'json' ? JSON.stringify(engine.scrubJson(JSON.parse(body)))
      : new TextDecoder().decode(engine.scrubRecords(new TextEncoder().encode(body)).scrubbed);
  for (const c of cases) for (const form of forms) {
    let r;
    try {const value = apply(encode(c, form), form); r = {output: value, idempotent: apply(value, form) === value};}
    catch (e) {r = {error: e.code ?? e.reason ?? e.name};}
    result(name, c, form, r);
  }
  console.error(name + ' complete');
}
if (worker) {
  for (const engine of Object.values(engines)) for (const s of Object.values(engine.scopes)) {
    s.cases = s.cases.size; s.failingCases = s.failingCases.size;
  }
  await fs.writeFile(option('--worker-output'), JSON.stringify({engines, observed: [...observed], failures}));
  process.exit(0);
}
// Separate processes are required: identical verified glue bytes share a data:
// module URL, whose initialization cannot be reset to a second WASM in-process.
await fs.mkdir(path.dirname(output), {recursive: true});
for (const label of ['alpha5', 'alpha9']) {
  const workerOutput = path.join(path.dirname(output), `adapter-${label}.private-synthetic.json`);
  const run = spawnSync(process.execPath, [...process.execArgv, fileURLToPath(import.meta.url), ...args,
    '--adapter-worker', label, '--worker-output', workerOutput], {encoding: 'utf8', timeout: 300000, maxBuffer: 256 * 1024 * 1024});
  if (run.error || run.status) throw Error(`adapter worker failed: ${label}: ${run.stderr}`);
  const r = JSON.parse(await fs.readFile(workerOutput));
  Object.assign(engines, r.engines);
  for (const [key, value] of r.observed) observed.set(key, value);
  failures.push(...r.failures);
  console.log('pipeline-adapter-' + label + ' complete');
}
const parity = {};
for (const label of ['alpha5', 'alpha9']) {
  let differences = 0;
  for (const c of cases) for (const form of forms)
    if (JSON.stringify(observed.get(`desktop-native-${label}:${c.id}:${form}`)) !== JSON.stringify(observed.get(`pipeline-adapter-${label}:${c.id}:${form}`))) differences++;
  parity[label] = {comparisons: requests.length, differences};
}
for (const engine of Object.values(engines)) for (const s of Object.values(engine.scopes)) {
  if (s.cases instanceof Set) s.cases = s.cases.size;
  if (s.failingCases instanceof Set) s.failingCases = s.failingCases.size;
}
const scopeKeys = ['pr21_author_fixtures', 'pr21_intent_subset', 'benign_controls'];
const testedIntentSubsetPass = ['desktop-native-alpha9', 'pipeline-adapter-alpha9'].every(n => scopeKeys.every(s => engines[n].scopes[s].failingCases === 0));
const shortCases = new Set(cases.filter(c => c.group === 'grammar' && supported.has(c.keyword)
  && ['is', 'was', ':'].includes(c.connector) && ['short_letter', 'short_symbol'].includes(c.valueKind)).map(c => c.id));
const lengthBoundaryQuestion = {cases: shortCases.size, candidateFailingCases: Object.fromEntries(
  ['desktop-native-alpha9', 'pipeline-adapter-alpha9'].map(engine => [engine,
    new Set(failures.filter(r => r.engine === engine && shortCases.has(r.caseId)).map(r => r.caseId)).size]))};
const report = {schema: 'relayscrubber.pr21-scoped-audit/v1', generatedAt: new Date().toISOString(), syntheticOnly: true,
  candidateSource: 'b54745161cade161318e6e1dc9ca5486b91c474d', hostedArtifact: 14024110518, hostedRun: 43394654201,
  adapterSource: '7e9b2f0f6b1af7af9b49087c4f4677f5d6d1a496', adapterSha256: sha(await fs.readFile(path.join(pipeline, 'packages/pipeline/src/lib/scrub-engine/bindgen-engine.ts'))),
  cases: cases.length, observations: cases.length * 3 * 4, corpusSha256: sha(JSON.stringify(cases)), engines, parity, testedIntentSubsetPass, lengthBoundaryQuestion,
  scopePolicy: {author: '37 frozen author fixtures, exact output required', intentSubset: 'Inline password/passcode/passphrase/pw, is/was/possessive-colon, values >=3 characters; spaces only in quoted values; plus unmatched quotes. This is a tested subset, not a claim about all PR intent.',
    broader: 'Extra nouns/connectors, values under 3 characters, unquoted multiword values, multiline forms, multiple disclosures and mutations are separately classified; not asserted as current PR blockers.'},
  limits: ['No session access, new native/WASM builds, rule edits, consumer pin-file edits or deployment.',
    'Existing native candidate binary has source-identical engine code at 8213b34/b547451; Desktop seam changes only the candidate version marker/dependency in ignored probes.',
    'Real pinned pipeline adapter runs against verified artifact bytes. Candidate pin is an in-memory test identity using an UNRELEASED-CI schema label, not a published-release claim or deployable consumer pin.',
    'Runtime TypeScript loader uses TypeScript 6.0.3; adapter dependency zod 4.6.7 satisfies its declared ^4.1.13 range. No generated runtime files or binaries are emitted.',
    'Engine/seam qualification does not prove live Desktop transport, pipeline storage, or every natural-language disclosure.'],
};
await fs.mkdir(path.dirname(output), {recursive: true});
await fs.writeFile(output, JSON.stringify(report, null, 2) + '\n');
await fs.writeFile(path.join(path.dirname(output), 'failures.jsonl'), failures.map(r => JSON.stringify(r)).join('\n') + '\n');
console.log(JSON.stringify(report, null, 2));
process.exitCode = testedIntentSubsetPass && parity.alpha9.differences === 0 ? 0 : 1;
