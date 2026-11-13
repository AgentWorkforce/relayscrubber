// Summarize existing synthetic observations; fresh native calls are bounded witnesses only.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {disclosureCases, spansCovered, PUBLIC} from '../eval/disclosure-coverage.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scratch = path.join(root, '.task-tmp/pr21-hosted-audit');
const report = JSON.parse(await fs.readFile(path.join(root, 'docs/results/pr21-hosted-scoped-audit-b547451.json')));
const generated = disclosureCases(), positives = generated.filter(c => c.expected === 'redact');
const author = JSON.parse(await fs.readFile(path.join(root, 'eval/alpha9_prose_credential_cases.json')));
const failures = (await fs.readFile(path.join(scratch, 'failures.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
const names = ['desktop-native-alpha5', 'pipeline-adapter-alpha5', 'desktop-native-alpha9', 'pipeline-adapter-alpha9'];
const failedIds = Object.fromEntries(names.map(name => [name, new Set(failures.filter(r => r.engine === name).map(r => r.caseId))]));
const supported = new Set(['password', 'passcode', 'passphrase', 'pw']);
const sha = x => createHash('sha256').update(x).digest('hex');
function scope(c) {
  const inline = c.group === 'grammar' && supported.has(c.keyword) && ['is', 'was', ':'].includes(c.connector);
  if (inline && ['short_letter', 'short_symbol'].includes(c.valueKind)) return 'pr21_length_boundary_question';
  if (inline && !(c.valueKind === 'spaces' && c.quote === 'none') || c.group === 'unmatched_quote' && supported.has(c.keyword)) return 'pr21_intent_subset';
  return 'expanded_policy_pending_direct_authorization';
}
function quote(c) {
  if (c.group === 'multiple') return 'double_and_single';
  if (c.group === 'unmatched_quote') return c.quote === "'" ? 'unmatched_single' : 'unmatched_double';
  const q = c.quote ?? 'none';
  return ({none: 'unquoted', "'": 'single', '"': 'double', '`': 'backtick', '“': 'curly_double'})[q] ?? q;
}
function valueShape(c) {
  if (c.valueKind) return 'fixed/' + c.valueKind;
  if (c.group === 'seeded_mutation') {
    const [a, b] = c.spans[0]; return 'seeded/codepoints_' + [...c.input.slice(a, b)].length;
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
  noun: c => c.group === 'multiple' ? 'multiple_nouns_see_multiplicity' : c.keyword,
  separator: c => c.connector ?? 'is', value_shape: valueShape, quoting: quote,
  multiline, multiplicity: c => c.spans.length === 2 ? 'two_disclosures' : 'one_disclosure',
  generator_family: c => c.group, scope,
};
const breakdowns = {}, selected = new Map();
for (const [axis, label] of Object.entries(axes)) {
  const groups = new Map();
  for (const c of positives) {
    const key = label(c); assert.equal(typeof key, 'string');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(c);
  }
  breakdowns[axis] = [];
  for (const [family, cases] of groups) {
    const failed = Object.fromEntries(names.map(name => [name, cases.filter(c => failedIds[name].has(c.id)).length]));
    breakdowns[axis].push({family, positiveCases: cases.length, failedCases: failed});
    const prioritized = cases.filter(c => failedIds['desktop-native-alpha9'].has(c.id));
    const options = prioritized.length ? prioritized : cases;
    const c = options.find(c => c.input.length <= 200) ?? options[0];
    if (!selected.has(c.id)) selected.set(c.id, {case: c, families: []});
    selected.get(c.id).families.push(axis + '/' + family);
  }
  assert.equal(breakdowns[axis].reduce((n, r) => n + r.positiveCases, 0), 7126);
  for (const name of names) assert.equal(breakdowns[axis].reduce((n, r) => n + r.failedCases[name], 0), name.endsWith('alpha5') ? 6119 : 5254);
}
const forms = ['text', 'json', 'ndjson'];
const record = content => ({kind: 'session_event', source: 'codex', payload: {content, public_context: PUBLIC}});
const encode = (c, form) => form === 'text' ? c.input : JSON.stringify(record(c.input)) + (form === 'ndjson' ? '\n' : '');
const decode = (body, form) => form === 'text' ? body : JSON.parse(body.trim()).payload.content;
const cases = [...selected.values()].map(v => v.case);
const requests = cases.flatMap(c => forms.map(form => ({id: `${c.id}:${form}`, body: encode(c, form)})));
const observed = new Map();
for (const version of ['alpha5', 'alpha9']) {
  const saved = JSON.parse(await fs.readFile(path.join(scratch, `adapter-${version}.private-synthetic.json`)));
  for (const [key, value] of saved.observed) observed.set(key, value);
  const binary = path.join(root, `.task-tmp/native-target/debug/arlap-desktop-${version}-qualification`);
  const run = spawnSync(binary, [], {input: JSON.stringify(requests), encoding: 'utf8', timeout: 30000, maxBuffer: 32 * 1024 * 1024});
  if (run.error || run.status) throw Error('bounded native witness call failed');
  const result = JSON.parse(run.stdout);
  assert.equal(result.rows.length, requests.length);
  for (const [i, row] of result.rows.entries()) {
    assert.equal(row.id, requests[i].id);
    assert.equal(row.error, undefined);
    observed.set(`desktop-native-${version}:${row.id}`, {content: decode(row.output, forms[i % 3]), error: null});
  }
}
const preview = text => text.length <= 200 ? text : text.slice(0, 150) + ' [preview truncated; regenerate by caseId]';
const witnesses = [];
for (const {case: c, families} of selected.values()) {
  const variants = {};
  for (const name of names) {
    const values = forms.map(form => observed.get(`${name}:${c.id}:${form}`));
    assert.ok(values.every(v => v && !v.error));
    assert.ok(values.every(v => v.content === values[0].content));
    variants[name] = {decodedOutputSha256: sha(values[0].content), decodedOutputPreview: preview(values[0].content),
      decodedOutputUtf8Bytes: Buffer.byteLength(values[0].content), forms, allFormsIdentical: true,
      protectedSpansFullyRedacted: spansCovered(c.input, values[0].content, c.spans)};
  }
  for (const version of ['alpha5', 'alpha9']) assert.equal(variants[`desktop-native-${version}`].decodedOutputSha256, variants[`pipeline-adapter-${version}`].decodedOutputSha256);
  witnesses.push({caseId: c.id, scope: scope(c), families, inventedInputPreview: preview(c.input),
    inputUtf8Bytes: Buffer.byteLength(c.input), inputSha256: sha(c.input), protectedSpans: c.spans,
    fullInputOmittedIfOver200CodeUnits: c.input.length > 200, regenerate: 'disclosureCases(24301, 1024).find(c => c.id === ' + JSON.stringify(c.id) + ')', variants});
}
const summary = {
  schema: 'relayscrubber.pr21-family-breakdown/v1', generatedAt: new Date().toISOString(), syntheticOnly: true,
  candidateSource: report.candidateSource, hostedRun: report.hostedRun, hostedArtifact: report.hostedArtifact,
  artifactIdentity: {packageSha256: 'd7eb1702fe73092d6607efe2481d67c1b3a97a06a90505afd2c5d5b6dec7db68',
    wasmSha256: '008406d7ed78ff85bea510544ceaf0818477f277f0705a4d61a56783ef7117f4',
    artifactJsonSha256: 'b6f3f5b93f58e9fb0725825cc6fc85e046221d5ded006e3cb8f27a91318659ef',
    sourceSha256: '291a6b373388b7bc5295091d1bcbc13a2e8c64e37b2bfe0d06b2dc4f12df32c9'},
  counts: {generatedPositive: 7126, generatedBenign: 45, authorPositive: author.filter(c => c.kind === 'positive').length,
    authorBenign: author.filter(c => c.kind === 'benign').length, totalPositive: 7126 + author.filter(c => c.kind === 'positive').length,
    totalBenign: 45 + author.filter(c => c.kind === 'benign').length, totalCases: report.cases, observations: report.observations},
  dimensions: {seed: 24301, seededMutations: 1024, grammarCrossProduct: '9 nouns * 7 separators * 3 casing modes * 3 quote forms * 9 fixed value shapes = 5103 cases',
    nouns: ['password', 'passcode', 'passphrase', 'pw', 'pass', 'PIN', 'secret', 'key', 'token'],
    separators: ['is', 'was', '=', ':', 'is now', 'set to', 'is set to'], casing: ['lower', 'upper', 'mixed'],
    quotes: ['none', 'single', 'double'], extraMultilineQuotes: ['backtick', 'curly double'],
    fixedValueShapes: ['one letter', 'one symbol', 'four digits', 'symbols', 'ordinary word', 'type-like word', 'unquoted/quoted spaces', 'unicode', '2049-code-unit long value'],
    seededValueCodepointLengths: [1, 2, 3, 8, 31, 64, 257, 1024],
    whitespace: ['space', 'double space', 'tab', 'LF', 'CRLF', 'U+2003'],
    additionalFamilies: ['gap line breaks', 'split connectors', 'quoted multiline values', 'unmatched quotes', 'two disclosures per line']},
  countSemantics: 'Counts are unique positive corpus cases failing any of text/JSON/NDJSON, not observation totals. Each axis partitions 7126 generated positives; axes overlap each other and are not causal attribution. Author fixtures and benign cases are counted separately.',
  engineIdentities: Object.fromEntries(names.map(name => [name, report.engines[name].identity])),
  harnessFileSha256: Object.fromEntries(await Promise.all([
    'eval/disclosure-coverage.mjs', 'scripts/prepare-arlap-probes.py', 'scripts/audit-pr21-disclosures.mjs',
    'scripts/qualification-ts-loader.mjs', 'scripts/summarize-pr21-families.mjs',
  ].map(async file => [file, sha(await fs.readFile(path.join(root, file)))]))),
  scopeCountsFromFullAudit: Object.fromEntries(names.map(name => [name, report.engines[name].scopes])),
  parity: report.parity, boundedWitnessNativeCalls: requests.length * 2, boundedWitnessCount: witnesses.length,
  breakdowns, witnesses,
  limits: ['PR21 remains draft; no merge/publication approval inferred.', 'Expanded-policy cases remain pending direct authorization. Length boundary is a scope question, not silently excluded.',
    'No session bodies or fixture queries. Only invented corpus observations and bounded calls to existing native probes are used.',
    'Fresh native witness hashes match the saved real-adapter hashes in every form; full-matrix native/adapter parity is from the completed exact-hosted-artifact audit.',
    'Candidate adapter identity is in-memory test-only with an UNRELEASED-CI schema label; no consumer pin file changed.',
    'Output hashes cover UTF-8 decoded synthetic content, including the public marker; wire JSON formatting is intentionally not hashed.',
    'Long witnesses are bounded previews plus complete hashes and deterministic regeneration recipes. No rule edits, engine builds, repins or deploys.'],
};
await fs.writeFile(path.join(root, 'docs/results/pr21-family-breakdown-b547451.json'), JSON.stringify(summary, null, 2) + '\n');
let markdown = `# PR21 synthetic family breakdown\n\nCandidate: \`${summary.candidateSource}\`, alpha.9, **DRAFT**. No merge or publication approval.\n\n`;
markdown += `The complete matrix contains **${summary.counts.totalPositive} positive** and **${summary.counts.totalBenign} benign** cases: 7,126 generated positives + 22 frozen author positives, and 45 generated + 15 author benign controls. Each runs as text, JSON and NDJSON on four paths: 86,496 observations. All 60 benign controls remain unchanged.\n\n`;
markdown += 'Generator: seed 24301; 1,024 seeded mutations. The core cross-product is 9 nouns × 7 separators × 3 casing modes × 3 quotes × 9 value shapes = 5,103 cases. Extra families cover gap/split-connector line breaks, quoted multiline values, unmatched quotes, and two disclosures on a line. Complete dimensions and identities are in the machine report below.\n\n';
markdown += '**Scope separation:** 728 additional intent-aligned cases and all 37 author fixtures pass on both candidate paths. The 216 one-character boundary cases have 162 candidate misses and require an explicit minimum-length decision. The other 6,182 generated positive cases are labeled `expanded_policy_pending_direct_authorization`, with 5,092 candidate misses. These are not asserted as current PR21 blockers. The earlier 6,398-case broader bucket includes the 216 length questions; do not add those counts twice.\n\n';
markdown += 'Tables count unique **generated positive cases** failing any form; each axis partitions the same 7,126 positives. Axes overlap each other and do not identify the cause of a miss. Author fixtures and benign controls are counted separately. Native and real pipeline-adapter counts match exactly, so each version has one displayed failure column.\n\n';
for (const [axis, rows] of Object.entries(breakdowns)) {
  markdown += `## ${axis.replaceAll('_', ' ')}\n\n| Family | Positive cases | alpha.5 failed | alpha.9 failed |\n| --- | ---: | ---: | ---: |\n`;
  for (const row of rows) markdown += `| \`${row.family.replaceAll('\n', '\\n')}\` | ${row.positiveCases} | ${row.failedCases['desktop-native-alpha5']} | ${row.failedCases['desktop-native-alpha9']} |\n`;
  markdown += '\n';
}
markdown += '## Bounded witnesses, hashes, and parity\n\n';
markdown += 'The [machine report](../docs/results/pr21-family-breakdown-b547451.json) contains 48 deduplicated invented witnesses covering every listed family, including their scope labels, protected spans, input hashes, and four variant output hashes/previews. Long inputs/outputs are capped previews with full hashes and deterministic regeneration recipes. No session bodies are included.\n\n';
markdown += 'Each witness has independently measured native alpha.5/alpha.9 output hashes and saved actual pipeline-adapter alpha.5/hosted-alpha.9 hashes. Hashes cover UTF-8 decoded content, including the public context marker; all three forms yield the same decoded content for these witnesses. All 288 bounded native calls match adapter hashes. Full-matrix parity is 0 differences / 21,624 comparisons for alpha.5, and 0 / 21,624 for alpha.9. The native and adapter paths are separate executions, not aliases.\n\n';
markdown += 'The exact package/WASM/manifest/source hashes and adapter/source limitations are recorded in the [scoped hosted audit](pr21-hosted-scoped-audit.md). Its native probes were already built; the candidate WASM is the downloaded hosted artifact, not the earlier local WASM build. The candidate adapter identity is in-memory test-only with an unreleased CI schema label; no consumer pin file changed.\n\n';
markdown += 'Harness: `scripts/summarize-pr21-families.mjs`; original runner: `scripts/audit-pr21-disclosures.mjs`; generator: `eval/disclosure-coverage.mjs`. File SHA-256 identities are in the machine report. Run the summarizer after the scoped audit; it reads only ignored synthetic results and makes bounded calls to existing native probes.\n\n';
markdown += 'No session access, fixture search/change, rule edit, re-pin, engine build, tag, publish, or deployment. Finite property-style tests do not prove detection of every natural-language disclosure.\n';
await fs.writeFile(path.join(root, 'eval/pr21-family-breakdown.md'), markdown);
console.log(JSON.stringify({counts: summary.counts, witnessCount: witnesses.length, nativeCalls: summary.boundedWitnessNativeCalls, parity: summary.parity}));
