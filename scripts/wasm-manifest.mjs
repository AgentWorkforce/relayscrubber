import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import init, { manifestJson } from '../js/generated/relayscrubber.js';
const bytes = await readFile(new URL('../js/generated/relayscrubber_bg.wasm', import.meta.url));
await init({ module_or_path: bytes });
const files = {};
for (const path of ['relayscrubber_bg.wasm', 'relayscrubber.js', 'relayscrubber.d.ts', 'relayscrubber_bg.wasm.d.ts']) {
  files[path] = createHash('sha256').update(await readFile(new URL(`../js/generated/${path}`, import.meta.url))).digest('hex');
}
const adapterFiles = {};
for (const path of ['index.js', 'index.d.ts']) adapterFiles[path] = createHash('sha256').update(await readFile(new URL(`../js/${path}`, import.meta.url))).digest('hex');
await writeFile(new URL('../js/generated/artifact.json', import.meta.url), JSON.stringify({ schema: 1, toolchain: '1.88.0', wasmBindgen: '0.2.104', manifest: JSON.parse(manifestJson()), files, adapterFiles }, null, 2) + '\n');
console.log(JSON.stringify({ wasmBytes: bytes.length, wasmSha256: files['relayscrubber_bg.wasm'], manifest: JSON.parse(manifestJson()) }));
