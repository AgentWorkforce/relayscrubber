// Transport and identity checks only. No secret recognition in JavaScript.
import init, { initSync, manifestJson, scrubText, scrubTextChecked, scrubJson, scrubRecords } from './generated/relayscrubber.js';

export const MAX_RECORD_BYTES = 16 * 1024 * 1024;
export const MAX_STREAM_BYTES = 64 * 1024 * 1024;
// Count UTF-8 before crossing the WASM allocator. Lone surrogates use U+FFFD,
// matching TextEncoder and wasm-bindgen. Stop immediately over the bound.
function admitText(text, code) {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) bytes++;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length && text.charCodeAt(i + 1) >= 0xdc00 && text.charCodeAt(i + 1) <= 0xdfff) { bytes += 4; i++; }
    else bytes += 3;
    if (bytes > MAX_RECORD_BYTES) throw new Error(code);
  }
}
function textChecked(text) { admitText(text, 'text_too_large'); return scrubTextChecked(text); }
function textCompatible(text) {
  try { admitText(text, 'text_too_large'); } catch { return '[REDACTED]'; }
  return scrubText(text);
}
function admitRecords(bytes) {
  if (bytes.byteLength > MAX_STREAM_BYTES) throw new Error('stream_too_large');
  let start = 0;
  for (let i = 0; i <= bytes.length; i++) {
    if (i === bytes.length || bytes[i] === 10) {
      if (i - start > MAX_RECORD_BYTES) throw new Error('record_too_large');
      start = i + 1;
    }
  }
}

function checked(expected) {
  const manifest = JSON.parse(manifestJson());
  if (!expected || ['schema', 'ruleset', 'rulesetVersion', 'rulesetSourceSha256', 'crateVersion', 'abiVersion', 'policy', 'redactionToken'].some(key => expected[key] !== manifest[key])) {
    throw new Error('scrubber_manifest_mismatch');
  }
  return Object.freeze({
    manifest: Object.freeze(manifest), scrubText: textCompatible, scrubLong: textCompatible, scrubTextChecked: textChecked,
    scrubJson: text => { admitText(text, 'record_too_large'); return JSON.parse(scrubJson(text)); },
    scrubRecords: bytes => {
      admitRecords(bytes);
      const result = JSON.parse(scrubRecords(bytes));
      return { bytes: new TextEncoder().encode(result.text), recordCount: result.recordCount, redactionCount: result.redactionCount };
    },
  });
}

let initialization;
let initializedDigest;
let compiledInitialized = false;

/** Initialize Node/Bun using trusted, pinned artifact bytes; never fetch implicitly. */
export async function loadScrubber({ bytes, expectedManifest, expectedWasmSha256 }) {
  if (compiledInitialized) throw new Error('scrubber_initialization_mismatch');
  if (!(bytes instanceof Uint8Array) || !/^[a-f0-9]{64}$/.test(expectedWasmSha256 ?? '')) throw new Error('scrubber_invalid_artifact');
  // Hash and initialize the same private snapshot across the asynchronous hash.
  const snapshot = Uint8Array.from(bytes);
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', snapshot))].map(b => b.toString(16).padStart(2, '0')).join('');
  if (digest !== expectedWasmSha256) throw new Error('scrubber_artifact_mismatch');
  if (!initialization) {
    initializedDigest = digest;
    initialization = init({ module_or_path: snapshot });
  }
  await initialization;
  if (initializedDigest !== digest) throw new Error('scrubber_initialization_mismatch');
  return checked(expectedManifest);
}

/** Workers use statically imported Modules. Verify artifact bytes at build time;
 * opaque compiled Modules cannot be hashed at runtime. Source identity is checked
 * at startup. This API intentionally never pretends to verify a Module byte hash.
 */
export function loadCompiledScrubber({ module, expectedManifest }) {
  if (!(module instanceof WebAssembly.Module) || initialization || compiledInitialized) throw new Error('scrubber_invalid_module');
  compiledInitialized = true;
  initSync({ module });
  return checked(expectedManifest);
}
