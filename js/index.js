// Transport and identity checks only. No secret recognition in JavaScript.
import init, { initSync, manifestJson, scrubText, scrubLong, scrubJson, scrubRecords } from './generated/relayscrubber.js';

function checked(expected) {
  const manifest = JSON.parse(manifestJson());
  if (!expected || ['schema', 'ruleset', 'rulesetVersion', 'rulesetSourceSha256', 'crateVersion', 'abiVersion', 'policy', 'redactionToken'].some(key => expected[key] !== manifest[key])) {
    throw new Error('scrubber_manifest_mismatch');
  }
  return Object.freeze({
    manifest: Object.freeze(manifest), scrubText, scrubLong,
    scrubJson: text => JSON.parse(scrubJson(text)),
    scrubRecords: bytes => {
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
