// The committed pin is the hosted Linux build, not a developer-platform build.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const pinned = JSON.parse(readFileSync(new URL('../docs/results/artifact.json', import.meta.url)));
const built = JSON.parse(readFileSync(new URL('../js/generated/artifact.json', import.meta.url)));
assert.deepEqual(built, pinned, 'hosted WASM/source/adapter bytes differ from committed pin');
console.log('Hosted build equals every committed source, WASM, glue and adapter digest');
