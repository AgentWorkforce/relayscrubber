// The committed pin is the hosted Linux build, not a developer-platform build.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
const pinned = JSON.parse(readFileSync(new URL('../docs/results/artifact.json', import.meta.url)));
const built = JSON.parse(readFileSync(new URL('../js/generated/artifact.json', import.meta.url)));
assert.deepEqual(built, pinned, 'hosted WASM/source/adapter bytes differ from committed pin');
const receipt = JSON.parse(readFileSync(new URL('../docs/results/review-fixes.json', import.meta.url)));
const packagePath = process.argv[2];
if (packagePath) {
  const digest = createHash('sha256').update(readFileSync(packagePath)).digest('hex');
  assert.equal(digest, receipt.hostedArtifact.packageSha256, 'hosted package differs from committed receipt');
}
console.log('Hosted build equals committed source, WASM, glue, adapter and supplied package digests');
