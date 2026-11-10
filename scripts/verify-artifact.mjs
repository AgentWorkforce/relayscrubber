// Run before Workers bundling; startup additionally pins the embedded ruleset.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
const path = process.argv[2];
const expected = process.argv[3];
if (!path || !/^[a-f0-9]{64}$/.test(expected ?? '')) throw new Error('usage: verify-artifact.mjs path trusted-sha256');
const actual = createHash('sha256').update(await readFile(path)).digest('hex');
if (actual !== expected) throw new Error('scrubber_artifact_mismatch');
console.log('artifact digest verified');
