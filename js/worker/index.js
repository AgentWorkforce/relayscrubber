// Local Workers/workerd smoke test. No product integration or deployment.
import module from '../generated/relayscrubber_bg.wasm';
import artifact from '../generated/artifact.json';
import { loadCompiledScrubber } from '../index.js';
const scrubber = loadCompiledScrubber({ module, expectedManifest: artifact.manifest });
export default {
  async fetch(request) {
    const input = await request.text();
    if (input.length > 262144) return new Response('input_too_large', { status: 413 });
    return Response.json({ text: scrubber.scrubText(input), manifest: scrubber.manifest });
  },
};
