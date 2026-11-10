export interface Manifest {
  schema: number; ruleset: string; rulesetVersion: number; rulesetSourceSha256: string;
  crateVersion: string; abiVersion: number; policy: 'secrets' | 'pii'; redactionToken: string;
}
export interface Scrubber {
  readonly manifest: Readonly<Manifest>;
  scrubText(text: string): string;
  scrubLong(text: string): string;
  scrubJson(jsonText: string): { value: unknown; redactionCount: number };
  scrubRecords(bytes: Uint8Array): { bytes: Uint8Array; recordCount: number; redactionCount: number };
}
export function loadScrubber(options: { bytes: Uint8Array; expectedManifest: Manifest; expectedWasmSha256: string }): Promise<Scrubber>;
export function loadCompiledScrubber(options: { module: WebAssembly.Module; expectedManifest: Manifest }): Scrubber;
