#!/usr/bin/env bun
/**
 * Direct byte-for-byte oracle comparison with canonical scrub.ts.
 *
 * Usage:
 *   bun scripts/parity-with-typescript.ts ../relayhistory-pipeline
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repo = resolve(import.meta.dir, "..");
const canonicalArgument = process.argv[2];
if (!canonicalArgument) {
  throw new Error(
    "usage: bun scripts/parity-with-typescript.ts /path/to/relayhistory-pipeline",
  );
}
const canonical = resolve(canonicalArgument);
const modulePath = resolve(canonical, "packages/pipeline/src/lib/scrub.ts");
const rawChunksPath = resolve(
  canonical,
  "packages/pipeline/src/lib/pipeline/raw-chunks.ts",
);
const pinnedManifest = JSON.parse(
  readFileSync(resolve(repo, "vendor/canonical/technical-foul.json"), "utf8"),
) as { rulesetSourceSha256: string; segmenterSha256: string };
const normalized = (path: string) =>
  readFileSync(path, "utf8").replaceAll("\r\n", "\n");
const digest = (text: string) =>
  createHash("sha256").update(text).digest("hex");
const scrubSource = normalized(modulePath);
const rawChunksSource = normalized(rawChunksPath);
const startMarker = "// <scrub-segmenter>";
const endMarker = "// </scrub-segmenter>";
const start = rawChunksSource.indexOf(startMarker);
const endStart = rawChunksSource.indexOf(endMarker, start);
if (start < 0 || endStart < 0) {
  throw new Error("canonical raw-chunks.ts is missing scrub-segmenter markers");
}
const segmenterSource = rawChunksSource.slice(
  start,
  endStart + endMarker.length,
);
const segmenterDigest = digest(segmenterSource);
const rulesetDigest = digest(`${scrubSource}\n${segmenterSource}`);
if (segmenterDigest !== pinnedManifest.segmenterSha256) {
  throw new Error(
    `canonical segmenter digest ${segmenterDigest} does not match pinned ${pinnedManifest.segmenterSha256}`,
  );
}
if (rulesetDigest !== pinnedManifest.rulesetSourceSha256) {
  throw new Error(
    `canonical ruleset digest ${rulesetDigest} does not match pinned ${pinnedManifest.rulesetSourceSha256}`,
  );
}
const { scrubJson, scrubText } = (await import(
  pathToFileURL(modulePath).href
)) as {
  scrubJson<T>(value: T): T;
  scrubText(value: string): string;
};
const { scrubLong } = (await import(pathToFileURL(rawChunksPath).href)) as {
  scrubLong(value: string): string;
};

type Part = [string, number | string];
type Generator = { prefix?: string; suffix?: string; parts: Part[] };
type Case = {
  id: string;
  input: string;
  expected: string;
  record?: boolean;
  expectedRecord?: string;
};
type Corpus = { generators: Record<string, Generator>; cases: Case[] };
const corpus = JSON.parse(
  readFileSync(resolve(repo, "vendor/corpus/scrub-secret-corpus.json"), "utf8"),
) as Corpus;

const charsets: Record<string, string> = {
  alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  upper_alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  letters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  digits: "0123456789",
  hex: "0123456789abcdef",
  urlsafe: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
  b64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
};

function generate(generator: Generator, seed: number): string {
  let output = generator.prefix ?? "";
  generator.parts.forEach(([kind, length], partIndex) => {
    if (kind === "lit") output += String(length);
    else if (kind === "uuid") {
      const hex = seed.toString(16);
      output += `${hex.padStart(8, "0")}-${hex.slice(-4).padStart(4, "0")}-4${hex.slice(-3).padStart(3, "0")}-a${(seed * 3).toString(16).slice(-3).padStart(3, "0")}-${hex.padStart(12, "0")}`;
    } else {
      const alphabet = charsets[kind];
      if (!alphabet) throw new Error(`unknown charset ${kind}`);
      for (let index = 0; index < Number(length); index++) {
        output +=
          alphabet[(index * 17 + seed * 31 + partIndex * 7) % alphabet.length];
      }
    }
  });
  return output + (generator.suffix ?? "");
}

function instantiate(
  c: Case,
  round: number,
): { input: string; expected: string } {
  const values = new Map<string, string>();
  const fill = (template: string) =>
    template.replace(/\{\{([a-z0-9_]+)\}\}/g, (_match, name: string) => {
      if (!values.has(name)) {
        const generator = corpus.generators[name];
        if (!generator) throw new Error(`${c.id}: unknown generator ${name}`);
        values.set(name, generate(generator, round + c.id.length));
      }
      return values.get(name)!;
    });
  return { input: fill(c.input), expected: fill(c.expected) };
}

const vectors = corpus.cases.flatMap((c) =>
  Array.from({ length: 5 }, (_, round) => ({
    id: `${c.id}/${round}`,
    ...instantiate(c, round),
  })),
);

let fuzzState = 0x6d2b79f5;
const next = () => {
  fuzzState ^= fuzzState << 13;
  fuzzState ^= fuzzState >>> 17;
  fuzzState ^= fuzzState << 5;
  return fuzzState >>> 0;
};
const generated = (length: number) => {
  const alphabet = charsets.alnum;
  return Array.from({ length }, () => alphabet[next() % alphabet.length]).join(
    "",
  );
};
// Ruleset 7's exception is only for the exact public replay identifier.
// Credential-shaped values continue through the independent detectors.
const v7TextStart = vectors.length;
for (const key of ["idempotency_key", "IDEMPOTENCY_KEY", "Idempotency_Key", "request_idempotency_key", "idempotency_key_secret", "idempotency_key_token"]) {
  for (const separator of ["=", ":"]) {
    for (const gap of ["", "\t", "\u00a0", "\ufeff"]) {
      for (const value of ["public-replay-42", `ghp_${generated(48)}`, `sk-proj-${generated(72)}`, `rth_at_${generated(72)}`]) {
        const input = `before ${key}${gap}${separator}${gap}${value} after`;
        vectors.push({ id: `v7/${vectors.length}`, input, expected: scrubText(input) });
      }
    }
  }
}
const v7TextCount = vectors.length - v7TextStart;
// Ruleset 8 must keep scanning inside public assignment values.
const v8TextStart = vectors.length;
for (const key of ["idempotency_key", "IDEMPOTENCY_KEY"]) {
  for (const separator of ["=", ":", " : ", "\t=\t", "\u00a0=\ufeff"]) {
    for (const quote of ["", '"', "'", String.fromCharCode(96)]) {
      for (const label of ["password", "token", "api_key", "client_secret", "credentials"]) {
        const input = key + separator + quote + label + "=fixture-only" + quote;
        vectors.push({ id: `v8/${vectors.length}`, input, expected: scrubText(input) });
      }
    }
  }
}
for (let depth = 1; depth <= 512; depth *= 2) {
  const input = "idempotency_key=".repeat(depth) + "password=fixture-only";
  vectors.push({ id: `v8/depth/${depth}`, input, expected: scrubText(input) });
}
const v8TextCount = vectors.length - v8TextStart;
const fuzzAtoms = () => [
  `Bearer ${generated(40)}`,
  `"password": "${generated(48)}"`,
  `--api-token ${generated(48)}`,
  `${"gh"}p_${generated(40)}`,
  `${"cf"}ut_${generated(48)}`,
  `https://operator:${generated(32)}@example.test/path`,
  `https://operator@example.test/path`,
  `person${next() % 100}@example.test`,
  `git@github.com:AgentWorkforce/relay.git`,
  `+1 (415) 555-0123`,
  `(415) 555-0123`,
  `4111 1111 1111 1111`,
  `/home/developer/project/file.rs`,
  `C:\\Users\\developer\\project\\file.rs`,
  `?code_verifier=${generated(64)}&next=ok`,
  `eyJ${generated(12)}.eyJ${generated(20)}.${generated(32)}`,
  `${"relay"}_ag_${generated(32)}`,
  `${"rth"}_at_${generated(20)}`,
  `ordinary ${generated(12)} text`,
];
for (let index = 0; index < 20_000; index++) {
  const atoms = fuzzAtoms();
  const count = 1 + (next() % 5);
  let input = "";
  for (let part = 0; part < count; part++) {
    const separators = [" ", "\n", " | ", " => ", "{}"];
    input +=
      (part === 0 ? "" : separators[next() % separators.length]) +
      atoms[next() % atoms.length];
  }
  vectors.push({ id: `fuzz/${index}`, input, expected: scrubText(input) });
}
for (const [id, input] of [
  ["unicode/unclosed-bound", `"password": "${"💣".repeat(2_100)}" tail`],
  ["unicode/whitespace", `"token": "${generated(32)}\u2003trailing`],
] as const) {
  vectors.push({ id, input, expected: scrubText(input) });
}
for (const separator of ["\r", "\n", "\r\n", "\u2028", "\u2029", "\u0085"]) {
  const separatorId = [...separator]
    .map((unit) => unit.codePointAt(0)?.toString(16))
    .join("-");
  for (const quote of ['"', "'", "`"]) {
    const value = `short${separator}${"v".repeat(4_097)}UNIQUE_TAIL`;
    for (const [suffix, close] of [
      ["closed", `${quote} after`],
      ["open", ""],
    ] as const) {
      const input = `${quote}token${quote}: ${quote}${value}${close}`;
      vectors.push({
        id: `quoted-cap/${separatorId}/${quote.charCodeAt(0)}/${suffix}`,
        input,
        expected: scrubText(input),
      });
    }
    const withinLength = 4_096 - `short${separator}`.length;
    const within = `short${separator}${"v".repeat(withinLength)}`;
    const withinInput = `${quote}token${quote}: ${quote}${within}${quote} after`;
    vectors.push({
      id: `quoted-cap/${separatorId}/${quote.charCodeAt(0)}/within`,
      input: withinInput,
      expected: scrubText(withinInput),
    });
  }
}
const escapedQuote = (depth: number) => `${"\\".repeat(2 ** depth - 1)}"`;
const nestedSecretDocument = (depth: number, body: string, eoi: boolean) => {
  let inner = `{${escapedQuote(depth)}api_key${escapedQuote(depth)}:${escapedQuote(depth)}${body}${eoi ? "" : `${escapedQuote(depth)}}`}`;
  for (let level = depth - 1; level >= 0; level -= 1) {
    inner = `{${escapedQuote(level)}content${escapedQuote(level)}:${escapedQuote(level)}${inner}${eoi ? "" : `${escapedQuote(level)}}`}`;
  }
  return inner;
};
const escapedAt = (depth: number, value: string) =>
  value.replace(/\\/g, "\\".repeat(2 ** depth));
const opBodies: Array<[string, (depth: number) => string]> = [];
for (const [name, literal, escaped] of [
  ["lf", "\n", "\\n"],
  ["cr", "\r", "\\r"],
  ["crlf", "\r\n", "\\r\\n"],
  ["u2028", "\u2028", "\\u2028"],
  ["u2029", "\u2029", "\\u2029"],
  ["u0085", "\u0085", "\\u0085"],
] as const) {
  opBodies.push([
    `${name}/literal`,
    () => `op://vault/item${literal}SECRETTAIL`,
  ]);
  opBodies.push([
    `${name}/escaped`,
    (depth) => `op://vault/item${escapedAt(depth, escaped)}SECRETTAIL`,
  ]);
}
opBodies.push(
  [
    "escaped-quote",
    (depth) => `op://vault/item${"\\".repeat(2 ** (depth + 1) - 1)}"SECRETTAIL`,
  ],
  [
    "escaped-backslash",
    (depth) => `op://vault/item${"\\".repeat(2 ** (depth + 1))}SECRETTAIL`,
  ],
  ["two-segments", () => "op://vault/item"],
  ["five-segments", () => "op://vault/item/section/field/SECRETTAIL"],
  ["six-segments", () => "op://vault/item/section/field/x/SECRETTAIL"],
  ["double-space", () => "op://vault/item  SECRETTAIL"],
  ["query", () => "op://vault/item/field?attribute=otp"],
  ["trailing-slash", () => "op://vault/item/field/"],
  ["empty-segment", () => "op://vault//field"],
  ["non-ascii", () => "op://váult/item/field"],
);
for (const [name, body] of opBodies) {
  for (const depth of [0, 1, 2]) {
    for (const eoi of [false, true]) {
      const input = nestedSecretDocument(depth, body(depth), eoi);
      vectors.push({
        id: `v5/op/${name}/depth-${depth}/${eoi ? "eoi" : "closed"}`,
        input,
        expected: nestedSecretDocument(depth, "[REDACTED]", eoi),
      });
    }
  }
}
for (const reference of [
  "op://vault/item/field",
  "op://Engineering/cloudflare/credential",
  "op://My Vault/item name/field",
  "op://vault/item/section/field",
]) {
  for (const depth of [0, 1, 2]) {
    const input = nestedSecretDocument(depth, reference, false);
    vectors.push({
      id: `v5/op/valid/depth-${depth}/${reference}`,
      input,
      expected: input,
    });
  }
}
const child = Bun.spawn(
  ["cargo", "run", "--quiet", "--example", "scrub_lines"],
  {
    cwd: repo,
    env: { ...Bun.env, TMPDIR: resolve(repo, ".task-tmp") },
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  },
);
child.stdin.write(JSON.stringify(vectors.map(({ input }) => input)));
child.stdin.end();
const [exitCode, stdout, stderr] = await Promise.all([
  child.exited,
  new Response(child.stdout).text(),
  new Response(child.stderr).text(),
]);
if (exitCode !== 0) throw new Error(stderr);
const rust = JSON.parse(stdout) as string[];

for (const [index, vector] of vectors.entries()) {
  const typescript = scrubText(vector.input);
  if (typescript !== vector.expected) {
    throw new Error(
      `${vector.id}: canonical TypeScript differs from corpus expected output`,
    );
  }
  if (rust[index] !== typescript) {
    throw new Error(
      `${vector.id}: Rust output differs from canonical TypeScript`,
    );
  }
}

const fill = "lorem ipsum dolor sit amet ".repeat(11_000);
const longVectors = [
  `${fill.slice(0, 262_130)} idempotency_key=public-replay-42 after`,
  `${fill.slice(0, 262_130)} idempotency_key=ghp_${generated(48)} after`,
  `${fill} ordinary tail`,
  `${fill.slice(0, 260_000)} "token": "short\n${"v".repeat(4_097)}UNIQUE_TAIL" after`,
  `${fill.slice(0, 259_000)} ${"x ".repeat(4_000)} bob@example.test done`,
  `${fill.slice(0, 261_000)} -----BEGIN PRIVATE KEY-----\n${"A".repeat(2_000)}\n-----END PRIVATE KEY----- after`,
  `${"x".repeat(262_125)} "token": op://${"aB3dE5fG7hJ9".repeat(350)}`,
];
const longChild = Bun.spawn(
  ["cargo", "run", "--quiet", "--example", "scrub_lines", "--", "--long"],
  {
    cwd: repo,
    env: { ...Bun.env, TMPDIR: resolve(repo, ".task-tmp") },
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  },
);
longChild.stdin.write(JSON.stringify(longVectors));
longChild.stdin.end();
const [longExit, longStdout, longStderr] = await Promise.all([
  longChild.exited,
  new Response(longChild.stdout).text(),
  new Response(longChild.stderr).text(),
]);
if (longExit !== 0) throw new Error(longStderr);
const rustLong = JSON.parse(longStdout) as string[];
for (const [index, input] of longVectors.entries()) {
  if (rustLong[index] !== scrubLong(input)) {
    throw new Error(
      `scrubLong/${index}: Rust output differs from canonical TypeScript`,
    );
  }
}

const recordVectors = corpus.cases
  .filter((c) => c.record)
  .flatMap((c) =>
    Array.from({ length: 5 }, (_, round) => {
      const filled = instantiate(c, round);
      return {
        id: `${c.id}/${round}`,
        input: filled.input,
        expected: JSON.parse(
          c.expectedRecord
            ? instantiate({ ...c, input: c.expectedRecord }, round).input
            : filled.expected,
        ) as unknown,
      };
    }),
  );
recordVectors.push({
  id: "collision/document-order",
  input: '{"b@x.io":"b","c":1,"a@x.io":"a","b+1@x.io":"b1"}',
  expected: {
    "[REDACTED]": "b",
    c: 1,
    "[REDACTED] (2)": "a",
    "[REDACTED] (3)": "b1",
  },
});
recordVectors.push({
  id: "number/negative-zero",
  input: '{"offset":-0}',
  expected: { offset: -0 },
});
for (const input of [
  JSON.stringify({idempotency_key: "public-replay-42", content: "idempotency_key=public-replay-42 api_key=synthetic-credential-value"}),
  JSON.stringify({idempotency_key: `ghp_${generated(48)}`}),
  JSON.stringify({text: "idempotency_key=password=fixture-only"}),
  '{"content":"api_key=synthetic-credential-value","content":"ordinary last value"}',
]) {
  recordVectors.push({id: `v7/record/${recordVectors.length}`, input, expected: scrubJson(JSON.parse(input))});
}
const jsonChild = Bun.spawn(
  [
    "cargo",
    "run",
    "--quiet",
    "--example",
    "scrub_lines",
    "--",
    "--json-text",
  ],
  {
    cwd: repo,
    env: { ...Bun.env, TMPDIR: resolve(repo, ".task-tmp") },
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  },
);
jsonChild.stdin.write(JSON.stringify(recordVectors.map(({ input }) => input)));
jsonChild.stdin.end();
const [jsonExit, jsonStdout, jsonStderr] = await Promise.all([
  jsonChild.exited,
  new Response(jsonChild.stdout).text(),
  new Response(jsonChild.stderr).text(),
]);
if (jsonExit !== 0) throw new Error(jsonStderr);
const rustJson = JSON.parse(jsonStdout) as unknown[];
const semanticEqual = (left: unknown, right: unknown): boolean => {
  if (typeof left === "number" || typeof right === "number") {
    return typeof left === "number" &&
      typeof right === "number" &&
      Object.is(left, right);
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => semanticEqual(item, right[index]));
  }
  if (left && right && typeof left === "object" && typeof right === "object") {
    const leftEntries = Object.entries(left as Record<string, unknown>).sort(
      ([a], [b]) => a.localeCompare(b),
    );
    const rightEntries = Object.entries(right as Record<string, unknown>).sort(
      ([a], [b]) => a.localeCompare(b),
    );
    return leftEntries.length === rightEntries.length &&
      leftEntries.every(
        ([key, value], index) =>
          key === rightEntries[index]?.[0] &&
          semanticEqual(value, rightEntries[index]?.[1]),
      );
  }
  return Object.is(left, right);
};
for (const [index, vector] of recordVectors.entries()) {
  const typescript = scrubJson(JSON.parse(vector.input) as unknown);
  if (!semanticEqual(typescript, vector.expected)) {
    throw new Error(
      `${vector.id}: canonical TypeScript differs from corpus expected record`,
    );
  }
  if (!semanticEqual(rustJson[index], typescript)) {
    throw new Error(
      `${vector.id}: Rust scrubJson differs from canonical TypeScript`,
    );
  }
}

console.log(
  `parity ok: ${vectors.length} scrubText vectors (${corpus.cases.length} corpus cases x 5 rounds + ${v7TextCount} v7 replay-identity vectors + ${v8TextCount} v8 nested-credential vectors + 20002 deterministic fuzz + 54 multiline-cap regressions + 144 strict-reference depth vectors), ${longVectors.length} scrubLong vectors byte-identical, and ${recordVectors.length} scrubJson vectors semantically identical`,
);
