#!/usr/bin/env bun
/**
 * Direct byte-for-byte oracle comparison with canonical scrub.ts.
 *
 * Usage:
 *   bun scripts/parity-with-typescript.ts ../relayhistory-pipeline
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const repo = resolve(import.meta.dir, "..");
const canonical = resolve(
  process.argv[2] ?? "../relayhistory-pipeline-pr306-review.qkw05V",
);
const modulePath = resolve(canonical, "packages/pipeline/src/lib/scrub.ts");
const { scrubText } = (await import(pathToFileURL(modulePath).href)) as {
  scrubText(value: string): string;
};
const rawChunksPath = resolve(
  canonical,
  "packages/pipeline/src/lib/pipeline/raw-chunks.ts",
);
const { scrubLong } = (await import(pathToFileURL(rawChunksPath).href)) as {
  scrubLong(value: string): string;
};

type Part = [string, number | string];
type Generator = { prefix?: string; suffix?: string; parts: Part[] };
type Case = { id: string; input: string; expected: string };
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
        output += alphabet[(index * 17 + seed * 31 + partIndex * 7) % alphabet.length];
      }
    }
  });
  return output + (generator.suffix ?? "");
}

function instantiate(c: Case, round: number): { input: string; expected: string } {
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
  Array.from({ length: 5 }, (_, round) => ({ id: `${c.id}/${round}`, ...instantiate(c, round) })),
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
  return Array.from({ length }, () => alphabet[next() % alphabet.length]).join("");
};
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
    input += (part === 0 ? "" : separators[next() % separators.length]) + atoms[next() % atoms.length];
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
  for (const quote of ['"', "'", "`"]) {
    const value = `short${separator}${"v".repeat(4_097)}UNIQUE_TAIL`;
    for (const [suffix, close] of [
      ["closed", `${quote} after`],
      ["open", ""],
    ] as const) {
      const input = `${quote}token${quote}: ${quote}${value}${close}`;
      vectors.push({
        id: `v4/${separator.codePointAt(0)?.toString(16)}/${quote.charCodeAt(0)}/${suffix}`,
        input,
        expected: scrubText(input),
      });
    }
    const withinLength = 4_096 - `short${separator}`.length;
    const within = `short${separator}${"v".repeat(withinLength)}`;
    const withinInput = `${quote}token${quote}: ${quote}${within}${quote} after`;
    vectors.push({
      id: `v4/${separator.codePointAt(0)?.toString(16)}/${quote.charCodeAt(0)}/within`,
      input: withinInput,
      expected: scrubText(withinInput),
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
    throw new Error(`${vector.id}: canonical TypeScript differs from corpus expected output`);
  }
  if (rust[index] !== typescript) {
    throw new Error(`${vector.id}: Rust output differs from canonical TypeScript`);
  }
}

const fill = "lorem ipsum dolor sit amet ".repeat(11_000);
const longVectors = [
  `${fill} ordinary tail`,
  `${fill.slice(0, 260_000)} "token": "short\n${"v".repeat(4_097)}UNIQUE_TAIL" after`,
  `${fill.slice(0, 259_000)} ${"x ".repeat(4_000)} bob@example.test done`,
  `${fill.slice(0, 261_000)} -----BEGIN PRIVATE KEY-----\n${"A".repeat(2_000)}\n-----END PRIVATE KEY----- after`,
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
    throw new Error(`scrubLong/${index}: Rust output differs from canonical TypeScript`);
  }
}

console.log(
  `parity ok: ${vectors.length} scrubText vectors (${corpus.cases.length} corpus cases x 5 rounds + 20002 deterministic fuzz + 54 v4 multiline-cap regressions) and ${longVectors.length} scrubLong vectors, byte-identical`,
);
