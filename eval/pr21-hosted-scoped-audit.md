# PR21 exact hosted-artifact audit

Candidate: `b54745161cade161318e6e1dc9ca5486b91c474d`, alpha.9.
CI run `43394654201`, artifact `14024110518`.
All inputs are invented. No session data, fixture access, engine builds, rule
edits, consumer pin-file changes, release/tag creation, or deployment.

## Findings and scope

**No failures in the tested intent-aligned subset:** all 37 frozen author
fixtures, 728 additional inline password-family cases, and 45 benign controls
pass on native alpha.9 and the real pipeline adapter with hosted alpha.9.
This is a bounded subset result, not a claim that all natural-language
disclosures are covered or a merge/publication approval.

**Length-boundary question:** `my password is q` and `my password is !`
remain unchanged on both candidate paths. Of 216 one-character cases using
password/passcode/passphrase/pw and is/was/possessive-colon, 162 miss complete
redaction. Some quoted assignment forms do redact. PR21's summary does not
state an accepted minimum length; confirm that boundary before treating
these as either required fixes or explicitly unsupported inputs. Do not
silently count them as outside scope.

**Broader grammar, reported separately:** the original broader corpus has
5,254 incomplete-redaction cases per candidate path. That includes the 162
length-boundary cases above and 5,092 other broader/stress misses. This
collection exercises extra nouns (`pass`, `PIN`, `secret`, `key`, `token`),
extra connectors (`=`, `is now`, `set to`, `is set to`), unquoted multiword
values, multiline disclosures/values, multiple disclosures, and seeded
mutations. Those wider requirements are not asserted as PR21 blockers;
their authorization/contract is a separate decision. Earlier broad FAIL
counts must not be presented as failures of the 37 author fixtures.

| Tested collection (unique cases per engine) | alpha.5 failing | alpha.9 failing |
| --- | ---: | ---: |
| PR21 author fixtures, 22 positive + 15 benign | 20 / 37 | 0 / 37 |
| Additional intent subset, 728 positive | 614 / 728 | 0 / 728 |
| Additional benign controls | 0 / 45 | 0 / 45 |
| Broader collection including length questions | 5,505 / 6,398 | 5,254 / 6,398 |

Each case runs as text, JSON and NDJSON. Across all 7,208 cases, 86,496
observations were made. Native and actual pipeline-adapter decoded results
agree exactly: zero differences in 21,624 comparisons for each version.
All 60 benign cases remain unchanged. The scoped audit exits 0 for its tested
intent subset; it does not green the wider grammar. Seven oracle/generator
tests pass.

## Exact artifacts and real seams

Downloaded package SHA-256:
`d7eb1702fe73092d6607efe2481d67c1b3a97a06a90505afd2c5d5b6dec7db68`.
Hosted WASM SHA-256:
`008406d7ed78ff85bea510544ceaf0818477f277f0705a4d61a56783ef7117f4`.
Manifest file SHA-256:
`b6f3f5b93f58e9fb0725825cc6fc85e046221d5ded006e3cb8f27a91318659ef`.
Engine source identity:
`291a6b373388b7bc5295091d1bcbc13a2e8c64e37b2bfe0d06b2dc4f12df32c9`.
All four supplied identities match the downloaded artifact.

The native probes are the already-built Desktop upload scrub seam from
`06164e88bcf7bd77f49d5979527f0d5aafb8b450`, using alpha.5 versus the
source-identical alpha.9 candidate engine tree (8213b34 and b547451 differ
only in documentation). No rebuild was performed. The candidate probe's
only Desktop source adjustment is the test-only version marker; its crate
dependency points at the candidate source. This is not the delivery queue
or a live upload proof.

The pipeline path executes **unmodified `bindgen-engine.ts` and its actual
dependencies** from source `7e9b2f0f6b1af7af9b49087c4f4677f5d6d1a496`.
The baseline uses its real alpha.5 pin and released package. Candidate bytes
are initialized with a test-only, in-memory identity; the adapter's release
schema label is `UNRELEASED-CI-43394654201`. It does not assert that such a
GitHub release exists. Actual provenance is the downloaded CI artifact and
its verified hashes above. No deployed or repo-tracked consumer pin changed.
Each version runs in a fresh process so generated-glue module caching
cannot reuse an earlier WASM initialization.

## Evidence and reproduction

Machine report:
[`../docs/results/pr21-hosted-scoped-audit-b547451.json`](../docs/results/pr21-hosted-scoped-audit-b547451.json).
Harness: `scripts/audit-pr21-disclosures.mjs` and runtime loader
`scripts/qualification-ts-loader.mjs`. It uses existing probe binaries from
the [initial preparation instructions](arlap-disclosure-qualification.md).
Do not rebuild for this audit. Required packages are the verified alpha.5
release and the extracted hosted candidate above. The pipeline snapshot and
all copied private source stay under ignored `.task-tmp/`; do not publish
those copies.

With the pinned pipeline source available at `.task-tmp/pipeline-7e9b2f0f`,
TypeScript 6.0.3 and zod 4.6.7 (the adapter declares `^4.1.13`):

```sh
QUALIFICATION_TYPESCRIPT_MODULE=/path/to/typescript/lib/typescript.js \
  node --import ./scripts/qualification-ts-loader.mjs scripts/audit-pr21-disclosures.mjs
```

The loader executes TypeScript at runtime and emits no build files. The
audit writes only synthetic reports under ignored `.task-tmp/`. No network
ingest, storage, dashboard, or deployment is exercised by this command.

The [family breakdown](pr21-family-breakdown.md) supplies per-noun, separator,
value-shape, quoting, multiline and multiplicity counts, plus bounded invented
witnesses with four-path output hashes and deterministic regeneration recipes.
