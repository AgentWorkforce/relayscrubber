# Candidate validation results

Candidate version is `0.5.0-alpha.10`. Only invented inputs were used; no
sampled data, labels or private re-audit directories were accessed. No merge,
tag, publication or consumer adoption is authorized by these results.

## Alpha.10 prose disclosure security fixes (candidate)

Three classes reported against the alpha.10 candidate (`643beb8`) are fixed
before any release; this section records local and source-run results only
and is not a PASS or an adoption claim. Two pins of the fixed code passed
their exact-head runs and were then blocked in the independent review. Both
are kept in [the receipt](results/review-fixes.json): the first (receipt head
`639f7f0`, code `a9c679f5`, run `44568426111`, exact-head run `44574798433`)
as `alpha10BlockedHostedArtifact`, the second (receipt head `48f9574`, code
`9338339b`, run `44628698592`, exact-head run `44633710253`) as
`alpha10SecondBlockedHostedArtifact`. The pin before them (run `44509387631`
on `d36050c5`, code `135c26de`) is `alpha10SupersededHostedArtifact`.

The hosted artifact pin in `docs/results/` now names the build of the
repaired head `30e6c348` (last code commit `bab88e75`) from CI run
`44655994607` (artifact `14594295374`, package SHA-256 `53ad2d6d…`, WASM
`ec2f44ab…`, ruleset source `2758bc53…`); a local Rust 1.88.0 rebuild
reproduces the package and every payload byte for byte. That run passed Linux
and Windows Rust (165 tests each), the frozen 199 witnesses with no missed
secret, Node 917/917 and Bun 917/917, and failed only its committed-pin
check, which still compared against the blocked `48f9574` pins. The
exact-head run of the commit carrying this pin must report committed-pin
equality and reproduce the same package and payloads; that gate has not run
yet and is reported with the handoff, not here.

The second block named one class, recorded with before and after outputs
under `alpha10ColonContextRepair` in the receipt:

- After a bare colon, a type-looking value was kept with no evidence that it
  was a type: `pw: abcq<defq>` stayed visible. A type annotation now needs
  source context in the engine's view, which is at most 512 bytes before the
  key in the same string: a fn signature, a struct, interface or type body
  around the key, or a `let`/`const`/`var` declaration naming it. So
  `struct X { pw: Vec<u8> }`, `fn f(pw: String)` and `const pw: string` are
  unchanged, and `pw: abcq<defq>`, `pw: Vec<u8>`, `password: Option<String>,`
  and `pw: string` redact. The controls that pinned the old output moved to
  the positive sets, each with a source-context sibling that keeps its output.
- Code-looking values after a bare colon had the same exemption and follow
  the same rule, for every credential key: `password: Orchid.River99!`,
  `pw: abc(def)` and `password: match option {…};` redact, and
  `const opts = {password: orchid.river};` is unchanged.
- Accepted precision tradeoff: no context is carried across lines or records.
  A multi-line body within 512 bytes of its opener keeps its field; a field
  line alone (`    pw: Vec<u8>,`), a field in its own NDJSON record and a
  field more than 512 bytes below its opener redact. Struct literals, class
  members and calls with a space before `(` now redact too, and the frozen
  witness `switch-case-auth` no longer equals its archived output (163 of 199
  exact, with no missed secret).
- Still kept: a code-shaped value in a labelled argument of a call whose `(`
  directly follows a callee, so `login(password: Orchid.River99!)` and prose
  shaped like one (`Re(password: orchid.river)`) stay visible. These and the
  other kept forms are listed under `alpha10ColonContextRepair.residuals`
  for the review to rule on.

Qualification (`scripts/qualify-prose-disclosures.mjs`, 7,541 cases, three
forms) on the repaired head fails no case of a required scope on native Rust
or on the WASM with the pinned hash, and the 22,623 native/WASM comparisons
differ in no byte. The optional-noun scope, which is not required, keeps a
value in 3,338 of its 3,952 cases per form.

The first block named three classes, recorded with examples under
`alpha10BlockRepair` in the receipt; they stay fixed:

- A bare cue's value ends only at a bracket or list that the line opened
  before the noun. An unmatched `)`, `]` or `}` and `&key=` or `;key=` are
  value: `pw: abc) tail` and `pass phrase: abc&key=v` redact to the end.
- Contiguous quoted segments and text glued to a close are one value:
  `my password is "abc""defq"` becomes `my password is "[REDACTED]"`.
  Whitespace still separates, so `"abc" "defq"` keeps `"defq"`. A value is
  exempt only when the whole run is references or placeholders; one literal
  part makes the whole run one marker.
- `docs/results/ci.json` and the receipt's top-level `interface`,
  `localChecks` and `controls` describe alpha.10; the alpha.8 objects are
  kept under `alpha8Receipt` and the `alpha8…` keys.

Forms the first repair left visible or over-redacts are carried under
`alpha10ColonContextRepair.residuals`.

The three classes fixed before the first block:

- Colon and equals cues for all eight nouns, with or without `my`, redact the
  whole value; type annotations, references and a lone `None` stay visible.
- A close quote escaped at the opener's level (`\"`, `\'`, `` \` ``) no longer
  ends the value; the 1024-byte bound is kept.
- Every Rust/WHATWG whitespace character, one line break, and encoded
  spellings (`&#32;`, `&#x20;`, `&nbsp;`, `%20`, `\u0020` and the rest of the
  matrix) separate the words.

`tests/prose_disclosure_alpha10.rs` and `js/test/prose-disclosure-alpha10.test.mjs`
run each case through the five text, JSON and record APIs plus idempotence.
On `643beb8` native Rust fails 188 of 2,912 cue cases, all 576 escape cases,
3 of 3 escape bounds, 66 of 148 separator cases, 152 of 164 encoded cases and
23 of 61 named cases; the candidate fails none. Qualification
(`scripts/qualify-prose-disclosures.mjs`, 7,539 cases) and the 257
precision-receipt rows are unchanged, and the synthetic evaluation differs only in
the ruleset source hash and timing.

A later probe of the candidate (`bcee2b3`) found that words or a bullet before
the noun could still redact less than the bare cue: a sentence-like prefix
(`The new password: zq9Secret`) leaked the whole value (F1), and a determiner
(`my password: correct horse battery`) kept the words after a documentary
word or conjunction (F2). Both now redact what the bare cue redacts. On
`bcee2b3` the probe's F1 matrix leaks 21 of 666 rows and its F2 matrix 152 of
336; the fix leaks none. A wider matrix of 101,760 prefixed lines (eight
nouns, eight cue spacings, 30 value styles, 53 prefixes) through text, long
and JSON text drops from 18,564 to 1,200 lines that keep a token the bare cue
redacts; the rest are prefixes that open a bracket before the noun, whose
close ends the value by design, and `orchidq, userq: bob`, where the bare
line-start form redacts the whole line as YAML. The frozen witnesses, the
qualification run and the 257 precision rows are unchanged; three superseded
pins (`inherited_assignment-166` and ruling rows 6 and 22) now redact the
whole value.

## Supplemental residual-row controls

The delayed authoritative ruling (lead ref `4cd7f0bfa23b`, relayed by fab-pipe
message `246250741124923392`) explicitly confirms `residual_cases.json` row12.
Its position, exact old/new expectations and all 17 positive controls remain.
Ten same-position siblings are appended: non-sensitive `mode`/`route` keep the
original record-shaped RHS; `const`/`let`/`var` object references remain visible,
including with the same documentary prefix; quoted declaration literals redact.
All ten pass native Rust 1.88 and exact hosted artifact `13857345338` across four
APIs and idempotence, with no engine or package-pin change. No other legacy
expectation is changed. The combined corpus now has 9,552 cases; blocked BFE
still fails the same 2,282 rows/API with identical failed-ID hashes. Fresh vectors
now contain 235,556 text / 235,561 structured cases. The follow-up exact-head
CI gate is required; the e7f validation below remains the preceding all-green receipt.

## Alpha.8 bare reassignment recall repair

The alpha.7 engine/artifact PASS for `bfeaa79d` was withdrawn by the independent
reviewer (message 246242359458385920). Published alpha.6/alpha.7 preserve some
bare sensitive reassignments that alpha.5 redacts. The successor removes the
spaced-equals/semicolon source-shape exemption: `password = summerDays;`,
`password = API_TOKEN;`, members, calls and templates redact without an
independently recognized declaration. `const`/`let`/`var` declaration references
retain their existing controls. Word prefixes also cannot waive an equals
assignment, including exported declaration literals. Only a complete Bearer
literal may delegate its entire credential body to the standalone scanner;
additional tails fail closed.

The 9,542 invented controls cover all explicit key families, case spellings,
export prefixes, source-shaped values, literal siblings, declarations and all
four APIs plus idempotence. Pinned Rust 1.88 native and the exact downloaded
alpha.7 WASM artifact fail the same 2,282 rows per API. The successor passes all 38,168 expectations and idempotence on native and
exact downloaded hosted WASM. Source CI passes Rust 1.88 Linux106/Windows106,
fmt, clippy with warnings denied, frozen199 with no misses, Node772/Bun772,
Workers, reproducibility and packaging. The source WASM job fails only the old
committed artifact pin comparison. Receipt-only exact-head all-green and
independent engine/artifact review remain required.

The lead explicitly authorizes 45 preservation-to-sensitive expectation
corrections in `eval/alpha6_syntax_cases.json`; every row, old output and new output
is enumerated in [the receipt](results/alpha8-reassignment-repair.json).
One additional inherited residual precision control contradicts the same
assignment policy: `eval/residual_cases.json` `/benign/12`, input
`Proposed schema: auth = record { issuer, audience }`, now expects
`Proposed schema: auth = [REDACTED]`. Its position remains stable with an explicit
input/expected object (19 controls, 18 preserved and one sensitive). The receipt
enumerates this correction too. All other legacy fixture rows, declaration
controls and security positives are unchanged. This retains alpha.7 whitespace and full-passphrase repairs. Desktop
adoption, publication and a new security PASS remain separately scoped.

Verified [source CI](https://github.com/AgentWorkforce/relayscrubber/actions/runs/43021347175), artifact `13855726467`:
package `7f08abcda6ee1e463a2414878131433631de869125c8f9153ed8c9ded555f099`, WASM `546cc6e7f9bf0d644608d84686dc59e1638045661cc43f2fb9255d29cc28c825`,
source `653b5822768c7ef2ae51f74f52f3514389a7fcd019cf5d92eb5fb6c173d01714`. Official archive digest and all six payload
pins match. The downloaded package passes Node772/Bun772 against fresh
235,546 text / 235,551 structured vectors. All 226,004 prior text / 226,009 prior
structured outputs were compared: exactly the 45 authorized bare expectations
change in each API group; every other prior output is byte-identical.
Native timing maxima Linux 2.493s / Windows 6.105s remain below
unchanged 10s, with the unchanged 5s WASM checks passing.

## Historical alpha.7 passphrase repair (PASS withdrawn)

Source/version commit `3fc896afece46905a40978af076bf5b9a913a2f2` closes the independent BLOCK on `dd0db036`. The four trailing-whitespace corrections remain. The unsafe Markdown prose shortening is removed; explicit bullet assignments retain the complete credential value regardless of words/case, including numeric prefixes and entity-encoded tails. CLI argument grammar remains separate. Entity-aware bounds are used only after preservation decisions, and never enable an exemption. Prefix inspection stays bounded. Five original prose precision expectations are withdrawn as sensitive.

The 1,329 invented review controls fail in 524 cases per API on exact blocked native and hosted artifact 13835231887; the repair passes across text/long/JSON/NDJSON and idempotence. Inherited gaps are closed rather than deferred. All prior 224,124 text / 224,129 structured outputs were compared: only the intended trailing-space restoration and the authorized correction below differ. Every other prior output is byte-identical.

**Authorized legacy correction:** lead ruling ref 7456c09bd3e1, resent by fab-pipe message 246182902534492160, changes exactly `eval/structural_cases.json` row10 `/10/expected` (`prose_outside_assignment`). Input: `- During the deployment discussion, auth: review the available alternatives.`. Old expected: `- During the deployment discussion, auth: [REDACTED] the available alternatives.`. New expected: `- During the deployment discussion, auth: [REDACTED]`. Nine case variants were added; all other legacy rows and prior positive controls remain unchanged. No security positive was removed or weakened.

Rust 1.88 Linux 105 / Windows 105 fmt/clippy, Node 732 / Bun 732, fresh 226,004 text / 226,009 structured vectors, frozen 199 zero misses/regressions/secondpass, Workers, independent reproducibility, packaging and downloaded-package replay pass. Source timing maxima Linux 2.879s / Windows 5.367s stay below the unchanged 10s limit; WASM timing limit remains 5s.

Verified source-generation [CI](https://github.com/AgentWorkforce/relayscrubber/actions/runs/42984758558), artifact `13838748927`: archive `3fa41795a2e07e38545fc8553d2866d055dc2051f0b1c233dc149ed977d5cbda`, package `adb643dadac708b934ce91ce39fa7d4c34d205dc9e55c657ea649680675ce51a`, WASM `0896ae88f27d90645f8bec4b6da5bacff4dcbe35365864bea00638a9c989c470`, source `cef2939f0b78a54c050a13f32c2cb70903a7e79a5558b3f9e915e621503bacdb`. Every official archive/manifest/payload/glue/adapter/package hash was verified. Source WASM fails only superseded pin equality. Receipt-only exact-head all-green and independent replacement engine/artifact review remain required. Production precision/adoption/publication remain separate. Evidence: `docs/results/alpha7-passphrase-review-repair.json`.

## Historical alpha.6 evidence

HTML entities establish the outer URL structure. Percent escapes stay inside
their components: a sensitive outer parameter is redacted through the next
literal or entity separator, including every encoded credential tail. Public
values open one percent-decoding layer at a time for nested URL/query discovery.
Each nested sensitive value stays opaque at its own layer. Original source
ranges compose through decoding, preserving every surrounding spelling.

Userinfo discovery separates authority delimiter encoding from password data.
Fully encoded protocol-relative and absolute authorities, including percent
encodings of HTML entity spellings, retain their complete password source span.
Reserved slashes, question marks, fragments, equals signs and at-signs cannot
truncate a password. Public usernames with encoded colons survive unchanged.
The layer budget is four percent layers and four entity layers; credential-bearing
public values fail closed if their nested percent budget is exhausted.

Disjoint lexical URL regions and cached parameter ends avoid overlapping suffix
scans. Source provenance keeps encoded whitespace, quotes and angle brackets
inside data. Non-rendering authority guards protect benign public userinfo from
flattened recovery scans, while sensitive assignments such as
`password=SYNTH@host` still redact. Known URL-valued public fields retain bare
userinfo recognition; arbitrary benign search values remain unchanged.

Test-only commit `307ff0f` records the initial failure on `69a7435d`: all four
reviewer witnesses fail across text/JSON/NDJSON, with 25,155 failing case/API
pairs in the initial outer-component cross-product. Test-only `d81085a` exposes
the nested credential-tail loss on the previous artifact. Test-only `4fee11b`
exposes the encoded-authority blocker on `7a08bee` before source edits: 42,765
failing case/API pairs in its initial cross-product. Additional relative-query
and assignment-guard regressions also have failing-before/passing-after evidence.

Coverage includes 84,840 outer component cases, 23,002 nested cases and 26,873
encoded-userinfo cases. The userinfo matrix has 25,821 positives and 1,052 benign
controls, crossing 22 authority delimiter spellings with seven reserved password
escapes, seven data styles, additional whole-URL encoding and four contexts.
Styles cover upper/lower hex, double encoding, numeric/named entity percent
signs, repeated percent prefixes and mixed reserved data. Five exact reviewer
encoded-authority witnesses, lexical data escapes and budget controls also run.
The property test includes both component data and fully encoded authorities.
Every API checks second-pass stability and original surrounding spelling.

All earlier gates remain unchanged: HTML punctuation 63,906; separator 12,512
including 188 benign controls; fix13 754; fix12 371+58 and exact 16 MiB; fix11 257;
matrix 1186/ruling 43/residual 19+17; earlier 27; Bearer 43+9;
complete 141/numeric 45; tables 34+13; frozen 199. There are zero fixture
expectation changes. Self-attacks cover percent-prefixed escapes, plus,
semicolon separators, fragments, encoded username colons, entity separators
without assignments and repeated nested prefixes. The original HTML timing
inputs, API calls, assertions and ten-second bounds remain unchanged.

Hosted Rust 1.88 passes 96 tests on each of Linux and Windows, plus fmt/clippy.
Node and Bun each pass 725 tests using 218,160 native text vectors and 218,165
structured vectors, with all 199 frozen witnesses. Contiguous 8,192-case parity
batches preserve every assertion and Bun's default watchdog. Frozen witnesses have zero
missed secrets or second-pass changes; Workers and independent-target
reproducibility pass. Normalization copies ordinary runs in bulk and clones
unchanged UTF-8 once; impossible userinfo/HTML scans return early. These changes
retain the unchanged 16 MiB test and Bun watchdog. The SHA256-verified hosted
package repeats Node725/Bun725 and Workers locally.

Hosted source, archive/package hashes, runtime counts and platform timings are
recorded in [the encoded-userinfo repair receipt](results/review-fixes.json)
under `encodedUserinfoLayerRepair`; historical receipts remain intact.
The version-only alpha.4 cut from reviewed head `77b89c60` is recorded under
`alpha4Release`, with new hosted artifact identities and unchanged engine/tests.
Its downloaded archive, embedded manifest and every payload digest were verified.
Precision: non-zero false positives remain.
[The artifact pin](results/artifact.json) and [CI receipt](results/ci.json)
identify the verified hosted package. Handoff requires one immutable exact-head
Linux, Windows and WASM CI run repeating every gate, including source, WASM,
glue, declarations, adapter and package pin equality.

The alpha.5 precision follow-up starts at published alpha.4 main `ba262739`.
Its test-first additions and source are recorded in `alpha5PrecisionRepair`.
All 194 unchanged benign cases fail on the published base; 491 positive/mixed
controls also fail per API. The 2,355-case shared fixture covers complete query
references, awaited calls and Rust reference aliases, with literal/encoding/tail
siblings and mixed literal-userinfo/query-reference controls. The successor
passes all precision cases and second-pass checks. Complete attribute guards
propagate through nested component/userinfo views; standalone URL recovery
remains active so whitespace tails cannot gain a prefix exemption.

The newline-only lookup optimization changes no compared output bytes across
220,515 native text and 220,520 JSON/NDJSON cases. Exact length-prefixed aggregate
hashes and the reconstruction recipe are in [the byte proof](results/alpha5-newline-proof.json).
The source/version manifest identities change as expected. No matrix input,
fixture expectation, API assertion, Bun watchdog or ten-second limit is relaxed.

The alpha.5 portable pin is the independently SHA256-verified [hosted implementation artifact](https://github.com/AgentWorkforce/relayscrubber/actions/runs/42941589608)
at `5843309e0d9bd0859c17736fb8f84bb5699ce3af`. Linux/Windows Rust98/fmt/clippy,
Node726/Bun726, Workers, independent WASM reproduction and packaging pass;
WASM fails only comparison with the superseded alpha.4 pin. Windows and Linux
timings pass unchanged ten-second limits; the receipt records every measurement.
Downloaded-package Node726/Bun726
and Workers replay pass with fresh 220,515 text and 220,520 structured vectors,
and frozen 199 has zero misses or second-pass changes. The 63,906/84,840/26,873/
23,002 matrices and every earlier gate remain intact. Final handoff requires
ALL-green exact-head Linux, Windows and WASM, including equality with these
precise source/WASM/glue/declaration/adapter/package pins. No merge or publish.


## Alpha.6 syntax precision and independent recall repair

Independent review BLOCKED `1c86b849` despite green CI and matching artifact
hashes. Context-free PascalCase YAML scalars, literal regex bodies under
credential keys, and bare `Key` scalar paths regressed alpha.5 recall. The prior
engine/artifact PASS is withdrawn. Cryptographic identity does not prove recall.

[The public review suite](../eval/alpha6_review_recall_cases.json) contains 902
invented controls. Exact alpha.5 has zero failures. The frozen blocked native
binary and its exact hosted WASM each fail 844 cases on every text/long/JSON-string/
NDJSON-string API. The replacement passes every native control, including direct
structured `Key` inputs. [The repair receipt](results/alpha6-review-blocker-repair.json)
records the observed red-before/green-after evidence.

The limited repair removes those three unsafe exemptions. Types require the
existing source-context grammar; regex literal bodies under credential keys and
bare `Key` scalars retain alpha.5 redaction. Non-credential regex source and
explicit source types stay preserved. Fifteen public invented preservation
expectations are explicitly corrected to sensitive: 8 regex assignments, 6 standalone
PascalCase fragments and 1 bare Key path. No private held-out labels were opened
or relabelled. The original ambiguous Key/path precision request is not claimed
solved without an approved contextual rule; no filename/type allowlist replaces it.

The original precision corpus now has 2707 controls (134 preservation/2573 attack),
with 902 review controls (8 preservation/894 attack): 3609 total (142/3467).
[The pinned Rust 1.88 baseline](results/alpha6-syntax-baseline.json) fails 86 benign
and 85 attack controls in the corrected original corpus. All replacement controls
pass across text/long/JSON/NDJSON and second passes. Every pre-alpha6 security
matrix, frozen witness and resource limit remains unchanged.

[Replacement source CI](https://github.com/AgentWorkforce/relayscrubber/actions/runs/42962311431)
verifies Linux/Windows Rust 102/fmt/clippy, Node 729/Bun 729, fresh 224,124 text and 224,129 structured
vectors, frozen 199 with zero misses/regressions/second-pass changes, Workers,
independent reproducibility and packaging. It failed only the superseded pin
comparison. Package SHA-256 `374b72f5d21ecaae558273bb350103c2d111cdbbb1eaf803615c221449066cc6`; WASM SHA-256 `f1d393b22ce47d4cb4ca762107a7f66e8b2747f6de60c193e8b07646db28e5fd`.
[Artifact verification](results/alpha6-artifact-verification.json) independently
checks GitHub's archive digest, all file/package hashes and canonical source identity.
Downloaded-package replay and final immutable-head pin gates are recorded in
[the review receipt](results/review-fixes.json).

Exact-head Linux/Windows/WASM must all pass before resubmission. Independent
replacement engine/artifact approval and production precision re-audit remain
pending. Only invented/public frozen data was used; no merge, tag or publish.
