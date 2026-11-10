# Candidate validation results

Candidate version remains `0.5.0-alpha.3`. Only invented inputs were used; no
sampled data, labels or private re-audit directories were accessed. No merge,
tag, publication or consumer adoption is authorized by these results.

The component-layer repair finds HTML attribute URL boundaries after decoding
HTML entities only. Percent escapes remain component data, including reserved
punctuation, double encoding and entity-wrapped percent signs. Selected values
map back to their full original source spans. Entity-produced separators remain
structural even without a following assignment. Component spans take precedence
when a separate decoded recovery match crosses an actual value boundary.
Previously supported nested and redirect URL recognition is retained.

Protocol-relative userinfo ends at a literal authority `@`; encoded slashes,
question marks, fragments, colons and at-signs stay in the password. Public
usernames containing encoded colons survive. Unquoted attribute boundaries also
require source-literal delimiters: percent-encoded whitespace, angle brackets
and quotes cannot truncate a credential or open a quoted attribute.

Test-only commit `307ff0f` records the baseline before production changes:
base `69a7435d` fails all four reviewer witnesses on text/JSON/NDJSON and 25,155
case/API pairs in the initial 84,831-case component matrix. The final component
matrix contains 84,840 invented cases: 84,592 credential cases and 248 benign
byte-identical controls. All 38 sensitive keys cross relative, root-relative,
protocol-relative, query-only and absolute URLs, three quoting forms, literal
and entity structural delimiters, seven reserved escapes and seven escape
styles. Styles include upper/lower hex, double encoding, entity-wrapped percent
signs, mixed reserved data and repeated percent prefixes. The property test also
exercises this dimension. Every API repeats its output to check idempotence.

Self-attacks cover assignment-looking encoded delimiters, percent prefixes,
plus, semicolon separators, fragments, encoded username colons, unquoted
percent-encoded whitespace/angle brackets, entity separators without assignments,
and a percent-encoded quote at an attribute's beginning. The last two groups
have separate failing-before/passing-after checks. Long component values run
through all APIs and second passes at 2,048 and 16,384 repetitions under the same
ten-second bound. The original HTML timing inputs and API calls are unchanged.

All earlier gates remain unchanged: HTML punctuation 63,906; separator 12,512
including 188 benign controls; fix13 754; fix12 371+58 and exact 16 MiB; fix11 257;
matrix 1186/ruling 43/residual 19+17; earlier 27; Bearer 43+9;
complete 141/numeric 45; tables 34+13; frozen 199. There are no fixture expectation
changes. The enlarged native/WASM parity corpus has 168,285 text and 168,290
structured vectors. Both text and structured parity use contiguous batches;
all cases and assertions remain, with Bun's default watchdog unchanged.

Hosted Rust 1.88 passes 88 tests on each of Linux and Windows, plus fmt/clippy.
Node and Bun each pass 689 tests. Frozen witnesses have zero missed secrets or
second-pass changes; Workers and independent-target reproducibility pass. The
unchanged long HTML probe measures 3.745s on Linux and 4.282s on Windows. The
exact downloaded/hash-verified hosted package repeats Node689/Bun689 and Workers.

Hosted artifact evidence, platform timings and runtime counts are recorded in
[the component repair receipt](results/review-fixes.json) under
`urlComponentLayerRepair`. [The artifact pin](results/artifact.json) and
[CI receipt](results/ci.json) identify the verified hosted package. Handoff
requires an immutable exact-head Linux, Windows and WASM CI run repeating all
gates, including artifact and package pin equality.
