# Candidate validation results

Candidate version remains `0.5.0-alpha.3`. Only invented inputs were used; no
sampled data, labels or private re-audit directories were accessed. Independent
precision re-audit remains separate. No merge, tag, publication or consumer
adoption is authorized by these results.

The relative URL repair removes the scheme requirement inside HTML attribute
values. Relative, root-relative, protocol-relative, query-only and schemeful
URLs share the existing sensitive-key catalog and source-offset mapping.
Sensitive query values and userinfo passwords are replaced in their original
spelling; public keys, usernames, hosts, paths and surrounding markup survive.
Plain-text protocol-relative passwords are also covered. Comments and raw-text
HTML elements do not supply attribute context, and the prior URL-regex source
exemption is retained.

The combined HTML property contains 63,906 cases: all 36,473 prior punctuation
witnesses plus 27,433 relative URL, userinfo and browser-resolution cases.
All 38 sensitive keys cross all 22 encoding styles, applicable positions from
the original seven-position model, three attribute quoting forms and mixed
punctuation. Extra probes cover `./`, `../`, query-only, fragments before queries,
backslashes after schemes, whitespace, every requested URL attribute, srcset
entries and meta refresh. Benign relative links, mailto, fragments, prose,
comments and script content stay byte-identical. Native and WASM checks compare
text/JSON/NDJSON output to independently constructed expected bytes and repeat
every API to verify idempotence. WASM correctness tests remain batched for Bun's
unchanged five-second watchdog.

Test commit `70a3719` adds the new matrix. Before the implementation changed,
base `db6a2739` failed 81,474 case/API pairs on the first 63,904 witnesses; the
final two cases add bare and single-backslash userinfo. Implementation
`f90a34a` closes the class, including the earlier structural URL-regex control.

The earlier gates are retained: separator 12,512 including 188 benign controls;
matrix 1186/ruling 43/residual 19+17; fix13 754; fix12 371+58 and exact 16 MiB;
fix11 257; earlier 27; Bearer 43+9; complete 141/numeric 45; tables 34+13;
frozen 199 with zero misses and second-pass changes. All timing input sizes,
API calls, assertions and ten-second limits are unchanged. Scans advance
monotonically over disjoint values and authorities; the adjacent-value cache
holds only one spelling and its ranges.

Hosted Rust 1.88 passes 82 tests on Linux and Windows, plus fmt/clippy.
Node 340 and Bun 340 pass with fresh 83,445 text
and 83,450 structured vectors. Workers and independent-target reproducibility
pass. The unchanged long HTML probe measured 4.681s on Linux and 6.464s on
Windows, both below ten seconds. The hosted artifact evidence and Linux/Windows timings are recorded in
[the repair receipt](results/review-fixes.json) under `relativeAttributeUrlRepair`.
[The artifact pin](results/artifact.json) and [CI receipt](results/ci.json) identify
the verified hosted package. Handoff requires an immutable exact-head Linux,
Windows and WASM CI run that repeats every gate, including pin equality.
