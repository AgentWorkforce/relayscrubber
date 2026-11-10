# Candidate validation results

The candidate remains `0.5.0-alpha.3`. Independent session precision re-audit is
separate; these invented regression tests do not measure real-session precision.
No private session samples, labels or re-audit directories were accessed. No
merge, tag, publication or consumer adoption is authorized by these results.

The latest repair recognizes HTML-encoded URL punctuation inside attribute
values: `:`, `/`, `?`, `&` and `=` work together across decimal, hex, named,
semicolonless numeric, recursive and mixed percent/entity forms. The existing
URL scanner runs on an attribute-local recognition view and maps only selected
credential values back to original source bytes. Quoted and unquoted attribute
spelling survives unchanged around `[REDACTED]`.

Test-only commit `bfb9833` precedes implementation `98f82be`. A shared generated
property covers 22 encoding styles, eight sensitive keys, three attribute forms,
the query-opener/equals cross product, and benign non-sensitive keys: 3,718 cases,
including 198 byte-identical benign controls. Exact base `7e8d410` fails 3,292
cases per text/JSON/NDJSON API. Its downloaded, hash-verified hosted WASM also
fails the new tests. The successor fails zero and is stable on second passes.
The reviewer's exact `&amp;signature&#61;` href witness is included.

The earlier separator property remains 12,512 cases, including 188 benign and
malformed/non-amp controls. All previous regression gates remain unchanged:
reviewer matrix 1,186; ruling43; residual19+17; entity171+percent583; query371+58
and exact16MiB; fix11 257; earlier27; Bearer43+9; complete141; numeric45; tables34+13.

Rust1.88: 81 all-target/all-feature tests, fmt and clippy `-D warnings` pass.
Node100/Bun100 pass with fresh23,257 text and23,262 structured vectors. All199
frozen witnesses have zero annotated misses and zero second-pass changes.
Long all-API tests cover numeric zero runs, nested entities and1.4MiB of repeated
HTML attributes at2,048/16,384 copies, under unchanged ten-second limits. Recognition
cursors advance monotonically and retain only a one-value cache.
Bun's five-second default per-test timeout is unchanged; property cases are batched.

The portable pin is the SHA256-verified [hosted implementation artifact](https://github.com/AgentWorkforce/relayscrubber/actions/runs/42878437930).
Linux81 and hosted Node100/Bun100, reproducibility, Workers, frozen witnesses and
packaging pass; the WASM job fails only comparison with the superseded pin.
The Windows implementation job was still queued when this receipt was prepared.
The downloaded package was hash-verified and replayed locally through Node/Bun
and Workers. See [the behavioral receipt](results/review-fixes.json), specifically
`htmlAttributePunctuationRepair`, for before/after counts, mapping audit and
portable source/WASM/glue/declaration/adapter/package digests.

Final handoff requires one immutable terminal-green exact-head CI on Linux,
Windows and WASM, including unchanged timing limits and equality with the
regenerated pins. The implementation artifact alone does not satisfy that gate.
