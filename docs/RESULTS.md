# Candidate validation results

Candidate version remains `0.5.0-alpha.3`. Independent precision re-audit stays
separate. Only invented inputs were used; no sampled data, labels or private
re-audit directories were accessed. No merge, tag, publication or consumer
adoption is authorized by these results.

The HTML attribute URL punctuation property now uses all38 sensitive keys from
the shared separator catalog, with an equality assertion preventing subsets.
All five characters `: / ? & =` vary across22 encodings at seven positions:
colon, each of the two scheme slashes, path slash, query opener, ampersand and
equals. Fully encoded `://` is explicitly covered. Uniform full URLs, isolated
positions and a deterministic529-row covering array exercise every pair of
position encodings: all21 position pairs cover every22x22 style combination,
each crossed with every sensitive key. Expected output replaces only the value.

The combined property has36,473 cases:32,755 expanded cases plus all3,718 earlier
witnesses retained unchanged. There are34,490 sensitive and1,983 byte-identical
benign cases. Every case exercises native and exact hosted WASM text/JSON/NDJSON,
original source spelling and second-pass identity. The earlier12,512 separator
cases remain unchanged, including188 benign/malformed controls.

Test-only commit `eb32500` expands coverage without changing the engine. The
punctuation engine fix remains `98f82be`, preceded by failing tests `bfb9833`,
with bounded performance follow-ups `3613a31`/`3afa509`. Historical base `7e8d410`
fails3,292 cases per API on the original3,718 witnesses; its exact hosted WASM
fails all21 new tests. The current engine passes the full expanded property.

Rust1.88 native81, fmt and clippy `-D warnings` pass. Exact hosted Node231/Bun231
pass with fresh56,012 text and56,017 structured vectors and all199 frozen
witnesses: zero annotated misses and zero second-pass changes. All earlier gates
remain covered: matrix1186/ruling43/residual19+17; entity171+percent583;
query371+58+exact16MiB; fix11 257; earlier27; Bearer43+9; complete141/numeric45;
tables34+13; admission, resource bounds, Workers and reproducibility.

The enlarged correctness matrix and its existing native timing probe run
serially so the matrix does not consume its own probe CPU budget. The exact
1,392,743-byte/16,384-attribute input, all API/idempotence calls, assertions and
ten-second deadline are unchanged. Other earlier tests retain their scheduling.
Bun's five-second per-test default is unchanged. The56,017 structured parity
records are checked in four contiguous batches of at most16,384, with every
API and second-pass assertion retained; the fixture is loaded once. The prior immutable engine CI
measured3.847s Linux/9.631s Windows; the expanded successor must repeat the same
timing gate before handoff. Local debug symbols were disabled after a disk-full
build; hosted CI keeps its unchanged default Rust profile.

Pins were regenerated from the SHA256-verified [terminal-green hosted artifact](https://github.com/AgentWorkforce/relayscrubber/actions/runs/42884504875)
and are byte-identical: only test coverage and receipts changed. See
[the behavioral receipt](results/review-fixes.json), specifically
`htmlAttributePunctuationRepair.coverage` and `fullSensitiveKeyFollowup`, for
the matrix proof, retained witnesses, timing contract and verified source/WASM/
glue/declaration/adapter/package hashes.

Final handoff requires one new immutable terminal-green exact-head CI on Linux,
Windows and WASM, including every expanded case and unchanged timing/pin gate.
