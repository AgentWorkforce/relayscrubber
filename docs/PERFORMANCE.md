# Runtime bound and adversarial evaluation

Let n be input UTF-8 bytes, c decoded escapes, q quotes, b container delimiters,
and m candidate spans. Each is O(n). The engine is O(n log n) time and O(n) memory.
This is an algorithmic bound for the implementation, not a wall-clock guarantee
independent of hardware, allocator pressure or process scheduling.

1. Normalization advances its source cursor after every successful escape chain.
   Repeated percent-25, literal backslashes and serialized unicode backslashes
   consume their bytes without recursive decoding. Failed runs are copied whole;
   they cannot restart a suffix search at every backslash. Non-ASCII escaped bytes
   stay opaque; original UTF-8 bytes are not reinterpreted as single-byte text.
2. Sparse source offsets, quote endpoints, scope changes, container endpoints and
   physical line endings are indexed. Quote endpoints use a balanced tree keyed
   by delimiter kind/depth: O(q log q). Scope and container stacks push/pop each
   entry at most once. Searches in sorted indexes cost O(log n), including
   missing quote closes and repeated nested public assignments. There is no
   per-name scan to the end of the line/input.
3. Regex patterns are fixed at compile time and cached. Rust regex searches use
   finite automata without backreferences or lookaround. In general regex
   iterators can be quadratic; **we do not infer a linear iterator bound from the
   crate name alone**. These patterns have fixed distinctive prefixes and maximal
   bounded-alphabet bodies. A successful unbounded body consumes its token run;
   an unsuccessful short body has fixed maximum lookahead. URL recognition finds
   only schemes, then advances a separate monotone cursor. Private-key searches
   advance through the matching footer or stop at the first unclosed block.
   See [regex's complexity contract](https://docs.rs/regex/1.13.1/regex/#untrusted-input).
4. Compact-token runs are disjoint. Each dot segment is considered once as a
   possible JWT/JWE header and decoded once. Header JSON parsing has serde's
   recursion limit. No signature or network verification is performed.
5. The contextual assignment cursor advances monotonically, jumping over a
   removed value. A name is scanned/classified a fixed number of times. Quoted,
   container and public extents use indexes. YAML bodies are scanned only when
   that entire consumed body is removed. Userinfo authority scans stop before the
   next literal URL scheme's slash; nested schemes cannot cause repeated scans
   of the same unbounded suffix. Encoded value whitespace/ampersands remain part
   of a credential, not accidental token terminators.
6. Original-byte range mapping uses O(m log c) work. Sorting/merging takes
   O(m log m); output copies disjoint original ranges once. Unchanged Unicode and
   surviving original encodings are preserved byte-for-byte.
7. JSON traversal checks a 128-level depth bound before recursion. Key sorting and
   collision naming are O(n log n) in total key bytes; collision counters advance
   monotonically and reserve natural keys before allocating suffixes. Records
   have 16 MiB/64 MiB per-record/operation limits and an atomic error boundary.

Memory is linear, with sparse offsets rather than a source-position array per
byte. Text APIs accept a complete string; callers set their own admission/memory
quotas. A WASM trap or host resource error is an admission failure, never a reason
to retain/upload original input. Whole NDJSON results are buffered for atomicity.

`tests/adversarial.rs` checks 64 KiB and 256 KiB families with a generous five-second
CI ceiling; the JS test repeats them in WASM. `examples/evaluate.rs` records five
steady-state samples per size, mean/worst time and MB/s. Families include deep
escape runs, percent chains, repeated unmatched credential openers, quoted names,
public replay chains, URL authorities, large identifiers and PEM openers. The
known quadratic public-chain suffix scan was removed before the reported build.

Measured values and host/runtime versions are recorded in `RESULTS.md` and the
machine-readable receipts. Re-run them on the deployment hardware; do not turn a
single desktop benchmark into a universal service-level promise.
