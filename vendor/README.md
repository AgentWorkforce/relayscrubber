# Historical evidence only

Nothing here is compiled, treated as the current oracle, or included in the new
crate package. The frozen Rust v8 sources and tests were copied/moved from
GitHub main `61bd5ca` without rewriting their internal historical references.
Those old relative include paths are intentionally archival, not runnable here.

`frozen-ts-v8` is the former `canonical/` directory. The TypeScript candidate 9
in relayhistory-pipeline PR #479 is known unsafe and was not adopted. The v6/v7
ledgers and corpus retain their original provenance; their presence does not
authorize their adoption. Current behavior is specified in `docs/SPEC.md` and
implemented exclusively by `src/`.
