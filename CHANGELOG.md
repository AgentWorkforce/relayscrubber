# Changelog

## Unreleased

Preserve an exact `project_key` whose value is a normalized repository identity
(`github.com/owner/repo`), so session capture can record which project a session
belongs to. Other `project_key` values, prefixed names and composite values stay
sensitive; credentials beside or inside a kept identity still redact.

## 0.5.0-alpha.5 (unreleased)

Preserve complete query references, awaited calls and Rust reference type aliases while retaining literal-secret redaction across URL decoding layers. Avoid unnecessary normalization lookups outside newlines.

0.5.0-alpha.4: releases the security-reviewed engine from PR #15 head 77b89c60 (closes unmatched-quote recovery, HTML-entity and semicolonless separators, entity-encoded URL punctuation, scheme-less attribute URLs, percent-encoded reserved characters in values and userinfo, fully encoded userinfo authorities, nested multi-layer values). Precision: non-zero false positives remain.
