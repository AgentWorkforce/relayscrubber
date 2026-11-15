# Changelog

## 0.5.0-alpha.10

Redact natural-language password disclosures such as `my password is x`, `the
passcode was '#'` and `my pwd: !`, with no minimum value length, for password,
passcode, passphrase, passwd, pwd, pw, `pass code` and `pass phrase` after
`is`, `was`, `is now`, `set to`, `is set to`, a colon, or `=` after a
determiner (`my pw = x`). Quoted values keep their
quotes and an unmatched quote is redacted through its line. Documentary
sentences (`the password is required`), references (`$PASSWORD`,
`{{password}}`), masks, placeholders and type annotations (`password: string`)
are unchanged. `passcode` is now a sensitive assignment name.

## 0.5.0-alpha.9

Preserve an exact `project_key` whose value is a normalized repository identity
(`github.com/owner/repo`), so session capture can record which project a session
belongs to. Other `project_key` values, prefixed names and composite values stay
sensitive; credentials beside or inside a kept identity still redact. Only the
exact spellings qualify, segments with long letter-and-digit pieces stay
sensitive, and an unquoted identity followed by another assignment on its line
is redacted with it.

## 0.5.0-alpha.5 (unreleased)

Preserve complete query references, awaited calls and Rust reference type aliases while retaining literal-secret redaction across URL decoding layers. Avoid unnecessary normalization lookups outside newlines.

0.5.0-alpha.4: releases the security-reviewed engine from PR #15 head 77b89c60 (closes unmatched-quote recovery, HTML-entity and semicolonless separators, entity-encoded URL punctuation, scheme-less attribute URLs, percent-encoded reserved characters in values and userinfo, fully encoded userinfo authorities, nested multi-layer values). Precision: non-zero false positives remain.
