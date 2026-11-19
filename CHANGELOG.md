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

Security fixes to the alpha.10 candidate, before any release:

- Colon and equals cues: `:` and `=` now disclose for all eight nouns with or
  without a determiner (`pw: Q`, `pass code: 4711`, `pass phrase = x`), and
  redact the whole value, conjunctions and documentary first words included
  (`password = velvet river lantern` no longer keeps `river lantern`). Type
  annotations (`password: string`, `pw: Vec<u8>`), references, a lone `None`
  and the operators `==`, `=>`, `::`, `!=` are unchanged. The value ends at
  an enclosing quote, at the close matching by type the innermost bracket
  left open before the noun in the noun's own string layer, or before the
  next `Key=` when the noun follows a `key=value` item and the same `;` or
  `&` (`Server=db;Password=x;Encrypt=true`). Any other close bracket, `;` or
  `&` is part of the value, so `pw: x]yq zq`, `(note pw: x]yq zq`,
  `{"note":"pw: x}yq zq"}`, `pw: abc&def=ghi`, `R&D pw: abc&def=ghi` and
  `note; my pw: abc;host=y` no longer keep any of the value.
- Escaped quotes: a `"`, `'` or `` ` `` preceded by an odd number of
  backslashes at the opener's escape level no longer ends a quoted value
  (`"abc\"def"`), including inside JSON-escaped strings; the 1024-byte bound
  and the unmatched-quote rule are unchanged.
- Contiguous quoted segments: a quoted segment that starts right at the
  value's close quote is part of the value, with the same or another quote,
  so `my password is "abc""defq"` no longer keeps `"defq"`. Unquoted text
  touching the close quote is part of the value too, up to the next
  whitespace, so `"abc"defq`, `""abcq` and `password=""abcq` no longer keep
  `defq` or `abcq`; trailing punctuation alone (`"abc".`) and a quoted string
  after whitespace still end the value. A touching segment may open with any
  quote mark or escape level, so `pw: "abc"\"defq\"`, `my password is
  "abc"\'defq\'` and `{"note":"my password is \"abc\"'defq'"}` no longer keep
  `defq`; only the close of a quote or bracket the line opened before the
  noun ends the run. After a quoted value, a `,`, `;` or `&` before a
  key-like field, or the close of a tag opened before the noun, ends it, so
  `password="abc",user="bob"` and `<a password="abc">text</a>` keep the next
  field.
- Enclosing closes: a redaction no longer removes the closing quote of the
  JSON string that holds the disclosure; an unterminated value inside it
  redacts up to that quote, so the line stays valid JSON with the same keys
  (`{"note":"password:\"abc\"defq","user":"bob"}` kept `password:\"` and
  dropped `","user":"bob"}`). A quote opened before the noun still closes
  the clause: `he said 'pw: abc'defq` keeps `defq` (known residual).
- Separators: every Rust/WHATWG whitespace character (including U+1680,
  U+205F and U+0085) and one line break may separate the words, so `my
  pass\ncode is x` redacts; HTML character references (`&#32;`, `&#x20;`,
  `&nbsp;` and the named spaces), percent, `%u` and `\u`/`\x` spellings of
  whitespace count as separators too.
- Prefixed colon and equals cues: words before the noun no longer redact less
  than the bare cue. `The new password: x`, `Please use pw = x`, `- note: my
  pass code: x` and `We discussed password: x` were left whole and now redact
  the value; after a determiner the whole value is redacted, so `my password:
  correct horse battery` no longer keeps `horse battery` and `the password: see
  vault` no longer keeps `vault`. With words or a bullet before the noun a
  close bracket is part of the value unless the line opened it before the
  noun (`The new password: ab)cd`, `* password: ab)cd`), and so is a `;` or
  `&` unless the line was already a `;`/`&` list before the noun (`my pw:
  abc&def=ghi`). `# ` and `// ` comment lines are unchanged.

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
