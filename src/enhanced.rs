//! Enhanced redaction: a strict, upload-safe superset of the canonical engine.
//!
//! The canonical pipeline ([`crate::scrub_long`] and friends) is never modified here.
//! This module adds the high-precision rules learned from real relay session
//! history, where the shape is unambiguous enough that redacting it cannot
//! be a false positive:
//!
//! * precise `?`/`&`/`#` credential parameters (pre-pass), which also shields
//!   sibling tails from greedy assignment runs;
//! * chat-webhook URLs that carry bearer tokens in the path;
//! * provider prefixes the engine table does not cover (Groq, age,
//!   Slack `xoxc`, Mailchimp, Databricks, Notion, and others);
//! * space-separated CLI-flag secrets (`--password hunter2`), including
//!   backslash-newline continuations, at any length;
//! * validated SSNs, private-range IPv4 addresses, and long mixed-class
//!   password-less URL userinfo (registry-style tokens).
//!
//! [`scrub_enhanced`] is the recommended upload-safe entry point: a precise
//! query-parameter pre-pass, then [`crate::scrub_long`], then a post-pass over the
//! whole output. [`scrub_json_enhanced`] and [`scrub_json_text_enhanced`]
//! give JSON the same treatment, and every entry point has a `_with_policy`
//! variant that threads [`Policy`] through to the canonical engine (use
//! [`Policy::Pii`] when email addresses and SSN shapes must not survive).
//! Every entry point is idempotent, never truncates, and fails closed
//! exactly like [`crate::scrub_long`].
//!
//! Deliberate non-goals (documented, not oversights): bare hex runs (a
//! 37-hex Cloudflare legacy key is indistinguishable from a digest),
//! Twilio-style short prefixes (they collide with MD5/SHA fragments),
//! public IPs (they collide with four-part versions), compressed IPv6
//! (`::` collides with Rust paths), single-dash flags (`-p` is usually a
//! port), and email/phone/card/home-path shapes, which the engine contract
//! preserves by default and covers for email/SSN under [`Policy::Pii`].

use std::collections::HashMap;

use serde_json::Value;

use crate::{scrub_json_text, scrub_json_with_policy};
use crate::{scrub_text_with_policy, Policy};

const REDACTED: &[u8] = b"[REDACTED]";

fn ci_eq(a: u8, b: u8) -> bool {
    a.eq_ignore_ascii_case(&b)
}

fn ci_starts(input: &[u8], at: usize, lit: &[u8]) -> bool {
    input.len() >= at + lit.len()
        && input[at..at + lit.len()]
            .iter()
            .zip(lit.iter())
            .all(|(&a, &b)| ci_eq(a, b))
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn is_tok_byte(c: u8) -> bool {
    is_word_byte(c) || c == b'-'
}

/// Query/fragment parameter names whose values are always credentials.
/// `state`, `code` and friends stay with the canonical OAuth rule;
/// `client_id`/`consumer_key` stay out (they are public identifiers).
const QUERY_NAMES: [&[u8]; 20] = [
    b"password",
    b"passwd",
    b"passphrase",
    b"pwd",
    b"secret",
    b"token",
    b"api_key",
    b"apikey",
    b"api-key",
    b"client_secret",
    b"oauth_token_secret",
    b"oauth_token",
    b"consumer_secret",
    b"signature",
    b"sig",
    b"x-amz-signature",
    b"x-amz-credential",
    b"x-amz-security-token",
    b"x-goog-signature",
    b"x-goog-credential",
];

fn is_param_end(c: u8) -> bool {
    matches!(
        c,
        b'&' | b'#' | b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'<' | b'`'
    )
}

/// A post-pass hit: copy `input[last..keep]`, emit the redaction token,
/// resume scanning at `end`.
type Hit = (usize, usize);

/// `replace_all` over bytes: `at(input, i)` is the hit starting at `i`, if any.
fn replace_each(input: &[u8], mut at: impl FnMut(&[u8], usize) -> Option<Hit>) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut last = 0;
    let mut i = 0;
    while i < input.len() {
        if let Some((keep, end)) = at(input, i) {
            out.extend_from_slice(&input[last..keep]);
            out.extend_from_slice(REDACTED);
            last = end;
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }
    out.extend_from_slice(&input[last..]);
    out
}

/// `prefix` then a body run of `body` (`min` units or more), plus an optional
/// `-glued` suffix run. Case-sensitive, mirroring the canonical style; a
/// preceding `-` is allowed so `build-<token>` still matches at the prefix.
fn prefixed_body(
    input: &[u8],
    i: usize,
    prefix: &[u8],
    min: usize,
    body: fn(u8) -> bool,
) -> Option<Hit> {
    if i > 0 && is_word_byte(input[i - 1]) {
        return None;
    }
    if input.len() < i + prefix.len() || input[i..i + prefix.len()] != *prefix {
        return None;
    }
    let mut e = i + prefix.len();
    while e < input.len() && body(input[e]) {
        e += 1;
    }
    if e - (i + prefix.len()) < min {
        return None;
    }
    if input.get(e) == Some(&b'-') {
        let mut f = e;
        while f < input.len() && is_tok_byte(input[f]) {
            f += 1;
        }
        if f > e + 1 {
            e = f;
        }
    }
    Some((i, e))
}

fn is_alnum_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn is_b64url_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

fn is_b64url_dot(c: u8) -> bool {
    is_b64url_byte(c) || c == b'.'
}

fn is_hex_byte(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// Second-wave provider prefixes: each is long and distinctive enough that a
/// match is never a false positive. Short/ambiguous families (`re_`, bare
/// `key-`, Twilio `AC`-SIDs that collide with hash fragments, public
/// `phc_`/`sb_publishable_` counterparts) are deliberately absent.
/// A literal provider prefix, its minimum body length, and its body class.
type PrefixSpec = (&'static [u8], usize, fn(u8) -> bool);

fn extra_provider_at(input: &[u8], i: usize) -> Option<Hit> {
    let specs: [PrefixSpec; 24] = [
        (b"dapi", 32, is_hex_byte),
        (b"pypi-", 50, is_b64url_byte),
        (b"r8_", 40, is_alnum_byte),
        (b"tskey-auth-", 20, is_alnum_byte),
        (b"tskey-api-", 20, is_alnum_byte),
        (b"tskey-oauth-", 20, is_alnum_byte),
        (b"dp.pt.", 30, is_b64url_dot),
        (b"dp.st.", 30, is_b64url_dot),
        (b"hvs.", 40, is_b64url_byte),
        (b"ops_", 30, is_alnum_byte),
        (b"pul-", 20, is_alnum_byte),
        (b"PMAK-", 20, is_hex_byte),
        (b"xkeysib-", 32, is_hex_byte),
        (b"NRAK-", 20, is_alnum_byte),
        (b"sntrys_", 30, is_b64url_byte),
        (b"squ_", 30, is_b64url_byte),
        (b"sbp_", 20, is_alnum_byte),
        (b"xai-", 20, is_alnum_byte),
        (b"pplx-", 20, is_alnum_byte),
        (b"gldt-", 20, is_b64url_byte),
        (b"glrt-", 20, is_b64url_byte),
        (b"secret_", 40, is_alnum_byte),
        (b"dckr_pat_", 20, is_alnum_byte),
        (b"lin_api_", 30, is_alnum_byte),
    ];
    specs
        .into_iter()
        .find_map(|(prefix, min, body)| prefixed_body(input, i, prefix, min, body))
}

/// A Mailchimp API key: 32 hex with at least one letter, then `-usN`.
fn mailchimp_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && is_word_byte(input[i - 1]) {
        return None;
    }
    if input.len() < i + 32
        || !input[i..i + 32].iter().all(|&c| c.is_ascii_hexdigit())
        || !input[i..i + 32].iter().any(|&c| c.is_ascii_alphabetic())
    {
        return None;
    }
    let mut e = i + 32;
    if !ci_starts(input, e, b"-us") {
        return None;
    }
    e += 3;
    let d = e;
    while e < input.len() && input[e].is_ascii_digit() {
        e += 1;
    }
    if e == d || e - d > 2 {
        return None;
    }
    if input
        .get(e)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
    {
        return None;
    }
    Some((i, e))
}

/// A Telegram bot token: `<6-12 digit id>:<30+ token chars>`.
fn telegram_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && is_word_byte(input[i - 1]) {
        return None;
    }
    let mut e = i;
    while e < input.len() && input[e].is_ascii_digit() {
        e += 1;
    }
    if !(6..=12).contains(&(e - i)) || input.get(e) != Some(&b':') {
        return None;
    }
    e += 1;
    let s = e;
    while e < input.len() && is_b64url_byte(input[e]) {
        e += 1;
    }
    if e - s < 30 {
        return None;
    }
    Some((i, e))
}

/// A Terraform Cloud token: `20+ token chars` ending in `.atlasv1`.
/// `run_end` is the cached end of the token-byte run through `i`: rescanning
/// a long token-less run to its end at every position is quadratic, and long
/// accepted tokens must keep matching, so no length cap is imposed. The
/// cached end equals the inline scan exactly.
fn atlasv1_at(input: &[u8], i: usize, run_end: usize) -> Option<Hit> {
    if i > 0 && is_word_byte(input[i - 1]) {
        return None;
    }
    // The body run stops before `.`, so it holds just the 20+ token chars.
    let e = run_end;
    if e - i < 20 || input.len() < e + 8 || input[e..e + 8] != *b".atlasv1" {
        return None;
    }
    let end = e + 8;
    if input
        .get(end)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
    {
        return None;
    }
    Some((i, end))
}

/// Newer provider prefixes the canonical set does not know.
fn new_provider_at(input: &[u8], i: usize) -> Option<Hit> {
    // DigitalOcean: dop_v1_ / doo_v1_ / dor_v1_ + 64 alphanumerics.
    for prefix in [b"dop_v1_".as_slice(), b"doo_v1_", b"dor_v1_"] {
        if let Some(hit) = prefixed_body(input, i, prefix, 64, is_alnum_byte) {
            return Some(hit);
        }
    }
    // Google OAuth access token: ya29. + 50 base64url units or more.
    if let Some(hit) = prefixed_body(input, i, b"ya29.", 50, is_b64url_byte) {
        return Some(hit);
    }
    // Groq: gsk_ + 48 alphanumerics or more.
    if let Some(hit) = prefixed_body(input, i, b"gsk_", 48, is_alnum_byte) {
        return Some(hit);
    }
    // age secret key: AGE-SECRET-KEY- + 20 alphanumerics or more.
    if let Some(hit) = prefixed_body(input, i, b"AGE-SECRET-KEY-", 20, is_alnum_byte) {
        return Some(hit);
    }
    // Slack browser token the canonical class misses: xoxc- like xoxb-.
    if (i == 0 || !is_tok_byte(input[i - 1]))
        && input.len() >= i + 5
        && input[i..i + 5] == *b"xoxc-"
    {
        let mut e = i + 5;
        while e < input.len() && (is_alnum_byte(input[e]) || input[e] == b'-') {
            e += 1;
        }
        if e - (i + 5) >= 10 && input.get(e) != Some(&b'_') {
            return Some((i, e));
        }
    }
    None
}

/// Discord webhooks: `[ptb.|canary.]discord[app].com/api/webhooks/<id>/<token>`.
/// Keeps the id, redacts the token (a `?wait=true` tail survives).
fn discord_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && (is_word_byte(input[i - 1]) || input[i - 1] == b'.' || input[i - 1] == b'-') {
        return None;
    }
    let mut h = i;
    for sub in [b"ptb.".as_slice(), b"canary.".as_slice()] {
        if ci_starts(input, h, sub) {
            h += sub.len();
            break;
        }
    }
    let host_len = if ci_starts(input, h, b"discordapp.com") {
        14
    } else if ci_starts(input, h, b"discord.com") {
        11
    } else {
        return None;
    };
    let mut e = h + host_len;
    if !ci_starts(input, e, b"/api/webhooks/") {
        return None;
    }
    e += 14;
    let id_start = e;
    while e < input.len()
        && !matches!(
            input[e],
            b'/' | b'?'
                | b'#'
                | b' '
                | b'\t'
                | b'\r'
                | b'\n'
                | b'"'
                | b'\''
                | b'<'
                | b'>'
                | b'`'
                | b')'
                | b']'
        )
    {
        e += 1;
    }
    if e == id_start || input.get(e) != Some(&b'/') {
        return None;
    }
    e += 1;
    let tok = e;
    while e < input.len()
        && (is_word_byte(input[e]) || matches!(input[e], b'-' | b'.' | b'~' | b'%'))
    {
        e += 1;
    }
    if e == tok {
        return None;
    }
    Some((tok, e))
}

/// Redact a secret-bearing path starting at `slash` (the `/` survives).
fn redact_path(input: &[u8], slash: usize) -> Option<Hit> {
    let mut e = slash + 1;
    while e < input.len()
        && !matches!(
            input[e],
            b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'<' | b'>' | b'`' | b')' | b']'
        )
    {
        e += 1;
    }
    if e == slash + 1 {
        return None;
    }
    Some((slash, e))
}

/// Webhook hosts whose path is bearer material: `<tenant>.webhook.office.com/…`,
/// `webhook.site/…` and `requestbin.com/…`. Only the host survives.
fn webhook_host_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && (is_word_byte(input[i - 1]) || input[i - 1] == b'.' || input[i - 1] == b'-') {
        return None;
    }
    let mut h = i;
    while h < input.len() && (input[h].is_ascii_alphanumeric() || input[h] == b'-') {
        h += 1;
    }
    if h > i && ci_starts(input, h, b".webhook.office.com") && input.get(h + 19) == Some(&b'/') {
        return redact_path(input, h + 19);
    }
    for host in [b"webhook.site".as_slice(), b"requestbin.com".as_slice()] {
        if ci_starts(input, i, host) && input.get(i + host.len()) == Some(&b'/') {
            return redact_path(input, i + host.len());
        }
    }
    None
}

/// An Ansible Vault: `$ANSIBLE_VAULT;<version>;<cipher>` followed by hex
/// tokens (same-line or newline-separated). The header alone is not
/// sensitive, so a header with no hex body is left alone.
fn ansible_at(input: &[u8], i: usize) -> Option<Hit> {
    if input.len() < i + 15 || input[i..i + 15] != *b"$ANSIBLE_VAULT;" {
        return None;
    }
    let mut e = i + 15;
    while e < input.len() && input[e] != b';' && input[e] != b'\n' && input[e] != b'\r' {
        e += 1;
    }
    if input.get(e) != Some(&b';') {
        return None;
    }
    e += 1;
    let cs = e;
    while e < input.len() && input[e].is_ascii_alphanumeric() {
        e += 1;
    }
    if e == cs {
        return None;
    }
    let mut hex_total = 0;
    let mut last = e;
    let mut p = e;
    loop {
        while p < input.len()
            && (input[p] == b' ' || input[p] == b'\t' || input[p] == b'\n' || input[p] == b'\r')
        {
            p += 1;
        }
        let s = p;
        while p < input.len() && input[p].is_ascii_hexdigit() {
            p += 1;
        }
        // Tokens shorter than 8 hex chars end the block (prose like `and`
        // must not be swallowed a nibble at a time).
        if p - s < 8 {
            break;
        }
        hex_total += p - s;
        last = p;
    }
    if hex_total < 32 {
        return None;
    }
    Some((i, last))
}

/// XML element names whose text content is always a secret. Bare `<key>` is
/// excluded on purpose: plists use it for non-secret names.
const XML_NAMES: [&[u8]; 18] = [
    b"password",
    b"passwd",
    b"passphrase",
    b"pwd",
    b"secret",
    b"token",
    b"apikey",
    b"api-key",
    b"api_key",
    b"clientsecret",
    b"client-secret",
    b"client_secret",
    b"authtoken",
    b"auth-token",
    b"accesstoken",
    b"access-token",
    b"privatekey",
    b"private-key",
];

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(&x, &y)| ci_eq(x, y))
}

/// `<password>hunter2</password>` (Maven settings, NuGet config, Tomcat
/// users): redact the inner text, keep both tags.
fn xml_at(input: &[u8], i: usize) -> Option<Hit> {
    if input.get(i) != Some(&b'<') || input.get(i + 1) == Some(&b'/') {
        return None;
    }
    let mut n = i + 1;
    while n < input.len()
        && (input[n].is_ascii_alphanumeric() || matches!(input[n], b'_' | b'-' | b'.'))
    {
        n += 1;
    }
    let name = &input[i + 1..n];
    if name.is_empty() || !XML_NAMES.iter().any(|m| eq_ci(name, m)) || input.get(n) != Some(&b'>') {
        return None;
    }
    let s = n + 1;
    let mut e = s;
    while e < input.len() && input[e] != b'<' {
        e += 1;
    }
    if e == s || input.get(e + 1) != Some(&b'/') {
        return None;
    }
    let mut c = e + 2;
    while c < input.len()
        && (input[c].is_ascii_alphanumeric() || matches!(input[c], b'_' | b'-' | b'.'))
    {
        c += 1;
    }
    if !eq_ci(&input[e + 2..c], name) || input.get(c) != Some(&b'>') {
        return None;
    }
    Some((s, e))
}

/// Cookie names whose values are session-bound secrets. Everything else
/// (`theme`, `locale`, `Path`, …) is kept. Matching happens only on lines
/// carrying a `Cookie:`/`Set-Cookie:` header; values are redacted by name
/// no matter how short, which is the standard session-cookie scrubbing rule.
const COOKIE_NAMES: [&[u8]; 27] = [
    b"phpsessid",
    b"jsessionid",
    b"aspsessionid",
    b"sessionid",
    b"session_id",
    b"session-id",
    b"sid",
    b"sessid",
    b"sess_id",
    b"session",
    b"sessiontoken",
    b"session_token",
    b"session-token",
    b"token",
    b"authtoken",
    b"auth_token",
    b"auth-token",
    b"jwt",
    b"id_token",
    b"access_token",
    b"refresh_token",
    b"remember_me",
    b"rememberme",
    b"csrftoken",
    b"csrf_token",
    b"xsrf_token",
    b"cf_clearance",
];

/// One secret cookie pair at `i` (`name=value`); the scanner finds the rest.
fn cookie_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && (is_word_byte(input[i - 1]) || input[i - 1] == b'-') {
        return None;
    }
    // No cookie name exceeds 13 bytes: cap the scan so a long delimiter-free
    // run cannot make every position walk to its end (quadratic).
    let mut n = i;
    while n < input.len()
        && n - i < 16
        && !matches!(
            input[n],
            b'=' | b';' | b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\''
        )
    {
        n += 1;
    }
    let name = &input[i..n];
    if name.is_empty()
        || !COOKIE_NAMES.iter().any(|m| eq_ci(name, m))
        || input.get(n) != Some(&b'=')
    {
        return None;
    }
    // Only inside a Cookie:/Set-Cookie: header line.
    let back = i.saturating_sub(2048);
    let line_start = input[back..i]
        .iter()
        .rposition(|&c| c == b'\n')
        .map_or(back, |p| back + p + 1);
    if !input[line_start..i]
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"cookie:"))
    {
        return None;
    }
    let mut v = n + 1;
    while v < input.len() && (input[v] == b' ' || input[v] == b'\t') {
        v += 1;
    }
    let s = v;
    while v < input.len()
        && !matches!(
            input[v],
            b';' | b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b','
        )
    {
        v += 1;
    }
    if v == s {
        return None;
    }
    Some((s, v))
}

/// Elasticsearch-style `Authorization: ApiKey <value>`: the canonical
/// fallback only catches long generated values, but an explicit scheme
/// labels the value at any length.
fn apikey_scheme_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && is_word_byte(input[i - 1]) {
        return None;
    }
    if !ci_starts(input, i, b"authorization") {
        return None;
    }
    let mut v = i + 13;
    if input.get(v) == Some(&b':') {
        v += 1;
    }
    while v < input.len() && (input[v] == b' ' || input[v] == b'\t') {
        v += 1;
    }
    if !eq_ci(input.get(v..v + 6).unwrap_or_default(), b"apikey") {
        return None;
    }
    v += 6;
    if v >= input.len() || (input[v] != b' ' && input[v] != b'\t') {
        return None;
    }
    while v < input.len() && (input[v] == b' ' || input[v] == b'\t') {
        v += 1;
    }
    let s = v;
    while v < input.len()
        && !matches!(
            input[v],
            b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'`' | b',' | b';'
        )
    {
        v += 1;
    }
    if v == s {
        return None;
    }
    Some((s, v))
}

/// kubeconfig `client-key-data:` base64 (always long); the value is private
/// key material. Short values (filenames in malformed files) are kept.
fn kube_key_data_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && is_word_byte(input[i - 1]) {
        return None;
    }
    if !ci_starts(input, i, b"client-key-data") {
        return None;
    }
    let mut v = i + 15;
    while v < input.len() && (input[v] == b' ' || input[v] == b'\t') {
        v += 1;
    }
    if input.get(v) == Some(&b':') || input.get(v) == Some(&b'=') {
        v += 1;
        while v < input.len() && (input[v] == b' ' || input[v] == b'\t') {
            v += 1;
        }
    } else {
        return None;
    }
    if input.get(v) == Some(&b'"') || input.get(v) == Some(&b'\'') {
        v += 1;
    }
    let s = v;
    while v < input.len()
        && (input[v].is_ascii_alphanumeric()
            || matches!(input[v], b'+' | b'/' | b'=' | b'-' | b'_'))
    {
        v += 1;
    }
    if v - s < 20 {
        return None;
    }
    Some((s, v))
}

/// `scheme://:password@host` (empty user, e.g. Redis URLs). The canonical
/// userinfo rules need a non-empty user, and the email rule would otherwise
/// eat the host too — so this runs as a pre-pass, keeping `://:` and `@`.
fn pre_pass_bare_userinfo(input: &[u8]) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(input.len());
    let mut count = 0;
    let mut i = 0;
    while i < input.len() {
        if input.len() >= i + 4 && input[i..i + 4] == *b"://:" {
            let mut e = i + 4;
            while e < input.len()
                && !matches!(
                    input[e],
                    b'@' | b'/' | b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'\'' | b'<' | b'>' | b'`'
                )
            {
                e += 1;
            }
            if e > i + 4 && input.get(e) == Some(&b'@') {
                out.extend_from_slice(&input[i..i + 4]);
                out.extend_from_slice(REDACTED);
                out.push(b'@');
                // Rewriting an already-redacted span is a no-op: emit it but
                // do not count it, so second runs count zero.
                if &input[i + 4..e] != REDACTED {
                    count += 1;
                }
                i = e + 1;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    (out, count)
}

/// Redact `?name=value` / `&name=value` / `#name=value` precisely, stopping
/// at `&` so sibling parameters survive. Runs before [`crate::scrub_long`] so the
/// greedy assignment rule never sees the raw value.
///
/// `json` is for raw JSON text: a backslash escape ends the value before
/// `\"`/`\'`/`\n`/`\r`/`\t` (so the closing quote survives and the document
/// stays valid) and consumes any other escape pair whole (so `\\` stays
/// correct). Plain text keeps the raw-delimiter scan.
fn pre_pass_params(input: &[u8], json: bool) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(input.len());
    let mut count = 0;
    let mut i = 0;
    while i < input.len() {
        let c = input[i];
        if c == b'?' || c == b'&' || c == b'#' {
            let mut done = false;
            for name in QUERY_NAMES {
                if ci_starts(input, i + 1, name) {
                    let v = i + 1 + name.len();
                    if input.get(v) == Some(&b'=') {
                        let mut e = v + 1;
                        while e < input.len() && !is_param_end(input[e]) {
                            if json && input[e] == b'\\' {
                                match input.get(e + 1) {
                                    Some(b'"') | Some(b'\'') | Some(b'n') | Some(b'r')
                                    | Some(b't') => break,
                                    Some(_) => e += 1,
                                    None => {}
                                }
                            }
                            e += 1;
                        }
                        if e == v + 1 {
                            // Empty values stay empty: there is nothing to
                            // leak, and filling them would be a false positive.
                            out.extend_from_slice(&input[i..e]);
                            i = e;
                            done = true;
                            break;
                        }
                        // A trailing space shields the sibling tail from the
                        // canonical greedy assignment rule, whose value run
                        // would otherwise eat `&mode=1`. It is only needed
                        // before `&`/`#`; anywhere else the token alone ends
                        // the match exactly.
                        out.extend_from_slice(&input[i..=v]);
                        out.extend_from_slice(REDACTED);
                        if input.get(e) == Some(&b'&') || input.get(e) == Some(&b'#') {
                            out.push(b' ');
                        }
                        i = e;
                        done = true;
                        // Rewriting an already-redacted value is a no-op:
                        // emit it but do not count it, so second runs zero.
                        if &input[v + 1..e] != REDACTED {
                            count += 1;
                        }
                    }
                    break;
                }
            }
            if done {
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    (out, count)
}

/// Long CLI flags whose space-separated value is always a secret, at any
/// length (`--password hunter2`). Single-dash flags stay out: `-p` is
/// usually a port. Values starting with `-` (another flag), `$` (an env
/// reference), a quote, or `#` are left alone, as is a flag with no value.
const CLI_NAMES: [&[u8]; 12] = [
    b"password",
    b"passwd",
    b"passphrase",
    b"pwd",
    b"secret",
    b"token",
    b"api-key",
    b"apikey",
    b"api-token",
    b"auth-token",
    b"access-token",
    b"client-secret",
];

fn cli_flag_at(input: &[u8], i: usize) -> Option<Hit> {
    if input.get(i) != Some(&b'-') || input.get(i + 1) != Some(&b'-') {
        return None;
    }
    if i > 0 && (is_word_byte(input[i - 1]) || input[i - 1] == b'-') {
        return None;
    }
    let mut n = i + 2;
    while n < input.len() && (input[n].is_ascii_alphanumeric() || input[n] == b'-') {
        n += 1;
    }
    let name = &input[i + 2..n];
    if name.is_empty()
        || !CLI_NAMES
            .iter()
            .any(|m| m.len() == name.len() && m.iter().zip(name.iter()).all(|(&a, &b)| ci_eq(a, b)))
    {
        return None;
    }
    // Whitespace to the value, through optional backslash-newline continuations.
    // A bare newline without a backslash ends the command, so it is not skipped.
    let mut v = n;
    let mut consumed = false;
    loop {
        while v < input.len() && (input[v] == b' ' || input[v] == b'\t') {
            v += 1;
            consumed = true;
        }
        if input.get(v) == Some(&b'\\')
            && (input.get(v + 1) == Some(&b'\n')
                || (input.get(v + 1) == Some(&b'\r') && input.get(v + 2) == Some(&b'\n')))
        {
            v += if input.get(v + 1) == Some(&b'\r') {
                3
            } else {
                2
            };
            consumed = true;
            continue;
        }
        break;
    }
    if !consumed || v >= input.len() {
        return None;
    }
    if matches!(input[v], b'-' | b'"' | b'\'' | b'`' | b'#' | b'$') {
        return None;
    }
    let s = v;
    // An already-redacted value is left alone: without this, the `]`/`\)`
    // delimiters below would split `[REDACTED]` on a re-scrub and the token
    // would grow a bracket every pass.
    if input.len() >= s + REDACTED.len() && input[s..s + REDACTED.len()] == *REDACTED {
        return None;
    }
    while v < input.len()
        && !matches!(
            input[v],
            b' ' | b'\t'
                | b'\r'
                | b'\n'
                | b'"'
                | b'\''
                | b'`'
                | b','
                | b';'
                | b'<'
                | b'>'
                | b')'
                | b']'
        )
    {
        v += 1;
    }
    if v == s {
        return None;
    }
    Some((s, v))
}

/// A validated US Social Security Number: `ddd-dd-dddd` with a real area
/// (001-899 except 666), group (01-99) and serial (0001-9999).
fn ssn_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && input[i - 1].is_ascii_digit() {
        return None;
    }
    let d = |k: usize| input.get(i + k).is_some_and(|c| c.is_ascii_digit());
    if !(d(0) && d(1) && d(2))
        || input.get(i + 3) != Some(&b'-')
        || !(d(4) && d(5))
        || input.get(i + 6) != Some(&b'-')
        || !(d(7) && d(8) && d(9) && d(10))
        || input.get(i + 11).is_some_and(|c| c.is_ascii_digit())
    {
        return None;
    }
    let num = |from: usize, len: usize| {
        input[i + from..i + from + len]
            .iter()
            .fold(0u32, |v, &c| v * 10 + u32::from(c - b'0'))
    };
    let (area, group, serial) = (num(0, 3), num(4, 2), num(7, 4));
    if area == 0 || area == 666 || area >= 900 || group == 0 || serial == 0 {
        return None;
    }
    Some((i, i + 11))
}

/// Whether an octet run starting at `i` is a private-range IPv4 address.
/// Only RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`)
/// and link-local (`169.254/16`) are redacted: public quads collide with
/// four-part versions, so they stay (documented, not an oversight).
fn private_ipv4_at(input: &[u8], i: usize) -> Option<Hit> {
    if i > 0 && (input[i - 1].is_ascii_digit() || input[i - 1] == b'.') {
        return None;
    }
    let mut octets = [0u32; 4];
    let mut e = i;
    for (g, octet) in octets.iter_mut().enumerate() {
        let s = e;
        while e < input.len() && input[e].is_ascii_digit() {
            e += 1;
        }
        if e == s || e - s > 3 {
            return None;
        }
        *octet = input[s..e]
            .iter()
            .fold(0u32, |v, &c| v * 10 + u32::from(c - b'0'));
        if *octet > 255 {
            return None;
        }
        if g < 3 {
            if input.get(e) != Some(&b'.') {
                return None;
            }
            e += 1;
        }
    }
    if input
        .get(e)
        .is_some_and(|c| c.is_ascii_digit() || *c == b'.')
    {
        return None;
    }
    let private = octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254);
    private.then_some((i, e))
}

/// A long mixed-class `scheme://user@host` user with no password. The
/// canonical engine keeps password-less userinfo; a 12+ character
/// letter-and-digit user is a registry-style token, not a login name.
/// Dots are excluded (emails stop the user scan before `@`), colons are
/// excluded (password form is already the engine's), short names (`user`,
/// `admin`) are preserved, and the host must contain a dot so stray
/// `a://b@c` prose can never fire. Only the user is redacted.
fn userinfo_token_at(input: &[u8], i: usize) -> Option<Hit> {
    if input.get(i) != Some(&b':')
        || input.get(i + 1) != Some(&b'/')
        || input.get(i + 2) != Some(&b'/')
    {
        return None;
    }
    let s = i + 3;
    let mut e = s;
    while e < input.len()
        && (input[e].is_ascii_alphanumeric()
            || input[e] == b'_'
            || input[e] == b'-'
            || input[e] == b'~')
    {
        e += 1;
    }
    if input.get(e) != Some(&b'@') {
        return None;
    }
    let user = &input[s..e];
    if user.len() < 12 {
        return None;
    }
    let letters = user.iter().any(u8::is_ascii_alphabetic);
    let digits = user.iter().any(u8::is_ascii_digit);
    if !letters || !digits {
        return None;
    }
    let mut h = e + 1;
    let mut dot = false;
    while h < input.len()
        && (input[h].is_ascii_alphanumeric() || input[h] == b'.' || input[h] == b'-')
    {
        if input[h] == b'.' {
            dot = true;
        }
        h += 1;
    }
    if !dot {
        return None;
    }
    Some((s, e))
}

/// The whole-output post-pass: every rule replaces with [`REDACTED`] and
/// never restores, so running it over [`crate::scrub_long`] output is
/// fail-closed, including for shapes split across a segment cut.
/// First post-pass hit at `i`, in priority order. One fused scan instead of
/// sixteen full-text passes: every rule only ever inserts `[REDACTED]`, so
/// matches never nest and first-hit-wins equals the old sequential result
/// (pinned by the eval suite's exact-output assertions).
fn post_hit_at(input: &[u8], i: usize, run_end: usize) -> Option<Hit> {
    new_provider_at(input, i)
        .or_else(|| extra_provider_at(input, i))
        .or_else(|| mailchimp_at(input, i))
        .or_else(|| telegram_at(input, i))
        .or_else(|| atlasv1_at(input, i, run_end))
        .or_else(|| discord_at(input, i))
        .or_else(|| webhook_host_at(input, i))
        .or_else(|| ansible_at(input, i))
        .or_else(|| xml_at(input, i))
        .or_else(|| cookie_at(input, i))
        .or_else(|| apikey_scheme_at(input, i))
        .or_else(|| kube_key_data_at(input, i))
        .or_else(|| cli_flag_at(input, i))
        .or_else(|| ssn_at(input, i))
        .or_else(|| private_ipv4_at(input, i))
        .or_else(|| userinfo_token_at(input, i))
}

fn post_pass(input: &[u8]) -> Vec<u8> {
    // End of the token-byte run under the scan cursor, for `atlasv1_at`.
    // Each forward scan starts where the last run ended and the cursor only
    // moves forward, so every byte is walked at most once per pass; the
    // input is never mutated mid-scan, so the cached end stays valid across
    // earlier hits and later matches are retained.
    let mut run = (0usize, 0usize);
    replace_each(input, |buf, i| {
        if i >= run.1 {
            let mut e = i;
            while e < buf.len() && is_tok_byte(buf[e]) {
                e += 1;
            }
            run = (i, e);
        }
        post_hit_at(buf, i, run.1)
    })
}

fn utf8(bytes: Vec<u8>) -> String {
    // All splices happen at ASCII boundaries of valid UTF-8 input, so this
    // cannot fail; a failure would mean a bug, and panicking would leak
    // nothing since callers hold the input.
    String::from_utf8(bytes).expect("enhanced redaction preserves UTF-8")
}

/// Scrub one string with the enhanced pipeline: precise query-parameter
/// pre-pass, then [`crate::scrub_long`], then the whole-output post-pass.
///
/// This is the recommended upload-safe entry point. It never truncates:
/// the canonical engine scans the complete input, and the pre/post passes
/// only swap secret spans for `[REDACTED]`.
#[must_use]
pub fn scrub_enhanced(value: &str) -> String {
    scrub_enhanced_with_policy(value, Policy::Secrets)
}

/// [`scrub_enhanced`] with an explicit privacy policy, threaded through to
/// the canonical engine. Use [`Policy::Pii`] when the output must not retain
/// email addresses or SSN shapes; the enhanced post-pass (provider prefixes,
/// webhooks, CLI flags, private IPv4, userinfo tokens) applies either way.
#[must_use]
pub fn scrub_enhanced_with_policy(value: &str, policy: Policy) -> String {
    let (params, _) = pre_pass_params(value.as_bytes(), false);
    let (pre, _) = pre_pass_bare_userinfo(&params);
    let mid = scrub_text_with_policy(&utf8(pre), policy);
    utf8(post_pass(mid.as_bytes()))
}

/// Apply both text pre-passes to every string value and key of a JSON tree,
/// so the value entry points treat query parameters and userinfo exactly
/// like the text entry point. Values arrive parsed (escapes already
/// decoded), so the plain-text scan applies. Keys that would collide after
/// substitution keep their original spelling; the canonical scrub resolves
/// collisions itself.
fn pre_pass_value(node: &mut Value) -> usize {
    match node {
        Value::String(s) => {
            let (params, n) = pre_pass_params(s.as_bytes(), false);
            let (fixed, m) = pre_pass_bare_userinfo(&params);
            *s = utf8(fixed);
            n + m
        }
        Value::Array(items) => items.iter_mut().map(pre_pass_value).sum(),
        Value::Object(map) => {
            let entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
            let mut count = 0;
            for (key, mut item) in entries {
                count += pre_pass_value(&mut item);
                let (params, n) = pre_pass_params(key.as_bytes(), false);
                let (fixed_bytes, m) = pre_pass_bare_userinfo(&params);
                let fixed = utf8(fixed_bytes);
                count += n + m;
                if fixed != key && map.contains_key(&fixed) {
                    map.insert(key, item);
                } else {
                    map.insert(fixed, item);
                }
            }
            count
        }
        _ => 0,
    }
}

/// `${base} (n)` for the first free `n`, mirroring the canonical JSON rule.
fn free_name(
    used: &serde_json::Map<String, Value>,
    base: &str,
    next: &mut HashMap<String, u64>,
) -> String {
    let slot = next.entry(base.to_owned()).or_insert(2);
    loop {
        let name = format!("{base} ({slot})");
        if !used.contains_key(&name) {
            *slot += 1;
            return name;
        }
        *slot += 1;
    }
}

/// Apply the post-pass to every string and key of an already-scrubbed JSON
/// tree, counting what changed (colliding keys get ` (2)` suffixes).
fn post_pass_value(node: &mut Value) -> usize {
    match node {
        Value::String(s) => {
            let fixed = utf8(post_pass(s.as_bytes()));
            if fixed == *s {
                0
            } else {
                *s = fixed;
                1
            }
        }
        Value::Array(items) => items.iter_mut().map(post_pass_value).sum(),
        Value::Object(map) => {
            let mut count = 0;
            let entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
            let mut next: HashMap<String, u64> = HashMap::new();
            for (key, mut item) in entries {
                count += post_pass_value(&mut item);
                let clean = utf8(post_pass(key.as_bytes()));
                if clean != key {
                    count += 1;
                }
                let name = if map.contains_key(&clean) {
                    free_name(map, &clean, &mut next)
                } else {
                    clean
                };
                map.insert(name, item);
            }
            count
        }
        _ => 0,
    }
}

/// [`scrub_json`](crate::scrub_json) with the enhanced pipeline: the
/// canonical scrub first, then the post-pass over every surviving string
/// and key. Returns the scrubbed value and the total redaction count.
#[must_use]
pub fn scrub_json_enhanced(value: &Value) -> (Value, usize) {
    scrub_json_enhanced_with_policy(value, Policy::Secrets)
}

/// [`scrub_json_enhanced`] with an explicit privacy policy, threaded through
/// to the canonical engine (see [`scrub_enhanced_with_policy`]).
#[must_use]
pub fn scrub_json_enhanced_with_policy(value: &Value, policy: Policy) -> (Value, usize) {
    let mut pre = value.clone();
    let mut count = pre_pass_value(&mut pre);
    let (mut clean, n) = scrub_json_with_policy(&pre, policy);
    count += n + post_pass_value(&mut clean);
    (clean, count)
}

/// [`scrub_json_text`](crate::scrub_json_text) with the enhanced pipeline:
/// the query-parameter pre-pass runs on the raw text (it only swaps secret
/// values for `[REDACTED]`, so the JSON stays valid), then the canonical
/// text scrub, then the post-pass. `None` exactly when the canonical entry
/// point returns `None`.
#[must_use]
pub fn scrub_json_text_enhanced(text: &str) -> Option<(Value, usize)> {
    let (params, n) = pre_pass_params(text.as_bytes(), true);
    let (pre_bytes, m) = pre_pass_bare_userinfo(&params);
    let pre = utf8(pre_bytes);
    let (mut clean, k) = scrub_json_text(&pre)?;
    let count = n + m + k + post_pass_value(&mut clean);
    Some((clean, count))
}

/// [`scrub_json_text_enhanced`] with an explicit privacy policy. There is no
/// canonical policy text entry point, so valid JSON is parsed and delegated
/// to [`scrub_json_with_policy`]; `None` exactly for invalid JSON.
#[must_use]
pub fn scrub_json_text_enhanced_with_policy(text: &str, policy: Policy) -> Option<(Value, usize)> {
    let (params, n) = pre_pass_params(text.as_bytes(), true);
    let (pre_bytes, m) = pre_pass_bare_userinfo(&params);
    let parsed: Value = serde_json::from_str(&utf8(pre_bytes)).ok()?;
    let (clean, k) = scrub_json_enhanced_with_policy(&parsed, policy);
    Some((clean, n + m + k))
}
