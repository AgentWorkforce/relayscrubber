//! The quoted key/value rule: the value of every quoted secret key, at any
//! JSON escaping depth, in JSON, YAML, Python and shell forms.

use super::js::{
    at, at_is, before, has, has_ci, is, is_alnum, is_digit, is_letter, is_lower, is_space,
    is_upper, looks_generated, one_of, run_end_capped, slice, REDACTED16,
};
use std::collections::HashMap;

/// Longest quoted value the rule looks through for its closing quote.
const MAX_QUOTED_VALUE: usize = 4096;

const COMPOUND_KEY_HEADS: [&str; 8] = [
    "api",
    "access",
    "private",
    "secret",
    "auth",
    "signing",
    "encryption",
    "master",
];
const COMPOUND_TOKEN_HEADS: [&str; 8] = [
    "session", "access", "refresh", "auth", "id", "bot", "bearer", "api",
];
const SECRET_WORDS: [&str; 10] = [
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "auth",
    "authorization",
    "credential",
    "credentials",
    "bearer",
];

/// Whether `name` ends with `word`, folding ASCII case.
fn ends_ci(name: &[u16], word: &str) -> bool {
    name.len()
        .checked_sub(word.len())
        .is_some_and(|at| has_ci(name, at, word))
}

/// Whether `name` ends with `head`, an optional `_`, space or `-`, then `tail`.
fn ends_compound(name: &[u16], head: &str, tail: &str) -> bool {
    ["", "_", " ", "-"]
        .iter()
        .any(|sep| ends_ci(name, &format!("{head}{sep}{tail}")))
}

/// Whether a quoted key names a secret (the Cloud's `isSecretKeyName`).
pub(super) fn is_secret_key_name(name: &[u16]) -> bool {
    let compound = COMPOUND_KEY_HEADS
        .iter()
        .any(|h| ends_compound(name, h, "key"))
        || ends_compound(name, "client", "secret")
        || COMPOUND_TOKEN_HEADS
            .iter()
            .any(|h| ends_compound(name, h, "token"));
    if compound {
        return true;
    }
    let Some(len) = SECRET_WORDS
        .iter()
        .filter(|w| ends_ci(name, w))
        .map(|w| w.len())
        .max()
    else {
        return false;
    };
    let idx = name.len() - len;
    if idx == 0 || !before(name, idx, is_letter) {
        return true;
    }
    before(name, idx, is_lower) && at(name, idx, is_upper)
}

/// A match of the quoted-key pattern: the key's span and where the match ends.
struct KeyMatch {
    key: (usize, usize),
    end: usize,
}

fn is_backslash(c: u16) -> bool {
    is(c, b'\\')
}

fn is_quote(c: u16) -> bool {
    one_of(c, b"\"'`")
}

fn is_blank(c: u16) -> bool {
    one_of(c, b" \t")
}

/// `(?<!\\)(\\{0,16})(["'`])([A-Za-z0-9_. -]{1,64})\1\2([ \t]{0,16}(?:=>|[:=])[ \t]{0,16})` at `i`.
fn quoted_key_at(t: &[u16], i: usize) -> Option<KeyMatch> {
    if before(t, i, is_backslash) {
        return None;
    }
    let bs = run_end_capped(t, i, 17, is_backslash) - i;
    let quote = *t.get(i + bs).filter(|&&c| bs <= 16 && is_quote(c))?;
    let ks = i + bs + 1;
    let ke = run_end_capped(t, ks, 65, |c| is_alnum(c) || one_of(c, b"_. -"));
    let closes = (ke..ke + bs).all(|k| at(t, k, is_backslash)) && at(t, ke + bs, |c| c == quote);
    if ke == ks || ke - ks > 64 || !closes {
        return None;
    }
    let s1 = ke + bs + 1;
    let sep = run_end_capped(t, s1, 17, is_blank);
    let after = if sep - s1 > 16 {
        return None;
    } else if has(t, sep, "=>") {
        sep + 2
    } else if at(t, sep, |c| one_of(c, b":=")) {
        sep + 1
    } else {
        return None;
    };
    let end = run_end_capped(t, after, 16, is_blank);
    Some(KeyMatch { key: (ks, ke), end })
}

/// The next quoted-key match at or after `from`, with its start.
fn find_key(t: &[u16], from: usize) -> Option<KeyMatch> {
    (from..t.len()).find_map(|i| quoted_key_at(t, i))
}

/// Number of backslashes immediately before `at`.
fn backslashes_before(t: &[u16], at: usize) -> usize {
    let mut n = 0;
    while before(t, at - n, is_backslash) {
        n += 1;
    }
    n
}

/// Per quote kind (quote and backslash count), a span already walked without
/// finding a closing quote.
type Unclosed = HashMap<(u16, usize), (usize, usize)>;

/// Whether the quote at `i` closes a value opened at `vs` with `bs` backslashes.
fn closes_at(t: &[u16], i: usize, vs: usize, bs: usize) -> bool {
    let period = if (bs + 1) & bs != 0 { 0 } else { 2 * (bs + 1) };
    let run = backslashes_before(t, i);
    let own = if i - run >= vs { run } else { i - vs };
    if period == 0 {
        own == bs
    } else {
        own % period == bs
    }
}

/// The span of a quoted value that opens at `vs`.
fn quoted_value(
    t: &[u16],
    vs: usize,
    bs: usize,
    quote: u16,
    unclosed: &mut Unclosed,
) -> (usize, usize) {
    let kind = (quote, bs);
    let seen = unclosed.get(&kind).copied();
    let inside = seen.is_some_and(|(a, b)| vs >= a && vs < b);
    let mut i = if inside { t.len() } else { vs };
    while i < t.len() && i - vs <= MAX_QUOTED_VALUE {
        let c = t.get(i).copied().unwrap_or_default();
        if is(c, b'\n') || is(c, b'\r') {
            break;
        }
        if c == quote && closes_at(t, i, vs, bs) {
            return (vs, i - bs);
        }
        i += 1;
    }
    if i < t.len() {
        unclosed.insert(kind, (vs, i));
    } else if !inside {
        unclosed.insert(kind, (vs, t.len()));
    }
    let window = slice(t, vs, vs + MAX_QUOTED_VALUE);
    let end = window
        .iter()
        .position(|&c| is_space(c))
        .map_or(t.len().min(vs + MAX_QUOTED_VALUE), |w| vs + w);
    (vs, end)
}

/// `-?\d+(?:\.\d+)?(?:e[+-]?\d+)?`, whole.
fn is_number(s: &[u16]) -> bool {
    let digits = |from: usize| {
        from + s
            .get(from..)
            .map_or(0, |r| r.iter().take_while(|&&c| is_digit(c)).count())
    };
    let mut i = usize::from(at_is(s, 0, b'-'));
    let mut e = digits(i);
    if e == i {
        return false;
    }
    i = e;
    if at_is(s, i, b'.') {
        e = digits(i + 1);
        if e > i + 1 {
            i = e;
        }
    }
    if at(s, i, |c| one_of(c, b"eE")) {
        let sign = i + 1 + usize::from(at(s, i + 1, |c| one_of(c, b"+-")));
        e = digits(sign);
        if e > sign {
            i = e;
        }
    }
    i == s.len()
}

/// JSON literals and numbers after a quoted secret key are not secrets.
fn non_secret_bare(s: &[u16]) -> bool {
    let word = ["true", "false", "null", "undefined", "none"]
        .iter()
        .any(|w| s.len() == w.len() && has_ci(s, 0, w));
    word || is_number(s)
}

/// The span of an unquoted value after a one-word key, when it looks generated.
fn bare_value(t: &[u16], end: usize, bs: usize, key: &[u16]) -> Option<(usize, usize)> {
    if bs > 0 || key.iter().any(|&c| is(c, b' ')) {
        return None;
    }
    let window = slice(t, end, end + MAX_QUOTED_VALUE);
    let n = window
        .iter()
        .take_while(|&&c| !(is_space(c) || one_of(c, b"\"'`,;{}[]\\")))
        .count();
    let bare = slice(window, 0, n);
    if n == 0 || non_secret_bare(bare) || !looks_generated(bare) {
        return None;
    }
    Some((end, end + n))
}

/// `name` without leading and trailing whitespace (`String.prototype.trim`).
fn trim(name: &[u16]) -> &[u16] {
    let start = name
        .iter()
        .position(|&c| !is_space(c))
        .unwrap_or(name.len());
    let end = name
        .iter()
        .rposition(|&c| !is_space(c))
        .map_or(start, |e| e + 1);
    slice(name, start, end)
}

/// Values the rule keeps: already redacted, or a 1Password reference.
fn keep(value: &[u16]) -> bool {
    value == REDACTED16 || has(value, 0, "op://")
}

/// The value span after a secret key match, if the rule takes one.
fn value_span(t: &[u16], m: &KeyMatch, unclosed: &mut Unclosed) -> Option<(usize, usize)> {
    let end = m.end;
    let bs = run_end_capped(t, end, 16, is_backslash) - end;
    match t.get(end + bs).copied().filter(|&c| is_quote(c)) {
        Some(quote) => Some(quoted_value(t, end + bs + 1, bs, quote, unclosed)),
        None => bare_value(t, end, bs, slice(t, m.key.0, m.key.1)),
    }
}

/// Redact the value of every quoted secret key, keeping the key, the
/// separator and the value's quotes.
pub(super) fn redact_quoted_secret_values(t: &[u16]) -> Vec<u16> {
    if !t.iter().any(|&c| one_of(c, b":=")) {
        return t.to_vec();
    }
    let mut out = Vec::new();
    let mut last = 0;
    let mut next = 0;
    let mut unclosed = Unclosed::new();
    while let Some(m) = find_key(t, next) {
        next = m.end;
        if !is_secret_key_name(trim(slice(t, m.key.0, m.key.1))) {
            continue;
        }
        let Some((vs, ve)) = value_span(t, &m, &mut unclosed) else {
            continue;
        };
        if ve <= vs || keep(slice(t, vs, ve)) {
            continue;
        }
        out.extend_from_slice(slice(t, last, vs));
        out.extend_from_slice(&REDACTED16);
        last = ve;
        next = next.max(ve);
    }
    if last == 0 {
        return t.to_vec();
    }
    out.extend_from_slice(slice(t, last, t.len()));
    out
}
