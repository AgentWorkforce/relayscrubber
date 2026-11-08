//! The quoted key/value rule: the value of every quoted secret key, at any
//! JSON escaping depth, in JSON, YAML, Python and shell forms.

use super::js::{
    at, at_is, before, has, has_ci, is, is_alnum, is_digit, is_letter, is_lower, is_space,
    is_upper, looks_generated, one_of, run_end_capped, slice, REDACTED16,
};
/// Longest quoted value the rule looks through for its closing quote.
pub(super) const MAX_QUOTED_VALUE: usize = 4096;

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
    start: usize,
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
    Some(KeyMatch {
        start: i,
        key: (ks, ke),
        end,
    })
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

/// The span of a quoted value, plus whether its close is past the v4 cap.
fn quoted_value(t: &[u16], vs: usize, bs: usize, quote: u16, prefix: bool) -> (usize, usize, bool) {
    let limit = t.len().min(vs.saturating_add(MAX_QUOTED_VALUE + 1));
    let mut close = None;
    let mut line_end = None;
    let mut i = vs;
    while i < limit {
        let c = t[i];
        if line_end.is_none() && (is(c, b'\n') || is(c, b'\r')) {
            line_end = Some(i);
        }
        if c == quote && closes_at(t, i, vs, bs) {
            close = Some(i);
            break;
        }
        i += 1;
    }

    if close.is_none() && (i - vs > MAX_QUOTED_VALUE || prefix) {
        while i < t.len() {
            if t[i] == quote && closes_at(t, i, vs, bs) {
                return (vs, i - bs, true);
            }
            i += 1;
        }
        return (vs, t.len(), true);
    }
    if let Some(at) = close.filter(|_| line_end.is_none()) {
        return (vs, at - bs, false);
    }
    let window = slice(t, vs, vs + MAX_QUOTED_VALUE);
    let end = window
        .iter()
        .position(|&c| is_space(c))
        .map_or(t.len().min(vs + MAX_QUOTED_VALUE), |w| vs + w);
    (vs, end, false)
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
fn bare_value(t: &[u16], end: usize, bs: usize, key: &[u16]) -> Option<(usize, usize, bool)> {
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
    let mut value_end = end + n;
    let over_bound = n == MAX_QUOTED_VALUE;
    if over_bound {
        while value_end < t.len()
            && !(is_space(t[value_end]) || one_of(t[value_end], b"\"'`,;{}[]\\"))
        {
            value_end += 1;
        }
    }
    Some((end, value_end, over_bound))
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
fn value_span(t: &[u16], m: &KeyMatch, prefix: bool) -> Option<(usize, usize, bool)> {
    let end = m.end;
    let bs = run_end_capped(t, end, 16, is_backslash) - end;
    match t.get(end + bs).copied().filter(|&c| is_quote(c)) {
        Some(quote) => Some(quoted_value(t, end + bs + 1, bs, quote, prefix)),
        None => bare_value(t, end, bs, slice(t, m.key.0, m.key.1)),
    }
}

/// Apply the quoted rule and optionally collect v4 over-cap spans.
fn redact(t: &[u16], mut spans: Option<&mut Vec<(usize, usize)>>, prefix: bool) -> Vec<u16> {
    if !t.iter().any(|&c| one_of(c, b":=")) {
        return t.to_vec();
    }
    let mut out = Vec::new();
    let mut last = 0;
    let mut next = 0;
    while let Some(m) = find_key(t, next) {
        next = m.end;
        if !is_secret_key_name(trim(slice(t, m.key.0, m.key.1))) {
            continue;
        }
        let Some((vs, ve, over_cap)) = value_span(t, &m, prefix) else {
            continue;
        };
        if over_cap {
            if let Some(found) = spans.as_deref_mut() {
                found.push((m.start, ve));
            }
        }
        if over_cap && ve <= vs {
            continue;
        }
        if ve <= vs || (!over_cap && keep(slice(t, vs, ve))) {
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

/// V4 over-cap key/value spans. Prefix mode treats an undecided open value
/// at the end of a look-ahead window as extending beyond that window.
pub(super) fn over_cap_quoted_value_spans(t: &[u16], prefix: bool) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let _ = redact(t, Some(&mut spans), prefix);
    spans
}

/// Redact the value of every quoted secret key, keeping the key, the
/// separator and the value's quotes.
pub(super) fn redact_quoted_secret_values(t: &[u16]) -> Vec<u16> {
    redact(t, None, false)
}
