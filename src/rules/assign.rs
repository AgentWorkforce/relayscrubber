//! Secrets named by the text around them: `Authorization` schemes,
//! `NAME=value` assignments and generated-looking tokens after a secret name.

use super::js::{
    at, at_is, before, first_of, has_ci, is, is_alnum, is_space, is_word, looks_generated, one_of,
    replace_all, run_end, run_end_capped, slice, Hit,
};

/// `(\bauthorization(?![A-Za-z0-9])[^A-Za-z0-9\r\n]{1,8}(?:Basic|Token|Bot|Digest|Negotiate|NTLM)\s+)[A-Za-z0-9._~+/=-]{8,}`
/// → `$1[REDACTED]`, gi.
fn authorization(t: &[u16], i: usize) -> Option<Hit> {
    if before(t, i, is_word) || !has_ci(t, i, "authorization") || at(t, i + 13, is_alnum) {
        return None;
    }
    let k = i + 13;
    let gap = run_end_capped(t, k, 8, is_gap);
    let schemes = ["Basic", "Token", "Bot", "Digest", "Negotiate", "NTLM"];
    (k + 1..=gap).rev().find_map(|p| {
        let s = p + first_of(t, p, &schemes, true)?;
        let v = run_end(t, s, is_space);
        let end = run_end(t, v, |c| is_alnum(c) || one_of(c, b"._~+/=-"));
        (v > s && end - v >= 8).then(|| Hit::redact(end, slice(t, i, v)))
    })
}

/// `[^A-Za-z0-9\r\n]`: what may stand between a secret name and its value.
fn is_gap(c: u16) -> bool {
    !(is_alnum(c) || is(c, b'\r') || is(c, b'\n'))
}

pub(super) fn redact_authorization(t: &[u16]) -> Vec<u16> {
    replace_all(t, authorization)
}

/// The assignment rule's secret names, in alternation order.
const ASSIGNED_NAMES: [&str; 13] = [
    "api_key",
    "api-key",
    "apikey",
    "apikey",
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "credentials",
    "credential",
];

/// After `name`, `\s*[:=]\s*["'`]?[^"'`\s,;]+` from `n`: the separator and the end.
fn assigned_value(t: &[u16], n: usize) -> Option<(usize, usize)> {
    let sep = run_end(t, n, is_space);
    if !at(t, sep, |c| one_of(c, b":=")) {
        return None;
    }
    let v = run_end(t, sep + 1, is_space);
    let v = v + usize::from(at(t, v, |c| one_of(c, b"\"'`")));
    let end = run_end(t, v, |c| !(one_of(c, b"\"'`,;") || is_space(c)));
    (end > v).then_some((sep, end))
}

/// `\b(?:[A-Za-z0-9]+_){0,8}(?:api[_-]?key|apikey|key|secret|token|password|passwd|passphrase|pwd|credentials?)\s*[:=]\s*["'`]?[^"'`\s,;]+`,
/// gi, replaced by everything up to the separator, the separator and the token.
fn assignment(t: &[u16], i: usize) -> Option<Hit> {
    if !at(t, i, is_alnum) || before(t, i, is_word) {
        return None;
    }
    let mut starts = vec![i];
    let mut p = i;
    while starts.len() <= 8 {
        let seg = run_end(t, p, is_alnum);
        if seg == p || !at_is(t, seg, b'_') {
            break;
        }
        p = seg + 1;
        starts.push(p);
    }
    starts.iter().rev().find_map(|&k| {
        ASSIGNED_NAMES.iter().find_map(|name| {
            if !has_ci(t, k, name) {
                return None;
            }
            let (sep, end) = assigned_value(t, k + name.len())?;
            Some(Hit::redact(end, slice(t, i, sep + 1)))
        })
    })
}

pub(super) fn redact_assignments(t: &[u16]) -> Vec<u16> {
    replace_all(t, assignment)
}

/// The fallback rule's secret names, in alternation order, with every
/// `[_ -]?` spelled out (the separator first, then none).
fn fallback_names() -> Vec<String> {
    let mut names: Vec<String> = ["password", "passwd", "passphrase", "secret", "token"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    names.push("credentials".into());
    names.push("credential".into());
    let pairs = [
        ("api", "key"),
        ("access", "key"),
        ("private", "key"),
        ("secret", "key"),
        ("client", "secret"),
        ("auth", "token"),
        ("session", "token"),
    ];
    for (head, tail) in pairs {
        for sep in ["_", " ", "-", ""] {
            names.push(format!("{head}{sep}{tail}"));
        }
    }
    names
}

/// `[A-Za-z0-9_+/=.-]`: a character of the fallback rule's token.
fn is_token(c: u16) -> bool {
    is_word(c) || one_of(c, b"+/=.-")
}

/// The fallback rule at `i`, gi:
/// `(?<![A-Za-z0-9])((?:<names>)(?![A-Za-z0-9_./-])[^A-Za-z0-9\r\n]{1,8})([A-Za-z0-9_+/=.-]{20,512})(?![A-Za-z0-9_+/=.-])`,
/// the token redacted only when it looks generated (the match is taken either way).
fn fallback(t: &[u16], i: usize, names: &[String]) -> Option<Hit> {
    if before(t, i, is_alnum) {
        return None;
    }
    names.iter().find_map(|name| {
        let k = i + name.len();
        if !has_ci(t, i, name) || at(t, k, |c| is_word(c) || one_of(c, b"./-")) {
            return None;
        }
        let gap = run_end_capped(t, k, 8, is_gap);
        (k + 1..=gap).rev().find_map(|p| {
            let end = run_end_capped(t, p, 513, is_token);
            if !(20..=512).contains(&(end - p)) {
                return None;
            }
            let token = slice(t, p, end);
            Some(if looks_generated(token) {
                Hit::redact(end, slice(t, i, p))
            } else {
                Hit::new(end, slice(t, i, end).to_vec())
            })
        })
    })
}

pub(super) fn redact_fallback(t: &[u16]) -> Vec<u16> {
    let names = fallback_names();
    replace_all(t, |t, i| fallback(t, i, &names))
}
