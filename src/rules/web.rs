//! Home directories, URL userinfo and email addresses.

use super::js::{
    at, at_is, before, boundary, has, has_ci, is, is_alnum, is_letter, is_space, is_word, leads,
    one_of, replace_all as replace, run_end, run_end_capped, slice, Hit,
};

/// `(^|[lead])<prefix>[^<sep>\s]+(?=<sep>)` → `$1~`.
fn home(
    t: &[u16],
    i: usize,
    lead: &[u8],
    prefix: impl Fn(&[u16], usize) -> Option<usize>,
    sep: u8,
) -> Option<Hit> {
    leads(t, i, |c| is_space(c) || one_of(c, lead)).find_map(|p| {
        let q = prefix(t, p)?;
        let end = run_end(t, q, |c| !(is(c, sep) || is_space(c)));
        let mut with = slice(t, i, p).to_vec();
        with.push(u16::from(b'~'));
        (end > q && at_is(t, end, sep)).then(|| Hit::new(end, with))
    })
}

/// The three home-directory rules: `/Users/<name>`, `/home/<name>` and
/// `C:\Users\<name>` become `~`.
pub(super) fn redact_home_paths(t: &[u16]) -> Vec<u16> {
    let unix =
        |root: &'static str| move |t: &[u16], p: usize| has(t, p, root).then_some(p + root.len());
    let windows = |t: &[u16], p: usize| {
        (at(t, p, is_letter) && has_ci(t, p + 1, ":\\Users\\")).then_some(p + 9)
    };
    let t = replace(t, |t, i| home(t, i, b"\"'(=:/", unix("/Users/"), b'/'));
    let t = replace(&t, |t, i| home(t, i, b"\"'(=:/", unix("/home/"), b'/'));
    replace(&t, |t, i| home(t, i, b"\"'(=", windows, b'\\'))
}

/// `[a-z][a-z0-9+.-]{0,31}://` at `i`, case-insensitively: where it ends.
fn scheme(t: &[u16], i: usize) -> Option<usize> {
    if !at(t, i, is_letter) {
        return None;
    }
    let r = run_end_capped(t, i + 1, 32, |c| is_alnum(c) || one_of(c, b"+.-"));
    (r - (i + 1) <= 31 && has(t, r, "://")).then_some(r + 3)
}

/// `([a-z][a-z0-9+.-]{0,31}:\/\/[^:\s/@]+:)[^@\s/]+(@)` → `$1[REDACTED]$2`, gi.
fn userinfo_password(t: &[u16], i: usize) -> Option<Hit> {
    let s = scheme(t, i)?;
    let u = run_end(t, s, |c| !(one_of(c, b":/@") || is_space(c)));
    if u == s || !at_is(t, u, b':') {
        return None;
    }
    let p = run_end(t, u + 1, |c| !(one_of(c, b"@/") || is_space(c)));
    if p == u + 1 || !at_is(t, p, b'@') {
        return None;
    }
    let mut hit = Hit::redact(p + 1, slice(t, i, u + 1));
    hit.with.push(u16::from(b'@'));
    Some(hit)
}

/// `([a-z][a-z0-9+.-]{0,31}:\/\/)(?!git@)[^:\s/@?#]+(@)` → `$1[REDACTED]$2`, gi.
fn userinfo_token(t: &[u16], i: usize) -> Option<Hit> {
    let s = scheme(t, i)?;
    if has_ci(t, s, "git@") {
        return None;
    }
    let u = run_end(t, s, |c| !(one_of(c, b":/@?#") || is_space(c)));
    if u == s || !at_is(t, u, b'@') {
        return None;
    }
    let mut hit = Hit::redact(u + 1, slice(t, i, s));
    hit.with.push(u16::from(b'@'));
    Some(hit)
}

/// The two URL userinfo rules: a password, then a bare token (`git@` kept).
/// Both need `://`, so text without one is returned as it is.
pub(super) fn redact_userinfo(t: &[u16]) -> Vec<u16> {
    if !(0..t.len()).any(|i| has(t, i, "://")) {
        return t.to_vec();
    }
    let t = replace(t, userinfo_password);
    replace(&t, userinfo_token)
}

/// `[A-Z0-9.-]`, case-insensitively: a domain character.
fn is_domain(c: u16) -> bool {
    is_alnum(c) || one_of(c, b".-")
}

/// Every `[A-Z0-9.-]{1,255}\.[A-Z]{2,24}` from `q`, longest domain first, as
/// `(dot, end)`: the dot before the top-level domain and the end of it.
fn domains(t: &[u16], q: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
    let r = run_end_capped(t, q, 256, is_domain);
    let last = r.min(q + 255);
    (q + 1..=last)
        .rev()
        .filter(move |&d| at_is(t, d, b'.'))
        .flat_map(move |d| {
            let letters = run_end_capped(t, d + 1, 24, is_letter) - (d + 1);
            (2..=letters).rev().map(move |n| (d, d + 1 + n))
        })
}

/// `(?!git@[A-Z0-9.-]{1,255}\.[A-Z]{2,24}:[\w~./-])` at `i`: an scp-style remote.
fn git_remote(t: &[u16], i: usize) -> bool {
    has_ci(t, i, "git@")
        && domains(t, i + 4)
            .any(|(_, e)| at_is(t, e, b':') && at(t, e + 1, |c| is_word(c) || one_of(c, b"~./-")))
}

/// The email rule at `i`, case-insensitive:
/// `(?<!:\/\/)\b(?!git@…)[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\.[A-Z]{2,24}\b(?!\.?[A-Z0-9-])`.
fn email(t: &[u16], i: usize) -> Option<Hit> {
    let after_scheme = i >= 3 && has(t, i - 3, "://");
    if after_scheme || !boundary(t, i) || git_remote(t, i) {
        return None;
    }
    let local = run_end_capped(t, i, 65, |c| is_alnum(c) || one_of(c, b"._%+-"));
    if local == i || local - i > 64 || !at_is(t, local, b'@') {
        return None;
    }
    let ends_clean = |e: usize| {
        let tail = |c: u16| is_alnum(c) || is(c, b'-');
        !at(t, e, is_word) && !at(t, e, tail) && !(at_is(t, e, b'.') && at(t, e + 1, tail))
    };
    let (_, end) = domains(t, local + 1).find(|&(_, e)| before(t, e, is_word) && ends_clean(e))?;
    Some(Hit::redact(end, &[]))
}

/// Email addresses (scp-style `git@host:path` remotes and URL userinfo kept).
pub(super) fn redact_emails(t: &[u16]) -> Vec<u16> {
    if !t.iter().any(|&c| is(c, b'@')) {
        return t.to_vec();
    }
    replace(t, email)
}
