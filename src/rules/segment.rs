//! The Cloud's scrub segmenter (`raw-chunks.ts#scrub-segmenter`): a text longer
//! than [`MAX_SCRUB_CHARS`] is split only where `cutIsSafe` holds (scrubbing
//! the two sides apart equals scrubbing them together), and each segment is
//! scrubbed on its own. Nothing is truncated: a remainder with no safe cut is
//! replaced by the redaction token, never sent in part.

use super::js::{at, before, has_ci, is, is_alnum, is_digit, is_space, one_of, run_start, slice};
use super::pem::{block_around, key_block_spans, open_at};
use super::{quoted, scrub16, web, MAX_SCRUB_CHARS, REDACTION_TOKEN};

/// Longest whitespace run a cut may sit in.
const MAX_CUT_GAP: usize = 1024;
/// Most candidate cuts one search fully checks.
const MAX_CUT_CHECKS: usize = 48;
/// Most candidates of any kind one search looks at.
const MAX_CUT_CANDIDATES: usize = 4096;
/// How far below the bound a search looks.
const CUT_SEARCH_CHARS: usize = 65_536;
/// How much text on each side of a cut the context check scrubs.
const CUT_CONTEXT_CHARS: usize = 8192;
/// How far back the credential keyword check looks.
const KEYWORD_WINDOW: usize = 64;

/// The credential keywords, every spelling of each alternative.
const KEYWORDS: [&str; 26] = [
    "bearer",
    "basic",
    "token",
    "password",
    "passwd",
    "pwd",
    "secret",
    "api-key",
    "api_key",
    "apikey",
    "access-key",
    "access_key",
    "accesskey",
    "secret-key",
    "secret_key",
    "secretkey",
    "private-key",
    "private_key",
    "privatekey",
    "client-secret",
    "client_secret",
    "clientsecret",
    "authorization",
    "auth",
    "credentials",
    "credential",
];

#[derive(Default)]
struct Budget {
    checks: usize,
    candidates: usize,
}

impl Budget {
    fn open(&self) -> bool {
        self.checks < MAX_CUT_CHECKS && self.candidates < MAX_CUT_CANDIDATES
    }
}

/// `p` itself, then `p - 1` when the unit before `p` is in `set`: an optional
/// one-unit class read backwards from `p`.
fn optional_before(s: &[u16], p: usize, set: &'static [u8]) -> impl Iterator<Item = usize> {
    let one = before(s, p, move |c| one_of(c, set)).then(|| p - 1);
    std::iter::once(p).chain(one)
}

/// A keyword (or `key`) ends at `p`, with no ASCII alphanumeric before it.
fn keyword_ends_at(s: &[u16], p: usize) -> bool {
    KEYWORDS.iter().chain(&["key"]).any(|word| {
        p.checked_sub(word.len())
            .is_some_and(|from| has_ci(s, from, word) && !before(s, from, is_alnum))
    })
}

/// `CREDENTIAL_KEYWORD` against the whole of `s`, which it must end:
/// `(?:(?<![A-Za-z0-9])keyword["']?\s*[:=]?|[:=])["']?$`, case-insensitive.
fn credential_keyword(s: &[u16]) -> bool {
    optional_before(s, s.len(), b"\"'").any(|e| {
        before(s, e, |c| one_of(c, b":="))
            || optional_before(s, e, b":=").any(|e| {
                let gap = run_start(s, e, is_space);
                optional_before(s, gap, b"\"'").any(|w| keyword_ends_at(s, w))
            })
    })
}

/// Past a whitespace run of at most [`MAX_CUT_GAP`] from `i`, or `None`.
fn skip_space(t: &[u16], mut i: usize) -> Option<usize> {
    let from = i;
    while at(t, i, is_space) {
        i += 1;
        if i - from > MAX_CUT_GAP {
            return None;
        }
    }
    Some(i)
}

/// Where a keyword's value would start after the whitespace run ending at
/// `end`: past it, an optional `:`/`=`, more whitespace and an optional quote.
fn value_start(t: &[u16], end: usize) -> Option<usize> {
    let mut i = skip_space(t, end)?;
    if at(t, i, |c| one_of(c, b":=")) {
        i += 1;
    }
    i = skip_space(t, i)?;
    if at(t, i, |c| one_of(c, b"\"'`")) {
        i += 1;
    }
    Some(i)
}

/// Whether a digit or `)` before `start` and a digit or `(` at `end` straddle a run.
fn between_digit_groups(t: &[u16], start: usize, end: usize) -> bool {
    before(t, start, |c| is_digit(c) || is(c, b')')) && at(t, end, |c| is_digit(c) || is(c, b'('))
}

/// Whether `t` may be cut at `cut`, and where the whitespace run around it starts.
fn cut_is_safe(t: &[u16], cut: usize, budget: &mut Budget) -> (bool, usize) {
    budget.candidates += 1;
    let start = run_start(t, cut, is_space);
    let mut end = cut;
    while end - start <= MAX_CUT_GAP && at(t, end, is_space) {
        end += 1;
    }
    if end - start > MAX_CUT_GAP || between_digit_groups(t, start, end) {
        return (false, start);
    }
    let mut reach = end;
    if credential_keyword(slice(t, start.saturating_sub(KEYWORD_WINDOW), start)) {
        match value_start(t, end) {
            Some(v) if v < t.len() => reach = v,
            _ => return (false, start),
        }
    }
    budget.checks += 1;
    let head = slice(t, start.saturating_sub(CUT_CONTEXT_CHARS), cut);
    let tail = slice(t, cut, reach + CUT_CONTEXT_CHARS);
    let mut apart = scrub16(head);
    apart.extend(scrub16(tail));
    (scrub16(&[head, tail].concat()) == apart, start)
}

/// The latest safe cut at or below the bound and above the search floor
/// whose preceding unit is a `boundary`, or `None`.
fn search_cut(t: &[u16], boundary: fn(u16) -> bool) -> Option<usize> {
    let top = open_at(t, MAX_SCRUB_CHARS).unwrap_or(MAX_SCRUB_CHARS);
    let floor = MAX_SCRUB_CHARS.saturating_sub(CUT_SEARCH_CHARS).max(1);
    let keys = key_block_spans(slice(t, 0, top));
    let mut budget = Budget::default();
    let mut cut = top;
    while cut >= floor && budget.open() {
        if let Some((start, _)) = block_around(&keys, cut) {
            cut = start;
            continue;
        }
        if before(t, cut, boundary) && !at(t, cut, is_space) {
            let (ok, run) = cut_is_safe(t, cut, &mut budget);
            if ok {
                return Some(cut);
            }
            cut = cut.min(run);
        }
        cut = cut.checked_sub(1)?;
    }
    None
}

/// The Cloud's cut: after whitespace. Where it finds none (compact JSON,
/// minified code), the desktop also tries after a comma. A comma is only a
/// candidate: it is a cut only if it passes the same `cutIsSafe` port as a
/// whitespace candidate (digit groups, the credential-keyword reach, and the
/// context check that the two sides scrub apart as they do together), so no
/// rule match ever straddles it. Where the Cloud finds no cut it refuses the
/// text; the desktop then redacts it (see [`scrub_long16`]).
fn long_cut(t: &[u16]) -> Option<usize> {
    search_cut(t, is_space).or_else(|| {
        // URL userinfo may span arbitrarily far past a comma. If a scheme is
        // in the candidate prefix, bounded context cannot prove that a comma
        // is outside credentials, so fail closed instead of splitting.
        (!web::has_scheme_before(t, MAX_SCRUB_CHARS))
            .then(|| search_cut(t, |c| is(c, b',')))
            .flatten()
    })
}

/// `scrubLong`: segments of at most [`MAX_SCRUB_CHARS`] split at safe cuts,
/// each scrubbed whole. Where the Cloud throws for a remainder with no safe
/// cut, the desktop replaces that remainder with the redaction token: no
/// part of it is sent, and the upload is never refused. Segments already cut
/// off at safe cuts are kept.
pub(super) fn scrub_long16(t: &[u16]) -> Vec<u16> {
    // Canonical v3 caps quoted-value inspection at 4,096 UTF-16 units and can
    // expose the suffix. Uploads fail closed until the canonical ruleset owns
    // the same regression: no part of an over-cap value leaves the device.
    if quoted::has_overlong_secret_value(t) {
        return REDACTION_TOKEN.encode_utf16().collect();
    }
    let mut out = Vec::with_capacity(t.len());
    let mut rest = t;
    while rest.len() > MAX_SCRUB_CHARS {
        let Some(cut) = long_cut(rest) else {
            out.extend(REDACTION_TOKEN.encode_utf16());
            return out;
        };
        out.extend(scrub16(slice(rest, 0, cut)));
        rest = slice(rest, cut, rest.len());
    }
    out.extend(scrub16(rest));
    out
}
