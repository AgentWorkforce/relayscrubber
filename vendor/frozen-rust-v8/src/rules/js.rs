//! JavaScript string and regular-expression semantics the rules depend on.
//!
//! The Cloud rule set runs non-Unicode JavaScript regular expressions over
//! UTF-16 strings, so text here is a slice of UTF-16 code units, `\s` is the
//! JavaScript whitespace set, `\d`, `\w` and `\b` are ASCII, and the `i` flag
//! folds ASCII case only.

/// `s` as UTF-16 code units, at compile time (ASCII only).
pub(super) const fn ascii16<const N: usize>(s: &[u8; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = s[i] as u16;
        i += 1;
    }
    out
}

/// The redaction token as UTF-16.
pub(super) const REDACTED16: [u16; 10] = ascii16(b"[REDACTED]");

pub(super) fn is_digit(c: u16) -> bool {
    (0x30..=0x39).contains(&c)
}

pub(super) fn is_upper(c: u16) -> bool {
    (0x41..=0x5a).contains(&c)
}

pub(super) fn is_lower(c: u16) -> bool {
    (0x61..=0x7a).contains(&c)
}

pub(super) fn is_letter(c: u16) -> bool {
    is_upper(c) || is_lower(c)
}

pub(super) fn is_alnum(c: u16) -> bool {
    is_letter(c) || is_digit(c)
}

/// `\w`: `[A-Za-z0-9_]`.
pub(super) fn is_word(c: u16) -> bool {
    is_alnum(c) || c == u16::from(b'_')
}

/// `[A-Za-z0-9_-]`, the token characters of the literal-prefix rules.
pub(super) fn is_tok(c: u16) -> bool {
    is_word(c) || c == u16::from(b'-')
}

/// `\s`: JavaScript's WhiteSpace and LineTerminator code points, all in the BMP.
pub(super) fn is_space(c: u16) -> bool {
    matches!(
        c,
        0x09..=0x0d
            | 0x20
            | 0xa0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028
            | 0x2029
            | 0x202f
            | 0x205f
            | 0x3000
            | 0xfeff
    )
}

/// Whether `c` is the ASCII character `b`.
pub(super) fn is(c: u16, b: u8) -> bool {
    c == u16::from(b)
}

/// Whether `c` is one of the ASCII characters in `set`.
pub(super) fn one_of(c: u16, set: &[u8]) -> bool {
    set.iter().any(|&b| is(c, b))
}

/// Whether the unit at `i` exists and satisfies `f`.
pub(super) fn at(t: &[u16], i: usize, f: impl Fn(u16) -> bool) -> bool {
    t.get(i).is_some_and(|&c| f(c))
}

/// Whether the unit before `i` exists and satisfies `f`.
pub(super) fn before(t: &[u16], i: usize, f: impl Fn(u16) -> bool) -> bool {
    i.checked_sub(1).is_some_and(|j| at(t, j, f))
}

/// Whether the unit at `i` is the ASCII character `b`.
pub(super) fn at_is(t: &[u16], i: usize, b: u8) -> bool {
    at(t, i, |c| is(c, b))
}

/// `\b` at `i`.
pub(super) fn boundary(t: &[u16], i: usize) -> bool {
    before(t, i, is_word) != at(t, i, is_word)
}

/// The first index at or after `from` whose unit fails `f` (or the length).
pub(super) fn run_end(t: &[u16], from: usize, f: impl Fn(u16) -> bool) -> usize {
    let mut i = from;
    while at(t, i, &f) {
        i += 1;
    }
    i
}

/// [`run_end`] that stops looking `cap` units after `from`.
pub(super) fn run_end_capped(t: &[u16], from: usize, cap: usize, f: impl Fn(u16) -> bool) -> usize {
    let mut i = from;
    while i - from < cap && at(t, i, &f) {
        i += 1;
    }
    i
}

/// The start of the run of units satisfying `f` that ends at `to`.
pub(super) fn run_start(t: &[u16], to: usize, f: impl Fn(u16) -> bool) -> usize {
    let mut i = to;
    while before(t, i, &f) {
        i -= 1;
    }
    i
}

/// Whether the ASCII literal `lit` starts at `i`, case-sensitively.
pub(super) fn has(t: &[u16], i: usize, lit: &str) -> bool {
    let units = lit.bytes().map(u16::from);
    t.get(i..i + lit.len())
        .is_some_and(|s| s.iter().copied().eq(units))
}

/// Whether the ASCII literal `lit` starts at `i`, folding ASCII case (the `i` flag).
pub(super) fn has_ci(t: &[u16], i: usize, lit: &str) -> bool {
    t.get(i..i + lit.len()).is_some_and(|s| {
        s.iter()
            .zip(lit.bytes())
            .all(|(&c, b)| fold(c) == u16::from(b.to_ascii_lowercase()))
    })
}

/// ASCII lowercase of one unit; any other unit is itself.
pub(super) fn fold(c: u16) -> u16 {
    if is_upper(c) {
        c + 32
    } else {
        c
    }
}

/// The length of the first literal in `alts` that starts at `i` (the
/// leftmost alternative wins, as in a regular-expression alternation).
pub(super) fn first_of(t: &[u16], i: usize, alts: &[&str], ci: bool) -> Option<usize> {
    alts.iter()
        .find(|lit| {
            if ci {
                has_ci(t, i, lit)
            } else {
                has(t, i, lit)
            }
        })
        .map(|lit| lit.len())
}

/// A match the global replace takes: it ends at `end` (exclusive) and is
/// replaced by `with`.
pub(super) struct Hit {
    pub end: usize,
    pub with: Vec<u16>,
}

impl Hit {
    pub(super) fn new(end: usize, with: Vec<u16>) -> Self {
        Self { end, with }
    }

    /// A match replaced by `head` followed by the redaction token.
    pub(super) fn redact(end: usize, head: &[u16]) -> Self {
        let mut with = head.to_vec();
        with.extend_from_slice(&REDACTED16);
        Self { end, with }
    }
}

/// `String.prototype.replace` with a global pattern: `at(t, i)` is the match
/// that starts at `i`, if any. The search resumes where a match ended, and
/// lookbehinds see the original text, as in JavaScript.
pub(super) fn replace_all(t: &[u16], mut at: impl FnMut(&[u16], usize) -> Option<Hit>) -> Vec<u16> {
    let mut out = Vec::with_capacity(t.len());
    let mut last = 0;
    let mut i = 0;
    while i < t.len() {
        match at(t, i) {
            Some(hit) => {
                out.extend_from_slice(t.get(last..i).unwrap_or_default());
                out.extend_from_slice(&hit.with);
                last = hit.end;
                i = hit.end.max(i + 1);
            }
            None => i += 1,
        }
    }
    out.extend_from_slice(t.get(last..).unwrap_or_default());
    out
}

/// The units `t[from..to]`, empty when out of range.
pub(super) fn slice(t: &[u16], from: usize, to: usize) -> &[u16] {
    t.get(from..to.min(t.len())).unwrap_or_default()
}

/// Shannon entropy in bits per character, as JavaScript computes it: counts
/// per code point (a lone surrogate counts as one), divided by the length in
/// UTF-16 units, summed in first-seen order.
pub(super) fn entropy(s: &[u16]) -> f64 {
    let mut counts: Vec<usize> = Vec::new();
    let mut slot = std::collections::HashMap::new();
    for c in char::decode_utf16(s.iter().copied()) {
        let key = c.map_or_else(|e| u32::from(e.unpaired_surrogate()), u32::from);
        let at = *slot.entry(key).or_insert_with(|| {
            counts.push(0);
            counts.len() - 1
        });
        if let Some(n) = counts.get_mut(at) {
            *n += 1;
        }
    }
    let len = s.len() as f64;
    counts.iter().fold(0.0, |h, &n| {
        let p = n as f64 / len;
        h - p * p.log2()
    })
}

/// A token that looks generated: 20+ units drawing on at least two of
/// lowercase, uppercase and digits, with at least 3.5 bits of entropy.
pub(super) fn looks_generated(token: &[u16]) -> bool {
    let has = |f: fn(u16) -> bool| usize::from(token.iter().any(|&c| f(c)));
    let classes = has(is_lower) + has(is_upper) + has(is_digit);
    token.len() >= 20 && classes >= 2 && entropy(token) >= 3.5
}

/// Where the rest of a pattern starts after a `(^|[class])` lead at `i`: `i`
/// itself at the start of the text, then past one unit of the class, in the
/// order the alternation tries them.
pub(super) fn leads(
    t: &[u16],
    i: usize,
    class: impl Fn(u16) -> bool,
) -> impl Iterator<Item = usize> {
    let start = (i == 0).then_some(i);
    let one = at(t, i, class).then_some(i + 1);
    start.into_iter().chain(one)
}
