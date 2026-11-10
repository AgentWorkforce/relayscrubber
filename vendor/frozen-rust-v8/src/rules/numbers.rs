//! Phone numbers and payment card numbers.

use super::js::{
    at, at_is, is, is_digit, is_word, leads, one_of, replace_all, run_end, slice, Hit, REDACTED16,
};

/// `(?!\w|[.-]?\d)` at `e` (the phone rules' end).
fn phone_end(t: &[u16], e: usize) -> bool {
    !(at(t, e, is_word) || (at(t, e, |c| one_of(c, b".-")) && at(t, e + 1, is_digit)))
}

/// After `+[1-9]\d*` at `q`, the end of every `(?:[ .-]?\(\d{1,4}\)\d*|[ .-]\d+)`
/// group the greedy loop takes, in order.
fn phone_groups(t: &[u16], mut q: usize) -> Vec<usize> {
    let mut ends = vec![q];
    loop {
        let s = q + usize::from(at(t, q, |c| one_of(c, b" .-")));
        let paren = at_is(t, s, b'(') && {
            let d = run_end(t, s + 1, is_digit);
            (1..=4).contains(&(d - s - 1)) && at_is(t, d, b')')
        };
        if paren {
            let d = run_end(t, s + 1, is_digit);
            q = run_end(t, d + 1, is_digit);
        } else if s > q && at(t, s, is_digit) {
            q = run_end(t, s, is_digit);
        } else {
            return ends;
        }
        ends.push(q);
    }
}

/// `(^|[^\w+])\+[1-9]\d*(?:…)*(?!\w|[.-]?\d)`, redacted (keeping the lead)
/// when it holds at least 8 digits; a shorter match is taken unchanged.
fn international(t: &[u16], i: usize) -> Option<Hit> {
    leads(t, i, |c| !(is_word(c) || is(c, b'+'))).find_map(|p| {
        if !at_is(t, p, b'+') || !at(t, p + 1, |c| (0x31..=0x39).contains(&c)) {
            return None;
        }
        let q = run_end(t, p + 1, is_digit);
        let end = phone_groups(t, q)
            .into_iter()
            .rev()
            .find(|&e| phone_end(t, e))?;
        let digits = slice(t, p, end).iter().filter(|&&c| is_digit(c)).count();
        Some(if digits >= 8 {
            Hit::redact(end, slice(t, i, p))
        } else {
            Hit::new(end, slice(t, i, end).to_vec())
        })
    })
}

/// `n` digits from `q`, the first in `2-9`.
fn area(t: &[u16], q: usize) -> Option<usize> {
    let ok = at(t, q, |c| (0x32..=0x39).contains(&c))
        && at(t, q + 1, is_digit)
        && at(t, q + 2, is_digit);
    ok.then_some(q + 3)
}

/// `(^|[^\w.+-])(?:\([2-9]\d{2}\) ?|[2-9]\d{2}[.-])[2-9]\d{2}[.-]\d{4}(?!\w|[.-]?\d)` → `$1[REDACTED]`.
fn north_american(t: &[u16], i: usize) -> Option<Hit> {
    leads(t, i, |c| !(is_word(c) || one_of(c, b".+-"))).find_map(|p| {
        let q = if at_is(t, p, b'(') {
            let a = area(t, p + 1).filter(|&a| at_is(t, a, b')'))?;
            a + 1 + usize::from(at_is(t, a + 1, b' '))
        } else {
            area(t, p).filter(|&a| at(t, a, |c| one_of(c, b".-")))? + 1
        };
        let x = area(t, q).filter(|&x| at(t, x, |c| one_of(c, b".-")))? + 1;
        let end = (x..x + 4).all(|k| at(t, k, is_digit)).then_some(x + 4)?;
        phone_end(t, end).then(|| Hit::redact(end, slice(t, i, p)))
    })
}

pub(super) fn redact_phones(t: &[u16]) -> Vec<u16> {
    let t = replace_all(t, international);
    replace_all(&t, north_american)
}

/// Issuer prefixes and lengths: Visa, Mastercard, American Express, Diners
/// Club, JCB, Discover and UnionPay.
fn known_issuer(d: &[u8]) -> bool {
    let n = d.len();
    if !(13..=19).contains(&n) {
        return false;
    }
    let p = |k: usize| {
        d.iter()
            .take(k)
            .fold(0u32, |v, &c| v * 10 + u32::from(c - b'0'))
    };
    let visa = d.first() == Some(&b'4') && matches!(n, 13 | 16 | 19);
    let mastercard = ((51..=55).contains(&p(2)) || (2221..=2720).contains(&p(4))) && n == 16;
    let amex = matches!(p(2), 34 | 37) && n == 15;
    let diners =
        ((300..=305).contains(&p(3)) || matches!(p(2), 36 | 38 | 39)) && matches!(n, 14 | 16);
    let jcb = (3528..=3589).contains(&p(4)) && (16..=19).contains(&n);
    let discover = (p(4) == 6011 || (644..=649).contains(&p(3)) || matches!(p(2), 65 | 62))
        && (16..=19).contains(&n);
    visa || mastercard || amex || diners || jcb || discover
}

/// A known issuer prefix and length and a valid Luhn check digit (ASCII digits).
pub(super) fn is_card_digits(digits: &[u8]) -> bool {
    if !known_issuer(digits) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &c)| {
            let d = u32::from(c - b'0');
            match (i % 2, d * 2) {
                (1, x) if x > 9 => x - 9,
                (1, x) => x,
                _ => d,
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// ASCII digits of UTF-16 digit units.
fn ascii(units: &[u16]) -> Vec<u8> {
    units.iter().filter_map(|&c| u8::try_from(c).ok()).collect()
}

/// Every card in a run of digit groups joined by single spaces or hyphens:
/// at each group the longest card over whole groups with one consistent
/// separator.
fn cards_in_run(run: &[u16]) -> Vec<u16> {
    let groups: Vec<&[u16]> = run.split(|&c| one_of(c, b" -")).collect();
    let seps: Vec<u16> = run.iter().copied().filter(|&c| !is_digit(c)).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(group) = groups.get(i) {
        let starts = group.first().is_some_and(|&c| (0x32..=0x36).contains(&c));
        let mut end = None;
        let mut digits = Vec::new();
        // Without an issuer's first digit no card starts here; skip the scan
        // rather than walk every later group (quadratic on `1 1 1 …`).
        let last = if starts { groups.len() } else { i };
        for j in i..last {
            if j > i + 1 && seps.get(j - 1) != seps.get(i) {
                break;
            }
            digits.extend(ascii(groups.get(j).copied().unwrap_or_default()));
            if digits.len() > 19 {
                break;
            }
            if digits.len() >= 13 && is_card_digits(&digits) {
                end = Some(j);
            }
        }
        match end {
            Some(_) => out.extend_from_slice(&REDACTED16),
            None => out.extend_from_slice(group),
        }
        let next = end.map_or(i + 1, |e| e + 1);
        if next < groups.len() {
            out.extend(seps.get(next - 1).copied());
        }
        i = next;
    }
    out
}

/// `(^|[^\w.+-])(\d+(?:[ -]\d+)*)(?!\w|[.-]\d)` → lead + the run with its cards redacted.
fn card_run(t: &[u16], i: usize) -> Option<Hit> {
    leads(t, i, |c| !(is_word(c) || one_of(c, b".+-"))).find_map(|p| {
        if !at(t, p, is_digit) {
            return None;
        }
        let mut ends = vec![run_end(t, p, is_digit)];
        while let Some(&e) = ends.last() {
            let next = at(t, e, |c| one_of(c, b" -")).then(|| run_end(t, e + 1, is_digit));
            match next.filter(|&n| n > e + 1) {
                Some(n) => ends.push(n),
                None => break,
            }
        }
        let end = ends.into_iter().rev().find(|&e| phone_end(t, e))?;
        let mut with = slice(t, i, p).to_vec();
        with.extend(cards_in_run(slice(t, p, end)));
        Some(Hit::new(end, with))
    })
}

pub(super) fn redact_cards(t: &[u16]) -> Vec<u16> {
    replace_all(t, card_run)
}
