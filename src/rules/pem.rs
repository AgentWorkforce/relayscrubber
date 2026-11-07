//! Private-key blocks: `-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----` up to the
//! next matching footer, as the PEM rule and the bounds pair them.

use super::js::{has, is, is_upper, replace_all, run_end, Hit};

/// The end of `[A-Z ]*PRIVATE KEY(?: BLOCK)?-----` from `q`, backtracking
/// the greedy class as the regular expression does: the last `PRIVATE KEY`
/// in the run of `[A-Z ]` that a dash run follows.
fn marker_tail(t: &[u16], q: usize) -> Option<usize> {
    let run = run_end(t, q, |c| is_upper(c) || is(c, b' '));
    let last = run.checked_sub(11)?;
    (q..=last).rev().find_map(|p| {
        if !has(t, p, "PRIVATE KEY") {
            return None;
        }
        let after = p + 11;
        if has(t, after, " BLOCK-----") {
            Some(after + 11)
        } else if has(t, after, "-----") {
            Some(after + 5)
        } else {
            None
        }
    })
}

/// The end of a header that starts at `i`.
fn header_at(t: &[u16], i: usize) -> Option<usize> {
    if has(t, i, "-----BEGIN ") {
        marker_tail(t, i + 11)
    } else {
        None
    }
}

/// The end of a footer that starts at `i`.
fn footer_at(t: &[u16], i: usize) -> Option<usize> {
    if has(t, i, "-----END ") {
        marker_tail(t, i + 9)
    } else {
        None
    }
}

/// The first header at or after `from`, as `(start, end)`.
pub(super) fn find_header(t: &[u16], from: usize) -> Option<(usize, usize)> {
    (from..t.len()).find_map(|i| header_at(t, i).map(|end| (i, end)))
}

/// The first footer at or after `from`, as `(start, end)`.
fn find_footer(t: &[u16], from: usize) -> Option<(usize, usize)> {
    (from..t.len()).find_map(|i| footer_at(t, i).map(|end| (i, end)))
}

/// The PEM rule: each block from its header to its footer, or to the end of
/// the text when it has none, becomes the redaction token.
pub(super) fn redact_private_keys(t: &[u16]) -> Vec<u16> {
    replace_all(t, |t, i| {
        let head = header_at(t, i)?;
        let end = find_footer(t, head).map_or(t.len(), |(_, end)| end);
        Some(Hit::redact(end, &[]))
    })
}

/// Every block as `[start, end)`: header to just past its footer, or to the
/// end of `t` for a block left open.
pub(super) fn key_block_spans(t: &[u16]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut at = 0;
    while let Some((start, head)) = find_header(t, at) {
        let Some((_, end)) = find_footer(t, head) else {
            spans.push((start, t.len()));
            break;
        };
        spans.push((start, end));
        at = end;
    }
    spans
}

/// The start of the first block in `t` with no footer.
pub(super) fn unclosed_start(t: &[u16]) -> Option<usize> {
    let mut at = 0;
    while let Some((start, head)) = find_header(t, at) {
        match find_footer(t, head) {
            Some((_, end)) => at = end,
            None => return Some(start),
        }
    }
    None
}

/// The block `cut` falls strictly inside, if any.
pub(super) fn block_around(spans: &[(usize, usize)], cut: usize) -> Option<(usize, usize)> {
    let next = spans.partition_point(|&(_, end)| end <= cut);
    spans.get(next).copied().filter(|&(start, _)| start < cut)
}

/// The header of a block that is open at `top` (it has no footer, or its
/// footer ends past `top`), among blocks whose header starts before `top`.
pub(super) fn open_at(t: &[u16], top: usize) -> Option<usize> {
    let mut at = 0;
    while let Some((start, head)) = find_header(t, at) {
        if start >= top {
            return None;
        }
        match find_footer(t, head) {
            Some((_, end)) if end <= top => at = end,
            _ => return Some(start),
        }
    }
    None
}
