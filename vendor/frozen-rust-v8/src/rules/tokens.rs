//! Credential shapes recognised by their own form: provider key prefixes
//! (and the same prefixes glued to a longer token by `-`), `Bearer` tokens,
//! SendGrid keys, webhook URLs, JWTs and OAuth query values.

use super::js::{
    at, at_is, before, first_of, has, has_ci, is, is_alnum, is_digit, is_letter, is_space, is_tok,
    is_upper, is_word, one_of, replace_all, run_end, slice, Hit, REDACTED16,
};

/// The part of a literal-prefix rule after `(?<![A-Za-z0-9_-])`: the end of
/// its match from `q`, if it matches there.
pub(super) type Rest = fn(&[u16], usize) -> Option<usize>;

/// The end of a run of `f` from `q`, when it holds at least `min` units.
fn run_min(t: &[u16], q: usize, min: usize, f: fn(u16) -> bool) -> Option<usize> {
    let r = run_end(t, q, f);
    (r - q >= min).then_some(r)
}

/// `q + n` when the `n` units from `q` all satisfy `f`.
fn exactly(t: &[u16], q: usize, n: usize, f: fn(u16) -> bool) -> Option<usize> {
    (q..q + n).all(|i| at(t, i, f)).then_some(q + n)
}

/// The position after the first of `alts` at `p`.
fn after(t: &[u16], p: usize, alts: &[&str]) -> Option<usize> {
    first_of(t, p, alts, false).map(|n| p + n)
}

/// The end of a match that `\b` closes after the fixed-length body ending at `e`.
fn then_boundary(t: &[u16], e: Option<usize>) -> Option<usize> {
    e.filter(|&e| !at(t, e, is_word))
}

/// `(?:sk|rk|pk|ak)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])`
fn openai(t: &[u16], p: usize) -> Option<usize> {
    let q = after(t, p, &["sk-", "rk-", "pk-", "ak-"])?;
    run_min(t, q, 20, is_tok)
}

/// `(?:(?:sk|rk|pk)_(?:live|test)_|whsec_)[A-Za-z0-9]{10,}\b`
fn stripe(t: &[u16], p: usize) -> Option<usize> {
    let alts = [
        "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_", "whsec_",
    ];
    let q = after(t, p, &alts)?;
    run_min(t, q, 10, is_alnum).filter(|&r| !at_is(t, r, b'_'))
}

/// `gh[pousr]_[A-Za-z0-9_]{20,}\b`
fn github(t: &[u16], p: usize) -> Option<usize> {
    let ok = has(t, p, "gh") && at(t, p + 2, |c| one_of(c, b"pousr")) && at_is(t, p + 3, b'_');
    if !ok {
        return None;
    }
    run_min(t, p + 4, 20, is_word)
}

/// `(?:AKIA|ASIA)[0-9A-Z]{16}\b`
fn aws(t: &[u16], p: usize) -> Option<usize> {
    let q = after(t, p, &["AKIA", "ASIA"])?;
    then_boundary(t, exactly(t, q, 16, |c| is_upper(c) || is_digit(c)))
}

/// `github_pat_[A-Za-z0-9_]{22,}`
fn github_pat(t: &[u16], p: usize) -> Option<usize> {
    run_min(t, after(t, p, &["github_pat_"])?, 22, is_word)
}

/// `glpat-[A-Za-z0-9_-]{20,}`
fn gitlab(t: &[u16], p: usize) -> Option<usize> {
    run_min(t, after(t, p, &["glpat-"])?, 20, is_tok)
}

/// `npm_[A-Za-z0-9]{36}\b`
fn npm(t: &[u16], p: usize) -> Option<usize> {
    then_boundary(t, exactly(t, after(t, p, &["npm_"])?, 36, is_alnum))
}

/// `hf_[A-Za-z]{34}\b`
fn hugging_face(t: &[u16], p: usize) -> Option<usize> {
    then_boundary(t, exactly(t, after(t, p, &["hf_"])?, 34, is_letter))
}

/// `cf(?:k|ut|at)_[A-Za-z0-9]{40,}`
fn cloudflare(t: &[u16], p: usize) -> Option<usize> {
    run_min(t, after(t, p, &["cfk_", "cfut_", "cfat_"])?, 40, is_alnum)
}

/// `(?:xox[baprse]|xapp)-[A-Za-z0-9-]{10,}(?![A-Za-z0-9_-])`
fn slack(t: &[u16], p: usize) -> Option<usize> {
    let xox = has(t, p, "xox") && at(t, p + 3, |c| one_of(c, b"baprse"));
    if !(xox || has(t, p, "xapp")) || !at_is(t, p + 4, b'-') {
        return None;
    }
    let class = |c| is_alnum(c) || is(c, b'-');
    run_min(t, p + 5, 10, class).filter(|&r| !at_is(t, r, b'_'))
}

/// `(?:capy|crsr)_[A-Za-z0-9_-]{16,}`
fn capy(t: &[u16], p: usize) -> Option<usize> {
    run_min(t, after(t, p, &["capy_", "crsr_"])?, 16, is_tok)
}

/// `relay_(?:ag|pa|ws|id)_[A-Za-z0-9._-]{16,}`
fn relay(t: &[u16], p: usize) -> Option<usize> {
    let q = after(t, p, &["relay_ag_", "relay_pa_", "relay_ws_", "relay_id_"])?;
    run_min(t, q, 16, |c| is_tok(c) || is(c, b'.'))
}

/// `rth_(?:at|rt|st)_[A-Za-z0-9_]{8,}\b`
fn relayhistory(t: &[u16], p: usize) -> Option<usize> {
    run_min(
        t,
        after(t, p, &["rth_at_", "rth_rt_", "rth_st_"])?,
        8,
        is_word,
    )
}

/// `AIza[0-9A-Za-z_-]{30,}(?![A-Za-z0-9_-])`
fn google(t: &[u16], p: usize) -> Option<usize> {
    run_min(t, after(t, p, &["AIza"])?, 30, is_tok)
}

/// The literal-prefix rules in rule-set order.
pub(super) const PREFIXED: [Rest; 14] = [
    openai,
    stripe,
    github,
    aws,
    github_pat,
    gitlab,
    npm,
    hugging_face,
    cloudflare,
    slack,
    capy,
    relay,
    relayhistory,
    google,
];

/// [`PREFIXED`] with the relay rule moved first, for the glued pass.
const GLUED_ORDER: [Rest; 14] = [
    relay,
    openai,
    stripe,
    github,
    aws,
    github_pat,
    gitlab,
    npm,
    hugging_face,
    cloudflare,
    slack,
    capy,
    relayhistory,
    google,
];

/// One literal-prefix rule: `(?<![A-Za-z0-9_-])` then `rest`, redacted whole.
pub(super) fn prefixed(t: &[u16], rest: Rest) -> Vec<u16> {
    replace_all(t, |t, i| {
        if before(t, i, is_tok) {
            return None;
        }
        rest(t, i).map(|end| Hit::redact(end, &[]))
    })
}

/// The glued form of one rule: `(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*?-(?:rest)[A-Za-z0-9_-]*`.
fn glued(t: &[u16], rest: Rest) -> Vec<u16> {
    replace_all(t, |t, i| {
        if before(t, i, is_tok) {
            return None;
        }
        let end = run_end(t, i, is_tok);
        (i..end)
            .filter(|&j| at_is(t, j, b'-'))
            .find_map(|j| rest(t, j + 1))
            .map(|e| Hit::redact(run_end(t, e, is_tok), &[]))
    })
}

/// Every literal-prefix rule again for a prefix glued to a longer token by
/// `-`, the relay rule first (its body may hold `.`). Text without a `-`
/// has nothing glued and is returned as it is.
pub(super) fn redact_glued_prefixes(t: &[u16]) -> Vec<u16> {
    if !t.contains(&u16::from(b'-')) {
        return t.to_vec();
    }
    GLUED_ORDER
        .into_iter()
        .fold(t.to_vec(), |text, rest| glued(&text, rest))
}

/// `\bBearer\s+[A-Za-z0-9._~+/=-]{15,}[A-Za-z0-9_~+/=-](?![A-Za-z0-9_~+/=-])`, gi.
pub(super) fn redact_bearer(t: &[u16]) -> Vec<u16> {
    replace_all(t, |t, i| {
        if before(t, i, is_word) || !has_ci(t, i, "bearer") {
            return None;
        }
        let s = run_end(t, i + 6, is_space);
        if s == i + 6 {
            return None;
        }
        let r = run_end(t, s, |c| is_alnum(c) || one_of(c, b"._~+/=-"));
        let last = (s..r).rev().find(|&k| !at_is(t, k, b'.'))?;
        let mut with: Vec<u16> = "Bearer ".encode_utf16().collect();
        with.extend_from_slice(&REDACTED16);
        (last >= s + 15).then(|| Hit::new(last + 1, with))
    })
}

/// `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])`
pub(super) fn redact_sendgrid(t: &[u16]) -> Vec<u16> {
    replace_all(t, |t, i| {
        if before(t, i, is_word) || !has(t, i, "SG.") {
            return None;
        }
        let dot = exactly(t, i + 3, 22, is_tok).filter(|&d| at_is(t, d, b'.'))?;
        let end = exactly(t, dot + 1, 43, is_tok).filter(|&e| !at(t, e, is_tok))?;
        Some(Hit::redact(end, &[]))
    })
}

/// `(hooks\.slack\.com\/(?:services|workflows|triggers)\/)[A-Za-z0-9_/-]{8,}` → `$1[REDACTED]`
pub(super) fn redact_slack_webhooks(t: &[u16]) -> Vec<u16> {
    replace_all(t, |t, i| {
        if !has(t, i, "hooks.slack.com/") {
            return None;
        }
        let q = after(t, i + 16, &["services/", "workflows/", "triggers/"])?;
        let end = run_min(t, q, 8, |c| is_tok(c) || is(c, b'/'))?;
        Some(Hit::redact(end, slice(t, i, q)))
    })
}

/// `(\/webhooks\/automations\/)[A-Za-z0-9._~-]{7,}[A-Za-z0-9_~-]` → `$1[REDACTED]`
pub(super) fn redact_automation_webhooks(t: &[u16]) -> Vec<u16> {
    replace_all(t, |t, i| {
        if !has(t, i, "/webhooks/automations/") {
            return None;
        }
        let q = i + 22;
        let r = run_end(t, q, |c| is_alnum(c) || one_of(c, b"._~-"));
        let last = (q..r).rev().find(|&k| !at_is(t, k, b'.'))?;
        (last >= q + 7).then(|| Hit::redact(last + 1, slice(t, i, q)))
    })
}

/// `[A-Za-z0-9_.-]{35,}`, each run's JWTs redacted.
pub(super) fn redact_jwts(t: &[u16]) -> Vec<u16> {
    let class = |c| is_tok(c) || is(c, b'.');
    replace_all(t, |t, i| {
        if before(t, i, class) {
            return None;
        }
        let r = run_end(t, i, class);
        (r - i >= 35).then(|| Hit::new(r, jwts_in_run(slice(t, i, r))))
    })
}

/// The first `eyJ` in `s` at or after `from`.
fn find_eyj(s: &[u16], from: usize) -> Option<usize> {
    (from..s.len()).find(|&k| has(s, k, "eyJ"))
}

/// Where a JWT header starts in segment `h`: an `eyJ` at a word boundary with
/// at least 11 units from it.
fn header_start(h: &[u16]) -> Option<usize> {
    let mut start = find_eyj(h, 0);
    while let Some(s) = start {
        let after_word = before(h, s, is_word);
        if !after_word && h.len() - s >= 11 {
            return Some(s);
        }
        start = if after_word { find_eyj(h, s + 1) } else { None };
    }
    None
}

/// Every `header.payload.signature` JWT in one dot-joined run, redacted.
fn jwts_in_run(run: &[u16]) -> Vec<u16> {
    let dot = u16::from(b'.');
    if !(0..run.len()).any(|k| has(run, k, ".eyJ")) {
        return run.to_vec();
    }
    let segments: Vec<&[u16]> = run.split(|&c| c == dot).collect();
    let mut out: Vec<Vec<u16>> = Vec::new();
    let mut i = 0;
    while let Some(header) = segments.get(i) {
        let payload = segments.get(i + 1).copied().unwrap_or_default();
        let signature = segments.get(i + 2).copied().unwrap_or_default();
        let jwt = has(payload, 0, "eyJ") && payload.len() >= 11 && signature.len() >= 16;
        if let Some(start) = header_start(header).filter(|_| jwt) {
            let mut piece = slice(header, 0, start).to_vec();
            piece.extend_from_slice(&REDACTED16);
            out.push(piece);
            i += 3;
            continue;
        }
        out.push(header.to_vec());
        i += 1;
    }
    out.join(&dot)
}

/// OAuth query values: `([?&](?:code_challenge|…|assertion)=)[^&\s]*` → `$1[REDACTED]`, gi.
pub(super) fn redact_oauth_values(t: &[u16]) -> Vec<u16> {
    let names = [
        "code_challenge=",
        "code_verifier=",
        "state=",
        "client_secret=",
        "access_token=",
        "id_token=",
        "refresh_token=",
        "assertion=",
    ];
    replace_all(t, |t, i| {
        if !at(t, i, |c| one_of(c, b"?&")) {
            return None;
        }
        let q = i + 1 + first_of(t, i + 1, &names, true)?;
        let end = run_end(t, q, |c| !(is(c, b'&') || is_space(c)));
        Some(Hit::redact(end, slice(t, i, q)))
    })
}
