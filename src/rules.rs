//! Technical Foul: the Cloud's secret-scrub rule set, run on this device
//! before a session upload leaves it.
//!
//! A port of `packages/pipeline/src/lib/scrub.ts` (rule set version
//! [`RULESET_VERSION`]) and of the scrub segmenter in
//! `packages/pipeline/src/lib/pipeline/raw-chunks.ts`, kept in lockstep with
//! the Cloud by the vendored manifest and corpus in `technical_foul/fixtures`:
//! the tests pin the rule-set source digest, the corpus digest, the version,
//! the bound and the token, and run every corpus case. The fixtures are
//! byte-exact copies of `packages/pipeline/technical-foul.json` and
//! `packages/pipeline/test/fixtures/scrub-secret-corpus.json` at
//! relayhistory-pipeline commit 86eaefea (#312).
//!
//! Text is scrubbed as UTF-16 with JavaScript's regular-expression semantics,
//! so a scrubbed string is byte for byte what the Cloud would store. Every
//! string and key is scrubbed whole with [`scrub_long`], as the Cloud's
//! raw-chunk path does, and a text is only ever split where the ported
//! `cutIsSafe` holds. Colliding keys get their ` (2)`, ` (3)` suffixes in
//! `Object.entries` order. Where this port differs from the Cloud on
//! purpose, the difference is noted where it is made and covered by a test:
//!  - [`scrub_long`] also tries a cut after a comma where text has no
//!    whitespace to cut after (compact JSON, minified code); a comma is a
//!    cut only if it passes the same `cutIsSafe` check as whitespace, so it
//!    only splits text whose scrub it does not change;
//!  - [`scrub_long`] replaces a remainder with no safe cut with the
//!    redaction token where the Cloud refuses it, so an upload is never
//!    refused and no part of that text is sent;
//!  - [`scrub_json`] checks every unsigned integer for a card number, where
//!    JavaScript has lost the digits of one past 2^53;
//!  - [`scrub_json`] keeps a `__proto__` key as an ordinary key, where a
//!    JavaScript object assignment drops it.

mod assign;
mod js;
mod json;
mod numbers;
mod pem;
mod quoted;
mod segment;
mod tokens;
mod web;

use js::{is, is_digit, is_space, slice};

/// The Cloud rule set this port matches (`SCRUB_RULESET_VERSION`).
pub const RULESET_VERSION: u32 = 3;

/// What every redacted secret becomes.
pub const REDACTION_TOKEN: &str = "[REDACTED]";

/// The longest text one bounded scrub takes (`MAX_SCRUB_CHARS`), in UTF-16 units.
pub const MAX_SCRUB_CHARS: usize = 262_144;

/// sha256 of the Cloud's `scrub.ts` this port was made from, as the Cloud's
/// `technical-foul.json` manifest records it.
pub const PINNED_RULESET_SOURCE_SHA256: &str =
    "e7607073a3afca3db6b015945f0b5fab256202f355b740f515987ec162bf3076";

/// Whether `t` may be cut before `i` (`safeCut` in `scrub.ts`): after
/// whitespace and not between two digit groups.
fn safe_cut(t: &[u16], i: usize) -> bool {
    let digit_or = |b: u8| move |c: u16| is_digit(c) || is(c, b);
    js::before(t, i, is_space)
        && !(i
            .checked_sub(1)
            .is_some_and(|j| js::before(t, j, digit_or(b')')))
            && js::at(t, i, digit_or(b'(')))
}

/// `boundForScrub`: text past [`MAX_SCRUB_CHARS`] is cut after whitespace
/// (before any private-key block left open there) and the cut is announced.
fn bound(t: &[u16]) -> std::borrow::Cow<'_, [u16]> {
    if t.len() <= MAX_SCRUB_CHARS {
        return t.into();
    }
    let mut cut = MAX_SCRUB_CHARS;
    while cut > 0 && !safe_cut(t, cut) {
        cut -= 1;
    }
    if let Some(open) = pem::unclosed_start(slice(t, 0, cut)) {
        cut = open;
    }
    let note = format!(
        "\n[relayhistory: truncated {} characters over the {MAX_SCRUB_CHARS}-character scrub limit]",
        t.len() - cut
    );
    let mut out = slice(t, 0, cut).to_vec();
    out.extend(note.encode_utf16());
    out.into()
}

/// One rule of the pipeline: text in, text out.
type Rule = fn(&[u16]) -> Vec<u16>;

/// One literal-prefix rule by its place in [`tokens::PREFIXED`].
fn prefixed<const N: usize>(t: &[u16]) -> Vec<u16> {
    tokens::PREFIXED
        .get(N)
        .map_or_else(|| t.to_vec(), |rest| tokens::prefixed(t, *rest))
}

/// `SECRET_PATTERNS`, in the Cloud's order.
const RULES: [Rule; 31] = [
    pem::redact_private_keys,
    web::redact_home_paths,
    tokens::redact_bearer,
    tokens::redact_sendgrid,
    prefixed::<0>,
    prefixed::<1>,
    prefixed::<2>,
    prefixed::<3>,
    prefixed::<4>,
    prefixed::<5>,
    prefixed::<6>,
    prefixed::<7>,
    prefixed::<8>,
    prefixed::<9>,
    tokens::redact_slack_webhooks,
    prefixed::<10>,
    prefixed::<11>,
    tokens::redact_automation_webhooks,
    tokens::redact_jwts,
    prefixed::<12>,
    tokens::redact_oauth_values,
    prefixed::<13>,
    tokens::redact_glued_prefixes,
    quoted::redact_quoted_secret_values,
    assign::redact_authorization,
    assign::redact_assignments,
    assign::redact_fallback,
    web::redact_userinfo,
    web::redact_emails,
    numbers::redact_phones,
    numbers::redact_cards,
];

/// `scrubText` over UTF-16: bound, then every rule in order.
fn scrub16(t: &[u16]) -> Vec<u16> {
    RULES
        .iter()
        .fold(bound(t).into_owned(), |text, rule| rule(&text))
}

/// Scrub one string as the Cloud's `scrubText` does: text past
/// [`MAX_SCRUB_CHARS`] is truncated after whitespace and the cut announced.
/// Uploads never take this: they are scrubbed with [`scrub_long`], which
/// does not truncate.
#[must_use]
pub fn scrub_text(value: &str) -> String {
    let units: Vec<u16> = value.encode_utf16().collect();
    String::from_utf16_lossy(&scrub16(&units))
}

/// Scrub a string of any length whole, segmented as the Cloud's `scrubLong`
/// does; a remainder with no safe cut, or an over-cap quoted secret that v3
/// cannot safely finish, becomes the redaction token.
#[must_use]
pub fn scrub_long(value: &str) -> String {
    let units: Vec<u16> = value.encode_utf16().collect();
    String::from_utf16_lossy(&segment::scrub_long16(&units))
}

/// Scrub every string value and key of a JSON value, and card numbers among
/// its numbers (`scrubJson`). Returns the scrubbed value and how many
/// strings, keys and numbers were redacted. Maps use the order provided by the
/// consumer's `serde_json::Value`; array-index keys are visited first, as
/// `Object.entries` lists them. Values nested beyond serde_json's default
/// 128-level parsing limit fail closed to a single redaction token rather than
/// risking a recursive stack overflow.
#[must_use]
pub fn scrub_json(value: &serde_json::Value) -> (serde_json::Value, usize) {
    let mut pending = vec![(value, 1usize)];
    while let Some((item, depth)) = pending.pop() {
        if depth > json::MAX_JSON_DEPTH {
            return (serde_json::Value::String(REDACTION_TOKEN.to_owned()), 1);
        }
        match item {
            serde_json::Value::Array(items) => {
                pending.extend(items.iter().map(|item| (item, depth + 1)));
            }
            serde_json::Value::Object(map) => {
                pending.extend(map.values().map(|item| (item, depth + 1)));
            }
            _ => {}
        }
    }
    let mut count = 0;
    let clean = json::scrub_node(&json::Node::from(value), &mut count);
    (clean, count)
}

/// [`scrub_json`] over a JSON text, suffixing colliding keys in the
/// `Object.entries` order that `JSON.parse` reads (array-index keys ascending,
/// then document order). `None` for invalid, out-of-range, or more-than-128-level
/// JSON. This does not enable global `serde_json` map-order or arbitrary-number
/// features.
#[must_use]
pub fn scrub_json_text(text: &str) -> Option<(serde_json::Value, usize)> {
    let node = json::parse_text(text)?;
    let mut count = 0;
    let clean = json::scrub_node(&node, &mut count);
    Some((clean, count))
}

#[cfg(test)]
mod tests;
