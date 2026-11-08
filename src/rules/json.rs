//! `scrubJson`: every string value and key of a JSON value, and card numbers
//! among its numbers, with colliding keys suffixed in JavaScript's
//! `Object.entries` order.

use super::numbers::is_card_digits;
use super::{scrub_long, REDACTION_TOKEN};
use serde_json::{Map, Number, Value};
use std::collections::HashMap;

/// Largest integer JavaScript holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The digits of a positive integer `n` if it is a card number.
fn card(n: u64) -> bool {
    n > 0 && is_card_digits(n.to_string().as_bytes())
}

/// `scrubNumber`: a JSON number that is a card number becomes the redaction
/// token. JavaScript can only check safe integers; serde_json keeps every
/// `u64` exact, so an unsigned integer is checked whatever its size.
pub(super) fn scrub_number(n: &Number) -> Option<Value> {
    let exact = n.as_u64().map(card);
    let float = || {
        n.as_f64()
            .filter(|f| f.fract() == 0.0 && *f > 0.0 && *f <= MAX_SAFE_INTEGER as f64)
            .is_some_and(|f| card(f as u64))
    };
    exact
        .unwrap_or_else(float)
        .then(|| Value::String(REDACTION_TOKEN.to_owned()))
}

/// A JSON value whose objects keep their entries in `Object.entries` order.
pub(super) enum Node {
    Leaf(Value),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}

/// The array index a key names (`"0"`, `"17"`, up to 2^32 - 2), if any.
/// JavaScript lists those keys first, in ascending order.
fn array_index(key: &str) -> Option<u32> {
    let canonical =
        key == "0" || (!key.starts_with('0') && key.bytes().all(|b| b.is_ascii_digit()));
    key.parse::<u32>()
        .ok()
        .filter(|n| canonical && *n < u32::MAX)
}

/// Entries in `Object.entries` order. `serde_json::Map` has already applied
/// JSON.parse's repeated-key rule (first position, last value), so only the
/// array-index ordering remains here.
fn js_order(mut entries: Vec<(String, Node)>) -> Vec<(String, Node)> {
    entries.sort_by_key(|(key, _)| array_index(key).map_or((1, 0), |n| (0, n)));
    entries
}

/// serde_json's arbitrary-precision representation reserves this object key.
/// Protect user strings with the same spelling before parsing so an ordinary
/// object can never be mistaken for the library's internal number wrapper.
const NUMBER_TOKEN: &str = "$serde_json::private::Number";

/// Find user strings that collide with serde_json's token and the longest
/// already-used NUL suffix. Non-candidate strings are scanned without an
/// allocation; the actual parser remains the authority on JSON validity.
fn protected_strings(text: &str) -> Option<(Vec<(usize, usize)>, usize)> {
    let bytes = text.as_bytes();
    let mut replacements = Vec::new();
    let mut max_nuls = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i;
        i += 1;
        let mut escaped = false;
        let mut closed = false;
        while i < bytes.len() {
            let byte = bytes[i];
            i += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                closed = true;
                if matches!(bytes.get(start + 1), Some(b'$' | b'\\')) {
                    let value: String = serde_json::from_str(&text[start..i]).ok()?;
                    if let Some(suffix) = value.strip_prefix(NUMBER_TOKEN) {
                        if suffix.bytes().all(|byte| byte == 0) {
                            max_nuls = max_nuls.max(suffix.len());
                            if suffix.is_empty() {
                                replacements.push((start, i));
                            }
                        }
                    }
                }
                break;
            }
        }
        if !closed {
            return None;
        }
    }
    Some((replacements, max_nuls))
}

/// Parse a JSON text without exposing serde_json's private arbitrary-number
/// marker as an observable key collision.
pub(super) fn parse_text(text: &str) -> Option<Value> {
    let (replacements, max_nuls) = protected_strings(text)?;
    if replacements.is_empty() {
        return serde_json::from_str(text).ok();
    }

    let mut protected = NUMBER_TOKEN.to_owned();
    for _ in 0..=max_nuls {
        protected.push('\0');
    }

    let replacement = serde_json::to_string(&protected).ok()?;
    let mut rewritten = String::with_capacity(text.len());
    let mut copied = 0;
    for (start, end) in replacements {
        rewritten.push_str(&text[copied..start]);
        rewritten.push_str(&replacement);
        copied = end;
    }
    rewritten.push_str(&text[copied..]);

    let mut value: Value = serde_json::from_str(&rewritten).ok()?;
    restore_protected(&mut value, &protected);
    Some(value)
}

fn restore_protected(value: &mut Value, protected: &str) {
    match value {
        Value::String(text) if text == protected => *text = NUMBER_TOKEN.to_owned(),
        Value::Array(items) => {
            for item in items {
                restore_protected(item, protected);
            }
        }
        Value::Object(map) => {
            let old = std::mem::take(map);
            for (mut key, mut item) in old {
                if key == protected {
                    key = NUMBER_TOKEN.to_owned();
                }
                restore_protected(&mut item, protected);
                map.insert(key, item);
            }
        }
        _ => {}
    }
}

impl From<&Value> for Node {
    /// Preserve the map's insertion order, then apply JavaScript's special
    /// ordering for array-index keys.
    fn from(value: &Value) -> Self {
        match value {
            Value::Array(items) => Node::Array(items.iter().map(Node::from).collect()),
            Value::Object(map) => Node::Object(js_order(
                map.iter()
                    .map(|(k, v)| (k.clone(), Node::from(v)))
                    .collect(),
            )),
            _ => Node::Leaf(value.clone()),
        }
    }
}

/// `${base} (n)` for the first free `n`, starting at the next one tried for `base`.
fn free_name(output: &Map<String, Value>, base: &str, next: &mut HashMap<String, u64>) -> String {
    let slot = next.entry(base.to_owned()).or_insert(2);
    let mut name = format!("{base} ({slot})");
    while output.contains_key(&name) {
        *slot += 1;
        name = format!("{base} ({slot})");
    }
    *slot += 1;
    name
}

/// Scrub one object in `Object.entries` order, counting what changed.
fn scrub_object(entries: &[(String, Node)], count: &mut usize) -> Value {
    let mut output = Map::new();
    let mut next = HashMap::new();
    for (key, item) in entries {
        let base = scrub_long(key);
        if base != *key {
            *count += 1;
        }
        let name = if output.contains_key(&base) {
            free_name(&output, &base, &mut next)
        } else {
            base
        };
        output.insert(name, scrub_node(item, count));
    }
    Value::Object(output)
}

/// Scrub one leaf, counting a redacted string or number.
fn scrub_leaf(value: &Value, count: &mut usize) -> Value {
    let clean = match value {
        Value::String(text) => Some(Value::String(scrub_long(text))).filter(|v| v != value),
        Value::Number(n) => scrub_number(n),
        _ => None,
    };
    clean.map_or_else(
        || value.clone(),
        |clean| {
            *count += 1;
            clean
        },
    )
}

/// Scrub `node`, adding the number of strings, keys and numbers it redacted
/// to `count`. Strings and keys of any length are scrubbed whole with the
/// segmenter, as the Cloud's raw-chunk path does.
pub(super) fn scrub_node(node: &Node, count: &mut usize) -> Value {
    match node {
        Node::Leaf(value) => scrub_leaf(value, count),
        Node::Array(items) => {
            Value::Array(items.iter().map(|item| scrub_node(item, count)).collect())
        }
        Node::Object(entries) => scrub_object(entries, count),
    }
}
