//! `scrubJson`: every string value and key of a JSON value, and card numbers
//! among its numbers, with colliding keys suffixed in JavaScript's
//! `Object.entries` order.

use super::numbers::is_card_digits;
use super::{scrub_long, REDACTION_TOKEN};
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
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

/// Entries in `Object.entries` order, from entries in document order: a
/// repeated key keeps its first place and its last value (`JSON.parse`),
/// array-index keys come first in ascending order, then the rest as given.
fn js_order(entries: Vec<(String, Node)>) -> Vec<(String, Node)> {
    let mut place: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<(String, Node)> = Vec::with_capacity(entries.len());
    for (key, item) in entries {
        if let Some(&i) = place.get(&key) {
            out[i].1 = item;
        } else {
            place.insert(key.clone(), out.len());
            out.push((key, item));
        }
    }
    out.sort_by_key(|(key, _)| array_index(key).map_or((1, 0), |n| (0, n)));
    out
}

impl From<&Value> for Node {
    /// A serde_json map has lost its document order; its own (sorted) order,
    /// which is also the order it serializes in, stands in for it.
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

struct NodeVisitor;

impl<'de> Visitor<'de> for NodeVisitor {
    type Value = Node;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Node, E> {
        Ok(Node::Leaf(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Node, E> {
        Ok(Node::Leaf(Value::Number(v.into())))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Node, E> {
        Ok(Node::Leaf(Value::Number(v.into())))
    }
    fn visit_f64<E>(self, v: f64) -> Result<Node, E> {
        Ok(Node::Leaf(
            Number::from_f64(v).map_or(Value::Null, Value::Number),
        ))
    }
    fn visit_str<E>(self, v: &str) -> Result<Node, E> {
        Ok(Node::Leaf(Value::String(v.to_owned())))
    }
    fn visit_string<E>(self, v: String) -> Result<Node, E> {
        Ok(Node::Leaf(Value::String(v)))
    }
    fn visit_unit<E>(self) -> Result<Node, E> {
        Ok(Node::Leaf(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Node, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Node::Array(items))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Node, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry::<String, Node>()? {
            entries.push(entry);
        }
        Ok(Node::Object(js_order(entries)))
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeVisitor)
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
