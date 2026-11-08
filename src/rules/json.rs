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
#[derive(Debug)]
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

const MAX_JSON_DEPTH: usize = 128;

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            at: 0,
        }
    }

    fn skip_space(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.at += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.at) == Some(&byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn literal(&mut self, text: &[u8], value: Value) -> Option<Node> {
        if self.bytes.get(self.at..self.at + text.len())? != text {
            return None;
        }
        self.at += text.len();
        Some(Node::Leaf(value))
    }

    fn string(&mut self) -> Option<String> {
        let start = self.at;
        if !self.take(b'"') {
            return None;
        }
        let mut escaped = false;
        while let Some(&byte) = self.bytes.get(self.at) {
            self.at += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return serde_json::from_str(&self.text[start..self.at]).ok();
            } else if byte < 0x20 {
                return None;
            }
        }
        None
    }

    fn digits(&mut self) -> bool {
        let start = self.at;
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
        }
        self.at > start
    }

    fn number(&mut self) -> Option<Node> {
        let start = self.at;
        let negative = self.take(b'-');
        match self.bytes.get(self.at) {
            Some(b'0') => {
                self.at += 1;
                if self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
                    return None;
                }
            }
            Some(b'1'..=b'9') if self.digits() => {}
            _ => return None,
        }

        let mut integral = true;
        if self.take(b'.') {
            integral = false;
            if !self.digits() {
                return None;
            }
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            integral = false;
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !self.digits() {
                return None;
            }
        }

        let token = &self.text[start..self.at];
        let number = if integral && negative {
            token.parse::<i64>().ok().map(Number::from)
        } else if integral {
            token.parse::<u64>().ok().map(Number::from)
        } else {
            None
        }
        .or_else(|| token.parse::<f64>().ok().and_then(Number::from_f64))?;
        Some(Node::Leaf(Value::Number(number)))
    }

    fn array(&mut self, depth: usize) -> Option<Node> {
        self.take(b'[').then_some(())?;
        self.skip_space();
        let mut items = Vec::new();
        if self.take(b']') {
            return Some(Node::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_space();
            if self.take(b']') {
                return Some(Node::Array(items));
            }
            self.take(b',').then_some(())?;
            self.skip_space();
        }
    }

    fn object(&mut self, depth: usize) -> Option<Node> {
        self.take(b'{').then_some(())?;
        self.skip_space();
        let mut entries: Vec<(String, Node)> = Vec::new();
        let mut positions: HashMap<String, usize> = HashMap::new();
        if self.take(b'}') {
            return Some(Node::Object(entries));
        }
        loop {
            let key = self.string()?;
            self.skip_space();
            self.take(b':').then_some(())?;
            self.skip_space();
            let value = self.value(depth + 1)?;
            if let Some(index) = positions.get(&key).copied() {
                entries[index].1 = value;
            } else {
                positions.insert(key.clone(), entries.len());
                entries.push((key, value));
            }
            self.skip_space();
            if self.take(b'}') {
                return Some(Node::Object(js_order(entries)));
            }
            self.take(b',').then_some(())?;
            self.skip_space();
        }
    }

    fn value(&mut self, depth: usize) -> Option<Node> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.skip_space();
        match self.bytes.get(self.at)? {
            b'n' => self.literal(b"null", Value::Null),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'"' => self.string().map(Value::String).map(Node::Leaf),
            b'[' => self.array(depth),
            b'{' => self.object(depth),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }
}

/// Parse JSON while retaining the key order seen by `JSON.parse` without
/// enabling `serde_json/preserve_order` for every crate in the dependency
/// graph. Numbers use serde_json's default JavaScript-compatible finite-number
/// representation; out-of-range inputs and values nested past 128 levels fail
/// parsing instead of changing a consumer's global number semantics or risking
/// an unbounded recursive parse.
pub(super) fn parse_text(text: &str) -> Option<Node> {
    let mut parser = Parser::new(text);
    let value = parser.value(1)?;
    parser.skip_space();
    (parser.at == parser.bytes.len()).then_some(value)
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
