//! Structured traversal with inherited context and atomic NDJSON transport.

use crate::{
    engine, AdmissionError, Policy, MAX_JSON_DEPTH, MAX_RECORD_BYTES, MAX_STREAM_BYTES,
    REDACTION_TOKEN,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

fn within_depth(value: &Value) -> bool {
    let mut pending = vec![(value, 0)];
    while let Some((item, depth)) = pending.pop() {
        if depth > MAX_JSON_DEPTH {
            return false;
        }
        match item {
            Value::Array(items) => pending.extend(items.iter().map(|v| (v, depth + 1))),
            Value::Object(map) => pending.extend(map.values().map(|v| (v, depth + 1))),
            _ => {}
        }
    }
    true
}

fn visit(
    value: &Value,
    public: bool,
    credential: bool,
    tags: bool,
    policy: Policy,
    count: &mut usize,
) -> Value {
    match value {
        Value::String(s) => {
            let clean = engine::scrub(s, public, policy);
            *count += usize::from(clean != *s);
            Value::String(clean)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| visit(v, public, credential, tags, policy, count))
                .collect(),
        ),
        Value::Object(map) => {
            let tag_pair = tags
                && !credential
                && map.len() == 2
                && map
                    .get("Key")
                    .and_then(Value::as_str)
                    .zip(map.get("Value").and_then(Value::as_str))
                    .is_some_and(|(key, value)| engine::cloud_tag_values(key, value));
            let mut out = Map::new();
            let mut next = BTreeMap::<String, usize>::new();
            let mut entries: Vec<_> = map
                .iter()
                .map(|(k, v)| (engine::scrub(k, false, policy), k, v))
                .collect();
            entries.sort_by(|a, b| a.1.cmp(b.1));
            let reserved: std::collections::BTreeSet<_> =
                entries.iter().map(|(base, _, _)| base.as_str()).collect();
            for (base, key, item) in &entries {
                *count += usize::from(base != *key);
                let name = if out.contains_key(base) {
                    let n = next.entry(base.clone()).or_insert(2);
                    loop {
                        let candidate = format!("{base} ({n})");
                        *n += 1;
                        if !out.contains_key(&candidate) && !reserved.contains(candidate.as_str()) {
                            break candidate;
                        }
                    }
                } else {
                    base.clone()
                };
                let clean = if (engine::sensitive(key)
                    || credential && !public && key.eq_ignore_ascii_case("key"))
                    && !(matches!(key.to_ascii_lowercase().as_str(), "auth" | "authentication")
                        && item.is_object())
                    && !(tag_pair && key.as_str() == "Key")
                    && !item.as_object().is_some_and(|map| {
                        map.len() == 1 && engine::masked_connection_mapping(&item.to_string())
                    })
                    && **item != Value::String(REDACTION_TOKEN.into())
                    && **item != Value::String(String::new())
                    && !(item.is_number() && engine::numeric_identifier(key))
                    && !item.is_boolean()
                    && !item.is_null()
                    && !item
                        .as_str()
                        .is_some_and(|s| engine::field_reference(key, s))
                {
                    *count += 1;
                    Value::String(REDACTION_TOKEN.into())
                } else {
                    visit(
                        item,
                        !engine::credential_context(key) && (public || engine::public_context(key)),
                        !engine::public_context(key)
                            && (credential || engine::credential_context(key)),
                        key.as_str() == "Tags" && item.is_array(),
                        policy,
                        count,
                    )
                };
                out.insert(name, clean);
            }
            // A consumer may enable serde_json/preserve_order. Canonicalize
            // input and final key order so that target features do not reorder bytes.
            let mut sorted: Vec<_> = out.into_iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(sorted.into_iter().collect())
        }
        _ => value.clone(),
    }
}

// Count serialized bytes without allocating a second copy or returning excerpts.
struct Budget(usize);
impl std::io::Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        if self.0 > MAX_RECORD_BYTES {
            return Err(std::io::Error::other("record_too_large"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn admit(value: &Value) -> Result<(), AdmissionError> {
    if !within_depth(value) {
        return Err(AdmissionError {
            code: "json_too_deep",
        });
    }
    serde_json::to_writer(&mut Budget(0), value).map_err(|_| AdmissionError {
        code: "record_too_large",
    })
}
/// Checked JSON traversal with a 16 MiB serialized logical-record bound.
pub fn scrub_json_checked(value: &Value) -> Result<(Value, usize), AdmissionError> {
    admit(value)?;
    let mut count = 0;
    Ok((
        visit(value, false, false, false, Policy::Secrets, &mut count),
        count,
    ))
}
/// Check encoded record size before parsing; errors contain no input excerpts.
pub fn scrub_json_text_checked(input: &str) -> Result<(Value, usize), AdmissionError> {
    if input.len() > MAX_RECORD_BYTES {
        return Err(AdmissionError {
            code: "record_too_large",
        });
    }
    let value = serde_json::from_str(input).map_err(|_| AdmissionError {
        code: "invalid_json",
    })?;
    scrub_json_checked(&value)
}

/// Scrub every JSON key/value and return the number of changed nodes.
/// Excess depth fails closed to a single marker; no input subtree is returned.
#[must_use]
pub fn scrub_json(value: &Value) -> (Value, usize) {
    scrub_json_with_policy(value, Policy::Secrets)
}

/// Scrub JSON with explicit PII policy and inherited public-value context.
#[must_use]
pub fn scrub_json_with_policy(value: &Value, policy: Policy) -> (Value, usize) {
    if admit(value).is_err() {
        return (Value::String(REDACTION_TOKEN.into()), 1);
    }
    let mut count = 0;
    let clean = visit(value, false, false, false, policy, &mut count);
    (clean, count)
}

/// Parse and scrub JSON. `None` means discard the original input, never persist it.
/// Duplicate keys use last-value semantics; always serialize the returned value.
#[must_use]
pub fn scrub_json_text(input: &str) -> Option<(Value, usize)> {
    scrub_json_text_checked(input).ok()
}

/// Stable errors never contain input text, keys, parser excerpts or credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "crate::TaggedError")]
pub struct RecordError {
    /// Stable error code.
    pub code: &'static str,
    /// One-based physical record line; zero denotes the whole-stream size limit.
    pub record: usize,
}
impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at record {}", self.code, self.record)
    }
}
impl std::error::Error for RecordError {}

/// Atomic NDJSON result; consumers may persist only a successful result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordOutput {
    /// Canonically serialized UTF-8 JSON with one newline per record.
    pub bytes: Vec<u8>,
    /// Number of nonblank records emitted.
    pub record_count: usize,
    /// Changed-node count across records.
    pub redaction_count: usize,
}

/// Scrub NDJSON atomically, up to 16 MiB per record and 64 MiB per operation.
/// On error there is no partial output.
pub fn scrub_records(input: &[u8]) -> Result<RecordOutput, RecordError> {
    if input.len() > MAX_STREAM_BYTES {
        return Err(RecordError {
            code: "stream_too_large",
            record: 0,
        });
    }
    let mut output = RecordOutput {
        bytes: Vec::new(),
        record_count: 0,
        redaction_count: 0,
    };
    for (i, line) in input.split(|&b| b == b'\n').enumerate() {
        let record = i + 1;
        if line.len() > MAX_RECORD_BYTES {
            return Err(RecordError {
                code: "record_too_large",
                record,
            });
        }
        let text = std::str::from_utf8(line).map_err(|_| RecordError {
            code: "invalid_utf8",
            record,
        })?;
        if text.trim().is_empty() {
            continue;
        }
        let (value, count) = scrub_json_text(text).ok_or(RecordError {
            code: "invalid_json",
            record,
        })?;
        serde_json::to_writer(&mut output.bytes, &value).expect("Vec write cannot fail");
        output.bytes.push(b'\n');
        output.record_count += 1;
        output.redaction_count += count;
    }
    Ok(output)
}
