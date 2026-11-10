//! Fixed automata and a monotone contextual scanner; no backtracking regex.

use crate::{normalize::View, Policy, REDACTION_TOKEN};
use aho_corasick::AhoCorasick;
use base64::Engine;
use regex::Regex;
use std::{borrow::Cow, ops::Range, sync::OnceLock};

// Keep patterns explicit and reviewable. Every alternative has a provider or
// protocol meaning; generic entropy and bare hashes are intentionally absent.
const PROVIDERS: &str = concat!(
    r"(?:",
    r"sk-(?:proj-|svcacct-|ant-api[0-9]{2}-)?[A-Za-z0-9_-]{20,}|",
    r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|",
    r"glpat-[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16,}|",
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,}|",
    r"xox[baprse]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}|",
    r"npm_[A-Za-z0-9]{36,}|pypi-[A-Za-z0-9_-]{32,}|",
    r"AIza[A-Za-z0-9_-]{35,}|ya29\.[A-Za-z0-9_-]{20,}|",
    r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43,}|",
    r"dop_v1_[a-f0-9]{64}|doo_v1_[a-f0-9]{64}|",
    r"cf(?:ut|at|k)_[A-Za-z0-9_-]{20,}|vercel_[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|",
    r"(?:capy|crsr)_[A-Za-z0-9_-]{16,}|relay_(?:ag|pa|ws|id)_[A-Za-z0-9._-]{16,}|rth_(?:at|rt|st)_[A-Za-z0-9_]{8,}",
    r")"
);
const WEBHOOK: &str = r"https://hooks\.slack(?:-gov)?\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+|/webhooks/automations/[A-Za-z0-9._~-]{8,}";

fn provider_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(&format!(r"\A(?:{PROVIDERS}|{WEBHOOK})")).expect("fixed provider regex")
    })
}

fn provider_matches(text: &str) -> Vec<Range<usize>> {
    // Find fixed provider prefixes once, then validate only at those positions.
    // The large token automaton must not retry every byte of ordinary long
    // fields (notably megabyte runs beginning with x on debug Windows builds).
    const PREFIXES: &[&str] = &[
        "sk-",
        "sk_",
        "rk_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "AKIA",
        "ASIA",
        "whsec_",
        "xoxb-",
        "xoxa-",
        "xoxp-",
        "xoxr-",
        "xoxs-",
        "xoxe-",
        "xapp-",
        "npm_",
        "pypi-",
        "AIza",
        "ya29.",
        "SG.",
        "dop_v1_",
        "doo_v1_",
        "cfut_",
        "cfat_",
        "cfk_",
        "vercel_",
        "hf_",
        "capy_",
        "crsr_",
        "relay_ag_",
        "relay_pa_",
        "relay_ws_",
        "relay_id_",
        "rth_at_",
        "rth_rt_",
        "rth_st_",
        "https://hooks.slack",
        "/webhooks/automations/",
    ];
    static STARTS: OnceLock<AhoCorasick> = OnceLock::new();
    let starts =
        STARTS.get_or_init(|| AhoCorasick::new(PREFIXES).expect("fixed provider prefixes"));
    let mut ranges = Vec::new();
    let mut cursor = 0;
    for prefix in starts.find_iter(text) {
        let start = prefix.start();
        if start < cursor {
            continue;
        }
        if let Some(token) = provider_regex().find(&text[start..]) {
            cursor = start + token.end();
            ranges.push(start..cursor);
        }
    }
    ranges
}

fn pem_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----").expect("fixed PEM regex")
    })
}

pub(crate) fn sensitive(name: &str) -> bool {
    if name.len() < 3 {
        return false;
    }
    // All credential names/suffixes end with one of these ASCII letters.
    // Reject huge ordinary words before normalization and suffix scans. The
    // previous normalization ignores separators even at the end of a name.
    let tail = name
        .trim_end_matches(['_', '-'])
        .as_bytes()
        .last()
        .map(u8::to_ascii_lowercase);
    if !tail.is_some_and(|b| b"detynhlsr".contains(&b)) {
        return false;
    }
    let n: Cow<'_, str> = if name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(
            name.bytes()
                .filter(|b| !matches!(b, b'_' | b'-'))
                .map(|b| char::from(b.to_ascii_lowercase()))
                .collect(),
        )
    };
    if matches!(
        n.as_ref(),
        "publickey" | "codechallenge" | "state" | "existingsecret"
    ) || [
        "secretref",
        "secretname",
        "credentialsfile",
        "credentialssecret",
        "credentialsecret",
        "credentialspath",
    ]
    .contains(&n.as_ref())
    {
        return false;
    }
    if public_context(name) {
        return false;
    }
    const NAMES: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "pin",
        "passphrase",
        "secret",
        "clientsecret",
        "apikey",
        "accesskey",
        "accountkey",
        "secretkey",
        "privatekey",
        "token",
        "accesstoken",
        "authtoken",
        "refreshtoken",
        "idtoken",
        "sessiontoken",
        "sessionid",
        "credential",
        "credentials",
        "authorization",
        "auth",
        "bearer",
        "proxyauthorization",
        "cookie",
        "setcookie",
    ];
    if NAMES.contains(&n.as_ref()) {
        return true;
    }
    // Credential suffixes include provider and camelCase names. Generic key
    // requires a separator or a camelCase boundary (preserve e.g. monkey).
    let lower = if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    };
    // Split and normalize each suffix once, not once per credential name.
    // Long ordinary fields otherwise multiply full-string scans in debug CI.
    let underscore_tail = lower.rsplit_once('_').map(|(_, t)| t.replace('-', ""));
    let hyphen_tail = lower.rsplit_once('-').map(|(_, t)| t.replace('_', ""));
    NAMES.iter().any(|tail| {
        underscore_tail.as_deref() == Some(*tail) || hyphen_tail.as_deref() == Some(*tail)
    }) || lower.ends_with("_key")
        || lower.ends_with("-key")
        || [
            "apikey",
            "accesstoken",
            "secretaccesskey",
            "sessiontoken",
            "clientsecret",
            "password",
            "passwd",
            "secret",
            "token",
        ]
        .iter()
        .any(|tail| n.ends_with(tail))
        || name.ends_with("Key")
}

pub(crate) fn public_context(name: &str) -> bool {
    name.eq_ignore_ascii_case("idempotency_key")
        || name.eq_ignore_ascii_case("idempotency-key")
        || name.eq_ignore_ascii_case("idempotencyKey")
}

pub(crate) fn numeric_identifier(name: &str) -> bool {
    name.replace(['_', '-'], "")
        .eq_ignore_ascii_case("sessionid")
}

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}
fn space_width(b: &[u8], i: usize) -> usize {
    if b.get(i).is_some_and(u8::is_ascii_whitespace) {
        return 1;
    }
    if b.get(i).is_some_and(|b| *b >= 0xc0) {
        if let Ok(s) = std::str::from_utf8(&b[i..i.saturating_add(4).min(b.len())]) {
            if let Some(c) = s
                .chars()
                .next()
                .filter(|c| c.is_whitespace() || *c == '\u{feff}')
            {
                return c.len_utf8();
            }
        } else {
            // Decode just this scalar; the following four-byte window may end
            // inside a later scalar.
            for width in 2..=4 {
                if let Some(s) = b
                    .get(i..i + width)
                    .and_then(|s| std::str::from_utf8(s).ok())
                {
                    if let Some(c) = s
                        .chars()
                        .next()
                        .filter(|c| c.is_whitespace() || *c == '\u{feff}')
                    {
                        return c.len_utf8();
                    }
                }
            }
        }
    }
    0
}
fn skip_space(b: &[u8], mut i: usize) -> usize {
    loop {
        let width = space_width(b, i);
        if width == 0 {
            return i;
        }
        i += width;
    }
}
fn line_end(view: &View, i: usize) -> usize {
    view.line_end(i)
}

fn value_end(view: &View, start: usize, context_end: Option<usize>) -> usize {
    let b = view.text.as_bytes();
    if start >= b.len() {
        return start;
    }
    if matches!(b[start], b'"' | b'\'' | b'`') {
        return view.quote_end(start).min(context_end.unwrap_or(b.len()));
    }
    if matches!(b[start], b'{' | b'[') && !view.text[start..].starts_with(REDACTION_TOKEN) {
        return view
            .container_end(start)
            .min(context_end.unwrap_or(b.len()));
    }
    if let Some(end) = context_end {
        return end;
    }
    let limit = view.enclosing_end(start).min(b.len());
    let mut end = start;
    if view.text[start..].starts_with(REDACTION_TOKEN) {
        end += REDACTION_TOKEN.len();
    }
    while end < limit
        && !(view.literal(end)
            && (space_width(b, end) > 0
                || matches!(
                    b[end],
                    b'"' | b'\'' | b'`' | b',' | b';' | b'&' | b'}' | b']' | b')'
                )))
    {
        end += 1;
    }
    end
}

fn indented_end(view: &View, value: usize, key_indent: usize) -> usize {
    let b = view.text.as_bytes();
    let mut cursor = view.line_end(value);
    let mut end = cursor;
    while cursor < b.len() {
        let mut next = cursor;
        if b[next] == b'\r' {
            next += 1;
        }
        if b.get(next) == Some(&b'\n') {
            next += 1;
        }
        if next >= b.len() {
            break;
        }
        let line_end = view.line_end(next);
        let mut content = next;
        while content < line_end && matches!(b[content], b' ' | b'\t') {
            content += 1;
        }
        if content < line_end {
            if content - next <= key_indent {
                break;
            }
            end = line_end;
        }
        cursor = line_end;
    }
    end
}

fn shell_reference(value: &str) -> bool {
    let Some(mut name) = value.strip_prefix('$') else {
        return false;
    };
    let braced = name.starts_with('{');
    if braced {
        let Some(inner) = name.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
            return false;
        };
        name = inner;
    }
    let end = name
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(name.len());
    if end == 0 || opaque_material(&name[..end]) {
        return false;
    }
    if end == name.len() {
        return true;
    }
    braced
        && [":-", ":=", ":?", ":+", "-", "+", "?"].iter().any(|op| {
            name[end..].strip_prefix(op).is_some_and(|default| {
                !opaque_material(default)
                    && (reference(default)
                        || shell_reference(default)
                        || !default.is_empty()
                            && default
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b"_-/ .".contains(&b)))
            })
        })
}

// These are references to credential storage, not credential values.
pub(crate) fn credential_context(name: &str) -> bool {
    [
        "aws",
        "auth",
        "authentication",
        "credentials",
        "credential",
        "secrets",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}
pub(crate) fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn type_context(view: &View, key: usize) -> bool {
    // Fixed lookbehind budget: repeated fields cannot rescan a growing prefix.
    let mut start = key.saturating_sub(512);
    while !view.text.is_char_boundary(start) {
        start += 1;
    }
    let prefix = &view.text[start..key];
    if !["fn", "struct", "interface", "type"]
        .iter()
        .any(|word| prefix.contains(word))
    {
        return false;
    }
    static TYPE: OnceLock<Regex> = OnceLock::new();
    TYPE.get_or_init(|| Regex::new(r"(?s)(?:\bfn\s+[A-Za-z_][A-Za-z0-9_]*(?:<[^;{}()]*>)?\s*\([^);{}=]*|\b(?:struct|interface)\s+[A-Za-z_][A-Za-z0-9_]*[^;{}]*\{[^}]*|\btype\s+[A-Za-z_][A-Za-z0-9_]*[^;{}]*=\s*\{[^}]*)(?:$)").expect("fixed type-context regex"))
        .is_match(&view.text[start..key])
}
fn code_object_context(view: &View, key: usize) -> bool {
    let mut start = key.saturating_sub(512);
    while !view.text.is_char_boundary(start) {
        start += 1;
    }
    let prefix = &view.text[start..key];
    if !prefix.contains('=') && !prefix.contains("json!") {
        return false;
    }
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?s)(?:\b(?:(?:let|const|var)\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{|\bjson!\(\{)[^{}]*$")
            .expect("fixed object expression context")
    })
    .is_match(&view.text[start..key])
}

// A reference must reach its delimiter within this budget. Whitespace and
// comments are part of the value, not proof that a reference has ended.
fn candidate_end(view: &View, value: usize) -> Option<usize> {
    let b = view.text.as_bytes();
    let line = view.line_end(value).min(view.enclosing_end(value));
    let limit = line.min(value.saturating_add(512));
    let outer = matches!(b.get(value), Some(b'"' | b'\'' | b'`')).then_some(b[value]);
    let mut outer_end = outer.map(|_| view.quote_end(value));
    let mut i = value + usize::from(outer.is_some());
    let mut stack = Vec::new();
    while i < limit {
        let ch = b[i];
        if stack.is_empty() && outer == Some(ch) && outer_end == Some(i) {
            return Some(i + 1);
        }
        if outer.is_none() && stack.is_empty() && matches!(ch, b',' | b';' | b'}' | b']' | b')') {
            return Some(i);
        }
        if matches!(ch, b'"' | b'\'' | b'`') && (outer.is_none() || !stack.is_empty()) {
            let end = view.quote_end(i);
            if end >= limit {
                return None;
            }
            if outer_end == Some(i) {
                // An inner shell quote shares the outer quote's spelling.
                // Follow the same-spelling chain past its close; never accept
                // a different encoded quote as the outer value's delimiter.
                outer_end = Some(view.quote_end(end));
            }
            i = end + 1;
            continue;
        }
        match ch {
            b'(' => stack.push(b')'),
            b'{' => stack.push(b'}'),
            b'[' => stack.push(b']'),
            b'<' if i > value && b[i - 1].is_ascii_alphanumeric() => stack.push(b'>'),
            b'>' if stack.last() == Some(&b'>') => {
                stack.pop();
            }
            b')' | b'}' | b']' => {
                if stack.pop() != Some(ch) {
                    return None;
                }
            }
            _ => {}
        }
        i += 1;
    }
    (limit == line && stack.is_empty() && outer.is_none()).then_some(limit)
}

fn candidate(view: &View, value: usize) -> Option<&str> {
    candidate_end(view, value).map(|end| view.text[value..end].trim_end())
}

fn opaque_material(value: &str) -> bool {
    value
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .any(|atom| {
            atom.len() >= 16
                && atom.bytes().any(|b| b.is_ascii_uppercase())
                && (atom.bytes().any(|b| b.is_ascii_digit())
                    || atom.len() >= 24 && atom.bytes().any(|b| b.is_ascii_lowercase()))
        })
}

fn hexadecimal_code_literal(value: &str) -> bool {
    value
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|atom| {
            if atom.len() < 16 {
                return false;
            }
            let compact = atom.replace('_', "");
            let number = compact
                .strip_prefix("0x")
                .or_else(|| compact.strip_prefix("0X"))
                .or_else(|| compact.strip_prefix("0o"))
                .or_else(|| compact.strip_prefix("0b"))
                .unwrap_or(&compact);
            let number = [
                "u128", "u64", "u32", "u16", "u8", "usize", "i128", "i64", "i32", "i16", "i8",
                "isize",
            ]
            .iter()
            .find_map(|suffix| number.strip_suffix(suffix))
            .unwrap_or(number);
            number.len() >= 16 && number.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

fn safe_code_literals(value: &str) -> bool {
    // Opaque numeric/hex material remains data inside a source call, including
    // Rust radix prefixes, digit separators and integer type suffixes.
    if opaque_material(value) || hexadecimal_code_literal(value) {
        return false;
    }
    let b = value.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if matches!(b[i], b'"' | b'\'' | b'`') {
            let quote = b[i];
            let Some(close) = b[i + 1..].iter().position(|&ch| ch == quote) else {
                // Rust lifetimes in types are identifiers, not strings.
                return quote == b'\''
                    && value[i + 1..]
                        .bytes()
                        .all(|ch| ch.is_ascii_alphanumeric() || b"_ >&,".contains(&ch));
            };
            let literal = &value[i + 1..i + 1 + close];
            let header_lookup = value[..i].ends_with(".get(")
                && b.get(i + close + 2) == Some(&b')')
                && matches!(literal, "Authorization" | "authorization");
            if !(literal == "Bearer "
                || i > 0 && b[i - 1] == b'[' && sensitive(literal)
                || header_lookup)
            {
                return false;
            }
            i += close + 2;
        } else {
            i += 1;
        }
    }
    true
}

fn code_expression(value: &str) -> bool {
    if !safe_code_literals(value) {
        return false;
    }
    for op in ["??", "||"] {
        if let Some((left, right)) = value.split_once(op) {
            return code_expression(left.trim()) && code_expression(right.trim());
        }
    }
    if let Some(rest) = value.strip_prefix("async ") {
        if let Some((params, body)) = rest.split_once("=>") {
            return params
                .trim()
                .strip_prefix('(')
                .and_then(|p| p.strip_suffix(')'))
                .is_some_and(|p| {
                    p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_, ".contains(&b))
                })
                && code_expression(body.trim());
        }
    }
    if let Some(rest) = value.strip_prefix("function()") {
        return rest
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .and_then(|s| s.trim().strip_prefix("return "))
            .is_some_and(|s| code_expression(s.trim().trim_end_matches(';')));
    }
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"^(?:new[ \t]+)?(?:\.[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\?\.|\.|::)[A-Za-z_][A-Za-z0-9_]*|\?\.\([A-Za-z0-9_., \t]*\)|\([A-Za-z0-9_., \t"'\[\]]*\)\??|\[(?:[A-Za-z_][A-Za-z0-9_]*|"[A-Za-z_][A-Za-z0-9_]*"|'[A-Za-z_][A-Za-z0-9_]*')\])*)!?$"#).expect("complete code expression"))
        .is_match(value)
}

fn code_value(view: &View, key: usize, value: usize, colon: bool, declaration: bool) -> bool {
    let Some(rest) = candidate(view, value) else {
        return false;
    };
    if !safe_code_literals(rest) {
        return false;
    }
    if bounded_prefix(view, key).split_whitespace().last() == Some("type") {
        static TUPLE: OnceLock<Regex> = OnceLock::new();
        if TUPLE.get_or_init(|| Regex::new(r"^\((?:String|bool|u(?:8|16|32|64|128|size)|i(?:8|16|32|64|128|size))(?:[ \t]*,[ \t]*(?:String|bool|u(?:8|16|32|64|128|size)|i(?:8|16|32|64|128|size)))+[ \t]*,?\)$").expect("complete primitive tuple type")).is_match(rest) {
            return true;
        }
    }
    if (declaration || colon && (rest.contains('.') || rest.contains('(') || rest.starts_with('.')))
        && code_expression(rest)
    {
        return true;
    }
    if colon && rest.starts_with("match ") && rest.ends_with('}') && rest.contains("=>") {
        return rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_ \t{}(),=>:&|".contains(&b));
    }
    // Types must also be complete; a balanced generic cannot hide a tail.
    if colon {
        let mut depth = 0usize;
        let mut type_end = None;
        for (i, b) in rest.bytes().enumerate() {
            match b {
                b'<' => depth += 1,
                b'>' if depth > 0 => {
                    depth -= 1;
                    if depth == 0 {
                        type_end = Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        let generic = type_end == Some(rest.len())
            && depth == 0
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:<>()[], &'".contains(&b));
        let simple = ["string", "boolean", "number", "bool", "&str"].contains(&rest)
            || type_context(view, key) && code_expression(rest);
        return generic || simple;
    }
    false
}

// Preserve only a complete, single-field mapping whose URI password is already
// a mask. A real password, extra field, query, or appended tail fails closed.
pub(crate) fn masked_connection_mapping(value: &str) -> bool {
    if !value.starts_with('{') || value.len() > 512 || opaque_material(value) {
        return false;
    }
    static MASKED: OnceLock<Regex> = OnceLock::new();
    MASKED.get_or_init(|| Regex::new(r#"^\{[ \t]*"[A-Z_]+"[ \t]*:[ \t]*"(?:postgresql|postgres|mysql)://[a-z_]{1,32}:\*{3,}@[a-z][a-z0-9.-]*/[a-z_]{1,32}"[ \t]*\}$"#).expect("complete masked connection mapping")).is_match(value)
}

pub(crate) fn cloud_tag_values(key: &str, value: &str) -> bool {
    let atom =
        |s: &str| !s.is_empty() && s.len() <= 12 && s.bytes().all(|b| b.is_ascii_lowercase());
    key.split_once(':').is_some_and(|(a, b)| atom(a) && atom(b)) && atom(value)
}

fn cloud_tag_key(view: &View, key: usize, value: usize) -> bool {
    let prefix = bounded_prefix(view, key);
    if !prefix.ends_with("\"Tags\":[{\"") {
        return false;
    }
    // Inspect the complete pair within one bounded physical line.
    let mut end = view.line_end(value).min(value.saturating_add(256));
    while !view.text.is_char_boundary(end) {
        end -= 1;
    }
    let tail = &view.text[value..end];
    static TAG_PAIR: OnceLock<Regex> = OnceLock::new();
    TAG_PAIR
        .get_or_init(|| {
            Regex::new(r#"^"[a-z]{1,12}:[a-z]{1,12}","Value":"[a-z]{1,12}"\}\]\}(?:$|[;])"#)
                .expect("complete cloud tag pair")
        })
        .is_match(tail)
}

// These exclusions require syntax, never the English meaning of a value.
fn structural_value(
    view: &View,
    name: &str,
    key: usize,
    value: usize,
    quoted_key: bool,
    colon: bool,
) -> bool {
    let first = view.text.as_bytes()[value];
    // Most credential scalars cannot be any of these structural forms. Reject
    // them before bounded lookbehind, tokenization or regex work.
    if !(colon && numeric_identifier(name) && matches!(first, b'-' | b'0'..=b'9')
        || matches!(first, b'?' | b'$' | b':' | b'{')
        || view.text[key..].starts_with("Key=")
        || view.text[key..].starts_with("idempotency-token"))
    {
        return false;
    }
    let mut limit = view.line_end(value).min(value + 512);
    while !view.text.is_char_boundary(limit) {
        limit -= 1;
    }
    let line_rest = &view.text[value..limit];
    let rest = candidate(view, value).unwrap_or("");
    let prefix = bounded_prefix(view, key);
    if prefix.ends_with("--") && view.text[key..].starts_with("idempotency-token") {
        let atom = line_rest.split(" --").next().unwrap_or(line_rest).trim();
        if limit == view.line_end(value)
            && !atom.is_empty()
            && atom
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return true;
        }
    }
    let complete = !rest.is_empty();
    let atom = rest.trim();
    if complete
        && colon
        && numeric_identifier(name)
        && (quoted_key || prefix.trim_end().ends_with(['{', ',']))
        && serde_json::from_str::<serde_json::Number>(atom).is_ok()
    {
        return true;
    }
    static SQL: OnceLock<Regex> = OnceLock::new();
    if complete
        && SQL
            .get_or_init(|| {
                Regex::new(r"(?i)\b(?:SELECT|UPDATE|INSERT|DELETE)\b").expect("fixed SQL context")
            })
            .is_match(prefix)
    {
        static BIND: OnceLock<Regex> = OnceLock::new();
        let sql_end = view.enclosing_end(value).min(view.line_end(value));
        let sql_tail = &view.text[value..sql_end];
        static CONTINUED_BIND: OnceLock<Regex> = OnceLock::new();
        if CONTINUED_BIND.get_or_init(|| Regex::new(r"(?i)^(?:\?[0-9]*|\$[0-9]+|:[A-Za-z_][A-Za-z0-9_]*)(?:[ \t]+(?:AND|OR)[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*=[ \t]*(?:[0-9]+|\?[0-9]*|\$[0-9]+))+[ \t]*;?$").expect("complete SQL bind continuation")).is_match(sql_tail) {
            return true;
        }
        if BIND
            .get_or_init(|| {
                Regex::new(r"^(?:\?[0-9]*|\$[0-9]+|:[A-Za-z_][A-Za-z0-9_]*)$")
                    .expect("fixed SQL bind syntax")
            })
            .is_match(atom)
        {
            return true;
        }
    }
    // A resource-name mapping is a reference only when its single value is
    // an unquoted hyphenated identifier. Quoted scalars remain fail closed.
    static RESOURCE: OnceLock<Regex> = OnceLock::new();
    if colon
        && RESOURCE
            .get_or_init(|| {
                Regex::new(r"^\{[ \t]*name[ \t]*:[ \t]*[a-z][a-z0-9]*(?:-[a-z][a-z0-9]*)+[ \t]*\}$")
                    .expect("fixed resource mapping")
            })
            .is_match(rest)
    {
        return true;
    }
    static TAG: OnceLock<Regex> = OnceLock::new();
    let tag = line_rest
        .split(" Key=")
        .next()
        .unwrap_or(line_rest)
        .split(" --")
        .next()
        .unwrap_or(line_rest)
        .trim();
    if limit == view.line_end(value)
        && !opaque_material(tag)
        && prefix.contains("--tags ")
        && prefix.contains("aws ")
        && view.text[key..].starts_with("Key=")
        && TAG
            .get_or_init(|| {
                Regex::new(r"^[A-Za-z_][A-Za-z0-9_:.-]*,Value=[A-Za-z0-9_:./-]+$")
                    .expect("fixed cloud tag pair")
            })
            .is_match(tag)
    {
        return true;
    }
    false
}

fn expansion_reference(value: &str) -> bool {
    if value.len() > 512 || opaque_material(value) {
        return false;
    }
    if let Some(expression) = value.strip_prefix("${{").and_then(|s| s.strip_suffix("}}")) {
        return expression.trim().contains('.') && code_expression(expression.trim());
    }
    let Some(command) = value.strip_prefix("$(").and_then(|s| s.strip_suffix(')')) else {
        return false;
    };
    let command = command.trim();
    static RAND: OnceLock<Regex> = OnceLock::new();
    if RAND
        .get_or_init(|| {
            Regex::new(r"^openssl rand -(?:hex|base64) [0-9]{1,3}$")
                .expect("complete random generator command")
        })
        .is_match(command)
    {
        return true;
    }
    if let Some(file) = command.strip_prefix("cat ") {
        let file = file.trim();
        let file = file
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(file);
        return shell_reference(file);
    }
    !command.is_empty()
        && command.len() <= 64
        && command.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
}

fn environment_command(value: &str) -> bool {
    if opaque_material(value) {
        return false;
    }
    let mut words = value.split_whitespace();
    if !words.next().is_some_and(shell_reference) {
        return false;
    }
    let Some(command) = words.next() else {
        return false;
    };
    !command.is_empty()
        && command.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        && words.all(|arg| {
            shell_reference(arg)
                || arg.strip_prefix("--").is_some_and(|flag| {
                    !flag.is_empty() && flag.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
                })
        })
}

fn match_arm_body(value: &str) -> bool {
    let Some((name, rhs)) = value.split_once('=') else {
        return code_expression(value);
    };
    !name.trim().is_empty()
        && name
            .trim()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && code_expression(rhs.trim())
}

fn assignments(
    view: &View,
    inherited: bool,
    spans: &mut Vec<Range<usize>>,
    url_values: &[Range<usize>],
) {
    let b = view.text.as_bytes();
    let mut i = 0;
    let mut public_until = if inherited { b.len() } else { 0 };
    // Classifications depend only on the name, while credential/public scope is
    // resolved below. Repeated container fields should not rerun normalization,
    // suffix checks and allocations for every occurrence and every scope.
    let mut names = std::collections::HashMap::new();
    let mut scalar_references = std::collections::HashMap::new();
    let mut scalar_contexts = None;
    // End positions are resolved by View, so context is retained independently
    // of byte distance. Cumulative flags make every push/pop constant time.
    let mut contexts: Vec<(usize, bool, bool)> = Vec::new();
    while i < b.len() {
        let flag_start = i >= 2 && &b[i - 2..i] == b"--";
        if !b[i].is_ascii_alphabetic() || (i > 0 && word(b[i - 1]) && !flag_start) {
            i += 1;
            continue;
        }
        // URL credential values have protocol-specific boundaries. Do not let
        // a generic assignment inside one widen it over public parameters.
        let n = url_values.partition_point(|span| span.start <= i);
        if n > 0 && i < url_values[n - 1].end {
            i = url_values[n - 1].end;
            continue;
        }
        let start = i;
        while i < b.len() && word(b[i]) {
            i += 1;
        }
        // Reject impossible assignment syntax before name hashing and scope
        // classification. Keep every possible separator prefix (including
        // Unicode whitespace); following words still enter the normal scan.
        if !b.get(i).is_some_and(|ch| {
            ch.is_ascii_whitespace()
                || *ch >= 0x80
                || matches!(ch, b':' | b'=' | b'"' | b'\'' | b'`' | b'?' | b'-')
        }) {
            continue;
        }
        while contexts.last().is_some_and(|c| c.0 <= start) {
            contexts.pop();
        }
        let (scope_end, credential, public) =
            contexts
                .last()
                .copied()
                .unwrap_or((b.len(), false, inherited));
        let name = &view.text[start..i];
        let (secret_name, is_public, is_credential) = *names.entry(name).or_insert_with(|| {
            (
                sensitive(name),
                public_context(name),
                credential_context(name),
            )
        });
        let is_secret = secret_name || name.eq_ignore_ascii_case("key") && credential && !public;
        if !is_secret && !is_public && !is_credential {
            continue;
        }
        let mut sep = i;
        if b.get(sep) == Some(&b'?') && b.get(sep + 1) == Some(&b':') {
            sep += 1;
        }
        let quoted_key = matches!(b.get(sep), Some(b'"' | b'\'' | b'`'));
        // JSON / quoted dictionary key.
        if matches!(b.get(sep), Some(b'"' | b'\'' | b'`')) {
            sep += 1;
            if b.get(sep) == Some(&b']') {
                sep += 1;
            }
        }
        sep = skip_space(b, sep);
        let flag = start >= 2 && &b[start - 2..start] == b"--";
        let header = name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("cookie")
            || name.eq_ignore_ascii_case("set-cookie");
        let has_sep = matches!(b.get(sep), Some(b':' | b'='));
        // Parameter expansion operators belong to the variable reference.
        if start >= 2
            && &b[start - 2..start] == b"${"
            && b.get(sep) == Some(&b':')
            && b.get(sep + 1)
                .is_some_and(|b| matches!(b, b'-' | b'+' | b'?' | b'='))
        {
            continue;
        }
        // A comparison in an explicit expression is not an assignment. Outside
        // expression syntax a leading '=' may be part of a real env/flag value.
        let mut before = start;
        while before > 0 && b[before - 1].is_ascii_whitespace() {
            before -= 1;
        }
        let expression = before > 0 && matches!(b[before - 1], b'(' | b'&' | b'|' | b'!');
        if b.get(sep) == Some(&b'=')
            && b.get(sep + 1) == Some(&b'=')
            && !flag
            && start >= public_until
            && (name.bytes().any(|b| b.is_ascii_lowercase())
                || expression
                || sep > i
                || [b"return".as_slice(), b"assert".as_slice()]
                    .iter()
                    .any(|kw| {
                        before >= kw.len()
                            && &b[before - kw.len()..before] == *kw
                            && (before == kw.len() || !word(b[before - kw.len() - 1]))
                    }))
        {
            continue;
        }
        let arrow = b.get(sep..sep + 2) == Some(b"->");
        if b.get(sep..sep + 2) == Some(b"::") {
            continue;
        }
        if !(has_sep || arrow || flag && sep > i) {
            continue;
        }
        let mut after_sep = sep + if arrow { 2 } else { usize::from(has_sep) };
        if has_sep
            && ((b[sep] == b':' && b.get(after_sep) == Some(&b'='))
                || (quoted_key && b[sep] == b'=' && b.get(after_sep) == Some(&b'>')))
        {
            after_sep += 1;
        }
        let value = skip_space(b, after_sep);
        if value >= b.len() {
            continue;
        }
        if flag && (name.starts_with("no-") || matches!(b[value], b'|' | b'&' | b';')) {
            continue;
        }
        if ["([^ ]+)/g;", "([^ ]+)/g", "([^ ]+)/"]
            .contains(&view.text[value..view.line_end(value)].trim())
        {
            continue;
        }
        if matches!(b[value], b'"' | b'\'' | b'`') && view.enclosing_end(value) == value {
            continue;
        }
        let quoted = matches!(b[value], b'"' | b'\'' | b'`');
        // Match-arm code bodies are references; PHP/Ruby hash-rocket string
        // assignments in the same position must still redact.
        if quoted_key
            && b.get(sep..sep + 2) == Some(b"=>")
            && !quoted
            && candidate(view, value).is_some_and(match_arm_body)
        {
            continue;
        }

        // Qualified keys can select a non-scalar object or a numeric coverage
        // counter. A string credential in the same position still redacts.
        if quoted_key
            && start > 0
            && matches!(b[start - 1], b'/' | b'.' | b':')
            && (matches!(b[value], b'{' | b'[')
                || view.text[value..value_end(view, value, None)]
                    .parse::<u64>()
                    .is_ok())
        {
            continue;
        }

        // A plain scoped `key` scalar has no expression grammar to inspect.
        // Resolve it once instead of rerunning bounded code/reference scans
        // for every leaf of a large credential container. Leave YAML lines,
        // symbolic values and type declarations to their existing paths.
        if name == "key"
            && credential
            && !public
            && !quoted
            && !view.line_key(start)
            && !(quoted_key && start > 0 && view.line_key(start - 1))
        {
            let mut scalar_end = value;
            while b.get(scalar_end).is_some_and(|b| word(*b)) {
                scalar_end += 1;
            }
            if scalar_end > value
                && b.get(scalar_end).is_some_and(|b| matches!(b, b',' | b'}'))
                && view.literal(scalar_end)
            {
                let scalar = &view.text[value..scalar_end];
                let (types, toys, excerpts) = *scalar_contexts.get_or_insert_with(|| {
                    let lower = view.text.to_ascii_lowercase();
                    (
                        ["fn", "struct", "interface", "type"]
                            .iter()
                            .any(|s| lower.contains(s)),
                        [
                            "synthetic fixture:",
                            "toy example:",
                            "test fixture:",
                            "test_vector",
                            "synthetic_fixture",
                        ]
                        .iter()
                        .any(|s| lower.contains(s)),
                        lower.contains("excerpt"),
                    )
                });
                let reference = *scalar_references
                    .entry(scalar)
                    .or_insert_with(|| field_reference(name, scalar));
                if !(reference
                    || types && type_context(view, start)
                    || toys && labeled_toy(view, start, scalar)
                    || excerpts && excerpt_value(view, start, scalar)
                    || non_assignment_wrapper(view, start))
                {
                    spans.push(value..scalar_end);
                    i = scalar_end;
                    continue;
                }
            }
        }

        if b[value] == b'{' && masked_connection_mapping(candidate(view, value).unwrap_or("")) {
            continue;
        }
        if !quoted
            && structural_value(
                view,
                name,
                start,
                value,
                quoted_key,
                b.get(sep) == Some(&b':'),
            )
        {
            continue;
        }
        let line_start = view.line_start(value);
        let crossed_line = line_start > after_sep;
        let yaml = b.get(sep) == Some(&b':')
            && (view.line_key(start) || quoted_key && start > 0 && view.line_key(start - 1));
        let key_indent = start - view.line_start(start);
        let yaml_indented = yaml
            && crossed_line
            && value - line_start > key_indent
            && b[line_start..value]
                .iter()
                .all(|c| matches!(c, b' ' | b'\t'));
        let block_mapping = yaml_indented
            && b[after_sep..view.line_end(after_sep)]
                .iter()
                .all(u8::is_ascii_whitespace);
        if (is_credential || is_public) && (matches!(b[value], b'{' | b'[') || block_mapping) {
            let end = if block_mapping {
                view.indentation_end(start)
            } else {
                view.container_end(value)
            };
            contexts.push((
                end.min(scope_end).min(view.enclosing_end(value)),
                !is_public && (credential || is_credential),
                !is_credential && (public || is_public),
            ));
            // Authentication config objects expose scheme/audience/enabled;
            // keep scanning their explicit credential fields and scoped keys.
            if !is_secret
                || is_public
                || (matches!(
                    name.to_ascii_lowercase().as_str(),
                    "auth" | "authentication"
                ) && (b[value] == b'{' || block_mapping))
            {
                continue;
            }
        }
        if !is_secret && !is_public {
            continue;
        }
        // Empty env/header assignments end at their physical line. Continue
        // across it only for explicit literals, quoted JSON keys, inherited
        // public values or an indented YAML value; never consume the next env key.
        let declaration = bounded_prefix(view, start).trim_end().ends_with("=>")
            || [b"let".as_slice(), b"var".as_slice(), b"const".as_slice()]
                .iter()
                .any(|kw| {
                    before >= kw.len()
                        && &b[before - kw.len()..before] == *kw
                        && (before == kw.len() || !word(b[before - kw.len() - 1]))
                });
        let code = declaration || (before > 0 && b[before - 1] == b'.') || sep > i;
        if quoted && numeric_identifier(name) && code_object_context(view, start) {
            let close = view.quote_end(value);
            let tail = skip_space(b, close.saturating_add(1));
            if tail < view.line_end(value) && !matches!(b[tail], b',' | b'}' | b']' | b')' | b';') {
                let end = candidate_end(view, close + 1).unwrap_or_else(|| view.line_end(value));
                spans.push(value..end);
                i = end;
                continue;
            }
        }
        if quoted
            && numeric_identifier(name)
            && code_object_context(view, start)
            && candidate(view, value).is_some_and(|whole| {
                let body = &whole[1..whole.len() - 1];
                body.len() <= 32
                    && body.contains('_')
                    && !hexadecimal_code_literal(body)
                    && body.split('_').all(|part| {
                        !part.is_empty()
                            && part.len() <= 12
                            && part.bytes().all(|b| b.is_ascii_lowercase())
                    })
            })
        {
            continue;
        }
        if !quoted
            && start >= public_until
            && (declaration
                || bounded_prefix(view, start).split_whitespace().last() == Some("type")
                || b.get(sep) == Some(&b':')
                || before > 0 && matches!(b[before - 1], b'{' | b',' | b'(')
                || b.get(sep) == Some(&b':') && (quoted_key || type_context(view, start)))
            && code_value(
                view,
                start,
                value,
                b.get(sep) == Some(&b':'),
                declaration
                    || (b.get(sep) == Some(&b':')
                        && !name.eq_ignore_ascii_case("key")
                        && code_object_context(view, start)),
            )
        {
            continue;
        }
        let explicit_literal = quoted
            || quoted_key
            || yaml_indented
            || start < public_until
            || (code && matches!(b[value], b'0'..=b'9' | b'-' | b'{' | b'['));
        if crossed_line && !explicit_literal {
            continue;
        }
        let context = (start < public_until && !credential).then_some(public_until);
        if is_public {
            public_until = if quoted {
                view.quote_end(value)
            } else {
                view.enclosing_end(value).min(line_end(view, value))
            }
            .min(context.unwrap_or(b.len()));
            continue;
        }
        let n = url_values.partition_point(|span| span.start <= value);
        if n > 0 && value < url_values[n - 1].end {
            i = url_values[n - 1].end;
            continue;
        }
        let mut end = if header && !quoted {
            line_end(view, value).min(view.enclosing_end(value))
        } else {
            value_end(view, value, context)
        };
        let content = value + usize::from(quoted);
        let raw = &view.text[content..end];
        if name == "Key" && bounded_prefix(view, start).contains("--tags ") {
            let tail = &view.text[value..view.line_end(value)];
            if opaque_material(tail) {
                end = view.line_end(value);
                spans.push(content..end);
                i = end;
                continue;
            }
        }
        // Quoted JSON keys retain valid JSON when a numeric credential is
        // replaced. Identifier numbers have their own narrow exemption above.
        if quoted_key
            && b.get(sep) == Some(&b':')
            && !quoted
            && serde_json::from_str::<serde_json::Number>(raw).is_ok()
        {
            // Include the numeric scalar in a quoted marker, preserving the
            // public text API's source spelling around it.
            spans.push(content..end);
            i = end;
            continue;
        }
        let complete_end = candidate_end(view, value);
        let full = complete_end.map(|end| {
            let start = value + usize::from(quoted);
            let end = end - usize::from(quoted);
            &view.text[start..end]
        });
        if full.is_some_and(expansion_reference) {
            continue;
        }
        if !quoted && full.is_some_and(environment_command) {
            continue;
        }
        if !quoted && raw.starts_with(REDACTION_TOKEN) && full.is_some_and(marker_reference) {
            continue;
        }
        if full.is_some_and(|whole| {
            field_reference(name, whole)
                || header && authorization_reference(whole)
                || quoted && b[value] == b'`' && template_reference(whole)
        }) || full.is_some_and(|whole| {
            regex_value(view, start, whole)
                || labeled_toy(view, start, whole)
                || excerpt_value(view, start, whole)
        }) || non_assignment_wrapper(view, start)
            && bounded_prefix(view, start).split_whitespace().last() != Some("type")
            && full.is_some_and(|s| !opaque_material(s) || s.starts_with("Bearer "))
        {
            continue;
        }
        if name == "Key" && !credential && cloud_tag_key(view, start, value) {
            continue;
        }
        // Failed structural candidates redact through their complete delimiter,
        // including opaque tails and literals inside calls/substitutions.
        let failed_reference = raw.starts_with('$')
            || !quoted
                && (declaration
                    || bounded_prefix(view, start).split_whitespace().last() == Some("type")
                    || matches!(b[value], b'$' | b'{' | b'[' | b'<' | b'*')
                    || raw.contains(['(', '.']));
        if full.is_some_and(opaque_material) || failed_reference {
            let limit = complete_end.map_or_else(
                || view.line_end(value).min(view.enclosing_end(value)),
                |end| end - usize::from(quoted),
            );
            end = end.max(limit);
        }
        // YAML literal/folded scalar: remove all following indented lines.
        if !quoted
            && yaml
            && (!matches!(b[value], b'{' | b'[') || view.text[value..].starts_with(REDACTION_TOKEN))
        {
            end = indented_end(view, value, key_indent)
                .min(context.unwrap_or(b.len()))
                .min(view.enclosing_end(value).min(b.len()));
        }
        if end > content {
            if reference(&view.text[content..end]) || shell_reference(&view.text[content..end]) {
                i = end;
                continue;
            }
            spans.push(content..end);
            i = end;
        }
    }
}

fn marker_reference(value: &str) -> bool {
    value.strip_prefix(REDACTION_TOKEN).is_some_and(|rest| {
        rest.is_empty()
            || rest.starts_with(char::is_whitespace)
                && rest.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_whitespace() || b"().,;-/".contains(&b)
                })
    })
}

// Only syntax before a key can establish a non-assignment wrapper. Never
// inspect the English credential value to decide whether it is documentary.
fn non_assignment_wrapper(view: &View, position: usize) -> bool {
    let prefix = bounded_prefix(view, position).trim();
    if prefix.starts_with('#') || prefix.starts_with("//") {
        return true;
    }
    let prefix = prefix.trim_end_matches(['"', '\'', '`']).trim_end();
    let sentence = prefix.trim_end_matches(':');
    sentence
        .bytes()
        .all(|b| b.is_ascii_alphabetic() || b.is_ascii_whitespace())
        && sentence.split_whitespace().take(2).count() == 2
}

fn regex_value(view: &View, position: usize, value: &str) -> bool {
    let prefix = bounded_prefix(view, position);
    let value = if prefix.contains("= /") {
        value
            .strip_suffix("/g")
            .or_else(|| value.strip_suffix('/'))
            .unwrap_or(value)
    } else {
        value
    };
    if prefix.contains("sed ") && prefix.ends_with("/^") && value == "/" {
        return true;
    }
    (prefix.contains("sed ") && prefix.ends_with("/^")
        || prefix.contains("rg ")
        || prefix.contains("grep ")
        || prefix.contains("= /"))
        && ["\\s", "\\s+", "\\s*", ".*", "[A-Z]", "[A-Z]+", "[A-Z]*"].contains(&value)
}

fn bounded_prefix(view: &View, position: usize) -> &str {
    let mut start = view.line_start(position).max(position.saturating_sub(512));
    while !view.text.is_char_boundary(start) {
        start += 1;
    }
    &view.text[start..position]
}

fn labeled_toy(view: &View, position: usize, value: &str) -> bool {
    let prefix = bounded_prefix(view, position);
    let lower = prefix.to_ascii_lowercase();
    let labeled = [
        "synthetic fixture:",
        "toy example:",
        "test fixture:",
        "test_vector",
        "synthetic_fixture",
    ]
    .iter()
    .any(|label| lower.contains(label));
    labeled
        && value.len() <= 64
        && ["toy", "fixture", "test"]
            .iter()
            .any(|p| value.to_ascii_lowercase().starts_with(p))
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn excerpt_value(view: &View, position: usize, value: &str) -> bool {
    let prefix = bounded_prefix(view, position);
    prefix.to_ascii_lowercase().contains("excerpt")
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_whitespace())
}

fn session_identifier(value: &str) -> bool {
    uuid(value)
        || (!value.is_empty()
            && value.len() <= 32
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && value.bytes().any(|b| b.is_ascii_lowercase()))
        || ["exec-", "call_", "toolu_"].iter().any(|p| {
            value.strip_prefix(p).is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 48
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        })
}

fn environment_reference(value: &str) -> bool {
    !opaque_material(value)
        && value.strip_prefix("process.env.").is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

fn template_reference(value: &str) -> bool {
    let Some((prefix, rest)) = value.split_once("${") else {
        return false;
    };
    if !(prefix.is_empty() || prefix == "Bearer ") {
        return false;
    }
    rest.strip_suffix('}').is_some_and(code_expression)
}

fn authorization_reference(value: &str) -> bool {
    let value = value.trim();
    let end = value.find(char::is_whitespace).unwrap_or(value.len());
    if !["bearer", "basic"].contains(&value[..end].to_ascii_lowercase().as_str()) {
        return false;
    }
    let rest = value[end..].trim();
    let rest = rest.trim_end_matches(['"', '\'', '`']);
    rest.is_empty()
        || marker_reference(rest)
        || reference(rest)
        || shell_reference(rest)
        || environment_reference(rest)
}

fn credential_prose(view: &View, spans: &mut Vec<Range<usize>>) {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| {
        Regex::new(r"(?i)\bAPI[ \t]+key[ \t]+([A-Za-z0-9_+/=-]{24,})")
            .expect("fixed credential prose regex")
    });
    for c in r.captures_iter(&view.text) {
        spans.push(c.get(1).expect("credential capture").range());
    }
}

fn comment_variable(value: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^(?:[a-z]+(?:[A-Z][a-z]+)*Variable|[a-z]+(?:_[a-z]+)*_variable)$")
            .expect("fixed variable identifier syntax")
    })
    .is_match(value)
}

fn bearer_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\bBearer[ \t]+([A-Za-z0-9._~+/=-]{8,})").expect("fixed bearer regex")
    })
}

fn url_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"[A-Za-z][A-Za-z0-9+.-]{0,31}://").expect("fixed URL scheme regex")
    })
}

fn compact_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9_.-]{12,}").expect("fixed compact-token regex"))
}

fn jwts(view: &View, spans: &mut Vec<Range<usize>>) {
    // Repeated public hostnames often share a non-JWT first segment. Cache
    // only its header classification; token spans remain specific to each run.
    let mut previous_header = "";
    let mut previous_count = None;
    let mut previous_non_jwt = "";
    for run in compact_regex().find_iter(&view.text) {
        // A complete run's JWT result is context independent. Reuse a single
        // previously checked negative run without allocating its segments again.
        if run.as_str() == previous_non_jwt {
            continue;
        }
        let before = spans.len();
        let segments: Vec<_> = run.as_str().split('.').collect();
        let mut offset = run.start();
        let mut i = 0;
        while i + 2 < segments.len() {
            if segments[i] != previous_header {
                previous_header = segments[i];
                previous_count = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(segments[i])
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .filter(|header| header.get("alg").is_some_and(serde_json::Value::is_string))
                    .map(|header| if header.get("enc").is_some() { 5 } else { 3 });
            }
            if let Some(count) = previous_count {
                if i + count <= segments.len() && (count == 5 || !segments[i + 1].is_empty()) {
                    let length = segments[i..i + count]
                        .iter()
                        .map(|s| s.len())
                        .sum::<usize>()
                        + count
                        - 1;
                    spans.push(offset..offset + length);
                    offset += length + 1;
                    i += count;
                    continue;
                }
            }
            offset += segments[i].len() + 1;
            i += 1;
        }
        if spans.len() == before {
            previous_non_jwt = run.as_str();
        }
    }
}

pub(crate) fn reference(value: &str) -> bool {
    if opaque_material(value) {
        return false;
    }
    // Explicit symbolic placeholders are normal configuration/documentation.
    // Embedded assignments/providers are still scanned independently.
    let placeholder = value.trim();
    static SYMBOLIC: OnceLock<Regex> = OnceLock::new();
    let symbolic = SYMBOLIC.get_or_init(|| Regex::new(r"(?i)^(?:(?:example|dummy|fake|sample|test|placeholder|your)(?:[-_][A-Za-z][A-Za-z0-9_-]{0,63})?|replace[-_]me|change[-_]?me)$").expect("fixed symbolic placeholder syntax"));
    if symbolic.is_match(placeholder)
        || placeholder == "masked_..."
        || placeholder == "hidden_..."
        || placeholder.len() >= 3 && placeholder.bytes().all(|b| b == b'*')
        || placeholder
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        || [
            "xxx",
            "XXX",
            "redacted",
            "REDACTED",
            "example",
            "demo",
            "placeholder",
            "YOUR_SECRET_HERE",
            "false",
            "true",
            "null",
            "undefined",
            "None",
            "none",
        ]
        .contains(&placeholder)
        || placeholder.strip_prefix("YOUR_").is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        })
        || placeholder
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 128
                    && s.starts_with(|c: char| c.is_ascii_alphabetic())
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' '))
            })
    {
        return true;
    }
    let Some(path) = value.strip_prefix("op://") else {
        return false;
    };
    let parts: Vec<_> = path.split('/').collect();
    (3..=4).contains(&parts.len())
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.trim() == *p
                && !p.contains("  ")
                && p.chars()
                    .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'))
        })
}

pub(crate) fn field_reference(name: &str, value: &str) -> bool {
    reference(value)
        || value.strip_suffix(" # placeholder").is_some_and(reference)
        || marker_reference(value)
        || shell_reference(value)
        || environment_reference(value)
        || name
            .replace(['_', '-'], "")
            .eq_ignore_ascii_case("sessionid")
            && session_identifier(value)
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "authorization" | "proxy-authorization"
        ) && authorization_reference(value)
}

fn documentation_url(password: &str, host: &str) -> bool {
    if shell_reference(password)
        || reference(password)
        || matches!(password, "%s" | "%d" | "{}" | "{password}" | "{PASSWORD}")
    {
        return true;
    }
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    let reserved = host == "localhost"
        || host == "example.com"
        || host == "example.org"
        || host == "example.net"
        || host.ends_with(".example.com")
        || host.ends_with(".example.org")
        || host.ends_with(".example.net")
        || host.ends_with(".test")
        || host.ends_with(".invalid")
        || host.ends_with(".example");
    reserved && (matches!(password, "password" | "example" | "placeholder") || reference(password))
}

fn url_regex_source(view: &View, start: usize, authority: usize) -> bool {
    let prefix = bounded_prefix(view, start);
    (prefix.ends_with("re.search(r\"") || prefix.ends_with("re.compile(r\""))
        && view.text[authority..].starts_with("[^:]+:([^@]+)@\"")
}

fn provider_symbol(view: &View, value: &str, start: usize, end: usize) -> bool {
    if !(value.starts_with("capy_") || value.starts_with("crsr_")) {
        return false;
    }
    let body = &value[5..];
    // Lowercase snake identifiers are references only in explicit source
    // positions. The same bytes in a scalar/string still use provider rules.
    if !body.contains('_')
        || !body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return false;
    }
    let prefix = bounded_prefix(view, start).trim_end();
    // URL labels and dotted hostnames are not source member declarations.
    // Known provider matches must retain their detector semantics there.
    if prefix.contains("://") {
        return false;
    }
    ["fn", "function", "let", "const", "var", "use", "import"]
        .iter()
        .any(|kw| {
            prefix.strip_suffix(kw).is_some_and(|before| {
                before.is_empty()
                    || before.ends_with(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            })
        })
        || prefix.ends_with("::")
        || view.text[end..].starts_with('(')
}

fn plain_query_key_sensitive(key: &str) -> bool {
    sensitive(key)
        || matches!(
            key.to_ascii_lowercase().as_str(),
            "x-amz-signature"
                | "x-amz-credential"
                | "x-amz-security-token"
                | "x-goog-signature"
                | "x-goog-credential"
                | "signature"
                | "sig"
                | "assertion"
                | "code_verifier"
        )
}

// Decode only the ASCII entity alphabet needed for query keys and nested
// separators. This is a recognition view; output always uses original ranges.
// Numeric accumulation saturates, so arbitrary leading zeros cannot overflow.
fn query_entity_tail(b: &[u8], start: usize, separator: bool) -> Option<(u8, usize)> {
    if b.get(start) != Some(&b'#') {
        for (name, ch) in [
            ("amp", b'&'),
            ("percnt", b'%'),
            ("lowbar", b'_'),
            ("UnderBar", b'_'),
            ("hyphen", b'-'),
            ("dash", b'-'),
            ("period", b'.'),
        ] {
            let end = start + name.len();
            if b.get(start..end)
                .is_some_and(|s| s.eq_ignore_ascii_case(name.as_bytes()))
                && (ch == b'&' || b.get(end) == Some(&b';'))
            {
                return Some((ch, end + usize::from(b.get(end) == Some(&b';'))));
            }
        }
        return None;
    }
    let mut p = start + 1;
    let hexadecimal = b.get(p).is_some_and(|c| c.eq_ignore_ascii_case(&b'x'));
    if hexadecimal {
        p += 1;
    }
    // Fail closed for ambiguous semicolonless hex followed by a key starting
    // with a-f, too: a superset of the HTML tokenizer's ampersand spellings.
    if separator {
        while b.get(p) == Some(&b'0') {
            p += 1;
        }
        let digits = if hexadecimal { b"26" } else { b"38" };
        if b.get(p..p + 2) == Some(digits) {
            p += 2;
            return Some((b'&', p + usize::from(b.get(p) == Some(&b';'))));
        }
    }
    let first = p;
    let mut value = 0u32;
    while let Some(digit) = b
        .get(p)
        .and_then(|ch| char::from(*ch).to_digit(if hexadecimal { 16 } else { 10 }))
    {
        value = value
            .saturating_mul(if hexadecimal { 16 } else { 10 })
            .saturating_add(digit);
        p += 1;
    }
    (p > first && value < 128).then_some((value as u8, p + usize::from(b.get(p) == Some(&b';'))))
}

// A chain consumes source bytes monotonically, even for thousands of nested
// amp; or percent layers. Percent escapes normally arrive decoded by View;
// decoding here also handles a percent sign produced by an HTML entity.
fn query_character(b: &[u8], start: usize, separator: bool) -> (u8, usize) {
    let mut ch = b[start];
    let mut end = start + 1;
    loop {
        let next = match ch {
            b'&' => query_entity_tail(b, end, separator),
            b'%' => b.get(end..end + 2).and_then(|pair| {
                let hi = char::from(pair[0]).to_digit(16)?;
                let lo = char::from(pair[1]).to_digit(16)?;
                Some(((hi * 16 + lo) as u8, end + 2))
            }),
            _ => None,
        };
        match next {
            Some((value, p)) => {
                ch = value;
                end = p;
            }
            None => return (ch, end),
        }
    }
}

fn query_key_character(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'-' | b'.')
}

fn query_key_end(b: &[u8], mut end: usize) -> usize {
    while end < b.len() {
        let (ch, next) = query_character(b, end, false);
        if !query_key_character(ch) {
            break;
        }
        end = next;
    }
    end
}

fn query_key_sensitive(key: &str) -> bool {
    if !key.contains('&') {
        return plain_query_key_sensitive(key);
    }
    let b = key.as_bytes();
    let mut decoded = String::with_capacity(key.len());
    let mut cursor = 0;
    while cursor < b.len() {
        let (ch, next) = query_character(b, cursor, false);
        if !query_key_character(ch) {
            return false;
        }
        decoded.push(char::from(ch));
        cursor = next;
    }
    plain_query_key_sensitive(&decoded)
}

fn html_query_separator(b: &[u8], start: usize) -> usize {
    match b[start] {
        b';' => 1,
        b'&' => {
            let (ch, end) = query_character(b, start, true);
            if ch == b'&' {
                end - start
            } else {
                0
            }
        }
        _ => 0,
    }
}

// Skip an entire entity when it is data rather than a separator. Otherwise
// each semicolon inside an encoded key could repeat the full key lookahead.
fn query_next(b: &[u8], start: usize) -> usize {
    if b[start] == b'&' {
        query_character(b, start, false).1
    } else {
        start + 1
    }
}

// An encoded ampersand inside an ordinary value is data unless it actually
// introduces key=value. Decode the lookahead key too, including sensitive
// names. A literal '&' retains ordinary URL semantics. No output is re-encoded.
fn query_separator(view: &View, start: usize) -> usize {
    let b = view.text.as_bytes();
    let width = html_query_separator(b, start);
    if width == 0 || width == 1 && b[start] == b'&' && view.literal(start) {
        return width;
    }
    let key = start + width;
    let end = query_key_end(b, key);
    if end > key && b.get(end) == Some(&b'=') {
        width
    } else {
        0
    }
}

// A malformed earlier value cannot terminate parameter discovery. Query
// separators remain visible beyond quotes, fragments, markup or line breaks.
// Run once over the remaining suffix, including nested schemes: another URL
// in a malformed value cannot hide a later parameter or trigger rescanning.
// Value boundaries stay local: recovery must not eat trailing prose or records.
fn recover_query_parameters(view: &View, start: usize, end: usize, spans: &mut Vec<Range<usize>>) {
    let b = view.text.as_bytes();
    let mut cursor = start;
    while cursor < end {
        let separator = if b[cursor] == b'?' {
            1
        } else {
            query_separator(view, cursor)
        };
        if separator == 0 {
            cursor = query_next(b, cursor);
            continue;
        }
        let key_start = cursor + separator;
        cursor = key_start;
        cursor = query_key_end(b, cursor).min(end);
        if b.get(cursor) != Some(&b'=') || !query_key_sensitive(&view.text[key_start..cursor]) {
            continue;
        }
        let value_start = cursor + 1;
        let mut parameter_end = value_start;
        while parameter_end < end && query_separator(view, parameter_end) == 0 {
            parameter_end = query_next(b, parameter_end);
        }
        let mut value_end = value_start;
        while value_end < parameter_end {
            if matches!(b[value_end], b'"' | b'\'' | b'`') {
                let close = view.quote_end(value_end);
                // An unmatched quote in the credential itself fails closed to
                // this parameter's end, never through the next literal '&'.
                value_end = if close < parameter_end {
                    close + 1
                } else {
                    parameter_end
                };
                continue;
            }
            if view.literal(value_end)
                && (b[value_end].is_ascii_whitespace() || matches!(b[value_end], b'<' | b'>'))
            {
                break;
            }
            value_end += 1;
        }
        if value_end > value_start {
            spans.push(value_start..value_end);
        }
        cursor = parameter_end;
    }
}

fn urls(view: &View, spans: &mut Vec<Range<usize>>) {
    let b = view.text.as_bytes();
    // Inspect nested actual URL schemes too. Authority scans stop at the next
    // literal slash, so their total work is bounded by adjacent scheme starts.
    for scheme in url_regex().find_iter(&view.text) {
        if url_regex_source(view, scheme.start(), scheme.end()) {
            continue;
        }
        let encoded_scheme = !view.literal(scheme.end() - 1);
        let boundary = |p| encoded_scheme || view.literal(p);
        let authority = scheme.end();
        let mut end = authority;
        while end < b.len()
            && !(boundary(end)
                && (b[end].is_ascii_whitespace()
                    || matches!(b[end], b'/' | b'?' | b'#' | b'"' | b'\'' | b'`')))
        {
            end += 1;
        }
        if let Some(at) = (authority..end)
            .rev()
            .find(|&i| b[i] == b'@' && boundary(i))
        {
            if let Some(colon) = (authority..at).find(|&i| b[i] == b':' && boundary(i)) {
                if colon + 1 < at
                    && !documentation_url(&view.text[colon + 1..at], &view.text[at + 1..end])
                {
                    spans.push(colon + 1..at);
                }
            }
            // A URL username without a password is public userinfo.
        }
    }
    let mut cursor = 0;
    let mut recovery_start = b.len();
    while let Some(scheme) = url_regex().find_at(&view.text, cursor) {
        if url_regex_source(view, scheme.start(), scheme.end()) {
            cursor = scheme.end();
            continue;
        }
        let mut end = scheme.end();
        let mut query_value = false;
        let mut in_query = false;
        let line = view.line_end(end);
        while end < line {
            if b[end] == b'?' {
                in_query = true;
            }
            if in_query && b[end] == b'=' {
                query_value = true;
            } else if query_separator(view, end) > 0 {
                query_value = false;
            }
            if query_value && matches!(b[end], b'"' | b'\'' | b'`') {
                let close = view.quote_end(end);
                if close < line {
                    let mut continuation = close + 1;
                    while continuation < line
                        && !matches!(b[continuation], b'&' | b'"' | b'\'' | b'`' | b'<' | b'>')
                        && space_width(b, continuation) == 0
                    {
                        continuation += 1;
                    }
                    if b.get(continuation) == Some(&b'&')
                        || b.get(end.wrapping_sub(1)) == Some(&b'=')
                    {
                        end = close + 1;
                        continue;
                    }
                }
            }
            if view.literal(end)
                && (b[end].is_ascii_whitespace()
                    || matches!(b[end], b'<' | b'>' | b'"' | b'\'' | b'`'))
            {
                break;
            }
            end = query_next(b, end);
        }
        cursor = end;
        let authority = scheme.end();
        let mut authority_end = authority;
        while authority_end < end && !matches!(b[authority_end], b'/' | b'?' | b'#') {
            authority_end += 1;
        }
        if let Some(at) = (authority..authority_end)
            .rev()
            .find(|&i| b[i] == b'@' && view.literal(i))
        {
            if let Some(colon) = (authority..at).find(|&i| b[i] == b':' && view.literal(i)) {
                if colon + 1 < at
                    && !documentation_url(
                        &view.text[colon + 1..at],
                        &view.text[at + 1..authority_end],
                    )
                {
                    spans.push(colon + 1..at);
                }
            }
            // A URL username without a password is public userinfo.
        }
        if let Some(query) = (authority_end..end).find(|&i| b[i] == b'?') {
            recovery_start = recovery_start.min(end);
            let mut start = query + 1;
            while start < end {
                let mut eq = start;
                while eq < end && b[eq] != b'=' && b[eq] != b'?' {
                    let (ch, next) = query_character(b, eq, false);
                    if query_key_character(ch) {
                        eq = next;
                    } else if query_separator(view, eq) > 0 {
                        break;
                    } else {
                        eq += 1;
                    }
                }
                if eq == end {
                    break;
                }
                if b[eq] != b'=' {
                    start = eq
                        + if b[eq] == b'?' {
                            1
                        } else {
                            query_separator(view, eq)
                        };
                    continue;
                }
                let sensitive = query_key_sensitive(&view.text[start..eq]);
                let mut parameter_end = eq + 1;
                while parameter_end < end
                    && query_separator(view, parameter_end) == 0
                    && (sensitive || b[parameter_end] != b'?')
                {
                    parameter_end = query_next(b, parameter_end);
                }
                if sensitive && eq + 1 < parameter_end {
                    spans.push(eq + 1..parameter_end);
                }
                // Public redirect values may contain another encoded query.
                // Each prefix/value is traversed once, including nested URLs.
                start = parameter_end
                    + if parameter_end < end && b[parameter_end] != b'?' {
                        query_separator(view, parameter_end)
                    } else {
                        1
                    };
            }
        }
    }
    recover_query_parameters(view, recovery_start, b.len(), spans);
}

// Scan each disjoint HTML attribute value once. A separate recognition view
// decodes all URL punctuation together, then maps only the selected credential
// ranges back through the ordinary view. Surrounding HTML is never re-encoded.
fn html_attribute_urls(view: &View, spans: &mut Vec<Range<usize>>) {
    let b = view.text.as_bytes();
    let mut cursor = 0;
    let mut in_tag = false;
    // Repeated adjacent attribute values share relative matches. Keep only
    // one borrowed spelling and its ranges, with no unbounded cache growth.
    let mut previous = "";
    let mut matches = Vec::new();
    while cursor < b.len() {
        match b[cursor] {
            b'<' if b
                .get(cursor + 1)
                .is_some_and(|ch| ch.is_ascii_alphabetic() || *ch == b'/') =>
            {
                in_tag = true
            }
            b'>' => in_tag = false,
            b'=' if in_tag => {
                cursor = skip_space(b, cursor + 1);
                if cursor >= b.len() {
                    break;
                }
                let quoted = matches!(b[cursor], b'"' | b'\'' | b'`');
                let start = cursor + usize::from(quoted);
                let end = if quoted {
                    view.quote_end(cursor)
                } else {
                    let mut end = cursor;
                    while end < b.len() && !b[end].is_ascii_whitespace() && b[end] != b'>' {
                        end += 1;
                    }
                    end
                };
                let value = &view.text[start..end];
                if value.contains('&') {
                    if value != previous {
                        let html = View::html_url(value);
                        let mut local = Vec::new();
                        urls(&html, &mut local);
                        matches = local
                            .into_iter()
                            .map(|r| html.source_start(r.start)..html.source_end(r.end - 1))
                            .collect::<Vec<_>>();
                        previous = value;
                    }
                    spans.extend(matches.iter().map(|r| start + r.start..start + r.end));
                }
                cursor = end + usize::from(quoted && end < b.len());
                continue;
            }
            _ => {}
        }
        cursor += 1;
    }
}

fn pii_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?-u:\b)[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}(?-u:\b)|(?-u:\b)[0-9]{3}-[0-9]{2}-[0-9]{4}(?-u:\b)").expect("fixed PII regex"))
}

pub(crate) fn scrub(input: &str, inherited: bool, policy: Policy) -> String {
    analyze(input, inherited, policy).text
}

// Removing malformed delimiters can change lexical scopes. Close over those
// changes with a fixed pass budget, retaining ranges in ORIGINAL input bytes.
// Exhaustion fails closed; no unbounded fixed-point loop is permitted.
pub(crate) fn analyze(input: &str, inherited: bool, policy: Policy) -> crate::ScrubReport {
    let mut report = analyze_once(input, inherited, policy);
    // With no replacement, the next pass sees exactly the same bytes and
    // deterministic scope. Repeating it cannot discover a new span.
    if report.redactions.is_empty() {
        return report;
    }
    for _ in 0..4 {
        let next = analyze_once(&report.text, inherited, policy);
        if next.text == report.text {
            return report;
        }
        let mut delta = 0isize;
        let replacements: Vec<_> = report
            .redactions
            .iter()
            .map(|r| {
                let start = r
                    .start
                    .checked_add_signed(delta)
                    .expect("mapped output offset");
                let length = replacement(input, r).len();
                let end = start + length;
                delta += length as isize - r.len() as isize;
                (start, end, r.start, r.end)
            })
            .collect();
        let original = |position: usize, is_end: bool| {
            let n = replacements.partition_point(|r| r.0 <= position);
            if n == 0 {
                return position;
            }
            let &(start, end, source_start, source_end) = &replacements[n - 1];
            if position == start {
                source_start
            } else if position < end {
                if is_end {
                    source_end
                } else {
                    source_start
                }
            } else {
                position - end + source_end
            }
        };
        let mut spans = report.redactions;
        spans.extend(
            next.redactions
                .iter()
                .map(|r| original(r.start, false)..original(r.end, true)),
        );
        report = render(input, spans);
    }
    crate::ScrubReport {
        text: REDACTION_TOKEN.into(),
        redactions: std::iter::once(0..input.len()).collect(),
    }
}
fn analyze_once(input: &str, inherited: bool, policy: Policy) -> crate::ScrubReport {
    if input.len() > crate::MAX_RECORD_BYTES {
        return crate::ScrubReport {
            text: REDACTION_TOKEN.into(),
            redactions: std::iter::once(0..input.len()).collect(),
        };
    }
    if input.is_empty() {
        return crate::ScrubReport {
            text: String::new(),
            redactions: Vec::new(),
        };
    }
    let view = View::new(input);
    let mut spans = Vec::new();
    for m in provider_matches(&view.text) {
        let value = &view.text[m.clone()];
        if provider_symbol(&view, value, m.start, m.end) {
            continue;
        }
        spans.push(m);
    }
    jwts(&view, &mut spans);
    for c in bearer_regex().captures_iter(&view.text) {
        let token = c.get(1).expect("credential capture");
        if let Some(end) = candidate_end(&view, token.start()) {
            if token.as_str() == "hidden_..."
                && view.text[token.start()..end].trim() != token.as_str()
            {
                spans.push(token.start()..end);
                continue;
            }
            if end > token.end() && opaque_material(&view.text[token.end()..end]) {
                spans.push(token.start()..end);
                continue;
            }
        }
        // A comment marker alone never exempts credential material. Only an
        // explicit variable identifier can retain reference semantics here.
        let prefix = bounded_prefix(&view, c.get(0).expect("bearer match").start()).trim();
        if !reference(token.as_str())
            && !environment_reference(token.as_str())
            && !labeled_toy(&view, token.start(), token.as_str())
            && !((prefix.starts_with('#') || prefix.starts_with("//"))
                && comment_variable(token.as_str()))
        {
            spans.push(token.range());
        }
    }
    let mut pos = 0;
    while let Some(c) = pem_regex().captures_at(&view.text, pos) {
        let begin = c.get(0).expect("PEM begin");
        let end_marker = format!("-----END {}-----", &c[1]);
        let end = view.text[begin.end()..]
            .find(&end_marker)
            .map_or(view.text.len(), |p| begin.end() + p + end_marker.len());
        spans.push(begin.start()..end);
        pos = end;
    }
    credential_prose(&view, &mut spans);
    let mut url_values = Vec::new();
    urls(&view, &mut url_values);
    html_attribute_urls(&view, &mut url_values);
    url_values.sort_unstable_by_key(|span| (span.start, span.end));
    assignments(&view, inherited, &mut spans, &url_values);
    spans.extend(url_values);
    if policy == Policy::Pii {
        for m in pii_regex().find_iter(&view.text) {
            spans.push(m.range());
        }
    }
    let original: Vec<Range<usize>> = spans
        .into_iter()
        .filter(|r| r.start < r.end)
        .map(|r| view.source_start(r.start)..view.source_end(r.end - 1))
        .collect();
    render(input, original)
}
fn replacement<'a>(input: &str, span: &Range<usize>) -> &'a str {
    if input
        .as_bytes()
        .get(span.start)
        .is_some_and(|b| b.is_ascii_digit() || *b == b'-')
        && serde_json::from_str::<serde_json::Number>(&input[span.clone()]).is_ok()
    {
        let prefix = input[..span.start].trim_end();
        if prefix
            .strip_suffix(':')
            .is_some_and(|s| s.trim_end().ends_with(['"', '\'', '`']))
        {
            return "\"[REDACTED]\"";
        }
    }
    REDACTION_TOKEN
}
fn render(input: &str, mut original: Vec<Range<usize>>) -> crate::ScrubReport {
    original.sort_unstable_by_key(|r| (r.start, r.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for span in original {
        if let Some(last) = merged.last_mut().filter(|last| span.start < last.end) {
            last.end = last.end.max(span.end);
        } else {
            merged.push(span);
        }
    }
    let mut out = String::with_capacity(input.len());
    let mut at = 0;
    for span in &merged {
        out.push_str(&input[at..span.start]);
        out.push_str(replacement(input, span));
        at = span.end;
    }
    out.push_str(&input[at..]);
    crate::ScrubReport {
        text: out,
        redactions: merged,
    }
}
