//! Fixed automata and a monotone contextual scanner; no backtracking regex.

use crate::{normalize::View, Policy, REDACTION_TOKEN};
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
    let mut starts: Vec<_> = PREFIXES
        .iter()
        .flat_map(|prefix| text.match_indices(prefix).map(|(start, _)| start))
        .collect();
    starts.sort_unstable();
    let mut ranges = Vec::new();
    let mut cursor = 0;
    for start in starts {
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
    let outer_end = outer.map(|_| view.quote_end(value));
    let mut nested_outer_quote = false;
    let mut i = value + usize::from(outer.is_some());
    let mut stack = Vec::new();
    while i < limit {
        let ch = b[i];
        if stack.is_empty() && outer == Some(ch) && (outer_end == Some(i) || nested_outer_quote) {
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
            nested_outer_quote |= outer_end == Some(i);
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

fn safe_code_literals(value: &str) -> bool {
    if opaque_material(value) {
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
            if !(literal == "Bearer " || i > 0 && b[i - 1] == b'[' && sensitive(literal)) {
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
    R.get_or_init(|| Regex::new(r#"^(?:new[ \t]+)?(?:\.[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\?\.|\.|::)[A-Za-z_][A-Za-z0-9_]*|\?\.\([A-Za-z0-9_., \t]*\)|\([A-Za-z0-9_., \t"'\[\]]*\)|\[(?:[A-Za-z_][A-Za-z0-9_]*|"[A-Za-z_][A-Za-z0-9_]*"|'[A-Za-z_][A-Za-z0-9_]*')\])*)!?$"#).expect("complete code expression"))
        .is_match(value)
}

fn code_value(view: &View, key: usize, value: usize, colon: bool, declaration: bool) -> bool {
    let Some(rest) = candidate(view, value) else {
        return false;
    };
    if !safe_code_literals(rest) {
        return false;
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
                .all(|b| b.is_ascii_alphanumeric() || b"_:<>()[], &'".contains(&b));
        let simple = ["string", "boolean", "number", "bool", "&str"].contains(&rest)
            || type_context(view, key) && code_expression(rest);
        return generic || simple;
    }
    false
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
    if !(quoted_key && colon && matches!(first, b'-' | b'0'..=b'9')
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
        && quoted_key
        && colon
        && numeric_identifier(name)
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

fn assignments(view: &View, inherited: bool, spans: &mut Vec<Range<usize>>) {
    let b = view.text.as_bytes();
    let mut i = 0;
    let mut public_until = if inherited { b.len() } else { 0 };
    // Classifications depend only on the name, while credential/public scope is
    // resolved below. Repeated container fields should not rerun normalization,
    // suffix checks and allocations for every occurrence and every scope.
    let mut names = std::collections::HashMap::new();
    // End positions are resolved by View, so context is retained independently
    // of byte distance. Cumulative flags make every push/pop constant time.
    let mut contexts: Vec<(usize, bool, bool)> = Vec::new();
    while i < b.len() {
        let flag_start = i >= 2 && &b[i - 2..i] == b"--";
        if !b[i].is_ascii_alphabetic() || (i > 0 && word(b[i - 1]) && !flag_start) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && word(b[i]) {
            i += 1;
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
        if !quoted
            && start >= public_until
            && (declaration
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
            && full.is_some_and(|s| !opaque_material(s) || s.starts_with("Bearer "))
        {
            continue;
        }
        // Failed structural candidates redact through their complete delimiter,
        // including opaque tails and literals inside calls/substitutions.
        if full.is_some_and(opaque_material) {
            end = end.max(complete_end.unwrap() - usize::from(quoted));
        } else if complete_end.is_none()
            && (matches!(b[value], b'$' | b'{' | b'[' | b'<' | b'*') || declaration)
        {
            end = end.max(view.line_end(value).min(view.enclosing_end(value)));
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
    for run in compact_regex().find_iter(&view.text) {
        let segments: Vec<_> = run.as_str().split('.').collect();
        let mut offset = run.start();
        let mut i = 0;
        while i + 2 < segments.len() {
            let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(segments[i])
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
            if let Some(header) =
                header.filter(|h| h.get("alg").is_some_and(serde_json::Value::is_string))
            {
                let count = if header.get("enc").is_some() { 5 } else { 3 };
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
    ["fn", "function", "let", "const", "var", "use", "import"]
        .iter()
        .any(|kw| {
            prefix.strip_suffix(kw).is_some_and(|before| {
                before.is_empty()
                    || before.ends_with(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            })
        })
        || prefix.ends_with('.')
        || prefix.ends_with("::")
        || view.text[end..].starts_with('(')
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
    while let Some(scheme) = url_regex().find_at(&view.text, cursor) {
        if url_regex_source(view, scheme.start(), scheme.end()) {
            cursor = scheme.end();
            continue;
        }
        let mut end = scheme.end();
        while end < b.len()
            && !(view.literal(end)
                && (b[end].is_ascii_whitespace()
                    || matches!(b[end], b'<' | b'>' | b'"' | b'\'' | b'`')))
        {
            end += 1;
        }
        cursor = end;
        let authority = scheme.end();
        let mut authority_end = authority;
        while authority_end < end
            && !(view.literal(authority_end) && matches!(b[authority_end], b'/' | b'?' | b'#'))
        {
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
        if let Some(query) = (authority_end..end).find(|&i| b[i] == b'?' && view.literal(i)) {
            let mut start = query + 1;
            while start < end {
                let mut parameter_end = start;
                while parameter_end < end
                    && !(b[parameter_end] == b'&' && view.literal(parameter_end))
                {
                    parameter_end += 1;
                }
                if let Some(eq) = (start..parameter_end).find(|&i| b[i] == b'=') {
                    let key = &view.text[start..eq];
                    let key_lower = key.to_ascii_lowercase();
                    if eq + 1 < parameter_end
                        && (sensitive(key)
                            || matches!(
                                key_lower.as_str(),
                                "x-amz-signature"
                                    | "x-amz-credential"
                                    | "x-amz-security-token"
                                    | "x-goog-signature"
                                    | "x-goog-credential"
                                    | "signature"
                                    | "sig"
                                    | "assertion"
                                    | "code_verifier"
                            ))
                    {
                        spans.push(eq + 1..parameter_end);
                    }
                }
                start = parameter_end + 1;
            }
        }
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
    assignments(&view, inherited, &mut spans);
    urls(&view, &mut spans);
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
