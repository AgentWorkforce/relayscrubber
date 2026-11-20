//! Fixed automata and a monotone contextual scanner; no backtracking regex.

use crate::{
    normalize::{Spaced, View},
    Policy, REDACTION_TOKEN,
};
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
        "passcode",
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
        // An unterminated quote fails closed, but never past the close of
        // the layer that encloses it (a JSON string's own close).
        return view
            .quote_end(start)
            .min(view.enclosing_end(start))
            .min(context_end.unwrap_or(b.len()));
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
// Fixed lookbehind budget shared by the source contexts: repeated fields
// cannot rescan a growing prefix.
fn context_window(view: &View, key: usize) -> &str {
    let mut start = key.saturating_sub(512);
    while !view.text.is_char_boundary(start) {
        start += 1;
    }
    &view.text[start..key]
}
// `text.contains(word)`, found by a search for the word's first character,
// which runs on the optimised byte search even in an unoptimised build.
fn holds(text: &str, word: &str) -> bool {
    let Some(first) = word.chars().next() else {
        return true;
    };
    let mut from = 0;
    while let Some(i) = text[from..].find(first) {
        if text[from + i..].starts_with(word) {
            return true;
        }
        from += i + first.len_utf8();
    }
    false
}
fn type_context(view: &View, key: usize) -> bool {
    let prefix = context_window(view, key);
    // Every form ends inside an open `(` (fn signature) or `{` (body); a
    // window with neither is rejected by two byte searches.
    let bytes = prefix.as_bytes();
    if !bytes.contains(&b'(') && !bytes.contains(&b'{') {
        return false;
    }
    if !["fn", "struct", "interface", "type"]
        .iter()
        .any(|word| holds(prefix, word))
    {
        return false;
    }
    static TYPE: OnceLock<Regex> = OnceLock::new();
    TYPE.get_or_init(|| Regex::new(r"(?s)(?:\bfn\s+[A-Za-z_][A-Za-z0-9_]*(?:<[^;{}()]*>)?\s*\([^);{}=]*|\b(?:struct|interface)\s+[A-Za-z_][A-Za-z0-9_]*[^;{}]*\{[^}]*|\btype\s+[A-Za-z_][A-Za-z0-9_]*[^;{}]*=\s*\{[^}]*)(?:$)").expect("fixed type-context regex"))
        .is_match(prefix)
}
fn code_object_context(view: &View, key: usize) -> bool {
    let prefix = context_window(view, key);
    // Both forms end inside an open `{`.
    if !prefix.as_bytes().contains(&b'{') || !prefix.contains('=') && !holds(prefix, "json!") {
        return false;
    }
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?s)(?:\b(?:(?:let|const|var)\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{|\bjson!\(\{)[^{}]*$")
            .expect("fixed object expression context")
    })
    .is_match(prefix)
}

// The key is a labelled argument directly inside an unclosed call whose `(`
// is glued to a callee identifier: `Record(contextKey: .workspaceID)`. A
// parenthesis with no callee (`(password: x)`) is prose, not source context.
// Same fixed lookbehind budget as the other contexts.
fn call_argument_context(view: &View, key: usize) -> bool {
    let prefix = context_window(view, key);
    if !prefix.contains('(') {
        return false;
    }
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"[A-Za-z_][A-Za-z0-9_]*\((?:[^(){};]*,)?[ \t\r\n]*$")
            .expect("fixed call-argument context")
    })
    .is_match(prefix)
}

// A reference must reach its delimiter within this budget. Whitespace and
// comments are part of the value, not proof that a reference has ended.
fn candidate_end(view: &View, value: usize) -> Option<usize> {
    candidate_end_with_entities(view, value, false)
}

// Entity punctuation in a documentary assignment is value data. This only
// extends redaction; it never decodes words or enables a source exemption.
fn entity_end(b: &[u8], start: usize, limit: usize) -> Option<usize> {
    let mut i = start + 1;
    let mut amp_end = None;
    while b
        .get(i..i + 4)
        .is_some_and(|s| s.eq_ignore_ascii_case(b"amp;"))
        && i + 4 <= limit
    {
        i += 4;
        amp_end = Some(i);
    }
    let body = i;
    if b.get(i) == Some(&b'#') {
        i += 1;
        let hex = b.get(i).is_some_and(|b| b.eq_ignore_ascii_case(&b'x'));
        i += usize::from(hex);
        let digits = i;
        while i < limit
            && if hex {
                b[i].is_ascii_hexdigit()
            } else {
                b[i].is_ascii_digit()
            }
        {
            i += 1;
        }
        if i == digits {
            return amp_end;
        }
    } else {
        while i < limit && b[i].is_ascii_alphanumeric() {
            i += 1;
        }
        if i == body {
            return amp_end;
        }
    }
    if i < limit && b[i] == b';' {
        Some(i + 1)
    } else {
        amp_end
    }
}

fn candidate_end_with_entities(view: &View, value: usize, entities: bool) -> Option<usize> {
    let b = view.text.as_bytes();
    let line = view.line_end(value).min(view.enclosing_end(value));
    let limit = line.min(value.saturating_add(512));
    let outer = matches!(b.get(value), Some(b'"' | b'\'' | b'`')).then_some(b[value]);
    let mut outer_end = outer.map(|_| view.quote_end(value));
    let mut i = value + usize::from(outer.is_some());
    let mut stack = Vec::new();
    while i < limit {
        let ch = b[i];
        if entities && ch == b'&' {
            if let Some(end) = entity_end(b, i, limit) {
                i = end;
                continue;
            }
        }
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

// An explicit sensitive assignment in a bullet owns the full scalar, even
// when surrounding text looks documentary. Inspect a bounded line prefix so
// repeated keys never rescan a long label. Value words and case are irrelevant.
fn bullet_assignment(view: &View, key: usize) -> bool {
    let prefix = &view.text.as_bytes()[view.line_start(key)..key];
    let mut i = 0;
    while i < prefix.len() && i < 512 {
        let width = space_width(prefix, i);
        if width == 0 {
            return matches!(prefix[i], b'-' | b'*' | b'+') && space_width(prefix, i + 1) > 0;
        }
        i += width;
    }
    // Exhausted indentation context is not evidence for ending a credential.
    prefix.len() >= 512
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

// Reference arguments contain identifiers rather than scalar literals.
fn symbolic_arguments(value: &str) -> bool {
    !value.contains(['"', '\'', '`'])
        && !value
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|atom| atom.as_bytes().first().is_some_and(u8::is_ascii_digit))
}

fn code_expression(value: &str) -> bool {
    if !safe_code_literals(value) {
        return false;
    }
    if let Some(rest) = value.strip_prefix("await ") {
        // Awaited credential calls may contain reference arguments, never
        // scalar literals (including short numeric credentials).
        return rest.contains('(')
            && symbolic_arguments(rest)
            && code_expression(rest.trim_start());
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

// Whether the last whitespace-separated word of `prefix` is one of `words`
// (none holds whitespace): the same answer as
// `split_whitespace().last()`, from the end of the text instead of a scan
// back across a long word.
fn last_word_is(prefix: &str, words: &[&str]) -> bool {
    let text = prefix.trim_end();
    words.iter().any(|word| {
        text.strip_suffix(word)
            .is_some_and(|head| head.is_empty() || head.ends_with(char::is_whitespace))
    })
}

// `let`/`const`/`var` directly before the key on its own line.
fn keyword_declaration(view: &View, key: usize) -> bool {
    last_word_is(bounded_prefix(view, key), &["let", "const", "var"])
        && bounded_prefix(view, key).ends_with(char::is_whitespace)
}

fn code_value(view: &View, key: usize, value: usize, colon: bool, declaration: bool) -> bool {
    // An isolated opener has no credential bytes. Never exempt a prefix of an
    // unfinished multi-line object: its entire remaining value must be empty.
    if !colon && view.text.len() - value <= 512 && view.text[value..].trim() == "{" {
        return true;
    }
    // Rust reference aliases have a lifetime apostrophe, not a quoted scalar.
    // Check the entire declaration suffix before the general quote scanner.
    if !colon && matches!(bounded_prefix(view, key).trim(), "type" | "pub type") {
        let end = view.line_end(value).min(value.saturating_add(512));
        if end == view.line_end(value) && view.text.is_char_boundary(end) {
            let rest = &view.text[value..end];
            static ALIAS: OnceLock<Regex> = OnceLock::new();
            if !opaque_material(rest)
                && ALIAS
                    .get_or_init(|| {
                        Regex::new(
                            r"^&(?:'[A-Za-z_][A-Za-z0-9_]*[ \t]+)?(?:mut[ \t]+)?str[ \t]*;[ \t]*$",
                        )
                        .expect("complete Rust str reference alias")
                    })
                    .is_match(rest)
            {
                return true;
            }
        }
    }
    let Some(rest) = candidate(view, value) else {
        return false;
    };
    if !safe_code_literals(rest) {
        return false;
    }
    // A source-shaped RHS does not establish source context. Only an
    // independently recognized declaration/context may preserve expressions.
    if !colon && declaration && template_reference(rest) && symbolic_arguments(rest) {
        return true;
    }
    if !colon
        && !last_word_is(bounded_prefix(view, key), &["type"])
        && declaration
        && crate::syntax::expression(rest)
    {
        return true;
    }
    if last_word_is(bounded_prefix(view, key), &["type"]) {
        static TUPLE: OnceLock<Regex> = OnceLock::new();
        if TUPLE.get_or_init(|| Regex::new(r"^\((?:String|bool|u(?:8|16|32|64|128|size)|i(?:8|16|32|64|128|size))(?:[ \t]*,[ \t]*(?:String|bool|u(?:8|16|32|64|128|size)|i(?:8|16|32|64|128|size)))+[ \t]*,?\)$").expect("complete primitive tuple type")).is_match(rest) {
            return true;
        }
    }
    // After a bare colon, a source-shaped RHS does not establish source
    // context either: an expression or `match` keeps its bytes only inside a
    // struct/interface/type body or fn signature, an object expression
    // (`name = {`, `json!({`) or a labelled call argument.
    // The type context depends only on the key; look it up once.
    let typed = std::cell::OnceCell::new();
    let in_type_context = || *typed.get_or_init(|| type_context(view, key));
    let expression_context = declaration
        || colon
            && (in_type_context()
                || code_object_context(view, key)
                || call_argument_context(view, key));
    if (declaration
        || expression_context
            && (rest.contains('.') || rest.contains('(') || rest.starts_with('.')))
        && code_expression(rest)
    {
        return true;
    }
    if colon
        && expression_context
        && rest.starts_with("match ")
        && rest.ends_with('}')
        && rest.contains("=>")
    {
        return rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_ \t{}(),=>:&|".contains(&b));
    }
    // A type-looking value after a bare colon is credential data unless
    // independently recognised source context surrounds the key: a fn
    // signature or struct/interface/type body (`type_context`), or a
    // `let`/`const`/`var` declaration. Types must also be complete; a balanced
    // generic cannot hide a tail.
    if colon && (in_type_context() || keyword_declaration(view, key)) {
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
        // In a signature or type body a Rust borrow (`&Token`, `&mut Token`)
        // is a type; the `&` is not a value byte to keep elsewhere.
        let borrowed = rest
            .strip_prefix('&')
            .map(|r| r.strip_prefix("mut ").unwrap_or(r));
        let simple = ["string", "boolean", "number", "bool", "&str"].contains(&rest)
            || in_type_context()
                && (code_expression(rest) || borrowed.is_some_and(code_expression));
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
    wrapped: &mut Vec<Range<usize>>,
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
        // A whitespace-separated option followed by another complete flag has
        // no value. Equals and quoted spellings still carry literal data.
        if flag && !has_sep && next_cli_flag(view, value) {
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
        if name == "Key"
            && quoted
            && !credential
            && !bounded_prefix(view, start).contains("--tags ")
            && !bounded_prefix(view, start).ends_with("\"Tags\":[{\"")
        {
            if let Some(end) = candidate_end(view, value) {
                let after = skip_space(b, end);
                if after < b.len() && !matches!(b[after], b',' | b'}' | b']' | b')' | b';') {
                    // A quoted scalar is only a prefix when data follows its
                    // closer. Keep the malformed value's full rejection extent.
                    let tail = candidate_end(view, end)
                        .unwrap_or_else(|| view.line_end(value).min(view.enclosing_end(value)));
                    spans.push(value..tail);
                    i = tail;
                    continue;
                }
            }
        }
        if !quoted && destructuring_bind(view, start) {
            continue;
        }
        if quoted_key && b.get(sep) == Some(&b':') && source_label(view, start, value) {
            continue;
        }
        if quoted_key && b.get(sep) == Some(&b':') && case_label(view, start) {
            // A rejected return body is still one whole labelled value;
            // removing only the `return` keyword would leave literal arguments.
            let end = candidate_end(view, value)
                .unwrap_or_else(|| view.line_end(value).min(view.enclosing_end(value)));
            spans.push(value..end);
            i = end;
            continue;
        }
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
        let source_context = !quoted
            && start >= public_until
            && b.get(sep) == Some(&b':')
            && !name.eq_ignore_ascii_case("key")
            && (code_object_context(view, start) || type_context(view, start));
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
            && (!flag && b.get(sep) == Some(&b'=')
                || declaration
                || last_word_is(bounded_prefix(view, start), &["type"])
                || b.get(sep) == Some(&b':')
                || before > 0 && matches!(b[before - 1], b'{' | b',' | b'(')
                || b.get(sep) == Some(&b':') && (quoted_key || type_context(view, start)))
            && code_value(
                view,
                start,
                value,
                b.get(sep) == Some(&b':'),
                declaration || source_context,
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
        let bullet = !quoted && !flag && has_sep && bullet_assignment(view, start);
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
            && !bullet
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
        // A quoted reference with text glued after its close
        // (`password="$defq""abc"`) is no whole reference: a prose
        // disclosure of the whole value still has the range.
        let glued_reference = quoted
            && complete_end.is_some_and(|end| {
                end > content
                    && view.text[end..].chars().next().is_some_and(|c| {
                        !c.is_whitespace() && !matches!(c, ',' | ';' | ')' | ']' | '}')
                    })
            });
        if full.is_some_and(expansion_reference) {
            if glued_reference {
                wrapped
                    .push(content..complete_end.map_or(content + 1, |e| (e - 1).max(content + 1)));
            }
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
        }) {
            if glued_reference {
                wrapped
                    .push(content..complete_end.map_or(content + 1, |e| (e - 1).max(content + 1)));
            }
            continue;
        }
        let sentence = non_assignment_wrapper(view, start)
            && !last_word_is(bounded_prefix(view, start), &["type"])
            && full.is_some_and(|s| {
                b.get(sep) != Some(&b'=')
                    && (!opaque_material(s) || s.starts_with("Bearer "))
                    // Delegate only a complete Bearer literal to the standalone
                    // scanner, which removes its entire credential body. A
                    // source-shaped value or an additional tail cannot qualify.
                    || s.split_once([' ', '\t']).is_some_and(|(scheme, body)| {
                        scheme.eq_ignore_ascii_case("bearer")
                            && body.trim_start_matches([' ', '\t']) == REDACTION_TOKEN
                    })
                    || bearer_regex()
                        .find(s)
                        .is_some_and(|m| m.start() == 0 && m.end() == s.len())
            });
        if !sentence && name == "Key" && !credential && cloud_tag_key(view, start, value) {
            continue;
        }
        // Failed structural candidates redact through their complete delimiter,
        // including opaque tails and literals inside calls/substitutions.
        let failed_reference = raw.starts_with('$')
            || !quoted
                && (bullet
                    || declaration
                    || source_context && b[value].is_ascii_alphabetic()
                    || !flag
                        && b.get(sep) == Some(&b'=')
                        && view.text[start..value].contains(" = ")
                        && complete_end.is_some_and(|end| b.get(end) == Some(&b';'))
                    || last_word_is(bounded_prefix(view, start), &["type"])
                    || matches!(b[value], b'$' | b'{' | b'[' | b'<' | b'*')
                    // After a colon a leading `&` is the value's first byte,
                    // not the query separator `value_end` stops at: an empty
                    // `raw` must not keep `admin password: &abcq`.
                    || b[value] == b'&' && b.get(sep) == Some(&b':')
                    || raw.contains(['(', '.', '/'])
                    || raw
                        .as_bytes()
                        .windows(2)
                        .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase())
                    || b.get(sep) == Some(&b':')
                        && raw.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
                        && raw.bytes().any(|b| b.is_ascii_lowercase())
                        && raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    || raw.contains('_')
                        && raw.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'));
        if full.is_some_and(opaque_material) || failed_reference {
            // Entity-aware bounds apply only after preservation decisions.
            // They can extend a rejected value, never admit an exemption.
            let complete_end = if bullet {
                candidate_end_with_entities(view, value, true)
            } else {
                complete_end
            };
            let limit = complete_end.map_or_else(
                || view.line_end(value).min(view.enclosing_end(value)),
                |end| {
                    if quoted {
                        end - 1
                    } else {
                        // Delimiter-adjacent whitespace is outside a rejected
                        // source value; keep all internal literal/comment tails.
                        value + view.text[value..end].trim_end().len()
                    }
                },
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
        if sentence {
            // Words before the key make this a sentence, not an assignment.
            // A prose disclosure of the same value still needs the range the
            // bare key would have redacted. A comment stays a comment, and a
            // Bearer literal stays delegated to the Bearer scanner.
            if !comment_wrapper(view, start)
                && !full.is_some_and(|s| {
                    s.split_once([' ', '\t'])
                        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                })
            {
                wrapped.push(content..end.max(content + 1).min(b.len()));
            }
            continue;
        }
        if end > content {
            if reference(&view.text[content..end]) || shell_reference(&view.text[content..end]) {
                // Only the first word is a reference; a prose disclosure
                // that takes the whole multi-word value still has one.
                if full.is_some_and(|whole| whole.trim_end().len() > end - content) {
                    wrapped.push(content..end);
                }
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

fn next_cli_flag(view: &View, value: usize) -> bool {
    let tail = &view.text[value..view.line_end(value)];
    let flag = tail.split_whitespace().next().unwrap_or("");
    flag.strip_prefix("--").is_some_and(|name| {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
    }) || flag.len() == 2 && flag.starts_with('-') && flag.as_bytes()[1].is_ascii_alphabetic()
}

fn destructuring_bind(view: &View, key: usize) -> bool {
    let start = view.line_start(key);
    let end = view.line_end(key);
    if end - start > 512 {
        return false;
    }
    let line = view.text[start..end].trim();
    if !safe_code_literals(line) {
        return false;
    }
    static BIND: OnceLock<Regex> = OnceLock::new();
    let Some(c) = BIND.get_or_init(|| Regex::new(r"^(?:const|let|var)[ \t]+\{[ \t]*[A-Za-z_][A-Za-z0-9_]*(?:[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_]*)?(?:[ \t]*,[ \t]*[A-Za-z_][A-Za-z0-9_]*(?:[ \t]*:[ \t]*[A-Za-z_][A-Za-z0-9_]*)?)*[ \t]*\}[ \t]*=[ \t]*(.+?);?$").expect("complete destructuring bind")).captures(line) else { return false };
    crate::syntax::expression(c.get(1).expect("bound expression").as_str())
}

fn source_label(view: &View, key: usize, value: usize) -> bool {
    let prefix = bounded_prefix(view, key).trim_end();
    if case_label(view, key) {
        return candidate(view, value)
            .and_then(|s| s.strip_prefix("return "))
            .is_some_and(|s| safe_code_literals(s) && crate::syntax::expression(s));
    }
    // The quoted search pattern ends before this colon. Require the whole
    // following command to be a path and an optional simple head pipeline.
    let Some(command) = prefix.split_whitespace().next() else {
        return false;
    };
    if !matches!(command, "grep" | "rg") {
        return false;
    }
    let tail = &view.text[value..view.line_end(value)];
    if tail.len() > 512 || opaque_material(tail) {
        return false;
    }
    static SEARCH: OnceLock<Regex> = OnceLock::new();
    SEARCH
        .get_or_init(|| {
            Regex::new(r"^(?:\./|/)?[A-Za-z_][A-Za-z0-9_./-]*/(?:[ \t]*\|[ \t]*head)?[ \t]*$")
                .expect("complete search path tail")
        })
        .is_match(tail)
}

fn case_label(view: &View, key: usize) -> bool {
    bounded_prefix(view, key)
        .trim_end()
        .trim_end_matches(['"', '\''])
        .trim_end()
        == "case"
}

// Only syntax before a key can establish a non-assignment wrapper. Never
// inspect the English credential value to decide whether it is documentary.
fn non_assignment_wrapper(view: &View, position: usize) -> bool {
    if comment_wrapper(view, position) {
        return true;
    }
    let prefix = bounded_prefix(view, position).trim();
    let prefix = prefix.trim_end_matches(['"', '\'']).trim_end();
    let sentence = prefix.trim_end_matches(':');
    sentence
        .bytes()
        .all(|b| b.is_ascii_alphabetic() || b.is_ascii_whitespace())
        && sentence.split_whitespace().take(2).count() == 2
}

// A `#` or `//` comment line before the key.
fn comment_wrapper(view: &View, position: usize) -> bool {
    let prefix = bounded_prefix(view, position).trim();
    prefix.starts_with('#') || prefix.starts_with("//")
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
    let rest = rest.trim_end_matches(['"', '\'']);
    rest.is_empty()
        || marker_reference(rest)
        || reference(rest)
        || shell_reference(rest)
        || environment_reference(rest)
}

fn credential_prose(view: &View, input: &str, spans: &mut Vec<Range<usize>>) -> Vec<ProseValue> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| {
        Regex::new(r"(?i)\bAPI[ \t]+key[ \t]+([A-Za-z0-9_+/=-]{24,})")
            .expect("fixed credential prose regex")
    });
    for c in r.captures_iter(&view.text) {
        spans.push(c.get(1).expect("credential capture").range());
    }
    prose_disclosures(view, input)
}

// A prose disclosure's value in source coordinates. Word cues and determiner
// forms always disclose. A bare `noun: value` or `noun = value` discloses
// only where the assignment engine also finds a credential value (sensitive
// nouns) or, for the short nouns it does not know, outside URL components;
// either way the prose rule then decides the whole extent of the value.
pub(crate) struct ProseValue {
    probe: usize,
    source: Range<usize>,
    gate: Gate,
}

#[derive(Clone, Copy, PartialEq)]
enum Gate {
    Always,
    Assigned,
    Outside,
}

// Every `char::is_whitespace` code point is a separator: these horizontal
// ones and the line breaks below. Encoded spellings are decoded first by
// `Spaced`. A CRLF pair counts as one line break.
const PROSE_SPACE: &str = r"[\t \u{a0}\u{1680}\u{2000}-\u{200a}\u{202f}\u{205f}\u{3000}]";
const PROSE_BREAK: &str = r"(?:\r\n|[\n\x0B\x0C\r\u{85}\u{2028}\u{2029}])";

fn line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

// Start of the line holding `position`, given every line start of the text.
fn prose_line_start(starts: &[usize], position: usize) -> usize {
    starts[starts.partition_point(|&s| s <= position) - 1]
}

// Natural-language password disclosures: `my password is x`, `the passcode
// was '#'`, `pw: !`, `password = velvet river lantern`. There is no minimum
// value length; documentary predicates (`the password is required`),
// references (`$PASSWORD`), type annotations with source context
// (`struct X { pw: string }`) and code (`if password is None`) are excluded. See docs/SPEC.md.
fn prose_disclosures(view: &View, input: &str) -> Vec<ProseValue> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| {
        // S: one or more separators with at most one line break; O: like S
        // but possibly empty.
        let (h, b) = (PROSE_SPACE, PROSE_BREAK);
        let s = format!(r"(?:{h}+(?:{b}{h}*)?|{b}{h}*)");
        let o = format!(r"{h}*(?:{b}{h}*)?");
        Regex::new(&format!(
            r"(?i)(?:\b(my|our|your|his|her|their|its|the){s})?\b(password|passcode|passphrase|passwd|pwd|pw|pass{s}code|pass{s}phrase)\b{o}(?:((?:is|was){s}set{s}to|is{s}now|set{s}to|is|was)\b(:?)|(:|=))"
        ))
        .expect("fixed prose disclosure regex")
    });
    let layer = Spaced::new(&view.text);
    let text: &str = &layer.text;
    let starts: Vec<usize> = std::iter::once(0)
        .chain(
            text.char_indices()
                .filter(|(_, c)| line_break(*c))
                .map(|(i, c)| i + c.len_utf8()),
        )
        .collect();
    let mut found = Vec::new();
    let mut covered = 0;
    let mut scan: (usize, usize, Vec<(char, u32)>) = (0, 0, Vec::new());
    let cap = std::cell::RefCell::new(Vec::new());
    let tables = ValueTables::default();
    let mut openers = (Openers::new(false, 0), Openers::new(true, 0));
    for c in r.captures_iter(text) {
        let whole = c.get(0).expect("prose disclosure match");
        let noun = c.get(2).expect("prose disclosure noun");
        let determiner = c.get(1).is_some();
        // A colon or equals cue assigns its whole value with or without a
        // determiner; only the gate below depends on the bare form.
        let cue = c.get(5);
        let bare = cue.filter(|_| !determiner);
        let rest = &text[whole.end()..];
        if whole.start() < covered
            || text[..noun.start()]
                .chars()
                .next_back()
                .is_some_and(|ch| matches!(ch, '.' | '$' | '@' | '-' | '/' | '\\'))
            || !determiner
                && code_condition(&text[prose_line_start(&starts, noun.start())..noun.start()])
            || rest.starts_with('=')
            || bare.is_some_and(|m| {
                m.as_str() == "=" && rest.starts_with('>')
                    || m.as_str() == ":" && rest.starts_with(':')
            })
        {
            continue;
        }
        // The value follows the cue after separators with at most one line
        // break; after a bare cue it must start on the cue's line.
        let mut start = whole.end();
        let mut breaks = 0;
        let allowed = if bare.is_some() { 0 } else { 1 };
        while let Some(ch) = text[start..].chars().next() {
            if line_break(ch) {
                if !(ch == '\n' && text[..start].ends_with('\r')) {
                    breaks += 1;
                }
                if breaks > allowed {
                    break;
                }
            } else if !ch.is_whitespace() {
                break;
            }
            start += ch.len_utf8();
        }
        if breaks > allowed {
            continue;
        }
        if start == whole.end() && c.get(3).is_some() && c.get(4).is_none_or(|m| m.is_empty()) {
            continue;
        }
        // The line ends at the break before the next line start.
        let line_end = starts
            .get(starts.partition_point(|&s| s <= start))
            .map_or(text.len(), |&next| {
                next - text[..next].chars().next_back().map_or(0, char::len_utf8)
            });
        let line_end = start + text[start..line_end].trim_end().len();
        if start >= line_end {
            continue;
        }
        let gate = match bare {
            None => Gate::Always,
            Some(cue) => {
                let key = layer.start(noun.start());
                // Code glued to a quote (`x "pw: process.env.X""abc"`) is one
                // value with what touches it, scanned below.
                let value = layer.start(start);
                let glued = candidate_end(view, value).is_some_and(|end| {
                    view.text[end..].starts_with(['"', '\'', '`'])
                        && view.text[end + 1..].starts_with(|c: char| {
                            c.is_alphanumeric() || matches!(c, '_' | '$' | '"' | '\'' | '`' | '\\')
                        })
                });
                if !glued && code_value(view, key, value, cue.as_str() == ":", false) {
                    continue;
                }
                if noun.as_str().contains(|ch: char| !ch.is_ascii_alphabetic())
                    || !sensitive(noun.as_str())
                {
                    Gate::Outside
                } else {
                    Gate::Assigned
                }
            }
        };
        let line_start = prose_line_start(&starts, whole.start());
        let prefix = &text[line_start..whole.start()];
        // Matches come in order, so the scan of a line's quotes and brackets
        // resumes at the last match on the same line instead of rescanning
        // the line.
        if scan.0 != line_start || scan.1 > whole.start() {
            scan = (line_start, line_start, Vec::new());
            openers = (
                Openers::new(false, line_start),
                Openers::new(true, line_start),
            );
        }
        open_quotes(view, input, &layer, &mut scan.2, scan.1..whole.start());
        scan.1 = whole.start();
        openers.0.advance(text, whole.start());
        openers.1.advance(text, whole.start());
        let context = ProseContext {
            prefix,
            quotes: scan.2.clone(),
            cue: match cue {
                None => Cue::Word,
                Some(_) if determiner || !prefix.trim().is_empty() => Cue::Prefixed,
                Some(_) => Cue::Bare,
            },
            cap: &cap,
            brackets: &openers.0.stack,
            tagged: &openers.1.stack,
            openers: &openers,
            tables: &tables,
        };
        if let Some((source, probe, end)) =
            prose_value(view, input, &layer, start, line_end, &context)
        {
            covered = end;
            // An empty quoted segment touched by text (`password=""abc`) is
            // no empty assignment: the assignment engine finds no value to
            // gate on, so the disclosure stands on its own, unless the text
            // is an operator (`password=""+x`).
            let mut quotes = text[start..].chars();
            let gate = match (quotes.next(), quotes.next(), quotes.next()) {
                (Some(q), Some(c), Some(next))
                    if gate != Gate::Always
                        && matches!(
                            (q, c),
                            ('"', '"') | ('\'', '\'') | ('`', '`') | ('“', '”') | ('‘', '’')
                        )
                        && end > start + q.len_utf8() + c.len_utf8()
                        && !matches!(
                            next,
                            '+' | '|'
                                | '&'
                                | '*'
                                | '/'
                                | '%'
                                | '<'
                                | '>'
                                | '='
                                | '!'
                                | '?'
                                | '^'
                                | '~'
                        ) =>
                {
                    Gate::Always
                }
                _ => gate,
            };
            found.push(ProseValue {
                probe,
                source,
                gate,
            });
        }
    }
    found
}

// How a prose disclosure's value was cued: by a word (`is`, `set to`), or
// by a colon or equals sign after the bare noun or after anything before it
// on the line (a word, a bullet, a quote mark).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cue {
    Word,
    Bare,
    Prefixed,
}

// What the line holds before the noun: its text, the quotes it opened and
// left open (each with its escape level, innermost last), and the cue.
// The last search for the close of one open quote: which quote (mark and
// escape level), structural or not, to which line end, from where, and the
// close found.
struct CapSearch {
    quote: (char, u32),
    structural: bool,
    line_end: usize,
    from: usize,
    found: Option<usize>,
}

#[derive(Clone)]
struct ProseContext<'a> {
    prefix: &'a str,
    quotes: Vec<(char, u32)>,
    cue: Cue,
    // The last close search for each open quote on the layer, shared by
    // every match: segments and later matches search from increasing
    // positions, so a line of many segments or matches is scanned once per
    // open quote, not once per match, however the open quotes alternate.
    cap: &'a std::cell::RefCell<Vec<CapSearch>>,
    // The quotes and brackets the prefix leaves open, without and with tags
    // (see `Openers`), kept per line rather than rebuilt per match.
    brackets: &'a [char],
    tagged: &'a [char],
    openers: &'a (Openers, Openers),
    tables: &'a ValueTables,
}

// Where a value's text ends, looked up instead of scanned for per key: each
// table is built once per layer, when a value first needs it.
#[derive(Default)]
struct ValueTables {
    // Where a bare value's enclosing bracket closes.
    closes: std::cell::OnceCell<BracketCloses>,
    // Where the next key of a `;` or `&` list starts.
    lists: std::cell::OnceCell<ListKeys>,
    // Where the next space and placeholder close lie after a quote close.
    marks: std::cell::OnceCell<ReferenceMarks>,
}

// The escape level of the quote at layer position `p`: a quote spelled with
// n backslashes is at level n.trailing_ones(); one not spelled literally
// (a curly quote, an entity) is at level 0.
fn quote_level(view: &View, input: &str, layer: &Spaced, p: usize, quote: char) -> u32 {
    quote_escape(view, input, layer.start(p), quote).map_or(0, |(_, n)| n.trailing_ones())
}

// An apostrophe between two letters or digits (`don't`) is no quote.
fn apostrophe(text: &str, p: usize) -> bool {
    text[p..].starts_with('\'')
        && text[..p]
            .chars()
            .next_back()
            .is_some_and(char::is_alphanumeric)
        && text[p + 1..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric)
}

// The quotes the layer range opens and leaves open, innermost last: a quote
// closes the latest open quote of its own mark at its own escape level (a
// `”` closes the latest `“`), and everything opened inside it. `open` holds
// what the text before the range left open, so a scan resumes where the last
// one stopped.
fn open_quotes(
    view: &View,
    input: &str,
    layer: &Spaced,
    open: &mut Vec<(char, u32)>,
    range: Range<usize>,
) {
    let text: &str = &layer.text;
    for (i, ch) in text[range.clone()].char_indices() {
        let p = range.start + i;
        if !matches!(ch, '"' | '\'' | '`' | '“' | '”') {
            continue;
        }
        let level = quote_level(view, input, layer, p, ch);
        if let Some(at) = open.iter().rposition(|&(c, l)| {
            if ch == '”' {
                c == '“'
            } else {
                c == ch && l == level
            }
        }) {
            open.truncate(at);
        } else if ch != '”'
            && !(ch == '\''
                && text[..p]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_alphanumeric))
        {
            open.push((ch, level));
        }
    }
}

// Text after a quote that closes an enclosing layer is structure, not more
// of the value, when the line ends there or it is whitespace, a bracket or
// tag close, a `:`, or a list separator before a key-like field.
fn structural_end(rest: &str) -> bool {
    match rest.chars().next() {
        None => true,
        Some(c) if c.is_whitespace() => true,
        Some('}' | ']' | ')' | '>') => true,
        Some('/') => rest.starts_with("/>"),
        Some(',' | ';' | '&') => key_like(&rest[1..]),
        Some(':') => !rest.starts_with("::"),
        _ => false,
    }
}

// A key-like field starts the text: an identifier or a quoted key, then `=`
// or `:` (not `==` or `::`).
fn key_like(rest: &str) -> bool {
    let rest = rest.trim_start_matches([' ', '\t']);
    let after = match rest.chars().next() {
        Some(q @ ('"' | '\'')) => {
            let body = &rest[1..];
            match body.find(q) {
                Some(n) if n > 0 && n <= 64 => &body[n + 1..],
                _ => return false,
            }
        }
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {
            let n = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
                .unwrap_or(rest.len());
            &rest[n..]
        }
        _ => return false,
    };
    let after = after.trim_start_matches([' ', '\t']);
    after.starts_with('=') && !after.starts_with("==")
        || after.starts_with(':') && !after.starts_with("::")
}

// Source range of a layer range.
fn prose_source(view: &View, layer: &Spaced, r: &Range<usize>) -> Range<usize> {
    let start = layer.start(r.start);
    let end = layer.end(r.end - 1);
    view.source_start(start)..view.source_end(end - 1)
}

// The source position of a quote spelled literally (possibly after an
// escape that View decoded) and the run of backslashes before it.
fn quote_escape(view: &View, input: &str, position: usize, quote: char) -> Option<(usize, u32)> {
    let b = input.as_bytes();
    let at = view.source_end(position).checked_sub(1)?;
    (u32::from(b[at]) == u32::from(quote)).then(|| {
        let n = b[..at].iter().rev().take_while(|&&c| c == b'\\').count();
        (at, u32::try_from(n).unwrap_or(u32::MAX))
    })
}

// A close quote ends the value when it is at the opener's escape level: an
// even run of backslashes before a literal quote is part of the value and
// leaves the quote closing (`"abc\\"`); an odd run escapes it (`"abc\"def"`).
// At escape level L (a JSON-encoded `\"` opener is level 1) a quote spelled
// with n backslashes closes exactly when n has L trailing one bits.
fn closes(opener: Option<u32>, candidate: Option<u32>, open: &str, close: &str) -> bool {
    match (opener, candidate) {
        (Some(a), Some(b)) => a.trailing_ones() == b.trailing_ones(),
        _ => open.eq_ignore_ascii_case(close),
    }
}

type ProseRange = (Range<usize>, usize, usize);

// A part of a prose value: value text, or a reference or placeholder that is
// exempt only when it is the whole value. Once any contiguous part is value,
// every part is (`pw: "abc""$defq"`, `pw: ${defq}abc`); a run made only of
// exempt parts (`"$A""$B"`, `${A}${B}`) stays exempt.
#[derive(Clone)]
enum Part {
    Value(ProseRange),
    Exempt(ProseRange),
}

impl Part {
    fn range(&self) -> &ProseRange {
        match self {
            Part::Value(r) | Part::Exempt(r) => r,
        }
    }
}

// A closed quoted segment and how far the text touching its close runs.
#[derive(Clone, Copy)]
struct QuotedSegment {
    inner: usize,
    end: usize,
    after: usize,
    run: usize,
    value_start: usize,
    value_end: usize,
}

enum ProseStep {
    // A value with no closed quoted segment, and the layer position of the
    // enclosing quote close it was cut at, if any.
    Done(Option<Part>, Option<usize>),
    // The segment, and how the text touching its close ends at `run`.
    Segment(QuotedSegment, RunEnd),
}

// How the text touching a closed value ends: at whitespace, a bracket or
// field, or the line end; at a quoted segment that continues the value; or
// at a quote that closes a layer the line opened before the noun.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RunEnd {
    Stop,
    Continues,
    Encloses,
}

// The index in `quotes` of the layer the quote `q` at layer position `p`
// closes: the latest one of the same mark at the same escape level (a `”`
// closes the latest `“`).
fn enclosed_layer(
    view: &View,
    input: &str,
    layer: &Spaced,
    quotes: &[(char, u32)],
    p: usize,
    q: char,
) -> Option<usize> {
    if !matches!(q, '”' | '"' | '\'' | '`') || quotes.is_empty() {
        return None;
    }
    let level = if q == '”' {
        0
    } else {
        quote_level(view, input, layer, p, q)
    };
    quotes.iter().rposition(|&(c, l)| match q {
        '”' => c == '“',
        _ => c == q && l == level,
    })
}

// Returns the value's source range, the View position where its content
// starts, and the layer position the disclosure covers up to. A run of
// contiguous quoted segments is walked with an explicit stack, not
// recursion, so a long run cannot exhaust the thread's stack.
//
// A value that ends at the close of a quote the line opened before the noun
// (`x "pw: abc"defq`, `he said 'my password is "abc"'"defq"`) goes on when
// a quote, a letter or digit, `_` or `$` touches that close: the close is
// redacted with the value, and the text touching it is scanned as the text
// touching a value's own close is, in the layer outside the closed quote.
fn prose_value(
    view: &View,
    input: &str,
    layer: &Spaced,
    start: usize,
    line_end: usize,
    context: &ProseContext,
) -> Option<ProseRange> {
    let text: &str = &layer.text;
    // Each segment, and for the close of an enclosing quote that a value
    // runs across, the value up to that close.
    let mut stack: Vec<(QuotedSegment, Option<Part>)> = Vec::new();
    let (mut at, mut line_end) = (start, line_end);
    let mut current = context.clone();
    let mut result = 'scan: loop {
        let (mut value, mut close) = match prose_segment(view, input, layer, at, line_end, &current)
        {
            ProseStep::Segment(segment, RunEnd::Continues) => {
                at = segment.run;
                line_end = line_end.max(segment.run);
                stack.push((segment, None));
                continue;
            }
            ProseStep::Segment(segment, end) => (
                finish_quoted(view, layer, &segment),
                (end == RunEnd::Encloses).then_some(segment.run),
            ),
            ProseStep::Done(value, close) => (value, close),
        };
        loop {
            let (Some(found), Some(shut)) = (value.clone(), close) else {
                break 'scan value;
            };
            let Some((k, after)) = glued(view, input, layer, &current, found.range(), shut) else {
                break 'scan value;
            };
            // Outside the closed quote: its layer and everything opened
            // inside it are closed, and so is its entry among the brackets
            // when the bracket scan saw it (an unescaped quote).
            let q = text[shut..].chars().next().unwrap_or('"');
            current.quotes.truncate(k);
            let opener = if q == '”' { '“' } else { q };
            if q == '”' || quote_level(view, input, layer, shut, q) == 0 {
                let (plain, tags) = context.openers;
                for (stack, scan) in [(&mut current.brackets, plain), (&mut current.tagged, tags)] {
                    if let Some(at) = scan.quote_at(opener).filter(|&at| at < stack.len()) {
                        *stack = &stack[..at];
                    }
                }
            }
            let (run, end) = touching_run(view, input, layer, after, &current);
            let segment = QuotedSegment {
                inner: shut,
                end: shut,
                after,
                run,
                value_start: found.range().0.start,
                value_end: found.range().0.end,
            };
            if end == RunEnd::Continues {
                at = run;
                line_end = line_end.max(run);
                stack.push((segment, Some(found)));
                continue 'scan;
            }
            // The text touching the close, less one mark of sentence
            // punctuation, joins the value; it may stop at the close of a
            // further enclosing quote that more text touches.
            // A reference glued to a reference stays exempt; any literal
            // part makes the whole run value.
            let tail = &text[after..run];
            let kept = tail.strip_suffix(['.', ',', ';']).unwrap_or(tail);
            let tail_end = after + kept.len();
            let pure =
                matches!(found, Part::Exempt(_)) && (kept.is_empty() || whole_reference(kept));
            let found = found.range();
            let range = (
                found.0.start
                    ..prose_source(view, layer, &(after..tail_end))
                        .end
                        .max(found.0.end),
                found.1,
                tail_end.max(found.2),
            );
            value = Some(if pure {
                Part::Exempt(range)
            } else {
                Part::Value(range)
            });
            close = (end == RunEnd::Encloses).then_some(run);
        }
    };
    // A segment the next one joins spans through the next one's end; one
    // whose next segment is no value ends on its own. A run is exempt only
    // when every part of it is a reference with nothing glued between.
    while let Some((segment, own)) = stack.pop() {
        result = match (result, own) {
            (Some(next), own) => {
                let pure = matches!(next, Part::Exempt(_))
                    && segment.after >= segment.run
                    && own.as_ref().map_or_else(
                        || whole_reference(text[segment.inner..segment.end].trim()),
                        |o| matches!(o, Part::Exempt(_)),
                    );
                let (next, _, next_end) = next.range().clone();
                let range = (
                    segment.value_start..next.end.max(segment.value_end),
                    own.map_or_else(|| layer.start(segment.inner), |o| o.range().1),
                    next_end,
                );
                Some(if pure {
                    Part::Exempt(range)
                } else {
                    Part::Value(range)
                })
            }
            (None, Some(own)) => Some(own),
            (None, None) => finish_quoted(view, layer, &segment),
        };
    }
    match result {
        Some(Part::Value(range)) => Some(range),
        _ => None,
    }
}

// Whether text glues onto the close `close` of a quote the line opened
// before the noun, at which `value` ends: a quote of any kind or escape
// level, a letter or digit, `_` or `$` touches the close, and only the
// value's own closing quotes or sentence punctuation lie between the value
// and it. Returns the closed layer's index and the position after the close.
fn glued(
    view: &View,
    input: &str,
    layer: &Spaced,
    context: &ProseContext,
    value: &ProseRange,
    close: usize,
) -> Option<(usize, usize)> {
    let text: &str = &layer.text;
    let q = text[close..].chars().next()?;
    let after = close + q.len_utf8();
    let rest = &text[after..];
    let touching = rest.chars().next().is_some_and(|c| {
        c.is_alphanumeric()
            || matches!(c, '_' | '$' | '"' | '\'' | '`' | '“' | '”' | '‘' | '’')
            || c == '\\' && rest.trim_start_matches('\\').starts_with(['"', '\'', '`'])
            || reference_prefix(text, after, &context.tables.marks)
    });
    let between = text.get(value.2.min(close)..close)?;
    if !touching
        || between.chars().any(|c| {
            !matches!(
                c,
                '"' | '\'' | '`' | '”' | '’' | '\\' | '.' | ',' | ';' | '!' | '?'
            )
        })
    {
        return None;
    }
    let k = enclosed_layer(view, input, layer, &context.quotes, close, q)?;
    Some((k, after))
}

fn prose_segment(
    view: &View,
    input: &str,
    layer: &Spaced,
    start: usize,
    line_end: usize,
    context: &ProseContext,
) -> ProseStep {
    let ProseContext { prefix, cue, .. } = *context;
    let enclosed = cue != Cue::Word;
    let text: &str = &layer.text;
    let Some(open) = text[start..].chars().next() else {
        return ProseStep::Done(None, None);
    };
    // The first quote at or after `from` on the line that closes a layer
    // the line opened before the noun (one of the same mark at the same
    // escape level, a `”` for a `“`); with
    // `structural`, only one that structure follows (a JSON string's close
    // before `}` or `,"key":`), so a quote touched by more text fails closed.
    let cap = |from: usize, structural: bool| {
        let mut searches = context.cap.borrow_mut();
        let mut first: Option<usize> = None;
        for &(open, level) in &context.quotes {
            let close = match open {
                '“' => '”',
                '"' | '\'' | '`' => open,
                _ => continue,
            };
            // A later search for the same quote reuses the last one when no
            // close lies between: nothing was found from an earlier
            // position, or what was found lies at or after this one.
            let last = searches.iter().position(|s| {
                s.quote == (open, level) && s.structural == structural && s.line_end == line_end
            });
            let found = match last.map(|n| &searches[n]) {
                Some(s) if s.from <= from && s.found.is_none_or(|p| p >= from) => s.found,
                _ => {
                    let found = text[from..line_end.max(from)]
                        .match_indices(close)
                        .map(|(i, _)| from + i)
                        .find(|&p| {
                            (close == '”' || quote_level(view, input, layer, p, close) == level)
                                && (!structural
                                    || structural_end(&text[p + close.len_utf8()..line_end]))
                        });
                    let search = CapSearch {
                        quote: (open, level),
                        structural,
                        line_end,
                        from,
                        found,
                    };
                    match last {
                        Some(n) => searches[n] = search,
                        None => {
                            // Distinct quotes and line ends are few; bound
                            // the list anyway.
                            if searches.len() >= 64 {
                                searches.clear();
                            }
                            searches.push(search);
                        }
                    }
                    found
                }
            };
            first = match (first, found) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        }
        first
    };
    let close = match open {
        '\'' | '"' | '`' => open,
        '“' => '”',
        '‘' => '’',
        _ => {
            // A bare value never runs over the close of an enclosing quote:
            // after a colon or equals cue the first one ends it; after a word
            // cue only one that structure follows.
            let found = cap(start, cue == Cue::Word);
            let end = found.unwrap_or(line_end);
            if end <= start {
                return ProseStep::Done(None, None);
            }
            return ProseStep::Done(
                unquoted_prose_value(
                    text,
                    start,
                    end,
                    prefix,
                    cue,
                    innermost(context.brackets, false),
                    context.tables,
                )
                .map(|(r, exempt)| {
                    let range = (prose_source(view, layer, &r), layer.start(r.start), r.end);
                    if exempt {
                        Part::Exempt(range)
                    } else {
                        Part::Value(range)
                    }
                }),
                found,
            );
        }
    };
    let inner = start + open.len_utf8();
    let mut limit = (inner + 1024).min(text.len());
    while !text.is_char_boundary(limit) {
        limit -= 1;
    }
    let spelling = |p: usize| {
        let v = layer.start(p);
        &input[view.source_start(v)..view.source_end(v)]
    };
    // Prefer a close on the same line; a quoted value may span lines up to
    // the bound. An unmatched quote fails closed through the end of the line.
    // `end` is the close's layer position, `value_end` the source end of the
    // value: backslashes before the close's own escape are value bytes.
    // The value never runs past the close of an enclosing layer: no close
    // beyond it is this value's, and an unterminated value ends before it.
    let bound = cap(inner, true);
    let found = if open == close {
        let opener = quote_escape(view, input, layer.start(start), open);
        text[inner..bound.unwrap_or(line_end.max(limit))]
            .match_indices(close)
            .map(|(n, _)| inner + n)
            // After a colon or equals cue, a quote that opens a later line's
            // own assignment (`note="`) is not this value's close.
            .filter(|&p| !enclosed || p < line_end || !text[..p].trim_end().ends_with(['=', ':']))
            .find_map(|p| {
                let candidate = quote_escape(view, input, layer.start(p), close);
                closes(
                    opener.map(|o| o.1),
                    candidate.map(|c| c.1),
                    spelling(start),
                    spelling(p),
                )
                .then(|| {
                    let value_end = match (opener, candidate) {
                        (Some((_, l)), Some((at, _))) => {
                            at - ((1usize << l.trailing_ones().min(31)) - 1)
                        }
                        _ => view.source_start(layer.start(p)),
                    };
                    (p, value_end)
                })
            })
    } else if let Some(bound) = bound {
        text[inner..bound]
            .find(close)
            .map(|n| (inner + n, view.source_start(layer.start(inner + n))))
    } else {
        text[inner..line_end.max(inner)]
            .find(close)
            .or_else(|| text[inner..limit].find(close))
            .map(|n| (inner + n, view.source_start(layer.start(inner + n))))
    };
    let Some((end, value_end)) = found else {
        let line_end = bound.unwrap_or(line_end);
        // A redacted value is already scrubbed. After a colon or equals cue
        // the opening quote stays, as it does for a sensitive assignment.
        if text[inner..line_end.max(inner)]
            .trim_start()
            .starts_with(REDACTION_TOKEN)
        {
            return ProseStep::Done(None, None);
        }
        let probe = if inner < line_end { inner } else { start };
        let from = if enclosed && inner < line_end {
            inner
        } else {
            start
        };
        if from >= line_end {
            return ProseStep::Done(None, None);
        }
        return ProseStep::Done(
            Some(Part::Value((
                prose_source(view, layer, &(from..line_end)),
                layer.start(probe),
                line_end,
            ))),
            bound,
        );
    };
    let value_start = view.source_start(layer.start(inner));
    // Text that touches the close with no whitespace (`"abc"defq`, `""abc`)
    // is the same value, up to the next whitespace, unless it is only
    // sentence or list punctuation (`"abc".`, `"abc";`). A quoted segment in
    // that text (`"abc""def"`, `"abc"'def'`, `"abc"de"f"`) continues the
    // value: the whole run is one value, and an unmatched segment fails
    // closed as above. A segment may open with any quote mark at any escape
    // level (`"abc"'def'`, `"abc"\"def\"`, `\"abc\"'def'` in a JSON string);
    // only a quote that closes a layer the line opened before the noun (the
    // JSON string's own close, the `"` of `echo "pw is 'x'"`) ends the run,
    // as does the close of the innermost bracket the line opened before the
    // noun.
    //
    // A field after the quoted value ends it too: a `,` `;` or `&` before a
    // key-like field (`password="abc",user="bob"`), or the close of a tag
    // the line opened before the noun (`<a password="abc">`).
    let after = end + close.len_utf8();
    let (run, how) = touching_run(view, input, layer, after, context);
    ProseStep::Segment(
        QuotedSegment {
            inner,
            end,
            after,
            run,
            value_start,
            value_end,
        },
        how,
    )
}

// The run of text touching a close at `after`, and how it ends (see
// `prose_segment`).
fn touching_run(
    view: &View,
    input: &str,
    layer: &Spaced,
    after: usize,
    context: &ProseContext,
) -> (usize, RunEnd) {
    let text: &str = &layer.text;
    let encloses =
        |p: usize, q: char| enclosed_layer(view, input, layer, &context.quotes, p, q).is_some();
    let bracket = innermost(context.brackets, false);
    let rest = &text[after.min(text.len())..];
    let field = rest.starts_with([',', ';', '&']) && key_like(&rest[1..])
        || (rest.starts_with('>') || rest.starts_with("/>"))
            && innermost(context.tagged, true) == Some('<');
    let mut run = after.min(text.len());
    // A bracket the run opens (`${defq}`) is closed inside it.
    let mut nested = Vec::new();
    while let Some(q) = text[run..].chars().next().filter(|_| !field) {
        match q {
            '(' | '[' | '{' => nested.push(q),
            ')' | ']' | '}' if nested.last() == Some(&bracket_opener(q)) => {
                nested.pop();
                run += 1;
                continue;
            }
            _ => {}
        }
        if q.is_whitespace() || matches!(q, ')' | ']' | '}') && Some(bracket_opener(q)) == bracket {
            break;
        }
        if matches!(q, '\'' | '"' | '`' | '“' | '‘' | '”') && !apostrophe(text, run) {
            if q == '”' && !encloses(run, q) {
                run += q.len_utf8();
                continue;
            }
            if encloses(run, q) {
                return (run, RunEnd::Encloses);
            }
            return (run, RunEnd::Continues);
        }
        run += q.len_utf8();
    }
    (run, RunEnd::Stop)
}

// The value of a closed quoted segment that no further segment joins: the
// quoted text and any non-punctuation text touching its close.
// A reference or placeholder is exempt, as a part of the run.
fn finish_quoted(view: &View, layer: &Spaced, segment: &QuotedSegment) -> Option<Part> {
    let text: &str = &layer.text;
    let QuotedSegment {
        inner,
        end,
        after,
        run,
        value_start,
        value_end,
    } = *segment;
    let tail = &text[after.min(run)..run];
    if tail
        .chars()
        .any(|c| !matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}' | '>'))
    {
        let kept = tail.strip_suffix(['.', ',', ';']).unwrap_or(tail);
        let tail_end = after + kept.len();
        return Some(Part::Value((
            value_start..prose_source(view, layer, &(after..tail_end)).end,
            layer.start(inner),
            tail_end,
        )));
    }
    let value = text[inner..end].trim();
    if value_end <= value_start
        || value.is_empty() && value_end == view.source_start(layer.start(end))
    {
        return None;
    }
    let range = (value_start..value_end, layer.start(inner), end);
    Some(if whole_reference(value) {
        Part::Exempt(range)
    } else {
        Part::Value(range)
    })
}

// A Python-style condition (`if password is None`) compares, not discloses.
fn code_condition(prefix: &str) -> bool {
    let word = prefix
        .trim_end()
        .rsplit(|c: char| !c.is_ascii_alphabetic())
        .next()
        .unwrap_or("");
    [
        "if", "elif", "while", "assert", "and", "or", "not", "return", "lambda",
    ]
    .contains(&word)
}

fn unquoted_prose_value(
    text: &str,
    start: usize,
    mut line_end: usize,
    prefix: &str,
    cue: Cue,
    bracket: Option<char>,
    tables: &ValueTables,
) -> Option<(Range<usize>, bool)> {
    let assigned = cue != Cue::Word;
    // The caller ends the value at an enclosing quote's close (an HTML
    // attribute, a shell argument, a JSON string).
    if assigned {
        // A bare value inside brackets ends at the close of the innermost bracket
        // the line opened before the key and left open, in the key's own
        // string layer: after a bare cue too, `pw: x]yq` and `my password:
        // ab)cd` keep the close, and so do `(note pw: x]yq` and a JSON
        // object's own `}` around the string that holds the key.
        if let Some(opener) = bracket {
            let found = tables
                .closes
                .get_or_init(|| BracketCloses::new(text))
                .first(start, opener);
            if let Some(close) = found.filter(|&p| p < line_end) {
                line_end = close;
            }
        }
        // And one inside a `;` or `&` separated key/value list (a connection
        // string, a query) at the separator before the next key, but only on a
        // line that was already such a list before the key: the key starts
        // right after a key=value item ended by that same separator. `pw:
        // abc&def=ghi`, `R&D pw: abc&def=ghi` and `note; pw: abc;host=y` are
        // one value.
        if let Some(sep) = list_separator(prefix) {
            let keys = tables.lists.get_or_init(|| ListKeys::new(text));
            if let Some(n) = keys.first(sep, start, line_end) {
                line_end = n;
            }
        }
        if line_end <= start {
            return None;
        }
    }
    // Documentary predicates are decided by the first word or two.
    const PREDICATES: &[&str] = &[
        "required",
        "optional",
        "mandatory",
        "missing",
        "unset",
        "set",
        "stored",
        "saved",
        "configured",
        "invalid",
        "incorrect",
        "wrong",
        "correct",
        "valid",
        "strong",
        "weak",
        "changed",
        "reset",
        "expired",
        "expire",
        "expires",
        "expiring",
        "rotated",
        "updated",
        "redacted",
        "hidden",
        "masked",
        "empty",
        "blank",
        "null",
        "nil",
        "none",
        "undefined",
        "unknown",
        "secure",
        "insecure",
        "compromised",
        "protected",
        "encrypted",
        "hashed",
        "salted",
        "generated",
        "needed",
        "used",
        "sensitive",
        "case-sensitive",
        "case-insensitive",
        "leaked",
        "exposed",
        "stolen",
        "cracked",
        "guessed",
        "shared",
        "sent",
        "accepted",
        "rejected",
        "revoked",
        "disabled",
        "enabled",
        "locked",
        "unlocked",
        "deleted",
        "removed",
        "cleared",
        "entered",
        "typed",
        "provided",
        "supplied",
        "given",
        "accepted",
        "verified",
        "checked",
        "validated",
        "displayed",
        "shown",
        "logged",
        "printed",
        "visible",
        "known",
        "forgotten",
        "lost",
        "too",
        "long",
        "short",
        "longer",
        "shorter",
        "ok",
        "okay",
        "fine",
        "good",
        "bad",
        "same",
        "different",
        "it",
        "this",
        "that",
        "here",
        "there",
        "below",
        "above",
        "following",
        "what",
        "which",
        "who",
        "mine",
        "yours",
        "ours",
        "theirs",
        "default",
        "unchanged",
        "incomplete",
        "complete",
        "ready",
        "pending",
        "available",
        "unavailable",
        "random",
        "temporary",
        "permanent",
        "unique",
        "personal",
        "private",
        "reused",
        "recycled",
        "persisted",
        "expected",
        "based",
        "outdated",
        "obsolete",
        "deprecated",
    ];
    // Determiners, prepositions and adverbs lead a documentary phrase when
    // more words follow; alone they may be the value (`my password is a`).
    const LEADS: &[&str] = &[
        "the", "a", "an", "this", "that", "these", "those", "your", "my", "our", "their", "his",
        "her", "its", "in", "on", "at", "for", "from", "by", "with", "of", "to", "under", "into",
        "not", "never", "also", "still", "now", "just", "only", "always", "being", "been",
        "usually", "often", "going", "about", "like", "more", "less", "least", "most", "exactly",
        "no", "any", "some", "all", "each", "every", "one", "two", "how", "where", "when",
        "managed", "kept", "sent", "set", "see", "refer", "check", "ask", "use", "contact",
    ];
    // `-able` adjectives and `-ed` participles before a preposition are
    // documentary (`configurable`, `stored in the vault`).
    const PREPOSITIONS: &[&str] = &[
        "to", "on", "in", "by", "with", "for", "from", "at", "as", "into", "using", "via",
    ];
    const UNITS: &[&str] = &[
        "character",
        "characters",
        "chars",
        "char",
        "digit",
        "digits",
        "letter",
        "letters",
        "byte",
        "bytes",
        "symbol",
        "symbols",
        "word",
        "words",
        "long",
    ];
    const CONJUNCTIONS: &[&str] = &[
        "and", "but", "so", "then", "because", "which", "or", "though", "although", "while",
        "when", "if", "unless", "until", "since",
    ];
    // A bracketed placeholder may contain spaces: `{{ password }}`. It, or a
    // run of them (`${A}${B}`), is exempt only when nothing is glued after
    // it; `${defq}abc` is one value.
    let line = &text[start..line_end];
    let mut placeholders = 0;
    while let Some(n) = [("${{", "}}"), ("{{", "}}"), ("<", ">"), ("${", "}")]
        .iter()
        .find_map(|(open, close)| {
            let rest = &line[placeholders..];
            rest.strip_prefix(open)?;
            let n = rest.find(close)? + close.len();
            prose_reference(&rest[..n]).then_some(n)
        })
    {
        placeholders += n;
    }
    if placeholders > 0 && separated(&line[placeholders..]) {
        return Some((start..start + placeholders, true));
    }
    let words = text[start..line_end]
        .split(|c: char| c != '\n' && c.is_whitespace())
        .filter(|w| !w.is_empty());
    let mut end = start;
    let mut cursor = start;
    // Brackets the value opened and has not closed: a comma or semicolon
    // inside them (`Map<String, u8>`, `(abc, def)`) does not end the value.
    let mut open = 0usize;
    for (i, word) in words.enumerate() {
        let at = cursor + text[cursor..].find(word).expect("word in line");
        cursor = at + word.len();
        // An arrow's `>` (`=>`, `->`) closes nothing: `pw: match a { b => c,
        // d => e }` is one value.
        let mut previous = None;
        for ch in word.chars() {
            match ch {
                '<' | '(' | '[' | '{' => open += 1,
                '>' if matches!(previous, Some('=' | '-')) => {}
                '>' | ')' | ']' | '}' => open = open.saturating_sub(1),
                _ => {}
            }
            previous = Some(ch);
        }
        let bare = word.trim_end_matches(['.', ',', ';', ':', '!', '?']);
        let lower = bare.to_ascii_lowercase();
        // A colon or equals cue assigns its whole value, as `password:
        // required` always has: only references, a lone null and code types
        // (checked by the caller) are exempt, and conjunctions belong to the
        // value.
        let reference = word.trim_end_matches(['.', ',', ';']);
        if i == 0 && whole_reference(reference) {
            let reference = if reference.starts_with(REDACTION_TOKEN) {
                REDACTION_TOKEN
            } else {
                reference
            };
            return Some((at..at + reference.len(), true));
        }
        if i == 0 && assigned {
            let only = text[cursor..line_end].trim().is_empty();
            if only && matches!(lower.as_str(), "none" | "null" | "nil" | "undefined") {
                return None;
            }
        } else if i == 0 {
            let more = text[cursor..line_end].split_whitespace().next();
            let lexical = lower.len() >= 5 && lower.bytes().all(|b| b.is_ascii_lowercase());
            if PREDICATES.contains(&lower.as_str())
                || lexical && (lower.ends_with("able") || lower.ends_with("ible"))
                || lexical
                    && lower.ends_with("ed")
                    && more.is_some_and(|m| PREPOSITIONS.contains(&m.to_ascii_lowercase().as_str()))
                || more.is_some() && LEADS.contains(&lower.as_str())
                || !bare.is_empty()
                    && bare.bytes().all(|b| b.is_ascii_digit())
                    && more.is_some_and(|m| {
                        UNITS.contains(
                            &m.trim_end_matches(['.', ',', ';'])
                                .to_ascii_lowercase()
                                .as_str(),
                        )
                    })
            {
                return None;
            }
        } else if !assigned && CONJUNCTIONS.contains(&lower.as_str()) {
            break;
        }
        end = cursor;
        if open == 0 && word.ends_with([',', ';', '.']) {
            break;
        }
    }
    // One mark of sentence punctuation after the value is kept, unless the
    // value is only punctuation; any further marks belong to the value.
    let value = &text[start..end];
    let trimmed = value.strip_suffix(['.', ',', ';']).unwrap_or(value);
    let mut end = start
        + if trimmed.trim_end_matches(['.', ',', ';']).is_empty() {
            value.len()
        } else {
            trimmed.len()
        };
    // Only the innermost bracket opened before the disclosure closes after it.
    if let Some(open) = bracket {
        let close = match open {
            '(' => ')',
            '[' => ']',
            _ => '}',
        };
        let value = &text[start..end];
        if value.len() > 1
            && value.ends_with(close)
            && value.matches(open).count() < value.matches(close).count()
        {
            end -= 1;
        }
    }
    (end > start).then_some((start..end, false))
}

// The text after a placeholder leaves it whole: nothing, a space, or
// sentence punctuation that ends the value.
fn separated(rest: &str) -> bool {
    let mut chars = rest.chars();
    match chars.next() {
        None => true,
        Some(c) if c.is_whitespace() => true,
        Some('.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}') => {
            chars.next().is_none_or(char::is_whitespace)
        }
        _ => false,
    }
}

fn bracket_opener(close: char) -> char {
    match close {
        ')' => '(',
        ']' => '[',
        _ => '{',
    }
}

// Where a scan that starts at a position with nothing open first meets a
// close of a given bracket type: a bracket opened on the way is skipped
// through its own close (a close of another type closes nothing, inside it or
// outside), and one never closed ends the scan with no close found. A scan
// from an opener's next position for its own type finds that opener's close,
// so the table is built once from the right over the text's brackets, and
// each bare value's lookup is a binary search instead of a scan to its line
// end.
struct BracketCloses {
    // Positions of the text's brackets, ascending.
    at: Vec<usize>,
    // For each bracket index (and one past the last), the index in `at` of
    // the close a scan from there meets, per type in `bracket_type` order;
    // `usize::MAX` when there is none.
    first: Vec<[usize; 3]>,
}

fn bracket_type(c: u8) -> usize {
    match c {
        b'(' | b')' => 0,
        b'[' | b']' => 1,
        _ => 2,
    }
}

impl BracketCloses {
    fn new(text: &str) -> Self {
        let b = text.as_bytes();
        let at: Vec<usize> = (0..b.len())
            .filter(|&i| matches!(b[i], b'(' | b'[' | b'{' | b')' | b']' | b'}'))
            .collect();
        let mut first = vec![[usize::MAX; 3]; at.len() + 1];
        for i in (0..at.len()).rev() {
            let c = b[at[i]];
            first[i] = if matches!(c, b')' | b']' | b'}') {
                let mut row = first[i + 1];
                row[bracket_type(c)] = i;
                row
            } else {
                match first[i + 1][bracket_type(c)] {
                    usize::MAX => [usize::MAX; 3],
                    close => first[close + 1],
                }
            };
        }
        Self { at, first }
    }

    // The first close of `opener`'s type a scan from `from` meets.
    fn first(&self, from: usize, opener: char) -> Option<usize> {
        let i = self.at.partition_point(|&p| p < from);
        let close = self.first[i][bracket_type(opener as u8)];
        (close != usize::MAX).then(|| self.at[close])
    }
}

// The innermost bracket (or, with `tags`, tag: `<a`, `</a`, closed by `>`)
// a stack of `Openers` leaves open in its last string layer: a quote opened
// after it hides it, and a close only closes a bracket of its own type
// opened in the same layer.
fn innermost(stack: &[char], tags: bool) -> Option<char> {
    stack
        .last()
        .copied()
        .filter(|&c| matches!(c, '(' | '[' | '{') || tags && c == '<')
}

// The quotes, brackets and (with `tags`) tags a line's text opens and leaves
// open, innermost last, built left to right from the line start. Matches on a
// line come in order, so the state advances from one match to the next
// instead of being rebuilt from the line start for each. The innermost entry
// of each mark is kept, with a link from each entry to the one below it of
// the same mark, so finding the entry a quote or bracket closes never scans
// the stack.
struct Openers {
    tags: bool,
    stack: Vec<char>,
    below: Vec<Option<usize>>,
    top: [Option<usize>; 8],
    // Where the scan stopped, the run of backslashes just before it and the
    // character before it.
    done: usize,
    slashes: usize,
    prev: Option<char>,
}

const OPENER_MARKS: [char; 8] = ['"', '`', '\'', '“', '(', '[', '{', '<'];

fn opener_slot(c: char) -> usize {
    OPENER_MARKS.iter().position(|&m| m == c).unwrap_or(0)
}

impl Openers {
    fn new(tags: bool, start: usize) -> Self {
        Self {
            tags,
            stack: Vec::new(),
            below: Vec::new(),
            top: [None; 8],
            done: start,
            slashes: 0,
            prev: None,
        }
    }

    fn push(&mut self, c: char) {
        let slot = opener_slot(c);
        self.below.push(self.top[slot]);
        self.top[slot] = Some(self.stack.len());
        self.stack.push(c);
    }

    fn truncate(&mut self, at: usize) {
        while self.stack.len() > at {
            if let (Some(c), Some(below)) = (self.stack.pop(), self.below.pop()) {
                self.top[opener_slot(c)] = below;
            }
        }
    }

    // Where the open quote mark `q` sits on the stack: each quote mark is
    // there at most once, since a second one closes the first.
    fn quote_at(&self, q: char) -> Option<usize> {
        self.top[opener_slot(q)]
    }

    // Scans `text[self.done..to]`. A `<` is a tag only when a letter or `/`
    // follows it inside the scanned text, so a `<` that ends the range is
    // left for the next advance: alone it opens nothing.
    fn advance(&mut self, text: &str, to: usize) {
        let from = self.done;
        for (i, ch) in text[from..to].char_indices() {
            let p = from + i;
            if self.tags && ch == '<' && p + 1 == to {
                self.done = p;
                return;
            }
            let escaped = self.slashes % 2 == 1;
            match ch {
                '"' | '`' | '\'' | '“' | '”' if !escaped => {
                    let open = if ch == '”' { '“' } else { ch };
                    if let Some(at) = self.top[opener_slot(open)] {
                        self.truncate(at);
                    } else if ch != '”'
                        && !(ch == '\'' && self.prev.is_some_and(char::is_alphanumeric))
                    {
                        self.push(ch);
                    }
                }
                '(' | '[' | '{' => self.push(ch),
                '<' if self.tags
                    && text[p + 1..to]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic() || c == '/') =>
                {
                    self.push(ch);
                }
                ')' | ']' | '}' | '>' if ch != '>' || self.tags => {
                    // Only a bracket opened inside the innermost open quote.
                    let floor = self.top[..4].iter().flatten().max().map_or(0, |q| q + 1);
                    let opener = if ch == '>' { '<' } else { bracket_opener(ch) };
                    if let Some(at) = self.top[opener_slot(opener)].filter(|&at| at >= floor) {
                        self.truncate(at);
                    }
                }
                _ => {}
            }
            self.slashes = if ch == '\\' { self.slashes + 1 } else { 0 };
            self.prev = Some(ch);
        }
        self.done = to;
    }
}

// The separator of the key/value list the text ends inside: it ends with
// `;` or `&` (and spaces) right after a `key=value` item.
fn list_separator(prefix: &str) -> Option<char> {
    let head = prefix.trim_end_matches(' ');
    let sep = head
        .chars()
        .next_back()
        .filter(|c| matches!(c, ';' | '&'))?;
    let before = &head[..head.len() - 1];
    let item = before.rsplit(sep).next().unwrap_or(before).trim();
    let last = item
        .rsplit(|c: char| c.is_whitespace() || c == '?')
        .next()
        .unwrap_or(item);
    (item.contains('=') && (next_list_key(item) || next_list_key(last))).then_some(sep)
}

// `Key=` or `User Id=` (not `==`) starts the next entry of a key/value list.
fn next_list_key(rest: &str) -> bool {
    let rest = rest.trim_start_matches(' ');
    let Some(eq) = rest.find('=') else {
        return false;
    };
    let key = &rest[..eq];
    eq <= 40
        && !rest[eq + 1..].starts_with('=')
        && key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b' '))
}

// Every `;` and `&` of a text that `next_list_key` could accept, so finding
// where a bare value's list item ends is a binary search instead of a scan
// to the line end. For a separator at `i` that the text after it could start
// a key after, `e` is the key's `=`: the first `=` after `i`, so it never
// decreases as `i` grows. Cut at a line end `l`, the text after `i` starts a
// key exactly when `e < l`, and when an `=` follows `e` (`==`) only if the
// cut falls right after `e`.
struct ListKeys {
    // Per separator (`;`, `&`): `(i, e)` with no `=` after `e`, and with one.
    single: [Vec<(usize, usize)>; 2],
    double: [Vec<(usize, usize)>; 2],
}

impl ListKeys {
    fn new(text: &str) -> Self {
        let b = text.as_bytes();
        let mut keys = Self {
            single: [Vec::new(), Vec::new()],
            double: [Vec::new(), Vec::new()],
        };
        for i in 0..b.len() {
            let slot = match b[i] {
                b';' => 0,
                b'&' => 1,
                _ => continue,
            };
            let mut t = i + 1;
            while b.get(t) == Some(&b' ') {
                t += 1;
            }
            let window = &b[t..(t + 41).min(b.len())];
            let Some(eq) = window.iter().position(|&c| c == b'=') else {
                continue;
            };
            let key = &window[..eq];
            if !key
                .first()
                .is_some_and(|&c| c.is_ascii_alphabetic() || c == b'_')
                || !key
                    .iter()
                    .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b' '))
            {
                continue;
            }
            let e = t + eq;
            if b.get(e + 1) == Some(&b'=') {
                keys.double[slot].push((i, e));
            } else {
                keys.single[slot].push((i, e));
            }
        }
        keys
    }

    // The first `sep` in `text[start..line_end]` that `next_list_key` accepts
    // with the text after it cut at `line_end`.
    fn first(&self, sep: char, start: usize, line_end: usize) -> Option<usize> {
        if line_end <= start {
            return None;
        }
        let slot = usize::from(sep != ';');
        let single = &self.single[slot];
        let a = single
            .get(single.partition_point(|&(i, _)| i < start))
            .filter(|&&(_, e)| e < line_end)
            .map(|&(i, _)| i);
        let double = &self.double[slot];
        let b = double
            .get(double.partition_point(|&(i, e)| i < start || e + 1 < line_end))
            .filter(|&&(_, e)| e + 1 == line_end)
            .map(|&(i, _)| i);
        match (a, b) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

// Placeholders, masks and variable references name a password, not disclose it.
fn prose_reference(value: &str) -> bool {
    value.starts_with(REDACTION_TOKEN)
        || shell_reference(value)
        || environment_reference(value)
        || template_reference(value)
        || value.chars().count() >= 3 && value.chars().all(|c| matches!(c, '*' | '•' | '●'))
        || (value.starts_with("{{") || value.starts_with("${{")) && value.ends_with("}}")
        || value.starts_with('<') && value.ends_with('>') && value.len() > 2
        || value.len() > 2 && value.starts_with('%') && value.ends_with('%')
        || value.strip_prefix("$env:").is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        || value.strip_prefix("YOUR_").is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        })
        || value.starts_with("op://")
}

// Whether the layer text at `at` starts with a placeholder, mask or marker
// (`<x>`, `%X%`, `{{x}}`, `***`, `[REDACTED]`), which is part of a value it
// touches. Only the text up to the next space counts; `marks` finds that
// space and a placeholder's close without scanning the rest of the line, so
// a line of many quoted keys and no spaces stays linear.
fn reference_prefix(text: &str, at: usize, marks: &std::cell::OnceCell<ReferenceMarks>) -> bool {
    let rest = &text[at..];
    // Neither the marker nor a mask holds a space, so the text up to the
    // next space starts with one exactly when the rest does.
    if rest.starts_with(REDACTION_TOKEN)
        || rest
            .chars()
            .take_while(|c| matches!(c, '*' | '•' | '●'))
            .take(3)
            .count()
            >= 3
    {
        return true;
    }
    let closed = |open: &str, close: usize| {
        if !rest.starts_with(open) {
            return false;
        }
        let marks = marks.get_or_init(|| ReferenceMarks::new(text));
        let Some(found) = marks.next(close, at + open.len()) else {
            return false;
        };
        // A close counts only before the next space; no close spans one.
        if marks
            .next(ReferenceMarks::SPACE, at)
            .is_some_and(|space| space < found)
        {
            return false;
        }
        let end = found + [0, 1, 1, 2][close];
        // `<…>` and `%…%` longer than two characters, and any `{{…}}`, are
        // references; only the short ones need the full check.
        end - at > 4 || prose_reference(&text[at..end])
    };
    closed("<", ReferenceMarks::ANGLE)
        || closed("%", ReferenceMarks::PERCENT)
        || closed("{{", ReferenceMarks::BRACES)
}

// Positions of whitespace, `>`, `%` and `}}` in a layer, so the next one
// after any position is a binary search.
struct ReferenceMarks {
    at: [Vec<usize>; 4],
}

impl ReferenceMarks {
    const SPACE: usize = 0;
    const ANGLE: usize = 1;
    const PERCENT: usize = 2;
    const BRACES: usize = 3;

    fn new(text: &str) -> Self {
        let mut at: [Vec<usize>; 4] = Default::default();
        for (i, c) in text.char_indices() {
            match c {
                '>' => at[Self::ANGLE].push(i),
                '%' => at[Self::PERCENT].push(i),
                '}' if text[i + 1..].starts_with('}') => at[Self::BRACES].push(i),
                c if c.is_whitespace() => at[Self::SPACE].push(i),
                _ => {}
            }
        }
        Self { at }
    }

    fn next(&self, kind: usize, from: usize) -> Option<usize> {
        let list = &self.at[kind];
        list.get(list.partition_point(|&p| p < from)).copied()
    }
}

// A reference or placeholder that is the whole value, with nothing literal
// glued to it: `[REDACTED]abc` and `<a>abc<b>` are values.
fn whole_reference(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix(REDACTION_TOKEN) {
        return rest.starts_with(char::is_whitespace)
            || rest.chars().all(|c| c.is_ascii_punctuation() && c != '$');
    }
    let inner = |open: &str, close: &str| {
        value
            .strip_prefix(open)
            .and_then(|v| v.strip_suffix(close))
            .is_some_and(|v| !v.contains(close) && !v.contains(open))
    };
    if value.starts_with("${{") {
        return inner("${{", "}}") && prose_reference(value);
    }
    if value.starts_with("{{") {
        return inner("{{", "}}") && prose_reference(value);
    }
    if value.starts_with('<') && value.ends_with('>') {
        return inner("<", ">");
    }
    if value.starts_with('%') && value.ends_with('%') && value.len() > 2 {
        return inner("%", "%");
    }
    if value.starts_with("op://") {
        return !value.contains(['"', '\'', '`', ' ']);
    }
    prose_reference(value)
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
        || ["project_key", "project-key", "projectkey"]
            .iter()
            .any(|exact| name.eq_ignore_ascii_case(exact))
            && repository_identity(value)
}

/// A normalized repository identity as session capture records it under an exact
/// `project_key`: `host.tld/owner/repo`, optionally with up to six more group
/// segments (`gitlab.com/group/sub/repo`). The host is dotted DNS labels with an
/// alphabetic top-level label; each path segment is ASCII letters, digits, `.`, `_`
/// or `-`, never `.` or `..`. A scheme, userinfo, port, query, percent or other
/// encoding, a local path, a single opaque token (a vendor "project key" such as
/// `c0ab12_...`), a hex segment of 20 or more digits, a segment piece (between `.`,
/// `_` or `-`) of 16 or more characters with a digit in it, or any generated-looking
/// atom keeps the value sensitive. Only the exact names `project_key`, `project-key`
/// and `projectKey` (any case) qualify; `project__key` or a prefixed name does not.
/// Like every
/// field reference, text assignments are judged on the decoded recognition view (so a
/// percent-spelled `/` reads as `/`); structured property values are judged literally.
fn repository_identity(value: &str) -> bool {
    if value.len() > 512 || opaque_material(value) {
        return false;
    }
    let mut parts = value.split('/');
    let host = parts.next().unwrap_or("");
    let labels: Vec<&str> = host.split('.').collect();
    let host_ok = host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_alphabetic()));
    let segments: Vec<&str> = parts.collect();
    host_ok
        && (2..=8).contains(&segments.len())
        && segments.iter().all(|s| {
            !s.is_empty()
                && s.len() <= 100
                && *s != "."
                && *s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                // A long lowercase hex run is digest or token material, not a name.
                && !(s.len() >= 20 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                // So is a long piece mixing letters and digits (`abc12def34ghi56jkl78`):
                // repository names split long words with `-`, `_` or `.`.
                && !s
                    .split(['.', '_', '-'])
                    .any(|piece| piece.len() >= 16 && piece.bytes().any(|b| b.is_ascii_digit()))
        })
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
    if ["relay_ag_", "relay_pa_", "relay_ws_", "relay_id_"]
        .iter()
        .any(|p| value.starts_with(p))
    {
        let prefix = bounded_prefix(view, start).trim();
        let tail = &view.text[end..view.line_end(end)];
        return matches!(prefix, "use" | "pub use")
            && value[9..].contains('_')
            && value[9..]
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_')
            && tail.trim() == ";";
    }
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

// Apply complete-value reference grammar in both normal and recovered queries.
// The whole parameter must match; whitespace, comments and literal tails never
// establish an exemption. Bound grammar work independently of parameter size.
fn query_reference(value: &str) -> bool {
    if value.len() > 512 {
        return false;
    }
    let value = value.trim_end();
    let variable = value.strip_prefix('$').map(|name| {
        name.strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(name)
    });
    reference(value)
        || shell_reference(value)
            && variable.is_some_and(|name| {
                name.as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        || environment_reference(value)
        || value.starts_with("${{") && symbolic_arguments(value) && expansion_reference(value)
        || value
            .strip_prefix('`')
            .and_then(|s| s.strip_suffix('`'))
            .is_some_and(|s| symbolic_arguments(s) && template_reference(s))
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
        let whole = &view.text[value_start..parameter_end];
        if value_end > value_start && !query_reference(whole) {
            // A reference prefix cannot hide literal data after whitespace.
            if whole.starts_with(['$', '`', '*'])
                || query_reference(&view.text[value_start..value_end])
            {
                value_end = parameter_end;
            }
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
                    let is_reference = query_reference(&view.text[eq + 1..parameter_end]);
                    // A URL's whitespace boundary is not proof that a symbolic
                    // credential has ended. Inspect its local parameter suffix;
                    // never exempt a reference prefix followed by literal data.
                    let mut complete = parameter_end;
                    let reference_candidate = is_reference
                        || view.text[eq + 1..parameter_end].starts_with(['$', '`', '*']);
                    if reference_candidate && complete == end {
                        let limit = view.line_end(complete);
                        while complete < limit
                            && b[complete] != b'?'
                            && query_separator(view, complete) == 0
                        {
                            complete = query_next(b, complete);
                        }
                    }
                    if !is_reference || !view.text[parameter_end..complete].trim().is_empty() {
                        spans.push(eq + 1..complete);
                    }
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

// Protocol-relative authorities also occur outside HTML. Consume each authority
// once, stopping before paths/queries so a later // cannot repeat its suffix.
fn relative_userinfo(view: &View, spans: &mut Vec<Range<usize>>) {
    if !view.text.contains('@') {
        return;
    }
    let b = view.text.as_bytes();
    let mut cursor = 0;
    while cursor + 1 < b.len() {
        if !matches!(b[cursor], b'/' | b'\\') || !matches!(b[cursor + 1], b'/' | b'\\') {
            cursor += 1;
            continue;
        }
        let slash = cursor;
        cursor += 2;
        let authority = cursor;
        let encoded_authority = !view.literal(slash) && !view.literal(slash + 1);
        let boundary = |p| encoded_authority || view.literal(p);
        if b.get(slash.wrapping_sub(1)) == Some(&b':') {
            let mut scheme = slash - 1;
            while scheme > slash.saturating_sub(33)
                && scheme > 0
                && (b[scheme - 1].is_ascii_alphanumeric()
                    || matches!(b[scheme - 1], b'+' | b'.' | b'-'))
            {
                scheme -= 1;
            }
            if url_regex_source(view, scheme, authority) {
                continue;
            }
        }
        while cursor < b.len()
            && !(boundary(cursor) && b[cursor].is_ascii_whitespace())
            && !(boundary(cursor)
                && matches!(
                    b[cursor],
                    b'/' | b'\\' | b'?' | b'#' | b'"' | b'\'' | b'`' | b'<' | b'>'
                ))
        {
            // A numeric entity's '#' is not an authority fragment boundary.
            cursor = query_next(b, cursor);
        }
        if let Some(at) = (authority..cursor)
            .rev()
            .find(|&i| b[i] == b'@' && boundary(i))
        {
            if let Some(colon) = (authority..at).find(|&i| b[i] == b':' && boundary(i)) {
                if colon + 1 < at
                    && !documentation_url(&view.text[colon + 1..at], &view.text[at + 1..cursor])
                {
                    spans.push(colon + 1..at);
                }
            }
        }
    }
}

// An attribute supplies context for bare and single-slash authorities as well
// as // authorities. Tokens keep srcset descriptors and refresh prefixes local.
fn attribute_userinfo(view: &View, spans: &mut Vec<Range<usize>>) -> bool {
    userinfo_at_layer(view, false, &[], spans, &mut Vec::new()).is_some()
}

fn userinfo_at_layer(
    view: &View,
    encoded: bool,
    parents: &[&View],
    spans: &mut Vec<Range<usize>>,
    guards: &mut Vec<Range<usize>>,
) -> Option<usize> {
    let mut authority_found = None;
    let literal = |position| {
        if !view.literal(position) {
            return false;
        }
        let mut source = view.source_start(position);
        for parent in parents.iter().rev() {
            if !parent.literal(source) {
                return false;
            }
            source = parent.source_start(source);
        }
        true
    };
    let b = view.text.as_bytes();
    let mut cursor = 0;
    while cursor < b.len() {
        if literal(cursor)
            && (b[cursor].is_ascii_whitespace() || matches!(b[cursor], b',' | b'"' | b'\''))
        {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < b.len()
            && !(literal(cursor)
                && (b[cursor].is_ascii_whitespace() || matches!(b[cursor], b',' | b'"' | b'\'')))
        {
            cursor += 1;
        }
        let token = &view.text[start..cursor];
        if token
            .get(..7)
            .is_some_and(|s| s.eq_ignore_ascii_case("mailto:"))
        {
            continue;
        }
        let mut authority = start;
        if token
            .get(..4)
            .is_some_and(|s| s.eq_ignore_ascii_case("url="))
        {
            authority += 4;
        }
        let authority_text = &view.text[authority..cursor];
        if authority_text
            .get(..7)
            .is_some_and(|s| s.eq_ignore_ascii_case("mailto:"))
        {
            continue;
        }
        if let Some(colon) = authority_text.find(':') {
            if colon > 0
                && colon <= 32
                && authority_text.as_bytes()[0].is_ascii_alphabetic()
                && authority_text.as_bytes()[..colon]
                    .iter()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'+' | b'.' | b'-'))
                && authority_text
                    .as_bytes()
                    .get(colon + 1)
                    .is_some_and(|ch| matches!(ch, b'/' | b'\\'))
            {
                authority += colon + 1;
            }
        }
        while authority < cursor && matches!(b[authority], b'/' | b'\\') {
            authority += 1;
        }
        let mut prefix_end = authority;
        while prefix_end < cursor && !matches!(b[prefix_end], b'/' | b'\\' | b'?' | b'#' | b'@') {
            prefix_end += 1;
        }
        let colon = (authority..prefix_end).find(|&p| b[p] == b':');
        let mut end = authority;
        while end < cursor {
            if matches!(b[end], b'/' | b'\\' | b'?' | b'#')
                && !(colon.is_some_and(|p| end > p) && (encoded || !literal(end)))
            {
                break;
            }
            end += 1;
        }
        if let Some(at) = (authority..end).rev().find(|&i| b[i] == b'@') {
            authority_found = Some(at);
            // Public userinfo must not suppress an independently recognized
            // sensitive assignment such as password=value@host.
            let assignment = view.text[authority..at]
                .split_once('=')
                .is_some_and(|(key, _)| plain_query_key_sensitive(key));
            if !assignment {
                guards.push(authority..at + 1);
            }
            if let Some(colon) = colon.filter(|&p| p < at) {
                let host_end = (at + 1..end)
                    .find(|&p| matches!(b[p], b'/' | b'\\' | b'?' | b'#'))
                    .unwrap_or(end);
                if colon + 1 < at
                    && !documentation_url(&view.text[colon + 1..at], &view.text[at + 1..host_end])
                {
                    spans.push(colon + 1..at);
                }
            }
        }
    }
    authority_found
}

fn has_network_prefix(text: &str) -> bool {
    let text = text.trim_start();
    text.starts_with("//") || url_regex().find(text).is_some_and(|m| m.start() == 0)
}

fn encoded_network_prefix(text: &str) -> bool {
    if has_network_prefix(text) {
        return true;
    }
    let mut end = text.len().min(512);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut prefix = text[..end].to_owned();
    for _ in 0..=4 {
        let html = View::html_components(&prefix);
        if has_network_prefix(&html.text) {
            return true;
        }
        let next = View::percent_layer(&html.text);
        if next.text == prefix {
            return false;
        }
        prefix = next.text;
    }
    false
}

#[derive(Clone, Copy)]
struct UserinfoLayer {
    percent: usize,
    html: usize,
    network: bool,
    serialized: bool,
    guard_references: bool,
}

fn userinfo_layers(
    view: &View,
    depth: usize,
    guard_references: bool,
    spans: &mut Vec<Range<usize>>,
    guards: &mut Vec<Range<usize>>,
) -> bool {
    let state = UserinfoLayer {
        percent: depth,
        html: 4,
        network: encoded_network_prefix(&view.text),
        serialized: view.text.contains("&%23") || view.text.contains("%26%23"),
        guard_references,
    };
    userinfo_layers_inner(view, state, &[], spans, guards)
}

fn userinfo_layers_inner(
    view: &View,
    state: UserinfoLayer,
    parents: &[&View],
    spans: &mut Vec<Range<usize>>,
    guards: &mut Vec<Range<usize>>,
) -> bool {
    if !state.network || has_network_prefix(&view.text) {
        let mut local = Vec::new();
        let mut bounds = Vec::new();
        if let Some(at) = userinfo_at_layer(view, false, parents, &mut local, &mut bounds) {
            let serialized = state.serialized
                && (view.text.contains("&%23")
                    || view.text.contains("%26%23")
                    || view.text.contains("%3A")
                    || view.text.contains("%3a"));
            if !local.is_empty() || !serialized {
                if let Some(query) = view.text[at + 1..].find('?') {
                    component_query_parameters(
                        view,
                        at + 1 + query,
                        state.percent,
                        state.guard_references,
                        &mut local,
                        &mut bounds,
                    );
                }
                spans.extend(local);
                guards.extend(bounds);
                return true;
            }
        }
    }
    // A resolved ordinary host/path cannot gain userinfo by decoding its
    // query values. Those values are handled separately by the query walker.
    let text = view.text.trim_start();
    if text.starts_with('/')
        && !text.starts_with("//")
        && text
            .as_bytes()
            .get(1)
            .is_some_and(|ch| !matches!(ch, b'%' | b'&' | b'\\'))
    {
        return false;
    }
    if has_network_prefix(text) {
        let start = if text.starts_with("//") {
            2
        } else {
            url_regex().find(text).map_or(0, |m| m.end())
        };
        let end = text.as_bytes()[start..]
            .iter()
            .position(|ch| matches!(ch, b'/' | b'\\' | b'?' | b'#'))
            .map_or(text.len(), |n| start + n);
        if !text.as_bytes()[start..end]
            .iter()
            .any(|ch| matches!(ch, b'%' | b'&' | b'@'))
        {
            return false;
        }
    }
    let html = View::html_components(&view.text);
    let mut next_state = state;
    let next = if html.text != view.text {
        if state.html == 0 {
            return false;
        }
        next_state.html -= 1;
        html
    } else {
        if state.percent == 0 {
            return false;
        }
        let percent = View::percent_layer(&view.text);
        if percent.text == view.text {
            return false;
        }
        next_state.percent -= 1;
        percent
    };
    let mut local = Vec::new();
    let mut bounds = Vec::new();
    let mut lineage = parents.to_vec();
    lineage.push(view);
    let found = userinfo_layers_inner(&next, next_state, &lineage, &mut local, &mut bounds);
    spans.extend(
        local
            .into_iter()
            .map(|r| next.source_start(r.start)..next.source_end(r.end - 1)),
    );
    guards.extend(
        bounds
            .into_iter()
            .map(|r| next.source_start(r.start)..next.source_end(r.end - 1)),
    );
    found
}

// This view has already decoded the HTML layer. Every ampersand is now
// structural, including entity-produced ampersands without a following key.
// Percent escapes are never consulted while finding a component's end.
fn nested_public_value(
    view: &View,
    value: Range<usize>,
    depth: usize,
    bare_authority: bool,
    guard_references: bool,
    spans: &mut Vec<Range<usize>>,
    guards: &mut Vec<Range<usize>>,
) -> bool {
    let public = &view.text[value.clone()];
    if depth == 0 {
        // At the fixed layer budget, credential-bearing encoded values fail
        // closed as a whole. Benign encoded data remains unchanged.
        let recovery = View::html_url(public);
        let mut local = Vec::new();
        recover_query_parameters(&recovery, 0, recovery.text.len(), &mut local);
        userinfo_at_layer(&recovery, true, &[], &mut local, &mut Vec::new());
        let bare = recovery
            .text
            .split_once('=')
            .is_some_and(|(key, _)| plain_query_key_sensitive(key));
        if bare || !local.is_empty() {
            spans.push(value);
        }
        return true;
    }
    let nested = View::percent_layer(public);
    if nested.text == public {
        return false;
    }
    let mut local = Vec::new();
    let mut bounds = Vec::new();
    let authority_context = bare_authority || encoded_network_prefix(&nested.text);
    if !authority_context
        || !userinfo_layers(
            &nested,
            depth - 1,
            guard_references,
            &mut local,
            &mut bounds,
        )
    {
        component_query_parameters(
            &nested,
            0,
            depth - 1,
            guard_references,
            &mut local,
            &mut bounds,
        );
    }
    guards.extend(bounds.into_iter().map(|r| {
        value.start + nested.source_start(r.start)..value.start + nested.source_end(r.end - 1)
    }));
    spans.extend(local.into_iter().map(|r| {
        value.start + nested.source_start(r.start)..value.start + nested.source_end(r.end - 1)
    }));
    true
}

fn component_query_parameters(
    view: &View,
    start: usize,
    depth: usize,
    guard_references: bool,
    spans: &mut Vec<Range<usize>>,
    guards: &mut Vec<Range<usize>>,
) {
    let b = view.text.as_bytes();
    let mut cursor = start;
    if start == 0 && view.text.contains('@') {
        let mut userinfo = Vec::new();
        let prefix_end = b
            .iter()
            .position(|ch| matches!(ch, b'=' | b'?' | b'&' | b';'))
            .unwrap_or(b.len());
        let explicit = view.text.starts_with("//")
            || url_regex().find(&view.text).is_some_and(|m| m.start() == 0);
        if (explicit || b[..prefix_end].contains(&b':')) && attribute_userinfo(view, &mut userinfo)
        {
            // '=' and percent escapes in an established password are opaque.
            // Only a later actual query can introduce parameter discovery.
            let at = userinfo
                .iter()
                .map(|r| r.end)
                .max()
                .or_else(|| view.text.find('@'))
                .unwrap_or(0);
            let Some(query) = view.text[at + 1..].find('?') else {
                return;
            };
            cursor = at + 1 + query;
        }
    }
    let mut initial = true;
    let mut recognized = false;
    let mut parameter_end = start;
    let mut percent = start;
    let mut unchanged_until = start;
    while cursor < b.len() {
        let separator = matches!(b[cursor], b'?' | b'&' | b';');
        if !separator && !initial {
            cursor += 1;
            continue;
        }
        initial = false;
        let key = cursor + usize::from(separator);
        cursor = key;
        while cursor < b.len() && !matches!(b[cursor], b'=' | b'?' | b'&' | b';') {
            cursor += 1;
        }
        if b.get(cursor) != Some(&b'=') {
            continue;
        }
        recognized = true;
        let spelling = &view.text[key..cursor];
        let decoded;
        let name = if spelling.bytes().any(|ch| matches!(ch, b'%' | b'\\')) {
            decoded = View::new(spelling);
            decoded.text.as_str()
        } else {
            spelling
        };
        let valid_key = name.bytes().all(query_key_character);
        let sensitive = valid_key && plain_query_key_sensitive(name);
        let encoded_key = !valid_key && spelling.contains('%');
        cursor += 1;
        let value = cursor;
        // Raw nested ?url= prefixes share the same outer separator. Cache its
        // end and next percent position instead of rescanning every suffix.
        if parameter_end <= value {
            parameter_end = value;
            while parameter_end < b.len() && !matches!(b[parameter_end], b'&' | b';') {
                if view.literal(parameter_end)
                    && (b[parameter_end].is_ascii_whitespace()
                        || matches!(b[parameter_end], b'<' | b'>'))
                {
                    break;
                }
                parameter_end += 1;
            }
        }
        if sensitive {
            let raw = &view.text[value..parameter_end];
            let mut complete = parameter_end;
            if query_reference(raw) || raw.starts_with(['$', '`', '*']) {
                // A decoded component is already bounded by its URL region or
                // attribute. Whitespace cannot prove a reference has ended;
                // literal tails stay opaque through the next outer separator.
                while complete < b.len() && !matches!(b[complete], b'&' | b';') {
                    complete += 1;
                }
            }
            if complete > value {
                if query_reference(&view.text[value..complete]) {
                    // Keep generic assignment/recovery scans within this
                    // complete component's proven URL boundary as well.
                    if guard_references {
                        guards.push(value..complete);
                    }
                } else {
                    spans.push(value..complete);
                }
            }
            cursor = complete;
            continue;
        }
        if encoded_key
            && nested_public_value(
                view,
                key..parameter_end,
                depth,
                false,
                guard_references,
                spans,
                guards,
            )
        {
            cursor = parameter_end;
            continue;
        }
        if percent < value {
            percent = value;
            while percent < b.len() && b[percent] != b'%' {
                percent += 1;
            }
        }
        if percent >= parameter_end || value < unchanged_until {
            // No new decoding layer is needed; raw nested queries are scanned
            // in this same view, with monotonically advancing cursors.
            continue;
        }
        let bare_authority = matches!(
            name.to_ascii_lowercase().as_str(),
            "url" | "uri" | "redirect_uri" | "redirect_url" | "next" | "return_to" | "caption"
        );
        if nested_public_value(
            view,
            value..parameter_end,
            depth,
            bare_authority,
            guard_references,
            spans,
            guards,
        ) {
            cursor = parameter_end;
        } else {
            unchanged_until = parameter_end;
        }
    }
    if !recognized && view.text.contains('%') {
        let mut userinfo = Vec::new();
        if !attribute_userinfo(view, &mut userinfo) {
            // A wholly encoded nested query can require another layer before
            // any key=value syntax becomes visible. Never decode userinfo data.
            nested_public_value(
                view,
                start..b.len(),
                depth,
                false,
                guard_references,
                spans,
                guards,
            );
        }
    }
}

// Literal and encoded absolute/protocol-relative URLs also occur without
// markup. Locate disjoint lexical URL regions in the ordinary view, but parse
// component boundaries from their original bytes. Skip nested scheme starts
// inside a region so deeply repeated redirect prefixes cannot rescan suffixes.
fn source_url_regions(
    input: &str,
    view: &View,
    output: &View,
    ancestors: &[View],
    queries: bool,
    spans: &mut Vec<Range<usize>>,
    guards: &mut Vec<Range<usize>>,
) {
    let b = view.text.as_bytes();
    let literal = |position| {
        if !view.literal(position) {
            return false;
        }
        let mut source = view.source_start(position);
        for parent in ancestors.iter().rev() {
            if !parent.literal(source) {
                return false;
            }
            source = parent.source_start(source);
        }
        true
    };
    let mut cursor = 0;
    let mut previous = "";
    let mut matches = Vec::new();
    let mut authority_guards = Vec::new();
    while cursor + 1 < b.len() {
        if !matches!(b[cursor], b'/' | b'\\') || !matches!(b[cursor + 1], b'/' | b'\\') {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 2;
        if b.get(start.wrapping_sub(1)) == Some(&b':') {
            let mut scheme = start - 1;
            while scheme > start.saturating_sub(33)
                && scheme > 0
                && (b[scheme - 1].is_ascii_alphanumeric()
                    || matches!(b[scheme - 1], b'+' | b'.' | b'-'))
            {
                scheme -= 1;
            }
            if url_regex_source(view, scheme, cursor) {
                continue;
            }
        }
        let limit = view.enclosing_end(start).min(b.len());
        while cursor < limit
            && !((b[cursor].is_ascii_whitespace()
                || matches!(b[cursor], b'"' | b'\'' | b'`' | b'<' | b'>'))
                && literal(cursor))
        {
            cursor += 1;
        }
        if cursor <= start {
            continue;
        }
        let mut source = view.source_start(start);
        let mut end = view.source_end(cursor - 1);
        for parent in ancestors.iter().rev() {
            source = parent.source_start(source);
            end = parent.source_end(end - 1);
        }
        if !input[source..end].contains('%') && !input[source..end].contains('&') {
            continue;
        }
        let spelling = &input[source..end];
        if spelling != previous {
            let components = View::html_components(spelling);
            let mut local = Vec::new();
            let mut bounds = Vec::new();
            let authority = userinfo_layers(&components, 4, false, &mut local, &mut bounds);
            if queries && !authority {
                component_query_parameters(&components, 0, 4, false, &mut local, &mut bounds);
            }
            matches = local
                .into_iter()
                .map(|r| components.source_start(r.start)..components.source_end(r.end - 1))
                .collect::<Vec<_>>();
            authority_guards = bounds
                .into_iter()
                .map(|r| components.source_start(r.start)..components.source_end(r.end - 1))
                .collect::<Vec<_>>();
            previous = spelling;
        }
        spans.extend(
            matches.iter().map(|r| {
                output.position(source + r.start)..output.position(source + r.end - 1) + 1
            }),
        );
        guards.extend(
            authority_guards.iter().map(|r| {
                output.position(source + r.start)..output.position(source + r.end - 1) + 1
            }),
        );
    }
}

fn source_url_components(
    input: &str,
    view: &View,
    spans: &mut Vec<Range<usize>>,
    guards: &mut Vec<Range<usize>>,
) {
    if !view.unchanged() && input.contains('%') {
        source_url_regions(input, view, view, &[], true, spans, guards);
    }
    let entity = |text: &str| {
        text.split('&').skip(1).any(|mut tail| {
            while tail.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("amp")) {
                tail = &tail[3..];
                if let Some(rest) = tail.strip_prefix(';') {
                    tail = rest;
                }
            }
            tail.starts_with('#')
                || ["percnt", "sol", "colon", "commat"].iter().any(|name| {
                    tail.get(..name.len())
                        .is_some_and(|p| p.eq_ignore_ascii_case(name))
                })
        })
    };
    let at_entity = |text: &str| {
        text.split('&').skip(1).any(|mut tail| {
            while tail.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("amp")) {
                tail = &tail[3..];
                if let Some(rest) = tail.strip_prefix(';') {
                    tail = rest;
                }
            }
            tail.starts_with('#')
                || ["percnt", "commat"].iter().any(|name| {
                    tail.get(..name.len())
                        .is_some_and(|p| p.eq_ignore_ascii_case(name))
                })
        })
    };
    // A plain query with no entity spelling needs no whole-input authority
    // recovery. Do not rescan an unchanged view of the same source bytes.
    let original_entity = entity(input);
    let decoded_entity = !view.unchanged() && entity(&view.text);
    if (original_entity || decoded_entity)
        && (view.text.contains('@') || at_entity(input) || decoded_entity && at_entity(&view.text))
    {
        let mut locators = Vec::new();
        let mut text = input.to_owned();
        let mut remaining = 4;
        for _ in 0..9 {
            let html = View::html_components(&text);
            let locator = if html.text != text {
                html
            } else {
                if remaining == 0 || !text.contains('%') {
                    break;
                }
                remaining -= 1;
                View::percent_layer(&text)
            };
            if locator.text == text {
                break;
            }
            text = locator.text.clone();
            locators.push(locator);
            let last = locators.len() - 1;
            source_url_regions(
                input,
                &locators[last],
                view,
                &locators[..last],
                false,
                spans,
                guards,
            );
        }
    }
}

// Scan each disjoint HTML attribute value with separate component and nested
// recognition layers. Entity-only component bounds take precedence over the
// percent-decoded recovery view. Map spans back without re-encoding HTML.
fn html_attribute_urls(
    input: &str,
    view: &View,
    spans: &mut Vec<Range<usize>>,
    components: &mut Vec<Range<usize>>,
    guards: &mut Vec<Range<usize>>,
) {
    if !view.text.contains('<') {
        return;
    }
    let b = view.text.as_bytes();
    let mut cursor = 0;
    let mut in_tag = false;
    let mut raw_text: Option<&[u8]> = None;
    // Repeated adjacent attribute values share relative matches. Keep only
    // one borrowed spelling and its ranges, with no unbounded cache growth.
    let mut previous = "";
    let mut matches = Vec::new();
    let mut component_matches = Vec::new();
    let mut component_guards = Vec::new();
    while cursor < b.len() {
        if !in_tag {
            if let Some(name) = raw_text {
                if b.get(cursor..cursor + 2) != Some(b"</")
                    || !b
                        .get(cursor + 2..cursor + 2 + name.len())
                        .is_some_and(|s| s.eq_ignore_ascii_case(name))
                    || !b
                        .get(cursor + 2 + name.len())
                        .is_some_and(|ch| ch.is_ascii_whitespace() || matches!(ch, b'>' | b'/'))
                {
                    cursor += 1;
                    continue;
                }
                raw_text = None;
            }
            if b.get(cursor..cursor + 4) == Some(b"<!--") {
                cursor += 4;
                while cursor < b.len() && b.get(cursor..cursor + 3) != Some(b"-->") {
                    cursor += 1;
                }
                cursor = (cursor + 3).min(b.len());
                continue;
            }
        }
        match b[cursor] {
            b'<' if b
                .get(cursor + 1)
                .is_some_and(|ch| ch.is_ascii_alphabetic() || *ch == b'/') =>
            {
                in_tag = true;
                for name in [b"script".as_slice(), b"style", b"textarea", b"title"] {
                    let end = cursor + 1 + name.len();
                    if b.get(cursor + 1..end)
                        .is_some_and(|s| s.eq_ignore_ascii_case(name))
                        && b.get(end)
                            .is_some_and(|ch| ch.is_ascii_whitespace() || *ch == b'>')
                    {
                        raw_text = Some(name);
                    }
                }
            }
            b'>' => in_tag = false,
            b'=' if in_tag => {
                cursor = skip_space(b, cursor + 1);
                if cursor >= b.len() {
                    break;
                }
                let quoted = view.literal(cursor) && matches!(b[cursor], b'"' | b'\'' | b'`');
                let start = cursor + usize::from(quoted);
                let end = if quoted {
                    view.quote_end(cursor)
                } else {
                    let mut end = cursor;
                    while end < b.len()
                        && !(view.literal(end) && (b[end].is_ascii_whitespace() || b[end] == b'>'))
                    {
                        end += 1;
                    }
                    end
                };
                let value = &view.text[start..end];
                let source_start = view.source_start(start);
                let source_end = if end > start {
                    view.source_end(end - 1)
                } else {
                    source_start
                };
                let source = &input[source_start..source_end];
                if value
                    .bytes()
                    .any(|ch| matches!(ch, b'&' | b'?' | b'@' | b'/' | b'\\'))
                {
                    if source != previous {
                        let html = View::html_url(value);
                        let mut local = Vec::new();
                        // The attribute supplies URL context; no scheme is
                        // required for query recognition in this disjoint view.
                        if let Some(query) = html.text.find('?') {
                            recover_query_parameters(&html, query, html.text.len(), &mut local);
                        }
                        let mut decoded = local;
                        // Component boundaries are determined before percent decoding.
                        // Entity punctuation is structure; percent escapes stay data.
                        let components = View::html_components(source);
                        let mut local = Vec::new();
                        let mut bounds = Vec::new();
                        let mut userinfo = Vec::new();
                        let authority_found =
                            userinfo_layers(&components, 4, true, &mut userinfo, &mut bounds);
                        if !authority_found {
                            component_query_parameters(
                                &components,
                                0,
                                4,
                                true,
                                &mut local,
                                &mut bounds,
                            );
                        }
                        // A real authority takes precedence over encoded punctuation
                        // inside its username/password. Fully encoded authorities
                        // still have their own recognition layer.
                        let encoded_authority = html.text.trim_start().starts_with("//")
                            && !components.text.trim_start().starts_with("//");
                        let serialized_entity =
                            components.text.contains("&%23") || components.text.contains("%26%23");
                        if !authority_found
                            || encoded_authority
                            || userinfo.is_empty() && serialized_entity
                        {
                            relative_userinfo(&html, &mut decoded);
                            attribute_userinfo(&html, &mut decoded);
                        }
                        local.extend(userinfo);
                        matches = decoded
                            .into_iter()
                            .map(|r| html.source_start(r.start)..html.source_end(r.end - 1))
                            .collect::<Vec<_>>();
                        component_matches = local
                            .into_iter()
                            .map(|r| {
                                components.source_start(r.start)..components.source_end(r.end - 1)
                            })
                            .collect::<Vec<_>>();
                        component_guards = bounds
                            .into_iter()
                            .map(|r| {
                                components.source_start(r.start)..components.source_end(r.end - 1)
                            })
                            .collect();
                        previous = source;
                    }
                    spans.extend(matches.iter().map(|r| start + r.start..start + r.end));
                    components.extend(component_matches.iter().map(|r| {
                        view.position(source_start + r.start)
                            ..view.position(source_start + r.end - 1) + 1
                    }));
                    guards.extend(component_guards.iter().map(|r| {
                        view.position(source_start + r.start)
                            ..view.position(source_start + r.end - 1) + 1
                    }));
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
        if matches!(bounded_prefix(&view, m.start).trim(), "use" | "pub use") {
            if let Some(end) = candidate_end(&view, m.start) {
                if opaque_material(&view.text[m.start..end])
                    || value.starts_with("relay_") && end > m.end
                {
                    spans.push(m.start..end);
                    continue;
                }
            }
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
    let prose = credential_prose(&view, input, &mut spans);
    let mut url_values = Vec::new();
    urls(&view, &mut url_values);
    relative_userinfo(&view, &mut url_values);
    let mut components = Vec::new();
    let mut guards = Vec::new();
    source_url_components(input, &view, &mut components, &mut guards);
    html_attribute_urls(input, &view, &mut url_values, &mut components, &mut guards);
    // Component spans supersede decoded-layer matches that cross their real
    // boundary. Sort/merge once, then use logarithmic overlap lookups.
    components.sort_unstable_by_key(|r| (r.start, r.end));
    let mut boundaries: Vec<Range<usize>> = Vec::new();
    for span in components {
        if let Some(last) = boundaries.last_mut().filter(|last| span.start < last.end) {
            last.end = last.end.max(span.end);
        } else {
            boundaries.push(span);
        }
    }
    guards.extend(boundaries.iter().cloned());
    guards.sort_unstable_by_key(|r| (r.start, r.end));
    let mut protected: Vec<Range<usize>> = Vec::new();
    for range in guards {
        if let Some(last) = protected.last_mut().filter(|last| range.start < last.end) {
            last.end = last.end.max(range.end);
        } else {
            protected.push(range);
        }
    }
    url_values.retain(|r| {
        let n = protected.partition_point(|span| span.end <= r.start);
        protected.get(n).is_none_or(|span| span.start >= r.end)
    });
    url_values.extend(boundaries);
    url_values.sort_unstable_by_key(|span| (span.start, span.end));
    let mut url_context = url_values.clone();
    url_context.extend(protected);
    url_context.sort_unstable_by_key(|r| (r.start, r.end));
    let mut context: Vec<Range<usize>> = Vec::new();
    for range in url_context {
        if let Some(last) = context.last_mut().filter(|last| range.start < last.end) {
            last.end = last.end.max(range.end);
        } else {
            context.push(range);
        }
    }
    let assigned = spans.len();
    let mut wrapped = Vec::new();
    assignments(&view, inherited, &mut spans, &context, &mut wrapped);
    let mut values: Vec<Range<usize>> = Vec::new();
    if prose.iter().any(|p| p.gate == Gate::Assigned) {
        let mut found = spans[assigned..].to_vec();
        found.extend(wrapped.iter().cloned());
        found.sort_unstable_by_key(|r| (r.start, r.end));
        for range in found {
            if let Some(last) = values.last_mut().filter(|last| range.start <= last.end) {
                last.end = last.end.max(range.end);
            } else {
                values.push(range);
            }
        }
    }
    let within = |ranges: &[Range<usize>], probe: usize| {
        let n = ranges.partition_point(|r| r.end <= probe);
        ranges.get(n).is_some_and(|r| r.start <= probe)
    };
    let inside = |probe: usize| within(&context, probe);
    // Sorted by start with a running maximum end, so the ranges holding a
    // probe are found without scanning every wrapped value per disclosure.
    wrapped.sort_unstable_by_key(|r| (r.start, r.end));
    let reach: Vec<usize> = wrapped
        .iter()
        .scan(0, |end, r| {
            *end = (*end).max(r.end);
            Some(*end)
        })
        .collect();
    let mut disclosed: Vec<Range<usize>> = Vec::new();
    for p in prose {
        let accepted = match p.gate {
            Gate::Always => true,
            Gate::Outside => !inside(p.probe),
            Gate::Assigned => !inside(p.probe) && within(&values, p.probe),
        };
        if !accepted {
            continue;
        }
        // Words before the key kept the assignment engine from redacting
        // the value; the disclosure covers what the bare key would have.
        if p.gate == Gate::Assigned {
            let mut i = wrapped.partition_point(|r| r.start <= p.probe);
            while i > 0 && reach[i - 1] > p.probe {
                i -= 1;
                let r = &wrapped[i];
                if p.probe < r.end {
                    disclosed.push(view.source_start(r.start)..view.source_end(r.end - 1));
                }
            }
        }
        disclosed.push(p.source);
    }
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
        .chain(disclosed.into_iter().filter(|r| r.start < r.end))
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

#[cfg(test)]
mod context_window_tests {
    use super::{call_argument_context, code_object_context, type_context, View};
    use regex::Regex;

    // Straightforward reference: the same 512-byte window rounded up to a
    // char boundary, matched by the full patterns with no prefilter.
    fn window(view: &View, key: usize) -> &str {
        let mut start = key.saturating_sub(512);
        while !view.text.is_char_boundary(start) {
            start += 1;
        }
        &view.text[start..key]
    }

    fn reference(patterns: &[Regex; 3], view: &View, key: usize) -> [bool; 3] {
        let window = window(view, key);
        [
            patterns[0].is_match(window),
            patterns[1].is_match(window),
            patterns[2].is_match(window),
        ]
    }

    #[test]
    fn source_context_predicates_match_reference_windows() {
        let patterns = [
            Regex::new(r"(?s)(?:\bfn\s+[A-Za-z_][A-Za-z0-9_]*(?:<[^;{}()]*>)?\s*\([^);{}=]*|\b(?:struct|interface)\s+[A-Za-z_][A-Za-z0-9_]*[^;{}]*\{[^}]*|\btype\s+[A-Za-z_][A-Za-z0-9_]*[^;{}]*=\s*\{[^}]*)(?:$)").unwrap(),
            Regex::new(r"(?s)(?:\b(?:(?:let|const|var)\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{|\bjson!\(\{)[^{}]*$").unwrap(),
            Regex::new(r"[A-Za-z_][A-Za-z0-9_]*\((?:[^(){};]*,)?[ \t\r\n]*$").unwrap(),
        ];
        let openers = [
            "fn f(",
            "fn g<T: Into<u8>>(a: T, ",
            "struct X {",
            "struct X { a: u8 } ",
            "interface X { a: b;",
            "type X = {",
            "type X = { a } ",
            "const x = {",
            "let y = { z: {",
            "x={",
            "json!({",
            "json!(",
            "Callee(",
            "Callee(a, ",
            "Callee(a); ",
            "(",
            "{",
            "}",
            ")",
            "=",
            "fn",
            "type",
            "x \"pw: a\" ",
            "plain prose, no opener ",
        ];
        let fillers = [
            "x", " ", "a", "\t", "\r\n", "\n", ",", ";", "é", "日", "😀", "(", "{", "}", ")", "=",
            "fn ", "Callee", "_",
        ];
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let mut cases = 0usize;
        for opener in openers {
            for round in 0..24 {
                // Pad so the opener sits near the window edge: padding stops
                // once the text and the opener reach the target
                // 505 + round % 16 - round % 3 bytes (within 503..=520).
                let mut text = String::new();
                let pad = ["x", "é", "日", "😀"][round % 4];
                while text.len() + opener.len() < 505 + round % 16 - round % 3 {
                    text.push_str(pad);
                }
                let at = next(text.len().max(1));
                let at = (0..=at).rev().find(|&i| text.is_char_boundary(i)).unwrap();
                text.insert_str(at, opener);
                for _ in 0..next(6) {
                    text.push_str(fillers[next(fillers.len())]);
                }
                let view = View::new(&text);
                let end = view.text.len();
                // Keys at the end, right after the opener, and where the
                // window is exactly 511, 512 or 513 bytes before rounding.
                let mut keys = vec![end, at + opener.len()];
                for back in 0..4 {
                    for edge in [511, 512, 513] {
                        keys.push(back + edge);
                    }
                }
                keys.retain(|&key| key <= end && view.text.is_char_boundary(key));
                for _ in 0..8 {
                    let key = next(end + 1);
                    if view.text.is_char_boundary(key) {
                        keys.push(key);
                    }
                }
                for key in keys {
                    let got = [
                        type_context(&view, key),
                        code_object_context(&view, key),
                        call_argument_context(&view, key),
                    ];
                    assert_eq!(
                        got,
                        reference(&patterns, &view, key),
                        "{:?} at {key}",
                        view.text
                    );
                    cases += 1;
                }
            }
        }
        assert!(cases > 1_000, "{cases}");
    }

    // The word checks give the answers of the standard library calls they
    // replace, with Unicode spaces and multi-byte text next to the words.
    #[test]
    fn word_checks_match_std() {
        use super::{holds, last_word_is};
        let parts = [
            "fn",
            "f",
            "type",
            "typ",
            "let",
            "const",
            "var",
            "json!",
            "json",
            "struct",
            "interface",
            " ",
            "\t",
            "\r\n",
            "\u{a0}",
            "\u{2003}",
            "é",
            "ﬁ",
            "x",
            "_",
            "(",
            "{",
            "=",
        ];
        let words = [
            "fn",
            "type",
            "let",
            "const",
            "var",
            "json!",
            "struct",
            "interface",
            "ﬁ",
        ];
        let mut seed = 0x5EED_u64;
        let mut next = |m: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % m as u64) as usize
        };
        for _ in 0..20_000 {
            let text: String = (0..next(7)).map(|_| parts[next(parts.len())]).collect();
            for word in words {
                assert_eq!(holds(&text, word), text.contains(word), "{text:?} {word:?}");
                assert_eq!(
                    last_word_is(&text, &[word]),
                    text.split_whitespace().last() == Some(word),
                    "{text:?} {word:?}"
                );
            }
            assert_eq!(
                last_word_is(&text, &["let", "const", "var"]),
                matches!(
                    text.split_whitespace().last(),
                    Some("let" | "const" | "var")
                ),
                "{text:?}"
            );
        }
    }
}

#[cfg(test)]
mod prose_scan_tests {
    use super::{
        bracket_opener, next_list_key, prose_reference, reference_prefix, BracketCloses, ListKeys,
        REDACTION_TOKEN,
    };

    // Short texts of every token the three tables look at, mixed with
    // multi-byte text, spaces and line breaks.
    fn texts() -> Vec<String> {
        let tokens = [
            "(",
            ")",
            "[",
            "]",
            "{",
            "}",
            "{{",
            "}}",
            "<",
            ">",
            "%",
            ";",
            "&",
            "=",
            "==",
            " ",
            "  ",
            "\t",
            "\n",
            "\r\n",
            "\u{a0}",
            "a",
            "_k",
            "key",
            "a.b-c",
            "9",
            "é",
            "日",
            "😀",
            "*",
            "***",
            "•",
            REDACTION_TOKEN,
            "\"",
            "'",
            ",",
        ];
        let mut seed = 0x0005_DEEC_E66Du64;
        let mut next = |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let mut texts = Vec::new();
        for _ in 0..3_000 {
            let mut text = String::new();
            for _ in 0..next(24) {
                text.push_str(tokens[next(tokens.len())]);
            }
            texts.push(text);
        }
        // A key whose `=` lies 40 and 41 bytes after the separator.
        for n in [39, 40, 41] {
            for tail in ["", "=", "==", "x"] {
                texts.push(format!("a; {}={tail}", "k".repeat(n)));
                texts.push(format!("&{}={tail}", "k".repeat(n)));
            }
        }
        // Several `==` keys, so a cut can fall right after a later one.
        texts.push("a; k==; j==; i=x".into());
        texts.push("&k==&j== &i==".into());
        texts
    }

    fn boundaries(text: &str) -> Vec<usize> {
        (0..=text.len())
            .filter(|&i| text.is_char_boundary(i))
            .collect()
    }

    // The scan `unquoted_prose_value` ran from each value start.
    fn close_reference(text: &str, start: usize, line_end: usize, opener: char) -> Option<usize> {
        let mut nested = Vec::new();
        for (i, ch) in text[start..line_end].char_indices() {
            match ch {
                '(' | '[' | '{' => nested.push(ch),
                ')' | ']' | '}' if nested.last() == Some(&bracket_opener(ch)) => {
                    nested.pop();
                }
                ')' | ']' | '}' if nested.is_empty() && bracket_opener(ch) == opener => {
                    return Some(start + i);
                }
                _ => {}
            }
        }
        None
    }

    fn list_reference(text: &str, start: usize, line_end: usize, sep: char) -> Option<usize> {
        let list = &text[start..line_end];
        list.char_indices()
            .find_map(|(i, ch)| (ch == sep && next_list_key(&list[i + 1..])).then_some(start + i))
    }

    fn prefix_reference(text: &str) -> bool {
        let token = text.split(char::is_whitespace).next().unwrap_or("");
        let closed = |open: &str, close: &str| {
            token.strip_prefix(open).is_some_and(|rest| {
                rest.find(close)
                    .is_some_and(|n| prose_reference(&token[..open.len() + n + close.len()]))
            })
        };
        token.starts_with(REDACTION_TOKEN)
            || closed("<", ">")
            || closed("%", "%")
            || closed("{{", "}}")
            || token
                .chars()
                .take_while(|c| matches!(c, '*' | '•' | '●'))
                .count()
                >= 3
    }

    #[test]
    fn line_tables_match_reference_scans() {
        let mut cases = 0usize;
        for text in texts() {
            let at = boundaries(&text);
            let closes = BracketCloses::new(&text);
            let lists = ListKeys::new(&text);
            let marks = std::cell::OnceCell::new();
            for (n, &start) in at.iter().enumerate() {
                assert_eq!(
                    reference_prefix(&text, start, &marks),
                    prefix_reference(&text[start..]),
                    "{text:?} at {start}"
                );
                for &line_end in &at[n..] {
                    for opener in ['(', '[', '{'] {
                        assert_eq!(
                            closes.first(start, opener).filter(|&p| p < line_end),
                            close_reference(&text, start, line_end, opener),
                            "{text:?} {opener} {start}..{line_end}"
                        );
                    }
                    for sep in [';', '&'] {
                        assert_eq!(
                            lists.first(sep, start, line_end),
                            list_reference(&text, start, line_end, sep),
                            "{text:?} {sep} {start}..{line_end}"
                        );
                    }
                    cases += 1;
                }
            }
        }
        assert!(cases > 100_000, "{cases}");
    }
}
