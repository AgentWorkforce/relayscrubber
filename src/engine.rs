//! Fixed automata and a monotone contextual scanner; no backtracking regex.

use crate::{normalize::View, Policy, REDACTION_TOKEN};
use base64::Engine;
use regex::Regex;
use std::{ops::Range, sync::OnceLock};

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
    R.get_or_init(|| Regex::new(&format!("{PROVIDERS}|{WEBHOOK}")).expect("fixed provider regex"))
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
    let n: String = name
        .bytes()
        .filter(|b| !matches!(b, b'_' | b'-'))
        .map(|b| char::from(b.to_ascii_lowercase()))
        .collect();
    if matches!(
        n.as_str(),
        "idempotencykey" | "publickey" | "key" | "codechallenge" | "state"
    ) {
        return false;
    }
    const NAMES: &[&str] = &[
        "password",
        "passwd",
        "pwd",
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
        "proxyauthorization",
        "cookie",
        "setcookie",
    ];
    if NAMES.contains(&n.as_str()) {
        return true;
    }
    // A provider prefix must be separated; do not redact tokenizer, monkey,
    // token_count, secret_name or ordinary identifiers ending in those letters.
    let lower = name.to_ascii_lowercase();
    NAMES.iter().any(|tail| {
        lower
            .rsplit_once('_')
            .is_some_and(|(_, t)| t.replace('-', "") == *tail)
            || lower
                .rsplit_once('-')
                .is_some_and(|(_, t)| t.replace('_', "") == *tail)
    }) || [
        "apikey",
        "accesstoken",
        "secretaccesskey",
        "sessiontoken",
        "clientsecret",
    ]
    .iter()
    .any(|tail| n.ends_with(tail))
}

pub(crate) fn public_context(name: &str) -> bool {
    name.eq_ignore_ascii_case("idempotency_key")
        || name.eq_ignore_ascii_case("idempotency-key")
        || name.eq_ignore_ascii_case("idempotencyKey")
}

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}
fn whitespace(b: u8) -> bool {
    b.is_ascii_whitespace()
}
fn skip_space(b: &[u8], mut i: usize) -> usize {
    while b.get(i).copied().is_some_and(whitespace) {
        i += 1;
    }
    i
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
    if view.enclosing_end(start) != usize::MAX {
        return view.enclosing_end(start).min(b.len());
    }
    let mut end = start;
    if view.text[start..].starts_with(REDACTION_TOKEN) {
        end += REDACTION_TOKEN.len();
    }
    while end < b.len()
        && !(view.literal(end)
            && (whitespace(b[end])
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
    let mut end = view.line_end(value);
    while end < b.len() {
        let mut next = end;
        if b[next] == b'\r' {
            next += 1;
        }
        if b.get(next) == Some(&b'\n') {
            next += 1;
        }
        if next >= b.len() {
            return next;
        }
        let line_end = view.line_end(next);
        let mut content = next;
        while content < line_end && matches!(b[content], b' ' | b'\t') {
            content += 1;
        }
        if content < line_end && content - next <= key_indent {
            break;
        }
        end = line_end;
    }
    end
}

fn assignments(view: &View, inherited: bool, spans: &mut Vec<Range<usize>>) {
    let b = view.text.as_bytes();
    let mut i = 0;
    let mut public_until = if inherited { b.len() } else { 0 };
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
        let name = &view.text[start..i];
        let is_secret = sensitive(name);
        let is_public = public_context(name);
        if !is_secret && !is_public {
            continue;
        }
        let mut sep = i;
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
            && expression
        {
            continue;
        }
        if !(has_sep || flag && sep > i) {
            continue;
        }
        let mut after_sep = sep + usize::from(has_sep);
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
        let quoted = matches!(b[value], b'"' | b'\'' | b'`');
        let line_start = view.line_start(value);
        let crossed_line = line_start > after_sep;
        let yaml = b.get(sep) == Some(&b':') && view.line_key(start);
        let key_indent = start - view.line_start(start);
        let yaml_indented = yaml
            && crossed_line
            && value - line_start > key_indent
            && b[line_start..value]
                .iter()
                .all(|c| matches!(c, b' ' | b'\t'));
        // Empty env/header assignments end at their physical line. Continue
        // across it only for explicit literals, quoted JSON keys, inherited
        // public values or an indented YAML value; never consume the next env key.
        let declaration = [b"let".as_slice(), b"var".as_slice(), b"const".as_slice()]
            .iter()
            .any(|kw| {
                before >= kw.len()
                    && &b[before - kw.len()..before] == *kw
                    && (before == kw.len() || !word(b[before - kw.len() - 1]))
            });
        let code = declaration || (before > 0 && b[before - 1] == b'.') || sep > i;
        let explicit_literal = quoted
            || quoted_key
            || yaml_indented
            || start < public_until
            || (code && matches!(b[value], b'0'..=b'9' | b'-' | b'{' | b'['));
        if crossed_line && !explicit_literal {
            continue;
        }
        let context = (start < public_until).then_some(public_until);
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
            line_end(view, value)
        } else {
            value_end(view, value, context)
        };
        let content = value + usize::from(quoted);
        // YAML literal/folded scalar: remove all following indented lines.
        if !quoted && yaml && !matches!(b[value], b'{' | b'[') {
            end = indented_end(view, value, key_indent)
                .min(context.unwrap_or(b.len()))
                .min(view.enclosing_end(value).min(b.len()));
        }
        if end > content {
            if reference(&view.text[content..end]) {
                i = end;
                continue;
            }
            spans.push(content..end);
            i = end;
        }
    }
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

fn urls(view: &View, spans: &mut Vec<Range<usize>>) {
    let b = view.text.as_bytes();
    // Inspect nested actual URL schemes too. Authority scans stop at the next
    // literal slash, so their total work is bounded by adjacent scheme starts.
    for scheme in url_regex().find_iter(&view.text) {
        if !(scheme.end() - 3..scheme.end()).all(|p| view.literal(p)) {
            continue;
        }
        let authority = scheme.end();
        let mut end = authority;
        while end < b.len()
            && !(view.literal(end)
                && (b[end].is_ascii_whitespace()
                    || matches!(b[end], b'/' | b'?' | b'#' | b'"' | b'\'' | b'`')))
        {
            end += 1;
        }
        if let Some(at) = (authority..end)
            .rev()
            .find(|&i| b[i] == b'@' && view.literal(i))
        {
            if let Some(colon) = (authority..at).find(|&i| b[i] == b':' && view.literal(i)) {
                if colon + 1 < at {
                    spans.push(colon + 1..at);
                }
            } else if &view.text[authority..at] != "git" {
                spans.push(authority..at);
            }
        }
    }
    let mut cursor = 0;
    while let Some(scheme) = url_regex().find_at(&view.text, cursor) {
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
                if colon + 1 < at {
                    spans.push(colon + 1..at);
                }
            } else if &view.text[authority..at] != "git" {
                spans.push(authority..at);
            }
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

pub(crate) fn analyze(input: &str, inherited: bool, policy: Policy) -> crate::ScrubReport {
    if input.is_empty() {
        return crate::ScrubReport {
            text: String::new(),
            redactions: Vec::new(),
        };
    }
    let view = View::new(input);
    let mut spans = Vec::new();
    for m in provider_regex().find_iter(&view.text) {
        spans.push(m.range());
    }
    jwts(&view, &mut spans);
    for c in bearer_regex().captures_iter(&view.text) {
        spans.push(c.get(1).expect("credential capture").range());
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
    assignments(&view, inherited, &mut spans);
    urls(&view, &mut spans);
    if policy == Policy::Pii {
        for m in pii_regex().find_iter(&view.text) {
            spans.push(m.range());
        }
    }
    let mut original: Vec<Range<usize>> = spans
        .into_iter()
        .filter(|r| r.start < r.end)
        .map(|r| view.source_start(r.start)..view.source_end(r.end - 1))
        .collect();
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
        out.push_str(REDACTION_TOKEN);
        at = span.end;
    }
    out.push_str(&input[at..]);
    crate::ScrubReport {
        text: out,
        redactions: merged,
    }
}
