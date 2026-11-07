use crate::{MAX_SCRUB_CHARS, REDACTION_TOKEN};
use regex::{Captures, Regex};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::LazyLock;

const MAX_QUOTED_VALUE: usize = 4096;
const TRUNCATION_NOTE: &str = "[relayhistory: truncated";

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("Technical Foul regex must compile")
}

fn replace<'a>(input: Cow<'a, str>, pattern: &Regex, replacement: &str) -> Cow<'a, str> {
    if pattern.is_match(input.as_ref()) {
        Cow::Owned(
            pattern
                .replace_all(input.as_ref(), replacement)
                .into_owned(),
        )
    } else {
        input
    }
}

fn replace_with<'a, F>(input: Cow<'a, str>, pattern: &Regex, replacement: F) -> Cow<'a, str>
where
    F: Fn(&Captures<'_>) -> String,
{
    let source = input.as_ref();
    let mut output = None::<String>;
    let mut last = 0;
    for captures in pattern.captures_iter(source) {
        let matched = captures.get(0).expect("capture zero is the whole match");
        let value = replacement(&captures);
        if value == matched.as_str() {
            continue;
        }
        let target = output.get_or_insert_with(|| String::with_capacity(source.len()));
        target.push_str(&source[last..matched.start()]);
        target.push_str(&value);
        last = matched.end();
    }
    if let Some(mut output) = output {
        output.push_str(&source[last..]);
        return Cow::Owned(output);
    }
    input
}

fn replace_exact_token(captures: &Captures<'_>, expected_len: usize) -> String {
    if captures.get(2).expect("token capture").as_str().len() == expected_len {
        format!(
            "{}{}",
            captures.get(1).map_or("", |matched| matched.as_str()),
            REDACTION_TOKEN
        )
    } else {
        captures.get(0).expect("match").as_str().to_owned()
    }
}

static PEM: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
    )
});
static UNIX_HOME: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?m)(^|[\s\"'(=:/])/(?:Users|home)/[^/\s]+/"#));
static WINDOWS_HOME: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?im)(^|[\s\"'(=])(?:[A-Z]:\\Users\\)[^\\\s]+\\"#));
static BEARER: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)(^|[^A-Za-z0-9_])(Bearer\s+)[A-Za-z0-9._~+/=-]{15,}[A-Za-z0-9_~+/=-]")
});
static SENDGRID: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_])(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43,})"));
static PREFIX_HYPHEN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])(?:sk|rk|pk|ak)-[A-Za-z0-9_-]{20,}"));
static PREFIX_UNDERSCORE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(^|[^A-Za-z0-9_-])(?:(?:sk|rk|pk)_(?:live|test)_|whsec_)[A-Za-z0-9]{10,}")
});
static GITHUB_CLASSIC: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])gh[pousr]_[A-Za-z0-9_]{20,}"));
static AWS_ID: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])((?:AKIA|ASIA)[0-9A-Z]{16}[A-Za-z0-9_]*)"));
static GITHUB_FINE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])github_pat_[A-Za-z0-9_]{22,}"));
static GITLAB: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}"));
static NPM: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])(npm_[A-Za-z0-9]{36}[A-Za-z0-9_]*)"));
static HUGGING_FACE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])(hf_[A-Za-z]{34}[A-Za-z0-9_]*)"));
static CLOUDFLARE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])cf(?:k|ut|at)_[A-Za-z0-9]{40,}"));
static SLACK: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])(?:xox[baprse]|xapp)-[A-Za-z0-9-]{10,}"));
static SLACK_HOOK: LazyLock<Regex> =
    LazyLock::new(|| re(r"(hooks\.slack\.com/(?:services|workflows|triggers)/)[A-Za-z0-9_/-]{8,}"));
static CAPY_CURSOR: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])(?:capy|crsr)_[A-Za-z0-9_-]{16,}"));
static RELAY: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])relay_(?:ag|pa|ws|id)_[A-Za-z0-9._-]{16,}"));
static AUTOMATION_HOOK: LazyLock<Regex> =
    LazyLock::new(|| re(r"(/webhooks/automations/)[A-Za-z0-9._~-]{7,}[A-Za-z0-9_~-]"));
static TOKEN_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"[A-Za-z0-9_.-]{35,}"));
static RTH: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])rth_(?:at|rt|st)_[A-Za-z0-9_]{8,}"));
static OAUTH_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)([?&](?:code_challenge|code_verifier|state|client_secret|access_token|id_token|refresh_token|assertion)=)[^&\s]*",
    )
});
static GOOGLE_API: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_-])AIza[0-9A-Za-z_-]{30,}"));
static GLUED_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"[A-Za-z0-9_.-]{21,}"));
static AUTHORIZATION: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)(\bauthorization[^A-Za-z0-9\r\n]{1,8}(?:Basic|Token|Bot|Digest|Negotiate|NTLM)\s+)[A-Za-z0-9._~+/=-]{8,}",
    )
});
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r#"(?i)\b(?:[A-Za-z0-9]+_){0,8}(?:api[_-]?key|apikey|key|secret|token|password|passwd|passphrase|pwd|credentials?)\s*[:=]\s*["'`]?[^\s"'`,;]+"#,
    )
});
static FALLBACK: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"(?i)(^|[^A-Za-z0-9])((?:password|passwd|passphrase|secret|token|credentials?|api[_ -]?key|access[_ -]?key|private[_ -]?key|secret[_ -]?key|client[_ -]?secret|auth[_ -]?token|session[_ -]?token)(?:[^A-Za-z0-9_./\r\n-][^A-Za-z0-9\r\n]{0,7}))([A-Za-z0-9_+/=.-]{20,})",
    )
});
static URL_PASSWORD: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)([a-z][a-z0-9+.-]{0,31}://[^:\s/@]+:)[^@\s/]+(@)"));
static URL_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)([a-z][a-z0-9+.-]{0,31}://)([^:\s/@?#]+)(@)"));
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)(^|[^:/])([A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\.[A-Z]{2,24})(:?)"));
static INTL_PHONE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9_+])\+[1-9]\d*(?:[ .-]?\(\d{1,4}\)\d*|[ .-]\d+)*"));
static NANP_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(^|[^A-Za-z0-9_.+-])(?:\([2-9]\d{2}\) ?|[2-9]\d{2}[.-])[2-9]\d{2}[.-]\d{4}")
});
static CARD_RUN: LazyLock<Regex> = LazyLock::new(|| re(r"(^|[^A-Za-z0-9_.+-])(\d+(?:[ -]\d+)*)"));
static NUMBER_LITERAL: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)^-?\d+(?:\.\d+)?(?:e[+-]?\d+)?$"));
static GLUED_RELAY_SUFFIX: LazyLock<Regex> =
    LazyLock::new(|| re(r"^relay_(?:ag|pa|ws|id)_[A-Za-z0-9._-]{16,}$"));
static GLUED_SUFFIX: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^(?:(?:sk|rk|pk|ak)-[A-Za-z0-9_-]{20,}|(?:(?:sk|rk|pk)_(?:live|test)_|whsec_)[A-Za-z0-9]{10,}|gh[pousr]_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z]{34}|cf(?:k|ut|at)_[A-Za-z0-9]{40,}|(?:xox[baprse]|xapp)-[A-Za-z0-9-]{10,}|(?:capy|crsr)_[A-Za-z0-9_-]{16,}|rth_(?:at|rt|st)_[A-Za-z0-9_]{8,}|AIza[0-9A-Za-z_-]{30,})[A-Za-z0-9_-]*$",
    )
});

fn redact_jwts_in_run(run: &str) -> String {
    if !run.contains(".eyJ") {
        return run.to_owned();
    }
    let segments: Vec<&str> = run.split('.').collect();
    let mut out = Vec::with_capacity(segments.len());
    let mut index = 0;
    while index < segments.len() {
        let header = segments[index];
        let payload = segments.get(index + 1).copied();
        let signature = segments.get(index + 2).copied();
        if payload.is_some_and(|part| part.starts_with("eyJ") && part.len() >= 11)
            && signature.is_some_and(|part| part.len() >= 16)
        {
            let bytes = header.as_bytes();
            let mut search = 0;
            let mut replaced = false;
            while let Some(relative) = header[search..].find("eyJ") {
                let start = search + relative;
                let word_before = start > 0 && is_word_byte(bytes[start - 1]);
                if !word_before && header.len() - start >= 11 {
                    out.push(format!("{}{}", &header[..start], REDACTION_TOKEN));
                    index += 3;
                    replaced = true;
                    break;
                }
                search = start + 1;
            }
            if replaced {
                continue;
            }
        }
        out.push(header.to_owned());
        index += 1;
    }
    out.join(".")
}

const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[allow(clippy::cast_precision_loss)]
fn entropy(value: &str) -> f64 {
    let mut counts = [0_usize; 256];
    for byte in value.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let length = value.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .fold(0.0, |h, count| {
            let probability = *count as f64 / length;
            h - probability * probability.log2()
        })
}

fn looks_generated(token: &str) -> bool {
    let classes = usize::from(token.bytes().any(|byte| byte.is_ascii_lowercase()))
        + usize::from(token.bytes().any(|byte| byte.is_ascii_uppercase()))
        + usize::from(token.bytes().any(|byte| byte.is_ascii_digit()));
    token.len() >= 20 && classes >= 2 && entropy(token) >= 3.5
}

/// Whether a key names a secret under the canonical quoted-key rule.
#[must_use]
pub fn is_secret_key_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let compound = [
        "api_key",
        "apikey",
        "api-key",
        "api key",
        "access_key",
        "accesskey",
        "access-key",
        "access key",
        "private_key",
        "privatekey",
        "private-key",
        "private key",
        "secret_key",
        "secretkey",
        "secret-key",
        "secret key",
        "auth_key",
        "authkey",
        "auth-key",
        "auth key",
        "signing_key",
        "signingkey",
        "signing-key",
        "signing key",
        "encryption_key",
        "encryptionkey",
        "encryption-key",
        "encryption key",
        "master_key",
        "masterkey",
        "master-key",
        "master key",
        "client_secret",
        "clientsecret",
        "client-secret",
        "client secret",
        "session_token",
        "sessiontoken",
        "session-token",
        "session token",
        "access_token",
        "accesstoken",
        "access-token",
        "access token",
        "refresh_token",
        "refreshtoken",
        "refresh-token",
        "refresh token",
        "auth_token",
        "authtoken",
        "auth-token",
        "auth token",
        "id_token",
        "idtoken",
        "id-token",
        "id token",
        "bot_token",
        "bottoken",
        "bot-token",
        "bot token",
        "bearer_token",
        "bearertoken",
        "bearer-token",
        "bearer token",
        "api_token",
        "apitoken",
        "api-token",
        "api token",
    ];
    if compound.iter().any(|suffix| lower.ends_with(suffix)) {
        return true;
    }
    let words = [
        "authorization",
        "credentials",
        "credential",
        "passphrase",
        "password",
        "passwd",
        "secret",
        "bearer",
        "token",
        "auth",
    ];
    for word in words {
        if let Some(start) = lower.strip_suffix(word).map(str::len) {
            if start == 0 {
                return true;
            }
            let previous = name.as_bytes()[start - 1];
            if !previous.is_ascii_alphabetic()
                || (previous.is_ascii_lowercase() && name.as_bytes()[start].is_ascii_uppercase())
            {
                return true;
            }
        }
    }
    false
}

fn backslashes_before(bytes: &[u8], at: usize, floor: usize) -> usize {
    let mut count = 0;
    while at > floor + count && bytes[at - count - 1] == b'\\' {
        count += 1;
    }
    count
}

fn byte_limit_utf16(text: &str, start: usize, max_units: usize) -> usize {
    let mut units = 0;
    for (offset, character) in text[start..].char_indices() {
        if units + character.len_utf16() > max_units {
            return start + offset;
        }
        units += character.len_utf16();
    }
    text.len()
}

fn quoted_key_at(
    text: &str,
    run_start: usize,
    quote_at: usize,
) -> Option<(usize, usize, u8, usize)> {
    let bytes = text.as_bytes();
    let slash_count = quote_at - run_start;
    if slash_count > 16 || !matches!(bytes[quote_at], b'\"' | b'\'' | b'`') {
        return None;
    }
    let quote = bytes[quote_at];
    let key_start = quote_at + 1;
    let mut at = key_start;
    while at < bytes.len()
        && at - key_start < 64
        && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'_' | b'.' | b' ' | b'-'))
    {
        at += 1;
    }
    if at == key_start || at + slash_count >= bytes.len() {
        return None;
    }
    if bytes[at..at + slash_count]
        .iter()
        .any(|byte| *byte != b'\\')
        || bytes[at + slash_count] != quote
    {
        return None;
    }
    let key_end = at;
    at += slash_count + 1;
    let spaces = at;
    while at < bytes.len() && at - spaces < 16 && matches!(bytes[at], b' ' | b'\t') {
        at += 1;
    }
    if at + 1 < bytes.len() && bytes[at] == b'=' && bytes[at + 1] == b'>' {
        at += 2;
    } else if at < bytes.len() && matches!(bytes[at], b':' | b'=') {
        at += 1;
    } else {
        return None;
    }
    let spaces = at;
    while at < bytes.len() && at - spaces < 16 && matches!(bytes[at], b' ' | b'\t') {
        at += 1;
    }
    Some((key_start, key_end, quote, at))
}

fn redact_quoted_secret_values(text: &str) -> String {
    if !text.contains([':', '=']) {
        return text.to_owned();
    }
    let bytes = text.as_bytes();
    let mut replacements = Vec::<(usize, usize)>::new();
    let mut unclosed = HashMap::<(u8, usize), (usize, usize)>::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' && (at == 0 || bytes[at - 1] != b'\\') {
            let run_start = at;
            while at < bytes.len() && bytes[at] == b'\\' && at - run_start <= 16 {
                at += 1;
            }
            if at >= bytes.len() || !matches!(bytes[at], b'\"' | b'\'' | b'`') {
                continue;
            }
            if let Some((key_start, key_end, _key_quote, end)) = quoted_key_at(text, run_start, at)
            {
                consider_quoted_value(
                    text,
                    key_start,
                    key_end,
                    end,
                    &mut replacements,
                    &mut unclosed,
                );
            }
        } else if matches!(bytes[at], b'\"' | b'\'' | b'`') && (at == 0 || bytes[at - 1] != b'\\') {
            if let Some((key_start, key_end, _key_quote, end)) = quoted_key_at(text, at, at) {
                consider_quoted_value(
                    text,
                    key_start,
                    key_end,
                    end,
                    &mut replacements,
                    &mut unclosed,
                );
            }
        }
        at += 1;
    }
    if replacements.is_empty() {
        return text.to_owned();
    }
    replacements.sort_unstable();
    let mut output = String::with_capacity(text.len());
    let mut last = 0;
    for (start, end) in replacements {
        if start < last || end <= start {
            continue;
        }
        output.push_str(&text[last..start]);
        output.push_str(REDACTION_TOKEN);
        last = end;
    }
    output.push_str(&text[last..]);
    output
}

fn consider_quoted_value(
    text: &str,
    key_start: usize,
    key_end: usize,
    end: usize,
    replacements: &mut Vec<(usize, usize)>,
    unclosed: &mut HashMap<(u8, usize), (usize, usize)>,
) {
    let name = text[key_start..key_end].trim();
    if !is_secret_key_name(name) {
        return;
    }
    let bytes = text.as_bytes();
    let mut slash_count = 0;
    while slash_count < 16 && end + slash_count < bytes.len() && bytes[end + slash_count] == b'\\' {
        slash_count += 1;
    }
    let quote = bytes.get(end + slash_count).copied();
    let (value_start, value_end) = if quote.is_some_and(|q| matches!(q, b'\"' | b'\'' | b'`')) {
        let quote = quote.expect("checked");
        let value_start = end + slash_count + 1;
        let period = if (slash_count + 1) & slash_count == 0 {
            2 * (slash_count + 1)
        } else {
            0
        };
        let seen = unclosed.get(&(quote, slash_count)).copied();
        let mut cursor = value_start;
        let mut value_end = None;
        let scan_end = byte_limit_utf16(text, value_start, MAX_QUOTED_VALUE);
        if seen.is_some_and(|(start, stop)| value_start >= start && value_start < stop) {
            cursor = bytes.len();
        }
        while cursor < bytes.len() && cursor <= scan_end {
            if matches!(bytes[cursor], b'\n' | b'\r') {
                break;
            }
            if bytes[cursor] == quote {
                let run = backslashes_before(bytes, cursor, value_start);
                let own = run.min(cursor - value_start);
                if (period > 0 && own % period == slash_count)
                    || (period == 0 && own == slash_count)
                {
                    value_end = Some(cursor - slash_count);
                    break;
                }
            }
            cursor += text[cursor..]
                .chars()
                .next()
                .expect("cursor is before the string end")
                .len_utf8();
        }
        let value_end = value_end.unwrap_or_else(|| {
            unclosed.insert((quote, slash_count), (value_start, cursor.min(bytes.len())));
            let bounded_end = byte_limit_utf16(text, value_start, MAX_QUOTED_VALUE);
            text[value_start..bounded_end]
                .char_indices()
                .find_map(|(offset, character)| {
                    is_js_whitespace(character).then_some(value_start + offset)
                })
                .unwrap_or(bounded_end)
        });
        (value_start, value_end)
    } else {
        if slash_count > 0 || name.contains(' ') {
            return;
        }
        let value_start = end;
        let mut value_end = value_start;
        let bounded_end = byte_limit_utf16(text, value_start, MAX_QUOTED_VALUE);
        while value_end < bounded_end {
            let character = text[value_end..]
                .chars()
                .next()
                .expect("cursor is before the bounded end");
            if is_js_whitespace(character)
                || matches!(
                    character,
                    '\"' | '\'' | '`' | ',' | ';' | '{' | '}' | '[' | ']' | '\\'
                )
            {
                break;
            }
            value_end += character.len_utf8();
        }
        let value = &text[value_start..value_end];
        if value.is_empty() || is_non_secret_bare(value) || !looks_generated(value) {
            return;
        }
        (value_start, value_end)
    };
    let value = &text[value_start..value_end];
    if !value.is_empty() && value != REDACTION_TOKEN && !value.starts_with("op://") {
        replacements.push((value_start, value_end));
    }
}

fn is_non_secret_bare(value: &str) -> bool {
    if ["true", "false", "null", "undefined", "none"]
        .iter()
        .any(|literal| value.eq_ignore_ascii_case(literal))
    {
        return true;
    }
    NUMBER_LITERAL.is_match(value)
}

fn is_glued_secret(run: &str) -> bool {
    for (index, _) in run.match_indices('-') {
        let suffix = &run[index + 1..];
        if suffix.starts_with("relay_") && GLUED_RELAY_SUFFIX.is_match(suffix) {
            return true;
        }
        if GLUED_SUFFIX.is_match(suffix) {
            return true;
        }
    }
    false
}

fn known_issuer(digits: &str) -> bool {
    let length = digits.len();
    if !(13..=19).contains(&length) || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let prefix = |count: usize| digits[..count.min(length)].parse::<u32>().unwrap_or(0);
    (digits.starts_with('4') && matches!(length, 13 | 16 | 19))
        || (((51..=55).contains(&prefix(2)) || (2221..=2720).contains(&prefix(4))) && length == 16)
        || (matches!(prefix(2), 34 | 37) && length == 15)
        || (((300..=305).contains(&prefix(3)) || matches!(prefix(2), 36 | 38 | 39))
            && matches!(length, 14 | 16))
        || ((3528..=3589).contains(&prefix(4)) && (16..=19).contains(&length))
        || ((prefix(4) == 6011 || (644..=649).contains(&prefix(3)) || matches!(prefix(2), 62 | 65))
            && (16..=19).contains(&length))
}

fn is_card_digits(digits: &str) -> bool {
    if !known_issuer(digits) {
        return false;
    }
    digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(index, byte)| {
            let mut digit = u32::from(byte - b'0');
            if index % 2 == 1 {
                digit *= 2;
                if digit > 9 {
                    digit -= 9;
                }
            }
            digit
        })
        .sum::<u32>()
        % 10
        == 0
}

/// Whether text is a consistently grouped, known-issuer, Luhn-valid card number.
#[must_use]
pub fn is_card_number(text: &str) -> bool {
    let mut digits = String::with_capacity(text.len());
    let mut separator = None;
    for byte in text.bytes() {
        if byte.is_ascii_digit() {
            digits.push(char::from(byte));
        } else if !matches!(byte, b' ' | b'-') || separator.is_some_and(|seen| seen != byte) {
            return false;
        } else {
            separator = Some(byte);
        }
    }
    is_card_digits(&digits)
}

fn redact_cards_in_run(run: &str) -> String {
    let groups: Vec<&str> = run.split([' ', '-']).collect();
    let separators: Vec<u8> = run.bytes().filter(|byte| !byte.is_ascii_digit()).collect();
    let mut output = String::with_capacity(run.len());
    let mut index = 0;
    while index < groups.len() {
        let mut end = None;
        let mut digits = String::new();
        if groups[index]
            .as_bytes()
            .first()
            .is_some_and(|byte| (b'2'..=b'6').contains(byte))
        {
            for next in index..groups.len() {
                if next > index + 1 && separators[next - 1] != separators[index] {
                    break;
                }
                digits.push_str(groups[next]);
                if digits.len() > 19 {
                    break;
                }
                if digits.len() >= 13 && is_card_digits(&digits) {
                    end = Some(next);
                }
            }
        }
        output.push_str(if end.is_some() {
            REDACTION_TOKEN
        } else {
            groups[index]
        });
        let next = end.map_or(index + 1, |last| last + 1);
        if next < groups.len() {
            output.push(char::from(separators[next - 1]));
        }
        index = next;
    }
    output
}

fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn is_js_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

fn bound_for_scrub(value: &str) -> Cow<'_, str> {
    let total = utf16_len(value);
    if total <= MAX_SCRUB_CHARS {
        return Cow::Borrowed(value);
    }
    let mut units = 0;
    let mut limit = value.len();
    for (index, character) in value.char_indices() {
        let width = character.len_utf16();
        if units + width > MAX_SCRUB_CHARS {
            limit = index;
            break;
        }
        units += width;
    }
    let mut cut = 0;
    let chars: Vec<(usize, char)> = value[..limit].char_indices().collect();
    for (position, (index, character)) in chars.iter().enumerate().rev() {
        if !is_js_whitespace(*character) {
            continue;
        }
        let after = index + character.len_utf8();
        let previous = position.checked_sub(1).map(|i| chars[i].1);
        let next = value[after..].chars().next();
        if !(previous.is_some_and(|c| c.is_ascii_digit() || c == ')')
            && next.is_some_and(|c| c.is_ascii_digit() || c == '('))
        {
            cut = after;
            break;
        }
    }
    if let Some(found) = PEM.find(&value[..cut]) {
        if found.end() == cut && !found.as_str().contains("-----END ") {
            cut = found.start();
        }
    }
    let dropped = total - utf16_len(&value[..cut]);
    Cow::Owned(format!(
        "{}\n{TRUNCATION_NOTE} {dropped} characters over the {MAX_SCRUB_CHARS}-character scrub limit]",
        &value[..cut]
    ))
}

/// Whether [`scrub_text`] will apply the canonical size bound.
#[must_use]
pub fn exceeds_scrub_bound(value: &str) -> bool {
    utf16_len(value) > MAX_SCRUB_CHARS
}

#[allow(clippy::too_many_lines)]
fn scrub_text_impl(value: &str) -> Cow<'_, str> {
    let mut text = bound_for_scrub(value);
    text = replace(text, &PEM, REDACTION_TOKEN);
    text = replace_with(text, &UNIX_HOME, |caps| {
        let prefix = caps.get(1).map_or("", |m| m.as_str());
        format!("{prefix}~/")
    });
    text = replace_with(text, &WINDOWS_HOME, |caps| {
        format!("{}~\\", caps.get(1).map_or("", |m| m.as_str()))
    });
    text = replace(text, &BEARER, "$1$2[REDACTED]");
    text = replace_with(text, &SENDGRID, |caps| {
        let token = caps.get(2).expect("SendGrid token").as_str();
        if token.len() == 69 {
            format!(
                "{}{}",
                caps.get(1).map_or("", |matched| matched.as_str()),
                REDACTION_TOKEN
            )
        } else {
            caps.get(0).expect("match").as_str().to_owned()
        }
    });
    text = replace(text, &PREFIX_HYPHEN, "$1[REDACTED]");
    text = replace(text, &PREFIX_UNDERSCORE, "$1[REDACTED]");
    text = replace(text, &GITHUB_CLASSIC, "$1[REDACTED]");
    text = replace_with(text, &AWS_ID, |caps| replace_exact_token(caps, 20));
    text = replace(text, &GITHUB_FINE, "$1[REDACTED]");
    text = replace(text, &GITLAB, "$1[REDACTED]");
    text = replace_with(text, &NPM, |caps| replace_exact_token(caps, 40));
    text = replace_with(text, &HUGGING_FACE, |caps| replace_exact_token(caps, 37));
    text = replace(text, &CLOUDFLARE, "$1[REDACTED]");
    text = replace(text, &SLACK, "$1[REDACTED]");
    text = replace(text, &SLACK_HOOK, "$1[REDACTED]");
    text = replace(text, &CAPY_CURSOR, "$1[REDACTED]");
    text = replace(text, &RELAY, "$1[REDACTED]");
    text = replace(text, &AUTOMATION_HOOK, "$1[REDACTED]");
    text = replace_with(text, &TOKEN_RUN, |caps| {
        redact_jwts_in_run(caps.get(0).expect("match").as_str())
    });
    text = replace(text, &RTH, "$1[REDACTED]");
    text = replace(text, &OAUTH_QUERY, "$1[REDACTED]");
    text = replace(text, &GOOGLE_API, "$1[REDACTED]");
    text = replace_with(text, &GLUED_RUN, |caps| {
        let run = caps.get(0).expect("match").as_str();
        if is_glued_secret(run) {
            REDACTION_TOKEN.to_owned()
        } else {
            run.to_owned()
        }
    });
    if text.contains([':', '=']) {
        let quoted = redact_quoted_secret_values(text.as_ref());
        if quoted != text.as_ref() {
            text = Cow::Owned(quoted);
        }
    }
    text = replace(text, &AUTHORIZATION, "$1[REDACTED]");
    text = replace_with(text, &ASSIGNMENT, |caps| {
        let matched = caps.get(0).expect("match").as_str();
        let index = matched.find([':', '=']).expect("assignment separator");
        format!(
            "{}{}{}",
            &matched[..index],
            &matched[index..=index],
            REDACTION_TOKEN
        )
    });
    text = replace_with(text, &FALLBACK, |caps| {
        let token = caps.get(3).expect("token").as_str();
        if token.len() <= 512 && looks_generated(token) {
            format!(
                "{}{}{}",
                caps.get(1).map_or("", |m| m.as_str()),
                caps.get(2).map_or("", |m| m.as_str()),
                REDACTION_TOKEN
            )
        } else {
            caps.get(0).expect("match").as_str().to_owned()
        }
    });
    text = replace(text, &URL_PASSWORD, "$1[REDACTED]$2");
    text = replace_with(text, &URL_TOKEN, |caps| {
        if caps.get(2).expect("userinfo").as_str() == "git" {
            caps.get(0).expect("match").as_str().to_owned()
        } else {
            format!(
                "{}{}@",
                caps.get(1).expect("scheme").as_str(),
                REDACTION_TOKEN
            )
        }
    });
    text = replace_with(text, &EMAIL, |caps| {
        let prefix = caps.get(1).map_or("", |m| m.as_str());
        let address = caps.get(2).expect("address").as_str();
        let colon = caps.get(3).map_or("", |m| m.as_str());
        if address.to_ascii_lowercase().starts_with("git@") && colon == ":" {
            format!("{prefix}{address}{colon}")
        } else {
            format!("{prefix}{REDACTION_TOKEN}{colon}")
        }
    });
    text = replace_with(text, &INTL_PHONE, |caps| {
        let matched = caps.get(0).expect("match").as_str();
        if matched.bytes().filter(u8::is_ascii_digit).count() >= 8 {
            format!(
                "{}{}",
                caps.get(1).map_or("", |m| m.as_str()),
                REDACTION_TOKEN
            )
        } else {
            matched.to_owned()
        }
    });
    text = replace(text, &NANP_PHONE, "$1[REDACTED]");
    text = replace_with(text, &CARD_RUN, |caps| {
        format!(
            "{}{}",
            caps.get(1).map_or("", |m| m.as_str()),
            redact_cards_in_run(caps.get(2).expect("run").as_str())
        )
    });
    text
}

/// Scrub one string with Technical Foul ruleset 3.
#[must_use]
pub fn scrub_text(value: &str) -> Cow<'_, str> {
    scrub_text_impl(value)
}
