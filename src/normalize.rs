//! One-pass delimiter decoding with offsets back to unchanged source bytes.

use std::borrow::Cow;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Decode {
    Escapes,
    Html,
    Components,
    Percent,
}

struct Change {
    position: usize,
    start: usize,
    end: usize,
}

pub(crate) struct View {
    pub text: String,
    changes: Vec<Change>,
    quotes: Vec<(usize, usize)>,
    scopes: Vec<(usize, usize)>,
    containers: Vec<(usize, usize)>,
    line_keys: Vec<usize>,
    line_ends: Vec<usize>,
    indented: Vec<(usize, usize)>,
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn pair(b: &[u8], i: usize) -> Option<u8> {
    Some(hex(*b.get(i)?)? * 16 + hex(*b.get(i + 1)?)?)
}

fn unicode(b: &[u8], i: usize) -> Option<(u8, usize)> {
    match b.get(i)?.to_ascii_lowercase() {
        b'u' if b.get(i + 1..i + 3)? == b"00" => Some((pair(b, i + 3)?, i + 5)),
        b'x' => Some((pair(b, i + 1)?, i + 3)),
        _ => None,
    }
}

fn percent(b: &[u8], start: usize) -> Option<(u8, usize)> {
    percent_tail(b, start + 1)
}

fn percent_tail(b: &[u8], mut p: usize) -> Option<(u8, usize)> {
    while b
        .get(p..p + 2)
        .is_some_and(|s| s.eq_ignore_ascii_case(b"25"))
    {
        p += 2;
    }
    if b.get(p).is_some_and(|c| c.eq_ignore_ascii_case(&b'u')) {
        unicode(b, p)
    } else {
        Some((pair(b, p)?, p + 2))
    }
}

fn after_slash(b: &[u8], mut p: usize) -> Option<(u8, usize)> {
    while b.get(p) == Some(&b'\\') {
        p += 1;
    }
    if b.get(p) == Some(&b'%') {
        return percent(b, p);
    }
    unicode(b, p).or_else(|| {
        let ch = *b.get(p)?;
        matches!(ch, b'"' | b'\'' | b'`' | b'=' | b':').then_some((ch, p + 1))
    })
}

// Each successful escape chain advances its cursor. A failed backslash run is
// copied as a run, so it cannot cause repeated suffix scans (including non-ASCII
// escapes). Repeated serialized unicode backslashes never recurse.
fn decoded(b: &[u8], start: usize) -> (u8, usize, u8) {
    let (mut value, mut p, style) = match b[start] {
        b'%' => match percent(b, start) {
            Some((value, end)) => (value, end, 1),
            None => return (b'%', start + 1, 0),
        },
        b'\\' => match after_slash(b, start) {
            Some((value, end)) => (value, end, 2),
            None => {
                let mut end = start + 1;
                while b.get(end) == Some(&b'\\') {
                    end += 1;
                }
                return (b'\\', end, 255);
            }
        },
        ch => return (ch, start + 1, 0),
    };
    while value == b'\\' {
        let next = if b.get(p) == Some(&b'%') {
            percent(b, p)
        } else {
            after_slash(b, p)
        };
        match next {
            Some((ch, end)) => {
                value = ch;
                p = end;
            }
            None => break,
        }
    }
    if value.is_ascii() {
        (value, p, style)
    } else {
        (b[start], p, 255)
    }
}

// HTML attribute recognition only. Optional-semicolon numeric punctuation
// accepts conservative prefixes even before hex-looking key/value material.
// The tokenizer consumes every layer once, retaining the original source span.
fn html_entity(b: &[u8], start: usize) -> Option<(u8, usize)> {
    if b.get(start) != Some(&b'#') {
        for (name, ch) in [
            ("amp", b'&'),
            ("colon", b':'),
            ("sol", b'/'),
            ("quest", b'?'),
            ("equals", b'='),
            ("percnt", b'%'),
            ("lowbar", b'_'),
            ("UnderBar", b'_'),
            ("hyphen", b'-'),
            ("dash", b'-'),
            ("period", b'.'),
            ("num", b'#'),
            ("commat", b'@'),
            ("quot", b'"'),
            ("apos", b'\''),
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
    let first = p;
    while b.get(p) == Some(&b'0') {
        p += 1;
    }
    for (decimal, hexadecimal_digits, ch) in [
        (b"58", b"3a", b':'),
        (b"47", b"2f", b'/'),
        (b"63", b"3f", b'?'),
        (b"38", b"26", b'&'),
        (b"61", b"3d", b'='),
        (b"64", b"40", b'@'),
    ] {
        let digits = if hexadecimal {
            hexadecimal_digits
        } else {
            decimal
        };
        if b.get(p..p + 2)
            .is_some_and(|s| s.eq_ignore_ascii_case(digits))
        {
            p += 2;
            return Some((ch, p + usize::from(b.get(p) == Some(&b';'))));
        }
    }
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

fn html_decoded(b: &[u8], start: usize, percent_layer: bool) -> (u8, usize, u8) {
    let mut ch = b[start];
    let mut end = start + 1;
    loop {
        let next = match ch {
            b'&' => html_entity(b, end),
            b'%' if percent_layer => percent_tail(b, end),
            _ => None,
        };
        match next {
            Some((value, p)) if value.is_ascii() => {
                ch = value;
                end = p;
            }
            _ => return (ch, end, u8::from(end > start + 1)),
        }
    }
}

// Every whitespace code point (`char::is_whitespace`, a superset of the WHATWG
// ASCII whitespace set) has these encoded spellings in prose: decimal and hex
// numeric references with or without leading zeros or `;`, the WHATWG named
// whitespace references, percent-encoded UTF-8, `%uXXXX`, `\uXXXX`, `\u{X}`,
// `\UXXXXXXXX` and `\xXX`. View already decodes the ASCII percent and
// backslash spellings; this layer adds the rest for prose recognition only.
const NAMED_SPACES: &[(&str, &str)] = &[
    ("Tab;", "\t"),
    ("NewLine;", "\n"),
    ("nbsp;", "\u{a0}"),
    ("nbsp", "\u{a0}"),
    ("NonBreakingSpace;", "\u{a0}"),
    ("ensp;", "\u{2002}"),
    ("emsp;", "\u{2003}"),
    ("emsp13;", "\u{2004}"),
    ("emsp14;", "\u{2005}"),
    ("numsp;", "\u{2007}"),
    ("puncsp;", "\u{2008}"),
    ("thinsp;", "\u{2009}"),
    ("ThinSpace;", "\u{2009}"),
    ("hairsp;", "\u{200a}"),
    ("VeryThinSpace;", "\u{200a}"),
    ("MediumSpace;", "\u{205f}"),
    ("ThickSpace;", "\u{205f}\u{200a}"),
];

fn hex_value(digits: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    for &d in digits {
        value = value.checked_mul(16)? + u32::from(hex(d)?);
    }
    Some(value)
}

fn space_char(value: u32) -> Option<char> {
    char::from_u32(value).filter(|c| c.is_whitespace())
}

fn encoded_space(b: &[u8], start: usize) -> Option<(Cow<'static, str>, usize)> {
    let one = |c: char, end: usize| Some((Cow::Owned(c.to_string()), end));
    match b[start] {
        b'&' if b.get(start + 1) == Some(&b'#') => {
            let mut p = start + 2;
            let hexadecimal = b.get(p).is_some_and(|c| c.eq_ignore_ascii_case(&b'x'));
            p += usize::from(hexadecimal);
            let first = p;
            let mut value = 0u32;
            while let Some(digit) = b
                .get(p)
                .and_then(|c| char::from(*c).to_digit(if hexadecimal { 16 } else { 10 }))
            {
                value = value
                    .saturating_mul(if hexadecimal { 16 } else { 10 })
                    .saturating_add(digit);
                p += 1;
            }
            if p == first {
                return None;
            }
            one(space_char(value)?, p + usize::from(b.get(p) == Some(&b';')))
        }
        b'&' => NAMED_SPACES.iter().find_map(|(name, decoded)| {
            b.get(start + 1..start + 1 + name.len())
                .is_some_and(|s| s == name.as_bytes())
                .then(|| (Cow::Borrowed(*decoded), start + 1 + name.len()))
        }),
        b'%' if b
            .get(start + 1)
            .is_some_and(|c| c.eq_ignore_ascii_case(&b'u')) =>
        {
            one(
                space_char(hex_value(b.get(start + 2..start + 6)?)?)?,
                start + 6,
            )
        }
        b'%' => {
            // Percent-encoded UTF-8 of one non-ASCII code point.
            let lead = pair(b, start + 1)?;
            let len = match lead {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return None,
            };
            let mut bytes = Vec::with_capacity(len);
            for n in 0..len {
                let at = start + 3 * n;
                if b.get(at) != Some(&b'%') {
                    return None;
                }
                bytes.push(pair(b, at + 1)?);
            }
            let s = std::str::from_utf8(&bytes).ok()?;
            one(space_char(u32::from(s.chars().next()?))?, start + 3 * len)
        }
        b'\\' => {
            let mut p = start;
            while b.get(p) == Some(&b'\\') {
                p += 1;
            }
            match *b.get(p)? {
                b'u' if b.get(p + 1) == Some(&b'{') => {
                    let close = p + 2 + b.get(p + 2..)?.iter().take(7).position(|&c| c == b'}')?;
                    one(
                        space_char(hex_value(&b[p + 2..close]).filter(|_| close > p + 2)?)?,
                        close + 1,
                    )
                }
                b'u' => one(space_char(hex_value(b.get(p + 1..p + 5)?)?)?, p + 5),
                b'U' => one(space_char(hex_value(b.get(p + 1..p + 9)?)?)?, p + 9),
                b'x' | b'X' => one(space_char(hex_value(b.get(p + 1..p + 3)?)?)?, p + 3),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Prose-only layer over a View's text that decodes encoded whitespace, with
/// offsets back to the View. Quotes and other bytes are never decoded here.
pub(crate) struct Spaced<'a> {
    pub text: Cow<'a, str>,
    // (position, decoded length, view start, view end)
    changes: Vec<(usize, usize, usize, usize)>,
}

impl<'a> Spaced<'a> {
    pub fn new(text: &'a str) -> Self {
        let b = text.as_bytes();
        let mut out = String::new();
        let mut changes = Vec::new();
        let mut copied = 0;
        let mut i = 0;
        while i < b.len() {
            if !matches!(b[i], b'&' | b'%' | b'\\') {
                i += 1;
                continue;
            }
            match encoded_space(b, i) {
                Some((decoded, end)) => {
                    out.push_str(&text[copied..i]);
                    changes.push((out.len(), decoded.len(), i, end));
                    out.push_str(&decoded);
                    copied = end;
                    i = end;
                }
                // A backslash run is decided once, from its first backslash.
                None if b[i] == b'\\' => {
                    while b.get(i) == Some(&b'\\') {
                        i += 1;
                    }
                }
                None => i += 1,
            }
        }
        if changes.is_empty() {
            return Self {
                text: Cow::Borrowed(text),
                changes,
            };
        }
        out.push_str(&text[copied..]);
        Self {
            text: Cow::Owned(out),
            changes,
        }
    }

    // The View position where the byte at `position` starts.
    pub fn start(&self, position: usize) -> usize {
        let n = self.changes.partition_point(|c| c.0 <= position);
        match n.checked_sub(1).map(|n| self.changes[n]) {
            None => position,
            Some((at, len, start, _)) if position < at + len => start,
            Some((at, len, _, end)) => end + position - at - len,
        }
    }

    // The View position just after the byte at `position`.
    pub fn end(&self, position: usize) -> usize {
        let n = self.changes.partition_point(|c| c.0 <= position);
        match n.checked_sub(1).map(|n| self.changes[n]) {
            Some((at, len, _, end)) if position < at + len => end,
            _ => self.start(position) + 1,
        }
    }
}

impl View {
    pub fn line_start(&self, position: usize) -> usize {
        let n = self.line_ends.partition_point(|&end| end < position);
        if n == 0 {
            0
        } else {
            self.line_ends[n - 1] + 1
        }
    }
    pub fn line_end(&self, position: usize) -> usize {
        let n = self.line_ends.partition_point(|&end| end < position);
        self.line_ends.get(n).copied().unwrap_or(self.text.len())
    }
    pub fn unchanged(&self) -> bool {
        self.changes.is_empty()
    }
    pub fn literal(&self, position: usize) -> bool {
        self.changes.is_empty()
            || self
                .changes
                .binary_search_by_key(&position, |c| c.position)
                .is_err()
    }
    pub fn source_start(&self, position: usize) -> usize {
        let n = self.changes.partition_point(|c| c.position <= position);
        if n == 0 {
            return position;
        }
        let change = &self.changes[n - 1];
        if change.position == position {
            change.start
        } else {
            position + change.end - change.position - 1
        }
    }
    pub fn source_end(&self, position: usize) -> usize {
        match self.changes.binary_search_by_key(&position, |c| c.position) {
            Ok(n) => self.changes[n].end,
            Err(_) => self.source_start(position) + 1,
        }
    }
    pub fn quote_end(&self, position: usize) -> usize {
        self.quotes
            .binary_search_by_key(&position, |q| q.0)
            .map_or(self.text.len(), |n| self.quotes[n].1)
    }
    pub fn enclosing_end(&self, position: usize) -> usize {
        let n = self.scopes.partition_point(|s| s.0 <= position);
        if n == 0 {
            usize::MAX
        } else {
            self.scopes[n - 1].1
        }
    }
    pub fn container_end(&self, position: usize) -> usize {
        self.containers
            .binary_search_by_key(&position, |c| c.0)
            .map_or(self.text.len(), |n| self.containers[n].1)
    }
    pub fn indentation_end(&self, position: usize) -> usize {
        self.indented
            .binary_search_by_key(&position, |c| c.0)
            .map_or(position, |n| self.indented[n].1)
    }
    pub fn line_key(&self, position: usize) -> bool {
        self.line_keys.binary_search(&position).is_ok()
    }

    pub fn new(input: &str) -> Self {
        Self::build(input, Decode::Escapes)
    }

    pub fn html_url(input: &str) -> Self {
        Self::build(input, Decode::Html)
    }

    pub fn html_components(input: &str) -> Self {
        Self::build(input, Decode::Components)
    }

    // Decode exactly one URL component encoding layer. A resulting percent
    // sign is data until a public value explicitly opens another nested layer.
    pub fn percent_layer(input: &str) -> Self {
        Self::build(input, Decode::Percent)
    }

    // Inverse mapping for ranges discovered in an entity-only source view.
    // Interior offsets of an escape map to the single recognition byte.
    pub fn position(&self, source: usize) -> usize {
        let n = self.changes.partition_point(|c| c.end <= source);
        if let Some(change) = self.changes.get(n).filter(|c| c.start <= source) {
            change.position
        } else if n == 0 {
            source
        } else {
            let change = &self.changes[n - 1];
            source - change.end + change.position + 1
        }
    }

    fn build(input: &str, mode: Decode) -> Self {
        let source = input.as_bytes();
        let mut bytes = Vec::new();
        let mut changes = Vec::new();
        let mut tags = Vec::new();
        let mut i = 0;
        while i < source.len() {
            // Copy ordinary runs in bulk. All decoder starters and quote tags
            // still take the same single-byte path below, in every view mode.
            let start = i;
            while i < source.len()
                && !matches!(source[i], b'%' | b'\\' | b'&' | b'"' | b'\'' | b'`')
            {
                i += 1;
            }
            if i > start {
                if !changes.is_empty() {
                    bytes.extend_from_slice(&source[start..i]);
                }
                continue;
            }
            // Ordinary bytes require no decoder call or escape-state setup.
            let (ch, end, style) = match (mode, source[i]) {
                (Decode::Html, b'&' | b'%') => html_decoded(source, i, true),
                (Decode::Components, b'&') => html_decoded(source, i, false),
                (Decode::Percent, b'%') => match pair(source, i + 1) {
                    Some(ch) if ch.is_ascii() => (ch, i + 3, 1),
                    _ => (source[i], i + 1, 0),
                },
                (Decode::Escapes, b'%' | b'\\') => decoded(source, i),
                _ => (source[i], i + 1, 0),
            };
            if style == 255 {
                if !changes.is_empty() {
                    bytes.extend_from_slice(&source[i..end]);
                }
                i = end;
                continue;
            }
            if end > i + 1 {
                if changes.is_empty() {
                    bytes.reserve(source.len());
                    bytes.extend_from_slice(&source[..i]);
                }
                changes.push(Change {
                    position: bytes.len(),
                    start: i,
                    end,
                });
            }
            if !changes.is_empty() {
                bytes.push(ch);
            }
            if matches!(ch, b'"' | b'\'' | b'`') {
                // Exact spelling/depth matters: e.g. backslash-x22 and three
                // backslashes plus quote have equal byte length but are not
                // interchangeable closers. Canonicalize hex/u/x letter case only.
                let spelling = &source[i..end];
                let tag = if spelling.iter().any(u8::is_ascii_uppercase) {
                    Cow::Owned(
                        spelling
                            .iter()
                            .map(u8::to_ascii_lowercase)
                            .collect::<Vec<_>>(),
                    )
                } else {
                    Cow::Borrowed(spelling)
                };
                let position = if changes.is_empty() {
                    i
                } else {
                    bytes.len() - 1
                };
                tags.push((position, tag));
            }
            i = end;
        }
        // Decoding changes only ASCII. Original UTF-8 sequences survive.
        // An unchanged input is already valid UTF-8: clone it once instead of
        // rebuilding and revalidating a potentially admission-sized buffer.
        let text = if changes.is_empty() {
            input.to_owned()
        } else {
            String::from_utf8(bytes).expect("normalization preserves UTF-8")
        };
        let b = text.as_bytes();
        let all_literal = changes.is_empty();
        let line_ends: Vec<_> = b
            .iter()
            .enumerate()
            .filter_map(|(p, ch)| {
                (matches!(ch, b'\r' | b'\n')
                    && (all_literal || changes.binary_search_by_key(&p, |c| c.position).is_err()))
                .then_some(p)
            })
            .collect();
        let mut quotes: Vec<_> = tags
            .iter()
            .map(|(position, _)| (*position, b.len()))
            .collect();
        let mut next = std::collections::BTreeMap::new();
        // A literal `'` between two letters or digits (`it's`) is an
        // apostrophe, not a quote: it neither opens nor closes one, and its
        // extent is itself. A quote opened elsewhere pairs with the next
        // literal `'` that is no apostrophe, or runs to the end. Otherwise
        // every re-scan of the output would reopen the value at the next
        // apostrophe word.
        let apostrophe = |p: usize| {
            text[..p]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric)
                && text[p + 1..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric)
        };
        let mut next_literal = None;
        for (n, (position, tag)) in tags.into_iter().enumerate().rev() {
            let following = if *tag != b"'"[..] {
                next.insert(tag, position)
            } else if apostrophe(position) {
                quotes[n].1 = position;
                continue;
            } else {
                next_literal.replace(position)
            };
            if let Some(end) = following {
                let line = line_ends.partition_point(|&p| p < end);
                let line_start = if line == 0 {
                    0
                } else {
                    line_ends[line - 1] + 1
                };
                let mut before = end;
                while before > line_start
                    && (b[before - 1].is_ascii_whitespace()
                        || matches!(b[before - 1], b'"' | b'\'' | b'`'))
                {
                    before -= 1;
                }
                // A quote opening a later line's assignment is not a trustworthy
                // close for an earlier credential, nor is one on the same line
                // that directly opens a value (`key='value`). Fail closed
                // through EOF.
                let assignment = before > line_start && matches!(b[before - 1], b'=' | b':' | b'>');
                // On the same line only `=` and `:` open a value: a quote
                // after `>` closes a tag-shaped value (`"<name>"`).
                let opens_value = assignment
                    && matches!(b[before - 1], b'=' | b':')
                    && b.get(end + 1)
                        .is_some_and(|c| !c.is_ascii_whitespace() && !b")]},;>".contains(c));
                if !assignment || (line_start <= position && !opens_value) {
                    quotes[n].1 = end;
                }
            }
        }
        // URL recognition uses only source offsets, quotes and line ends.
        // Attribute-local views do not need assignment/container indexes.
        if mode != Decode::Escapes {
            return Self {
                text,
                changes,
                quotes,
                line_ends,
                scopes: Vec::new(),
                containers: Vec::new(),
                line_keys: Vec::new(),
                indented: Vec::new(),
            };
        }
        let mut scopes = Vec::new();
        let mut stack = Vec::new();
        for &(position, end) in &quotes {
            let closing = stack.last() == Some(&position);
            while stack.last().is_some_and(|&end| end <= position) {
                stack.pop();
            }
            let outer = stack.last().copied().unwrap_or(usize::MAX);
            // An apostrophe (extent `position`) opens no scope.
            if !closing && end > position && end <= outer.min(b.len()) {
                stack.push(end);
            }
            scopes.push((position + 1, stack.last().copied().unwrap_or(usize::MAX)));
        }
        let mut containers = Vec::new();
        let mut stack = Vec::new();
        let mut line_keys = Vec::new();
        let mut leading = true;
        for (position, &ch) in b.iter().enumerate() {
            if ch == b'\n'
                && (all_literal
                    || changes
                        .binary_search_by_key(&position, |c| c.position)
                        .is_err())
            {
                leading = true;
            } else if leading
                && !ch.is_ascii_whitespace()
                && (ch != b'-' || !b.get(position + 1).is_some_and(u8::is_ascii_whitespace))
            {
                line_keys.push(position);
                leading = false;
            }
        }
        let mut position = 0;
        while position < b.len() {
            match b[position] {
                b'"' | b'\'' | b'`' => {
                    let end = quotes
                        .binary_search_by_key(&position, |q| q.0)
                        .map_or(b.len(), |n| quotes[n].1);
                    // A public scalar may itself contain credential config.
                    // Index its delimiters with a separate stack, so those
                    // scopes end inside the quote without affecting the outer
                    // document. Each byte belongs to exactly one such scan.
                    let mut inner = Vec::new();
                    for (cursor, &ch) in b.iter().enumerate().take(end).skip(position + 1) {
                        match ch {
                            b'{' | b'[' => {
                                inner.push((containers.len(), ch));
                                containers.push((cursor, end));
                            }
                            b'}' | b']' => {
                                if let Some(&(n, open)) = inner.last() {
                                    if (open == b'{' && ch == b'}') || (open == b'[' && ch == b']')
                                    {
                                        containers[n].1 = cursor + 1;
                                        inner.pop();
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    position = end.saturating_add(1);
                    continue;
                }
                b'{' | b'[' => {
                    stack.push((containers.len(), b[position]));
                    containers.push((position, b.len()));
                }
                b'}' | b']' => {
                    if let Some(&(n, open)) = stack.last() {
                        if (open == b'{' && b[position] == b'}')
                            || (open == b'[' && b[position] == b']')
                        {
                            containers[n].1 = position + 1;
                            stack.pop();
                        }
                    }
                }
                _ => {}
            }
            position += 1;
        }
        // Resolve indentation extents once. Each line enters/leaves the stack
        // once; repeated keys never rescan an arbitrarily large YAML prefix.
        let mut indented: Vec<(usize, usize)> = Vec::new();
        let mut stack: Vec<(usize, usize)> = Vec::new();
        let mut line = 0;
        for &key in &line_keys {
            if b[key] == b'#' {
                continue;
            }
            while line < line_ends.len() && line_ends[line] < key {
                line += 1;
            }
            let start = if line == 0 {
                0
            } else {
                line_ends[line - 1] + 1
            };
            let indent = key - start;
            while stack.last().is_some_and(|&(_, depth)| depth >= indent) {
                let (index, _) = stack.pop().expect("indentation stack");
                indented[index].1 = start;
            }
            stack.push((indented.len(), indent));
            indented.push((key, b.len()));
        }
        Self {
            text,
            changes,
            quotes,
            scopes,
            containers,
            line_keys,
            line_ends,
            indented,
        }
    }
}
