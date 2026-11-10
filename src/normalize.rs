//! One-pass delimiter decoding with offsets back to unchanged source bytes.

use std::borrow::Cow;

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

fn html_decoded(b: &[u8], start: usize) -> (u8, usize, u8) {
    let mut ch = b[start];
    let mut end = start + 1;
    loop {
        let next = match ch {
            b'&' => html_entity(b, end),
            b'%' => percent_tail(b, end),
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
        Self::build(input, false)
    }

    pub fn html_url(input: &str) -> Self {
        Self::build(input, true)
    }

    fn build(input: &str, html: bool) -> Self {
        let source = input.as_bytes();
        let mut bytes = Vec::with_capacity(source.len());
        let mut changes = Vec::new();
        let mut tags = Vec::new();
        let mut i = 0;
        while i < source.len() {
            // Ordinary bytes require no decoder call or escape-state setup.
            let (ch, end, style) = match (html, source[i]) {
                (true, b'&' | b'%') => html_decoded(source, i),
                (false, b'%' | b'\\') => decoded(source, i),
                _ => (source[i], i + 1, 0),
            };
            if style == 255 {
                bytes.extend_from_slice(&source[i..end]);
                i = end;
                continue;
            }
            if end > i + 1 {
                changes.push(Change {
                    position: bytes.len(),
                    start: i,
                    end,
                });
            }
            bytes.push(ch);
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
                tags.push((bytes.len() - 1, tag));
            }
            i = end;
        }
        // Decoding changes only ASCII. Original UTF-8 sequences survive.
        let text = String::from_utf8(bytes).expect("normalization preserves UTF-8");
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
        for (n, (position, tag)) in tags.into_iter().enumerate().rev() {
            if let Some(end) = next.insert(tag, position) {
                let line = line_ends.partition_point(|&p| p < end);
                let line_start = if line == 0 {
                    0
                } else {
                    line_ends[line - 1] + 1
                };
                let mut before = end;
                while before > line_start && b[before - 1].is_ascii_whitespace() {
                    before -= 1;
                }
                // A quote opening a later line's assignment is not a trustworthy
                // close for an earlier credential. Fail closed through EOF.
                if line_start <= position
                    || before == line_start
                    || !matches!(b[before - 1], b'=' | b':' | b'>')
                {
                    quotes[n].1 = end;
                }
            }
        }
        // URL recognition uses only source offsets, quotes and line ends.
        // Attribute-local views do not need assignment/container indexes.
        if html {
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
            if !closing && end <= outer.min(b.len()) {
                stack.push(end);
            }
            scopes.push((position + 1, stack.last().copied().unwrap_or(usize::MAX)));
        }
        let mut containers = Vec::new();
        let mut stack = Vec::new();
        let mut line_keys = Vec::new();
        let mut leading = true;
        for (position, &ch) in b.iter().enumerate() {
            let literal = all_literal
                || changes
                    .binary_search_by_key(&position, |c| c.position)
                    .is_err();
            if ch == b'\n' && literal {
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
