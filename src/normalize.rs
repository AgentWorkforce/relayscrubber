//! One-pass delimiter decoding with offsets back to unchanged source bytes.

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
    let mut p = start + 1;
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
        self.changes
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
    pub fn line_key(&self, position: usize) -> bool {
        self.line_keys.binary_search(&position).is_ok()
    }

    pub fn new(input: &str) -> Self {
        let source = input.as_bytes();
        let mut bytes = Vec::with_capacity(source.len());
        let mut changes = Vec::new();
        let mut tags = Vec::new();
        let mut i = 0;
        while i < source.len() {
            let (ch, end, style) = decoded(source, i);
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
                tags.push((
                    bytes.len() - 1,
                    source[i..end]
                        .iter()
                        .map(u8::to_ascii_lowercase)
                        .collect::<Vec<_>>(),
                ));
            }
            i = end;
        }
        // Decoding changes only ASCII. Original UTF-8 sequences survive.
        let text = String::from_utf8(bytes).expect("normalization preserves UTF-8");
        let b = text.as_bytes();
        let line_ends: Vec<_> = b
            .iter()
            .enumerate()
            .filter_map(|(p, ch)| {
                (matches!(ch, b'\r' | b'\n')
                    && changes.binary_search_by_key(&p, |c| c.position).is_err())
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
            let literal = changes
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
        Self {
            text,
            changes,
            quotes,
            scopes,
            containers,
            line_keys,
            line_ends,
        }
    }
}
