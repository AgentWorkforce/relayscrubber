//! Bounded, complete source expressions containing references rather than secrets.

use crate::engine::{credential_context, sensitive};

// The caller supplies at most 512 bytes. Every token advances one cursor; the
// depth cap also bounds the stack for adversarially nested source fragments.
struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    depth: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }

    fn take(&mut self, token: &[u8]) -> bool {
        self.space();
        if self.bytes[self.at..].starts_with(token) {
            self.at += token.len();
            true
        } else {
            false
        }
    }

    fn identifier(&mut self) -> Option<&str> {
        self.space();
        let start = self.at;
        if !self
            .bytes
            .get(start)
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        {
            return None;
        }
        self.at += 1;
        while self
            .bytes
            .get(self.at)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            self.at += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.at]).ok()
    }

    fn expression(&mut self, numbers: bool) -> bool {
        if self.depth >= 32 {
            return false;
        }
        self.depth += 1;
        let result = self.inner(numbers);
        self.depth -= 1;
        result
    }

    fn inner(&mut self, numbers: bool) -> bool {
        if !self.operand(numbers) {
            return false;
        }
        loop {
            self.space();
            // Adjacent slash/comment openers are lexical comments, never
            // division followed by a regex operand. Their tails remain data.
            if self.bytes[self.at..].starts_with(b"//") || self.bytes[self.at..].starts_with(b"/*")
            {
                return false;
            }
            if self.bytes[self.at..].starts_with(b"?.") {
                return false;
            }
            let operator = [
                b"===".as_slice(),
                b"!==",
                b"==",
                b"!=",
                b"<=",
                b">=",
                b"&&",
                b"||",
                b"??",
                b"+",
                b"-",
                b"*",
                b"/",
                b"%",
                b"&",
                b"|",
                b"^",
                b"<",
                b">",
            ]
            .iter()
            .find(|op| self.bytes[self.at..].starts_with(op))
            .copied();
            if let Some(operator) = operator {
                // A hyphenated scalar is credential data, not evidence of
                // subtraction. Require explicit token spacing for this form.
                if operator == b"-"
                    && !(self.at > 0
                        && self.bytes[self.at - 1].is_ascii_whitespace()
                        && self
                            .bytes
                            .get(self.at + 1)
                            .is_some_and(u8::is_ascii_whitespace))
                {
                    return false;
                }
                self.at += operator.len();
                if !self.operand(numbers) {
                    return false;
                }
            } else if self.take(b"?") {
                return self.expression(numbers) && self.take(b":") && self.expression(numbers);
            } else {
                return true;
            }
        }
    }

    fn operand(&mut self, numbers: bool) -> bool {
        self.space();
        if self.take(b"!") || self.take(b"~") || self.take(b"&") {
            return self.expression(false);
        }
        if self.take(b"(") {
            if !self.expression(numbers) || !self.take(b")") {
                return false;
            }
        } else if self.take(b"{") {
            if !self.take(b"}") {
                loop {
                    let Some(key) = self.identifier() else {
                        return false;
                    };
                    let number = !sensitive(key)
                        && !credential_context(key)
                        && !key.eq_ignore_ascii_case("key");
                    if self.take(b":") && !self.expression(number) {
                        return false;
                    }
                    if self.take(b"}") {
                        break;
                    }
                    if !self.take(b",") {
                        return false;
                    }
                    if self.take(b"}") {
                        break;
                    }
                }
            }
        } else if self.take(b"[") {
            if !self.list(b"]") {
                return false;
            }
        } else if numbers
            && self
                .bytes
                .get(self.at)
                .is_some_and(|b| b.is_ascii_digit() || *b == b'-')
        {
            let start = self.at;
            while self
                .bytes
                .get(self.at)
                .is_some_and(|b| b.is_ascii_digit() || b".-+eE".contains(b))
            {
                self.at += 1;
            }
            if serde_json::from_slice::<serde_json::Number>(&self.bytes[start..self.at]).is_err() {
                return false;
            }
        } else {
            let Some(name) = self.identifier() else {
                return false;
            };
            if matches!(name, "new" | "await" | "typeof") {
                return self.expression(false);
            }
        }
        loop {
            if self.take(b"?.") || self.take(b".") || self.take(b"::") {
                if self.identifier().is_none() {
                    return false;
                }
            } else if self.take(b"(") {
                if !self.list(b")") {
                    return false;
                }
            } else if self.take(b"[") {
                if !self.expression(false) || !self.take(b"]") {
                    return false;
                }
            } else {
                return true;
            }
        }
    }

    fn list(&mut self, close: &[u8]) -> bool {
        if self.take(close) {
            return true;
        }
        loop {
            if !self.expression(false) {
                return false;
            }
            if self.take(close) {
                return true;
            }
            if !self.take(b",") {
                return false;
            }
        }
    }
}

pub(crate) fn expression(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || !value.is_ascii() {
        return false;
    }
    let mut parser = Parser {
        bytes: value.as_bytes(),
        at: 0,
        depth: 0,
    };
    parser.expression(false) && {
        parser.space();
        parser.at == parser.bytes.len()
    }
}
