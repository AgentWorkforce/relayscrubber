#![allow(missing_docs)]
//! 0.5.0-alpha.10 prose disclosure classes. Each case runs through the checked,
//! text, long, JSON and record paths and must be idempotent.
//!
//! - Bare colon and equals cues (`pw: x`, `password = velvet river lantern`)
//!   redact the whole value for every noun, with no minimum length, while type
//!   annotations and code stay byte identical.
//! - A quoted value ends at the first close quote preceded by an even run of
//!   backslashes (`"abc\"def"` is one value; `"abc\\"` closes).
//! - Every `char::is_whitespace` separator, and its encoded spellings, joins
//!   the words of a disclosure.
//! - Words before a colon or equals cue (a determiner, an adjective, a verb
//!   phrase, a conjunction, a bullet or a label) never redact less than the
//!   bare cue does.

use relayscrubber::{scrub_json, scrub_long, scrub_records, scrub_text, scrub_text_checked};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Case {
    id: String,
    kind: String,
    input: String,
    expected: String,
}

const R: &str = "[REDACTED]";
const PUBLIC: &str = "QUALIFICATION_PUBLIC_CONTEXT";
const NOUNS: [&str; 8] = [
    "password",
    "passcode",
    "passphrase",
    "passwd",
    "pwd",
    "pw",
    "pass code",
    "pass phrase",
];
const WORD_CUES: [&str; 6] = ["is", "was", "is now", "set to", "is set to", "was set to"];

fn check(id: &str, input: &str, expected: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let value = json!({ "text": input });
    let records = scrub_records(value.to_string().as_bytes()).expect("valid record");
    let outputs = [
        ("checked", scrub_text_checked(input).expect("admitted text")),
        ("text", scrub_text(input)),
        ("long", scrub_long(input)),
        (
            "json",
            scrub_json(&value).0["text"]
                .as_str()
                .expect("JSON text")
                .to_owned(),
        ),
        (
            "records",
            serde_json::from_slice::<serde_json::Value>(&records.bytes).unwrap()["text"]
                .as_str()
                .expect("record text")
                .to_owned(),
        ),
    ];
    for (api, output) in outputs {
        if output != expected {
            failures.push(format!(
                "{id}/{api}: {input:?} -> {output:?}, want {expected:?}"
            ));
        } else if scrub_text(&output) != output {
            failures.push(format!("{id}/{api}: second pass changed {output:?}"));
        }
    }
    if scrub_records(&records.bytes).expect("second pass").bytes != records.bytes {
        failures.push(format!("{id}/records: second pass changed"));
    }
    failures
}

fn run(cases: &[(String, String, String)]) -> Vec<String> {
    cases
        .iter()
        .flat_map(|(id, input, expected)| check(id, input, expected))
        .collect()
}

fn report(name: &str, cases: usize, failures: &[String]) {
    let failed: std::collections::BTreeSet<&str> = failures
        .iter()
        .map(|f| f.split('/').next().unwrap_or(f))
        .collect();
    eprintln!(
        "{name}: {cases} cases, {} failing cases, {} failing case/API pairs",
        failed.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{}",
        failures[..failures.len().min(40)].join("\n")
    );
}

/// Every noun, with and without a determiner, after every word cue (with
/// one or two spaces or a tab) and every colon and equals layout.
fn cue_matrix() -> Vec<(String, String, String)> {
    let mut layouts: Vec<(String, String)> = Vec::new();
    for cue in WORD_CUES {
        for gap in [" ", "  ", "\t"] {
            layouts.push((format!("{gap}{}{gap}", cue.replace(' ', gap)), cue.into()));
        }
    }
    for layout in [": ", ":", " : ", ":\t", " = ", "=", "= ", " ="] {
        layouts.push((layout.into(), layout.trim().into()));
    }
    let values = [
        ("", "Q"),
        ("", "orchid"),
        ("", "velvet river lantern"),
        ("\"", "orchid lamp"),
        ("'", "orchid lamp"),
        ("`", "orchid lamp"),
        ("", "松🔐éж"),
    ];
    let mut cases = Vec::new();
    for noun in NOUNS {
        for determiner in ["", "my "] {
            for (layout, cue) in &layouts {
                for (quote, value) in values {
                    let left = format!("{PUBLIC}\n{determiner}{noun}{layout}{quote}");
                    cases.push((
                        format!("cue {determiner}{noun} {cue:?} {layout:?} {quote}{value}{quote}"),
                        format!("{left}{value}{quote}"),
                        format!("{left}{R}{quote}"),
                    ));
                }
            }
        }
    }
    cases
}

#[test]
fn every_noun_cue_and_layout_redacts_the_whole_value() {
    let cases = cue_matrix();
    assert_eq!(cases.len(), 8 * 2 * 26 * 7);
    report("cue matrix", cases.len(), &run(&cases));
}

/// `"abc\"def"`: an odd backslash run escapes the quote, an even run is part
/// of the value and the quote closes. The JSON and record paths carry each
/// case one escape level deeper.
fn escape_matrix() -> Vec<(String, String, String)> {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for cue in WORD_CUES {
            for quote in ['"', '\'', '`'] {
                for slashes in 1..=4 {
                    let run = "\\".repeat(slashes);
                    let left = format!("{PUBLIC}\nmy {noun} {cue} {quote}");
                    let input = format!("{left}abc{run}{quote}def{quote}");
                    let expected = if slashes % 2 == 1 {
                        format!("{left}{R}{quote}")
                    } else {
                        format!("{left}{R}{quote}def{quote}")
                    };
                    cases.push((
                        format!("escape {noun} {cue} {quote} {slashes}"),
                        input,
                        expected,
                    ));
                }
            }
        }
    }
    cases
}

#[test]
fn an_escaped_close_quote_does_not_end_the_value() {
    let cases = escape_matrix();
    assert_eq!(cases.len(), 8 * 6 * 3 * 4);
    report("escape matrix", cases.len(), &run(&cases));
}

#[test]
fn an_escaped_quote_keeps_the_unmatched_and_bounded_rules() {
    let long = "x".repeat(1100);
    let cases = [
        // No unescaped close on the line: fail closed through the line end.
        ("my password is \"abc\\\"def", format!("my password is {R}")),
        (
            "my password is \"abc\\\"def\nnext line",
            format!("my password is {R}\nnext line"),
        ),
        // A close past the 1024-byte bound is not searched for.
        (
            &*format!("my password is \"abc\\\"{long}\n\"tail"),
            format!("my password is {R}\n\"tail"),
        ),
    ];
    let cases: Vec<_> = cases
        .iter()
        .enumerate()
        .map(|(i, (input, expected))| (format!("bound {i}"), input.to_string(), expected.clone()))
        .collect();
    report("escape bounds", cases.len(), &run(&cases));
}

/// Every `char::is_whitespace` code point that is not a line break.
const SPACES: [char; 18] = [
    '\t', ' ', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
    '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{202f}', '\u{205f}',
    '\u{3000}',
];
/// Every `char::is_whitespace` line break.
const BREAKS: [&str; 8] = [
    "\n", "\r\n", "\r", "\u{b}", "\u{c}", "\u{85}", "\u{2028}", "\u{2029}",
];

#[test]
fn the_separator_table_is_rust_whitespace() {
    let all: Vec<char> = (0..=0x10ffff)
        .filter_map(char::from_u32)
        .filter(|c| c.is_whitespace())
        .collect();
    let mut table: Vec<char> = SPACES.to_vec();
    table.extend(
        BREAKS
            .iter()
            .filter(|b| b.chars().count() == 1)
            .flat_map(|b| b.chars()),
    );
    table.sort_unstable();
    assert_eq!(table, all);
}

fn separator_matrix() -> Vec<(String, String, String)> {
    let mut cases = Vec::new();
    for (i, space) in SPACES.iter().enumerate() {
        let s = space.to_string();
        for template in [
            "my{s}password{s}is{s}",
            "my{s}pass{s}code{s}is{s}",
            "my{s}pass{s}phrase{s}was{s}",
            "pass{s}phrase:{s}",
            "pass{s}code{s}={s}",
            "pw{s}is{s}set{s}to{s}",
        ] {
            let left = template.replace("{s}", &s);
            cases.push((
                format!("space U+{:04X} {template}", u32::from(*space)),
                format!("{PUBLIC}\n{left}velvet{s}river"),
                format!("{PUBLIC}\n{left}{R}"),
            ));
        }
        let _ = i;
    }
    for b in BREAKS {
        for template in [
            "my pass{b}code is ",
            "my pass{b}phrase is ",
            "my password{b}is ",
            "my password is{b}",
            "my{b}password is ",
        ] {
            let left = template.replace("{b}", b);
            cases.push((
                format!("break {b:?} {template}"),
                format!("{PUBLIC}\n{left}orchid"),
                format!("{PUBLIC}\n{left}{R}"),
            ));
        }
    }
    cases
}

#[test]
fn every_whitespace_separator_and_line_break_joins_the_disclosure() {
    let cases = separator_matrix();
    assert_eq!(cases.len(), 18 * 6 + 8 * 5);
    report("separator matrix", cases.len(), &run(&cases));
}

/// Encoded spellings of a space and of the other separators.
const ENCODED: [&str; 22] = [
    "&#32;",
    "&#032;",
    "&#32",
    "&#x20;",
    "&#X20;",
    "&#x020;",
    "&#9;",
    "&#xA0;",
    "&#160;",
    "&nbsp;",
    "&nbsp",
    "&NonBreakingSpace;",
    "&ensp;",
    "&emsp;",
    "&thinsp;",
    "&hairsp;",
    "&MediumSpace;",
    "&#x1680;",
    "&#8287;",
    "%C2%A0",
    "%E1%9A%80",
    "%E2%81%9F",
];
const ENCODED_ESCAPES: [&str; 8] = [
    "%20",
    "%u0020",
    "%u205F",
    "\\u0020",
    "\\u00a0",
    "\\u205f",
    "\\u{1680}",
    "\\x20",
];

fn encoded_matrix() -> Vec<(String, String, String)> {
    let mut cases = Vec::new();
    for e in ENCODED.iter().chain(ENCODED_ESCAPES.iter()) {
        for template in [
            "my{s}password{s}is{s}",
            "my{s}pass{s}code{s}is{s}",
            "my pass{s}phrase{s}was{s}",
            "pass{s}phrase:{s}",
            "pass{s}code{s}={s}",
        ] {
            let left = template.replace("{s}", e);
            cases.push((
                format!("encoded {e} {template}"),
                format!("{PUBLIC}\n{left}orchid"),
                format!("{PUBLIC}\n{left}{R}"),
            ));
        }
    }
    for b in [
        "&#10;",
        "&#xA;",
        "&NewLine;",
        "&#13;",
        "&#x2028;",
        "%E2%80%A8",
        "\\u2028",
    ] {
        for template in ["my pass{b}code is ", "my pass{b}phrase is "] {
            let left = template.replace("{b}", b);
            cases.push((
                format!("encoded break {b} {template}"),
                format!("{PUBLIC}\n{left}orchid"),
                format!("{PUBLIC}\n{left}{R}"),
            ));
        }
    }
    cases
}

#[test]
fn encoded_separators_join_the_disclosure() {
    let cases = encoded_matrix();
    assert_eq!(cases.len(), 30 * 5 + 7 * 2);
    report("encoded separator matrix", cases.len(), &run(&cases));
}

const CUES: [&str; 8] = [":", " :", ": ", " : ", "=", " = ", "= ", " ="];
/// Determiners, adjectives, verb phrases, conjunctions, bullets and labels.
const PREFIXES: [&str; 34] = [
    "my ",
    "our ",
    "your ",
    "the ",
    "The ",
    "its ",
    "my new ",
    "The new ",
    "the old ",
    "The wifi ",
    "Use this ",
    "Please use ",
    "Enter your ",
    "Use the new ",
    "Here is the ",
    "and my ",
    "and the ",
    "but your ",
    "And the new ",
    "- ",
    "* ",
    "- my ",
    "1. ",
    "* the new ",
    "note: ",
    "Note: my ",
    "FYI: ",
    "note: the new ",
    "x y ",
    "Reset ",
    "admin ",
    "We discussed ",
    "Here is my ",
    "or the ",
];

/// Whatever the bare colon or equals cue redacts, the same disclosure after
/// any prefix redacts too: one character, an ordinary value, several words,
/// a value that starts with a documentary word or holds a conjunction, a
/// quoted value with spaces, and Unicode.
fn prefix_matrix() -> Vec<(String, String, String)> {
    let values = [
        ("", "Q"),
        ("", "zq9Secret"),
        ("", "velvet river lantern"),
        ("", "correct horse battery"),
        ("", "required and then"),
        ("", "see vault later"),
        ("", "example and then"),
        ("", "none and then"),
        ("", "orchid7 and tulip"),
        ("", "wrong or right"),
        ("", "valid but long"),
        ("\"", "velvet river"),
        ("'", "velvet river"),
        ("`", "velvet river"),
        ("", "pässwört ünï"),
        ("", "密码 秘密"),
    ];
    let mut cases = Vec::new();
    for noun in NOUNS {
        for cue in CUES {
            for (quote, value) in values {
                for prefix in PREFIXES {
                    let left = format!("{PUBLIC}\n{prefix}{noun}{cue}{quote}");
                    cases.push((
                        format!("prefix {prefix:?} {noun}{cue:?} {quote}{value}{quote}"),
                        format!("{left}{value}{quote}"),
                        format!("{left}{R}{quote}"),
                    ));
                }
            }
        }
    }
    cases
}

#[test]
fn a_prefix_never_redacts_less_than_the_bare_cue() {
    let cases = prefix_matrix();
    assert_eq!(cases.len(), 8 * 8 * 16 * 34);
    report("prefix matrix", cases.len(), &run(&cases));
}

/// A value with an unbalanced close bracket, or a `&` or `;` before what
/// looks like another key, after any prefix (a word, a bullet) is redacted whole,
/// as the bare cue's assignment redacts it: the bracket or separator is part
/// of the value unless the line opened a bracket or a list before the key.
#[test]
fn a_prefix_redacts_a_value_with_a_close_bracket_or_separator_whole() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for cue in CUES {
            for value in [
                "ab)cd", "x]y z", "q}r", "6)K", "h{E]MT-a", "f(x) y", "ab&cd=ef", "k;host=y",
            ] {
                for prefix in PREFIXES {
                    let left = format!("{PUBLIC}\n{prefix}{noun}{cue}");
                    cases.push((
                        format!("bracket {prefix:?} {noun}{cue:?} {value}"),
                        format!("{left}{value}"),
                        format!("{left}{R}"),
                    ));
                }
            }
        }
    }
    assert_eq!(cases.len(), 8 * 8 * 8 * 34);
    // A bracket or a list the line opened before the key still ends it.
    for (input, expected) in [
        (
            "(my password: abc) see docs",
            "(my password: [REDACTED]) see docs",
        ),
        (
            "f(the password=abc) more",
            "f(the password=[REDACTED]) more",
        ),
        ("[my pw: x] ok", "[my pw: [REDACTED]] ok"),
        (
            "call(note password: abc) end",
            "call(note password: [REDACTED]) end",
        ),
        (
            "host=db;my password=abc;user=x",
            "host=db;my password=[REDACTED];user=x",
        ),
        ("?a=1&my pw=abc&b=2", "?a=1&my pw=[REDACTED]&b=2"),
    ] {
        cases.push((
            format!("enclosed {input:?}"),
            format!("{PUBLIC}\n{input}"),
            format!("{PUBLIC}\n{expected}"),
        ));
    }
    report(
        "prefix bracket and separator values",
        cases.len(),
        &run(&cases),
    );
}

/// Values with an unmatched close bracket, or a `&key=` or `;key=` inside
/// them: one word, several words and Unicode.
const DELIMITED_VALUES: [&str; 15] = [
    "x]yq",
    "x)yq",
    "x}yq",
    "abc&def=ghi",
    "abc;host=y",
    "x]yq zq",
    "x)yq zq",
    "x}yq zq",
    "abc&def=ghi jk",
    "abc;host=y zz",
    "密]码 秘",
    "pä)ss ü",
    "ж}ок",
    "密码&键=值",
    "ünï;host=ж",
];

/// The bare colon or equals cue redacts such a value whole, for every noun
/// and layout: a close bracket the line did not open before the noun, and a
/// `;` or `&` on a line that was not a list before the noun, belong to the
/// value. A determiner or words before the noun redact the same value.
fn bare_delimiter_matrix(noun: &str) -> Vec<(String, String, String)> {
    let mut cases = Vec::new();
    for lead in ["", "my ", "The new "] {
        for cue in CUES {
            for value in DELIMITED_VALUES {
                let left = format!("{PUBLIC}\n{lead}{noun}{cue}");
                cases.push((
                    format!("bare delimiter {lead:?} {noun}{cue:?} {value}"),
                    format!("{left}{value}"),
                    format!("{left}{R}"),
                ));
            }
        }
    }
    cases
}

#[test]
fn a_bare_cue_redacts_a_value_with_a_close_bracket_or_separator_whole() {
    let mut total = 0;
    let mut failures = Vec::new();
    for noun in NOUNS {
        let cases = bare_delimiter_matrix(noun);
        assert_eq!(cases.len(), 3 * 8 * 15);
        total += cases.len();
        failures.extend(run(&cases));
    }
    report("bare bracket and separator values", total, &failures);
}

/// A bracket or a list the line opened before the noun still ends the value,
/// after a bare cue as after a prefixed one.
#[test]
fn a_bracket_or_list_opened_before_a_bare_cue_still_ends_it() {
    let mut cases = Vec::new();
    for (input, expected) in [
        ("(my pw: abc) docs", "(my pw: [REDACTED]) docs"),
        ("(pw: abc) docs", "(pw: [REDACTED]) docs"),
        ("[pass code: x] ok", "[pass code: [REDACTED]] ok"),
        ("{pass phrase=abc} more", "{pass phrase=[REDACTED]} more"),
        ("host=db;pw=abc;user=x", "host=db;pw=[REDACTED];user=x"),
        (
            "host=db;pass code=abc;user=x",
            "host=db;pass code=[REDACTED];user=x",
        ),
        ("?a=1&pw=abc&b=2", "?a=1&pw=[REDACTED]&b=2"),
        ("a=1&pass phrase=abc&b=2", "a=1&pass phrase=[REDACTED]&b=2"),
    ] {
        cases.push((
            format!("enclosed bare {input:?}"),
            format!("{PUBLIC}\n{input}"),
            format!("{PUBLIC}\n{expected}"),
        ));
    }
    report("bare enclosed controls", cases.len(), &run(&cases));
}

/// No quoted segment that touches the value's close quote survives: the
/// same quote twice, mixed quotes, or more than two segments. A later quoted
/// string after whitespace keeps today's boundary.
#[test]
fn contiguous_quoted_segments_are_one_value() {
    let segments = [
        ("\"abc\"\"defq\"", "\""),
        ("'abc''defq'", "'"),
        ("`abc``defq`", "`"),
        ("\"abc\"'defq'", "'"),
        ("'abc'\"defq\"", "\""),
        ("\"abc\"`defq`", "`"),
        ("“abc”“defq”", "”"),
        ("“abc”‘defq’", "’"),
        ("‘abc’\"defq\"", "\""),
        ("\"abc\"\"de\"'fq'", "'"),
        ("\"密码\"\"秘ж\"", "\""),
    ];
    let mut cases = Vec::new();
    for noun in NOUNS {
        for (lead, cue) in [
            ("my ", " is "),
            ("my ", " was set to "),
            ("", ": "),
            ("", "="),
            ("my ", ": "),
            ("The new ", " = "),
        ] {
            for (value, close) in segments {
                let open: String = value.chars().take(1).collect();
                let left = format!("{PUBLIC}\n{lead}{noun}{cue}");
                // Everything between the first opener and the last close is
                // the value. The quotes stay, except where a sensitive
                // assignment fails closed on mixed quotes through the line
                // (`password: "[REDACTED]`); every API must agree on it.
                let input = format!("{left}{value}");
                let whole = format!("{left}{open}{R}{close}");
                let text = scrub_text(&input);
                let expected = if [format!("{left}{open}{R}"), format!("{left}{R}")].contains(&text)
                {
                    text
                } else {
                    whole
                };
                cases.push((
                    format!("quoted {lead}{noun}{cue:?} {value}"),
                    input,
                    expected,
                ));
            }
            let left = format!("{PUBLIC}\n{lead}{noun}{cue}");
            cases.push((
                format!("quoted spaced {lead}{noun}{cue:?}"),
                format!("{left}\"abc\" \"defq\""),
                format!("{left}\"{R}\" \"defq\""),
            ));
        }
    }
    // An unmatched contiguous segment fails closed; a quote the line opened
    // before the noun, or the end of an enclosing JSON string, is not a
    // segment; an apostrophe is not an opened quote.
    for (input, expected) in [
        ("my password is \"abc\"\"de", "my password is \"[REDACTED]"),
        ("pw: 'abc''de", "pw: '[REDACTED]"),
        (
            "echo \"my password is 'abc'\"",
            "echo \"my password is '[REDACTED]'\"",
        ),
        ("title=\"pw: 'abc'\" x", "title=\"pw: '[REDACTED]'\" x"),
        (
            "Don't forget, my password is 'abc''defq'",
            "Don't forget, my password is '[REDACTED]'",
        ),
        (
            "{\"t\":\"my password is \\\"abc\\\"\\\"defq\\\"\"}",
            "{\"t\":\"my password is \\\"[REDACTED]\\\"\"}",
        ),
        (
            "{\"t\":\"my password is \\\"abc\\\"\"}",
            "{\"t\":\"my password is \\\"[REDACTED]\\\"\"}",
        ),
    ] {
        cases.push((
            format!("quoted named {input:?}"),
            format!("{PUBLIC}\n{input}"),
            format!("{PUBLIC}\n{expected}"),
        ));
    }
    report("contiguous quoted segments", cases.len(), &run(&cases));
}

/// A benign control never redacts less after a prefix: what the bare cue
/// redacts (`password=string`) the prefixed form redacts too, and what the
/// bare cue keeps (`password: $PASSWORD`) the prefixed form keeps or redacts
/// whole, never in part. `{{ password }}` is a template placeholder: the bare
/// cue redacts it as a failed reference, while a prefixed sentence keeps it.
#[test]
fn a_prefix_keeps_the_bare_cue_outcome_for_benign_controls() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for cue in CUES {
            for value in ["string", "$PASSWORD", "${{ secrets.PW }}", "none", "null"] {
                let input = format!("{PUBLIC}\n{noun}{cue}{value}");
                let bare = scrub_text(&input);
                let tail = bare.strip_prefix(&format!("{PUBLIC}\n")).unwrap();
                for prefix in PREFIXES {
                    let input = format!("{PUBLIC}\n{prefix}{noun}{cue}{value}");
                    let redacted = format!("{PUBLIC}\n{prefix}{noun}{cue}{R}");
                    let expected = if bare != format!("{PUBLIC}\n{noun}{cue}{value}") {
                        format!("{PUBLIC}\n{prefix}{tail}")
                    } else if scrub_text(&input) == redacted {
                        redacted
                    } else {
                        input.clone()
                    };
                    cases.push((
                        format!("benign {prefix:?} {noun}{cue:?} {value}"),
                        input,
                        expected,
                    ));
                }
            }
        }
    }
    assert_eq!(cases.len(), 8 * 8 * 5 * 34);
    report("prefix benign controls", cases.len(), &run(&cases));
}

#[test]
fn named_lead_examples_benign_controls_and_json_escaped_quotes() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../eval/prose_disclosure_alpha10_cases.json")).unwrap();
    for kind in ["positive", "benign"] {
        assert!(cases.iter().any(|c| c.kind == kind));
    }
    let failures: Vec<String> = cases
        .iter()
        .inspect(|c| assert!(c.kind == "positive" || c.input == c.expected, "{}", c.id))
        .flat_map(|c| check(&c.id, &c.input, &c.expected))
        .collect();
    report("alpha.10 named cases", cases.len(), &failures);
}

#[test]
fn every_disclosure_is_idempotent_and_redacted_output_is_stable() {
    // A redacted disclosure is a reference on the next pass, for every
    // noun and cue: the matrices above already require a stable second pass;
    // this pins that the redacted forms themselves are untouched.
    let mut failures = Vec::new();
    for noun in NOUNS {
        for cue in [": ", " = ", " is ", "=", ":"] {
            let input = format!("{noun}{cue}{R}");
            failures.extend(check(&format!("stable {noun}{cue}"), &input, &input));
        }
    }
    report("redacted stability", NOUNS.len() * 5, &failures);
}

/// Leads and cues for the quoted-tail matrix: the intent forms (`is`, `was`,
/// `:`) with and without a determiner, a word cue, and the equals layouts.
const TAIL_CUES: [(&str, &str); 8] = [
    ("my ", " is "),
    ("my ", " was "),
    ("my ", " was set to "),
    ("", ": "),
    ("", "="),
    ("my ", ": "),
    ("The new ", " = "),
    ("", " is "),
];

/// A quoted segment, empty or not, followed by text with no whitespace in
/// between: (value, text kept after the redaction).
const QUOTED_TAILS: [(&str, &str); 22] = [
    ("\"\"abcq", ""),
    ("\"\"abc\"", ""),
    ("''abcq", ""),
    ("``abcq", ""),
    ("\"abc\"defq", ""),
    ("\"abc\"defq\"ghiq\"", ""),
    ("'abc'defq", ""),
    ("`abc`defq", ""),
    ("“abc”defq", ""),
    ("‘abc’defq", ""),
    ("\"abc\"-defq", ""),
    ("\"abc\"(defq)", ""),
    ("\"abc\".defq", ""),
    ("\"abc\"d", ""),
    ("\"abc\"defq.", "."),
    ("\"abc\"defq, ok", ", ok"),
    ("\"abc\"defq more", " more"),
    ("\"abc\"defq\nnext", "\nnext"),
    ("\"密码\"秘ж", ""),
    ("“”秘ж", ""),
    ("'abc'defq'ghiq'", ""),
    ("\"abc\"defq'ghiq'", ""),
];

/// Text that continues a quoted value with no whitespace is the same value,
/// up to the next whitespace; a run of sentence or list punctuation alone
/// keeps today's boundary.
#[test]
fn text_that_touches_a_close_quote_is_part_of_the_value() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for (lead, cue) in TAIL_CUES {
            let left = format!("{PUBLIC}\n{lead}{noun}{cue}");
            for (value, kept) in QUOTED_TAILS {
                let open: String = value.chars().take(1).collect();
                let input = format!("{left}{value}");
                // The quote may stay or go (a sensitive assignment fails
                // closed without it); nothing of the value may.
                let shapes = [format!("{left}{open}{R}{kept}"), format!("{left}{R}{kept}")];
                let text = scrub_text(&input);
                let expected = if shapes.contains(&text) {
                    text
                } else {
                    shapes[0].clone()
                };
                cases.push((format!("tail {lead}{noun}{cue:?} {value}"), input, expected));
            }
            for (value, expected) in [
                ("\"abc\".", "\"[REDACTED]\"."),
                ("\"abc\", ok", "\"[REDACTED]\", ok"),
                ("\"abc\" \"defq\"", "\"[REDACTED]\" \"defq\""),
                (
                    "\"abc\"; the user is bob",
                    "\"[REDACTED]\"; the user is bob",
                ),
                ("\"abc\" and user is bob", "\"[REDACTED]\" and user is bob"),
                ("\"abc\"\"defq\"", "\"[REDACTED]\""),
                ("'abc'.", "'[REDACTED]'."),
                ("`abc`, ok", "`[REDACTED]`, ok"),
                ("“abc”.", "“[REDACTED]”."),
                ("\"abc\"!?", "\"[REDACTED]\"!?"),
                ("\"abc\"...", "\"[REDACTED]\"..."),
            ] {
                cases.push((
                    format!("tail control {lead}{noun}{cue:?} {value}"),
                    format!("{left}{value}"),
                    format!("{left}{expected}"),
                ));
            }
        }
    }
    // Escaped quotes inside a JSON string, one and two levels deep: the tail
    // ends at the string's own close quote.
    for (input, expected) in [
        (
            "{\"note\":\"my password is \\\"abc\\\"defq\"}",
            "{\"note\":\"my password is \\\"[REDACTED]\"}",
        ),
        (
            "{\"note\":\"pw: \\\"abc\\\"defq\"}",
            "{\"note\":\"pw: \\\"[REDACTED]\"}",
        ),
        (
            "{\"note\":\"my password is \\\"\\\"abcq\"}",
            "{\"note\":\"my password is \\\"[REDACTED]\"}",
        ),
        (
            "{\"t\":\"{\\\"note\\\":\\\"my pw is \\\\\\\"abc\\\\\\\"defq\\\"}\"}",
            "{\"t\":\"{\\\"note\\\":\\\"my pw is \\\\\\\"[REDACTED]\\\"}\"}",
        ),
        (
            "{\"note\":\"my password is \\\"abc\\\".\"}",
            "{\"note\":\"my password is \\\"[REDACTED]\\\".\"}",
        ),
        (
            "echo \"my password is 'abc'defq\"",
            "echo \"my password is '[REDACTED]\"",
        ),
    ] {
        cases.push((
            format!("tail named {input:?}"),
            format!("{PUBLIC}\n{input}"),
            format!("{PUBLIC}\n{expected}"),
        ));
    }
    report("quoted value tails", cases.len(), &run(&cases));
}

/// A close bracket ends a bare cue's value only when it matches, by type, the
/// innermost opener still unclosed before the key in the key's own string
/// layer. A close of another type is part of the value.
#[test]
fn only_the_innermost_opener_s_close_ends_the_value() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for cue in [": ", "="] {
            for (input, expected) in [
                // Leaks before the fix.
                (
                    format!("(note {noun}{cue}x]yq zq"),
                    format!("(note {noun}{cue}{R}"),
                ),
                (
                    format!("{{a {noun}{cue}x)yq zq"),
                    format!("{{a {noun}{cue}{R}"),
                ),
                (
                    format!("[a] ({noun}{cue}x]yq zq) end"),
                    format!("[a] ({noun}{cue}{R}) end"),
                ),
                (
                    format!("log (info: {noun}{cue}x]yq zq"),
                    format!("log (info: {noun}{cue}{R}"),
                ),
                (
                    format!("{{\"note\":\"{noun}{cue}x]yq zq\"}}"),
                    format!("{{\"note\":\"{noun}{cue}{R}\"}}"),
                ),
                (
                    format!("{{\"note\":\"{noun}{cue}x}}yq zq\"}}"),
                    format!("{{\"note\":\"{noun}{cue}{R}\"}}"),
                ),
                (
                    format!("{{\"a\":[\"{noun}{cue}x)yq zq\"]}}"),
                    format!("{{\"a\":[\"{noun}{cue}{R}\"]}}"),
                ),
                (
                    format!("{{\"note\":\"(info: {noun}{cue}x]yq zq\"}}"),
                    format!("{{\"note\":\"(info: {noun}{cue}{R}\"}}"),
                ),
                (
                    format!("(say \"{noun}{cue}x)yq zq\""),
                    format!("(say \"{noun}{cue}{R}\""),
                ),
                (
                    format!("[a {{b}} {noun}{cue}x}}yq zq"),
                    format!("[a {{b}} {noun}{cue}{R}"),
                ),
                (
                    format!("say \"(a {noun}{cue}x]y) z\""),
                    format!("say \"(a {noun}{cue}{R}) z\""),
                ),
                // Controls.
                (
                    format!("[a (b) {noun}{cue}x]yq zq"),
                    format!("[a (b) {noun}{cue}{R}]yq zq"),
                ),
                (
                    format!("(my {noun}{cue}abc) docs"),
                    format!("(my {noun}{cue}{R}) docs"),
                ),
                (format!("[{noun}{cue}x]yq"), format!("[{noun}{cue}{R}]yq")),
                (
                    format!("{{{noun}{cue}x}}yq"),
                    format!("{{{noun}{cue}{R}}}yq"),
                ),
                (format!("{noun}{cue}x]yq zq"), format!("{noun}{cue}{R}")),
                (format!("{noun}{cue}(x)yq"), format!("{noun}{cue}{R}")),
                (format!("{noun}{cue}[x]yq"), format!("{noun}{cue}{R}")),
                (format!("{noun}{cue}x}}yq"), format!("{noun}{cue}{R}")),
                (
                    format!("[note] {noun}{cue}x)yq zq"),
                    format!("[note] {noun}{cue}{R}"),
                ),
                (
                    format!("(see docs) {noun}{cue}x)yq zq"),
                    format!("(see docs) {noun}{cue}{R}"),
                ),
                (
                    format!("log [info] {noun}{cue}x]yq zq"),
                    format!("log [info] {noun}{cue}{R}"),
                ),
                (
                    format!("{{\"note\":\"(my {noun}{cue}abc) docs\"}}"),
                    format!("{{\"note\":\"(my {noun}{cue}{R}) docs\"}}"),
                ),
                (
                    format!("(a {noun}{cue}f(x)y) z"),
                    format!("(a {noun}{cue}{R}) z"),
                ),
            ] {
                cases.push((
                    format!("innermost {input:?}"),
                    format!("{PUBLIC}\n{input}"),
                    format!("{PUBLIC}\n{expected}"),
                ));
            }
        }
    }
    report("innermost opener", cases.len(), &run(&cases));
}

/// A `;` or `&` ends a bare cue's value only when the line before the key
/// already holds a key=value item ended by that same separator and the key
/// starts right after it.
#[test]
fn only_a_list_the_line_already_is_ends_the_value_at_its_separator() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for (input, expected) in [
            // Leaks before the fix.
            (
                format!("a;b {noun}: abc;host=y"),
                format!("a;b {noun}: {R}"),
            ),
            (
                format!("note; my {noun}: abc;host=y"),
                format!("note; my {noun}: {R}"),
            ),
            (
                format!("R&D {noun}: abc&def=ghi"),
                format!("R&D {noun}: {R}"),
            ),
            (
                format!("a & b; {noun}: abc;host=y"),
                format!("a & b; {noun}: {R}"),
            ),
            (format!("a=1;{noun}=abc&user=x"), format!("a=1;{noun}={R}")),
            (
                format!("a=1& b {noun}: abc&def=ghi"),
                format!("a=1& b {noun}: {R}"),
            ),
            (
                format!("x=1; note {noun}: abc;host=y"),
                format!("x=1; note {noun}: {R}"),
            ),
            // Controls.
            (
                format!("host=db;{noun}=abc;user=x"),
                format!("host=db;{noun}={R};user=x"),
            ),
            (
                format!("a=1&{noun}=abc&user=x"),
                format!("a=1&{noun}={R}&user=x"),
            ),
            (
                format!("host=db; {noun}=abc; user=x"),
                format!("host=db; {noun}={R}; user=x"),
            ),
            (
                format!("?a=1&{noun}=abc&b=2"),
                format!("?a=1&{noun}={R}&b=2"),
            ),
            (
                format!("x=1 {noun}: abc&def=ghi"),
                format!("x=1 {noun}: {R}"),
            ),
            (
                format!("url?a=1 says {noun}: abc&def=ghi"),
                format!("url?a=1 says {noun}: {R}"),
            ),
            (format!("{noun}: abc;host=y"), format!("{noun}: {R}")),
            (format!("{noun}: a&b"), format!("{noun}: {R}")),
        ] {
            cases.push((
                format!("list {input:?}"),
                format!("{PUBLIC}\n{input}"),
                format!("{PUBLIC}\n{expected}"),
            ));
        }
    }
    report("list separator", cases.len(), &run(&cases));
}
