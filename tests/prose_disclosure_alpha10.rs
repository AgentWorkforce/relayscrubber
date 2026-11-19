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
