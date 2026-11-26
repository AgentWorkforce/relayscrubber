#![allow(missing_docs)]
//! 0.5.0-alpha.11 descriptor-separated prose disclosures. alpha.10 left
//! `the password for the box is x` unchanged: a relational descriptor between
//! the noun and its cue defeated the prose disclosure rule.
//!
//! - A bounded, same-clause descriptor (an optional participle, a preposition
//!   and up to `DESCRIPTOR_TOKENS` = 16 words) may stand between any of the
//!   eight nouns and a cue (`is`, `was`, `is now`, `set to`, `is set to`,
//!   `was set to`, `is:`, `was:`, `:`, `=`). Identifiers inside it (hosts,
//!   paths, dotted, hyphenated, quoted or bracketed names, digits) do not end
//!   it, nor (after the alpha.11 ruling, see `descriptor_ruling.rs`) do
//!   coordination, commas or relative clauses; a sentence end, a blank line,
//!   a code operator or a soft boundary such as `will` does.
//! - Past the bound the descriptor fails closed: the next cue before the end
//!   of the sentence discloses, soft boundaries notwithstanding.
//! - A complement after a descriptor is judged exactly as the same complement
//!   right after the noun is in alpha.10: documentary siblings stay visible
//!   where alpha.10 keeps them, and nowhere else.
//!
//! Each case runs through the checked, text, long, JSON and record paths and
//! must be idempotent.

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
const V: &str = "Tr0ub4dor-Example-91";
// The engine's `DESCRIPTOR_TOKENS`: words after the preposition read with the
// full descriptor grammar before the fail-closed regime starts.
const LIMIT: usize = 16;

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
    // A case id may hold `/` (paths, URLs): it ends at the first `/{api}:`.
    let failed: std::collections::BTreeSet<&str> = failures
        .iter()
        .map(|f| {
            ["checked", "text", "long", "json", "records"]
                .iter()
                .filter_map(|api| f.find(&format!("/{api}:")))
                .min()
                .map_or(f.as_str(), |end| &f[..end])
        })
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

fn case(id: &str, input: &str, expected: &str) -> (String, String, String) {
    (id.into(), input.into(), expected.into())
}

/// The minimum corpus: every noun in the nine forms. F1 and F2 have no cue
/// and stay unchanged; F4, F5 and F6 keep their alpha.10 output; F3, F3q and
/// F3s are the leak.
fn f_matrix() -> Vec<(String, String, String)> {
    let mut cases = Vec::new();
    for noun in NOUNS {
        let cap = format!("The {noun}");
        for (form, input, expected) in [
            ("F1", format!("{noun} {V}"), format!("{noun} {V}")),
            (
                "F2",
                format!("use {noun} {V} to log in"),
                format!("use {noun} {V} to log in"),
            ),
            (
                "F3",
                format!("the {noun} for the box is {V}"),
                format!("the {noun} for the box is {R}"),
            ),
            (
                "F3q",
                format!("the {noun} for the box is '{V}'"),
                format!("the {noun} for the box is '{R}'"),
            ),
            (
                "F3s",
                format!("the {noun} for the box is ab"),
                format!("the {noun} for the box is {R}"),
            ),
            (
                "F4",
                format!("{cap} is {V} for the staging box."),
                format!("{cap} is {R}."),
            ),
            (
                "F5",
                format!("{cap} is {V}. Then restart the service."),
                format!("{cap} is {R}. Then restart the service."),
            ),
            ("F6c", format!("{noun}: {V}"), format!("{noun}: {R}")),
            ("F6e", format!("{noun}={V}"), format!("{noun}={R}")),
        ] {
            cases.push((format!("{form} {noun}"), input, expected));
        }
    }
    cases
}

#[test]
fn the_nine_forms_for_every_noun() {
    let cases = f_matrix();
    assert_eq!(cases.len(), 72);
    report("F matrix", cases.len(), &run(&cases));
}

const DESCRIPTORS: [&str; 24] = [
    "for the box",
    "for the box in prod",
    "on db1.example.com",
    "in /srv/app/config.yml",
    "at 10.0.0.12",
    "of the `deploy` user",
    "to the \"prod\" box",
    "with user=admin",
    "used by the CI runner",
    "assigned to svc-account_2",
    "belonging to Bob's account",
    "for https://db.example.com:5432/x",
    "on [eu-west-1]",
    "for (prod)",
    "for 'staging db'",
    "for v1.2.3",
    "for user@example.com",
    "stored on host-7",
    "for the staging-box #3",
    "FOR THE BOX",
    "in the EU region",
    "for the\nbox",
    "for the\r\nbox",
    "used by\nthe runner",
];

const CUES: [&str; 11] = [
    " is ",
    " was ",
    " is now ",
    " set to ",
    " is set to ",
    " was set to ",
    " is: ",
    " was: ",
    ": ",
    " : ",
    " = ",
];

/// Every noun, with and without a determiner, after every descriptor and
/// every cue.
fn descriptor_matrix() -> Vec<(String, String, String)> {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for determiner in ["the ", "", "My "] {
            for descriptor in DESCRIPTORS {
                for cue in CUES {
                    let left = format!("{PUBLIC}\n{determiner}{noun} {descriptor}{cue}");
                    cases.push((
                        format!("descriptor {determiner}{noun} {descriptor:?} {cue:?}"),
                        format!("{left}Q1x"),
                        format!("{left}{R}"),
                    ));
                }
            }
        }
    }
    cases
}

#[test]
fn every_noun_descriptor_and_cue_redacts_the_value() {
    let cases = descriptor_matrix();
    assert_eq!(cases.len(), 8 * 3 * DESCRIPTORS.len() * CUES.len());
    report("descriptor matrix", cases.len(), &run(&cases));
}

/// Opaque, short, symbol, multiword, cased, quoted and line-broken values.
fn value_matrix() -> Vec<(String, String, String)> {
    let values = [
        ("", "Q", ""),
        ("", "ab", ""),
        ("", V, ""),
        ("", "#", ""),
        ("", "!$%^", ""),
        ("", "HUNTER2", ""),
        ("", "velvet river lantern", ""),
        ("", "松🔐éж", ""),
        ("'", "orchid lamp", "'"),
        ("\"", "orchid lamp", "\""),
        ("`", "orchid lamp", "`"),
        ("\n", "Q1x", ""),
        ("\r\n", "Q1x", ""),
    ];
    let mut cases = Vec::new();
    for noun in NOUNS {
        for cue in [" is ", " was set to ", ": "] {
            for (open, value, close) in values {
                let cue = if open.starts_with(['\n', '\r']) {
                    cue.trim_end()
                } else {
                    cue
                };
                let left = format!("the {noun} for the box{cue}{open}");
                cases.push((
                    format!("value {noun} {cue:?} {open:?}{value}"),
                    format!("{left}{value}{close}"),
                    format!("{left}{R}{close}"),
                ));
            }
        }
    }
    cases
}

#[test]
fn every_value_shape_after_a_descriptor_redacts_whole() {
    let cases = value_matrix();
    assert_eq!(cases.len(), 8 * 3 * 13);
    report("value matrix", cases.len(), &run(&cases));
}

#[test]
fn line_breaks_encodings_tails_and_several_disclosures_per_line() {
    let cases = [
        case(
            "blank line in the descriptor",
            "the password for the box\n\nis Q1x",
            "the password for the box\n\nis Q1x",
        ),
        case(
            "two disclosures",
            "the password for the box is Q1x and the passcode for the vm is Z9y",
            &format!("the password for the box is {R} and the passcode for the vm is {R}"),
        ),
        case(
            "direct then descriptor",
            "the pw is Q1x, the pwd for the vm was set to Z9y",
            &format!("the pw is {R}, the pwd for the vm was set to {R}"),
        ),
        case(
            "two descriptors and a tail",
            "the password for the box is Q1x and the password for the vm is Z9y, ok",
            &format!("the password for the box is {R} and the password for the vm is {R}, ok"),
        ),
        case(
            "semicolon tail",
            "the password for the box is Q1x; user is bob",
            &format!("the password for the box is {R}; user is bob"),
        ),
        case(
            "sentence tail",
            "the password for the box is Q1x. Then restart.",
            &format!("the password for the box is {R}. Then restart."),
        ),
        case(
            "F4 tail",
            "the password for the box is Q1x for the staging box.",
            &format!("the password for the box is {R}."),
        ),
        case(
            "comma tail",
            "the password for the box is Q1x, ok",
            &format!("the password for the box is {R}, ok"),
        ),
        case(
            "relative tail",
            "the password for the box is Q1x which is new",
            &format!("the password for the box is {R} which is new"),
        ),
        case(
            "bracket tail",
            "the password for the box is hunter2 (see vault)",
            &format!("the password for the box is {R}"),
        ),
        case(
            "JSON text",
            "{\"note\":\"the password for the box is Q1x\"}",
            &format!("{{\"note\":\"the password for the box is {R}\"}}"),
        ),
        case(
            "HTML spaces",
            "the&#32;password&#32;for&#32;the&#32;box&#32;is&#32;Q1x",
            &format!("the&#32;password&#32;for&#32;the&#32;box&#32;is&#32;{R}"),
        ),
        case(
            "URL spaces",
            "the%20password%20for%20the%20box%20is%20Q1x",
            &format!("the%20password%20for%20the%20box%20is%20{R}"),
        ),
        case(
            "upper case",
            "THE PASSWORD FOR THE BOX IS Q1X",
            &format!("THE PASSWORD FOR THE BOX IS {R}"),
        ),
        case(
            "capitalised colon",
            "Password for the box: hunter2",
            &format!("Password for the box: {R}"),
        ),
    ];
    report("layouts", cases.len(), &run(&cases));
}

const DOCUMENTARY: [&str; 17] = [
    "required",
    "Required",
    "REQUIRED",
    "required.",
    "REQUIRED!",
    "hashed",
    "stored in the vault",
    "case-sensitive",
    "at least 8 characters",
    "optional",
    "wrong",
    "changed",
    "not set",
    "$PASSWORD",
    "{{password}}",
    "<password>",
    "********",
];

const ATTACKS: [&str; 16] = [
    "required123",
    "xrequired",
    "'required'",
    "\"hashed\"",
    "req&#117;ired",
    "hashed123",
    "stored-in-the-vault",
    "Q",
    "ab",
    "#",
    "velvet river lantern",
    "HUNTER2",
    "Tr0ub4dor-Example-91",
    "(hidden)",
    "hunter2 (see vault)",
    "\nQ1x",
];

/// The complement after a descriptor is judged as alpha.10 judges the same
/// complement right after the noun: no descriptor-specific allowlist.
#[test]
fn a_complement_after_a_descriptor_keeps_the_alpha10_verdict() {
    let mut failures = Vec::new();
    let mut count = 0;
    for noun in NOUNS {
        for determiner in ["the ", "", "my "] {
            for descriptor in ["for the box", "used by db1.example.com", "on (prod)"] {
                for cue in [" is", " was", " is now"] {
                    for complement in DOCUMENTARY.iter().chain(ATTACKS.iter()) {
                        let gap = if complement.starts_with('\n') {
                            ""
                        } else {
                            " "
                        };
                        let direct =
                            scrub_text(&format!("{determiner}{noun}{cue}{gap}{complement}"));
                        let head = format!("{determiner}{noun}{cue}");
                        let expected = direct.replacen(
                            &head,
                            &format!("{determiner}{noun} {descriptor}{cue}"),
                            1,
                        );
                        assert_ne!(direct, expected, "descriptor not inserted");
                        let input =
                            format!("{determiner}{noun} {descriptor}{cue}{gap}{complement}");
                        count += 1;
                        failures.extend(check(&format!("sibling {input:?}"), &input, &expected));
                    }
                }
            }
        }
    }
    report("documentary siblings", count, &failures);
}

/// The documentary siblings stay visible and every same-position attack
/// redacts.
#[test]
fn documentary_siblings_stay_visible_and_their_attacks_redact() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for complement in DOCUMENTARY {
            let input = format!("the {noun} for the box is {complement}");
            cases.push((format!("keep {input:?}"), input.clone(), input));
        }
        for (attack, expected) in [
            ("required123", R.to_owned()),
            ("xrequired", R.into()),
            ("'required'", format!("'{R}'")),
            ("\"hashed\"", format!("\"{R}\"")),
            ("req&#117;ired", R.into()),
            ("hashed123", R.into()),
            ("Q", R.into()),
            ("#", R.into()),
            ("velvet river lantern", R.into()),
            ("HUNTER2", R.into()),
            ("(hidden)", R.into()),
        ] {
            let left = format!("the {noun} for the box is ");
            cases.push((
                format!("attack {noun} {attack:?}"),
                format!("{left}{attack}"),
                format!("{left}{expected}"),
            ));
        }
    }
    report("documentary pairs", cases.len(), &run(&cases));
}

#[test]
fn benign_controls_code_and_clause_boundaries_stay_unchanged() {
    let mut cases = Vec::new();
    for input in [
        "password policy for the box is strict",
        "reset your password for the box",
        "the password field for the box is empty",
        // Coordination, commas and relative clauses no longer end the
        // descriptor (alpha.11 ruling); those rows are pinned in
        // `pinned_outcomes_near_the_class`.
        "the password for the box. It is Q1x",
        "the password for the box! It is Q1x",
        "the password for the box will be rotated; it is Q1x",
        "the password for the box should rotate: weekly is fine",
        "the password for the box && x is Q1x",
        "the password for the box == x is Q1x",
        "the password for (the box)) is Q1x",
        "for pw in pws: print(pw)",
        "if password in data: return x",
        "[pw for pw in pws if pw is None]",
        "x = [pw for pw in pws]",
        "const pw of list: x",
        "while password in cache: pass",
        "assert pw is not None",
        "use password for the box",
    ] {
        cases.push(case(&format!("benign {input:?}"), input, input));
    }
    report("benign", cases.len(), &run(&cases));
}

fn words(n: usize) -> String {
    (1..=n)
        .map(|i| format!("a{i}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// limit-1, limit and limit+1 words, with and without the soft boundaries
/// that end a descriptor within the bound. At the bound the descriptor
/// fails closed: a later cue in the same sentence still discloses.
#[test]
fn the_descriptor_bound_is_explicit_and_fails_closed() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for n in [LIMIT - 1, LIMIT, LIMIT + 1, LIMIT + 2, 4 * LIMIT] {
            for cue in [" is ", ": ", " = ", " was set to "] {
                let left = format!("the {noun} for {}{cue}", words(n));
                cases.push((
                    format!("bound {noun} {n} {cue:?}"),
                    format!("{left}Q1x"),
                    format!("{left}{R}"),
                ));
            }
        }
        // A soft boundary at word limit-1 or limit ends the descriptor; at
        // limit+1 the fail-closed regime no longer reads it. Coordination, a
        // relative pronoun and a comma no longer end it (alpha.11 ruling), so
        // they disclose at every position.
        for (at, stops) in [(LIMIT - 1, true), (LIMIT, true), (LIMIT + 1, false)] {
            for soft in ["and", "which", "will", ","] {
                let text = if soft == "," {
                    format!("the {noun} for {}, b is Q1x", words(at))
                } else {
                    format!("the {noun} for {} {soft} is Q1x", words(at - 1))
                };
                let redacts = !stops || soft != "will";
                let expected = if redacts {
                    text.replace("Q1x", R)
                } else {
                    text.clone()
                };
                cases.push((format!("soft {noun} {soft} at {at}"), text, expected));
            }
        }
        // Within the bound a cue inside a bracket or quote the descriptor
        // opened does not count; from word limit+1 on it does.
        for (at, redacts) in [(LIMIT - 1, false), (LIMIT, true), (LIMIT + 1, true)] {
            for opener in ["(", "\""] {
                let text = format!("the {noun} for {} {opener}b is Q1x", words(at - 1));
                let expected = if redacts {
                    text.replace("Q1x", R)
                } else {
                    text.clone()
                };
                cases.push((format!("open {noun} {opener} at {at}"), text, expected));
            }
        }
        // A sentence end, a blank line or a code operator ends the search
        // in both regimes.
        for n in [LIMIT - 1, LIMIT + 1, 4 * LIMIT] {
            for stop in [". b", "! b", "\n\nb", " x; b", " x == b"] {
                let text = format!("the {noun} for {}{stop} is Q1x", words(n));
                cases.push((format!("stop {noun} {n} {stop:?}"), text.clone(), text));
            }
        }
    }
    report("bound", cases.len(), &run(&cases));
}

/// Explicit outcomes chosen for this class, pinned so a change is visible.
#[test]
fn pinned_outcomes_near_the_class() {
    let cases = [
        // A colon after a descriptor is a bare colon cue: the rest is the
        // value, as `password: click the link` is in alpha.10.
        case(
            "colon instruction",
            "Reset the password for your account: click the link",
            &format!("Reset the password for your account: {R}"),
        ),
        case(
            "pwd colon",
            "pwd in the shell: /srv/x",
            &format!("pwd in the shell: {R}"),
        ),
        // Past the bound a comma or a relative pronoun does not end the
        // search for the cue (fail closed).
        case(
            "past bound comma",
            &format!("the password for {}, which b is Q1x", words(LIMIT + 1)),
            &format!("the password for {}, which b is {R}", words(LIMIT + 1)),
        ),
        // alpha.11 ruling: coordination, commas, relative clauses and glued
        // cues no longer end the descriptor. Pinned over-redaction: a second
        // clause joined by `and` is read as the descriptor.
        case(
            "conjunction over-redaction",
            "the password for the box expired and the user is bob",
            &format!("the password for the box expired and the user is {R}"),
        ),
        case(
            "relative which",
            "the password for the box, which is new, is Q1x",
            &format!("the password for the box, which is new, is {R}"),
        ),
        case(
            "relative that",
            "the password for the box that is used by CI is Q1x",
            &format!("the password for the box that is used by CI is {R}"),
        ),
        case(
            "spaced hyphen",
            "the password for the box - x is Q1x",
            &format!("the password for the box - x is {R}"),
        ),
        case(
            "glued",
            "the password for the box=Q1x",
            &format!("the password for the box={R}"),
        ),
    ];
    report("pinned", cases.len(), &run(&cases));
}

#[test]
fn eval_fixture_cases() {
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../eval/descriptor_disclosure_alpha11_cases.json"
    ))
    .unwrap();
    assert!(cases.len() >= 40);
    let mut failures = Vec::new();
    for c in &cases {
        assert!(c.kind == "positive" || c.kind == "benign", "{}", c.id);
        assert_eq!(c.kind == "benign", c.input == c.expected, "{}", c.id);
        failures.extend(check(&c.id, &c.input, &c.expected));
    }
    report("eval fixture", cases.len(), &failures);
}
