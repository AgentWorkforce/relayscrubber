#![allow(missing_docs)]
//! 0.5.0-alpha.11 scope ruling: forms the first alpha.11 candidate left
//! unchanged that must disclose.
//!
//! - A. A glued cue in the descriptor (`pw for box=x`, `Password for
//!   root:x`) discloses the right-hand side, unless the word holds `://`,
//!   `::`, `==`, `!=`, `<=`, `>=`, `:=` or `=>`. A later qualified cue wins
//!   (`the password for db:5432 is x` discloses `x` only).
//! - B. Coordination (`and`, `or`, `&`, `+`, a spaced hyphen, en or em dash)
//!   no longer ends a descriptor.
//! - C. A relative clause or comma parenthetical in the descriptor no longer
//!   ends it; the cue right after a relative pronoun belongs to the relative
//!   clause, so the final value discloses.
//! - D. The colon over-redactions of alpha.11 stay.
//! - E. New direct cues for all eight nouns, with and without a descriptor:
//!   `is still`, `is now set to`, `has been set to`, `was reset to`,
//!   `changed to`, plural nouns with `are` and `were`, and contact clauses
//!   (`the password Bob uses is x`, `the password that I use is x`).
//!
//! Precision controls (`is not`, `isn't`, `will be`, `should be`),
//! documentary complements, code, F1 and F2 stay unchanged. Each case runs
//! through the checked, text, long, JSON and record paths and must be
//! idempotent.

use relayscrubber::{scrub_json, scrub_long, scrub_records, scrub_text, scrub_text_checked};
use serde_json::json;

const R: &str = "[REDACTED]";
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
const PLURALS: [&str; 8] = [
    "passwords",
    "passcodes",
    "passphrases",
    "passwds",
    "pwds",
    "pws",
    "pass codes",
    "pass phrases",
];
const V: &str = "Tr0ub4dor-Example-91";
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

fn words(n: usize) -> String {
    (1..=n)
        .map(|i| format!("a{i}"))
        .collect::<Vec<_>>()
        .join(" ")
}

const VALUES: [(&str, &str, &str); 7] = [
    ("", "Q", ""),
    ("", "ab", ""),
    ("", V, ""),
    ("", "!$%^", ""),
    ("", "松🔐éж", ""),
    ("'", "orchid lamp", "'"),
    ("\"", "orchid lamp", "\""),
];

// Documentary complements and their same-position attacks: after any new
// form, a complement is judged as alpha.10 judges it after `the <noun> is`.
const DOCUMENTARY: [&str; 12] = [
    "required",
    "REQUIRED!",
    "hashed",
    "stored in the vault",
    "case-sensitive",
    "at least 8 characters",
    "optional",
    "not set",
    "$PASSWORD",
    "{{password}}",
    "<password>",
    "********",
];

const ATTACKS: [&str; 8] = [
    "required123",
    "'required'",
    "\"hashed\"",
    "stored-in-the-vault",
    "Q",
    "#",
    "HUNTER2",
    "velvet river lantern",
];

/// The alpha.10 verdict on `complement` right after `the <noun> is`, moved
/// to `left`: the complement redacts exactly where alpha.10 redacts it.
fn alpha10_verdict(noun: &str, left: &str, complement: &str) -> String {
    let head = format!("the {noun} is ");
    let direct = scrub_text(&format!("{head}{complement}"));
    assert!(direct.starts_with(&head), "{direct:?}");
    format!("{left}{}", &direct[head.len()..])
}

// ---------------------------------------------------------------- A: glued

const GLUED: [(&str, &str); 6] = [
    ("for box=", "for box="),
    ("for box:", "for box:"),
    ("for root:", "for root:"),
    ("for the box=", "for the box="),
    ("with user=", "with user="),
    ("on db1.example.com:", "on db1.example.com:"),
];

#[test]
fn a_glued_cue_discloses_the_right_hand_side() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for determiner in ["the ", "", "My "] {
            for (glued, kept) in GLUED {
                for (open, value, close) in VALUES {
                    if value.contains(' ') {
                        // A glued value is one word.
                        continue;
                    }
                    let input = format!("{determiner}{noun} {glued}{open}{value}{close}");
                    cases.push((
                        format!("glued {input:?}"),
                        input,
                        format!("{determiner}{noun} {kept}{open}{R}{close}"),
                    ));
                }
                // A comma or semicolon after the glued value ends it, as
                // after a spaced `=`.
                for tail in [", ok", "; ok", "."] {
                    let input = format!("{determiner}{noun} {glued}Q1x{tail}");
                    cases.push((
                        format!("glued tail {input:?}"),
                        input,
                        format!("{determiner}{noun} {kept}{R}{tail}"),
                    ));
                }
            }
        }
    }
    report("glued", cases.len(), &run(&cases));
}

#[test]
fn a_glued_cue_ruling_rows_and_costs() {
    let cases = [
        case("pw box=", "pw for box=Q1x", &format!("pw for box={R}")),
        case("pw box:", "pw for box:Q1x", &format!("pw for box:{R}")),
        case(
            "Password root:",
            "Password for root:hunter2",
            &format!("Password for root:{R}"),
        ),
        case(
            "the box=",
            "the password for the box=Q1x",
            &format!("the password for the box={R}"),
        ),
        // A later qualified cue wins over a glued word.
        case(
            "later cue wins",
            "the password for db:5432 is V7x",
            &format!("the password for db:5432 is {R}"),
        ),
        case(
            "later colon wins",
            "the password for db:5432 on host-7: V7x",
            &format!("the password for db:5432 on host-7: {R}"),
        ),
        case(
            "later set to wins",
            "the password with user=admin was set to V7x",
            &format!("the password with user=admin was set to {R}"),
        ),
        // Costs: with no later cue, the glued value discloses even where it
        // is not a password.
        case(
            "cost port",
            "the password for db:5432",
            &format!("the password for db:{R}"),
        ),
        case(
            "cost user",
            "the password with user=admin",
            &format!("the password with user={R}"),
        ),
        case(
            "cost two glued words",
            "the password for a=b c=d",
            &format!("the password for a={R}"),
        ),
        // A URL word is no glued cue.
        case(
            "cost URL",
            "the password for https://db.example.com:5432/x",
            "the password for https://db.example.com:5432/x",
        ),
        case(
            "URL then cue",
            "the password for https://db.example.com:5432/x is V7x",
            &format!("the password for https://db.example.com:5432/x is {R}"),
        ),
        // Operators are no glued cue.
        case("::", "the password for a::b", "the password for a::b"),
        case("==", "the password for a==b", "the password for a==b"),
        case("!=", "the password for a!=b", "the password for a!=b"),
        case("<=", "the password for a<=b", "the password for a<=b"),
        case(">=", "the password for a>=b", "the password for a>=b"),
        case(":=", "the password for a:=b", "the password for a:=b"),
        case("=>", "the password for a=>b", "the password for a=>b"),
        // A label holds a letter, and a value does not start a path.
        case(
            "time",
            "the password for the 10:30 meeting",
            "the password for the 10:30 meeting",
        ),
        case(
            "drive path",
            "the password for C:\\Users\\bob",
            "the password for C:\\Users\\bob",
        ),
        // Several disclosures per line.
        case(
            "two glued",
            "pw for box=Q1x; pw for vm:Z9y",
            &format!("pw for box={R}; pw for vm:{R}"),
        ),
        // Code stays code.
        case("code for", "for pw in pws: x=pw", "for pw in pws: x=pw"),
        case(
            "code if",
            "if password in data: x=1",
            "if password in data: x=1",
        ),
    ];
    report("glued pins", cases.len(), &run(&cases));
}

// ---------------------------------------------------------- B: coordination

const COORDINATED: [&str; 9] = [
    "for staging and prod",
    "for the box or vm",
    "for staging & prod",
    "for staging + prod",
    "for the box - the new one -",
    "for the box -- the new one --",
    "for the box \u{2014} the new one \u{2014}",
    "for the box \u{2013} the new one \u{2013}",
    "for staging, qa and prod",
];

// Relative clauses and comma parentheticals (C), as a descriptor after the
// noun: each is written right after the noun.
const RELATIVE: [&str; 9] = [
    " for the box, which is new,",
    " for the box that is used by CI",
    " for the box that I set",
    ", for the box,",
    " that I use",
    " that is used by CI",
    ", which is new,",
    " for the box which was set up by ops",
    " for the box, the new one,",
];

const NEW_CUES: [&str; 6] = [
    " is ",
    " was ",
    " is still ",
    " has been set to ",
    ": ",
    " = ",
];

#[test]
fn b_and_c_descriptors_disclose_the_final_value() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for determiner in ["the ", "", "My "] {
            let descriptors = COORDINATED
                .iter()
                .map(|d| format!(" {d}"))
                .chain(RELATIVE.iter().map(|d| d.to_string()));
            for descriptor in descriptors {
                for cue in NEW_CUES {
                    let left = format!("{determiner}{noun}{descriptor}{cue}");
                    cases.push((
                        format!("final {left:?}"),
                        format!("{left}Q1x"),
                        format!("{left}{R}"),
                    ));
                }
                for (open, value, close) in VALUES {
                    let left = format!("{determiner}{noun}{descriptor} is {open}");
                    cases.push((
                        format!("final value {left:?}{value}"),
                        format!("{left}{value}{close}"),
                        format!("{left}{R}{close}"),
                    ));
                }
            }
        }
    }
    report("coordination and relative", cases.len(), &run(&cases));
}

#[test]
fn b_and_c_documentary_siblings_and_their_attacks() {
    let mut failures = Vec::new();
    let mut count = 0;
    for noun in NOUNS {
        let descriptors = COORDINATED
            .iter()
            .map(|d| format!(" {d}"))
            .chain(RELATIVE.iter().map(|d| d.to_string()));
        for descriptor in descriptors {
            for complement in DOCUMENTARY.iter().chain(ATTACKS.iter()) {
                let left = format!("the {noun}{descriptor} is ");
                let input = format!("{left}{complement}");
                let expected = alpha10_verdict(noun, &left, complement);
                count += 1;
                failures.extend(check(&format!("sibling {input:?}"), &input, &expected));
            }
        }
    }
    report("coordination and relative siblings", count, &failures);
}

#[test]
fn b_and_c_ruling_rows_pins_and_stops() {
    let cases = [
        case(
            "and",
            "the password for staging and prod is Q1x",
            &format!("the password for staging and prod is {R}"),
        ),
        case(
            "or",
            "the password for the box or vm is Q1x",
            &format!("the password for the box or vm is {R}"),
        ),
        case(
            "&",
            "the password for staging & prod is Q1x",
            &format!("the password for staging & prod is {R}"),
        ),
        case(
            "+",
            "the password for staging + prod is Q1x",
            &format!("the password for staging + prod is {R}"),
        ),
        case(
            "hyphen",
            "the password for the box - the new one - is Q1x",
            &format!("the password for the box - the new one - is {R}"),
        ),
        case(
            "em dash",
            "the password for the box \u{2014} the new one \u{2014} is Q1x",
            &format!("the password for the box \u{2014} the new one \u{2014} is {R}"),
        ),
        // Pinned over-redaction: a second clause joined by `and` is read as
        // part of the descriptor.
        case(
            "over-redaction and",
            "the password for the box expired and the user is bob",
            &format!("the password for the box expired and the user is {R}"),
        ),
        // Pinned over-redaction: a comma no longer ends the descriptor.
        case(
            "over-redaction comma",
            "the password for the box, the user is bob",
            &format!("the password for the box, the user is {R}"),
        ),
        case(
            "documentary and",
            "the password for staging and prod is required",
            "the password for staging and prod is required",
        ),
        case(
            "documentary and hashed",
            "the password for staging and prod is hashed",
            "the password for staging and prod is hashed",
        ),
        case(
            "documentary and vault",
            "the password for staging and prod is stored in the vault",
            "the password for staging and prod is stored in the vault",
        ),
        case(
            "which",
            "the password for the box, which is new, is Q1x",
            &format!("the password for the box, which is new, is {R}"),
        ),
        case(
            "that is used",
            "the password for the box that is used by CI is Q1x",
            &format!("the password for the box that is used by CI is {R}"),
        ),
        case(
            "that I set",
            "the password for the box that I set is Q1x",
            &format!("the password for the box that I set is {R}"),
        ),
        case(
            "comma parenthetical",
            "the password, for the box, is Q1x",
            &format!("the password, for the box, is {R}"),
        ),
        case(
            "which documentary",
            "the password for the box, which is new, is required",
            "the password for the box, which is new, is required",
        ),
        case(
            "that documentary",
            "the password for the box that is used by CI is hashed",
            "the password for the box that is used by CI is hashed",
        ),
        case(
            "that I set documentary",
            "the password for the box that I set is stored in the vault",
            "the password for the box that I set is stored in the vault",
        ),
        // Nested cues: the cue right after the relative pronoun is the
        // relative clause's; the later main cue discloses. With no main cue
        // the relative clause's cue discloses (fail closed).
        case(
            "nested set to",
            "the password that was set to X1 is Y2",
            &format!("the password that was set to X1 is {R}"),
        ),
        case(
            "nested no main cue",
            "the password for the box, which is new",
            &format!("the password for the box, which is {R}"),
        ),
        case(
            "nested two relatives",
            "the password for the box which is new that is old is Q1x",
            &format!("the password for the box which is new that is old is {R}"),
        ),
        case(
            "nested glued then main",
            "the password for db:5432, which is new, is Q1x",
            &format!("the password for db:5432, which is new, is {R}"),
        ),
        // Unchanged: the value after a main cue keeps its alpha.11 extent.
        case(
            "tail relative",
            "the password for the box is Q1x which is new",
            &format!("the password for the box is {R} which is new"),
        ),
        // Stops stay stops.
        case(
            "sentence end",
            "the password for the box. It is Q1x",
            "the password for the box. It is Q1x",
        ),
        case(
            "blank line",
            "the password for the box, which\n\nis Q1x",
            "the password for the box, which\n\nis Q1x",
        ),
        case(
            "semicolon",
            "the password for the box and vm; it is Q1x",
            "the password for the box and vm; it is Q1x",
        ),
        case(
            "&&",
            "the password for the box && x is Q1x",
            "the password for the box && x is Q1x",
        ),
        case(
            "but",
            "the password for the box expired but the user is bob",
            "the password for the box expired but the user is bob",
        ),
        case(
            "whose",
            "the password for the user whose account is locked",
            "the password for the user whose account is locked",
        ),
        case(
            "will",
            "the password for the box will be rotated; it is Q1x",
            "the password for the box will be rotated; it is Q1x",
        ),
        // Several disclosures per line, and a tail.
        case(
            "two disclosures",
            "the password for staging and prod is Q1x and the pw that I use is Z9y, ok",
            &format!("the password for staging and prod is {R} and the pw that I use is {R}, ok"),
        ),
    ];
    report("coordination and relative pins", cases.len(), &run(&cases));
}

/// A relative clause or comma at word limit-1, limit and limit+1: the final
/// value discloses at every position, and only it.
#[test]
fn b_and_c_at_the_descriptor_bound() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for at in [LIMIT - 1, LIMIT, LIMIT + 1] {
            for (form, text) in [
                (
                    "which",
                    format!("the {noun} for {}, which is new, is Q1x", words(at - 1)),
                ),
                (
                    "that",
                    format!("the {noun} for {} that is used by CI is Q1x", words(at - 1)),
                ),
                (
                    "and",
                    format!("the {noun} for {} and prod is Q1x", words(at - 1)),
                ),
                ("comma", format!("the {noun} for {}, b is Q1x", words(at))),
                (
                    "dash",
                    format!("the {noun} for {} - b - is Q1x", words(at - 1)),
                ),
                (
                    "nested",
                    format!("the {noun} for {} that was set to X1 is Y2", words(at - 1)),
                ),
            ] {
                let expected = if form == "nested" {
                    text.replace("Y2", R)
                } else {
                    text.replace("Q1x", R)
                };
                cases.push((format!("bound {form} {noun} {at}"), text, expected));
            }
            // With no main cue the relative clause's cue discloses.
            let text = format!("the {noun} for {}, which is new", words(at - 1));
            cases.push((
                format!("bound fallback {noun} {at}"),
                text.clone(),
                text.replace("new", R),
            ));
        }
    }
    report("bound", cases.len(), &run(&cases));
}

// ------------------------------------------------------- D: colon pins stay

#[test]
fn d_colon_over_redactions_and_controls_stay() {
    let cases = [
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
        case(
            "empty colon",
            "Enter the password for your account:",
            "Enter the password for your account:",
        ),
        case("reset", "reset your password", "reset your password"),
        case("policy", "password policy", "password policy"),
        case("field", "the password field", "the password field"),
        case("passwords policy", "passwords policy", "passwords policy"),
        case(
            "reset noun",
            "the password reset to the default flow",
            "the password reset to the default flow",
        ),
    ];
    report("colon pins", cases.len(), &run(&cases));
}

// ---------------------------------------------------------- E: direct cues

const SINGULAR_CUES: [&str; 14] = [
    " is still ",
    " was still ",
    " is now set to ",
    " is still set to ",
    " has been set to ",
    " had been set to ",
    " has been changed to ",
    " was reset to ",
    " is reset to ",
    " was changed to ",
    " was updated to ",
    " changed to ",
    " updated to ",
    " has been reset to ",
];

const PLURAL_CUES: [&str; 8] = [
    " are ",
    " were ",
    " are still ",
    " are now ",
    " are now set to ",
    " have been set to ",
    " were reset to ",
    " changed to ",
];

// Contact clauses and relative clauses with their own subject.
const CONTACT: [&str; 7] = [
    " Bob uses",
    " that I use",
    " I use",
    " you chose",
    " we set",
    " the admin uses",
    " Alice picked",
];

#[test]
fn e_new_cues_disclose_for_every_noun() {
    let mut cases = Vec::new();
    for (nouns, cues) in [(NOUNS, &SINGULAR_CUES[..]), (PLURALS, &PLURAL_CUES[..])] {
        for noun in nouns {
            for determiner in ["the ", "", "My "] {
                for descriptor in ["", " for the box", " used by db1.example.com"] {
                    for cue in cues {
                        let left = format!("{determiner}{noun}{descriptor}{cue}");
                        cases.push((
                            format!("cue {left:?}"),
                            format!("{left}Q1x"),
                            format!("{left}{R}"),
                        ));
                    }
                }
                for (open, value, close) in VALUES {
                    let cue = cues[0];
                    let left = format!("{determiner}{noun}{cue}{open}");
                    cases.push((
                        format!("cue value {left:?}{value}"),
                        format!("{left}{value}{close}"),
                        format!("{left}{R}{close}"),
                    ));
                }
            }
        }
    }
    for (noun, plural) in NOUNS.into_iter().zip(PLURALS) {
        for determiner in ["the ", "My "] {
            for contact in CONTACT {
                for (noun, cue) in [(noun, " is "), (noun, " was "), (plural, " are ")] {
                    let left = format!("{determiner}{noun}{contact}{cue}");
                    cases.push((
                        format!("contact {left:?}"),
                        format!("{left}Q1x"),
                        format!("{left}{R}"),
                    ));
                }
            }
        }
    }
    report("new cues", cases.len(), &run(&cases));
}

#[test]
fn e_ruling_rows_and_neighbours() {
    let cases = [
        case(
            "is still",
            "the password is still Q1x",
            &format!("the password is still {R}"),
        ),
        case(
            "is now set to",
            "the password is now set to Q1x",
            &format!("the password is now set to {R}"),
        ),
        case(
            "has been set to",
            "the password has been set to Q1x",
            &format!("the password has been set to {R}"),
        ),
        case(
            "was reset to",
            "the password was reset to Q1x",
            &format!("the password was reset to {R}"),
        ),
        case(
            "plural",
            "the passwords are Q1x",
            &format!("the passwords are {R}"),
        ),
        case(
            "contact",
            "the password Bob uses is Q1x",
            &format!("the password Bob uses is {R}"),
        ),
        case(
            "that I use",
            "the password that I use is Q1x",
            &format!("the password that I use is {R}"),
        ),
        case(
            "changed to",
            "password changed to Q1x",
            &format!("password changed to {R}"),
        ),
        // The shorter cue still discloses where the longer one finds no value.
        case(
            "is still alone",
            "the password is still",
            &format!("the password is {R}"),
        ),
        case(
            "two disclosures",
            "the password is still Q1x and the passcodes are Z9y",
            &format!("the password is still {R} and the passcodes are {R}"),
        ),
        case(
            "sentence tail",
            "the passwords were Q1x. Then restart.",
            &format!("the passwords were {R}. Then restart."),
        ),
        case(
            "F4 tail",
            "The password has been set to Q1x for the staging box.",
            &format!("The password has been set to {R}."),
        ),
        // A plural noun takes word cues only; agreement is checked on the
        // direct cue.
        case("plural colon", "the passwords: Q1x", "the passwords: Q1x"),
        case("plural equals", "passwords = Q1x", "passwords = Q1x"),
        case("plural is", "the passwords is Q1x", "the passwords is Q1x"),
        case(
            "singular are",
            "the password are Q1x",
            "the password are Q1x",
        ),
        case(
            "plural descriptor colon",
            "Passwords for db1: Q1x",
            "Passwords for db1: Q1x",
        ),
        // A contact clause needs a determiner and a verb.
        case(
            "contact no determiner",
            "password Bob uses is Q1x",
            "password Bob uses is Q1x",
        ),
        case(
            "contact no verb",
            "the password Manager app is great",
            "the password Manager app is great",
        ),
        case(
            "contact documentary",
            "the password you entered is incorrect",
            "the password you entered is incorrect",
        ),
    ];
    report("new cue pins", cases.len(), &run(&cases));
}

/// Precision controls, documentary complements, code, F1 and F2 stay as they
/// are for every noun, singular and plural.
#[test]
fn e_precision_controls_documentary_and_code_stay() {
    let mut cases = Vec::new();
    for (noun, plural) in NOUNS.into_iter().zip(PLURALS) {
        for descriptor in ["", " for the box"] {
            for (noun, control) in [
                (noun, " is not "),
                (noun, " isn't "),
                (noun, " will be "),
                (noun, " should be "),
                (noun, " is not set to "),
                (noun, " has not been set to "),
                (plural, " are not "),
                (plural, " aren't "),
                (plural, " will be "),
                (plural, " should be "),
            ] {
                let input = format!("the {noun}{descriptor}{control}Q1x");
                cases.push((format!("control {input:?}"), input.clone(), input));
            }
        }
        for input in [
            format!("{plural} {V}"),
            format!("use {plural} {V} to log in"),
            format!("if {noun} is still None: x"),
            format!("assert {noun} changed to x"),
            format!("{plural} = [a, b]"),
            format!("{plural}: list[str]"),
            format!("for {plural} in x: y"),
            format!("x.{plural} are y"),
            format!("$PASSWORDS are set to {V}"),
        ] {
            cases.push((format!("code {input:?}"), input.clone(), input));
        }
    }
    report("controls", cases.len(), &run(&cases));
}

#[test]
fn e_documentary_siblings_and_their_attacks() {
    let mut failures = Vec::new();
    let mut count = 0;
    for (noun, plural) in NOUNS.into_iter().zip(PLURALS) {
        let lefts = SINGULAR_CUES
            .iter()
            .map(|cue| format!("the {noun}{cue}"))
            .chain(PLURAL_CUES.iter().map(|cue| format!("the {plural}{cue}")))
            .chain(CONTACT.iter().map(|c| format!("the {noun}{c} is ")))
            .chain([format!("the {noun} for the box is still ")]);
        for left in lefts {
            for complement in DOCUMENTARY.iter().chain(ATTACKS.iter()) {
                let input = format!("{left}{complement}");
                let expected = alpha10_verdict(noun, &left, complement);
                count += 1;
                failures.extend(check(&format!("sibling {input:?}"), &input, &expected));
            }
        }
    }
    report("new cue siblings", count, &failures);
}

/// A new cue at word limit-1, limit and limit+1 of a descriptor.
#[test]
fn e_at_the_descriptor_bound() {
    let mut cases = Vec::new();
    for (noun, plural) in NOUNS.into_iter().zip(PLURALS) {
        for n in [LIMIT - 1, LIMIT, LIMIT + 1] {
            for (noun, cue) in [
                (noun, " is still "),
                (noun, " has been set to "),
                (noun, " was reset to "),
                (plural, " are "),
            ] {
                let left = format!("the {noun} for {}{cue}", words(n));
                cases.push((
                    format!("bound {noun} {n} {cue:?}"),
                    format!("{left}Q1x"),
                    format!("{left}{R}"),
                ));
            }
        }
    }
    report("new cue bound", cases.len(), &run(&cases));
}

// ---------------------------------------------------------- bounded work

/// The new grammar stays linear: runs of each new form, each after the
/// prefixes that open a quote, a JSON string or a descriptor, and one long
/// descriptor of each new form, at 64 and 256 KiB.
#[test]
fn bounded_work_for_the_new_grammar_at_64_and_256_kib() {
    use std::time::{Duration, Instant};
    let _ = scrub_text("warmup");
    let timed = |label: String, input: &str| {
        let start = Instant::now();
        std::hint::black_box(scrub_text(input));
        let elapsed = start.elapsed();
        eprintln!("{label} {elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "{label} exceeded the CI bound"
        );
    };
    for size in [65_536, 262_144] {
        for unit in [
            "pw for a and ",
            "pw for a & ",
            "pw for a - ",
            "pw for a \u{2014} ",
            "pw for a, which is ",
            "pw that is ",
            "pw which ",
            "pw for a=b ",
            "pw for a:b ",
            "pw for a=b; ",
            "pw for a -: ",
            "the pws are ",
            "the pw Bob uses ",
            "the pw I set ",
            "pw is still ",
            "pw has been set to ",
            "pw was reset to ",
            "pw changed to ",
            "pw is now ",
        ] {
            for prefix in ["", "x \"", "{\"note\":\"", "the password for "] {
                let input = format!("{prefix}{}", unit.repeat(size / unit.len() + 1));
                let mut cut = size;
                while !input.is_char_boundary(cut) {
                    cut -= 1;
                }
                timed(format!("unit {size} {unit:?} {prefix:?}"), &input[..cut]);
            }
        }
        for (head, unit, tail) in [
            ("the password for ", "a and ", " is x"),
            ("the password for ", "a, which ", " is x"),
            ("the password for ", "that is a ", " is x"),
            ("the password for ", "a=b ", " is x"),
            ("the password for ", "a - ", " is x"),
            ("the password Bob ", "uses ", " is x"),
            ("the passwords for ", "a or ", " are x"),
        ] {
            let body = unit.repeat((size - head.len() - tail.len()) / unit.len());
            timed(
                format!("long {size} {head:?} {unit:?}"),
                &format!("{head}{body}{tail}"),
            );
        }
    }
}

// ------------------------------- contact clause followed by punctuation

// Subjects a contact clause accepts: a capitalised name, a personal pronoun,
// a determiner and a word; with a verb in `-s`, `-ed`, `set` or an irregular
// past.
const CONTACT_SUBJECTS: [&str; 6] = [
    " Bob uses",
    " Alice set",
    " I set",
    " you chose",
    " the admin uses",
    " we picked",
];

// Punctuation right after the contact verb: a comma parenthetical or
// relative clause (with a line break inside), a colon or equals sign, spaced
// or glued.
const CONTACT_TAILS: [&str; 8] = [
    ", which is new, is ",
    ", which was new, was ",
    ",\nwhich is new, is ",
    ": ",
    " : ",
    " = ",
    "=",
    ":",
];

/// A contact clause behaves like a relative clause with its own subject
/// (`the password that I use`) when punctuation follows its verb directly:
/// the final value discloses.
#[test]
fn e_contact_clause_followed_by_punctuation_discloses() {
    let mut cases = Vec::new();
    for (noun, plural) in NOUNS.into_iter().zip(PLURALS) {
        for determiner in ["the ", "My "] {
            for subject in CONTACT_SUBJECTS {
                for tail in CONTACT_TAILS {
                    let left = format!("{determiner}{noun}{subject}{tail}");
                    cases.push((
                        format!("contact {left:?}"),
                        format!("{left}Q1x"),
                        format!("{left}{R}"),
                    ));
                }
                for tail in [", which is new, is ", ": "] {
                    for (open, value, close) in VALUES {
                        let left = format!("{determiner}{noun}{subject}{tail}{open}");
                        cases.push((
                            format!("contact value {left:?}{value}"),
                            format!("{left}{value}{close}"),
                            format!("{left}{R}{close}"),
                        ));
                    }
                }
                let left = format!("{determiner}{plural}{subject}, which are new, are ");
                cases.push((
                    format!("contact plural {left:?}"),
                    format!("{left}Q1x"),
                    format!("{left}{R}"),
                ));
            }
        }
    }
    report("contact punctuation", cases.len(), &run(&cases));
}

#[test]
fn e_contact_clause_punctuation_rows_and_controls() {
    let cases = [
        case(
            "which",
            "the password Bob uses, which is new, is Zq9x",
            &format!("the password Bob uses, which is new, is {R}"),
        ),
        case(
            "set which",
            "the password Alice set, which is new, is Zq9x",
            &format!("the password Alice set, which is new, is {R}"),
        ),
        case(
            "colon",
            "the password Bob uses: Zq9x",
            &format!("the password Bob uses: {R}"),
        ),
        case(
            "glued",
            "the password Bob uses=Zq9x",
            &format!("the password Bob uses={R}"),
        ),
        case(
            "line break",
            "the password Bob uses,\nwhich is new, is Zq9x",
            &format!("the password Bob uses,\nwhich is new, is {R}"),
        ),
        case(
            "sentence tail",
            "the password Bob uses: Zq9x. Then restart.",
            &format!("the password Bob uses: {R}. Then restart."),
        ),
        // Forms that already disclosed stay as they are.
        case(
            "relative which",
            "the password that I set, which is new, is Zq9x",
            &format!("the password that I set, which is new, is {R}"),
        ),
        case(
            "relative colon",
            "the password that I use: Zq9x",
            &format!("the password that I use: {R}"),
        ),
        case(
            "bracket",
            "the password Bob uses (daily) is Zq9x",
            &format!("the password Bob uses (daily) is {R}"),
        ),
        case(
            "colon after cue",
            "the password Bob uses is: Zq9x",
            &format!("the password Bob uses is: {R}"),
        ),
        case(
            "descriptor which",
            "the password Bob uses for staging, which is new, is Zq9x",
            &format!("the password Bob uses for staging, which is new, is {R}"),
        ),
        // A contact clause still needs a determiner on the noun.
        case(
            "no determiner colon",
            "password Bob uses: Zq9x",
            "password Bob uses: Zq9x",
        ),
        case(
            "no determiner glued",
            "password Bob uses=Zq9x",
            "password Bob uses=Zq9x",
        ),
        case(
            "no determiner which",
            "password Bob uses, which is new, is Zq9x",
            "password Bob uses, which is new, is Zq9x",
        ),
        // No cue, or a cue in another clause or sentence.
        case(
            "appositive",
            "the password Bob uses, Zq9x",
            "the password Bob uses, Zq9x",
        ),
        case(
            "semicolon",
            "the password Bob uses; it is Zq9x",
            "the password Bob uses; it is Zq9x",
        ),
        case(
            "sentence",
            "the password Bob uses. It is Zq9x",
            "the password Bob uses. It is Zq9x",
        ),
        case(
            "boundary",
            "the password Bob uses, but the user is Zq9x",
            "the password Bob uses, but the user is Zq9x",
        ),
        case(
            "documentary which",
            "the password Bob uses, which is new, is required",
            "the password Bob uses, which is new, is required",
        ),
        case(
            "documentary contact",
            "the password you entered is incorrect",
            "the password you entered is incorrect",
        ),
    ];
    report("contact punctuation pins", cases.len(), &run(&cases));
}

/// After `, which is new, is` a complement is judged as alpha.10 judges it
/// after `the <noun> is`; after `:` exactly as after the relative clause
/// `the <noun> that I use:`.
#[test]
fn e_contact_clause_punctuation_siblings_and_their_attacks() {
    let mut failures = Vec::new();
    let mut count = 0;
    for noun in NOUNS {
        for subject in CONTACT_SUBJECTS {
            for complement in DOCUMENTARY.iter().chain(ATTACKS.iter()) {
                let left = format!("the {noun}{subject}, which is new, is ");
                let input = format!("{left}{complement}");
                let expected = alpha10_verdict(noun, &left, complement);
                count += 1;
                failures.extend(check(&format!("sibling {input:?}"), &input, &expected));

                let relative = format!("the {noun} that I use: ");
                let reference = scrub_text(&format!("{relative}{complement}"));
                assert!(reference.starts_with(&relative), "{reference:?}");
                let left = format!("the {noun}{subject}: ");
                let input = format!("{left}{complement}");
                let expected = format!("{left}{}", &reference[relative.len()..]);
                count += 1;
                failures.extend(check(&format!("sibling {input:?}"), &input, &expected));
            }
        }
    }
    report("contact punctuation siblings", count, &failures);
}

/// The contact clause's verb does not count toward the descriptor bound.
#[test]
fn e_contact_clause_punctuation_at_the_descriptor_bound() {
    let mut cases = Vec::new();
    for noun in NOUNS {
        for at in [LIMIT - 1, LIMIT, LIMIT + 1] {
            let text = format!("the {noun} Bob uses, {}, is Q1x", words(at));
            cases.push((
                format!("bound comma {noun} {at}"),
                text.clone(),
                text.replace("Q1x", R),
            ));
            let text = format!("the {noun} Bob uses, which is {} is Q1x", words(at - 2));
            cases.push((
                format!("bound which {noun} {at}"),
                text.clone(),
                text.replace("Q1x", R),
            ));
        }
    }
    report("contact punctuation bound", cases.len(), &run(&cases));
}

// ---------------------------------------- has changed to, has now been to

const HAS_CHANGED_SINGULAR: [&str; 8] = [
    " has changed to ",
    " had changed to ",
    " has now been set to ",
    " has still been set to ",
    " has now been changed to ",
    " had now been reset to ",
    " has still been updated to ",
    " had still been set to ",
];

const HAS_CHANGED_PLURAL: [&str; 5] = [
    " have changed to ",
    " had changed to ",
    " have now been set to ",
    " have still been changed to ",
    " had now been updated to ",
];

#[test]
fn e_has_changed_to_and_has_now_been_set_to_disclose() {
    let mut cases = Vec::new();
    for (nouns, cues) in [
        (NOUNS, &HAS_CHANGED_SINGULAR[..]),
        (PLURALS, &HAS_CHANGED_PLURAL[..]),
    ] {
        for noun in nouns {
            for determiner in ["the ", "", "My "] {
                for descriptor in [
                    "",
                    " for the box",
                    " that I use",
                    " used by db1.example.com",
                ] {
                    for cue in cues {
                        let left = format!("{determiner}{noun}{descriptor}{cue}");
                        cases.push((
                            format!("cue {left:?}"),
                            format!("{left}Q1x"),
                            format!("{left}{R}"),
                        ));
                    }
                }
                for (open, value, close) in VALUES {
                    let left = format!("{determiner}{noun}{}{open}", cues[0]);
                    cases.push((
                        format!("cue value {left:?}{value}"),
                        format!("{left}{value}{close}"),
                        format!("{left}{R}{close}"),
                    ));
                }
            }
        }
    }
    for noun in NOUNS {
        for at in [LIMIT - 1, LIMIT, LIMIT + 1] {
            for cue in [" has changed to ", " has now been set to "] {
                let left = format!("the {noun} for {}{cue}", words(at));
                cases.push((
                    format!("bound {noun} {at} {cue:?}"),
                    format!("{left}Q1x"),
                    format!("{left}{R}"),
                ));
            }
        }
    }
    report("has changed to", cases.len(), &run(&cases));
}

#[test]
fn e_has_changed_to_rows_and_controls() {
    let cases = [
        case(
            "has changed to",
            "the password has changed to Zq9x",
            &format!("the password has changed to {R}"),
        ),
        case(
            "has now been set to",
            "the password has now been set to Zq9x",
            &format!("the password has now been set to {R}"),
        ),
        case(
            "plural",
            "the passwords have changed to Zq9x",
            &format!("the passwords have changed to {R}"),
        ),
        case(
            "F4 tail",
            "The password has changed to Zq9x for the staging box.",
            &format!("The password has changed to {R}."),
        ),
        // No `to`, or no value after it.
        case(
            "no to",
            "the password has changed",
            "the password has changed",
        ),
        case(
            "since",
            "the password has changed since Monday",
            "the password has changed since Monday",
        ),
        // Number agreement as for the other cues.
        case(
            "plural has",
            "the passwords has changed to Zq9x",
            "the passwords has changed to Zq9x",
        ),
        case(
            "singular have",
            "the password have changed to Zq9x",
            "the password have changed to Zq9x",
        ),
        case(
            "plural has now",
            "the passwords has now been set to Zq9x",
            "the passwords has now been set to Zq9x",
        ),
        // Exactly the two forms: no other adverb, no adverb before `changed`.
        case(
            "has now changed",
            "the password has now changed to Zq9x",
            "the password has now changed to Zq9x",
        ),
        case(
            "has recently been",
            "the password has recently been set to Zq9x",
            "the password has recently been set to Zq9x",
        ),
        case(
            "has been now",
            "the password has been now set to Zq9x",
            "the password has been now set to Zq9x",
        ),
        case(
            "has not changed",
            "the password has not changed to Zq9x",
            "the password has not changed to Zq9x",
        ),
        case(
            "has not been",
            "the password has not been set to Zq9x",
            "the password has not been set to Zq9x",
        ),
    ];
    report("has changed to pins", cases.len(), &run(&cases));
}

/// `has changed to` judges its complement exactly as `changed to` does, and
/// `has now been set to` exactly as `has been set to` does.
#[test]
fn e_has_changed_to_siblings_and_their_attacks() {
    let mut failures = Vec::new();
    let mut count = 0;
    for (noun, plural) in NOUNS.into_iter().zip(PLURALS) {
        for (reference, left) in [
            (
                format!("the {noun} changed to "),
                format!("the {noun} has changed to "),
            ),
            (
                format!("the {noun} changed to "),
                format!("the {noun} had changed to "),
            ),
            (
                format!("the {plural} changed to "),
                format!("the {plural} have changed to "),
            ),
            (
                format!("the {noun} has been set to "),
                format!("the {noun} has now been set to "),
            ),
            (
                format!("the {noun} has been set to "),
                format!("the {noun} has still been set to "),
            ),
        ] {
            for complement in DOCUMENTARY
                .iter()
                .chain(ATTACKS.iter())
                .chain(["meet the policy"].iter())
            {
                let output = scrub_text(&format!("{reference}{complement}"));
                assert!(output.starts_with(&reference), "{output:?}");
                let input = format!("{left}{complement}");
                let expected = format!("{left}{}", &output[reference.len()..]);
                count += 1;
                failures.extend(check(&format!("sibling {input:?}"), &input, &expected));
            }
        }
    }
    report("has changed to siblings", count, &failures);
}

// ---------------------------------------------------------- bounded work

/// Contact clauses followed by punctuation and the new `has` cues stay
/// linear, and so do runs of bare and determined nouns.
#[test]
fn bounded_work_for_contact_punctuation_and_has_changed_at_64_and_256_kib() {
    use std::time::{Duration, Instant};
    let _ = scrub_text("warmup");
    let timed = |label: String, input: &str| {
        let start = Instant::now();
        std::hint::black_box(scrub_text(input));
        let elapsed = start.elapsed();
        eprintln!("{label} {elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(5),
            "{label} exceeded the CI bound"
        );
    };
    for size in [65_536, 262_144] {
        for unit in [
            "pw ",
            "the pw ",
            "the pw Bob uses, ",
            "the pw Bob uses: ",
            "the pw Bob uses=a ",
            "the pw Bob uses, which is ",
            "the pw I set,\n",
            "pw has changed to ",
            "pw has now been set to ",
            "the pws have still been ",
        ] {
            for prefix in ["", "x \"", "{\"note\":\"", "the password for "] {
                let input = format!("{prefix}{}", unit.repeat(size / unit.len() + 1));
                timed(format!("unit {size} {unit:?} {prefix:?}"), &input[..size]);
            }
        }
        for (head, unit, tail) in [
            ("the password Bob uses, ", "a ", " is x"),
            ("the password Bob uses, which ", "a ", " is x"),
            ("the password has ", "now ", " been set to x"),
        ] {
            let body = unit.repeat((size - head.len() - tail.len()) / unit.len());
            timed(
                format!("long {size} {head:?} {unit:?}"),
                &format!("{head}{body}{tail}"),
            );
        }
    }
}
