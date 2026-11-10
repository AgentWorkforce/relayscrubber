#![allow(missing_docs)]
#[path = "../eval/generate.rs"]
mod generate;
use relayscrubber::{scrub_report, scrub_text, Policy};

#[test]
fn independent_seeded_corpus_requires_complete_secret_span_coverage() {
    for seed in [0x5eed, 0xa11ce, 0xdeadbeef, 0x123456789] {
        for case in generate::recall(seed, 32) {
            let report = scrub_report(&case.text, Policy::Secrets);
            for expected in &case.secrets {
                assert!(
                    report
                        .redactions
                        .iter()
                        .any(|r| r.start <= expected.start && r.end >= expected.end),
                    "class {} seed {seed}: missing complete coverage",
                    case.class
                );
            }
            assert_eq!(
                scrub_text(&report.text),
                report.text,
                "{} idempotence",
                case.class
            );
        }
        for (class, text) in generate::benign(seed, 64) {
            assert_eq!(scrub_text(&text), text, "{class}");
        }
    }
}
