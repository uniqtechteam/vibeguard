//! Runs every fixture under `tests/fixtures/<RULE-ID>/{bad,good}`.

#![allow(
    clippy::panic,
    reason = "a fixture with a missing or broken expected.json should fail the test loudly"
)]

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Expected {
    rule: String,
    file: String,
    line: Option<u32>,
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn rule_dirs() -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(fixtures_root()) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

#[test]
fn bad_fixtures_produce_exactly_the_expected_findings() {
    for dir in rule_dirs() {
        let bad = dir.join("bad");
        if !bad.is_dir() {
            continue;
        }
        let raw = fs::read_to_string(bad.join("expected.json"))
            .unwrap_or_else(|_| panic!("{} needs an expected.json", bad.display()));
        let mut expected: Vec<Expected> = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("{}: bad expected.json: {e}", bad.display()));
        let rule = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        // each fixture asserts its own rule; other rules may legitimately fire on the same code
        let mut got: Vec<Expected> = vibeguard_core::scan(&bad)
            .unwrap_or_else(|e| panic!("{}: {e}", bad.display()))
            .findings
            .into_iter()
            .filter(|f| f.rule == rule)
            .map(|f| Expected {
                rule: f.rule,
                file: f.file,
                line: f.line,
            })
            .collect();
        expected.sort();
        got.sort();
        assert_eq!(got, expected, "fixture {}", bad.display());
    }
}

#[test]
fn good_fixtures_produce_no_finding_of_their_rule() {
    for dir in rule_dirs() {
        let good = dir.join("good");
        if !good.is_dir() {
            continue;
        }
        let rule = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        let hits: Vec<_> = vibeguard_core::scan(&good)
            .unwrap_or_else(|e| panic!("{}: {e}", good.display()))
            .findings
            .into_iter()
            .filter(|f| f.rule == rule)
            .collect();
        assert!(
            hits.is_empty(),
            "fixture {} reported {hits:?}",
            good.display()
        );
    }
}
