//! SPEC-CLI-001 FR-003, FR-005, FR-006, FR-007: rules, config, inline ignores, baseline, SARIF, Markdown.

#![allow(
    clippy::unwrap_used,
    reason = "test setup; a failure should stop the test"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vibeguard"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn demo_app() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/demo-app")
}

fn json(args: &[&str]) -> serde_json::Value {
    let mut all = vec!["scan"];
    all.extend_from_slice(args);
    all.extend_from_slice(&["--format", "json"]);
    serde_json::from_slice(&run(&all).stdout).unwrap()
}

fn rules_found(v: &serde_json::Value) -> Vec<String> {
    let mut r: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule"].as_str().unwrap().to_owned())
        .collect();
    r.sort();
    r
}

// ---------------------------------------------------------------- rules / explain / selection

#[test]
fn rules_lists_every_rule() {
    let text = stdout(&run(&["rules"]));
    for id in [
        "SEC-001", "SEC-002", "SEC-003", "DB-001", "DB-002", "DB-003", "PAY-001", "PAY-002",
        "CFG-IGN",
    ] {
        assert!(text.contains(id), "{id} missing:\n{text}");
    }
}

#[test]
fn explain_prints_the_rule_and_unknown_ids_exit_2() {
    let o = run(&["explain", "db-001"]);
    assert!(o.status.success());
    assert!(stdout(&o).starts_with("DB-001 Supabase table without Row Level Security"));
    assert_eq!(run(&["explain", "XYZ-999"]).status.code(), Some(2));
}

#[test]
fn rules_and_skip_select_what_runs() {
    let root = demo_app();
    let root = root.to_str().unwrap();
    assert_eq!(
        rules_found(&json(&[root, "--rules", "DB-001,DB-002"])),
        ["DB-001", "DB-002"]
    );
    let skipped = rules_found(&json(&[root, "--skip", "PAY-001,PAY-002"]));
    assert!(!skipped.iter().any(|r| r.starts_with("PAY")), "{skipped:?}");
}

#[test]
fn val_001_unknown_rule_ids_exit_2_with_the_valid_list() {
    let o = run(&["scan", demo_app().to_str().unwrap(), "--rules", "NOPE-001"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("valid rules: "));
}

// ---------------------------------------------------------------- vibeguard.toml

#[test]
fn config_file_skips_rules_ignores_paths_and_sets_the_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, ".env.example", "NEXT_PUBLIC_STRIPE_SECRET_KEY=\n");
    write(
        root,
        "examples/demo/.env.example",
        "NEXT_PUBLIC_SERVICE_ROLE_KEY=\n",
    );
    write(
        root,
        "supabase/migrations/001.sql",
        "create table notes (id int);\n",
    );
    let r = root.to_str().unwrap();
    assert_eq!(rules_found(&json(&[r])), ["DB-001", "SEC-003", "SEC-003"]);
    write(
        root,
        "vibeguard.toml",
        "fail_on = \"critical\"\nskip = [\"DB-001\"]\n\n[paths]\nignore = [\"examples/**\"]\n",
    );
    assert_eq!(rules_found(&json(&[r])), ["SEC-003"]);
    assert_eq!(
        run(&["scan", r]).status.code(),
        Some(0),
        "only a high finding left, fail_on = critical"
    );
    assert_eq!(
        run(&["scan", r, "--fail-on", "high"]).status.code(),
        Some(1),
        "the flag beats the file"
    );
}

#[test]
fn a_bad_config_file_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "vibeguard.toml", "fail_on = \"sometimes\"\n");
    assert_eq!(
        run(&["scan", dir.path().to_str().unwrap()]).status.code(),
        Some(2)
    );
    write(dir.path(), "vibeguard.toml", "no_such_setting = true\n");
    assert_eq!(
        run(&["scan", dir.path().to_str().unwrap()]).status.code(),
        Some(2)
    );
}

// ---------------------------------------------------------------- inline ignores

#[test]
fn ac_003_inline_ignore_silences_the_rule_on_that_line() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "supabase/migrations/001.sql",
        "-- vibeguard-ignore: DB-001 public list of countries, read-only data\ncreate table countries (code text);\ncreate table notes (id int);\n",
    );
    let r = dir.path().to_str().unwrap();
    let v = json(&[r]);
    assert_eq!(rules_found(&v), ["DB-001"], "notes is still reported");
    assert_eq!(
        v["ignored"][0]["reason"],
        "public list of countries, read-only data"
    );
    let pretty = stdout(&run(&["scan", r, "--show-ignored"]));
    assert!(
        pretty.contains("Reason: public list of countries"),
        "{pretty}"
    );
    assert!(pretty.contains("1 ignored"), "{pretty}");
}

#[test]
fn val_002_ignore_without_reason_or_with_unknown_rule_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "supabase/migrations/001.sql",
        "-- vibeguard-ignore: DB-001\ncreate table countries (code text);\n-- vibeguard-ignore: DB-999 typo\n",
    );
    let v = json(&[dir.path().to_str().unwrap()]);
    assert_eq!(
        rules_found(&v),
        ["CFG-IGN", "CFG-IGN", "DB-001"],
        "no reason means not ignored"
    );
}

// ---------------------------------------------------------------- baseline

#[test]
fn ac_004_baseline_hides_known_findings_and_shows_new_ones() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "supabase/migrations/001.sql",
        "create table notes (id int);\n",
    );
    let base = root.join("baseline.json");
    let r = root.to_str().unwrap();
    let b = base.to_str().unwrap();
    assert_eq!(
        run(&["scan", r, "--write-baseline", b]).status.code(),
        Some(1)
    );
    let o = run(&["scan", r, "--baseline", b]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    assert!(stdout(&o).contains("1 in baseline"));
    // a new problem appears above the old one; the old one stays hidden even though its line moved
    write(
        root,
        "supabase/migrations/001.sql",
        "create table todos (id int);\ncreate table notes (id int);\n",
    );
    let v = json(&[r, "--baseline", b]);
    assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    assert!(
        v["findings"][0]["snippet"]
            .as_str()
            .unwrap()
            .contains("todos")
    );
    assert_eq!(v["baselined"], 1);
}

#[test]
fn a_missing_baseline_file_exits_2() {
    assert_eq!(
        run(&[
            "scan",
            demo_app().to_str().unwrap(),
            "--baseline",
            "/nope/baseline.json"
        ])
        .status
        .code(),
        Some(2)
    );
}

// ---------------------------------------------------------------- SARIF and Markdown

#[test]
fn ac_002_sarif_is_valid_against_the_official_schema() {
    let o = run(&["scan", demo_app().to_str().unwrap(), "--format", "sarif"]);
    let sarif: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let schema_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/schemas/sarif-2.1.0.json");
    let schema: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(schema_path).unwrap()).unwrap();
    let validator = jsonschema::draft4::new(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&sarif)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 8);
    for r in results {
        assert!(
            r["partialFingerprints"]["vibeguard/v1"]
                .as_str()
                .is_some_and(|f| f.len() == 16)
        );
        assert!(r["properties"]["security-severity"].is_string());
    }
}

#[test]
fn markdown_is_a_table_with_every_finding() {
    let text = stdout(&run(&[
        "scan",
        demo_app().to_str().unwrap(),
        "--format",
        "markdown",
    ]));
    assert!(text.starts_with("## vibeguard\n\n| Severity | Rule | Where | Code | Why | Fix |"));
    let rows = text
        .lines()
        .filter(|l| {
            ["| critical", "| high", "| medium", "| low"]
                .iter()
                .any(|p| l.starts_with(p))
        })
        .count();
    assert_eq!(rows, 8, "{text}");
}
