//! End-to-end tests of the `vibeguard` binary: exit codes, formats, files, colours and the demo app.

#![allow(
    clippy::unwrap_used,
    reason = "test setup; a failure should stop the test"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vibeguard"));
    cmd.env_remove("NO_COLOR");
    cmd
}

fn demo_app() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/demo-app")
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

#[test]
fn version_and_help_work() {
    let v = run(&["--version"]);
    assert!(v.status.success());
    assert!(stdout(&v).starts_with("vibeguard "));
    let h = run(&["scan", "--help"]);
    assert!(h.status.success());
    assert!(stdout(&h).contains("--fail-on"));
}

#[test]
fn clean_project_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "src/index.ts", "export const hello = 'world'\n");
    let o = run(&["scan", dir.path().to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    assert!(stdout(&o).contains("No problems found."));
}

#[test]
fn ac_001_critical_finding_exits_1() {
    let o = run(&["scan", demo_app().to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn ac_005_fail_on_never_exits_0() {
    let o = run(&["scan", demo_app().to_str().unwrap(), "--fail-on", "never"]);
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn fail_on_critical_ignores_high_findings() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".env.example",
        "NEXT_PUBLIC_STRIPE_SECRET_KEY=\n",
    );
    let root = dir.path().to_str().unwrap();
    assert_eq!(
        run(&["scan", root]).status.code(),
        Some(1),
        "high fails the default threshold"
    );
    assert_eq!(
        run(&["scan", root, "--fail-on", "critical"]).status.code(),
        Some(0)
    );
}

#[test]
fn medium_confidence_needs_strict_to_fail() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".env.example", "NEXT_PUBLIC_OPENAI_KEY=\n");
    let root = dir.path().to_str().unwrap();
    assert_eq!(
        run(&["scan", root, "--fail-on", "low"]).status.code(),
        Some(0)
    );
    assert_eq!(
        run(&["scan", root, "--fail-on", "low", "--strict"])
            .status
            .code(),
        Some(1)
    );
}

#[test]
fn missing_folder_exits_2_with_a_message() {
    let o = run(&["scan", "/definitely/not/a/folder"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("cannot scan"));
}

#[test]
fn unknown_option_exits_2() {
    assert_eq!(run(&["scan", "--no-such-flag"]).status.code(), Some(2));
}

#[test]
fn json_is_valid_and_counts_match() {
    let o = run(&["scan", demo_app().to_str().unwrap(), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    let count = |sev: &str| findings.iter().filter(|f| f["severity"] == sev).count();
    for sev in ["critical", "high", "medium", "low"] {
        assert_eq!(
            v["summary"][sev].as_u64().unwrap(),
            count(sev) as u64,
            "{sev}"
        );
    }
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    let stack: Vec<&str> = v["stack"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str())
        .collect();
    assert_eq!(stack, ["nextjs", "supabase", "stripe"]);
}

#[test]
fn demo_app_reports_every_planted_problem() {
    let o = run(&["scan", demo_app().to_str().unwrap(), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let mut got: Vec<String> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{} {}:{}",
                f["rule"].as_str().unwrap(),
                f["file"].as_str().unwrap(),
                f["line"]
            )
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        [
            "DB-001 supabase/migrations/20250101000000_init.sql:1",
            "DB-002 supabase/migrations/20250101000000_init.sql:12",
            "PAY-001 app/api/stripe/webhook/route.ts:6",
            "PAY-002 app/api/checkout/route.ts:9",
            "SEC-002 components/AdminTable.tsx:4",
            "SEC-003 .env.example:3",
        ]
    );
}

#[test]
fn findings_use_forward_slashes() {
    let o = run(&["scan", demo_app().to_str().unwrap(), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    for f in v["findings"].as_array().unwrap() {
        assert!(!f["file"].as_str().unwrap().contains('\\'), "{f}");
    }
}

#[test]
fn output_flag_writes_the_report_to_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("report.json");
    let o = run(&[
        "scan",
        demo_app().to_str().unwrap(),
        "--format",
        "json",
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        o.stdout.is_empty(),
        "nothing on stdout when --output is used"
    );
    let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(out).unwrap()).unwrap();
    assert_eq!(v["findings"].as_array().unwrap().len(), 6);
}

#[test]
fn quiet_prints_only_the_summary() {
    let o = run(&["scan", demo_app().to_str().unwrap(), "--quiet"]);
    let text = stdout(&o);
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.starts_with("3 critical · 3 high · 0 medium · 0 low · "));
}

#[test]
fn piped_output_has_no_colour_codes() {
    let o = run(&["scan", demo_app().to_str().unwrap()]);
    assert!(!stdout(&o).contains('\x1b'));
}

#[test]
fn secrets_are_masked_in_every_format_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    // assembled at runtime so no key-shaped string is stored in the repository
    let key = ["sk", "_live_", "51HendToEndTestKey", "0123456789QRST"].concat();
    write(
        dir.path(),
        "src/pay.ts",
        &format!("const stripe = new Stripe('{key}')\n"),
    );
    let root = dir.path().to_str().unwrap();
    for format in ["pretty", "json"] {
        let o = run(&["scan", root, "--format", format]);
        let text = stdout(&o);
        assert!(!text.contains(&key), "{format} leaked the key:\n{text}");
        assert!(
            text.contains("sk_live_****QRST"),
            "{format} lacks the masked key:\n{text}"
        );
    }
}

#[test]
fn pretty_output_matches_the_snapshot() {
    let o = run(&["scan", demo_app().to_str().unwrap()]);
    let text = stdout(&o);
    // the timing changes run to run; everything else must not
    let stable: String = text
        .lines()
        .map(|l| match l.rfind(" in ") {
            Some(i) if l.ends_with('s') && l.contains(" files") => format!("{} in <time>", &l[..i]),
            _ => l.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/snapshots/demo-app.txt");
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::write(&path, &stable).unwrap();
    }
    let expected = fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        stable, expected,
        "run with UPDATE_SNAPSHOTS=1 to accept a deliberate change"
    );
}
