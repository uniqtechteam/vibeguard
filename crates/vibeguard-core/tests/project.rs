//! Walking, skipping and stack detection.

#![allow(clippy::unwrap_used, reason = "test setup on a temp folder")]

use std::fs;
use std::path::Path;

use vibeguard_core::{
    Confidence, FailOn, Finding, MAX_FILE_BYTES, Project, Report, Severity, Stack, Summary,
};

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

#[test]
fn skips_dependency_and_build_folders_and_gitignored_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "src/app.ts", "export {}");
    write(root, "node_modules/x/index.js", "x");
    write(root, ".next/server/page.js", "x");
    write(root, "dist/bundle.js", "x");
    write(root, "secret-notes.txt", "x");
    write(root, ".gitignore", "secret-notes.txt\n");
    let project = Project::load(root).unwrap();
    let paths: Vec<&str> = project.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, [".gitignore", "src/app.ts"]);
}

#[test]
fn skips_files_over_the_size_limit_and_binaries() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "big.json",
        &"a".repeat(usize::try_from(MAX_FILE_BYTES).unwrap() + 1),
    );
    fs::write(root.join("logo.png"), [0x89, b'P', b'N', b'G', 0, 0, 1]).unwrap();
    let project = Project::load(root).unwrap();
    assert!(project.file("big.json").is_none());
    assert!(project.file("logo.png").unwrap().text().is_none());
}

#[test]
fn detects_stack_from_package_json_and_folders() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "package.json",
        r#"{"dependencies":{"next":"15","@supabase/supabase-js":"2","stripe":"17"}}"#,
    );
    write(root, "firestore.rules", "rules_version = '2';");
    let project = Project::load(root).unwrap();
    assert!(project.uses(Stack::NextJs));
    assert!(project.uses(Stack::Supabase));
    assert!(project.uses(Stack::Stripe));
    assert!(project.uses(Stack::Firebase));
    assert!(!project.uses(Stack::Vite));
}

#[test]
fn missing_folder_is_an_error() {
    assert!(Project::load(Path::new("/definitely/not/here")).is_err());
}

fn report(severity: Severity, confidence: Confidence) -> Report {
    Report {
        version: "test",
        stack: Vec::new(),
        scanned_files: 1,
        duration_ms: 1,
        findings: vec![Finding {
            rule: "X-001".into(),
            title: "t".into(),
            severity,
            confidence,
            file: "f".into(),
            line: Some(1),
            snippet: String::new(),
            why: String::new(),
            fix: String::new(),
        }],
        summary: Summary::default(),
        internal_errors: Vec::new(),
    }
}

#[test]
fn ac_001_critical_finding_fails_the_default_threshold() {
    let r = report(Severity::Critical, Confidence::High);
    assert!(r.fails(FailOn::AtLeast(Severity::High), false));
}

#[test]
fn ac_005_fail_on_never_passes_even_with_critical_findings() {
    let r = report(Severity::Critical, Confidence::High);
    assert!(!r.fails(FailOn::Never, false));
}

#[test]
fn medium_confidence_fails_only_when_strict() {
    let r = report(Severity::Critical, Confidence::Medium);
    assert!(!r.fails(FailOn::AtLeast(Severity::High), false));
    assert!(r.fails(FailOn::AtLeast(Severity::High), true));
}

#[test]
fn below_threshold_passes() {
    let r = report(Severity::Low, Confidence::High);
    assert!(!r.fails(FailOn::AtLeast(Severity::High), false));
}
