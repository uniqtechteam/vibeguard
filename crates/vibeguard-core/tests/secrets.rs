//! SEC-001, SEC-002, SEC-003 against small temporary projects.
//!
//! Fake keys are assembled at runtime so no key-shaped string is stored in this repository.

#![allow(clippy::unwrap_used, reason = "test setup on a temp folder")]

use std::fs;
use std::path::Path;

use vibeguard_core::{Confidence, Finding, Severity, scan};

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

fn stripe_live_key() -> String {
    ["sk", "_live_", "51HfakeKeyForTests", "0123456789WXYZ"].concat()
}

fn findings(root: &Path, rule: &str) -> Vec<Finding> {
    scan(root)
        .unwrap()
        .findings
        .into_iter()
        .filter(|f| f.rule == rule)
        .collect()
}

// ------------------------------------------------------------- SEC-001

#[test]
fn ac_001_sec_001_finds_a_live_key_in_code_with_its_line() {
    let dir = tempfile::tempdir().unwrap();
    let key = stripe_live_key();
    write(
        dir.path(),
        "src/pay.ts",
        &format!("import Stripe from 'stripe'\n\nconst s = new Stripe(\"{key}\")\n"),
    );
    let f = findings(dir.path(), "SEC-001");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].file.as_str(), f[0].line), ("src/pay.ts", Some(3)));
    assert_eq!(f[0].severity, Severity::Critical);
}

#[test]
fn ac_003_sec_001_never_shows_the_full_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = stripe_live_key();
    write(
        dir.path(),
        "config.js",
        &format!("export const key = '{key}'\n"),
    );
    let f = findings(dir.path(), "SEC-001");
    assert!(!f[0].snippet.contains(&key));
    assert!(
        f[0].snippet.contains("sk_live_****WXYZ"),
        "{}",
        f[0].snippet
    );
}

#[test]
fn sec_001_flags_an_unignored_env_file_with_secret_values() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".env.local",
        "NEXT_PUBLIC_SITE_URL=https://x.dev\nSTRIPE_SECRET_KEY=abc123\n",
    );
    let f = findings(dir.path(), "SEC-001");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!((f[0].file.as_str(), f[0].line), (".env.local", None));
}

#[test]
fn ac_002_sec_001_ignores_examples_ignored_env_files_and_public_only_env() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".env.example",
        "STRIPE_SECRET_KEY=your-key-here\n",
    );
    write(dir.path(), ".env", "STRIPE_SECRET_KEY=abc123\n");
    write(dir.path(), ".gitignore", ".env\n");
    write(
        dir.path(),
        ".env.production",
        "NEXT_PUBLIC_SITE_URL=https://x.dev\n",
    );
    assert_eq!(findings(dir.path(), "SEC-001"), Vec::<Finding>::new());
}

// ------------------------------------------------------------- SEC-002

#[test]
fn ac_001_sec_002_finds_service_role_in_a_client_component() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"dependencies":{"next":"15","@supabase/supabase-js":"2"}}"#,
    );
    write(
        dir.path(),
        "app/admin/AdminPanel.tsx",
        "'use client'\nimport { createClient } from '@supabase/supabase-js'\nconst db = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n",
    );
    let f = findings(dir.path(), "SEC-002");
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(
        (f[0].file.as_str(), f[0].line),
        ("app/admin/AdminPanel.tsx", Some(3))
    );
}

#[test]
fn sec_002_counts_every_file_under_src_in_a_vite_app() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"dependencies":{"vite":"6"}}"#,
    );
    write(
        dir.path(),
        "src/lib/db.ts",
        "export const key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY\n",
    );
    assert_eq!(findings(dir.path(), "SEC-002").len(), 1);
}

#[test]
fn ac_002_sec_002_allows_service_role_in_server_code() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"dependencies":{"next":"15"}}"#,
    );
    write(
        dir.path(),
        "app/api/admin/route.ts",
        "const db = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n",
    );
    write(
        dir.path(),
        "pages/api/sync.ts",
        "const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n",
    );
    write(
        dir.path(),
        "supabase/functions/cron/index.ts",
        "Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')\n",
    );
    write(
        dir.path(),
        "src/routes/+page.server.ts",
        "const k = env.SUPABASE_SERVICE_ROLE_KEY\n",
    );
    assert_eq!(findings(dir.path(), "SEC-002"), Vec::<Finding>::new());
}

// ------------------------------------------------------------- SEC-003

#[test]
fn ac_001_sec_003_flags_a_secret_with_a_public_prefix() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".env.example",
        "NEXT_PUBLIC_STRIPE_SECRET_KEY=\nNEXT_PUBLIC_OPENAI_KEY=\n",
    );
    let f = findings(dir.path(), "SEC-003");
    assert_eq!(f.len(), 2, "{f:?}");
    let strong = f.iter().find(|x| x.line == Some(1)).unwrap();
    assert_eq!(
        (strong.severity, strong.confidence),
        (Severity::High, Confidence::High)
    );
    let weak = f.iter().find(|x| x.line == Some(2)).unwrap();
    assert_eq!(
        (weak.severity, weak.confidence),
        (Severity::Medium, Confidence::Medium)
    );
}

#[test]
fn sec_003_reports_each_name_once_per_file() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "lib/ai.ts",
        "const a = process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY\nconst b = process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY\n",
    );
    assert_eq!(findings(dir.path(), "SEC-003").len(), 1);
}

#[test]
fn ac_002_sec_003_allows_keys_that_are_public_by_design() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".env.example",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=\nNEXT_PUBLIC_FIREBASE_API_KEY=\nVITE_SITE_URL=\n",
    );
    assert_eq!(findings(dir.path(), "SEC-003"), Vec::<Finding>::new());
}

#[test]
fn sec_003_ignores_public_prefixes_outside_web_code_and_env_files() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "docs/setup.md",
        "Never set NEXT_PUBLIC_STRIPE_SECRET_KEY.\n",
    );
    write(
        dir.path(),
        "tools/check.py",
        "BAD = 'NEXT_PUBLIC_STRIPE_SECRET_KEY'\n",
    );
    assert_eq!(findings(dir.path(), "SEC-003"), Vec::<Finding>::new());
}
