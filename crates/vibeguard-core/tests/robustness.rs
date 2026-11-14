//! Odd inputs, many key shapes, and speed.

#![allow(clippy::unwrap_used, reason = "test setup on a temp folder")]

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use vibeguard_core::scan;

fn write(root: &Path, rel: &str, body: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

#[test]
fn odd_files_do_not_break_the_scan() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "empty.ts", b"");
    write(root, "only-newlines.sql", b"\n\n\n");
    write(root, "binary.bin", &[0, 159, 146, 150, 0, 1, 2]);
    write(root, "latin1.ts", &[0x63, 0x61, 0x66, 0xe9, b'\n']);
    write(
        root,
        "unicode.ts",
        "const name = 'Tiếng Việt 日本語 🙂'\n".as_bytes(),
    );
    write(
        root,
        "crlf.sql",
        b"create table a (id int);\r\nalter table a enable row level security;\r\n",
    );
    write(root, "no-newline.env", b"KEY=value");
    let deep = (0..40)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join("/");
    write(root, &format!("{deep}/deep.ts"), b"export {}\n");
    let report = scan(root).unwrap();
    assert!(
        report.internal_errors.is_empty(),
        "{:?}",
        report.internal_errors
    );
    assert!(report.scanned_files >= 8);
}

#[test]
fn unterminated_sql_comment_and_string_are_handled() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "supabase/migrations/001.sql",
        b"create table notes (id int);\n/* never closed\nalter table notes enable row level security;\n",
    );
    write(
        dir.path(),
        "supabase/migrations/002.sql",
        b"select 'unterminated;\ncreate policy p on x for all using (true\n",
    );
    let report = scan(dir.path()).unwrap();
    assert!(
        report.internal_errors.is_empty(),
        "{:?}",
        report.internal_errors
    );
    // the RLS line sits inside an unclosed comment, so the table is still unprotected
    assert!(report.findings.iter().any(|f| f.rule == "DB-001"));
}

#[cfg(unix)]
#[test]
fn symlink_loops_do_not_hang() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "src/a.ts", b"export {}\n");
    std::os::unix::fs::symlink(root, root.join("src/loop")).unwrap();
    let started = Instant::now();
    let report = scan(root).unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(report.internal_errors, Vec::<String>::new());
}

/// Every key shape SEC-001 knows, with many variants each: the full key must never be in a snippet.
#[test]
fn no_key_variant_ever_appears_unmasked() {
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        .chars()
        .collect();
    let mut seed: u64 = 0x5eed_1234_abcd_ef01;
    let mut random = |n: usize, upper_digits_only: bool| -> String {
        (0..n)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let pool = if upper_digits_only {
                    36
                } else {
                    alphabet.len()
                };
                let i = usize::try_from(seed % pool as u64).unwrap();
                if upper_digits_only {
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                        .chars()
                        .nth(i)
                        .unwrap()
                } else {
                    alphabet[i]
                }
            })
            .collect()
    };
    let mut keys = Vec::new();
    for _ in 0..25 {
        keys.push(["sk", "_live_", &random(40, false)].concat());
        keys.push(["rk", "_live_", &random(30, false)].concat());
        keys.push(["wh", "sec_", &random(32, false)].concat());
        keys.push(["AK", "IA", &random(16, true)].concat());
        keys.push(["sk", "-proj-", &random(48, false)].concat());
        keys.push(["gh", "p_", &random(36, false)].concat());
    }
    let dir = tempfile::tempdir().unwrap();
    let mut body = String::new();
    for (i, k) in keys.iter().enumerate() {
        writeln!(body, "const k{i} = \"{k}\"").unwrap();
    }
    write(dir.path(), "src/keys.ts", body.as_bytes());
    let report = scan(dir.path()).unwrap();
    let sec: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule == "SEC-001")
        .collect();
    assert_eq!(sec.len(), keys.len(), "every key found once");
    let json = serde_json::to_string(&report).unwrap();
    for k in &keys {
        assert!(!json.contains(k.as_str()), "key leaked: {k}");
    }
}

/// SPEC-RULE-001 §14: 5,000 files in under a second. Only meaningful in a release build:
/// `cargo test --release -- --ignored five_thousand_files`.
#[test]
#[ignore = "speed check; run in release mode"]
fn five_thousand_files_in_under_a_second() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "package.json",
        br#"{"dependencies":{"next":"15","@supabase/supabase-js":"2","stripe":"17"}}"#,
    );
    for i in 0..5000 {
        let body = format!(
            "'use client'\nimport {{ useState }} from 'react'\n\nexport function C{i}() {{\n  const [n, setN] = useState({i})\n  return n\n}}\n"
        );
        write(
            root,
            &format!("components/c{}/C{i}.tsx", i % 50),
            body.as_bytes(),
        );
    }
    let started = Instant::now();
    let report = scan(root).unwrap();
    let took = started.elapsed();
    assert_eq!(report.scanned_files, 5001);
    assert!(took < Duration::from_secs(1), "took {took:?}");
}
