//! The built-in rules and small helpers they share.

pub mod secrets;
pub mod stripe;
pub mod supabase;

use crate::{Confidence, Finding, Severity, SourceFile};

/// Extensions of files that hold code or config worth reading for secrets and env usage.
pub(crate) const CODE_EXTS: &[&str] = &[
    "js",
    "jsx",
    "ts",
    "tsx",
    "mjs",
    "cjs",
    "mts",
    "cts",
    "svelte",
    "vue",
    "astro",
    "json",
    "yaml",
    "yml",
    "toml",
    "py",
    "rb",
    "go",
    "rs",
    "php",
    "java",
    "kt",
    "swift",
    "dart",
    "sh",
    "sql",
    "md",
    "txt",
    "html",
    "env",
    "ini",
    "cfg",
    "conf",
    "properties",
    "xml",
];

/// Generated or lock files that only produce noise.
pub(crate) fn is_noise(file: &SourceFile) -> bool {
    let name = file.name();
    matches!(
        name,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "bun.lockb"
            | "Cargo.lock"
            | "composer.lock"
    ) || name.to_ascii_lowercase().contains(".min.")
        || std::path::Path::new(name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("map"))
}

/// Whether the file is a dotenv file (`.env`, `.env.local`, `.env.production`, …).
pub(crate) fn is_env_file(file: &SourceFile) -> bool {
    let name = file.name();
    name == ".env" || name.starts_with(".env.")
}

/// Whether the file is an example dotenv meant to be committed.
pub(crate) fn is_env_example(file: &SourceFile) -> bool {
    let name = file.name();
    ["example", "sample", "template", "dist", "defaults"]
        .iter()
        .any(|w| name.ends_with(&format!(".{w}")))
}

/// Whether the file holds code or config.
pub(crate) fn is_code(file: &SourceFile) -> bool {
    is_env_file(file)
        || file
            .name()
            .rsplit_once('.')
            .is_some_and(|(_, ext)| CODE_EXTS.contains(&ext))
}

/// Build a finding.
pub(crate) struct Meta {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
}

impl Meta {
    /// The catalogue entry for a rule whose main finding uses this meta.
    pub(crate) const fn info(
        &self,
        summary: &'static str,
        explanation: &'static str,
    ) -> crate::rule::RuleInfo {
        crate::rule::RuleInfo {
            id: self.id,
            title: self.title,
            severity: self.severity,
            confidence: self.confidence,
            summary,
            explanation,
        }
    }

    pub(crate) fn finding(
        &self,
        file: &SourceFile,
        line: Option<u32>,
        snippet: String,
        why: String,
        fix: String,
    ) -> Finding {
        Finding {
            rule: self.id.to_owned(),
            title: self.title.to_owned(),
            severity: self.severity,
            confidence: self.confidence,
            file: file.path.clone(),
            line,
            snippet,
            why,
            fix,
        }
    }
}

/// 1-based line number for an index from `lines().enumerate()`.
pub(crate) fn line_no(index: usize) -> Option<u32> {
    u32::try_from(index + 1).ok()
}

/// Trim a snippet to something readable in a terminal.
pub(crate) fn short_line(line: &str) -> String {
    short(line)
}

/// Trim a snippet to something readable in a terminal.
pub(crate) fn short(line: &str) -> String {
    let line = line.trim();
    if line.chars().count() > 160 {
        let cut: String = line.chars().take(157).collect();
        format!("{cut}...")
    } else {
        line.to_owned()
    }
}
