//! `vibeguard.toml`, scan options, inline ignores and baselines.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::Finding;

/// The optional `vibeguard.toml` at the project root.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `critical`, `high`, `medium`, `low` or `never`.
    pub fail_on: Option<String>,
    /// Let medium-confidence findings fail the build.
    #[serde(default)]
    pub strict: bool,
    /// Rule ids that never run.
    #[serde(default)]
    pub skip: Vec<String>,
    /// Path settings.
    #[serde(default)]
    pub paths: PathsConfig,
}

/// `[paths]` in `vibeguard.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsConfig {
    /// Globs of files whose findings are dropped, e.g. `examples/**`.
    #[serde(default)]
    pub ignore: Vec<String>,
}

impl Config {
    /// Read `file` if it exists.
    ///
    /// # Errors
    /// When the file exists but is not valid TOML or has unknown keys.
    pub fn load(file: &Path) -> Result<Option<Self>, String> {
        let Ok(text) = fs::read_to_string(file) else {
            return Ok(None);
        };
        toml::from_str(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", file.display()))
    }
}

/// What to run and what to leave out.
#[derive(Debug, Default, Clone)]
pub struct ScanOptions {
    /// Run only these rules (empty = all).
    pub only: Vec<String>,
    /// Never run these rules.
    pub skip: Vec<String>,
    /// Drop findings in files matching these globs.
    pub ignore_paths: Vec<String>,
    /// Drop findings whose fingerprint is in this set.
    pub baseline: Option<BTreeSet<String>>,
}

impl ScanOptions {
    /// Check rule ids and globs before scanning.
    ///
    /// # Errors
    /// An unknown rule id or an invalid glob, with the list of valid ids.
    pub fn validate(&self) -> Result<(), String> {
        let known: Vec<&str> = crate::rule::catalogue().iter().map(|i| i.id).collect();
        for id in self.only.iter().chain(&self.skip) {
            if !known.iter().any(|k| k.eq_ignore_ascii_case(id)) {
                return Err(format!(
                    "unknown rule `{id}`; valid rules: {}",
                    known.join(", ")
                ));
            }
        }
        self.globs().map(drop)
    }

    pub(crate) fn runs(&self, id: &str) -> bool {
        let listed = |list: &[String]| list.iter().any(|x| x.eq_ignore_ascii_case(id));
        (self.only.is_empty() || listed(&self.only)) && !listed(&self.skip)
    }

    pub(crate) fn globs(&self) -> Result<GlobSet, String> {
        let mut b = GlobSetBuilder::new();
        for g in &self.ignore_paths {
            b.add(Glob::new(g).map_err(|e| format!("bad path glob `{g}`: {e}"))?);
        }
        b.build().map_err(|e| e.to_string())
    }
}

/// A finding silenced by a `vibeguard-ignore` comment.
#[derive(Debug, Clone, Serialize)]
pub struct Ignored {
    /// The finding that was silenced.
    pub finding: Finding,
    /// The reason written in the comment.
    pub reason: String,
}

/// `vibeguard-ignore: DB-001, SEC-003 reason text`
static IGNORE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"vibeguard-ignore:\s*([A-Za-z]+-\d{3}(?:\s*,\s*[A-Za-z]+-\d{3})*)(.*)").ok()
});

/// An ignore comment on one line: the rule ids and the reason (empty when missing).
pub(crate) fn ignore_comment(line: &str) -> Option<(Vec<String>, String)> {
    let c = IGNORE.as_ref()?.captures(line)?;
    let ids = c
        .get(1)?
        .as_str()
        .split(',')
        .map(|s| s.trim().to_ascii_uppercase())
        .collect();
    let reason = c
        .get(2)
        .map_or("", |m| m.as_str())
        .trim()
        .trim_end_matches(|c: char| "*/}->#%".contains(c) || c.is_whitespace())
        .to_owned();
    Some((ids, reason))
}

/// A stable fingerprint: rule + file + the snippet with whitespace collapsed (not the line number,
/// so edits elsewhere in the file do not change it). FNV-1a, 64 bit, hex.
#[must_use]
pub fn fingerprint(f: &Finding) -> String {
    let snippet: Vec<&str> = f.snippet.split_whitespace().collect();
    let key = format!("{}|{}|{}", f.rule, f.file, snippet.join(" "));
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// The baseline file: findings known and accepted when it was written.
#[derive(Debug, Serialize, Deserialize)]
pub struct Baseline {
    /// Format version.
    pub version: u32,
    /// Fingerprints, sorted.
    pub fingerprints: BTreeSet<String>,
}

impl Baseline {
    /// A baseline holding every current finding.
    #[must_use]
    pub fn of(findings: &[Finding]) -> Self {
        Self {
            version: 1,
            fingerprints: findings.iter().map(fingerprint).collect(),
        }
    }

    /// Read a baseline file.
    ///
    /// # Errors
    /// When the file is missing or not a baseline.
    pub fn load(file: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("{}: not a baseline file: {e}", file.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ignore_comments_in_several_styles() {
        assert_eq!(
            ignore_comment("// vibeguard-ignore: DB-001 public lookup table"),
            Some((vec!["DB-001".to_owned()], "public lookup table".to_owned()))
        );
        assert_eq!(
            ignore_comment("-- vibeguard-ignore: db-001, SEC-003"),
            Some((
                vec!["DB-001".to_owned(), "SEC-003".to_owned()],
                String::new()
            ))
        );
        assert_eq!(
            ignore_comment("{/* vibeguard-ignore: SEC-003 demo only */}"),
            Some((vec!["SEC-003".to_owned()], "demo only".to_owned()))
        );
        assert_eq!(
            ignore_comment("<!-- vibeguard-ignore: SEC-003 docs site -->"),
            Some((vec!["SEC-003".to_owned()], "docs site".to_owned()))
        );
        assert_eq!(ignore_comment("const x = 1"), None);
    }

    #[test]
    fn fingerprint_ignores_whitespace_but_not_content() {
        let f = |snippet: &str| Finding {
            rule: "SEC-003".into(),
            title: String::new(),
            severity: crate::Severity::High,
            confidence: crate::Confidence::High,
            file: ".env".into(),
            line: Some(1),
            snippet: snippet.into(),
            why: String::new(),
            fix: String::new(),
        };
        assert_eq!(fingerprint(&f("A =  1")), fingerprint(&f("A = 1")));
        assert_ne!(fingerprint(&f("A = 1")), fingerprint(&f("A = 2")));
    }
}
