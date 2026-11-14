//! What a rule reports.

use serde::{Deserialize, Serialize};

/// How bad a finding is. Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth tidying before launch.
    Low,
    /// Should be fixed soon.
    Medium,
    /// Fix before launch.
    High,
    /// Leaks data or money today.
    Critical,
}

/// How sure the rule is. Medium-confidence findings never fail a build by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// A heuristic that can be wrong; read the code before acting.
    Medium,
    /// The pattern is unambiguous.
    High,
}

/// One problem found in one place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Rule id, for example `DB-001`.
    pub rule: String,
    /// Short title of the rule.
    pub title: String,
    /// How bad it is.
    pub severity: Severity,
    /// How sure the rule is.
    pub confidence: Confidence,
    /// Path relative to the scanned root, always with forward slashes.
    pub file: String,
    /// 1-based line, or `None` when the whole file is the problem (a tracked `.env`).
    pub line: Option<u32>,
    /// The matched text with any secret masked.
    pub snippet: String,
    /// One sentence: why this matters.
    pub why: String,
    /// One sentence: how to fix it.
    pub fix: String,
}
