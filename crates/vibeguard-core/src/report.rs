//! The result of a scan and the decision whether it should fail a build.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::rule::Rule;
use crate::{Confidence, Finding, Project, Severity, Stack};

/// Counts per severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Critical findings.
    pub critical: usize,
    /// High findings.
    pub high: usize,
    /// Medium findings.
    pub medium: usize,
    /// Low findings.
    pub low: usize,
}

/// Everything a scan produced.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Engine version.
    pub version: &'static str,
    /// Detected stack.
    pub stack: Vec<Stack>,
    /// Number of files read.
    pub scanned_files: usize,
    /// Wall time of the scan in milliseconds.
    pub duration_ms: u128,
    /// Findings, most severe first.
    pub findings: Vec<Finding>,
    /// Counts per severity.
    pub summary: Summary,
    /// Rules that crashed (the scan carried on without them).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub internal_errors: Vec<String>,
}

/// When a scan should fail the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    /// Any finding at or above this severity fails.
    AtLeast(Severity),
    /// Never fail.
    Never,
}

impl Report {
    /// The scan's wall time.
    #[must_use]
    pub fn duration(&self) -> Duration {
        Duration::from_millis(u64::try_from(self.duration_ms).unwrap_or(u64::MAX))
    }

    /// Whether the findings should fail the build. Medium-confidence findings count only when `strict`.
    #[must_use]
    pub fn fails(&self, fail_on: FailOn, strict: bool) -> bool {
        let FailOn::AtLeast(min) = fail_on else {
            return false;
        };
        self.findings
            .iter()
            .any(|f| f.severity >= min && (strict || f.confidence == Confidence::High))
    }
}

/// Load the project at `root` and run `rules` over it.
///
/// # Errors
/// When `root` cannot be read.
pub fn scan_with(root: &Path, rules: &[Box<dyn Rule>]) -> std::io::Result<Report> {
    let started = Instant::now();
    let project = Project::load(root)?;
    let mut findings = Vec::new();
    let mut internal_errors = Vec::new();
    for rule in rules {
        match catch_unwind(AssertUnwindSafe(|| rule.check(&project))) {
            Ok(found) => findings.extend(found),
            Err(_) => internal_errors.push(format!("internal error in {}", rule.id())),
        }
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule.cmp(&b.rule))
    });
    let mut summary = Summary::default();
    for f in &findings {
        match f.severity {
            Severity::Critical => summary.critical += 1,
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
        }
    }
    Ok(Report {
        version: crate::VERSION,
        stack: project.stack.iter().copied().collect(),
        scanned_files: project.files.len(),
        duration_ms: started.elapsed().as_millis(),
        findings,
        summary,
        internal_errors,
    })
}
