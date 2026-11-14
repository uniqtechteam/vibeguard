//! The result of a scan and the decision whether it should fail a build.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::{Ignored, ScanOptions, fingerprint, ignore_comment};
use crate::rule::{Rule, RuleInfo};
use crate::{Confidence, Finding, Project, Severity, Stack};

/// The engine's own check: a `vibeguard-ignore` comment without a reason or with an unknown rule.
pub const CFG_IGN: RuleInfo = RuleInfo {
    id: "CFG-IGN",
    title: "Ignore comment that does not work",
    severity: Severity::Low,
    confidence: Confidence::High,
    summary: "vibeguard-ignore comments that give no reason or name an unknown rule",
    explanation: "Every `vibeguard-ignore: RULE-ID reason` comment needs a reason, so the next person knows why the finding was accepted. A comment that names a rule vibeguard does not know silences nothing.",
};

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
    /// Findings silenced by `vibeguard-ignore` comments, with their reasons.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<Ignored>,
    /// Findings left out because they are in the baseline.
    #[serde(skip_serializing_if = "is_zero")]
    pub baselined: usize,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde passes a reference"
)]
fn is_zero(n: &usize) -> bool {
    *n == 0
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

/// Load the project at `root`, run the selected `rules`, then apply path ignores, inline ignores and
/// the baseline from `options`.
///
/// # Errors
/// When `root` cannot be read or the options are invalid.
pub fn scan_with(
    root: &Path,
    rules: &[Box<dyn Rule>],
    options: &ScanOptions,
) -> Result<Report, String> {
    let started = Instant::now();
    options.validate()?;
    let globs = options.globs()?;
    let project =
        Project::load(root).map_err(|e| format!("cannot scan {}: {e}", root.display()))?;
    let mut findings = Vec::new();
    let mut internal_errors = Vec::new();
    for rule in rules.iter().filter(|r| options.runs(r.id())) {
        match catch_unwind(AssertUnwindSafe(|| rule.check(&project))) {
            Ok(found) => findings.extend(found),
            Err(_) => internal_errors.push(format!("internal error in {}", rule.id())),
        }
    }
    findings.retain(|f| !globs.is_match(&f.file));
    let (mut findings, ignored) = apply_inline_ignores(&project, findings, &globs, options);
    let before = findings.len();
    if let Some(base) = &options.baseline {
        findings.retain(|f| !base.contains(&fingerprint(f)));
    }
    let baselined = before - findings.len();
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
        ignored,
        baselined,
    })
}

/// Move findings silenced by a `vibeguard-ignore` comment (same line or the line above) into `ignored`,
/// and report ignore comments that have no reason or name an unknown rule.
fn apply_inline_ignores(
    project: &Project,
    findings: Vec<Finding>,
    globs: &globset::GlobSet,
    options: &ScanOptions,
) -> (Vec<Finding>, Vec<Ignored>) {
    let known: Vec<&str> = crate::rule::catalogue().iter().map(|i| i.id).collect();
    let mut kept = Vec::new();
    let mut ignored = Vec::new();
    for f in findings {
        let comment = f.line.and_then(|line| {
            let text = project.file(&f.file)?.text()?;
            let lines: Vec<&str> = text.lines().collect();
            let at = usize::try_from(line).ok()?.checked_sub(1)?;
            [Some(at), at.checked_sub(1)]
                .into_iter()
                .flatten()
                .filter_map(|i| lines.get(i).and_then(|l| ignore_comment(l)))
                .find(|(ids, _)| ids.contains(&f.rule))
        });
        match comment {
            Some((_, reason)) if !reason.is_empty() => ignored.push(Ignored { finding: f, reason }),
            _ => kept.push(f),
        }
    }
    if options.runs(CFG_IGN.id) {
        for file in project.files.iter().filter(|f| !globs.is_match(&f.path)) {
            let Some(text) = file.text() else { continue };
            if !text.contains("vibeguard-ignore:") {
                continue;
            }
            for (i, line) in text.lines().enumerate() {
                let Some((ids, reason)) = ignore_comment(line) else {
                    continue;
                };
                let unknown: Vec<&String> = ids
                    .iter()
                    .filter(|id| !known.contains(&id.as_str()))
                    .collect();
                let why = if !unknown.is_empty() {
                    format!(
                        "This comment names {}, which vibeguard does not know, so it silences nothing.",
                        unknown
                            .iter()
                            .map(|u| format!("`{u}`"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                } else if reason.is_empty() {
                    "This ignore comment gives no reason, so the next person cannot tell why the finding was accepted.".to_owned()
                } else {
                    continue;
                };
                kept.push(Finding {
                    rule: CFG_IGN.id.to_owned(),
                    title: CFG_IGN.title.to_owned(),
                    severity: CFG_IGN.severity,
                    confidence: CFG_IGN.confidence,
                    file: file.path.clone(),
                    line: u32::try_from(i + 1).ok(),
                    snippet: crate::rules::short_line(line),
                    why,
                    fix: "Write it as `vibeguard-ignore: RULE-ID reason`, with a rule from `vibeguard rules` and a short reason.".to_owned(),
                });
            }
        }
    }
    (kept, ignored)
}
