//! Report formats. Snippets arrive already masked; nothing here may print a raw secret.

use std::fmt::Write as _;

use vibeguard_core::rule::RuleInfo;
use vibeguard_core::{Confidence, Finding, Report, Severity, rule};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

fn severity_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "\x1b[1;31m",
        Severity::High => "\x1b[31m",
        Severity::Medium => "\x1b[33m",
        Severity::Low => "\x1b[36m",
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

/// Group a number with commas: 1284 → "1,284".
fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The one-line summary, e.g. `1 critical · 2 high · 0 medium · 0 low · 1,284 files in 0.41s`.
pub fn summary_line(report: &Report) -> String {
    let s = report.summary;
    format!(
        "{} critical · {} high · {} medium · {} low · {} {} in {:.2}s",
        s.critical,
        s.high,
        s.medium,
        s.low,
        thousands(report.scanned_files),
        if report.scanned_files == 1 {
            "file"
        } else {
            "files"
        },
        report.duration().as_secs_f64()
    )
}

/// Readable terminal output, grouped by severity.
pub fn pretty(report: &Report, color: bool, quiet: bool, show_ignored: bool) -> String {
    let paint = |code: &str, text: &str| {
        if color {
            format!("{code}{text}{RESET}")
        } else {
            text.to_owned()
        }
    };
    let mut out = String::new();
    if !quiet {
        if report.findings.is_empty() {
            let _ = writeln!(out, "No problems found.\n");
        }
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            let group: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|f| f.severity == sev)
                .collect();
            if group.is_empty() {
                continue;
            }
            let _ = writeln!(
                out,
                "{}",
                paint(severity_color(sev), &severity_label(sev).to_uppercase())
            );
            for f in group {
                let place = match f.line {
                    Some(l) => format!("{}:{l}", f.file),
                    None => f.file.clone(),
                };
                let unsure = if f.confidence == Confidence::Medium {
                    "  (check by hand)"
                } else {
                    ""
                };
                let _ = writeln!(out, "  {} {}{unsure}", paint(BOLD, &f.rule), f.title);
                let _ = writeln!(out, "    {}", paint(DIM, &place));
                if !f.snippet.is_empty() {
                    let _ = writeln!(out, "    > {}", f.snippet.trim());
                }
                let _ = writeln!(out, "    Why: {}", f.why);
                let _ = writeln!(out, "    Fix: {}\n", f.fix);
            }
        }
    }
    if show_ignored && !quiet && !report.ignored.is_empty() {
        let _ = writeln!(out, "{}", paint(DIM, "IGNORED"));
        for i in &report.ignored {
            let place = i.finding.line.map_or_else(
                || i.finding.file.clone(),
                |l| format!("{}:{l}", i.finding.file),
            );
            let _ = writeln!(out, "  {} {}  ({place})", i.finding.rule, i.finding.title);
            let _ = writeln!(out, "    Reason: {}\n", i.reason);
        }
    }
    let mut line = summary_line(report);
    if !report.ignored.is_empty() {
        let _ = write!(line, " · {} ignored", report.ignored.len());
    }
    if report.baselined > 0 {
        let _ = write!(line, " · {} in baseline", report.baselined);
    }
    let _ = writeln!(out, "{line}");
    out
}

/// A Markdown report for pull request comments.
pub fn markdown(report: &Report) -> String {
    let mut out = String::from("## vibeguard\n\n");
    if report.findings.is_empty() {
        out.push_str("No problems found.\n\n");
    } else {
        out.push_str("| Severity | Rule | Where | Code | Why | Fix |\n|---|---|---|---|---|---|\n");
        for f in &report.findings {
            let place = f
                .line
                .map_or_else(|| format!("`{}`", f.file), |l| format!("`{}:{l}`", f.file));
            let cell = |s: &str| s.replace('|', "\\|").replace('\n', " ");
            let _ = writeln!(
                out,
                "| {} | {} {} | {place} | {} | {} | {} |",
                severity_label(f.severity),
                f.rule,
                cell(&f.title),
                if f.snippet.is_empty() {
                    String::new()
                } else {
                    format!("`{}`", cell(&f.snippet).replace('`', "'"))
                },
                cell(&f.why),
                cell(&f.fix)
            );
        }
        out.push('\n');
    }
    let _ = writeln!(out, "{}", summary_line(report));
    out
}

/// `vibeguard rules`: one line per rule.
pub fn rule_list() -> String {
    let mut out = String::new();
    for i in rule::catalogue() {
        let _ = writeln!(
            out,
            "{:<8} {:<9} {}",
            i.id,
            severity_label(i.severity),
            i.summary
        );
    }
    out
}

/// `vibeguard explain ID`.
pub fn explain(i: &RuleInfo) -> String {
    let confidence = match i.confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium (read the code before acting)",
    };
    format!(
        "{} {}\nSeverity: {} · Confidence: {confidence}\n\n{}\n\nSilence one finding with a comment on the line or the line above:\n  vibeguard-ignore: {} <reason>\n",
        i.id,
        i.title,
        severity_label(i.severity),
        i.explanation,
        i.id
    )
}

/// The full report as pretty-printed JSON.
pub fn json(report: &Report) -> String {
    let mut text =
        serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeguard_core::mask::mask_in;
    use vibeguard_core::{Summary, mask::mask};

    // Assembled from pieces so no key-shaped string sits in the repository.
    fn secret() -> String {
        ["sk", "_live_", "51Habcdefghijklmn", "WXYZ"].concat()
    }

    fn report_with_secret() -> Report {
        Report {
            version: "test",
            stack: Vec::new(),
            scanned_files: 1284,
            duration_ms: 410,
            findings: vec![Finding {
                rule: "SEC-001".into(),
                title: "Secret committed to the repo".into(),
                severity: Severity::Critical,
                confidence: Confidence::High,
                file: "src/pay.ts".into(),
                line: Some(3),
                snippet: mask_in(&format!("const key = \"{}\"", secret()), &secret()),
                why: "Anyone with the code can charge cards on your account.".into(),
                fix: "Revoke the key, then read it from an environment variable.".into(),
            }],
            summary: Summary {
                critical: 1,
                ..Summary::default()
            },
            internal_errors: Vec::new(),
            ignored: Vec::new(),
            baselined: 0,
        }
    }

    #[test]
    fn masks_secrets_in_every_format() {
        let r = report_with_secret();
        for text in [
            pretty(&r, false, false, false),
            pretty(&r, true, false, false),
            json(&r),
            markdown(&r),
            crate::sarif::render(&r),
        ] {
            assert!(!text.contains(&secret()), "full secret leaked:\n{text}");
            assert!(
                text.contains(&mask(&secret())),
                "masked form missing:\n{text}"
            );
        }
    }

    #[test]
    fn summary_groups_thousands() {
        assert_eq!(
            summary_line(&report_with_secret()),
            "1 critical · 0 high · 0 medium · 0 low · 1,284 files in 0.41s"
        );
    }

    #[test]
    fn one_file_is_singular() {
        let mut r = report_with_secret();
        r.scanned_files = 1;
        assert!(summary_line(&r).ends_with("1 file in 0.41s"));
    }

    #[test]
    fn no_color_means_no_escape_codes() {
        assert!(!pretty(&report_with_secret(), false, false, false).contains('\x1b'));
    }
}
