//! SARIF 2.1.0 output for GitHub code scanning.

use serde_json::{Value, json};
use vibeguard_core::{Confidence, Report, Severity, fingerprint, rule};

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// GitHub turns this number into the Critical / High / Medium / Low label on an alert.
fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
    }
}

fn precision(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
    }
}

/// The report as a SARIF 2.1.0 log.
pub fn render(report: &Report) -> String {
    let catalogue = rule::catalogue();
    let rules: Vec<Value> = catalogue
        .iter()
        .map(|i| {
            json!({
                "id": i.id,
                "name": i.title.replace(' ', ""),
                "shortDescription": { "text": i.summary },
                "fullDescription": { "text": i.explanation },
                "help": { "text": i.explanation },
                "defaultConfiguration": { "level": level(i.severity) },
                "properties": {
                    "tags": ["security"],
                    "precision": precision(i.confidence),
                    "security-severity": security_severity(i.severity),
                },
            })
        })
        .collect();
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let mut region = json!({ "startLine": f.line.unwrap_or(1) });
            if !f.snippet.is_empty() {
                region["snippet"] = json!({ "text": f.snippet });
            }
            let mut result = json!({
                "ruleId": f.rule,
                "level": level(f.severity),
                "message": { "text": format!("{} {}", f.why, f.fix) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file, "uriBaseId": "%SRCROOT%" },
                        "region": region,
                    }
                }],
                "partialFingerprints": { "vibeguard/v1": fingerprint(f) },
                "properties": { "security-severity": security_severity(f.severity) },
            });
            if let Some(index) = catalogue.iter().position(|i| i.id == f.rule) {
                result["ruleIndex"] = json!(index);
            }
            result
        })
        .collect();
    let log = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vibeguard",
                    "version": report.version,
                    "informationUri": "https://github.com/uniqtechteam/vibeguard",
                    "rules": rules,
                }
            },
            "originalUriBaseIds": { "%SRCROOT%": { "uri": "file:///" } },
            "results": results,
        }],
    });
    let mut text = serde_json::to_string_pretty(&log).unwrap_or_default();
    text.push('\n');
    text
}
