//! The rule engine behind the `vibeguard` command line tool.
//!
//! It reads a project from disk, runs every enabled rule over it and returns findings.
//! Nothing here touches the network.

mod finding;
pub mod rule;

use std::path::Path;

pub use finding::{Confidence, Finding, Severity};

/// Version of the engine, shown by `vibeguard --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run every rule over the project at `root` and return the findings, most severe first.
#[must_use]
pub fn scan(root: &Path) -> Vec<Finding> {
    let mut findings: Vec<Finding> = rule::all().iter().flat_map(|r| r.check(root)).collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    findings
}
