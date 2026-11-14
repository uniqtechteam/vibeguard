//! The rule engine behind the `vibeguard` command line tool.
//!
//! It reads a project from disk, runs every enabled rule over it and returns findings.
//! Nothing here touches the network.

pub mod config;
mod finding;
pub mod mask;
mod project;
mod report;
pub mod rule;
mod rules;

use std::path::Path;

pub use config::{Baseline, Config, Ignored, ScanOptions, fingerprint};
pub use finding::{Confidence, Finding, Severity};
pub use project::{MAX_FILE_BYTES, Project, SourceFile, Stack};
pub use report::{CFG_IGN, FailOn, Report, Summary, scan_with};

/// Version of the engine, shown by `vibeguard --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run every rule over the project at `root` with default options.
///
/// # Errors
/// When `root` does not exist or is not a folder.
pub fn scan(root: &Path) -> Result<Report, String> {
    scan_with(root, &rule::all(), &ScanOptions::default())
}
