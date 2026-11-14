//! `vibeguard`: find the security holes AI-built apps ship with, before your users do.

mod output;
mod sarif;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use vibeguard_core::{Baseline, Config, FailOn, ScanOptions, Severity, rule};

/// Find the security holes AI-built apps ship with, before your users do.
#[derive(Parser)]
#[command(name = "vibeguard", version = vibeguard_core::VERSION, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a project folder and report what would leak data or money.
    Scan(Box<ScanArgs>),
    /// List every rule with its severity.
    Rules,
    /// Explain one rule: what it finds, why it matters, how to fix it.
    Explain {
        /// Rule id, for example DB-001.
        id: String,
    },
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Folder to scan.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Pretty)]
    format: Format,
    /// Write the report to this file instead of the terminal.
    #[arg(long, short)]
    output: Option<PathBuf>,
    /// Exit with code 1 when a finding is at least this severe [default: high, or `fail_on` in vibeguard.toml].
    #[arg(long, value_enum)]
    fail_on: Option<Threshold>,
    /// Let medium-confidence findings fail the build too.
    #[arg(long)]
    strict: bool,
    /// Run only these rules (comma-separated ids).
    #[arg(long, value_delimiter = ',')]
    rules: Vec<String>,
    /// Never run these rules (comma-separated ids), on top of `skip` in vibeguard.toml.
    #[arg(long, value_delimiter = ',')]
    skip: Vec<String>,
    /// Config file [default: <PATH>/vibeguard.toml].
    #[arg(long)]
    config: Option<PathBuf>,
    /// Report only findings that are not in this baseline file.
    #[arg(long)]
    baseline: Option<PathBuf>,
    /// Write every current finding to this baseline file.
    #[arg(long)]
    write_baseline: Option<PathBuf>,
    /// Also list findings silenced by vibeguard-ignore comments, with their reasons.
    #[arg(long)]
    show_ignored: bool,
    /// Print only the summary line.
    #[arg(long, short)]
    quiet: bool,
}

/// How the report is written.
#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// Readable terminal output.
    Pretty,
    /// Machine-readable JSON.
    Json,
    /// SARIF 2.1.0, for GitHub code scanning.
    Sarif,
    /// Markdown, for pull request comments.
    Markdown,
}

#[derive(Clone, Copy, ValueEnum)]
enum Threshold {
    Critical,
    High,
    Medium,
    Low,
    Never,
}

impl Threshold {
    fn parse(s: &str) -> Option<Self> {
        <Self as ValueEnum>::from_str(s, true).ok()
    }
}

impl From<Threshold> for FailOn {
    fn from(t: Threshold) -> Self {
        match t {
            Threshold::Critical => FailOn::AtLeast(Severity::Critical),
            Threshold::High => FailOn::AtLeast(Severity::High),
            Threshold::Medium => FailOn::AtLeast(Severity::Medium),
            Threshold::Low => FailOn::AtLeast(Severity::Low),
            Threshold::Never => FailOn::Never,
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Scan(args) => scan(&args).unwrap_or_else(|e| {
            eprintln!("vibeguard: {e}");
            ExitCode::from(2)
        }),
        Command::Rules => {
            print!("{}", output::rule_list());
            ExitCode::SUCCESS
        }
        Command::Explain { id } => {
            if let Some(info) = rule::find(&id) {
                print!("{}", output::explain(info));
                ExitCode::SUCCESS
            } else {
                eprintln!("vibeguard: unknown rule `{id}`; run `vibeguard rules` to see them all");
                ExitCode::from(2)
            }
        }
    }
}

fn scan(args: &ScanArgs) -> Result<ExitCode, String> {
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| args.path.join("vibeguard.toml"));
    if args.config.is_some() && !config_path.is_file() {
        return Err(format!("config file {} not found", config_path.display()));
    }
    let config = Config::load(&config_path)?.unwrap_or_default();
    let threshold = match (args.fail_on, config.fail_on.as_deref()) {
        (Some(t), _) => t,
        (None, Some(s)) => Threshold::parse(s).ok_or_else(|| {
            format!(
                "{}: fail_on must be critical, high, medium, low or never",
                config_path.display()
            )
        })?,
        (None, None) => Threshold::High,
    };
    let baseline = match &args.baseline {
        Some(file) => Some(Baseline::load(file)?.fingerprints),
        None => None,
    };
    let options = ScanOptions {
        only: args.rules.clone(),
        skip: config.skip.iter().chain(&args.skip).cloned().collect(),
        ignore_paths: config.paths.ignore.clone(),
        baseline,
    };
    let report = vibeguard_core::scan_with(&args.path, &rule::all(), &options)?;
    for err in &report.internal_errors {
        eprintln!("vibeguard: {err} (the scan carried on without it)");
    }
    if let Some(file) = &args.write_baseline {
        let json = serde_json::to_string_pretty(&Baseline::of(&report.findings))
            .map_err(|e| e.to_string())?;
        std::fs::write(file, json + "\n")
            .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    }
    let to_terminal = args.output.is_none() && std::io::stdout().is_terminal();
    let color = to_terminal && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let text = match args.format {
        Format::Pretty => output::pretty(&report, color, args.quiet, args.show_ignored),
        Format::Json => output::json(&report),
        Format::Sarif => sarif::render(&report),
        Format::Markdown => output::markdown(&report),
    };
    match &args.output {
        Some(file) => std::fs::write(file, text),
        None => std::io::stdout().lock().write_all(text.as_bytes()),
    }
    .map_err(|e| format!("cannot write the report: {e}"))?;
    let strict = args.strict || config.strict;
    Ok(if report.fails(threshold.into(), strict) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
