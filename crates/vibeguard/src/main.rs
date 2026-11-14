//! `vibeguard`: find the security holes AI-built apps ship with, before your users do.

mod output;

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use vibeguard_core::{FailOn, Severity};

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
    Scan(ScanArgs),
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
    /// Exit with code 1 when a finding is at least this severe.
    #[arg(long, value_enum, default_value_t = Threshold::High)]
    fail_on: Threshold,
    /// Let medium-confidence findings fail the build too.
    #[arg(long)]
    strict: bool,
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
}

#[derive(Clone, Copy, ValueEnum)]
enum Threshold {
    Critical,
    High,
    Medium,
    Low,
    Never,
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
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => scan(&args),
    }
}

fn scan(args: &ScanArgs) -> ExitCode {
    let report = match vibeguard_core::scan(&args.path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vibeguard: cannot scan {}: {e}", args.path.display());
            return ExitCode::from(2);
        }
    };
    for err in &report.internal_errors {
        eprintln!("vibeguard: {err} (the scan carried on without it)");
    }
    let to_terminal = args.output.is_none() && std::io::stdout().is_terminal();
    let color = to_terminal && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let text = match args.format {
        Format::Pretty => output::pretty(&report, color, args.quiet),
        Format::Json => output::json(&report),
    };
    let written = match &args.output {
        Some(file) => std::fs::write(file, text),
        None => std::io::stdout().lock().write_all(text.as_bytes()),
    };
    if let Err(e) = written {
        eprintln!("vibeguard: cannot write the report: {e}");
        return ExitCode::from(2);
    }
    if report.fails(args.fail_on.into(), args.strict) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
