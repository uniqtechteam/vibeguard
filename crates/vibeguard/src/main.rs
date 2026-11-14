//! `vibeguard`: find the security holes AI-built apps ship with, before your users do.

use clap::Parser;

/// Find the security holes AI-built apps ship with, before your users do.
#[derive(Parser)]
#[command(name = "vibeguard", version = vibeguard_core::VERSION, about)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
