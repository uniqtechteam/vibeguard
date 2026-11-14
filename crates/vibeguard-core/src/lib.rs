//! The rule engine behind the `vibeguard` command line tool.
//!
//! It reads a project from disk, runs every enabled rule over it and returns findings.
//! Nothing here touches the network.

/// Version of the engine, shown by `vibeguard --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
