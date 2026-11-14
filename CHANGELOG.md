# Changelog

All notable changes to vibeguard are written down here, for people who use it.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Project setup: the `vibeguard` command line tool and the `vibeguard-core` rule engine.
- The finding model (rule, severity, confidence, file, line, masked snippet, why, fix) and a fixture
  test harness, so every rule is tested against a bad and a good example project.
- `vibeguard scan [PATH]`: walks the project (respects `.gitignore`, skips `node_modules`, build output
  and files over 2 MB), detects Next.js, Vite, Supabase, Firebase and Stripe, and prints a readable report
  or JSON (`--format json`, `--output FILE`).
- Exit codes for CI: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` errors.
  Medium-confidence findings only fail the build with `--strict`. `--quiet` and `NO_COLOR` supported.
- Secrets are masked in every format (`sk_live_****WXYZ`).
