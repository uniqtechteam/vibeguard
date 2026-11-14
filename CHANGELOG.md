# Changelog

All notable changes to vibeguard are written down here, for people who use it.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Project setup: the `vibeguard` command line tool and the `vibeguard-core` rule engine.
- The finding model (rule, severity, confidence, file, line, masked snippet, why, fix) and a fixture
  test harness, so every rule is tested against a bad and a good example project.
