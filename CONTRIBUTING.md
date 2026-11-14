# Contributing

Thanks for helping. A few things make a pull request easy to merge:

- **One change per pull request**, with a short description of what and why.
- **A new rule** goes in `crates/vibeguard-core/src/rules/`, gets a `RuleInfo` (summary and explanation in
  plain words), is added to `rule::all()`, and comes with `tests/fixtures/<RULE-ID>/bad` (plus an
  `expected.json`) and `tests/fixtures/<RULE-ID>/good`. Never commit a real-looking secret: tests that need
  one build it at runtime, as in `crates/vibeguard-core/tests/secrets.rs`.
- **Messages** say what is wrong and how to fix it in one sentence each, without jargon.
- **Checks** must pass: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`. If you change the readable output on purpose, refresh the snapshot with
  `UPDATE_SNAPSHOTS=1 cargo test -p vibeguard --test cli`.
- **CHANGELOG.md**: add a line under *Unreleased* written for people who use the tool.

By contributing you agree that your work is licensed under MIT OR Apache-2.0, like the rest of the project.
