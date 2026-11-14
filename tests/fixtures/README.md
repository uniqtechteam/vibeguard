# Fixtures

One folder per rule: `tests/fixtures/<RULE-ID>/bad/` is a small project that must produce exactly the
findings listed in its `expected.json`, and `tests/fixtures/<RULE-ID>/good/` is the near miss that must
produce no finding of that rule. The harness in `crates/vibeguard-core/tests/fixtures.rs` walks every
folder, so a new rule only needs new fixtures.

`expected.json` is a list of `{ "rule": "DB-001", "file": "supabase/migrations/001_init.sql", "line": 3 }`.
Secrets in fixtures are fake.
