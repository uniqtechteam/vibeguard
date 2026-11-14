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
- First rules:
  - **SEC-001** finds live Stripe keys, webhook secrets, AWS keys, private keys, OpenAI/Anthropic and
    GitHub tokens and Supabase service-role keys anywhere in the code, plus `.env` files with secret
    values that git does not ignore.
  - **SEC-002** finds the Supabase service-role key in code that runs in the browser (client components,
    `components/`, Vite `src/`), and leaves server routes, edge functions and `.server` files alone.
  - **SEC-003** finds secret-sounding variables with a public prefix (`NEXT_PUBLIC_`, `VITE_`,
    `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_`). Names with SECRET, PRIVATE or SERVICE_ROLE are certain;
    other `_KEY` / `TOKEN` names are reported as worth a look. Keys that are public by design (anon,
    publishable, Firebase web config) are not reported.
  - **DB-001** reads `supabase/migrations` in order and reports every table in `public` that never gets
    Row Level Security. Quoted names, `if exists`, `only`, dropped tables and comments are handled.
  - **DB-002** reports policies that let anyone, or any signed-in user, insert, update or delete every
    row (`using (true)` / `with check (true)`). Public read policies are fine and not reported.
  - **DB-003** reports upload policies on `storage.objects` that never check who is uploading, when a
    public bucket exists.
  - **PAY-001** reports Stripe webhook handlers that act on events (`checkout.session.completed`,
    `invoice.*`, …) without ever calling `stripe.webhooks.constructEvent`.
  - **PAY-002** reports `checkout.sessions.create` / `paymentIntents.create` calls whose `amount` or
    `unit_amount` comes straight from the request body. Server-side price lookups are fine.
  - **FB-001** reports Firestore and Storage rules like `allow write: if true;` or `allow read, write;`,
    the generated "test mode" rule, and `".write": true` in `database.rules.json`.
  - **API-001** reports Next.js route handlers that export POST, PUT, PATCH or DELETE (and `pages/api`
    handlers that write to the database) without any session, token or signature check. Routes covered
    by an authenticating `middleware.ts` matcher are left alone. Reported as worth a look.
  - **WEB-001** reports CORS that allows every origin (`origin: true`, `*`, or the request's own Origin)
    together with credentials.
  - **CFG-001** reports `ignoreBuildErrors`, `ignoreDuringBuilds`, `productionBrowserSourceMaps` and Vite
    `build.sourcemap` left on.
- Client tokens that are public by design (for example Paddle's `CLIENT_TOKEN`) are no longer reported by
  SEC-003.
- A test suite you can trust: end-to-end tests of the real binary (exit codes, JSON, `--output`,
  `--quiet`, no colour when piped), a demo app with every problem planted and a snapshot of its report,
  150 generated keys that must never appear unmasked, odd files (binary, invalid UTF-8, CRLF, unclosed SQL
  comments, deep folders, symlink loops) and a speed check of 5,000 files in under a second.
- CI runs the tests on Linux, macOS and Windows.
- `vibeguard rules` lists every rule; `vibeguard explain DB-001` explains one.
- `--rules` and `--skip` choose which rules run; unknown ids stop with the list of valid ones.
- `vibeguard.toml` at the project root: `fail_on`, `strict`, `skip` and `[paths] ignore` globs. Flags
  win over the file.
- Inline ignores: `vibeguard-ignore: DB-001 public lookup table` on the line or the line above. A reason
  is required; a comment without one, or naming an unknown rule, is reported as `CFG-IGN`.
  `--show-ignored` lists what was silenced and why.
- Baselines: `--write-baseline FILE` records today's findings, `--baseline FILE` then reports only new
  ones. Fingerprints ignore line numbers, so editing elsewhere in a file does not bring old findings back.
- `--format sarif` (validated against the official SARIF 2.1.0 schema, with GitHub security-severity
  levels) and `--format markdown` for pull request comments.
- GitHub Action: `uses: uniqtechteam/vibeguard@v0` downloads the right binary (checksum verified), scans,
  uploads SARIF to code scanning, writes a summary to the job page and fails on findings at or above
  `fail-on`.
- Release builds for Linux (x86_64, aarch64), macOS (Intel, Apple Silicon) and Windows, with SHA-256
  checksums. Each release installs and runs the published Action on all three systems before anything
  is published to crates.io.

