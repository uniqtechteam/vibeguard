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
- Client tokens that are public by design (for example Paddle's `CLIENT_TOKEN`) are no longer reported by
  SEC-003.
