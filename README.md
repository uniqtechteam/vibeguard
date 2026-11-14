# vibeguard

vibeguard looks through an app that was built quickly with AI tools and finds the problems that leak data
or money before real users arrive. It runs offline, reads your files and nothing else, and explains each
finding in one plain sentence with the fix.

**Status:** early development, not released yet. The first version targets Next.js and Vite apps on
Supabase or Firebase, with Stripe.

## What the first version checks

| Rule | What it finds |
|---|---|
| SEC-001 | Keys and secrets committed to the repo, including tracked `.env` files |
| SEC-002 | The Supabase service-role key used in code that runs in the browser |
| SEC-003 | Secret-looking variables with a client prefix such as `NEXT_PUBLIC_` |
| DB-001 | Supabase tables without Row Level Security |
| DB-002 | Row Level Security policies that let anyone write |
| DB-003 | Public storage buckets that anyone can upload to |
| FB-001 | Firestore or Storage rules open to everyone |
| API-001 | Routes that change data without checking who is asking |
| PAY-001 | Stripe webhooks that never verify the signature |
| PAY-002 | Payment amounts taken from the request instead of the server |
| WEB-001 | CORS open to every site while sending credentials |
| CFG-001 | Build settings that hide type errors or ship source maps |

## Licence

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

---

Built by [UniqTech](https://uniqtech.dev). We also review apps built with AI tools by hand when you want a
second pair of eyes.
