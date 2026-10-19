# rls-guard

[![rls-guard](https://github.com/cekuu35/rls-guard/actions/workflows/rls-guard.yml/badge.svg)](https://github.com/cekuu35/rls-guard/actions/workflows/rls-guard.yml)

Fail CI when the common Supabase/Postgres RLS regressions show up in the `public` schema — before they ship.

One SQL file, one workflow, no dependencies beyond a stock `postgres` container.

## What it catches

| Check | Finding |
| --- | --- |
| `table-without-rls` | Table in `public` with row security disabled |
| `policy-missing-with-check` | `INSERT`/`UPDATE`/`ALL` policy without explicit `WITH CHECK` (the `USING` expression is silently reused for writes) |
| `policy-wide-open` | Policy with `qual` or `with_check` = `true` (unconditional allow) |
| `view-not-security-invoker` | View in `public` running with owner rights instead of the caller's (`security_invoker = false`) |

The guard prints every finding, then raises so `psql -v ON_ERROR_STOP=1` exits non-zero and the job goes red.

## Quick start

1. Copy [`rls-guard.sql`](rls-guard.sql) into your repo.
2. Copy [`.github/workflows/rls-guard.yml`](.github/workflows/rls-guard.yml).
3. Point `DATABASE_URL` at a database where you load your schema (a `pg_dump --schema-only` of `public` is enough — no live Supabase project needed).

Or run it locally:

```bash
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres
psql "$DATABASE_URL" -f your_schema.sql
bash ci/run-guard.sh your_schema.sql pass   # must exit 0
```

## How this repo tests itself

Two CI jobs run on every push:

- **clean schema** ([`examples/schema-clean.sql`](examples/schema-clean.sql)) — the guard must exit 0.
- **bad schema** ([`examples/schema-bad.sql`](examples/schema-bad.sql)) — one deliberate violation per check; the guard must exit non-zero.

If either job flips, the guard is broken, not the schema.

## Requirements

- PostgreSQL 15+ (the `security_invoker` view option; tested on 16).
- Works against any reachable database: local Postgres, a Supabase branch, or a schema dump restored in CI.

## Going deeper

- Free 5-minute check: [Supabase RLS breaking change (Oct 30, 2026): 5-minute check to avoid 42501 errors](https://dev.to/cekuu35/supabase-rls-breaking-change-oct-30-2026-5-minute-check-to-avoid-42501-errors-50ei)
- Full review of policies, grants, CORS and secret hygiene: [RLS Audit Kit](https://cengokurtoglu.gumroad.com/l/rls-audit-kit) ($29)

## License

[MIT](LICENSE)
