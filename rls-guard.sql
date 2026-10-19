-- rls-guard.sql — fail CI when common RLS regressions appear in the public schema.
-- Requires: PostgreSQL 15+ (views with security_invoker). Tested on 16.
-- Usage: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f rls-guard.sql
-- Exit code 0 = clean, 3 (non-zero) = findings printed above the error.

\set ON_ERROR_STOP on

CREATE TEMP TABLE guard_findings (
    check_id text NOT NULL,
    detail   text NOT NULL
);

-- C1: tables in public with row security disabled (data readable/writable by
--     anyone the DB user grants reach — the classic Supabase leak).
INSERT INTO guard_findings
SELECT 'table-without-rls',
       format('table public.%I (owner %I)', c.relname, pg_get_userbyid(c.relowner))
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
  AND NOT c.relrowsecurity;

-- C2: UPDATE/INSERT/ALL policies without an explicit WITH CHECK. The USING
--     expression is silently reused as the write predicate (USING/WITH CHECK
--     asymmetry) — reads gate the row, writes sail through untested.
INSERT INTO guard_findings
SELECT 'policy-missing-with-check',
       format('policy %I on public.%I (cmd %s)', policyname, tablename, cmd)
FROM pg_catalog.pg_policies
WHERE schemaname = 'public'
  AND cmd IN ('INSERT', 'UPDATE', 'ALL')
  AND with_check IS NULL;

-- C3: policies that allow everything unconditionally (qual/with_check = true).
INSERT INTO guard_findings
SELECT 'policy-wide-open',
       format('policy %I on public.%I (cmd %s, qual=%s, with_check=%s)',
              policyname, tablename, cmd, COALESCE(qual, '-'), COALESCE(with_check, '-'))
FROM pg_catalog.pg_policies
WHERE schemaname = 'public'
  AND (qual = 'true' OR with_check = 'true');

-- C4: views in public that do NOT run with the caller's privileges
--     (security_invoker is absent/false → view owner's rights, RLS bypassed
--      for the caller). Stored in pg_class.reloptions as security_invoker=true.
INSERT INTO guard_findings
SELECT 'view-not-security-invoker',
       format('view public.%I', c.relname)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'v'
  AND NOT COALESCE(c.reloptions @> ARRAY['security_invoker=true'], false);

\echo ''
\echo '=== rls-guard findings ==='
SELECT check_id, detail FROM guard_findings ORDER BY check_id, detail;

DO $$
DECLARE
    n integer;
BEGIN
    SELECT count(*) INTO n FROM guard_findings;
    IF n > 0 THEN
        RAISE EXCEPTION 'rls-guard: % finding(s) require review (see table above)', n;
    END IF;
    RAISE NOTICE 'rls-guard: OK (0 findings)';
END $$;
