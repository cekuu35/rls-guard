-- examples/schema-bad.sql — one violation per rls-guard check.
-- Loading this and running rls-guard MUST fail (ci/run-guard.sh ... fail asserts that).

-- C1 finding: table with row security disabled.
CREATE TABLE public.leaky_notes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    body text NOT NULL
);

-- C2 finding: UPDATE policy without WITH CHECK (USING reused for writes).
CREATE TABLE public.member_docs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id uuid NOT NULL,
    body text NOT NULL
);

ALTER TABLE public.member_docs ENABLE ROW LEVEL SECURITY;

CREATE POLICY member_docs_update ON public.member_docs
    FOR UPDATE USING (owner_id = (current_setting('request.jwt.claim.sub', true))::uuid);

-- C3 finding: unconditional SELECT policy.
CREATE TABLE public.shared_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    line text NOT NULL
);

ALTER TABLE public.shared_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY shared_logs_read ON public.shared_logs
    FOR SELECT USING (true);

-- C4 finding: view without security_invoker (runs with owner rights).
CREATE VIEW public.all_notes AS
    SELECT id, body FROM public.leaky_notes;
