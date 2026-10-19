-- examples/schema-clean.sql — passes rls-guard (RLS enabled, explicit WITH CHECK,
-- no unconditional policies, security_invoker view).

CREATE TABLE public.projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id uuid NOT NULL,
    name text NOT NULL
);

ALTER TABLE public.projects ENABLE ROW LEVEL SECURITY;

CREATE POLICY projects_select_own ON public.projects
    FOR SELECT USING (owner_id = (current_setting('request.jwt.claim.sub', true))::uuid);

CREATE POLICY projects_insert_own ON public.projects
    FOR INSERT WITH CHECK (owner_id = (current_setting('request.jwt.claim.sub', true))::uuid);

CREATE POLICY projects_update_own ON public.projects
    FOR UPDATE
    USING (owner_id = (current_setting('request.jwt.claim.sub', true))::uuid)
    WITH CHECK (owner_id = (current_setting('request.jwt.claim.sub', true))::uuid);

CREATE POLICY projects_delete_own ON public.projects
    FOR DELETE USING (owner_id = (current_setting('request.jwt.claim.sub', true))::uuid);

CREATE TABLE public.settings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id uuid NOT NULL,
    prefs jsonb NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE public.settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY settings_all_own ON public.settings
    FOR ALL
    USING (owner_id = (current_setting('request.jwt.claim.sub', true))::uuid)
    WITH CHECK (owner_id = (current_setting('request.jwt.claim.sub', true))::uuid);

CREATE VIEW public.owned_projects
    WITH (security_invoker = true)
    AS SELECT id, owner_id, name FROM public.projects;
