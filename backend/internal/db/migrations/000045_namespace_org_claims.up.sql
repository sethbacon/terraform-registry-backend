-- 000045_namespace_org_claims.up.sql
-- Namespace-to-organization ownership claims (issue #555, CWE-639).
--
-- Module and provider namespaces were previously free-text: any authenticated
-- principal holding modules:write / providers:write could publish into,
-- overwrite, deprecate, or delete artifacts in ANY namespace. This table binds
-- each namespace to the organization that first published into it; the
-- mutation routes verify the caller's organization against this binding before
-- any write (see internal/middleware/namespace_authz.go).
--
-- One row per namespace: a namespace is a single identity shared by modules
-- and providers, so a claim covers both artifact kinds.
CREATE TABLE namespace_claims (
    namespace       VARCHAR(255) PRIMARY KEY,
    organization_id UUID         NOT NULL,
    claimed_by      UUID,
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_namespace_claims_org ON namespace_claims(organization_id);

-- Foreign keys follow the 000038 pattern: point at the identity schema when
-- the identity-schema cutover has happened, otherwise at public.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
    ALTER TABLE public.namespace_claims ADD CONSTRAINT namespace_claims_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE CASCADE;
    ALTER TABLE public.namespace_claims ADD CONSTRAINT namespace_claims_claimed_by_fkey FOREIGN KEY (claimed_by) REFERENCES identity.users(id) ON DELETE SET NULL;
  ELSE
    ALTER TABLE public.namespace_claims ADD CONSTRAINT namespace_claims_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;
    ALTER TABLE public.namespace_claims ADD CONSTRAINT namespace_claims_claimed_by_fkey FOREIGN KEY (claimed_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;

-- Backfill: every namespace that already has artifacts is claimed by the
-- organization that owns the earliest-created artifact in it. In the standard
-- single-org deployment every row belongs to the default organization, so this
-- preserves existing behavior exactly.
INSERT INTO namespace_claims (namespace, organization_id, claimed_by, created_at)
SELECT DISTINCT ON (namespace) namespace, organization_id, created_by, created_at
FROM (
    SELECT namespace, organization_id, created_by, created_at FROM modules   WHERE organization_id IS NOT NULL
    UNION ALL
    SELECT namespace, organization_id, created_by, created_at FROM providers WHERE organization_id IS NOT NULL
) existing_artifacts
ORDER BY namespace, created_at
ON CONFLICT (namespace) DO NOTHING;
