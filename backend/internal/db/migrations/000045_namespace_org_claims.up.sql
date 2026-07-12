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
--
-- organization_id is ON DELETE RESTRICT, not CASCADE: silently dropping a
-- claim when its organization is deleted would let resolveOwnerOrg's
-- artifact-row fallback (namespace_authz.go) re-attribute the namespace to
-- whichever organization the (unrelated, pre-existing) module/provider rows
-- happen to be tagged with -- every write handler stamps organization_id
-- from the default organization regardless of the real caller, so this is
-- reliably reachable, not a rare edge case. The application layer
-- (OrganizationHandlers.DeleteOrganizationHandler) checks for and rejects
-- this case with a clear 409 before ever reaching the database; the FK is
-- the fail-closed backstop if that check is ever bypassed or forgotten.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity') THEN
    ALTER TABLE public.namespace_claims ADD CONSTRAINT namespace_claims_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES identity.organizations(id) ON DELETE RESTRICT;
    ALTER TABLE public.namespace_claims ADD CONSTRAINT namespace_claims_claimed_by_fkey FOREIGN KEY (claimed_by) REFERENCES identity.users(id) ON DELETE SET NULL;
  ELSE
    ALTER TABLE public.namespace_claims ADD CONSTRAINT namespace_claims_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE RESTRICT;
    ALTER TABLE public.namespace_claims ADD CONSTRAINT namespace_claims_claimed_by_fkey FOREIGN KEY (claimed_by) REFERENCES public.users(id) ON DELETE SET NULL;
  END IF;
END $$;

-- Backfill: a namespace whose existing artifacts all belong to exactly one
-- organization is claimed by that organization (in the standard single-org
-- deployment this is every namespace, preserving existing behavior exactly).
-- A namespace whose artifacts already span more than one organization is left
-- UNCLAIMED rather than assigned to an arbitrary "earliest" winner: the
-- runtime authorizer already treats multi-org artifact ownership without a
-- claim as ambiguous and denies non-admin mutation (errAmbiguousOwnership) --
-- picking a winner here would have been *more* permissive than the fix's own
-- runtime behavior for the exact same condition.
WITH artifact_orgs AS (
    SELECT namespace, organization_id, created_by, created_at
    FROM modules
    WHERE organization_id IS NOT NULL
    UNION ALL
    SELECT namespace, organization_id, created_by, created_at
    FROM providers
    WHERE organization_id IS NOT NULL
),
unambiguous AS (
    SELECT namespace
    FROM artifact_orgs
    GROUP BY namespace
    HAVING COUNT(DISTINCT organization_id) = 1
)
INSERT INTO namespace_claims (namespace, organization_id, claimed_by, created_at)
SELECT DISTINCT ON (ao.namespace) ao.namespace, ao.organization_id, ao.created_by, ao.created_at
FROM artifact_orgs ao
JOIN unambiguous u ON u.namespace = ao.namespace
ORDER BY ao.namespace, ao.created_at
ON CONFLICT (namespace) DO NOTHING;
