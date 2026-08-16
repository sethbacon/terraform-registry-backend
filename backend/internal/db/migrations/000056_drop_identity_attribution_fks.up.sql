-- 000056_drop_identity_attribution_fks
--
-- Remove every foreign key that points a registry FEATURE table at an identity
-- entity (a user or an organization). Issue #883.
--
-- THE DEFECT
--
-- Migrations 000038 and 000045 chose each constraint's target schema from
-- schema EXISTENCE:
--
--   IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'identity')
--     ... REFERENCES identity.organizations(id)
--   ELSE
--     ... REFERENCES public.organizations(id)
--
-- Schema existence is not schema authority. The `identity` schema is created by
-- TFR_IDENTITY_MIGRATIONS_ENABLED; whether the application READS AND WRITES it
-- is the separate TFR_IDENTITY_SCHEMA_ENABLED cutover. docs/identity-schema.md
-- documents running for a while in exactly the gap between them -- step 1 of
-- "Existing deployment" says to enable migrations only, copy the data, and cut
-- over later -- and any fresh install that enables migrations without the
-- cutover lands there permanently.
--
-- In that gap the schema exists and is empty of the rows that matter, so the
-- constraint resolves at `identity` while every row the application writes
-- carries a `public` id. The write is rejected:
--
--   ERROR: insert or update on table "namespace_claims" violates foreign key
--          constraint "namespace_claims_organization_id_fkey"
--   DETAIL: Key (organization_id)=(...) is not present in table "organizations".
--
-- POST /api/v1/modules 500s on every attempt. `modules_created_by_fkey` and
-- `modules_organization_id_fkey` reject the module row itself for the same
-- reason, so the failure is not confined to the one constraint that was
-- reported.
--
-- WHY DROP RATHER THAN REPOINT
--
-- Repointing at `public` is the same defect aimed the other way: it breaks the
-- deployments that DID cut over. A statically chosen target cannot be right in
-- both topologies, because the choice is made at migration time while the
-- answer is a runtime property that can be flipped back and forth by an
-- environment variable on any restart.
--
-- And there is a third topology where no choice works at all. Identity may live
-- in a SEPARATE DATABASE (TFR_IDENTITY_DATABASE_*, see docs/configuration.md).
-- PostgreSQL cannot express a foreign key across databases, so on those
-- deployments these constraints have never existed and the application has
-- always had to hold the invariant itself.
--
-- This repository reached the same conclusion twice before, and both are
-- precedent rather than coincidence:
--
--   000046_user_token_revocations -- "No FK to users: identity data may live in
--     the shared identity schema (or a separate identity database) after the
--     identity-schema cutover, while this table always lives on the registry's
--     own connection."
--   000051_platform_admins -- omitted its foreign keys on identical reasoning.
--
-- A registry table that stores an identity id stores it as an ATTRIBUTION, not
-- as a join into a table it owns. The correct end state is the one those two
-- migrations already ship: no database-level constraint, the same schema shape
-- in every topology.
--
-- WHAT WAS LOST, AND WHAT STILL HOLDS IT
--
-- On the INSERT side nothing is lost. Every one of these columns is stamped
-- from an authenticated principal that the identity store already resolved on
-- the request path; none is caller-supplied. A constraint cannot reject a value
-- the authenticator just produced -- except in the broken topology, where it
-- rejects all of them.
--
-- On the DELETE side the application already holds the two invariants that
-- mattered, and it holds them BEFORE the database is reached, with an
-- actionable status code rather than a 500:
--
--   * namespace_claims.organization_id was ON DELETE RESTRICT as a "fail-closed
--     backstop" for organization deletion. OrganizationHandlers.
--     DeleteOrganizationHandler already refuses with 409 via
--     NamespaceClaimRepository.CountByOrganization, and refuses the ambiguous
--     unclaimed-namespace case too via OwnsArtifacts.
--   * modules/providers.organization_id was ON DELETE CASCADE. The same 409
--     makes that cascade unreachable through the API: an organization owning
--     any module or provider row cannot be deleted at all.
--
-- The residual cost is recorded in the pull request for #883 rather than here,
-- because it is a property of the application and will change as the
-- application does: the ON DELETE SET NULL and restricting constraints on the
-- remaining *_by attribution columns no longer scrub or block on user deletion,
-- so a deleted user's UUID can remain in an attribution column. Those columns
-- are display-only provenance; no authorization decision reads them. The
-- separate-identity-database topology has always behaved this way.
--
-- SCOPE
--
-- Exactly the 24 constraints 000038 and 000045 created, dropped BY NAME so this
-- is correct whichever schema they currently resolve at -- including
-- deployments that followed docs/identity-schema.md's caveat and hand-edited
-- those files for a non-default TFR_IDENTITY_SCHEMA_NAME, since renaming the
-- target never renamed the constraint.
--
-- Identity's OWN tables keep their foreign keys. api_keys, audit_logs,
-- oidc_config, org_quotas, org_quota_usage, organization_members and
-- revoked_tokens reference users/organizations from within the identity set
-- itself; they move to the `identity` schema wholesale at cutover and their
-- constraints stay inside whichever schema holds them. 000038 deliberately left
-- them alone and so does this.
--
-- Idempotent, and safe on a database that never had the constraints:
-- ALTER TABLE IF EXISTS ... DROP CONSTRAINT IF EXISTS is a no-op both ways.
-- Dropping a constraint takes ACCESS EXCLUSIVE briefly but scans nothing, so
-- this is fast on any table size. No index is dropped: PostgreSQL creates no
-- index for the referencing side of a foreign key.

ALTER TABLE IF EXISTS public.download_events                DROP CONSTRAINT IF EXISTS download_events_user_id_fkey;

ALTER TABLE IF EXISTS public.mirror_approval_requests       DROP CONSTRAINT IF EXISTS mirror_approval_requests_organization_id_fkey;
ALTER TABLE IF EXISTS public.mirror_approval_requests       DROP CONSTRAINT IF EXISTS mirror_approval_requests_requested_by_fkey;
ALTER TABLE IF EXISTS public.mirror_approval_requests       DROP CONSTRAINT IF EXISTS mirror_approval_requests_reviewed_by_fkey;

ALTER TABLE IF EXISTS public.mirror_configurations          DROP CONSTRAINT IF EXISTS mirror_configurations_created_by_fkey;
ALTER TABLE IF EXISTS public.mirror_configurations          DROP CONSTRAINT IF EXISTS mirror_configurations_organization_id_fkey;

ALTER TABLE IF EXISTS public.mirror_policies                DROP CONSTRAINT IF EXISTS mirror_policies_created_by_fkey;
ALTER TABLE IF EXISTS public.mirror_policies                DROP CONSTRAINT IF EXISTS mirror_policies_organization_id_fkey;

ALTER TABLE IF EXISTS public.module_versions                DROP CONSTRAINT IF EXISTS module_versions_published_by_fkey;

ALTER TABLE IF EXISTS public.modules                        DROP CONSTRAINT IF EXISTS modules_created_by_fkey;
ALTER TABLE IF EXISTS public.modules                        DROP CONSTRAINT IF EXISTS modules_organization_id_fkey;

ALTER TABLE IF EXISTS public.namespace_claims               DROP CONSTRAINT IF EXISTS namespace_claims_claimed_by_fkey;
ALTER TABLE IF EXISTS public.namespace_claims               DROP CONSTRAINT IF EXISTS namespace_claims_organization_id_fkey;

ALTER TABLE IF EXISTS public.provider_versions              DROP CONSTRAINT IF EXISTS provider_versions_published_by_fkey;

ALTER TABLE IF EXISTS public.providers                      DROP CONSTRAINT IF EXISTS providers_created_by_fkey;
ALTER TABLE IF EXISTS public.providers                      DROP CONSTRAINT IF EXISTS providers_organization_id_fkey;

ALTER TABLE IF EXISTS public.scm_oauth_tokens               DROP CONSTRAINT IF EXISTS scm_oauth_tokens_user_id_fkey;

ALTER TABLE IF EXISTS public.scm_providers                  DROP CONSTRAINT IF EXISTS scm_providers_organization_id_fkey;

ALTER TABLE IF EXISTS public.storage_config                 DROP CONSTRAINT IF EXISTS storage_config_created_by_fkey;
ALTER TABLE IF EXISTS public.storage_config                 DROP CONSTRAINT IF EXISTS storage_config_updated_by_fkey;

ALTER TABLE IF EXISTS public.storage_migrations             DROP CONSTRAINT IF EXISTS storage_migrations_created_by_fkey;

ALTER TABLE IF EXISTS public.system_settings                DROP CONSTRAINT IF EXISTS system_settings_storage_configured_by_fkey;

ALTER TABLE IF EXISTS public.version_approval_events        DROP CONSTRAINT IF EXISTS version_approval_events_performed_by_fkey;

ALTER TABLE IF EXISTS public.version_immutability_violations DROP CONSTRAINT IF EXISTS version_immutability_violations_resolved_by_fkey;
