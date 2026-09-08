-- Backfill NULL organization_id on providers and modules to an operator-named
-- organization, then make the column NOT NULL so the ambiguity cannot return.
--
-- WHY (registry issue #1035). A NULL organization_id had two meanings that the
-- schema could not tell apart: "shared with every organization, deliberately"
-- and "nobody ever stamped this". providers.GetProvider read it as the former
-- (`organization_id = $1 OR organization_id IS NULL`), which made such a row
-- visible to admin and mirror paths acting in ANY organization, while the list,
-- search and by-namespace-type lookups all disagreed and hid it. Modules never
-- had the permissive read, but their column was nullable too and migration
-- 000045 silently skipped NULL rows when building namespace_claims -- so a
-- NULL-org module has no namespace ownership claim at all.
--
-- The Terraform protocol is unaffected by design and by test. A provider source
-- is host/namespace/type and a module source is host/namespace/name/system:
-- neither has a slot for an organization, so protocol reads resolve through
-- GetProviderByNamespace / GetModuleByNamespace, which carry no organization in
-- their WHERE. Issue #972 installed a class guard that fails the build if a
-- protocol read is ever wired back to the org-scoped lookup. This migration
-- changes who OWNS a row, not who may read it over the protocol.
--
-- THE ORGANIZATION IS NAMED BY THE OPERATOR, NOT GUESSED. The backfill target
-- comes from TFR_BACKFILL_ORGANIZATION_ID, carried onto the migration
-- connection as the `tfr.backfill_organization_id` setting (see
-- internal/db/db.go). It is deliberately NOT the default organization: on a
-- multi-tenant deployment the default org is where untenanted rows have
-- historically accumulated, and silently adding more to it is the failure this
-- issue exists to stop.
--
-- FAILS CLOSED, TWICE:
--   1. NULL rows exist and no organization was named -> abort with instructions.
--   2. Backfilling would collide with an existing row under the target
--      organization -> abort and name the collisions. UNIQUE (organization_id,
--      namespace, type) treats NULLs as distinct in Postgres, so several NULL
--      rows may share a namespace/type today; collapsing them onto one owner is
--      a merge, and a merge is an operator decision about which row is real.

DO $$
DECLARE
    target_text  TEXT;
    target_org   UUID;
    null_providers BIGINT;
    null_modules   BIGINT;
    collisions   TEXT;
BEGIN
    SELECT count(*) INTO null_providers FROM providers WHERE organization_id IS NULL;
    SELECT count(*) INTO null_modules   FROM modules   WHERE organization_id IS NULL;

    IF null_providers = 0 AND null_modules = 0 THEN
        RAISE NOTICE 'no NULL organization_id rows; nothing to backfill';
    ELSE
        target_text := current_setting('tfr.backfill_organization_id', true);

        IF target_text IS NULL OR btrim(target_text) = '' THEN
            RAISE EXCEPTION
                'found % provider row(s) and % module row(s) with a NULL organization_id, '
                'but no backfill organization was named. Set TFR_BACKFILL_ORGANIZATION_ID '
                'to the id of the organization that should own them and start again. '
                'Choose it deliberately: it is not required to be the default organization, '
                'and these rows are exactly the ones whose owner was never recorded.',
                null_providers, null_modules;
        END IF;

        BEGIN
            target_org := btrim(target_text)::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'TFR_BACKFILL_ORGANIZATION_ID is not a UUID: %', target_text;
        END;

        IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = target_org) THEN
            RAISE EXCEPTION 'TFR_BACKFILL_ORGANIZATION_ID names organization %, which does not exist', target_org;
        END IF;

        -- Collisions, reported together rather than one per failed run.
        SELECT string_agg(detail, E'\n  ') INTO collisions FROM (
            SELECT format('provider %s/%s (%s NULL-org row(s), and the target organization %s)',
                          p.namespace, p.type, count(*),
                          CASE WHEN EXISTS (
                              SELECT 1 FROM providers o
                              WHERE o.organization_id = target_org
                                AND o.namespace = p.namespace AND o.type = p.type
                          ) THEN 'already owns one' ELSE 'owns none' END) AS detail
            FROM providers p
            WHERE p.organization_id IS NULL
            GROUP BY p.namespace, p.type
            HAVING count(*) > 1
                OR EXISTS (SELECT 1 FROM providers o
                           WHERE o.organization_id = target_org
                             AND o.namespace = p.namespace AND o.type = p.type)
            UNION ALL
            SELECT format('module %s/%s/%s (%s NULL-org row(s), and the target organization %s)',
                          m.namespace, m.name, m.system, count(*),
                          CASE WHEN EXISTS (
                              SELECT 1 FROM modules o
                              WHERE o.organization_id = target_org
                                AND o.namespace = m.namespace AND o.name = m.name AND o.system = m.system
                          ) THEN 'already owns one' ELSE 'owns none' END) AS detail
            FROM modules m
            WHERE m.organization_id IS NULL
            GROUP BY m.namespace, m.name, m.system
            HAVING count(*) > 1
                OR EXISTS (SELECT 1 FROM modules o
                           WHERE o.organization_id = target_org
                             AND o.namespace = m.namespace AND o.name = m.name AND o.system = m.system)
        ) AS c;

        IF collisions IS NOT NULL THEN
            RAISE EXCEPTION
                'backfilling to organization % would violate the (organization_id, namespace, ...) '
                'uniqueness of these artifacts:%  %  Resolve them by hand -- deciding which row is '
                'real is a merge, not something a migration may guess -- then start again.',
                target_org, E'\n  ', collisions;
        END IF;

        UPDATE providers SET organization_id = target_org, updated_at = NOW() WHERE organization_id IS NULL;
        UPDATE modules   SET organization_id = target_org, updated_at = NOW() WHERE organization_id IS NULL;
        RAISE NOTICE 'backfilled % provider row(s) and % module row(s) to organization %',
            null_providers, null_modules, target_org;
    END IF;
END $$;

ALTER TABLE providers ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE modules   ALTER COLUMN organization_id SET NOT NULL;
