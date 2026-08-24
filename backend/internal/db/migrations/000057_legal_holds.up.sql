-- 000057_legal_holds
--
-- Create the table the audit retention sweep consults before deleting. Issue
-- #872.
--
-- WHY THIS IS A MIGRATION AND NOT EnsureTable
--
-- internal/audit/legal_hold.go created this table at startup with
-- CREATE TABLE IF NOT EXISTS, "so the feature is always available without
-- requiring a numbered migration". That is the #864 class: schema the migration
-- chain does not describe, invisible to anything that reasons about the schema
-- from the chain. #871's guard credits it to runtime DDL and logs the credit,
-- which is a tolerated gap rather than an approved design. EnsureTable is
-- deleted in the same change that adds this file.
--
-- WHERE THE COLUMNS COME FROM
--
-- Rendered by store.LegalHoldTableDDL in terraform-suite-identity, the package
-- whose sweep predicate READS them. The shape is not transcribed here by hand:
-- TestMigration000057MatchesTheLibraryDDL compares this file against that
-- function, so the reader and the table cannot drift apart. Change the library,
-- and this migration fails until it is regenerated.
--
-- WHICH DATABASE THIS LANDS IN
--
-- The app database, like every migration in this chain. audit_logs lives in the
-- identity schema, which by default is the SAME database, so the sweep's
-- NOT EXISTS reaches across schemas and resolves.
--
-- A deployment that puts identity in a SEPARATE database (TFR_IDENTITY_DATABASE_*)
-- lands this table where the sweep cannot see it. That is not left to be
-- discovered by a deletion: router.go verifies the table on the identity
-- connection at startup and refuses to run the retention job at all if it does
-- not resolve. Not sweeping is untidy; sweeping without the predicate destroys
-- the evidence the feature exists to preserve.

CREATE TABLE IF NOT EXISTS "legal_holds" (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    start_date   TIMESTAMPTZ NOT NULL,
    end_date     TIMESTAMPTZ NOT NULL,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    placed_by    UUID,
    placed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_by  UUID,
    released_at  TIMESTAMPTZ,
    CONSTRAINT legal_holds_range CHECK (end_date >= start_date)
);
CREATE INDEX IF NOT EXISTS "idx_legal_holds_active_range" ON "legal_holds" (start_date, end_date) WHERE active;
