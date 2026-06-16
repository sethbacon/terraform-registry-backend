-- Migration 000040: Default new terraform_mirror_configs to stable-only and
-- requires-approval.
--
-- New binary mirrors should be safe-by-default: only stable releases are synced
-- and newly synced versions wait for approval before becoming visible. The API
-- handler already applies these defaults when the request omits the fields; this
-- migration aligns the column DEFAULT clauses so direct SQL inserts behave the
-- same way.
--
-- Only the DEFAULT for future inserts changes. Existing rows keep their current
-- stable_only / requires_approval values.

ALTER TABLE terraform_mirror_configs
    ALTER COLUMN stable_only       SET DEFAULT true,
    ALTER COLUMN requires_approval SET DEFAULT true;
