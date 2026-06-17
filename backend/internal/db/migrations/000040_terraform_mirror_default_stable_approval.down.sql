-- Migration 000040 (down): Revert terraform_mirror_configs column defaults to
-- their original false values. Existing rows are not modified.

ALTER TABLE terraform_mirror_configs
    ALTER COLUMN stable_only       SET DEFAULT false,
    ALTER COLUMN requires_approval SET DEFAULT false;
