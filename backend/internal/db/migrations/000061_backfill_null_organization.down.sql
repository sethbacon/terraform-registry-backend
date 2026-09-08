-- Only the constraint is reversible. The backfill is not: once a NULL has been
-- replaced with a real owner, nothing records which rows were NULL before, and
-- inventing that set on the way down would be a worse lie than the ambiguity
-- this migration removed. Dropping NOT NULL restores the ability to write a
-- NULL; it does not restore the rows that used to hold one.
ALTER TABLE providers ALTER COLUMN organization_id DROP NOT NULL;
ALTER TABLE modules   ALTER COLUMN organization_id DROP NOT NULL;
