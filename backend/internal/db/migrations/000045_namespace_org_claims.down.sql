-- 000045_namespace_org_claims.down.sql
-- Drops the namespace ownership table. Namespace-to-organization bindings are
-- lost; they are re-derived from existing artifacts if the up migration is
-- re-applied.
DROP TABLE IF EXISTS namespace_claims;
