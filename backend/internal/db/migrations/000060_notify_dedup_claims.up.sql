-- 000060_notify_dedup_claims
--
-- Give this repository's default schema the notify_dedup_claims table the
-- shared identity store now writes unconditionally
-- (identity/store/notify_dedup_repository.go, identity migration 000008,
-- terraform-suite-identity#157).
--
-- SAME CLASS AS #864 (000058_audit_logs_actor_email), CAUGHT BEFORE IT SHIPPED
--
-- TFR_IDENTITY_SCHEMA_ENABLED is off by default, so identityDB is the plain
-- app pool and NotifyDedupRepository.ClaimDedup's unqualified
-- "notify_dedup_claims" resolves against public — created by identity
-- migration 000008 only when TFR_IDENTITY_MIGRATIONS_ENABLED is also on
-- (also off by default). Without this migration, every ScannerUpdateJob
-- notification in the default configuration would issue a doomed INSERT
-- (42P01, table does not exist), caught only by claimDedup's fail-open
-- handling — the dedup guarantee the whole feature exists to provide would
-- silently not apply to the one confirmed live consumer, in the most common
-- deployment shape, forever. schemaguard's TestDefaultConfigurationCanExecuteItsOwnSQL
-- (issue #864's guard) catches this at `go test` time rather than at a
-- runtime log line nobody is watching.
--
-- WHY THIS REMEDY
--
-- Mirrors 000058's resolution exactly: fix the DEFAULT deployment without
-- requiring an operator to flip either identity flag. Additive — a
-- deployment that later completes the identity-schema cutover reads
-- identity.notify_dedup_claims, where the table already exists (migration
-- 000008), and this one becomes inert rather than wrong. Shape matches the
-- identity migration exactly (same columns, same types, same PRIMARY KEY),
-- so the two tables cannot answer "is this key claimed" differently.

CREATE TABLE IF NOT EXISTS notify_dedup_claims (
    dedup_key   TEXT PRIMARY KEY,
    claimed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
