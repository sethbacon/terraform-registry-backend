-- Per-user token-revocation watermarks (issue #559 finding [9]).
--
-- revoked_tokens (JTI denylist) can only revoke tokens whose JTI is known.
-- Privilege changes (role-template reassignment, org-membership removal,
-- role-template scope edits) must invalidate every outstanding token for the
-- affected user, whose JTIs are not tracked. Instead, a watermark is upserted
-- per user: any JWT whose iat predates the watermark is treated as revoked by
-- the auth middleware.
--
-- No FK to users: identity data may live in the shared identity schema (or a
-- separate identity database) after the identity-schema cutover, while this
-- table always lives on the registry's own connection.
CREATE TABLE IF NOT EXISTS user_token_revocations (
    user_id        UUID PRIMARY KEY,
    revoked_before TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
