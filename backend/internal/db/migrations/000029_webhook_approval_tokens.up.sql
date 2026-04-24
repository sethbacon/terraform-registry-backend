-- 000029_webhook_approval_tokens.up.sql
-- Adds single-use approval tokens for out-of-band (email/Slack link) approval
-- of mirror access requests without requiring admin login.

CREATE TABLE webhook_approval_tokens (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash          VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 hex of the random token
    approval_request_id UUID        NOT NULL REFERENCES mirror_approval_requests(id) ON DELETE CASCADE,
    created_at          TIMESTAMP   NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMP   NOT NULL,
    used_at             TIMESTAMP   NULL
);

CREATE INDEX idx_webhook_approval_tokens_approval ON webhook_approval_tokens(approval_request_id);
CREATE INDEX idx_webhook_approval_tokens_expires  ON webhook_approval_tokens(expires_at) WHERE used_at IS NULL;
