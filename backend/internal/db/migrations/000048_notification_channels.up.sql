-- Notification channels: additional delivery destinations (Slack, Microsoft
-- Teams, a generic webhook, or an ad-hoc email recipient list) for the
-- module_published, approval_pending, cve_detected, and
-- scanner_update_available events, alongside the shared SMTP recipients list
-- (notifications.recipients / cve.email_recipients). The target is a
-- capability-bearing secret, so it is stored encrypted (via the shared token
-- cipher) like other admin-configured secrets in this repo. events is a JSONB
-- array (registry has no precedent for a native Postgres TEXT[] column;
-- JSONB matches the rest of this schema's convention for list-valued config).
CREATE TABLE IF NOT EXISTS notification_channels (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT NOT NULL,
    type             TEXT NOT NULL,                  -- webhook | slack | teams | email
    encrypted_target TEXT NOT NULL,                  -- encrypted destination URL or recipient list
    events           JSONB NOT NULL DEFAULT '[]',    -- subscribed events; empty = all
    enabled          BOOLEAN NOT NULL DEFAULT true,
    last_status      TEXT,                           -- sent | failed
    last_error       TEXT,
    last_sent_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_channels_name ON notification_channels (name);
