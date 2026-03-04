-- Add expiry notification tracking to api_keys so the background notifier can
-- avoid re-sending the same warning email after a server restart.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS expiry_notification_sent_at TIMESTAMPTZ;
