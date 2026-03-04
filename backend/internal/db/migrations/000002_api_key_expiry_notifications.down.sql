ALTER TABLE api_keys
    DROP COLUMN IF EXISTS expiry_notification_sent_at;
