DROP INDEX IF EXISTS idx_webhook_events_retry;

ALTER TABLE scm_webhook_events
  DROP COLUMN IF EXISTS retry_count,
  DROP COLUMN IF EXISTS max_retries,
  DROP COLUMN IF EXISTS next_retry_at,
  DROP COLUMN IF EXISTS last_error;
