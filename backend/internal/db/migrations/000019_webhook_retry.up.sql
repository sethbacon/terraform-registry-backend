ALTER TABLE scm_webhook_events
  ADD COLUMN retry_count   INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN max_retries   INTEGER NOT NULL DEFAULT 3,
  ADD COLUMN next_retry_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN last_error    TEXT;

CREATE INDEX idx_webhook_events_retry
  ON scm_webhook_events(next_retry_at)
  WHERE processed = false AND next_retry_at IS NOT NULL AND retry_count < max_retries;
