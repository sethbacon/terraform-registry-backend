CREATE TABLE storage_migrations (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  source_config_id    UUID        NOT NULL REFERENCES storage_config(id),
  target_config_id    UUID        NOT NULL REFERENCES storage_config(id),
  status              VARCHAR(20) NOT NULL DEFAULT 'pending',
  total_artifacts     INTEGER     NOT NULL DEFAULT 0,
  migrated_artifacts  INTEGER     NOT NULL DEFAULT 0,
  failed_artifacts    INTEGER     NOT NULL DEFAULT 0,
  skipped_artifacts   INTEGER     NOT NULL DEFAULT 0,
  error_message       TEXT,
  started_at          TIMESTAMP WITH TIME ZONE,
  completed_at        TIMESTAMP WITH TIME ZONE,
  created_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  created_by          UUID        REFERENCES users(id),
  CONSTRAINT chk_migration_status CHECK (status IN ('pending','running','completed','failed','cancelled'))
);

CREATE TABLE storage_migration_items (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  migration_id  UUID        NOT NULL REFERENCES storage_migrations(id) ON DELETE CASCADE,
  artifact_type VARCHAR(20) NOT NULL,
  artifact_id   UUID        NOT NULL,
  source_path   VARCHAR(500) NOT NULL,
  status        VARCHAR(20) NOT NULL DEFAULT 'pending',
  error_message TEXT,
  migrated_at   TIMESTAMP WITH TIME ZONE,
  CONSTRAINT chk_item_type CHECK (artifact_type IN ('module','provider')),
  CONSTRAINT chk_item_status CHECK (status IN ('pending','migrating','migrated','failed','skipped'))
);

CREATE INDEX idx_migration_items_status ON storage_migration_items(migration_id, status);
CREATE INDEX idx_migrations_status ON storage_migrations(status);
