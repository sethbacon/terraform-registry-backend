# Terraform Registry Backend -- Roadmap

> **Goal**: Raise all review scores to 9/10 or 10/10.
> **Out of scope**: v1.0 API stability (deferred), state management, runtime execution (plan/apply).
> **Structure**: Phases are ordered by impact. Work items within each phase are **independent** and can be worked on by separate agents in parallel unless noted otherwise.

---

## Phase 1: High-Availability & Security Hardening (Security 8→9, Enterprise 7→9)

### 1.1 Redis-Backed Rate Limiter

**Why**: The in-memory token bucket (`internal/middleware/ratelimit.go:52-222`) is the single biggest HA blocker. Each instance maintains independent state; clients bypass limits by rotating across pods. The code itself documents this at line 58-61.

**Current state**:
- `RateLimiter` struct (line 62-67) is a concrete type with no interface.
- `RateLimitMiddleware` (line 168) accepts `*RateLimiter` pointer; nil = disabled.
- Three hardcoded presets: `DefaultRateLimitConfig()` (200/min), `AuthRateLimitConfig()` (10/min), `UploadRateLimitConfig()` (30/min). Config values from `config.go` lines 255-259 (`security.rate_limiting.requests_per_minute`, `burst`) are **never wired** to these presets -- only `Enabled` is used (router.go line 470).
- `BackgroundServices` (router.go line 67-96) owns rate limiter lifecycle and calls `rl.Stop()` on shutdown.

**Work items**:

1. **Extract `RateLimiterBackend` interface** in `internal/middleware/ratelimit.go`:
   ```go
   type RateLimiterBackend interface {
       Allow(ctx context.Context, key string) (bool, error)
       RemainingTokens(ctx context.Context, key string) (int, error)
       Close() error
   }
   ```
   Refactor the existing in-memory implementation to satisfy this interface. Update `RateLimitMiddleware` to accept the interface instead of `*RateLimiter`.

2. **Implement Redis backend** in new package `internal/middleware/ratelimit_redis.go`:
   - Use `go-redis/redis_rate` with the GCRA algorithm (as recommended in the existing code comment at line 60).
   - Accept `RedisConfig` for connection details.
   - Implement `Allow()` using `redis_rate.Limiter.Allow()`.
   - Implement `Close()` to close the Redis connection.

3. **Add Redis configuration** to `internal/config/config.go`:
   - New `RedisConfig` struct under `Config`: `Host`, `Port`, `Password`, `DB`, `TLS`, `PoolSize`, `DialTimeout`.
   - Bind env vars: `TFR_REDIS_HOST`, `TFR_REDIS_PORT`, etc.
   - Add to `setDefaults()` and `Validate()`.

4. **Wire config values to rate limiter presets** in `router.go`:
   - Use `cfg.Security.RateLimiting.RequestsPerMinute` and `Burst` from config instead of hardcoded `DefaultRateLimitConfig()` when custom values are provided.
   - Fall back to presets when config values are zero/default.

5. **Factory logic** in `router.go` (around line 469): If `cfg.Redis.Host != ""`, create Redis-backed limiters; otherwise fall back to in-memory with a startup warning log.

6. **Tests**: Unit tests for both backends. Integration test with a real Redis container (use `testcontainers-go` or Docker Compose in CI).

7. **Metrics**: Add `rate_limit_rejections_total` CounterVec (labels: `tier`, `key_type`) to `internal/telemetry/metrics.go`. Increment in `RateLimitMiddleware` on 429 responses.

**Affected files**: `internal/middleware/ratelimit.go`, `internal/middleware/ratelimit_redis.go` (new), `internal/config/config.go`, `internal/api/router.go`, `internal/telemetry/metrics.go`, `config.example.yaml`, `docs/configuration.md`, `deployments/helm/values.yaml`

**Acceptance criteria**: Rate limiting works correctly across multiple pods with Redis. Falls back gracefully to in-memory when Redis is unavailable. Config values are respected. Metrics track rejections.

---

### 1.2 Redis-Backed OIDC Session Store

**Why**: The in-memory OIDC state store (`internal/api/admin/auth.go:36-95`) causes 100% OIDC login failure behind a load balancer without sticky sessions. The code documents this at lines 36-38.

**Current state**:
- `AuthHandlers.sessionStore` is `map[string]*SessionState` protected by `sync.Mutex`.
- `SessionState` (line 44-49): `State`, `CreatedAt`, `RedirectURL`, `ProviderType`.
- Created in `LoginHandler` (line 147), consumed + deleted in `CallbackHandler` (lines 229-245).
- Cleanup goroutine (lines 82-95) runs every 5 min, removes entries >10 min old.

**Work items**:

1. **Extract `StateStore` interface** in `internal/auth/statestore.go` (new file):
   ```go
   type StateStore interface {
       Save(ctx context.Context, state string, data *SessionState, ttl time.Duration) error
       Load(ctx context.Context, state string) (*SessionState, error)
       Delete(ctx context.Context, state string) error
       Close() error
   }
   ```

2. **Refactor in-memory implementation** into `internal/auth/statestore_memory.go` satisfying the interface.

3. **Implement Redis backend** in `internal/auth/statestore_redis.go`:
   - Use Redis `SET` with `EX` for TTL (auto-expiry, no cleanup goroutine needed).
   - Serialize `SessionState` as JSON.
   - `Load` uses `GET` + `DEL` atomically (Lua script or pipeline) for single-use.

4. **Wire into `AuthHandlers`**: Accept `StateStore` interface in constructor. Factory in `router.go` selects backend based on `cfg.Redis.Host`.

5. **Tests**: Unit tests with mock store. Integration test for login flow across two instances (test that callback works on a different instance than login).

**Affected files**: `internal/auth/statestore.go` (new), `internal/auth/statestore_memory.go` (new), `internal/auth/statestore_redis.go` (new), `internal/api/admin/auth.go`, `internal/api/router.go`

**Acceptance criteria**: OIDC login works without sticky sessions in multi-pod deployment. In-memory mode still works for single-instance deployments.

---

### 1.3 Per-Organization Rate Limiting

**Why**: Currently rate limiting is per-user/per-API-key/per-IP only (`ratelimit.go:201-222`). An organization with many users has uncapped aggregate throughput.

**Current state**:
- `getRateLimitKey()` checks `user_id`, then `api_key_id`, then `c.ClientIP()`. No `organization_id` path exists (despite org context being available in Gin context from auth middleware at `auth.go:157`).

**Work items**:

1. **Add `OrgRateLimitConfig`** to `config.go`: `org_requests_per_minute`, `org_burst`.

2. **Add composite rate limiting** in `ratelimit.go`: After individual key check passes, also check org-level key `org:<orgID>` with the org config. Both must pass.

3. **Propagate org ID** to rate limiter: The org ID is already set in Gin context by auth middleware. The rate limiter just needs to read it.

4. **Tests**: Verify that individual limits + org limits both apply. Verify that users without an org context (e.g., public endpoints) are unaffected.

**Affected files**: `internal/middleware/ratelimit.go`, `internal/config/config.go`, `config.example.yaml`

**Depends on**: 1.1 (should use the same `RateLimiterBackend` interface).

---

### 1.4 Secrets Rotation Support

**Why**: JWT secret and encryption key are loaded once via `sync.Once` (`internal/auth/jwt.go:59`) with no hot-reload. Rotating requires a full restart, and changing `ENCRYPTION_KEY` makes all previously encrypted SCM tokens unreadable.

**Work items**:

1. **Dual-key decryption for `TokenCipher`** (`internal/crypto/tokencipher.go`):
   - Accept `ENCRYPTION_KEY` (current) and `ENCRYPTION_KEY_PREVIOUS` (optional).
   - Encrypt always uses the current key.
   - Decrypt tries current key first; on GCM auth failure, tries previous key.
   - This allows zero-downtime rotation: set new key as current, old key as previous, restart pods, then re-encrypt all tokens in a background job.

2. **JWT secret reload via file-watch** (`internal/auth/jwt.go`):
   - Add `TFR_JWT_SECRET_FILE` config option (alternative to env var).
   - Use `fsnotify` to watch the file for changes.
   - On change, atomically swap the signing key (use `atomic.Pointer[[]byte]`).
   - New tokens use the new key; validation tries both keys (current and previous) for a configurable overlap period.

3. **Documentation**: Add `docs/secrets-rotation.md` with step-by-step rotation procedures for JWT secret, encryption key, and OIDC client secrets.

4. **Helm integration**: Update `deployments/helm/values.yaml` to support `ENCRYPTION_KEY_PREVIOUS` and `TFR_JWT_SECRET_FILE`.

**Affected files**: `internal/crypto/tokencipher.go`, `internal/auth/jwt.go`, `internal/config/config.go`, `config.example.yaml`, `docs/secrets-rotation.md` (new), `deployments/helm/values.yaml`, `deployments/helm/templates/secret.yaml`

---

## Phase 2: Feature Completeness (Features 8→9, Ease of Use 7→9)

### 2.1 Webhook Retry with Exponential Backoff

**Why**: Webhook processing is fire-and-forget (`internal/api/webhooks/scm_webhook.go:177-188`). Failed `ProcessTagPush` calls are logged but never retried. If the SCM is temporarily unavailable or the storage backend hiccups, module versions are silently lost.

**Current state**:
- `safego.Go()` spawns a background goroutine with 10-min timeout.
- Webhook log tracks state: `processing` → `completed` / `failed` / `skipped`.
- The `scm_webhook_events` table (migration 000001, lines 275-299) has `processed` boolean and `error` text columns but no retry tracking.
- `SCMPublisher.ProcessTagPush` (scm_publisher.go:72-140) does the actual work.

**Work items**:

1. **Database migration** (`000019_webhook_retry.up.sql`):
   ```sql
   ALTER TABLE scm_webhook_events
     ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0,
     ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 3,
     ADD COLUMN next_retry_at TIMESTAMP WITH TIME ZONE,
     ADD COLUMN last_error TEXT;
   CREATE INDEX idx_webhook_events_retry
     ON scm_webhook_events(next_retry_at)
     WHERE processed = false AND retry_count < max_retries;
   ```

2. **Webhook retry job** in `internal/jobs/webhook_retry_job.go` (new file):
   - Polling loop similar to `ModuleScannerJob` pattern.
   - Query: `SELECT * FROM scm_webhook_events WHERE processed = false AND retry_count < max_retries AND next_retry_at <= NOW() ORDER BY next_retry_at LIMIT ?`.
   - For each event: re-derive connector from `module_scm_repo_id` → `scm_provider` → `BuildConnector()`, re-run `ProcessTagPush`.
   - On success: mark `processed = true`.
   - On failure: increment `retry_count`, set `next_retry_at` with exponential backoff (1min, 5min, 30min), update `last_error`.
   - Configurable: `TFR_WEBHOOKS_MAX_RETRIES` (default 3), `TFR_WEBHOOKS_RETRY_INTERVAL_MINS` (poll interval, default 2).

3. **Update `scm_webhook.go`**: On initial failure, set `next_retry_at = NOW() + 1 minute` instead of leaving in terminal failed state.

4. **Metrics**: Add `webhook_retries_total` CounterVec (labels: `outcome`: success/failure/exhausted) to `telemetry/metrics.go`.

5. **Config**: Add `WebhooksConfig` to `config.go` with `MaxRetries`, `RetryIntervalMins`.

6. **Tests**: Unit test for backoff calculation. Integration test for retry flow with a mock SCM connector that fails then succeeds.

**Affected files**: `internal/db/migrations/000019_*.sql` (new), `internal/jobs/webhook_retry_job.go` (new), `internal/api/webhooks/scm_webhook.go`, `internal/services/scm_publisher.go`, `internal/config/config.go`, `internal/telemetry/metrics.go`, `internal/api/router.go` (register job), `config.example.yaml`

---

### 2.2 Advanced Search with PostgreSQL Full-Text Search

**Why**: Current search uses `ILIKE '%query%'` across namespace, name, description (`module_repository.go:562-655`, `provider_repository.go:751+`). This has no relevance ranking, no stemming, and forces sequential scans on large registries (no GIN indexes exist).

**Work items**:

1. **Database migration** (`000020_search_indexes.up.sql`):
   ```sql
   -- Add tsvector columns for full-text search
   ALTER TABLE modules ADD COLUMN search_vector tsvector;
   ALTER TABLE providers ADD COLUMN search_vector tsvector;

   -- Populate
   UPDATE modules SET search_vector =
     setweight(to_tsvector('english', coalesce(name, '')), 'A') ||
     setweight(to_tsvector('english', coalesce(namespace, '')), 'B') ||
     setweight(to_tsvector('english', coalesce(description, '')), 'C') ||
     setweight(to_tsvector('english', coalesce(system, '')), 'B');

   UPDATE providers SET search_vector =
     setweight(to_tsvector('english', coalesce(type, '')), 'A') ||
     setweight(to_tsvector('english', coalesce(namespace, '')), 'B') ||
     setweight(to_tsvector('english', coalesce(description, '')), 'C');

   -- GIN indexes
   CREATE INDEX idx_modules_search ON modules USING GIN(search_vector);
   CREATE INDEX idx_providers_search ON providers USING GIN(search_vector);

   -- Triggers to maintain on INSERT/UPDATE
   CREATE OR REPLACE FUNCTION modules_search_vector_update() RETURNS trigger AS $$
   BEGIN
     NEW.search_vector :=
       setweight(to_tsvector('english', coalesce(NEW.name, '')), 'A') ||
       setweight(to_tsvector('english', coalesce(NEW.namespace, '')), 'B') ||
       setweight(to_tsvector('english', coalesce(NEW.description, '')), 'C') ||
       setweight(to_tsvector('english', coalesce(NEW.system, '')), 'B');
     RETURN NEW;
   END $$ LANGUAGE plpgsql;

   CREATE TRIGGER trg_modules_search BEFORE INSERT OR UPDATE ON modules
     FOR EACH ROW EXECUTE FUNCTION modules_search_vector_update();
   -- (Same pattern for providers)
   ```

2. **Update search repository methods** (`module_repository.go`, `provider_repository.go`):
   - Replace `ILIKE` with `search_vector @@ plainto_tsquery('english', $query)` for ranked results.
   - Add `ts_rank(search_vector, query)` to ORDER BY for relevance scoring.
   - Keep `ILIKE` as fallback when query is a single short token (prefix matching).

3. **Add sort parameter** to search API: `sort=relevance|name|downloads|created|updated`, `order=asc|desc`.

4. **Add namespace and system/type filters** as explicit query parameters (currently only `namespace` and `system` exist for modules; add `organization` filter).

5. **Tests**: Unit tests for search ranking (name match ranks higher than description match). Performance test with 1000+ modules.

**Affected files**: `internal/db/migrations/000020_*.sql` (new), `internal/db/repositories/module_repository.go`, `internal/db/repositories/provider_repository.go`, `internal/api/modules/search.go`, `internal/api/providers/search.go`

---

### 2.3 Security Scanning in Setup Wizard

**Why**: The setup wizard configures OIDC, storage, and admin user but does not configure security scanning. Users must manually configure scanning via environment variables after setup. Adding scanning to the wizard improves first-run experience.

**Current state**:
- Setup wizard: 5 endpoints in `internal/api/setup/handlers.go` (status, validate-token, OIDC, storage, admin, complete).
- Scanning config: `ScanningConfig` in `config.go` lines 42-68. Fields: `Enabled`, `Tool`, `BinaryPath`, `ExpectedVersion`, `Timeout`, `WorkerCount`, `ScanIntervalMins`, `VersionArgs`, `ScanArgs`, `OutputFormat`.
- Scanner factory: `scanner/scanner.go:43-67` creates scanners by tool name.
- Scanner validation: each scanner has a `Version()` method that runs `<binary> --version`.
- Setup status (`GetSetupStatus` in handlers.go) checks `oidc_configured`, `storage_configured`, `admin_configured`. No `scanning_configured` field.

**Work items**:

1. **New setup endpoint** `POST /api/v1/setup/scanning/test` in `internal/api/setup/handlers.go`:
   - Accept: `{ tool: string, binary_path: string, expected_version?: string }`.
   - Validate that the binary exists at the given path.
   - Call `scanner.NewScanner(tool, binaryPath, ...)` then `s.Version(ctx)`.
   - If `expected_version` set, compare with actual version.
   - Return `{ success: bool, detected_version: string, error?: string }`.

2. **New setup endpoint** `POST /api/v1/setup/scanning` in `internal/api/setup/handlers.go`:
   - Accept: `{ enabled: bool, tool: string, binary_path: string, expected_version: string, timeout_secs: int, worker_count: int }`.
   - Persist to `system_settings` table (key: `scanning_config`, value: JSON).
   - Update runtime config (similar to how OIDC provider is swapped at runtime).

3. **Update `GetSetupStatus`** to include `scanning_configured` field (read from `system_settings`).

4. **Register routes** in `router.go` under the setup group with `SetupTokenMiddleware`.

5. **Migration** (`000021_setup_scanning.up.sql`): Add `scanning_config` row to `system_settings` if not exists.

6. **Runtime integration**: On startup, if `system_settings.scanning_config` exists and no env-var override, use the DB-stored config for the scanner job.

7. **Tests**: E2E test for test/save endpoints. Unit test for scanner validation with mock binary.

**Affected files**: `internal/api/setup/handlers.go`, `internal/api/setup/responses.go`, `internal/api/router.go`, `internal/config/config.go`, `internal/db/migrations/000021_*.sql` (new), `cmd/server/main.go` (config merge logic)

---

### 2.4 Storage Migration Wizard

**Why**: The `StoragePage` warns "Changing storage backends may result in data loss" but provides no migration path. The `storage_backend` column on `module_versions` and `provider_platforms` tracks where each artifact lives, and the `Storage` interface (`internal/storage/storage.go:26-46`) already exposes `Upload/Download/Delete/Exists` -- all the primitives needed for migration.

**Current state**:
- `module_versions.storage_backend` (VARCHAR(50)) records backend per version.
- `provider_platforms` has similar storage tracking.
- API methods `activateStorageConfig`, `updateStorageConfig` exist in the frontend `api.ts` but are **not wired** to any UI on the StoragePage.
- The runtime only initializes one storage backend from config (`NewStorage(cfg)` based on `DefaultBackend`).

**Work items**:

1. **Database migration** (`000022_storage_migration.up.sql`):
   ```sql
   CREATE TABLE storage_migrations (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     source_config_id UUID NOT NULL REFERENCES storage_config(id),
     target_config_id UUID NOT NULL REFERENCES storage_config(id),
     status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending/running/completed/failed/cancelled
     total_artifacts INTEGER NOT NULL DEFAULT 0,
     migrated_artifacts INTEGER NOT NULL DEFAULT 0,
     failed_artifacts INTEGER NOT NULL DEFAULT 0,
     error_message TEXT,
     started_at TIMESTAMP WITH TIME ZONE,
     completed_at TIMESTAMP WITH TIME ZONE,
     created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
     created_by UUID REFERENCES users(id)
   );

   CREATE TABLE storage_migration_items (
     id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
     migration_id UUID NOT NULL REFERENCES storage_migrations(id) ON DELETE CASCADE,
     artifact_type VARCHAR(20) NOT NULL, -- 'module' or 'provider'
     artifact_id UUID NOT NULL,
     source_path VARCHAR(500) NOT NULL,
     status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending/migrated/failed/skipped
     error_message TEXT,
     migrated_at TIMESTAMP WITH TIME ZONE
   );
   CREATE INDEX idx_migration_items_status ON storage_migration_items(migration_id, status);
   ```

2. **Storage migration service** in `internal/services/storage_migration.go` (new):
   - `PlanMigration(sourceConfigID, targetConfigID)`: Query all `module_versions` and `provider_platforms` on the source backend. Return artifact count and estimated size.
   - `ExecuteMigration(migrationID)`: Background job that iterates `storage_migration_items`, for each: Download from source → Upload to target → Update `storage_backend` column → Mark migrated. Uses worker pool (configurable concurrency). Tracks progress in `storage_migrations.migrated_artifacts`.
   - `GetMigrationStatus(migrationID)`: Returns current progress.
   - `CancelMigration(migrationID)`: Sets cancellation flag, workers check before each item.
   - Both source and target `Storage` instances initialized simultaneously from their respective `storage_config` rows.

3. **API endpoints** in `internal/api/admin/storage_migration.go` (new):
   - `POST /api/v1/admin/storage/migrations/plan`: Plan a migration (returns artifact count).
   - `POST /api/v1/admin/storage/migrations`: Start a migration.
   - `GET /api/v1/admin/storage/migrations/:id`: Get migration status.
   - `POST /api/v1/admin/storage/migrations/:id/cancel`: Cancel a running migration.
   - `GET /api/v1/admin/storage/migrations`: List migrations.
   - Scope required: `admin`.

4. **Register routes** in `router.go`.

5. **Tests**: Unit tests for plan/execute/cancel. Integration test with local→local migration (different base paths).

**Affected files**: `internal/db/migrations/000022_*.sql` (new), `internal/services/storage_migration.go` (new), `internal/api/admin/storage_migration.go` (new), `internal/db/repositories/storage_migration_repository.go` (new), `internal/db/models/storage_migration.go` (new), `internal/api/router.go`

---

### 2.5 Audit Log Retention & Cleanup

**Why**: The `audit_logs` table has no cleanup mechanism (`audit_repository.go` has no `Delete` method). The table will grow unboundedly. No partitioning exists (migration 000001). The review flagged this explicitly.

**Work items**:

1. **Database migration** (`000023_audit_retention.up.sql`):
   - Add `retention_days` to `system_settings` (default 90).
   - Add partial index: `CREATE INDEX idx_audit_logs_created ON audit_logs(created_at)`.

2. **Cleanup job** in `internal/jobs/audit_cleanup_job.go` (new):
   - Similar pattern to the existing JWT revocation cleanup goroutine (`main.go:218-227`).
   - Runs daily at configurable time.
   - Deletes audit logs older than `retention_days` in batches (1000 per batch to avoid long locks).
   - Config: `TFR_AUDIT_RETENTION_DAYS` (default 90), `TFR_AUDIT_CLEANUP_BATCH_SIZE` (default 1000).

3. **Archive before delete** (optional): If audit shipper is configured (webhook/file), ship logs before deletion.

4. **API endpoint** `GET /api/v1/admin/audit-logs/export` with date range filter for bulk export before cleanup.

5. **Metrics**: Add `audit_logs_cleaned_total` counter to `telemetry/metrics.go`.

6. **Config**: Add `AuditRetentionConfig` to `config.go`.

**Affected files**: `internal/db/migrations/000023_*.sql` (new), `internal/jobs/audit_cleanup_job.go` (new), `internal/config/config.go`, `internal/telemetry/metrics.go`, `internal/api/router.go`, `config.example.yaml`

---

## Phase 3: Operational Maturity (Maturity 7→9, Enterprise 7→9)

### 3.1 Fix Helm Chart Issues

**Why**: Several concrete bugs found in the Helm chart during review.

**Work items** (each is independent):

1. **Fix readinessProbe**: `deployments/helm/templates/deployment-backend.yaml` line 79 points to `/health` but should point to `/ready`. The `/ready` endpoint (router.go line 877) checks both database AND storage, while `/health` only checks database.

2. **Create ServiceMonitor template**: `deployments/helm/values.yaml` defines `serviceMonitor.enabled` (line 233) but no `templates/servicemonitor.yaml` exists. Create the template:
   ```yaml
   {{- if .Values.serviceMonitor.enabled }}
   apiVersion: monitoring.coreos.com/v1
   kind: ServiceMonitor
   metadata:
     name: {{ include "terraform-registry.fullname" . }}
     labels: {{ include "terraform-registry.labels" . | nindent 4 }}
   spec:
     selector:
       matchLabels: {{ include "terraform-registry.selectorLabels" . | nindent 6 }}
     endpoints:
       - port: metrics
         interval: {{ .Values.serviceMonitor.interval | default "30s" }}
         path: /metrics
   {{- end }}
   ```

3. **Add scanning config to values.yaml**: The `ScanningConfig` struct in `config.go` has 10+ fields but none are exposed in the Helm chart.

4. **Add audit config to values.yaml**: The `AuditConfig` / `AuditShipperConfig` structs exist but are not parameterized in Helm.

5. **Add PrometheusRule template** for alerting: High error rate, rate limiter exhaustion, mirror sync failure, scan failure.

6. **Add topologySpreadConstraints** to the backend deployment template (currently only in the Kustomize production overlay).

**Affected files**: `deployments/helm/templates/deployment-backend.yaml`, `deployments/helm/templates/servicemonitor.yaml` (new), `deployments/helm/templates/prometheusrule.yaml` (new), `deployments/helm/values.yaml`

---

### 3.2 Disaster Recovery Documentation

**Why**: No DR runbook, no RTO/RPO guidance, no backup procedures documented. This is a key enterprise readiness gap.

**Work items**:

1. **Create `docs/disaster-recovery.md`**:
   - **Backup procedures**: PostgreSQL `pg_dump` / `pg_basebackup` with recommended schedule (daily full, hourly WAL archiving). Storage backend backup per cloud (S3 versioning, Azure soft-delete, GCS object versioning).
   - **Restore procedures**: Step-by-step for each scenario: database restore, storage restore, full-cluster recovery.
   - **RTO/RPO targets**: Document recommended targets (e.g., RPO 1hr with WAL shipping, RTO 30min with warm standby).
   - **Failover playbook**: PostgreSQL failover (streaming replication + pgBouncer), storage backend failover (cloud-native HA), application pod recovery (Kubernetes self-healing).
   - **Testing procedures**: Quarterly DR drill checklist.

2. **Create `docs/capacity-planning.md`**:
   - Database sizing: rows per module/version, audit log growth rate formula.
   - Storage sizing: average module archive size, mirror size estimation.
   - Compute: pod resource recommendations by registry size (small/medium/large).
   - Network: bandwidth estimation for mirror syncs.

3. **Kubernetes CronJob for backups** in `deployments/helm/templates/cronjob-backup.yaml`:
   - Optional `pg_dump` CronJob with S3/Azure/GCS upload.
   - Parameterized in `values.yaml` under `backup.enabled`, `backup.schedule`, `backup.destination`.

**Affected files**: `docs/disaster-recovery.md` (new), `docs/capacity-planning.md` (new), `deployments/helm/templates/cronjob-backup.yaml` (new), `deployments/helm/values.yaml`

---

### 3.3 Architecture Decision Records

**Why**: No ADR directory exists (`docs/adr/` was checked and not found). Key design decisions are undocumented -- why scope-based RBAC instead of role-based, why PostgreSQL not SQLite, why in-memory rate limiting was chosen initially, etc.

**Work items**:

1. **Create `docs/adr/` directory** with `README.md` explaining the ADR format (use Michael Nygard's template: Title, Status, Context, Decision, Consequences).

2. **Backfill key ADRs** (each is a separate file, can be written in parallel):
   - `001-scope-based-rbac.md`: Why fine-grained scopes instead of coarse roles.
   - `002-postgresql-as-primary-store.md`: Why PostgreSQL, not SQLite or embedded DB.
   - `003-storage-backend-abstraction.md`: Factory pattern, pluggable backends.
   - `004-jwt-plus-apikey-dual-auth.md`: Why both JWT and API key auth.
   - `005-fire-and-forget-webhooks.md`: Trade-offs, why retry was deferred, migration plan to retry queue.
   - `006-in-memory-rate-limiting.md`: Initial trade-off, Redis migration plan.
   - `007-setup-wizard-one-time-token.md`: Security model for first-run setup.
   - `008-module-scanning-architecture.md`: Scanner interface, SARIF support, worker pool.
   - `009-network-mirror-protocol.md`: Why implement the provider network mirror protocol.
   - `010-binary-mirror-custom-protocol.md`: Why a custom protocol for Terraform/OpenTofu binaries.

**Affected files**: `docs/adr/README.md` (new), `docs/adr/001-*.md` through `docs/adr/010-*.md` (new)

---

### 3.4 Getting Started Tutorial

**Why**: No end-to-end tutorial exists walking through deploy → publish → consume. Documentation is comprehensive but lacks a guided "happy path."

**Work items**:

1. **Create `docs/getting-started.md`**:
   - **Part 1: Deploy** (Docker Compose quickstart, 5 minutes to running).
   - **Part 2: Configure** (Navigate setup wizard, configure local storage + dev OIDC or dev mode).
   - **Part 3: Publish a module** (Upload via UI, upload via `curl`, publish from GitHub via SCM integration with a sample repo).
   - **Part 4: Consume in Terraform** (Configure `~/.terraformrc`, write a `module {}` block, run `terraform init`).
   - **Part 5: Publish a provider** (Upload via UI, verify with `terraform providers mirror`).
   - **Part 6: Set up a mirror** (Configure a provider mirror, sync, verify with `terraform init` using network mirror protocol).
   - Each section includes expected output/screenshots descriptions.

2. **Create `examples/` directory** with sample Terraform configurations:
   - `examples/module-consumer/main.tf`: Consumes a module from the local registry.
   - `examples/terraformrc-example`: Sample `.terraformrc` with `credentials` block.

**Affected files**: `docs/getting-started.md` (new), `examples/module-consumer/main.tf` (new), `examples/terraformrc-example` (new)

---

### 3.5 Observability Improvements

**Why**: Several specific gaps identified during review.

**Work items** (each is independent):

1. **Add `app_info` metric** to `telemetry/metrics.go`:
   ```go
   var AppInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
       Name: "terraform_registry_info",
       Help: "Application build information",
   }, []string{"version", "go_version", "build_date"})
   ```
   Set to 1 on startup in `main.go`.

2. **Add `mirror_sync_duration_seconds` labels**: Currently has no labels (`telemetry/metrics.go:155`). Add `mirror_id` and `mirror_type` labels.

3. **Add scanner job metrics**: `module_scan_queue_depth` gauge, `module_scan_duration_seconds` histogram.

4. **Add revoked token cleanup metric**: `jwt_revoked_tokens_cleaned_total` counter.

5. **Grafana dashboard ConfigMap**: Create `deployments/helm/templates/grafana-dashboard.yaml` with a pre-built JSON dashboard covering: request rate, error rate, p99 latency, mirror sync health, scan queue depth, rate limiter rejections, DB connection pool.

**Affected files**: `internal/telemetry/metrics.go`, `cmd/server/main.go`, `internal/jobs/module_scanner_job.go`, `deployments/helm/templates/grafana-dashboard.yaml` (new)

---

## Phase 4: Documentation Excellence (Documentation 9→10)

### 4.1 Module Deprecation UX Improvement

**Why**: Deprecation exists (repository lines 699-747, API routes at router.go:594-599) but the workflow is basic. No module-level deprecation (only version-level), no migration guidance field.

**Work items**:

1. **Database migration** (`000024_module_deprecation.up.sql`):
   ```sql
   ALTER TABLE modules
     ADD COLUMN deprecated BOOLEAN NOT NULL DEFAULT FALSE,
     ADD COLUMN deprecated_at TIMESTAMP WITH TIME ZONE,
     ADD COLUMN deprecation_message TEXT,
     ADD COLUMN successor_module_id UUID REFERENCES modules(id);
   ```

2. **Repository methods** in `module_repository.go`: `DeprecateModule(moduleID, message, successorID)`, `UndeprecateModule(moduleID)`.

3. **API endpoints**:
   - `POST /api/v1/modules/:ns/:name/:sys/deprecate` with body `{ message: string, successor?: { namespace, name, system } }`.
   - `DELETE /api/v1/modules/:ns/:name/:sys/deprecate`.

4. **Search integration**: Deprecated modules shown with lower priority in search results (sort by `deprecated ASC, relevance DESC`).

5. **Terraform protocol**: Return a deprecation warning in the module versions list response (protocol allows additional metadata).

6. **Tests**: Unit test for deprecation/undeprecation flow. E2E test for search result ordering.

**Affected files**: `internal/db/migrations/000024_*.sql` (new), `internal/db/repositories/module_repository.go`, `internal/db/models/module.go`, `internal/api/modules/deprecation.go` (new), `internal/api/router.go`

---

### 4.2 Documentation Polish

**Work items** (each is independent, can be written in parallel):

1. **Update `docs/observability.md`** with all Prometheus metrics (current list + new ones from 3.5), Grafana dashboard import instructions, alerting recommendations.

2. **Update `docs/configuration.md`** with all new config options (Redis, webhook retry, audit retention, per-org rate limiting, scanning setup, storage migration).

3. **Update `docs/deployment.md`** with Helm ServiceMonitor, Grafana dashboard, backup CronJob instructions.

4. **Update README.md** with links to Getting Started tutorial, DR runbook, ADRs.

5. **Create `docs/api-migration-guide.md`** documenting breaking changes between minor versions and migration steps.

**Affected files**: `docs/observability.md`, `docs/configuration.md`, `docs/deployment.md`, `README.md`, `docs/api-migration-guide.md` (new)

---

## Summary: Score Impact Projection

| Category                 | Before | After | Key Drivers                                                                                    |
| ------------------------ | ------ | ----- | ---------------------------------------------------------------------------------------------- |
| **Security**             | 8      | 9     | Redis rate limiter, OIDC session HA, per-org rate limiting, secrets rotation                   |
| **Ease of Use**          | 7      | 9     | Getting Started tutorial, scanning setup wizard, storage migration wizard, advanced search     |
| **Documentation**        | 9      | 10    | ADRs, DR runbook, capacity planning, Getting Started, API migration guide                      |
| **Maturity**             | 8      | 9     | Helm fixes, ServiceMonitor, Grafana dashboard, webhook retry, audit cleanup                    |
| **Feature Completeness** | 9      | 10    | Advanced search (FTS), webhook retry, module deprecation, storage migration, scanning setup    |
| **Enterprise Readiness** | 7      | 9     | Redis HA, DR runbook, secrets rotation, audit retention, backup CronJob, per-org rate limiting |

---

## Dependency Graph

```
Phase 1 (parallel):
  1.1 Redis Rate Limiter ─────┐
  1.2 Redis OIDC Sessions ────┤── share Redis config (1.1 creates RedisConfig, 1.2 reuses)
  1.3 Per-Org Rate Limiting ──┘── depends on 1.1 (interface)
  1.4 Secrets Rotation ──────── independent

Phase 2 (parallel, after Phase 1 Redis config exists):
  2.1 Webhook Retry ──────── independent
  2.2 Advanced Search ────── independent
  2.3 Scanning Setup Wizard ── independent
  2.4 Storage Migration ──── independent
  2.5 Audit Retention ────── independent

Phase 3 (parallel):
  3.1 Helm Fixes ─────────── independent
  3.2 DR Documentation ───── independent
  3.3 ADRs ───────────────── independent
  3.4 Getting Started ────── independent
  3.5 Observability ──────── independent

Phase 4 (after Phase 2-3):
  4.1 Module Deprecation UX ── depends on 2.2 (search integration)
  4.2 Documentation Polish ─── depends on all prior phases (documents new features)
```
