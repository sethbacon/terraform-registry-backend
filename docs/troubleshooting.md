# Troubleshooting

This guide covers common issues and their solutions. For each issue, start with the diagnostic
steps before attempting fixes.

## Diagnostic Tools

The backend ships with several utility commands in `backend/cmd/`:

```bash
cd backend

# Test database connectivity
go run cmd/check-db/main.go

# Repair dirty migration state (use after interrupted migration)
go run cmd/fix-migration/main.go

# Test API connectivity (basic health check)
go run cmd/test-api/main.go

# Generate bcrypt hash for an API key (for manual DB operations)
go run cmd/hash/main.go <api-key-value>
```

Increase log verbosity to see detailed request tracing:

```bash
export TFR_LOGGING_LEVEL=debug
go run cmd/server/main.go serve
```

---

## Database Issues

### Connection Refused

```err
failed to connect to database: dial tcp localhost:5432: connect: connection refused
```

**Causes and fixes:**

- PostgreSQL is not running: `sudo systemctl start postgresql` or `docker-compose up -d db`
- Wrong host: check `TFR_DATABASE_HOST` matches your PostgreSQL server
- Firewall blocking port 5432: check security groups / firewall rules
- PostgreSQL bound to `127.0.0.1` only: edit `postgresql.conf` to set `listen_addresses = '*'` for non-local connections (and update `pg_hba.conf`)

### Authentication Failed

```sql
pq: password authentication failed for user "registry"
```

- Wrong password: check `TFR_DATABASE_PASSWORD`
- User does not exist: `createuser -U postgres registry`
- Database does not exist: `createdb -U postgres -O registry terraform_registry`

### Migration Errors

#### Dirty State

```err
Dirty database version 5. Fix and force version.
```

This happens when a migration was partially applied (e.g., due to a crash or timeout).

```bash
# 1. Identify which migration failed
go run cmd/fix-migration/main.go

# 2. If the fix tool cannot resolve it automatically, manually reset:
psql -U registry -d terraform_registry \
  -c "UPDATE schema_migrations SET dirty = false WHERE version = 5;"

# 3. Re-run migrations
go run cmd/server/main.go migrate up
```

#### Missing Migration Files

```err
no migration files found
```

The server looks for migrations in `backend/internal/db/migrations/`. Ensure the binary
is run from the `backend/` directory or set the migration path explicitly.

#### Version Mismatch After Consolidation

If you ran the registry before Session 26 (when migrations were consolidated into a single
file), reset the migration state:

```sql
TRUNCATE schema_migrations;
INSERT INTO schema_migrations (version, dirty) VALUES (1, false);
```

Then restart the server — it will recognize the schema as current and skip re-applying.

### Slow Queries

Enable PostgreSQL query logging in `postgresql.conf`:

```conf
log_min_duration_statement = 1000   # log queries taking > 1 second
```

Then check for missing indexes. The most common slow queries are:

- `api_keys` table scan: ensure `idx_api_keys_prefix` index exists
- `modules` / `providers` search: ensure the GIN indexes on `name`, `namespace` are present

To check whether the connection pool is near-exhaustion (which causes queued requests and elevated latency), query the `db_open_connections` metric:

```promql
# Pool utilisation — alert if this exceeds ~80% of TFR_DATABASE_MAX_CONNECTIONS (default 25)
db_open_connections
```

---

## Authentication Problems

### "Missing JWT secret" at Startup

```err
FATAL: JWT secret is required in production mode
```

Set `TFR_JWT_SECRET` to a random string of at least 32 characters:

```bash
export TFR_JWT_SECRET=$(openssl rand -hex 32)
```

If you're in development and want to bypass this check:

```bash
export TFR_DEV_MODE=true
```

### Invalid API Key

```json
{"error": "Invalid or expired API key"}
```

- Verify the key starts with the configured prefix (default `tfr_`)
- Check the key has not expired (Admin → API Keys → check Expires column)
- Check the key has the required scope for the endpoint (e.g., `modules:write` for upload)
- Use `go run cmd/hash/main.go <key>` to verify the hash matches what's in the database

### OIDC Login Fails

See [OIDC Configuration](oidc_configuration.md) for provider-specific troubleshooting.

Common issues:

- **Redirect URI mismatch**: the `redirect_url` in config must exactly match the URI registered in your OIDC provider's application settings (including trailing slash)
- **Clock skew**: OIDC tokens are time-sensitive; ensure server and OIDC provider clocks are synchronized (NTP)
- **Wrong issuer URL**: `issuer_url` must match the `iss` claim in the token exactly (including or excluding trailing slash)
- **Client credentials**: verify `client_id` and `client_secret` are copied correctly from your provider

Enable debug logging (`TFR_LOGGING_LEVEL=debug`) to see the raw OIDC discovery document and token claims.

### JWT Token Expired

Browser sessions expire based on the JWT `exp` claim (default: 24 hours). The frontend
should redirect to login automatically. If it does not, clear local storage:

```javascript
// In the browser console
localStorage.clear()
location.reload()
```

---

## Storage Backend Errors

### Local Storage

```err
permission denied: /var/lib/terraform-registry/modules/...
```

The backend process user must have read/write access to `TFR_STORAGE_LOCAL_BASE_PATH`:

```bash
sudo chown -R registry:registry /var/lib/terraform-registry
sudo chmod 750 /var/lib/terraform-registry
```

### Azure Blob Storage

**Container not found:**

```err
StorageErrorCode=ContainerNotFound
```

Create the container manually before activating the Azure backend:

```bash
az storage container create \
  --name terraform-registry \
  --account-name myaccount \
  --account-key $AZURE_STORAGE_KEY
```

Or use the `EnsureContainer()` helper described in the admin storage configuration UI.

**Invalid SAS token:**

SAS tokens have a configurable TTL. If downloads fail with `AuthenticationFailed`,
increase `TFR_STORAGE_AZURE_SAS_TOKEN_EXPIRY` (default: `15m`). Large provider binaries
on slow connections may need `1h` or more.

**Account key error:**

```err
Server failed to authenticate the request
```

Verify you're using the account key (not a SAS token or connection string) for
`TFR_STORAGE_AZURE_ACCOUNT_KEY`. The key is a base64-encoded string visible in
Azure Portal → Storage Account → Access keys.

### AWS S3

**Access Denied:**

```err
AccessDenied: Access Denied
```

With `auth_method: default` on EC2/EKS, check the instance profile / IRSA role has:

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
  "Resource": ["arn:aws:s3:::your-bucket", "arn:aws:s3:::your-bucket/*"]
}
```

With `auth_method: static`, verify `TFR_STORAGE_S3_ACCESS_KEY_ID` and `TFR_STORAGE_S3_SECRET_ACCESS_KEY` are correct and the IAM user has the required permissions.

**No such bucket:**

```err
NoSuchBucket: The specified bucket does not exist
```

Create the bucket in the correct region before starting the registry. The registry does not create buckets automatically.

**Endpoint mismatch:**

For MinIO, set:

```bash
TFR_STORAGE_S3_ENDPOINT=http://minio:9000
TFR_STORAGE_S3_FORCE_PATH_STYLE=true
```

MinIO does not support virtual-hosted-style bucket addressing by default.

### Google Cloud Storage

**Permission denied:**

```err
storage: object doesn't exist
googleapi: Error 403: Caller does not have storage.objects.create
```

Ensure the service account or workload identity has `roles/storage.objectAdmin` on the bucket,
or at minimum:

- `storage.objects.create`
- `storage.objects.get`
- `storage.objects.delete`
- `storage.buckets.get`

**ADC not found:**

```err
google: could not find default credentials
```

Set `GOOGLE_APPLICATION_CREDENTIALS` to point to a service account JSON file,
or use `gcloud auth application-default login` for local development.

---

## SCM Webhook Issues

### Webhook Signature Validation Failed

```json
{"error": "invalid webhook signature"}
```

- The `webhook_secret` in the SCM provider configuration must match the secret configured in your SCM provider's webhook settings
- GitHub uses HMAC-SHA256 of the raw payload; GitLab uses a plain token comparison; Azure DevOps uses a basic auth header — each validation path is different
- Check that the payload arrives unmodified: some reverse proxies re-encode the body, invalidating the HMAC

### Webhook Not Received

Enable debug logging to see incoming webhook requests. Also check:

- The webhook URL is publicly reachable from your SCM provider's servers
- Your firewall/security group allows inbound HTTPS from the SCM provider's IP ranges
- The webhook is configured for the correct events (push and tag events are required)
- Check the SCM provider's webhook delivery log for error responses

### OAuth Token Expired

SCM OAuth tokens expire. Symptoms include:

- Repository browser shows empty results or "unauthorized" errors
- Webhook publishing stops working

Fix: In the admin UI (Admin → SCM Providers), find the provider and click **Re-authorize** to go through the OAuth flow again. The new token is encrypted and stored; existing webhooks continue working.

### Module Version Not Published After Tag Push

Check the webhook event log (Admin → SCM Providers → [provider] → Event History):

1. Was the webhook received? (event appears in log)
2. Was the tag resolved to a commit SHA? (check event details)
3. Did the clone succeed? (check for clone errors in the event)
4. Was the version already published? (duplicate version attempts are rejected)

---

## Provider Mirror Failures

### Upstream Registry Unreachable

```err
failed to discover services at https://registry.terraform.io
```

- Check outbound connectivity from the registry server to `registry.terraform.io:443`
- If behind a proxy, set `HTTPS_PROXY` environment variable
- Verify the upstream URL is correct (default: `https://registry.terraform.io`)

### GPG Verification Failed

```err
GPG signature verification failed
```

Provider binaries from the public registry are signed by HashiCorp's GPG key. If verification
fails:

- The binary may have been corrupted in transit (retry the sync)
- The signature key in the registry database may be outdated (check the `provider_versions.gpg_public_key` column)
- Upstream may have rotated signing keys — the mirror will fetch the new key on the next sync cycle

### Checksum Mismatch

```err
SHA256 checksum mismatch: expected abc123... got def456...
```

The downloaded binary does not match the `SHA256SUMS` file. This indicates either
corruption in transit or a modified binary. The sync is aborted for safety.

- Retry the sync: click **Sync Now** in Admin → Mirrors, or wait for the next scheduled sync
- If it consistently fails, check the upstream registry for issues

### Sync Never Completes

Check the sync history (Admin → Mirrors → [mirror] → Sync History) for errors. Common causes:

- Large number of provider versions to sync: initial syncs of broad filters (e.g., all HashiCorp providers) can take hours
- Rate limiting from upstream: the sync job respects upstream timeouts; if rate limited, the sync pauses and retries
- Binary download timeout: increase the download timeout if provider files are large and your connection is slow (not yet configurable via UI; requires code change)

Use metrics to confirm the sync job is active and to identify which mirror is failing:

```promql
# Rate of sync errors per mirror (non-zero means a mirror is consistently failing)
rate(mirror_sync_errors_total[1h])

# p95 sync duration — a sudden spike indicates an upstream slowdown or large sync batch
histogram_quantile(0.95, rate(mirror_sync_duration_seconds_bucket[1h]))
```

---

## Frontend Issues

### Dev Server Proxy Error

```err
[vite] http proxy error: ECONNREFUSED
```

The frontend dev server (`npm run dev`) proxies API calls to the backend at `http://localhost:8080`.
This error means the backend is not running. Start the backend first:

```bash
cd backend
go run cmd/server/main.go serve
```

### Build Fails

```err
error TS2345: Argument of type 'X' is not assignable to parameter of type 'Y'
```

TypeScript strict mode is enforced. Check:

- All required props are passed to components
- API response types in `src/types/index.ts` match the actual backend response shape
- Run `npm run lint` to see all errors before building

### Auth Redirect Loop

If the app redirects to login repeatedly after logging in:

1. Check that `TFR_SERVER_BASE_URL` is set correctly — the OIDC redirect URI must match
2. Clear browser cookies and local storage for the registry domain
3. Check browser console for CORS errors (indicates `TFR_SECURITY_CORS_ALLOWED_ORIGINS` missing your domain)

### API Documentation Page Blank

The `/api-docs` page loads ReDoc from a CDN (`cdn.jsdelivr.net`). If the page is blank:

- Check the browser console for network errors
- If CDN access is blocked by corporate network policy, the spec can be served locally by configuring `nginx` to proxy the CDN URLs
- Verify the backend is running and `/swagger.json` returns a valid JSON response

---

## Common Error Messages

| Error | Likely Cause | Fix |
| --- | --- | --- |
| `version already exists` | Duplicate module/provider version upload | Version strings are immutable; bump the version number |
| `invalid semver format` | Version string not following `X.Y.Z` | Use a valid semver: `1.0.0`, not `v1.0.0` or `1.0` |
| `file too large` | Module > 100MB or provider > 500MB | Reduce archive size; check for accidentally included build artifacts |
| `path traversal detected` | Archive contains `../` paths | Re-create the archive with relative paths only |
| `namespace not found` | Organization/namespace doesn't exist | Create the organization first via Admin → Organizations |
| `insufficient permissions` | Missing required scope | Check the API key or user's role template scopes |
| `token is expired` | JWT expired | Re-login; check server/client clock sync |
| `encryption key missing` | `ENCRYPTION_KEY` not set | Set the `ENCRYPTION_KEY` environment variable |

---

## Metrics-Based Diagnostics

When something is wrong but logs are not yet clear, the Prometheus metrics endpoint
(`http://<host>:9090/metrics` by default) provides real-time signals. The queries below
map common symptoms to specific metrics. For the full catalogue and alert rules see the
[Observability Reference](observability.md).

### 5xx Error Spike

```promql
# Request error rate across all routes (non-zero = active 5xx traffic)
sum(rate(http_requests_total{status=~"5.."}[5m])) by (path, status)

# Absolute count of 5xx responses in the last 10 minutes
sum(increase(http_requests_total{status=~"5.."}[10m])) by (path)
```

Cross-reference with `TFR_LOGGING_LEVEL=debug` output: each error response includes a
`request_id` that links the metric label to the full log line.

### High Latency

```promql
# p99 latency per route — identify which endpoint is slow
histogram_quantile(0.99, sum by (path, le) (rate(http_request_duration_seconds_bucket[5m])))

# Average latency across all routes
rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m])
```

High latency on database-heavy routes (modules, providers, admin) often indicates pool
exhaustion — check `db_open_connections` in parallel.

### Database Connection Pool Exhaustion

```promql
# Current open connections — sampled every 30 s
db_open_connections

# Utilisation percentage (substitute your TFR_DATABASE_MAX_CONNECTIONS value)
db_open_connections / 25 * 100
```

If this exceeds ~80% of your configured maximum, increase `TFR_DATABASE_MAX_CONNECTIONS`
or investigate long-running transactions holding connections open
(`SELECT * FROM pg_stat_activity WHERE state = 'active'`).

### Mirror Sync Failures

```promql
# Which mirrors are failing (mirror_id is the UUID from Admin → Mirrors)
rate(mirror_sync_errors_total[1h])

# Recent error spike (fires if > 3 failures in 30 minutes for any mirror)
increase(mirror_sync_errors_total[30m]) > 3

# Sync duration — a jump here suggests a large batch or slow upstream
histogram_quantile(0.95, rate(mirror_sync_duration_seconds_bucket[1h]))
```

### API Key Expiry Notification Stall

```promql
# Emails sent in the last 24 hours — a flat zero when keys are near expiry suggests
# SMTP is misconfigured or the notifications feature is disabled
rate(apikey_expiry_notifications_sent_total[24h])
```

If this is zero when you expect notifications, check:

- `TFR_NOTIFICATIONS_ENABLED=true` is set
- `TFR_NOTIFICATIONS_SMTP_HOST` is reachable from the server (`telnet <host> 587`)
- `TFR_NOTIFICATIONS_WARNING_DAYS` covers the keys approaching expiry
- Backend logs for `"failed to send expiry email"` lines (visible at `info` level)

### Metrics Endpoint Not Reachable

If `curl http://localhost:9090/metrics` times out or returns connection refused:

- `TFR_TELEMETRY_ENABLED` must be `true` (default)
- `TFR_TELEMETRY_METRICS_PROMETHEUS_PORT` defaults to `9090` — verify it matches your scrape config
- The metrics listener binds to `0.0.0.0` but is intentionally **not** routed through the public Nginx ingress; access it directly on the internal network or via SSH tunnel
- Check backend startup logs for `"metrics server started"` to confirm the listener came up

---

## Getting Help

If the above guidance doesn't resolve your issue:

1. Check the backend logs with `TFR_LOGGING_LEVEL=debug` for detailed error context
2. Check the [GitHub Issues](https://github.com/sethbacon/terraform-registry/issues) for similar reports
3. Open a new issue with:
   - The exact error message
   - Relevant log output (sanitize credentials)
   - Your deployment method and configuration (sanitize secrets)
   - Steps to reproduce
