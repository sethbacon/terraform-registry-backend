# Implementation Plan: terraform-registry-backend — OSS Feature Parity

## Context

Three features identified from competitive analysis of the open-source Terraform registry landscape (boring-registry, tapir, terrareg) that are worth adding to `C:\dev\gh\terraform-registry-backend`:

1. **Pull-through provider caching** — boring-registry differentiator. On a cache miss at a mirror endpoint, fetch metadata from upstream and serve it immediately (returning upstream binary URLs), while triggering background binary download. Eliminates the 404 that currently occurs when `terraform init` requests a provider not yet in the scheduled sync.

2. **Module security scanning** — tapir differentiator. Async scan of every uploaded module archive using a configurable, pluggable scanner (Trivy, Grype, Semgrep, or any SARIF-emitting CLI). Tool and version are operator-chosen. Stores structured vulnerability counts and raw results. Surfaced via admin API. Expected by enterprise environments.

3. **terraform-docs auto-generation** — tapir/terrareg differentiator. Extract and index module variables, outputs, and provider requirements from `.tf` files in the module archive at upload time using `hashicorp/terraform-config-inspect` (official HashiCorp Go library, no binary dep). Makes module discovery meaningful for consumers.

**Migration baseline:** Migrations 000001–000014 currently exist in the repo. This plan adds 000015, 000016, 000017.

**Key existing patterns to reuse:**

- `APIKeyExpiryNotifier` (`backend/internal/jobs/api_key_expiry_notifier.go`) — template for optional background jobs with `Enabled` + binary-availability guards in `Start()`
- `provider_version_docs` table (migration 000012) — schema template for structured doc storage
- `provider_version_shasums` + `zh:` enrichment in `backend/internal/api/mirror/platform_index.go` — already returns upstream URLs for unsynced platforms; pull-through extends this to un-synced versions
- `safego.Go()` (`backend/internal/safego/safego.go`) — panic-recovering goroutine launcher; use for all new background goroutines
- `MirrorSyncJob.syncProviderVersion` (`backend/internal/jobs/mirror_sync.go`) — the existing upstream fetch path; pull-through reuses this logic for on-demand fetches
- `validation.ExtractReadme()` — same seek-to-start → extract → parse → store pattern as terraform-docs analysis
- `mirror.NewUpstreamRegistry(url)` — existing upstream registry client; reuse in pull-through service

---

## Feature 1: Pull-Through Provider Caching

### What It Does

Today: `GET /terraform/providers/{hostname}/{namespace}/{type}/index.json` returns 404 if the provider has never been synced. `terraform init` fails until the next scheduled sync cycle (every 10 minutes by default).

After: On cache miss, if pull-through is enabled for a matching mirror config, the handler fetches the version list and all-platform shasums from upstream (fast JSON-only calls), populates the DB, and returns a valid response. Binary downloads point to upstream URLs via the existing `zh:`-only enrichment path while background binary download is triggered. On subsequent requests, locally cached binary URLs are served.

**Design note:** The `provider_version_shasums` table already stores all-platform SHA256SUMS from upstream (including platforms not yet downloaded). `PlatformIndexHandler` already uses these to return `zh:` hashes pointing to upstream URLs for unsynced platforms. Pull-through only needs to populate the metadata tier (provider/version rows + shasums) on demand. The binary download path is already handled by the existing enrichment + sync job.

### Step 1 — Database Migration 000015

**New file:** `backend/internal/db/migrations/000015_pull_through_cache.up.sql`

```sql
ALTER TABLE mirror_configurations
    ADD COLUMN IF NOT EXISTS pull_through_enabled        BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS pull_through_cache_ttl_hours INTEGER  NOT NULL DEFAULT 24;

COMMENT ON COLUMN mirror_configurations.pull_through_enabled IS
    'If true, mirror endpoints fetch from upstream on cache miss instead of returning 404';
COMMENT ON COLUMN mirror_configurations.pull_through_cache_ttl_hours IS
    'Hours before re-fetching upstream metadata for a pull-through cached provider';
```

**New file:** `backend/internal/db/migrations/000015_pull_through_cache.down.sql`

```sql
ALTER TABLE mirror_configurations
    DROP COLUMN IF EXISTS pull_through_cache_ttl_hours,
    DROP COLUMN IF EXISTS pull_through_enabled;
```

### Step 2 — Update Model and Repository

**File:** `backend/internal/db/models/mirror.go` — add two fields to `MirrorConfiguration`:

```go
PullThroughEnabled       bool `db:"pull_through_enabled"        json:"pull_through_enabled"`
PullThroughCacheTTLHours int  `db:"pull_through_cache_ttl_hours" json:"pull_through_cache_ttl_hours"`
```

**File:** `backend/internal/db/repositories/mirror_repository.go`:

1. Update `Create()` INSERT, `Update()` UPDATE, `GetByID()` SELECT, and `List()` SELECT to include the two new columns.

2. Add new method:

```go
// GetPullThroughConfigsForProvider returns enabled pull-through mirror configs whose
// namespace_filter and provider_filter match the given values. Most-specific match first.
func (r *MirrorRepository) GetPullThroughConfigsForProvider(
    ctx context.Context, orgID, namespace, providerType string,
) ([]*models.MirrorConfiguration, error) {
    const q = `
        SELECT id, name, upstream_registry_url, namespace_filter, provider_filter,
               version_filter, platform_filter, organization_id,
               pull_through_enabled, pull_through_cache_ttl_hours, sync_interval_hours
        FROM mirror_configurations
        WHERE organization_id = $1
          AND enabled = true
          AND pull_through_enabled = true
          AND (namespace_filter = '' OR namespace_filter = $2)
          AND (provider_filter  = '' OR provider_filter  = $3)
        ORDER BY
            (CASE WHEN provider_filter  != '' THEN 1 ELSE 0 END) DESC,
            (CASE WHEN namespace_filter != '' THEN 1 ELSE 0 END) DESC
    `
    var configs []*models.MirrorConfiguration
    err := r.db.SelectContext(ctx, &configs, q, orgID, namespace, providerType)
    return configs, err
}
```

**File:** `backend/internal/db/repositories/provider_repository.go` — add upsert variants (the existing `CreateProvider` / `CreateVersion` likely return errors on conflict; add `ON CONFLICT DO UPDATE` variants):

```go
// UpsertProvider creates or updates a provider row, returning the existing or new record.
func (r *ProviderRepository) UpsertProvider(ctx context.Context, orgID, namespace, providerType string) (*models.Provider, error)

// UpsertVersion creates or updates a provider version row.
func (r *ProviderRepository) UpsertVersion(ctx context.Context, providerID, version string, protocols []string, shasumURL, shasumSigURL, gpgKey string) (*models.ProviderVersion, error)
```

### Step 3 — Pull-Through Service

**New file:** `backend/internal/services/pull_through.go`

```go
package services

// PullThroughService fetches provider metadata from an upstream registry on demand,
// populating provider_versions and provider_version_shasums so that mirror endpoints
// can serve valid responses on cache miss.
type PullThroughService struct {
    providerRepo *repositories.ProviderRepository
    mirrorRepo   *repositories.MirrorRepository
    orgRepo      *repositories.OrganizationRepository
}

func NewPullThroughService(
    providerRepo *repositories.ProviderRepository,
    mirrorRepo   *repositories.MirrorRepository,
    orgRepo      *repositories.OrganizationRepository,
) *PullThroughService

// FetchProviderMetadata fetches version list + shasums from upstream for the given provider,
// populates the local DB, and returns the versions now available. Does NOT download binaries.
// Binary URLs are served via the existing zh: hash enrichment in PlatformIndexHandler.
func (s *PullThroughService) FetchProviderMetadata(
    ctx context.Context,
    mirrorCfg *models.MirrorConfiguration,
    orgID, namespace, providerType string,
) ([]string, error) {
    client := mirror.NewUpstreamRegistry(mirrorCfg.UpstreamRegistryURL)
    if err := client.DiscoverServices(ctx); err != nil {
        return nil, fmt.Errorf("upstream service discovery: %w", err)
    }

    versions, err := client.ListProviderVersions(ctx, namespace, providerType)
    if err != nil {
        return nil, fmt.Errorf("upstream version list: %w", err)
    }

    // Apply the mirror config's version filter (reuse filterVersions from mirror_sync.go)
    filtered := filterVersions(versions, mirrorCfg.VersionFilter)

    provider, err := s.providerRepo.UpsertProvider(ctx, orgID, namespace, providerType)
    if err != nil {
        return nil, fmt.Errorf("upsert provider: %w", err)
    }

    var available []string
    for _, v := range filtered {
        pv, err := s.providerRepo.UpsertVersion(ctx, provider.ID, v.Version,
            v.Protocols, v.ShasumURL, v.ShasumSignatureURL, v.GPGPublicKey)
        if err != nil {
            slog.Warn("pull-through: failed to upsert version",
                "version", v.Version, "error", err)
            continue
        }

        // Fetch and store all-platform shasums. This is what allows zh: hashes to be
        // served for platforms not yet downloaded — the existing PlatformIndexHandler
        // enrichment code reads from provider_version_shasums.
        if err := s.fetchAndStoreShasums(ctx, client, pv.ID, v); err != nil {
            slog.Warn("pull-through: failed to store shasums",
                "version", v.Version, "error", err)
        }
        available = append(available, v.Version)
    }

    slog.Info("pull-through: metadata populated",
        "namespace", namespace, "type", providerType,
        "versions_fetched", len(available))
    return available, nil
}

// fetchAndStoreShasums downloads the upstream SHA256SUMS file and calls
// providerRepo.UpsertProviderVersionShasums — reusing the exact same path as
// the scheduled sync job in mirror_sync.go:syncProviderVersion.
func (s *PullThroughService) fetchAndStoreShasums(
    ctx context.Context,
    client *mirror.UpstreamRegistryClient,
    providerVersionID string,
    v upstream.ProviderVersion,
) error { ... }
```

**Important:** `filterVersions` currently lives in `backend/internal/jobs/mirror_sync.go` (unexported). Move it to a shared `backend/internal/mirror/filter.go` package so both the sync job and the pull-through service can use it.

### Step 4 — Update Mirror Handlers

Both handlers currently receive `(db *sql.DB, cfg *config.Config)`. Add `pullThrough *services.PullThroughService` and `mirrorRepo *repositories.MirrorRepository` to each factory signature.

**File:** `backend/internal/api/mirror/index.go` — `IndexHandler`

After `providerRepo.GetProvider(orgID, namespace, providerType)` returns not-found, add:

```go
// Cache miss — check for pull-through configuration
configs, err := mirrorRepo.GetPullThroughConfigsForProvider(c.Request.Context(), org.ID, namespace, providerType)
if err != nil || len(configs) == 0 {
    c.Data(http.StatusNotFound, "application/json", []byte(`{"errors":["provider not found"]}`))
    return
}

versions, err := pullThrough.FetchProviderMetadata(c.Request.Context(), configs[0], org.ID, namespace, providerType)
if err != nil {
    slog.Error("pull-through fetch failed", "namespace", namespace, "type", providerType, "error", err)
    c.Data(http.StatusBadGateway, "application/json", []byte(`{"errors":["upstream fetch failed"]}`))
    return
}

// Build version map and serve — same format as the existing success path
versionMap := make(map[string]struct{}, len(versions))
for _, v := range versions { versionMap[v] = struct{}{} }
// ... serialize to MirrorVersionIndexResponse and return via c.Data (not c.JSON, to avoid charset suffix)
```

**File:** `backend/internal/api/mirror/platform_index.go` — `PlatformIndexHandler`

After `providerRepo.GetVersion(providerID, version)` returns not-found, add:

```go
// Version not in local DB — attempt pull-through
configs, err := mirrorRepo.GetPullThroughConfigsForProvider(c.Request.Context(), org.ID, namespace, providerType)
if err != nil || len(configs) == 0 {
    c.Data(http.StatusNotFound, "application/json", []byte(`{"errors":["provider version not found"]}`))
    return
}
if _, err := pullThrough.FetchProviderMetadata(c.Request.Context(), configs[0], org.ID, namespace, providerType); err != nil {
    c.Data(http.StatusBadGateway, "application/json", []byte(`{"errors":["upstream fetch failed"]}`))
    return
}
// Re-query: after pull-through, version + shasums are now in DB
providerVersion, err = providerRepo.GetVersion(providerID, version)
if err != nil {
    c.Data(http.StatusNotFound, "application/json", []byte(`{"errors":["provider version not found after pull-through"]}`))
    return
}
// Fall through to existing platform listing + zh: hash enrichment (no further changes needed)
```

### Step 5 — Wire into Router

**File:** `backend/internal/api/router.go`

```go
// Construct pull-through service alongside other services (~line 109)
pullThroughSvc := services.NewPullThroughService(providerRepo, mirrorRepo, orgRepo)

// Update mirror handler registrations (~lines 345-347)
v1Mirror.GET("/:hostname/:namespace/:type/index.json",
    mirror.IndexHandler(db, cfg, pullThroughSvc, mirrorRepo))
v1Mirror.GET("/:hostname/:namespace/:type/:versionfile",
    mirror.PlatformIndexHandler(db, cfg, auditRepo, pullThroughSvc, mirrorRepo))
```

### Step 6 — Admin API Update

**File:** `backend/internal/api/admin/mirror.go`

Update `CreateMirrorConfig` (around line 50) and `UpdateMirrorConfig` (around line 130) request body structs and SQL to pass through `pull_through_enabled` and `pull_through_cache_ttl_hours`. The model update in Step 2 handles JSON serialization automatically. Add Swagger `@Param` annotations for the two new fields.

### Verification — Feature 1

```bash
# 1. Create a mirror config with pull_through_enabled=true via admin API
# 2. Request a provider that has never been synced:
curl "http://localhost:8080/terraform/providers/registry.terraform.io/hashicorp/aws/index.json"
# Expected: {"versions": {"5.0.0": {}, "5.1.0": {}}} instead of 404

# 3. Request the platform index for a specific version:
curl "http://localhost:8080/terraform/providers/registry.terraform.io/hashicorp/aws/5.0.0.json"
# Expected: {"archives": {"linux_amd64": {"url": "https://releases.hashicorp.com/...", "hashes": ["zh:..."]}}}

# 4. Wait for sync job — re-request: should see h1: hashes with local storage URLs
# 5. Test with pull_through_enabled=false: confirm 404 behavior unchanged
# 6. go test ./backend/internal/api/mirror/... -run TestPullThrough
# 7. go test ./backend/internal/services/... -run TestPullThroughService
```

---

## Feature 2: Module Security Scanning (Pluggable Scanner)

### How It Works

After any module version is created (direct upload or SCM webhook), a pending scan record is inserted. A background job polls for pending scans, downloads each module archive to a temp directory, runs the configured scanner binary, stores structured results (severity counts + raw output), and transitions the scan record to `clean` or `findings`. Results are queryable via an admin endpoint. Entire feature is disabled by default.

### Scanner Design (Pluggable Tool)

After any module version is created (direct upload or SCM webhook), a pending scan record is inserted. A background job polls for pending scans, downloads each module archive to a temp directory, runs the configured scanner binary, stores structured results (severity counts + raw output), and transitions the scan record to `clean` or `findings`. Results are queryable via an admin endpoint. Entire feature is disabled by default.

**Design rationale — pluggable tool:** The scanning tool is operator-chosen. Trivy has had supply chain incidents; Grype (Anchore), Semgrep, and others are credible alternatives. The design defines a `Scanner` interface so new backends can be added without touching job or handler code. The operator configures which tool to use (`scanning.tool: trivy|grype|semgrep|custom`) and its binary path. Optionally, an `expected_version` can be pinned so the job refuses to run if the installed binary version doesn't match — a lightweight supply chain check that catches tampered or accidentally upgraded binaries.

**Supported tools at launch:**

- `trivy` — Aqua Security Trivy (`trivy fs --format json`)
- `grype` — Anchore Grype (`grype dir: --output json`) — no known supply chain incidents; good alternative
- `semgrep` — Semgrep OSS (`semgrep --json --config auto`) — focused on IaC misconfig and secrets
- `custom` — any tool that can be invoked as `<binary> <dir>` and writes JSON to stdout; requires `output_format: sarif` or `output_format: json` with a custom jq-style field mapping

### Step 1 — Database Migration 000016

**New file:** `backend/internal/db/migrations/000016_module_version_scans.up.sql`

```sql
CREATE TABLE module_version_scans (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_version_id UUID        NOT NULL REFERENCES module_versions(id) ON DELETE CASCADE,
    scanner           VARCHAR(50) NOT NULL,   -- 'trivy', 'grype', 'semgrep', 'custom'
    scanner_version   VARCHAR(50),            -- actual binary version at scan time
    expected_version  VARCHAR(50),            -- pinned version from config (for audit)
    status            VARCHAR(20) NOT NULL DEFAULT 'pending',
    scanned_at        TIMESTAMPTZ,
    critical_count    INT         NOT NULL DEFAULT 0,
    high_count        INT         NOT NULL DEFAULT 0,
    medium_count      INT         NOT NULL DEFAULT 0,
    low_count         INT         NOT NULL DEFAULT 0,
    raw_results       JSONB,
    error_message     TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (module_version_id)
);

CREATE INDEX idx_mvs_pending ON module_version_scans(created_at)
    WHERE status = 'pending';
CREATE INDEX idx_mvs_version ON module_version_scans(module_version_id);
```

**New file:** `backend/internal/db/migrations/000016_module_version_scans.down.sql`

```sql
DROP TABLE IF EXISTS module_version_scans;
```

### Step 2 — Configuration

**File:** `backend/internal/config/config.go`

Add to top-level `Config` struct:

```go
Scanning ScanningConfig `mapstructure:"scanning"`
```

Add struct definition:

```go
type ScanningConfig struct {
    Enabled          bool          `mapstructure:"enabled"`
    Tool             string        `mapstructure:"tool"`              // "trivy", "grype", "semgrep", "custom"
    BinaryPath       string        `mapstructure:"binary_path"`       // e.g. "/usr/local/bin/grype"
    ExpectedVersion  string        `mapstructure:"expected_version"`  // optional: "0.74.0". Job refuses to run if mismatch.
    SeverityThreshold string       `mapstructure:"severity_threshold"` // "CRITICAL,HIGH,MEDIUM,LOW"
    Timeout          time.Duration `mapstructure:"timeout"`           // default 5m per scan
    WorkerCount      int           `mapstructure:"worker_count"`      // default 2 concurrent scans
    ScanIntervalMins int           `mapstructure:"scan_interval_mins"` // default 5
    // For "custom" tool type only:
    VersionArgs      []string      `mapstructure:"version_args"`      // args to get version string, e.g. ["version", "--short"]
    ScanArgs         []string      `mapstructure:"scan_args"`         // args before the directory, e.g. ["dir:", "--output", "json"]
    OutputFormat     string        `mapstructure:"output_format"`     // "sarif" or "json" (for custom tools)
}
```

In `setDefaults()`:

```go
v.SetDefault("scanning.enabled", false)
v.SetDefault("scanning.tool", "grype")
v.SetDefault("scanning.severity_threshold", "CRITICAL,HIGH,MEDIUM,LOW")
v.SetDefault("scanning.timeout", 5*time.Minute)
v.SetDefault("scanning.worker_count", 2)
v.SetDefault("scanning.scan_interval_mins", 5)
```

In `bindEnvVars()`, add all keys:

```go
"scanning.enabled", "scanning.tool", "scanning.binary_path",
"scanning.expected_version", "scanning.severity_threshold",
"scanning.timeout", "scanning.worker_count", "scanning.scan_interval_mins",
"scanning.version_args", "scanning.scan_args", "scanning.output_format",
```

In `Validate()`, add when `scanning.enabled`:

```go
if cfg.Scanning.Enabled {
    if cfg.Scanning.BinaryPath == "" {
        return fmt.Errorf("scanning.binary_path is required when scanning.enabled=true")
    }
    valid := []string{"trivy", "grype", "semgrep", "custom"}
    if !slices.Contains(valid, cfg.Scanning.Tool) {
        return fmt.Errorf("scanning.tool must be one of: %s", strings.Join(valid, ", "))
    }
}
```

### Step 3 — Scanner Interface and Implementations

**New file:** `backend/internal/scanner/scanner.go`

```go
package scanner

// Scanner is the interface all scanning backends must implement.
type Scanner interface {
    // Name returns the human-readable tool name (stored in the DB with results).
    Name() string
    // Version returns the actual installed binary version string.
    // Used for record-keeping and to enforce ExpectedVersion pinning.
    Version(ctx context.Context) (string, error)
    // ScanDirectory scans the extracted module directory and returns structured results.
    // Implementations must handle their own timeout via the context.
    ScanDirectory(ctx context.Context, dir string) (*ScanResult, error)
}

// ScanResult is the normalised output of any scanner.
type ScanResult struct {
    ScannerVersion string          // actual binary version at scan time
    CriticalCount  int
    HighCount      int
    MediumCount    int
    LowCount       int
    HasFindings    bool
    RawJSON        json.RawMessage // raw output from the tool, stored as-is
}

// New constructs the appropriate Scanner implementation based on config.
// Returns an error if the tool is unknown or the binary is not accessible.
func New(cfg *config.ScanningConfig) (Scanner, error) {
    if _, err := os.Stat(cfg.BinaryPath); err != nil {
        return nil, fmt.Errorf("scanner binary not accessible at %q: %w", cfg.BinaryPath, err)
    }
    switch cfg.Tool {
    case "trivy":
        return newTrivyScanner(cfg.BinaryPath, cfg.Timeout), nil
    case "grype":
        return newGrypeScanner(cfg.BinaryPath, cfg.Timeout), nil
    case "semgrep":
        return newSemgrepScanner(cfg.BinaryPath, cfg.Timeout), nil
    case "custom":
        return newCustomScanner(cfg.BinaryPath, cfg.VersionArgs, cfg.ScanArgs, cfg.OutputFormat, cfg.Timeout), nil
    default:
        return nil, fmt.Errorf("unknown scanner tool %q", cfg.Tool)
    }
}
```

**New file:** `backend/internal/scanner/trivy.go`

```go
// trivyScanner implements Scanner for Aqua Security Trivy.
// Runs: trivy fs --format json --scanners vuln,secret,misconfig --exit-code 0 --quiet <dir>
// Output schema: {"Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]}
type trivyScanner struct { binaryPath string; timeout time.Duration }

func newTrivyScanner(binaryPath string, timeout time.Duration) Scanner { ... }

func (s *trivyScanner) Name() string { return "trivy" }

func (s *trivyScanner) Version(ctx context.Context) (string, error) {
    out, _ := exec.CommandContext(ctx, s.binaryPath, "version", "--format", "json").Output()
    var v struct { Version string `json:"Version"` }
    json.Unmarshal(out, &v)
    return v.Version, nil
}

func (s *trivyScanner) ScanDirectory(ctx context.Context, dir string) (*ScanResult, error) {
    ctx, cancel := context.WithTimeout(ctx, s.timeout)
    defer cancel()
    out, err := exec.CommandContext(ctx, s.binaryPath,
        "fs", "--format", "json", "--scanners", "vuln,secret,misconfig",
        "--exit-code", "0", "--quiet", dir).Output()
    if err != nil && ctx.Err() != nil {
        return nil, fmt.Errorf("trivy timed out after %s", s.timeout)
    }
    return parseTrivyJSON(s.Name(), out)
}
```

**New file:** `backend/internal/scanner/grype.go`

```go
// grypeScanner implements Scanner for Anchore Grype.
// Runs: grype dir:<dir> --output json --quiet
// Output schema: {"matches": [{"vulnerability": {"severity": "High"}}]}
type grypeScanner struct { binaryPath string; timeout time.Duration }

func newGrypeScanner(binaryPath string, timeout time.Duration) Scanner { ... }

func (s *grypeScanner) Name() string { return "grype" }

func (s *grypeScanner) Version(ctx context.Context) (string, error) {
    out, _ := exec.CommandContext(ctx, s.binaryPath, "version", "--output", "json").Output()
    var v struct { Version string `json:"version"` }
    json.Unmarshal(out, &v)
    return v.Version, nil
}

func (s *grypeScanner) ScanDirectory(ctx context.Context, dir string) (*ScanResult, error) {
    ctx, cancel := context.WithTimeout(ctx, s.timeout)
    defer cancel()
    out, err := exec.CommandContext(ctx, s.binaryPath,
        "dir:"+dir, "--output", "json", "--quiet").Output()
    if err != nil && ctx.Err() != nil {
        return nil, fmt.Errorf("grype timed out after %s", s.timeout)
    }
    return parseGrypeJSON(s.Name(), out)
}

// parseGrypeJSON maps grype severity strings ("Critical", "High", etc.) to counts.
func parseGrypeJSON(scannerName string, data []byte) (*ScanResult, error) { ... }
```

**New file:** `backend/internal/scanner/semgrep.go`

```go
// semgrepScanner implements Scanner for Semgrep OSS.
// Runs: semgrep --json --config auto --quiet <dir>
// Output schema: {"results": [{"extra": {"severity": "ERROR"}}]}
// Semgrep severity: ERROR → high, WARNING → medium, INFO → low (no "critical" level).
type semgrepScanner struct { binaryPath string; timeout time.Duration }
```

**New file:** `backend/internal/scanner/custom.go`

```go
// customScanner allows any tool that writes JSON or SARIF to stdout.
// Operators configure: version_args, scan_args, output_format ("sarif" or "json").
// SARIF output: parses runs[].results[].level ("error"→high, "warning"→medium, "note"→low).
type customScanner struct {
    binaryPath   string
    versionArgs  []string
    scanArgs     []string
    outputFormat string
    timeout      time.Duration
}
```

**Shared parser helper** `backend/internal/scanner/sarif.go`:

```go
// parseSARIF parses a SARIF 2.1.0 JSON document and returns counts by level.
// level "error" → high, "warning" → medium, "note" → low.
// Used by customScanner and can be used by any tool that emits SARIF.
func parseSARIF(scannerName string, data []byte) (*ScanResult, error) { ... }
```

### Step 4 — Version Pinning Check

In `ModuleScannerJob.Start()`, after constructing the `Scanner`, verify the actual version against the configured `ExpectedVersion` before beginning work:

```go
s, err := scanner.New(j.cfg)
if err != nil {
    slog.Error("module scanner: failed to construct scanner", "error", err)
    return nil  // non-fatal
}

actualVersion, err := s.Version(ctx)
if err != nil {
    slog.Error("module scanner: failed to get scanner version",
        "tool", j.cfg.Tool, "binary", j.cfg.BinaryPath, "error", err)
    return nil
}

if j.cfg.ExpectedVersion != "" && actualVersion != j.cfg.ExpectedVersion {
    slog.Error("module scanner: binary version mismatch — refusing to run",
        "tool", j.cfg.Tool,
        "expected", j.cfg.ExpectedVersion,
        "actual", actualVersion,
        "binary", j.cfg.BinaryPath,
        "action", "update scanning.expected_version in config or reinstall the expected version")
    return nil  // fail safe: don't scan with a potentially tampered binary
}

slog.Info("module scanner: started",
    "tool", j.cfg.Tool, "version", actualVersion, "binary", j.cfg.BinaryPath)
```

This is the supply chain mitigation: if `expected_version` is set and the actual binary differs, the job aborts and logs a clear error. Operators rotate `expected_version` in config when they intentionally upgrade.

### Step 5 — Model and Scan Repository

**New file:** `backend/internal/db/models/module_scan.go`

```go
package models

type ModuleScan struct {
    ID              string          `db:"id"                json:"id"`
    ModuleVersionID string          `db:"module_version_id" json:"module_version_id"`
    Scanner         string          `db:"scanner"           json:"scanner"`
    ScannerVersion  *string         `db:"scanner_version"   json:"scanner_version,omitempty"`
    ExpectedVersion *string         `db:"expected_version"  json:"expected_version,omitempty"`
    Status          string          `db:"status"            json:"status"`
    ScannedAt       *time.Time      `db:"scanned_at"        json:"scanned_at,omitempty"`
    CriticalCount   int             `db:"critical_count"    json:"critical_count"`
    HighCount       int             `db:"high_count"        json:"high_count"`
    MediumCount     int             `db:"medium_count"      json:"medium_count"`
    LowCount        int             `db:"low_count"         json:"low_count"`
    RawResults      json.RawMessage `db:"raw_results"       json:"raw_results,omitempty"`
    ErrorMessage    *string         `db:"error_message"     json:"error_message,omitempty"`
    CreatedAt       time.Time       `db:"created_at"        json:"created_at"`
    UpdatedAt       time.Time       `db:"updated_at"        json:"updated_at"`
}
```

**New file:** `backend/internal/db/repositories/module_scan_repository.go`

Key methods (same as before; `MarkComplete` now records `scanner_version` and `expected_version`):

```go
func (r *ModuleScanRepository) CreatePendingScan(ctx context.Context, moduleVersionID string) error
func (r *ModuleScanRepository) ListPendingScans(ctx context.Context, limit int) ([]*models.ModuleScan, error)
func (r *ModuleScanRepository) MarkScanning(ctx context.Context, scanID string) error  // conditional UPDATE
func (r *ModuleScanRepository) MarkComplete(ctx context.Context, scanID string, result *scanner.ScanResult, expectedVersion string) error
func (r *ModuleScanRepository) MarkError(ctx context.Context, scanID, errMsg string) error
func (r *ModuleScanRepository) GetLatestScan(ctx context.Context, moduleVersionID string) (*models.ModuleScan, error)
func (r *ModuleScanRepository) ResetStaleScanningRecords(ctx context.Context, olderThan time.Duration) error
```

`MarkScanning` uses conditional UPDATE to handle concurrent workers:

```sql
UPDATE module_version_scans
SET status = 'scanning', updated_at = NOW()
WHERE id = $1 AND status = 'pending'
```

Return a sentinel error if 0 rows affected.

### Step 6 — Scanner Background Job

**New file:** `backend/internal/jobs/module_scanner_job.go`

```go
type ModuleScannerJob struct {
    cfg        *config.ScanningConfig
    scanRepo   *repositories.ModuleScanRepository
    moduleRepo *repositories.ModuleRepository
    storage    storage.Storage
    stopChan   chan struct{}
}

func (j *ModuleScannerJob) Name() string { return "module-scanner" }

func (j *ModuleScannerJob) Start(ctx context.Context) error {
    if !j.cfg.Enabled {
        slog.Info("module scanner: disabled (scanning.enabled=false)")
        return nil
    }
    if j.cfg.BinaryPath == "" {
        slog.Info("module scanner: disabled (scanning.binary_path not set)")
        return nil
    }

    s, err := scanner.New(j.cfg)
    if err != nil {
        slog.Error("module scanner: failed to construct scanner", "error", err)
        return nil
    }

    // Version pinning check (supply chain protection)
    actualVersion, err := s.Version(ctx)
    if err != nil {
        slog.Error("module scanner: cannot get binary version", "error", err)
        return nil
    }
    if j.cfg.ExpectedVersion != "" && actualVersion != j.cfg.ExpectedVersion {
        slog.Error("module scanner: version mismatch — refusing to run",
            "tool", j.cfg.Tool, "expected", j.cfg.ExpectedVersion, "actual", actualVersion)
        return nil
    }
    slog.Info("module scanner: started", "tool", s.Name(), "version", actualVersion)

    _ = j.scanRepo.ResetStaleScanningRecords(ctx, 30*time.Minute)

    interval := time.Duration(j.cfg.ScanIntervalMins) * time.Minute
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    j.runScanCycle(ctx, s, actualVersion)
    for {
        select {
        case <-ticker.C:   j.runScanCycle(ctx, s, actualVersion)
        case <-j.stopChan: return nil
        case <-ctx.Done(): return nil
        }
    }
}

func (j *ModuleScannerJob) Stop() error { close(j.stopChan); return nil }

func (j *ModuleScannerJob) runScanCycle(ctx context.Context, s scanner.Scanner, version string) {
    pending, _ := j.scanRepo.ListPendingScans(ctx, j.cfg.WorkerCount*2)
    sem := make(chan struct{}, j.cfg.WorkerCount)
    var wg sync.WaitGroup
    for _, scan := range pending {
        scan := scan
        sem <- struct{}{}
        wg.Add(1)
        safego.Go(func() {
            defer func() { <-sem; wg.Done() }()
            j.scanOne(ctx, s, scan)
        })
    }
    wg.Wait()
}

func (j *ModuleScannerJob) scanOne(ctx context.Context, s scanner.Scanner, scan *models.ModuleScan) {
    if err := j.scanRepo.MarkScanning(ctx, scan.ID); err != nil { return } // another worker claimed it

    mv, err := j.moduleRepo.GetVersionByID(ctx, scan.ModuleVersionID)
    if err != nil {
        _ = j.scanRepo.MarkError(ctx, scan.ID, "module version not found")
        return
    }

    tmpDir, _ := os.MkdirTemp("", "scan-*")
    defer os.RemoveAll(tmpDir)

    reader, err := j.storage.Download(ctx, mv.StoragePath)
    if err != nil {
        _ = j.scanRepo.MarkError(ctx, scan.ID, "download: "+err.Error())
        return
    }
    defer reader.Close()

    if err := archiver.ExtractTarGz(reader, tmpDir); err != nil {
        _ = j.scanRepo.MarkError(ctx, scan.ID, "extract: "+err.Error())
        return
    }

    result, err := s.ScanDirectory(ctx, tmpDir)
    if err != nil {
        _ = j.scanRepo.MarkError(ctx, scan.ID, err.Error())
        return
    }

    _ = j.scanRepo.MarkComplete(ctx, scan.ID, result, j.cfg.ExpectedVersion)
    slog.Info("scan complete", "version_id", scan.ModuleVersionID,
        "tool", s.Name(), "critical", result.CriticalCount, "high", result.HighCount)
}
```

### Step 7 — Queue Scan After Upload

**File:** `backend/internal/api/modules/upload.go` — update factory to accept `scanRepo` and `scanningCfg`. After `CreateVersion()` succeeds (~line 246):

```go
if scanningCfg.Enabled && scanningCfg.BinaryPath != "" {
    if err := scanRepo.CreatePendingScan(c.Request.Context(), moduleVersion.ID); err != nil {
        slog.Warn("failed to queue scan", "version_id", moduleVersion.ID, "error", err)
    }
}
```

**File:** `backend/internal/services/scm_publisher.go` — same pattern after SCM `CreateVersion()`.

### Step 8 — Admin API Endpoint

**New file:** `backend/internal/api/admin/scans.go`

```go
// @Summary Get module version scan results
// @Description Returns the latest security scan for a module version, including tool name and version
// @Tags admin, modules
// @Success 200 {object} models.ModuleScan
// @Failure 404 {object} gin.H
// @Router /api/v1/admin/modules/{namespace}/{name}/{system}/versions/{version}/scan [get]
func GetModuleScanHandler(db *sql.DB) gin.HandlerFunc { ... }
```

Register in `backend/internal/api/router.go` in the admin modules route group.

### Step 9 — Wire Job

```go
scanRepo := repositories.NewModuleScanRepository(db)
moduleScannerJob := jobs.NewModuleScannerJob(&cfg.Scanning, scanRepo, moduleRepo, storageBackend)
registry.Register(moduleScannerJob)
```

### Verification — Feature 2

```bash
# With Grype (recommended alternative to Trivy):
# Install: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Config:
# scanning.enabled: true
# scanning.tool: grype
# scanning.binary_path: /usr/local/bin/grype
# scanning.expected_version: "0.74.0"   # pin to known-good version

# 1. Upload a module — scan is queued
curl -X POST http://localhost:8080/api/v1/modules \
  -F "namespace=test" -F "name=vpc" -F "system=aws" -F "version=1.0.0" \
  -F "file=@vpc-module.tar.gz"

# 2. Check scan result:
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/admin/modules/test/vpc/aws/versions/1.0.0/scan"
# Returns: {"scanner":"grype","scanner_version":"0.74.0","expected_version":"0.74.0","status":"clean",...}

# 3. Test version mismatch protection:
# Set expected_version: "0.73.0" while grype 0.74.0 is installed.
# Job should log "version mismatch — refusing to run" and not process scans.

# 4. Switch to Trivy: scanning.tool: trivy, scanning.binary_path: /usr/local/bin/trivy
# Scan results format changes, but DB schema and API are identical.

# 5. go test ./backend/internal/scanner/... — tests each implementation
# 6. go test ./backend/internal/jobs/... -run TestModuleScannerJob
```

---

## Feature 3: terraform-docs Auto-Generation

### Extraction and Storage

At module version creation time (both direct upload and SCM webhook), the module archive is extracted to a temp directory, all `.tf` files are parsed using `hashicorp/terraform-config-inspect`, and structured metadata (variables with types/descriptions/defaults, outputs, provider requirements, Terraform version constraints) is stored in a new DB table. Available immediately via a public API endpoint — synchronous, no background job needed.

**Library choice:** `github.com/hashicorp/terraform-config-inspect` — official HashiCorp Go library, minimal transitive deps, no binary required, parses variables/outputs/required_providers/required_core. Simpler than adding the full `terraform-docs` CLI as a binary dependency.

**Relationship to existing README storage:** The README and terraform-docs metadata are parallel, complementary, and stored in completely separate places. They are extracted from the same archive but serve different purposes and never conflict:

- **README** (`module_versions.readme`, TEXT column, nullable) — already extracted by `validation.ExtractReadme()` at `upload.go:~220`. This path is **untouched** by Feature 3. Stores the human-readable narrative documentation (the `README.md` file).
- **terraform-docs** (`module_version_docs` table, JSONB) — new in this feature. Stores machine-parseable structured metadata: variable names/types/descriptions/defaults, output names/descriptions, provider sources/version constraints, required Terraform version.

A module with a README and variables gets **both** stored. A module with no `.tf` variables gets the README stored and the docs endpoint returns 404 (not an error — graceful). A module with no README but many variables gets structured docs stored and the README column stays null. Neither replaces the other: the README answers "what does this module do?"; the structured docs answer "what inputs does it require and what does it output?".

### Step 1 — Add Dependency

From `backend/` directory:

```bash
go get github.com/hashicorp/terraform-config-inspect@latest
```

The library only depends on `hashicorp/hcl` (already an indirect dep from Viper) and `zclconf/go-cty`. Run `go mod tidy`.

### Step 2 — Database Migration 000017

**New file:** `backend/internal/db/migrations/000017_module_version_docs.up.sql`

```sql
CREATE TABLE module_version_docs (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    module_version_id UUID        NOT NULL REFERENCES module_versions(id) ON DELETE CASCADE,
    inputs            JSONB,
    outputs           JSONB,
    providers         JSONB,
    requirements      JSONB,
    generated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (module_version_id)
);

CREATE INDEX idx_mvd_version ON module_version_docs(module_version_id);
```

JSONB schemas:

- `inputs`: `[{"name":"vpc_cidr","type":"string","description":"...","default":null,"required":true}]`
- `outputs`: `[{"name":"vpc_id","description":"...","sensitive":false}]`
- `providers`: `[{"name":"aws","source":"hashicorp/aws","version_constraints":">= 4.0"}]`
- `requirements`: `{"required_version":">=1.0.0"}`

**New file:** `backend/internal/db/migrations/000017_module_version_docs.down.sql`

```sql
DROP TABLE IF EXISTS module_version_docs;
```

### Step 3 — Shared Archiver Package

Currently `extractTarGz` exists privately in `backend/internal/services/scm_publisher.go`. Both the analyzer (Feature 3) and scanner job (Feature 2) need it.

**New file:** `backend/internal/archiver/tarball.go`

```go
package archiver

// ExtractTarGz extracts a gzipped tar archive from reader into destDir.
// Enforces path traversal protection. Returns error on invalid archive.
func ExtractTarGz(reader io.Reader, destDir string) error { ... }

// FindModuleRoot returns the actual Terraform module root within an extracted directory.
// If the directory contains exactly one subdirectory with .tf files (GitHub/GitLab archive
// format adds a wrapper directory), returns that subdirectory. Otherwise returns extractedDir.
func FindModuleRoot(extractedDir string) string {
    entries, _ := os.ReadDir(extractedDir)
    if len(entries) == 1 && entries[0].IsDir() {
        sub := filepath.Join(extractedDir, entries[0].Name())
        if tfs, _ := filepath.Glob(filepath.Join(sub, "*.tf")); len(tfs) > 0 {
            return sub
        }
    }
    return extractedDir
}
```

Update `backend/internal/services/scm_publisher.go` to delete the local `extractTarGz` function and import `archiver.ExtractTarGz`. Update `backend/internal/jobs/module_scanner_job.go` to also use `archiver.ExtractTarGz`.

### Step 4 — Terraform Analyzer

**New file:** `backend/internal/analyzer/terraform.go`

```go
package analyzer

import (
    "github.com/hashicorp/terraform-config-inspect/tfconfig"
    "github.com/terraform-registry/terraform-registry/internal/archiver"
)

// ModuleDoc holds structured documentation extracted from a Terraform module.
type ModuleDoc struct {
    Inputs       []InputVar    `json:"inputs"`
    Outputs      []OutputVal   `json:"outputs"`
    Providers    []ProviderReq `json:"providers"`
    Requirements *Requirements `json:"requirements,omitempty"`
}

type InputVar struct {
    Name        string      `json:"name"`
    Type        string      `json:"type,omitempty"`
    Description string      `json:"description,omitempty"`
    Default     interface{} `json:"default,omitempty"`
    Required    bool        `json:"required"`
}

type OutputVal struct {
    Name        string `json:"name"`
    Description string `json:"description,omitempty"`
    Sensitive   bool   `json:"sensitive,omitempty"`
}

type ProviderReq struct {
    Name               string `json:"name"`
    Source             string `json:"source,omitempty"`
    VersionConstraints string `json:"version_constraints,omitempty"`
}

type Requirements struct {
    RequiredVersion string `json:"required_version,omitempty"`
}

// AnalyzeDir parses Terraform files in moduleDir and returns structured metadata.
// Uses tfconfig.LoadModule which tolerates partial/incomplete modules.
// Returns (nil, nil) if the directory has no .tf files.
func AnalyzeDir(moduleDir string) (*ModuleDoc, error) {
    module, diags := tfconfig.LoadModule(moduleDir)
    if module == nil {
        return nil, nil
    }
    if diags.HasErrors() {
        // Log but continue — partial parse is common with missing providers
        slog.Debug("terraform-config-inspect: parse diagnostics",
            "dir", moduleDir, "diags", diags.Error())
    }

    doc := &ModuleDoc{}

    for name, v := range module.Variables {
        doc.Inputs = append(doc.Inputs, InputVar{
            Name: name, Type: v.Type, Description: v.Description,
            Default: v.Default, Required: v.Required,
        })
    }
    sort.Slice(doc.Inputs, func(i, j int) bool { return doc.Inputs[i].Name < doc.Inputs[j].Name })

    for name, o := range module.Outputs {
        doc.Outputs = append(doc.Outputs, OutputVal{
            Name: name, Description: o.Description, Sensitive: o.Sensitive,
        })
    }
    sort.Slice(doc.Outputs, func(i, j int) bool { return doc.Outputs[i].Name < doc.Outputs[j].Name })

    for name, p := range module.RequiredProviders {
        req := ProviderReq{Name: name, Source: p.Source}
        if len(p.VersionConstraints) > 0 {
            req.VersionConstraints = strings.Join(p.VersionConstraints, ", ")
        }
        doc.Providers = append(doc.Providers, req)
    }
    sort.Slice(doc.Providers, func(i, j int) bool { return doc.Providers[i].Name < doc.Providers[j].Name })

    if len(module.RequiredCore) > 0 {
        doc.Requirements = &Requirements{
            RequiredVersion: strings.Join(module.RequiredCore, ", "),
        }
    }

    return doc, nil
}

// AnalyzeArchive extracts a tar.gz archive and calls AnalyzeDir on the module root.
// reader must be seekable (os.File satisfies this). Temp dir is cleaned up on return.
func AnalyzeArchive(reader io.ReadSeeker) (*ModuleDoc, error) {
    if _, err := reader.Seek(0, io.SeekStart); err != nil {
        return nil, fmt.Errorf("seek archive: %w", err)
    }
    tmpDir, err := os.MkdirTemp("", "tfdocs-*")
    if err != nil {
        return nil, fmt.Errorf("mkdirtemp: %w", err)
    }
    defer os.RemoveAll(tmpDir)

    if err := archiver.ExtractTarGz(reader, tmpDir); err != nil {
        return nil, fmt.Errorf("extract: %w", err)
    }
    return AnalyzeDir(archiver.FindModuleRoot(tmpDir))
}
```

### Step 5 — Module Docs Repository

**New file:** `backend/internal/db/repositories/module_docs_repository.go`

```go
package repositories

type ModuleDocsRepository struct {
    db *sql.DB
}

func NewModuleDocsRepository(db *sql.DB) *ModuleDocsRepository

// UpsertModuleDocs stores or replaces terraform-docs metadata. Idempotent.
func (r *ModuleDocsRepository) UpsertModuleDocs(
    ctx context.Context, moduleVersionID string, doc *analyzer.ModuleDoc,
) error {
    inputsJSON, _ := json.Marshal(doc.Inputs)
    outputsJSON, _ := json.Marshal(doc.Outputs)
    providersJSON, _ := json.Marshal(doc.Providers)
    var reqJSON interface{}
    if doc.Requirements != nil {
        reqJSON, _ = json.Marshal(doc.Requirements)
    }
    _, err := r.db.ExecContext(ctx, `
        INSERT INTO module_version_docs (module_version_id, inputs, outputs, providers, requirements)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (module_version_id) DO UPDATE SET
            inputs = EXCLUDED.inputs, outputs = EXCLUDED.outputs,
            providers = EXCLUDED.providers, requirements = EXCLUDED.requirements,
            generated_at = NOW()
    `, moduleVersionID, inputsJSON, outputsJSON, providersJSON, reqJSON)
    return err
}

// GetModuleDocs returns stored docs for a module version. Returns nil if none exist.
func (r *ModuleDocsRepository) GetModuleDocs(
    ctx context.Context, moduleVersionID string,
) (*analyzer.ModuleDoc, error) { ... }

// HasDocs returns true if docs exist for the given module version ID (used in listing).
func (r *ModuleDocsRepository) HasDocs(ctx context.Context, moduleVersionID string) (bool, error) { ... }
```

### Step 6 — Integration in Upload Handler

**File:** `backend/internal/api/modules/upload.go`

Update `UploadHandler` factory to also accept `moduleDocsRepo *repositories.ModuleDocsRepository`.

After `validation.ExtractReadme(tmpFile)` (around line 220) and after `moduleRepo.CreateVersion()` succeeds (around line 246):

```go
// Extract terraform-docs metadata (non-fatal — a module without variables is valid)
if _, err := tmpFile.Seek(0, io.SeekStart); err == nil {
    doc, err := analyzer.AnalyzeArchive(tmpFile)
    if err != nil {
        slog.Warn("terraform-docs: failed to analyze archive",
            "namespace", namespace, "name", name, "version", version, "error", err)
    } else if doc != nil {
        if err := moduleDocsRepo.UpsertModuleDocs(c.Request.Context(), moduleVersion.ID, doc); err != nil {
            slog.Warn("terraform-docs: failed to store docs",
                "version_id", moduleVersion.ID, "error", err)
        } else {
            slog.Debug("terraform-docs: stored",
                "version_id", moduleVersion.ID,
                "inputs", len(doc.Inputs), "outputs", len(doc.Outputs))
        }
    }
}
```

### Step 7 — Integration in SCM Publisher

**File:** `backend/internal/services/scm_publisher.go`

Add `moduleDocsRepo *repositories.ModuleDocsRepository` field and constructor param.

In `publishModuleVersion`, after `moduleRepo.CreateVersion()` succeeds, the temp archive at `archivePath` is still on disk:

```go
if f, err := os.Open(archivePath); err == nil {
    defer f.Close()
    if doc, err := analyzer.AnalyzeArchive(f); err != nil {
        slog.Warn("terraform-docs: failed to analyze SCM archive",
            "module", module.Name, "version", version, "error", err)
    } else if doc != nil {
        _ = p.moduleDocsRepo.UpsertModuleDocs(ctx, moduleVersion.ID, doc)
    }
}
```

### Step 8 — Public API Endpoint

**New file:** `backend/internal/api/modules/docs.go`

```go
// @Summary Get module documentation
// @Description Returns extracted terraform-docs metadata: variables, outputs, provider requirements
// @Tags modules
// @Param namespace path string true "Namespace"
// @Param name path string true "Module name"
// @Param system path string true "Provider system"
// @Param version path string true "Version"
// @Success 200 {object} analyzer.ModuleDoc
// @Failure 404 {object} gin.H
// @Router /api/v1/modules/{namespace}/{name}/{system}/{version}/docs [get]
func GetModuleDocsHandler(db *sql.DB) gin.HandlerFunc { ... }
```

Register in `backend/internal/api/router.go` in the modules route group:

```go
modulesGroup.GET("/:namespace/:name/:system/:version/docs", modules.GetModuleDocsHandler(db))
```

### Step 9 — Enrich Module Version Listing

**File:** `backend/internal/api/modules/versions.go`

Add `has_docs bool` to the version listing query via a lateral subquery or LEFT JOIN:

```sql
LEFT JOIN LATERAL (
    SELECT TRUE AS has_docs FROM module_version_docs
    WHERE module_version_id = mv.id LIMIT 1
) d ON TRUE
```

**File:** `backend/internal/api/modules/responses.go`

Add to `ModuleVersionEntry`:

```go
HasDocs bool `json:"has_docs"`
```

### Verification — Feature 3

```bash
# 1. Upload a module with variables.tf and outputs.tf
curl -X POST http://localhost:8080/api/v1/modules \
  -F "namespace=hashicorp" -F "name=vpc" -F "system=aws" -F "version=1.0.0" \
  -F "file=@vpc-module.tar.gz"

# 2. Immediately query docs (synchronous — available in same request cycle):
curl "http://localhost:8080/api/v1/modules/hashicorp/vpc/aws/1.0.0/docs"
# Expected:
# {
#   "inputs": [{"name":"vpc_cidr","type":"string","description":"CIDR block","required":true}],
#   "outputs": [{"name":"vpc_id","description":"The VPC ID"}],
#   "providers": [{"name":"aws","source":"hashicorp/aws","version_constraints":">= 4.0"}],
#   "requirements": {"required_version": ">= 1.0"}
# }

# 3. Module with no .tf files → upload succeeds, docs endpoint returns 404 (graceful)
# 4. Module with syntax errors → partial parse, best-effort docs stored
# 5. SCM webhook trigger → docs extracted and stored as part of auto-publish

# 6. go test ./backend/internal/analyzer/... -run TestAnalyzeDir
# 7. go test ./backend/internal/analyzer/... -run TestAnalyzeArchive
```

---

## File Index (All New / Modified Files)

### Shared Refactoring (prerequisite for Features 2 & 3)

| Action | File                                         | Change                                          |
| ------ | -------------------------------------------- | ----------------------------------------------- |
| New    | `backend/internal/archiver/tarball.go`       | `ExtractTarGz`, `FindModuleRoot`                |
| Modify | `backend/internal/services/scm_publisher.go` | Use `archiver.ExtractTarGz` (delete local copy) |

### Feature 1 Files: Pull-Through Provider Caching

| Action | File                                                                         | Change                                               |
| ------ | ---------------------------------------------------------------------------- | ---------------------------------------------------- |
| New    | `backend/internal/db/migrations/000015_pull_through_cache.{up,down}.sql`     | Migration                                            |
| Modify | `backend/internal/db/models/mirror.go`                                       | Add 2 fields to `MirrorConfiguration`                |
| Modify | `backend/internal/db/repositories/mirror_repository.go`                      | Update CRUD + add `GetPullThroughConfigsForProvider` |
| Modify | `backend/internal/db/repositories/provider_repository.go`                    | Add `UpsertProvider`, `UpsertVersion`                |
| Move   | `backend/internal/jobs/mirror_sync.go` → `backend/internal/mirror/filter.go` | Export `filterVersions` to shared location           |
| New    | `backend/internal/services/pull_through.go`                                  | `PullThroughService`                                 |
| Modify | `backend/internal/api/mirror/index.go`                                       | Add pull-through on cache miss                       |
| Modify | `backend/internal/api/mirror/platform_index.go`                              | Add pull-through on cache miss                       |
| Modify | `backend/internal/api/router.go`                                             | Wire `PullThroughService` into mirror handlers       |
| Modify | `backend/internal/api/admin/mirror.go`                                       | Expose new fields in create/update API + Swagger     |

### Feature 2: Module Security Scanning

| Action | File                                                                       | Change                                                |
| ------ | -------------------------------------------------------------------------- | ----------------------------------------------------- |
| New    | `backend/internal/db/migrations/000016_module_version_scans.{up,down}.sql` | Migration                                             |
| Modify | `backend/internal/config/config.go`                                        | Add `ScanningConfig` struct + defaults + env bindings |
| New    | `backend/internal/db/models/module_scan.go`                                | `ModuleScan` model                                    |
| New    | `backend/internal/db/repositories/module_scan_repository.go`               | Scan CRUD                                             |
| New    | `backend/internal/scanner/trivy.go`                                        | `TrivyScanner`, `ScanResult`                          |
| New    | `backend/internal/jobs/module_scanner_job.go`                              | Scanner background job                                |
| Modify | `backend/internal/api/modules/upload.go`                                   | Queue scan after `CreateVersion`                      |
| Modify | `backend/internal/services/scm_publisher.go`                               | Queue scan after SCM `CreateVersion`                  |
| New    | `backend/internal/api/admin/scans.go`                                      | `GetModuleScanHandler`                                |
| Modify | `backend/internal/api/router.go`                                           | Register scan endpoint + wire scanner job             |

### Feature 3: terraform-docs like Auto-Generation

| Action | File                                                                      | Change                                              |
| ------ | ------------------------------------------------------------------------- | --------------------------------------------------- |
| Modify | `backend/go.mod`                                                          | Add `github.com/hashicorp/terraform-config-inspect` |
| New    | `backend/internal/db/migrations/000017_module_version_docs.{up,down}.sql` | Migration                                           |
| New    | `backend/internal/analyzer/terraform.go`                                  | `AnalyzeDir`, `AnalyzeArchive`, `ModuleDoc` types   |
| New    | `backend/internal/db/repositories/module_docs_repository.go`              | Docs CRUD                                           |
| Modify | `backend/internal/api/modules/upload.go`                                  | Call analyzer, store docs after `CreateVersion`     |
| Modify | `backend/internal/services/scm_publisher.go`                              | Call analyzer, store docs after SCM `CreateVersion` |
| New    | `backend/internal/api/modules/docs.go`                                    | `GetModuleDocsHandler`                              |
| Modify | `backend/internal/api/router.go`                                          | Register `/docs` endpoint                           |
| Modify | `backend/internal/api/modules/responses.go`                               | Add `HasDocs bool` to `ModuleVersionEntry`          |
| Modify | `backend/internal/api/modules/versions.go`                                | Add `has_docs` to listing query via LEFT JOIN       |
