<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.1] - 2026-02-24

### Added

- **`version_filter` field on `terraform_mirror_configs`** (migration `000005`) — operators can
  supply a regex to restrict which upstream versions are synced (e.g. `^1\.` to pin to the 1.x
  line).  Empty string means "sync all versions" (existing behaviour preserved).

- **`stable_only` field on `terraform_mirror_configs`** (migration `000006`) — boolean flag that,
  when true, skips pre-release versions (those with a pre-release segment such as `-alpha`,
  `-beta`, `-rc`) during sync.  Defaults to `false`.

- **Per-platform download count tracking** (migration `000007`) — adds `download_count` to
  `terraform_version_platforms`; incremented on every binary download, surfaced in the dashboard
  stats response.

- **GitHub Releases mirror client** (`internal/mirror/github_releases.go`) — new mirror backend
  that fetches release assets directly from the GitHub Releases API.  Accepts an optional
  `GITHUB_TOKEN` environment variable for authenticated requests (higher rate limits).

- **`GET /terraform/binaries`** — new public endpoint that lists all active mirror
  configurations (name, tool, description, latest synced version).

### Fixed

- Mirror sync job now correctly applies the `version_filter` regex and `stable_only` flag when
  selecting which versions to sync.
- `terraform_releases` mirror client updated to read `version_filter` and `stable_only` from
  the config record.
- `terraform_mirror_repository` read/write paths updated for the two new config fields.

### Changed

- Docker-compose files cleaned up: aligned environment variable names with current config keys
  (`TFR_SERVER_BASE_URL`, `TFR_SECURITY_TLS_ENABLED`), switched backend service to build from
  local context, added comment directing users to the separate frontend repository.

## [1.2.0] - 2026-02-22

### Added

- **Multi-config Terraform binary mirror** — operators can now create multiple named mirror
  configurations (`terraform_mirror_configs`) and run independent mirrors for HashiCorp
  Terraform, OpenTofu, or any custom upstream URL side-by-side.  Each config carries a `name`,
  `description`, and `tool` type (`terraform` | `opentofu` | `custom`).

- **Database migration `000004_terraform_binary_mirror`** — introduces the
  `terraform_mirror_configs` table (name, description, tool, GPG verify flag, platform filter,
  custom URL); `terraform_versions` and `terraform_sync_history` tables both gain a `config_id`
  foreign key so all records are scoped to their parent config.

- **`TerraformMirrorConfig` model and repository** — full CRUD in
  `internal/db/repositories/terraform_mirror_repository.go`; all version/history queries
  accept a `configID uuid.UUID` parameter.  New request models:
  `CreateTerraformMirrorConfigRequest` and `UpdateTerraformMirrorConfigRequest`.

- **Admin API — `terraform-mirrors` resource group** (`internal/api/admin/terraform_mirror.go`):
  
  | Method | Path | Scope |
  | ----- | --- | --- |
  | `POST` | `/api/v1/admin/terraform-mirrors` | `mirrors:manage` |
  | `GET` | `/api/v1/admin/terraform-mirrors` | `mirrors:read` |
  | `GET` | `/api/v1/admin/terraform-mirrors/:id` | `mirrors:read` |
  | `GET` | `/api/v1/admin/terraform-mirrors/:id/status` | `mirrors:read` |
  | `PUT` | `/api/v1/admin/terraform-mirrors/:id` | `mirrors:manage` |
  | `DELETE` | `/api/v1/admin/terraform-mirrors/:id` | `mirrors:manage` |
  | `POST` | `/api/v1/admin/terraform-mirrors/:id/sync` | `mirrors:manage` |
  | `GET` | `/api/v1/admin/terraform-mirrors/:id/versions` | `mirrors:read` |
  | `GET` | `/api/v1/admin/terraform-mirrors/:id/versions/:version` | `mirrors:read` |
  | `DELETE` | `/api/v1/admin/terraform-mirrors/:id/versions/:version` | `mirrors:manage` |
  | `GET` | `/api/v1/admin/terraform-mirrors/:id/versions/:version/platforms` | `mirrors:read` |
  | `GET` | `/api/v1/admin/terraform-mirrors/:id/history` | `mirrors:read` |

- **Public download API** (`internal/api/terraform_binaries/binaries.go`) — mirrors are reached
  by name through unauthenticated endpoints:

  | Path | Description |
  | ------ | ------------- |
  | `GET /terraform/binaries/:name/versions` | List all synced versions |
  | `GET /terraform/binaries/:name/versions/latest` | Resolve the latest version |
  | `GET /terraform/binaries/:name/versions/:version` | List platforms for a version |
  | `GET /terraform/binaries/:name/versions/:version/:os/:arch` | Download binary |

- **`TerraformMirrorSyncJob` multi-config loop** (`internal/jobs/terraform_mirror_sync.go`) —
  the background sync job now iterates all active configs rather than assuming a single config;
  `TriggerSync(ctx, configID uuid.UUID)` triggers an immediate sync for one config.

- **`terraform_binary_downloads_total` Prometheus metric** — a
  `CounterVec{version, os, arch}` incremented on every successful binary download; documented in
  `docs/observability.md`.

### Changed

- **Router** — old `/terraform/binaries/versions[/...]` routes replaced by
  `/terraform/binaries/:name/versions[/...]`; old `/api/v1/admin/terraform-mirror` (singular)
  replaced by `/api/v1/admin/terraform-mirrors` (plural, full CRUD).

## [1.1.0] - 2026-02-22

### Added

- **Setup wizard API** (`backend/internal/api/setup/`) — new HTTP handler group that drives the
  first-run configuration wizard, with endpoints for:
  - `GET /api/v1/setup/status` — enhanced setup status including OIDC, storage, and admin state
  - `POST /api/v1/setup/validate-token` — validates the one-time setup token
  - `POST /api/v1/setup/oidc/test` — verifies OIDC provider reachability before saving
  - `POST /api/v1/setup/oidc` — saves OIDC provider configuration to the database
  - `POST /api/v1/setup/storage/test` — verifies storage backend connectivity before saving
  - `POST /api/v1/setup/storage` — saves storage backend configuration to the database
  - `POST /api/v1/setup/admin` — creates the initial admin user and records their pending email
  - `POST /api/v1/setup/complete` — marks setup as complete

- **Setup token middleware** (`backend/internal/middleware/setup.go`) — `SetupTokenMiddleware`
  guards all setup endpoints with a `SetupToken <token>` Authorization scheme; verifies the
  token against a bcrypt hash stored in the database; includes a per-IP rate limiter
  (10 attempts per 15-minute window) to prevent brute-force attacks.

- **Database migration: setup wizard** (`backend/internal/db/migrations/000003_setup_wizard`) —
  extends `system_settings` with `setup_completed`, `setup_token_hash`, `oidc_configured`, and
  `pending_admin_email` columns; adds an `oidc_config` table for OIDC provider configuration
  with AES-256-GCM encrypted client secrets.

- **`OIDCConfig` model** (`backend/internal/db/models/oidc_config.go`) — database model for
  OIDC provider configuration with `ToResponse()` (omits encrypted secrets) and `GetScopes()`
  helpers.

- **`OIDCConfigRepository`** (`backend/internal/db/repositories/oidc_config_repository.go`) —
  full CRUD for `oidc_config` rows plus system-settings helpers: `IsSetupCompleted`,
  `SetSetupCompleted`, `GetSetupTokenHash`, `SetSetupTokenHash`, `IsOIDCConfigured`,
  `SetOIDCConfigured`, `Set/Get/ClearPendingAdminEmail`, `GetEnhancedSetupStatus`, and
  `ActivateOIDCConfig` (transactional deactivate-all + activate-one).

- **Dynamic OIDC hot-swap** (`backend/internal/api/admin/auth.go`) — `AuthHandlers.SetOIDCProvider()`
  atomically replaces the active OIDC provider at runtime via `sync/atomic.Pointer`, allowing
  the setup wizard to activate a newly configured provider without a server restart.

- **On-startup OIDC provider loading** (`backend/internal/api/router.go`) — the router reads any
  active `oidc_config` row on startup and initialises the OIDC provider from it, so a
  database-configured provider survives container restarts without changes to `config.yaml`.

- **OIDC pre-provisioned user linking** (`backend/internal/db/repositories/user_repository.go`) —
  `GetOrCreateUserFromOIDC` falls back to email-based lookup when no user matches the OIDC
  subject; a pre-provisioned account created by the setup wizard is linked to the incoming OIDC
  identity on first login, preserving the admin role and organisation membership.

- **Initial Setup Guide** (`docs/initial-setup.md`) — end-to-end walk-through of the setup
  wizard flow including token retrieval, wizard steps, and a curl-based headless procedure.

- **Test coverage for new packages** — new test files bring all setup-wizard packages to ≥ 65%
  statement coverage (CI threshold):
  - `backend/internal/api/setup/handlers_test.go` — 35+ handler tests
  - `backend/internal/middleware/setup_test.go` — 12 middleware tests
  - `backend/internal/db/models/oidc_config_test.go` — 12 model tests
  - `backend/internal/db/repositories/oidc_config_repository_test.go` — 30+ repository tests

### Changed

- **`SystemSettings` model** — extended with `setup_completed`, `setup_token_hash` (never
  serialised to JSON), `oidc_configured`, and `pending_admin_email` fields to track wizard
  progress.

- **`GET /api/v1/setup/status`** — previously served by `StorageHandlers.GetSetupStatus`; now
  served by `SetupHandlers.GetSetupStatus`, returning the full enhanced status object.

- **`docs/architecture.md`** — added "Repository Structure" section with a table linking both
  repos to their Docker image names on GHCR.

- **`README.md`** — added "First-Run Setup" section describing the setup token flow and wizard
  steps; links to the new `docs/initial-setup.md`.

## [1.0.1] - 2026-02-21

### Added

- **Deployment config validation CI job** — `.github/workflows/ci.yml`: new `deployment-validate`
  job validates all three Docker Compose files, Helm chart (`helm lint`), both Kustomize overlays
  (`kubectl kustomize`), and Terraform configs for AWS, Azure, and GCP (`terraform validate`).

- **Deployment configs release asset** — `.github/workflows/release.yml`: packages all files under
  `deployments/` as `deployment-configs-<version>.tar.gz` and attaches it to the GitHub Release.

- **Repo-split deployment infrastructure** — updated all deployment configs to reflect the
  backend/frontend split:
  - `docker-compose.test.yml`: healthchecks, `seed-db` service, `ENCRYPTION_KEY`,
    `TFR_DATABASE_SSL_MODE=disable`; removed `5433` port binding
  - `docker-compose.prod.yml`: image defaults qualified to `ghcr.io/sethbacon/`
  - `deployments/create-dev-admin-user.sql`: copied from `backend/scripts/` for compose use
  - Helm `values.yaml`, Kubernetes base manifests, production kustomization: image refs
    qualified to `ghcr.io/sethbacon/terraform-registry-backend` and `…-frontend`
  - GCR `deploy.sh`: pull-from-ghcr pattern rather than building locally
  - `deployments/aws-ecs/task-definition-frontend.json`: removed (frontend is a separate repo)

### Fixed

- **`docker-compose.prod.yml` validated as overlay** — compose config step now runs
  `docker compose -f docker-compose.yml -f docker-compose.prod.yml config` since the prod file
  is an overlay that inherits the `volumes:` block from the base file.

- **Missing `.env.production` during CI compose config** — touch a stub `.env.production` before
  running `docker compose config` so the `env_file` directive does not fail in CI.

- **Azure Terraform provider version** — `deployments/terraform/azure/main.tf`: bumped constraint
  from `~> 3.80` to `>= 4.0`; `azurerm_storage_container.storage_account_id` is a v4-only
  attribute and v3.x only has `storage_account_name`.

- **AWS and GCP Terraform provider versions** — relaxed `~> 5.0` to `>= 5.0` for both
  `hashicorp/aws` and `hashicorp/google` so the deployment-validate job is not capped at a
  specific minor series.

### Changed

- **`docs/deployment.md`**: added "Repository Structure & Docker Images" section with
  `ghcr.io/sethbacon/` pull commands; updated AWS ECS, standalone binary, and migration
  sections to reference published images instead of local builds.

- **`.github/copilot-instructions.md`**: synced from `CLAUDE.md` (backend-scoped).

- **`README.md`**: added Immutable Publishing, Module README Support, and Enhanced Mirror RBAC
  feature bullets.

### Added

- **Unit tests for Session 31 telemetry/middleware additions** — four new white-box test files:
  - `backend/internal/middleware/metrics_test.go` — 5 tests for `MetricsMiddleware` (counter values, histogram labels, route template grouping, `<no-route>` sentinel, error status recording)
  - `backend/internal/middleware/requestid_test.go` — 5 tests for `RequestIDMiddleware` (UUID generation, format validation, upstream propagation, context storage, per-request uniqueness)
  - `backend/internal/telemetry/slog_test.go` — 5 tests for `SetupLogger` (all format × level combos, JSON validity, text key=value output, level filtering, source annotation)
  - `backend/internal/telemetry/metrics_test.go` — 8 tests verifying all registered metrics are described and can be incremented/observed

- **Dependabot configuration** — `.github/dependabot.yml` configures bi-weekly automated dependency updates (every Monday 09:00 UTC) for Go modules, frontend npm packages, E2E npm packages, and GitHub Actions; updates are grouped into one PR per ecosystem; major-version bumps on `gin`, `migrate`, React, and MUI are ignored to reduce noise

- **CI/CD pipeline enhancements** — `.github/workflows/ci.yml`:
  - `go mod tidy` drift check (fails CI if `go.mod`/`go.sum` would change after tidy)
  - Explicit `go build ./...` and `go vet ./...` steps before running tests
  - Race detector enabled (`-race`) on the backend test run
  - Fixed swagger diff path (was `backend/docs/swagger.json`, now correctly `docs/swagger.json` relative to working directory)
  - New parallel `gosec` job with documented exclusion list; uploads JSON scan results as artifact
  - New parallel `docker-build` smoke-test job — builds the backend `Dockerfile` and verifies the container does not crash immediately
  - Node 18 → 20 in frontend and E2E jobs; `actions/setup-go` v4 → v5
  - E2E teardown step now uses `if: always()` so the Compose stack is cleaned up even on failure

- **Scheduled build workflow** — `.github/workflows/scheduled-build.yml`: weekly Monday 08:00 UTC full build covering Go (mod-tidy check, build, vet, test with race detector), frontend (npm audit, lint, build), and Docker image build; automatically opens a GitHub issue when a scheduled run fails

- **Release workflow** — `.github/workflows/release.yml`: triggered on semver tags (`v*.*.*`); runs validation, builds multi-platform Go binaries (Linux/macOS/Windows × amd64/arm64), generates SHA-256 checksums, creates a GitHub Release with all assets, and builds + pushes the Docker image to `ghcr.io` with semantic version tags (`v1.2.3`, `1.2`, `1`, `latest`)

### Fixed

- Numerous documentation reference fixes and cross-referencing added
  - `docs/troubleshooting.md` - enhanced with new metric endpoint information
  - **Deployment checklist** — `docs/deployment.md`: pre-deployment verification document with 10 sections covering environment variables (database, storage, auth, server, observability), database migration steps, TLS/SSL validation, DNS verification, per-platform deployment steps (Docker Compose, Kubernetes/Helm, standalone binary), post-deployment smoke tests, monitoring verification, and rollback procedures for all deployment methods

## [1.1.1] - 2026-02-19 (SCM Provider Linking Bug Fixes & Hardening)

### Added

- **SCM fields on ModuleVersion model** — Added `CommitSHA *string`, `TagName *string`, and `SCMRepoID *string`
  fields to `db/models/module.go`. These are stored at version-publish time so the tag verifier and audit
  tooling can compare commit SHAs without re-querying the SCM provider.

- **Repository layer for SCM version fields** — `db/repositories/module_repository.go`:
  - `CreateVersion` INSERT now persists `commit_sha`, `tag_name`, and `scm_repo_id`
  - `GetVersion` and `ListVersions` scans populate the three new fields
  - New method `GetAllWithSourceCommit` returns all module versions that have a non-null `commit_sha`,
    used by the tag verifier to efficiently query only SCM-tracked versions

- **Tag integrity verifier implementation** — `services/tag_verifier.go` `runVerification` now has a full
  working implementation:
  - Calls `GetAllWithSourceCommit` to retrieve all versions with a stored commit SHA
  - Groups versions by SCM repo, builds a provider connector per group using the module creator's OAuth token
  - For each version, calls `FetchTagByName` on the connector and compares the live commit SHA against the
    stored value; mismatches are logged as violations

- **Configurable storage backend in mirror sync** — `jobs/mirror_sync.go`:
  - Added `storageBackendName string` field to `MirrorSyncJob` struct
  - Updated `NewMirrorSyncJob` signature to accept the backend name
  - Replaced the hardcoded `"local"` string with `j.storageBackendName` so mirrored artifacts are written
    to whichever backend the deployment is configured to use
  - `router.go` updated to pass `cfg.Storage.DefaultBackend` to `NewMirrorSyncJob`
  - Mirror sync test call-sites updated to pass an explicit backend name

- **Live connectivity probe in TestStorageConfig** — `api/admin/storage.go` `TestStorageConfig`:
  - Now instantiates the real storage backend via `storage.NewStorage(testCfg)` rather than returning a
    stub success
  - Executes an `Exists` probe (10-second context deadline) against a `.connectivity-test` key to confirm
    the backend is reachable and credentials are valid
  - Returns HTTP 200 with `success: false` and an error message when the backend is unreachable or
    mis-configured (distinct from HTTP 400 which indicates a structurally invalid config)

### Fixed

- **`(latest)` label and "Latest Version" stuck on deprecated version** — `ModuleDetailPage.tsx`, `ProviderDetailPage.tsx`:
  - The `(latest)` badge in the version dropdown used `index === 0` (first item in the semver-sorted
    list) regardless of its deprecation status. When the highest-semver version was deprecated, it
    displayed as "(latest) [DEPRECATED]" and the actual usable latest version had no label.
  - The "Latest Version:" field in the Module / Provider Information panel had the same bug, always
    showing `versions[0].version`.
  - Both now use `versions.find(v => !v.deprecated) ?? versions[0]` so the `(latest)` label and the
    info panel value always point to the highest semver non-deprecated version, falling back to the
    overall highest version only when every version is deprecated.

- **`auto_publish_enabled` JSON mismatch** — `internal/scm/types.go`:
  - `ModuleSCMRepo.AutoPublish` had `json:"auto_publish"` but every frontend consumer reads
    `auto_publish_enabled`; the mismatch caused the auto-publish toggle to always read as `false`
    after a link was created or fetched. Changed the JSON tag to `"auto_publish_enabled"` (the `db`
    tag remains `"auto_publish"` to match the database column).

- **Selected tag not published on link creation** — `frontend/src/components/PublishFromSCMWizard.tsx`:
  - When a user picked a specific tag in the "Choose Repository" step, clicking "Link Module" created
    the link record but never imported that tag. The wizard now calls `triggerManualSync` immediately
    after a successful link when `selectedTag` is set, so the chosen version is imported automatically.
    The sync runs in the background (HTTP 202); a sync failure is non-fatal and the user can always
    use "Sync Now" from the module page.

- **Module detail page not refreshing after sync** — `frontend/src/pages/ModuleDetailPage.tsx`:
  - After clicking "Sync Now" the page waited only 2 seconds before reloading, which was too short
    for the background sync goroutine to finish. Replaced the single `setTimeout` with a `pollForVersions`
    helper that issues `loadModuleDetails()` reloads at 2 s, 5 s, and 12 s after the sync is triggered,
    ensuring newly imported versions appear automatically.
  - The wizard's `onComplete` callback only called `loadSCMLink` (link metadata), never reloading
    module versions. It now also calls `pollForVersions()` so versions imported by the wizard-triggered
    sync surface without requiring a manual page refresh.
  - Removed the misuse of `setError` to display the "Sync triggered" success message — errors and
    success notices are no longer conflated in the same state field.

- **Module existence check in `LinkModuleToSCM`** — `api/modules/scm_linking.go`:
  - Added `GetModuleByID` lookup before attempting SCM provider resolution; the handler now returns
    HTTP 404 with a clear "module not found" message when the target module ID does not exist, rather
    than producing a misleading internal error

- **README extraction for SCM-synced versions** — `services/scm_publisher.go`:
  - Module versions published via SCM tag push or manual sync now attempt to extract a `README.md` from
    the downloaded tarball and persist it as the version's readme field, matching the behaviour of
    directly-uploaded versions

- **Version existence check before publish** — `services/scm_publisher.go`:
  - Added a `VersionExists` guard in the SCM publish path so that a version whose semver is already
    registered in the registry is skipped cleanly rather than causing a duplicate-key DB error

- **Comprehensive OAuth token refresh** — `services/scm_publisher.go` and related SCM service code:
  - Extracted a `refreshAndPersistToken` helper that refreshes an expired or near-expiry OAuth token
    and writes the updated token back to the database in a single operation
  - Proactive refresh: the helper is called before any SCM API operation when the stored token is
    expired or within 5 minutes of expiry
  - Reactive refresh: if an SCM API call returns an auth error, the token is refreshed and the call
    is retried once before surfacing the error to the caller
  - Both `ProcessTagPush` (webhook-triggered) and `processTagForManualSync` (manual sync) now use
    the refresh helper, ensuring long-lived background processes never fail due to stale tokens
  - **`ListRepositories` handler** (`api/admin/scm_oauth.go`): Added the same proactive + reactive
    refresh pattern to the repository browser endpoint — if the stored token is expired or within
    60 seconds of expiry, `tryRefresh()` is called before the Azure DevOps/GitLab API request is
    made; on a reactive 401/403 the refresh is retried once. Extracted a `tryRefresh()` closure to
    eliminate duplicated encrypt-persist-swap logic.
  - **Azure DevOps `fetchProjects`** (`scm/azuredevops/connector.go`): The error returned on a
    non-200 HTTP response from the ADO projects API now includes the actual HTTP status code
    (e.g. `"failed to fetch projects (HTTP 401)"`) so the status is visible in both the backend
    logs and the frontend error message, making token-expiry failures unambiguous.
  - **HTTP 203 normalisation for ADO expired tokens** (`scm/azuredevops/connector.go`,
    `api/admin/scm_oauth.go`): Azure DevOps / Entra ID returns `HTTP 203 Non-Authoritative
    Information` instead of 401 when a bearer token has expired. `fetchProjects` now detects 203
    and normalises it to 401 inside the returned `*APIError` so the existing reactive-refresh
    logic in `ListRepositories`, `ListRepositoryTags`, and `ListRepositoryBranches` correctly
    triggers a token refresh and retries the request rather than propagating a 500 to the client.
    All three handlers' final-error auth checks were also updated to catch 203 as an explicit
    reconnect signal, returning HTTP 401 with a user-friendly message instead of HTTP 500.

- **SCM webhook URL-secret validation** — `api/webhooks/scm_webhook.go` `HandleWebhook`:
  - Added first-layer security check: the `:secret` path parameter is extracted and compared against the
    last segment of the stored `WebhookURL` using `crypto/subtle.ConstantTimeCompare`, preventing timing
    attacks
  - Any mismatch returns HTTP 401 before the request body is read or the HMAC signature is verified

- **Duplicate version guard in `ProcessTagPush`** — `services/scm_publisher.go`:
  - Real OAuth token is now looked up from the module creator's stored credentials rather than using a
    placeholder; token is decrypted and passed to the connector

- **Race-condition duplicate guard in `processTagForManualSync`** — `services/scm_publisher.go`:
  - Added the same `VersionExists` check so that concurrent manual sync calls for the same tag do not
    cause double-inserts

- **Best-effort webhook deregistration on unlink** — `api/modules/scm_linking.go` `UnlinkModuleFromSCM`:
  - When unlinking a module, a `connector.RemoveWebhook()` call is now made to deregister the webhook
    from the SCM provider before the database record is deleted
  - Failure of the remote call is non-fatal: the database unlink proceeds regardless, with the error
    logged for operator visibility

### Changed

- **Swagger annotations updated** for all API handlers modified in this effort:
  - `HandleWebhook`: description now documents two-layer security (URL-secret constant-time compare +
    HMAC signature); `@Failure 401` clarified to cover both failure modes; `@Param secret` description
    updated to reflect its role as a URL-embedded first-layer guard
  - `LinkModuleToSCM`: added `@Failure 404 "Module not found or SCM provider not found"` to cover the
    new `GetModuleByID` existence check; previously only SCM-provider-not-found was documented
  - `UnlinkModuleFromSCM`: description updated to document best-effort remote webhook deregistration
  - `TriggerManualSync`: description updated to state the sync is asynchronous (returns 202 immediately),
    that the OAuth token is proactively refreshed when expired, and that already-existing versions are
    skipped; added missing `@Failure 401` for "no OAuth token for this SCM provider" case
  - `TestStorageConfig`: description updated from "validate without saving" to document real backend
    instantiation + 10-second connectivity probe; `@Success 200` clarified to note `success: false` means
    the backend is unreachable; `@Failure 400` scoped to structurally invalid configuration input

- **Repository browser visual selection feedback** — `frontend/src/components/RepositoryBrowser.tsx`:
  - Added `selectedTag?: SCMTag | null` prop so the parent wizard can drive tag highlighting
  - Selected repository accordion gains a blue `primary.main` border and `borderWidth: 2` outline;
    the folder icon swaps to a filled `CheckCircleIcon` in `primary` colour
  - A `"Selected"` primary `Chip` appears in the accordion summary next to the repository name
  - Tag `ListItemButton` entries now receive the MUI `selected` prop when they match both
    `selectedTag.tag_name` and the currently expanded repository, giving them the standard
    active-state background tint

- **Inline publishing options in SCM wizard step 1** — `frontend/src/components/PublishFromSCMWizard.tsx`:
  - After a repository is selected in step 1 ("Choose Repository"), an inline **Publishing Options**
    `Paper` panel appears immediately below the browser without requiring the user to advance to step 2
  - The panel shows either a deletable `Chip` for the selected tag name or instructional italic text
    when no tag has been chosen yet
  - An `auto_publish_enabled` `Switch` with an explanatory `Alert` (shown only when the toggle is on)
    lets users configure automatic publishing before leaving the browser step
  - `onRepositorySelect` now clears `selectedTag` on every repository change so stale tag state
    never carries over to a freshly selected repository

- **Structured error logging in RepositoryBrowser** — `frontend/src/components/RepositoryBrowser.tsx`:
  - `loadRepositories` and `loadTagsAndBranches` catch blocks now emit a `console.error` object
    containing `status`, `serverMessage`, `responseData`, `message`, and `url`, making token-expiry
    and network failures unambiguous in the browser DevTools
  - Auth errors (HTTP 401/403) surface the server-provided message directly; other errors include
    the HTTP status code in the displayed string for easier diagnosis

- **Upload page split into dedicated module and provider pages** — `frontend/src/pages/admin/`:
  - The original monolithic `UploadPage` (which combined module and provider upload under a single
    tabbed view) has been replaced by two focused, independently-routed pages:
    - **`ModuleUploadPage`** (`/admin/upload/module`) — presents a method-chooser card UI with two
      paths: **Upload from File** (`.tar.gz` archive upload) and **Link from SCM Repository** (embeds
      the `PublishFromSCMWizard` after a lightweight module-record creation form);
      accepts `location.state.moduleData` for pre-filling namespace/name/provider from the modules list
    - **`ProviderUploadPage`** (`/admin/upload/provider`) — presents a method-chooser with two paths:
      **Manual Upload** (zip binary upload form with namespace/type/version/OS/arch fields) and
      **Provider Mirror** (navigates to `/admin/mirrors?action=add` to configure a scheduled mirror);
      accepts `location.state.providerData` for pre-filling namespace/type from the providers list
  - **`UploadPage`** reduced to a one-line backward-compatibility redirect shim:
    `<Navigate to="/admin/upload/module" replace />` so any bookmarked or linked `/admin/upload`
    URLs continue to work without a 404
  - **`App.tsx`** — two new `ProtectedRoute`-wrapped routes registered:
    - `/admin/upload/module` requires `modules:write` scope
    - `/admin/upload/provider` requires `providers:write` scope
  - **Navigation link fixes**: `DashboardPage` quick-action cards for "Upload Module" and
    "Upload Provider" now target `/admin/upload/module` and `/admin/upload/provider` respectively;
    the **Upload Provider** button in `ProvidersPage` similarly updated to `/admin/upload/provider`
  - **Publish New Version button added ProviderDetailPage**
    - Publish New Version button added to provider details page
    - Button hidden when provider is Network Mirrored

## [1.1.0] - 2026-02-18 - Sessions 26–29 (Phase 7 Complete)

### Added

- **Session 26: Database Migration Consolidation + Unit Tests**
  - Consolidated all 28 incremental migrations into a single `000001_initial_schema` pair for clean deployments
  - Removed account-specific seed migrations that targeted `admin@dev.local` dev UUIDs
  - Schema includes all tables, indexes, constraints, and system seed data (6 role templates, 2 mirror policies, system_settings singleton) in final state
  - `down.sql` drops all 25 tables with CASCADE in correct reverse FK order
  - 6 new unit test files (zero prior coverage):
    - `validation/semver_test.go` — 23 test cases for version parsing and comparison
    - `validation/archive_test.go` — 17 test cases including path traversal and size limit validation
    - `validation/platform_test.go` — 28 test cases for OS/arch validation
    - `auth/scopes_test.go` — full scope matrix including admin wildcard and write-implies-read
    - `auth/jwt_test.go` — JWT round-trip, expiry, wrong-key, and dev-mode tests
    - `crypto/tokencipher_test.go` — AES-GCM seal/open, key derivation, non-determinism tests

- **Session 27: Additional Unit Tests (11 new test files)**
  - `auth/apikey_test.go` — API key format, prefix, uniqueness, validation, and header extraction (19 cases)
  - `pkg/checksum/checksum_test.go` — SHA256 calculation and verification with known vectors and error cases
  - `validation/gpg_test.go` — GPG key parsing, format validation, checksum extraction, binary validation, and signature verification
  - `validation/readme_test.go` — README extraction from tarballs (9 cases including case-insensitive matching)
  - `config/config_test.go` — DSN/address generation, full validation matrix (24 cases: storage backends, OIDC, TLS)
  - `scm/types_test.go` — Provider type enum, PAT detection, token expiry, webhook event classification
  - `scm/errors_test.go` — Error sentinel distinctness (15 sentinels), alias correctness (18 pairs), `errors.Is` wrapping
  - `scm/connector_test.go` — Pagination defaults and connector settings validation for all auth modes
  - `scm/provider_test.go` — Provider config validation across all 4 SCM platform types
  - `scm/factory_test.go` — Factory registration, type support, provider creation
  - `scm/registry_test.go` — Connector registry build for success, unregistered, invalid, and PAT scenarios
  - All tests pass; `go vet ./...` clean

- **Session 28: E2E Test Framework + Security Scanning**
  - **Playwright E2E framework** (`e2e/` directory at repo root):
    - `playwright.config.ts` — Chromium, trace/video on, retries on CI, `baseURL` env-var override
    - `fixtures/auth.ts` — Shared dev-login fixture (requires `DEV_MODE=true`)
    - `tests/auth.spec.ts` — Login render, dev-login redirect, protected-route redirect, logout
    - `tests/modules.spec.ts` — Module list heading/search/cards, detail page navigation
    - `tests/providers.spec.ts` — Provider list, search, Network Mirrored badge, detail page
    - `tests/admin.spec.ts` — Users/Orgs/API Keys/Mirrors page loads, unauthenticated redirect
  - **gosec security scan** (96 files, 25,036 lines scanned):
    - Fixed **G301** (5 occurrences): directory permissions `0755` → `0750` in `storage/local/local.go` and `services/scm_publisher.go`
    - Fixed **G302** (2 occurrences): audit log file permissions `0644` → `0600` in `audit/shipper.go`
    - 81 remaining findings documented as false positives or accepted risk in `backend/gosec-report.md`
  - **npm audit** — 355 packages audited; zero critical/high findings; 9 moderate in devDependencies only (not bundled); report at `frontend/npm-audit-report.md`
  - **Swagger annotation coverage** — `docs/SWAGGER_ANNOTATION_CHECKLIST.md` confirms 104/104 endpoints annotated; interactive ReDoc page added at `/api-docs` route

- **Session 29: Backend Documentation + Frontend UX + Context-Sensitive Help**
  - **Go file documentation** — Added file-level doc comments to all 58 non-generated `.go` files across the entire backend (api/admin, api/mirror, api/modules, api/providers, api/webhooks, auth, config, db/models, db/repositories, jobs, middleware, mirror, scm and all 4 SCM provider packages, services, all 4 storage backend packages, validation, cmd, pkg). Comments follow WHY-not-WHAT convention, documenting design decisions, security rationale, and non-obvious algorithms. `go vet ./...` clean after all edits.
  - **Frontend helper text** — Added contextual guidance to all non-obvious admin form fields:
    - `StoragePage.tsx`: Azure (account_name, account_key, container_name), S3 (bucket, region, auth_method with per-option description, access_key_id, secret_access_key, role_arn, external_id), GCS (auth_method with per-option description)
    - `UsersPage.tsx`: email, name, organization dropdown, role template dropdown
    - `SCMProvidersPage.tsx`: name (with platform examples), client_id
  - **Context-sensitive help panel** — Right-hand slide-in drawer accessible via the AppBar `?` icon:
    - `frontend/src/contexts/HelpContext.tsx` — `helpOpen` state with `openHelp`/`closeHelp`, persisted to `localStorage` across page refresh
    - `frontend/src/components/HelpPanel.tsx` — MUI persistent `Drawer` on desktop (temporary overlay on mobile); `getHelpContent(pathname)` maps all 15 routes to page-specific overview + key actions; 320px width; `X` button closes; footer link to `/api-docs`
    - Panel pushes main content left on desktop with animated margin transition
    - Content updates automatically on navigation; panel state survives page refresh
  - **E2E/build housekeeping**:
    - `e2e/tsconfig.json` added to silence IDE TypeScript false-positive warnings in `playwright.config.ts`
    - `.gitignore` updated: `e2e/playwright-report*` and `e2e/test-results*` excluded from version control

### Fixed

- **gosec G301/G302**: Hardened file and directory permission modes in local storage backend and audit log shipper

### Security

- gosec scan establishes baseline: 7 permission findings fixed; 81 findings triaged and documented in `backend/gosec-report.md`
- npm audit baseline: zero critical/high vulnerabilities in production bundle

## [1.0.0] - 2026-02-10 - Sessions 22-25 (Phase 6 Complete)

### Added

- **Phase 6 Complete: All Storage Backends, Deployments, and SCM Integrations**

- **Session 22: Bitbucket Data Center SCM Integration**
  - Bitbucket Data Center connector with full API integration (636 LOC)
  - Repository browsing, search, and tag enumeration with commit SHA resolution
  - Webhook creation and management for automated publishing
  - Personal Access Token (PAT) authentication for Bitbucket (no OAuth required)
  - Database migration 000027: Added `bitbucket_host` column to scm_providers
  - Frontend support for Bitbucket DC with dynamic form fields
  - Extended SCMProvider type with bitbucket_host field
  - SCM provider type constant and error handling for Bitbucket

- **Session 23: Storage Configuration in Terraform**
  - Added storage backend variable support to all 3 Terraform configs (AWS, Azure, GCP)
  - Each cloud defaults to native storage with zero additional configuration:
    - AWS: S3 with IAM role authentication
    - Azure: Azure Blob Storage with Direct Account Key
    - GCP: Google Cloud Storage with Workload Identity
  - All 4 storage backends (S3, Azure Blob, GCS, Local) available in every cloud
  - Conditional secrets management via Secrets Manager/Secret Manager/Key Vault
  - Storage configuration merged into task definitions/container apps via locals
  - Enhanced RBAC with storage-specific scope support (storage:read, storage:write, storage:manage)

- **Session 24: API Key Frontend Lifecycle Management**
  - Optional expiration date field in API key creation dialog
  - API key edit dialog for updating name, scopes, and expiration
  - API key rotation with grace period options (1-72h slider)
  - Expiration indicators: Red "Expired", orange "Expires soon" (within 7 days)
  - Scopes column with chip display and overflow tooltip
  - Helper functions for expiration status and datetime conversion
  - `rotateAPIKey()` method in API service
  - Copy-to-clipboard for newly rotated API key values

- **Session 25: Storage Configuration Azure Bug Fix & Phase 6 Completion**
  - Fixed critical bug in Azure Terraform deployment:
    - Corrected `azurerm_storage_account` resource reference to `azurerm_storage_account.main.primary_access_key`
    - Ensures proper Container App secret management
    - Resolves failures related to storage account key initialization
  - Cleaned up database migration state for Bitbucket DC
  - Removed duplicate/empty migration files

### Summary of Phase 6 Deliverables

**Storage Backends (Sessions 16-18):**

- ✅ Azure Blob Storage backend with SAS token support and CDN URLs
- ✅ AWS S3-compatible backend with presigned URLs and multipart uploads
- ✅ Google Cloud Storage backend with signed URLs and resumable uploads
- ✅ All backends support multiple authentication methods
- ✅ SHA256 checksum calculation and verification for all uploads

**Deployment Configurations (Sessions 20-21):**

- ✅ Docker Compose (dev and production)
- ✅ Kubernetes + Kustomize with base and environment overlays (dev, prod)
- ✅ Helm Chart with configurable values and all storage backends
- ✅ Azure Container Apps with Bicep templates
- ✅ AWS ECS Fargate with CloudFormation stack
- ✅ Google Cloud Run with VPC connectors
- ✅ Standalone binary deployment with systemd and nginx
- ✅ Terraform IaC for AWS, Azure, and GCP with full storage configuration

**SCM Enhancements & API Keys (Sessions 22-24):**

- ✅ Bitbucket Data Center as 4th SCM provider alongside GitHub, Azure DevOps, GitLab
- ✅ Complete API key lifecycle management with expiration and rotation
- ✅ Frontend UI for API key creation, editing, and rotation
- ✅ Scope management with checkboxes and overflow handling

### Milestone

- **✅ Phase 6 Complete**: Enterprise-grade Terraform Registry fully implemented
  - All 3 Terraform protocols (Module, Provider, Mirror)
  - 4 storage backends with multi-cloud support
  - 4 SCM providers with automated publishing
  - Complete deployment options (Docker, K8s, PaaS, binary)
  - Full authentication and RBAC system
  - React SPA with comprehensive admin UI
  - Ready for Phase 7 (Testing & Documentation) and Phase 8 (Production Polish)

## [0.9.0] - 2026-02-06 - Session 15

### Added

- **Provider Network Mirroring - Complete Implementation (Phase 5C)**
  - Full `syncProvider()` implementation with actual provider binary downloads
  - Downloads provider binaries from upstream registries (registry.terraform.io)
  - Stores binaries in local storage backend
  - Creates provider, version, and platform records in database
  - SHA256 checksum verification for all downloaded files
  - GPG signature verification using ProtonMail/go-crypto library
  - Mirrored provider tracking tables (migration 011):
    - `mirrored_providers`: tracks which providers came from which mirror
    - `mirrored_provider_versions`: tracks version sync status and verification
  - Organization support for mirror configurations
  - Connected TriggerSync API to background sync job
  - Enhanced RBAC with mirror-specific scopes:
    - `mirrors:read`: View mirror configurations and sync status
    - `mirrors:manage`: Create, update, delete mirrors and trigger syncs
  - Audit logging for all mirror operations via middleware
  - Mirror Management UI page (frontend):
    - List all mirror configurations with status
    - Create/edit/delete mirror configurations
    - Trigger manual sync
    - View sync status and history
    - Namespace and provider filters
    - Navigation in admin sidebar

### Milestone

- **Phase 5C Complete**: Provider network mirroring fully implemented with GPG verification, RBAC, audit logging, and UI

## [0.8.0] - 2026-02-04 - Session 14

### Added

- **Provider Network Mirroring Infrastructure (Phase 5C Session 14)**
  - Database migration 010: `mirror_configurations` and `mirror_sync_history` tables
  - Upstream registry client with Terraform Provider Registry Protocol support
  - Service discovery for upstream registries
  - Provider version enumeration from upstream
  - Package download URL resolution
  - Mirror configuration models and repository layer
  - Full CRUD API endpoints for mirror management (`/api/v1/admin/mirrors/*`)
  - Background sync job infrastructure with 10-minute interval checks
  - Sync history tracking and status monitoring
  - Framework ready for actual provider downloads

### Fixed

- Fixed migration system: renamed migrations to `.up.sql`/`.down.sql` convention
- Created `fix-migration` utility for cleaning dirty migration states

## [0.7.0] - 2026-02-04 - Session 13

### Added

- **SCM Frontend UI & Comprehensive Debugging (Phase 5A Session 13)**
  - Complete SCM provider management interface
  - Repository browser with search and filtering
  - Publishing wizard with commit pinning
  - Description field for module uploads
  - Helper text and tab-specific guidelines for all upload forms
  - Authentication-gated upload buttons on modules/providers pages
  - Network mirrored provider badges for visual differentiation
  - ISO 8601 date formatting for international compatibility

### Fixed

- **Single-Tenant Mode Issues**:
  - Organization filtering now correctly skips when multi-tenancy is disabled
  - Search handlers conditionally check MultiTenancy.Enabled configuration
  - Repository layer handles empty organization ID with proper SQL WHERE clauses
  
- **Frontend Data Visibility**:
  - Module and provider search results now include computed latest_version and download_count
  - Backend aggregates version data and download statistics for search results
  - Fixed undefined values display with proper fallbacks (N/A, 0)
  - Provider download counts correctly handle platform-level aggregation

- **Navigation & Routing**:
  - Fixed route parameters in ModuleDetailPage (provider→system)
  - Fixed route parameters in ProviderDetailPage (name→type)
  - Dashboard cards now navigate correctly to respective pages
  - Quick action cards navigate with state to select correct upload tab

- **Date Display**:
  - Changed from localized dates to ISO 8601 format (YYYY-MM-DD)
  - Applied consistently across all version displays
  - Backend now includes published_at in version responses

- **Provider Pages**:
  - Fixed versions response structure handling (direct array vs. nested)
  - Fixed TypeScript linting errors (unused imports, type mismatches)
  - Provider cards now use provider.type instead of non-existent provider.name
  - Added organization_name and published_at fields to Provider/ProviderVersion types

- **Upload Interface**:
  - Added description field to module upload form
  - FormData creation fixed for proper API compatibility
  - Tab-specific upload guidelines implemented
  - Removed duplicate generic guidelines section

### Technical Details

- Backend search endpoints now query versions to compute latest_version
- Module versions: Sum download_count across all versions
- Provider versions: Platform-level downloads (set to 0 pending aggregation implementation)
- Frontend uses computed values from search results instead of missing model fields
- All dates use RFC3339 format in API responses
- Network mirror differentiation uses provider.source field presence

### Phase Completion

- ✅ **Phase 5A Complete**: SCM integration fully implemented with production-ready UI

## [0.6.0] - 2024-01-XX - Session 11

### Added

- **SCM OAuth Flows & Repository Operations (Phase 5A Session 11)**
  - GitHub connector with complete OAuth 2.0 authorization flow
  - GitHub repository listing, searching, and browsing
  - GitHub branch and tag operations with commit resolution
  - GitHub archive download (tarball/zipball)
  - Azure DevOps connector with OAuth 2.0 flow
  - Azure DevOps project and repository browsing
  - Azure DevOps branch, tag, and commit operations
  - Azure DevOps archive download functionality
  - GitLab connector with OAuth 2.0 flow and token refresh
  - Token encryption/decryption using AES-256-GCM
  - SCM repository data access layer
  - Support for self-hosted SCM instances
  - Connector registry with factory pattern
  - Pagination support for all list operations
  - Repository search functionality

### Technical Details

- **GitHub Integration**:
  - OAuth app flow with code exchange
  - REST API v3 with proper versioning headers
  - Repository filtering and sorting
  - Tag-to-commit SHA resolution
  - Archive download with format selection
  
- **Azure DevOps Integration**:
  - Azure DevOps Services OAuth with JWT assertions
  - Project-based repository organization
  - Git refs API for branches and tags
  - Token refresh support with expiry tracking
  
- **GitLab Integration**:
  - Standard OAuth 2.0 flow
  - Token refresh capability
  - Self-hosted GitLab support
  - Stub implementations ready for completion

### Infrastructure

- Connector interface with consistent API across providers
- Error handling with wrapped remote API errors
- Token expiry checking and validation
- Secure credential management

## [0.5.1] - 2024-01-XX - Session 10

### Added

- **SCM Integration Foundation (Phase 5A Session 10)**
  - Database migration for SCM integration (008_scm_integration.sql)
  - SCM provider configurations table
  - User OAuth tokens table with encryption
  - Module-to-repository linking table
  - Webhook event logging table
  - Version immutability violations tracking
  - SCM provider interface and types
  - Connector abstraction layer
  - Token encryption utilities (AES-256-GCM)
  - Connector registry/factory pattern
  - Error definitions for SCM operations

### Changed

- Extended module_versions table with SCM metadata (commit SHA, source URL, tag)

## [0.5.0] - 2024-01-XX - Session 9

### Added

- **Frontend SPA (Phase 5 Complete)**
  - Complete React 18+ TypeScript application with Vite
  - Material-UI component library integration
  - Module browsing and search pages with pagination
  - Provider browsing and search pages with pagination
  - Module and provider detail pages with version history
  - Admin dashboard with system statistics
  - User management UI (list, create, edit, delete)
  - Organization management UI (list, create, edit, delete)
  - API key management UI with scope configuration
  - Upload interface for modules and providers
  - Authentication context with JWT support
  - Protected routes for admin functionality
  - Responsive design with light theme (dark mode ready)
  - Comprehensive error handling and loading states
  - Optimistic UI updates for better UX
  - Vite dev server with backend proxy on port 3000

### Changed

- Updated implementation plan to reflect frontend completion
- Renamed VCS (Version Control System) to SCM (Source Code Management) throughout project

## [0.4.0] - 2024-01-XX - Session 8

### Added

- **User & Organization Management (Phase 4 Complete)**
  - User management REST endpoints (list, search, create, update, delete)
  - Organization management REST endpoints (list, search, create, update, delete)
  - Organization membership management (add, update, remove members)
  - Role-based organization membership (owner, admin, member, viewer)
  - User search by email and name
  - Organization search by name
  - Pagination support for user and organization listings
  - Audit logging for all administrative actions
  - RBAC middleware integration for endpoint protection

### Changed

- Enhanced authentication middleware with organization context
- Improved API key scoping for multi-tenant operations
- Updated database schema with organization member roles

## [0.3.0] - 2024-01-XX - Session 7

### Added

- **Authentication & Authorization (Phase 4)**
  - JWT-based authentication system
  - API key authentication with bcrypt hashing
  - OIDC provider support (generic)
  - Azure AD / Entra ID integration
  - Role-based access control (RBAC) middleware
  - Scope-based authorization for fine-grained permissions
  - API key management endpoints (create, list, delete)
  - Authentication endpoints (login, logout, refresh)
  - Token encryption for OAuth tokens
  - Configurable single-tenant vs multi-tenant mode
  - User model with OIDC subject support
  - Organization model for multi-tenancy
  - API key model with expiration and scopes

### Changed

- Updated router with authentication middleware
- Protected admin endpoints with proper authorization
- Enhanced database schema with auth tables

## [0.2.0] - 2024-01-XX - Sessions 4-6

### Added

- **Provider Registry Protocol (Phase 3 Complete)**
  - Provider version listing endpoint
  - Provider binary download endpoint with platform support
  - Provider upload endpoint with validation
  - GPG signature verification framework
  - Provider platform matrix support (OS/Architecture)
  - SHA256 checksum validation for provider binaries
  - Provider data models and repositories
  - Provider search functionality

- **Network Mirror Protocol (Phase 3 Complete)**
  - Version index endpoint for provider mirroring
  - Platform index endpoint for specific versions
  - JSON response formatting per Terraform mirror spec
  - Hostname-based provider routing
  - Integration with existing provider storage

### Changed

- Enhanced storage abstraction to support provider binaries
- Updated database schema with provider tables
- Improved validation for provider uploads

## [0.1.0] - 2024-01-XX - Sessions 1-3

### Added

- **Module Registry Protocol (Phase 2 Complete)**
  - Module version listing endpoint
  - Module download endpoint with redirect support
  - Module upload endpoint with validation
  - Module search with pagination
  - Direct file serving for local storage
  - SHA256 checksum generation and verification
  - Semantic version validation
  - Archive format validation (tar.gz, zip)
  - Security checks for path traversal
  - Download tracking and analytics
  - Module data models and repositories

- **Project Foundation (Phase 1 Complete)**
  - Go backend with Gin framework
  - PostgreSQL database with migrations
  - Configuration management (YAML + environment variables)
  - Service discovery endpoint (/.well-known/terraform.json)
  - Health check endpoint
  - Docker Compose setup for local development
  - Dockerfile for backend service
  - Storage abstraction layer
  - Local filesystem storage backend
  - Organization-based multi-tenancy support

### Infrastructure

- PostgreSQL database schema with migrations
- Database repositories for data access layer
- HTTP middleware (logging, CORS, error handling)
- Request validation utilities
- Checksum utilities for file integrity

[Unreleased]: https://github.com/sethbacon/terraform-registry-backend/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/sethbacon/terraform-registry-backend/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sethbacon/terraform-registry-backend/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sethbacon/terraform-registry-backend/releases/tag/v0.1.0
