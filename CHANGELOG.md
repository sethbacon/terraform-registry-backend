<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0-rc.2] - 2026-04-13

## [0.4.0-rc.1] - 2026-04-13

---

## [0.3.5] - 2026-04-13

### Fixed

- fix: add `/auth/exchange-token` endpoint so the frontend can securely receive the SSO JWT from the HttpOnly cookie instead of URL query params
- fix: change SSO callback cookie SameSite from Strict to Lax for cross-site redirect compatibility with identity providers

### Added

- feat: include `version` and `build_date` in `/health` response for deployment verification

### Chore

- chore: update deployment configs to v0.3.4/v0.4.2 and document release update steps in CLAUDE.md

---

## [0.3.4] - 2026-04-13

### Fixed

- fix: respect `security.rate_limiting.enabled` config — all rate limiters (auth, general, upload) were unconditionally applied, ignoring the config flag

---

## [0.3.3] - 2026-04-11

### Fixed

- fix: move module scan route from `/admin/modules/` to `/modules/` prefix to resolve gin wildcard panic on startup

### Documentation

- docs: add module security scanning setup guide covering Trivy, Checkov, Terrascan, Snyk, and custom scanner backends
- docs: add module documentation extraction guide covering terraform-docs auto-extraction API and web UI
- docs: add `scanning:` section to `config.example.yaml` and `TFR_SCANNING_*` variables to configuration reference

---

## [0.3.1] - 2026-04-09

### Security

- fix: reject path traversal sequences in `/v1/files/*filepath` handler and add `safeJoin` containment check to local storage backend — prevents arbitrary host file reads via `GET /v1/files/../../etc/passwd` when using local storage with `ServeDirectly: true` (public endpoint, no auth required)
- fix: reject symlinks and hard links in module archive validation — prevents the registry from storing archives that would create path-escaping symlinks on Terraform client machines during `terraform init`
- fix: require HTTPS for OIDC issuer URL — rejects `http://` issuers that would allow MITM substitution of JWKS signing keys to forge valid ID tokens

---

## [0.3.0] - 2026-04-10

### Added

- feat: pull-through provider caching on mirror cache miss — serves provider metadata immediately from upstream on cache miss while triggering background binary download, eliminating 404s during `terraform init` for unsynced providers
- feat: pluggable module security scanning (Trivy, Terrascan, Snyk, Checkov, custom SARIF) — async scan of every uploaded module archive; stores vulnerability counts and raw results surfaced via admin API
- feat: terraform-docs auto-generation from .tf files at module upload time — extracts and indexes module variables, outputs, and provider requirements using `hashicorp/terraform-config-inspect` (no binary dependency)

### Changed

- test: raise CI coverage floor from 74% to 76.2% via interface-based S3/GCS storage mocks and systematic branch coverage across validation, analyzer, auth/oidc, mirror, and admin packages

---

## [0.2.32] - 2026-04-07

### Security

- fix: deliver JWT auth tokens via HttpOnly secure cookies instead of URL query parameters — prevents token leakage in browser history, server logs, and referrer headers
- fix: add JWT revocation via JTI blocklist with database-backed `revoked_tokens` table — logout now invalidates tokens server-side instead of relying solely on client-side cookie deletion
- fix: prevent CORS `Access-Control-Allow-Credentials: true` from being sent with wildcard origins — only specific origin matches now receive credentials support
- fix: make HSTS header conditional on TLS — `Strict-Transport-Security` is no longer sent over plain HTTP connections, per RFC 6797
- fix: prevent decompression bombs in archive extraction by counting actual bytes written instead of trusting tar header sizes
- fix: protect session store with `sync.Mutex` to prevent concurrent map read/write panics
- fix: `generateRandomSecret()` now returns an error instead of silently falling back to a time-based secret
- fix: remove `GIN_MODE` from `isDevMode()` check — development-only code paths are no longer accidentally enabled by Gin's debug mode
- fix: add `ReadHeaderTimeout` (10s) and `IdleTimeout` (120s) to HTTP server to mitigate slowloris attacks

### Added

- feat: JWT revocation infrastructure — new migration `000013_jwt_revocation` creates `revoked_tokens` table; new `TokenRepository` with `RevokeToken`, `IsTokenRevoked`, and `CleanupExpiredRevocations` methods; daily cleanup goroutine in server startup
- feat: pagination support with `limit`/`offset` query params and `{items, total, limit, offset}` envelope for module versions, provider versions, provider docs, mirrored providers, and mirror config versions
- feat: background job registry with `Job` interface and `Registry` providing `Register`, `StartAll`, `StopAll` lifecycle management
- feat: migration `000014_terraform_mirror_gpg_config` adds `custom_gpg_key` and `skip_gpg_verify` columns to `terraform_mirror_configs`
- feat: checksum sidecar `.sha256` files for local storage — avoids re-reading entire files to compute checksums in `GetMetadata()`
- feat: migration file count parity test ensuring every `.up.sql` has a matching `.down.sql`

### Changed

- refactor: replace all `fmt.Printf`/`fmt.Println` logging with structured `log/slog` calls in audit shipper, SCM linking, and SCM publisher
- refactor: replace `getResourceType()` string-scanning helpers with `c.FullPath()` switch statement in audit middleware
- refactor: remove custom `itoa()` and `min()` functions in favour of stdlib `strconv.Itoa()` and Go builtin `min()`
- refactor: remove `contains()` and `indexOf()` helper functions from audit middleware
- chore: add HA limitation comments to `RateLimiter` (in-memory token bucket) and `docContentCache` (in-memory TTL cache)
- chore: add Swagger annotations to `ServeModuleFile`, `UploadModule`, and `UploadProviderVersion` handlers
- chore: bump Go version from 1.26.0 to 1.26.1
- chore: bump Docker runtime image from `alpine:3.19` to `alpine:3.21`; add `TARGETARCH` build arg for multi-platform builds
- chore: raise CI coverage threshold from 65% to 75%; add per-package coverage gate (80% for auth and middleware)
- chore: add `golangci-lint` step to CI pipeline with `.golangci.yml` configuration

---

## [0.2.31] - 2026-04-07

### Security

- fix: deliver JWT auth tokens via HttpOnly secure cookies instead of URL query parameters — prevents token leakage in browser history, server logs, and referrer headers
- fix: add JWT revocation via JTI blocklist with database-backed `revoked_tokens` table — logout now invalidates tokens server-side instead of relying solely on client-side cookie deletion
- fix: prevent CORS `Access-Control-Allow-Credentials: true` from being sent with wildcard origins — only specific origin matches now receive credentials support
- fix: make HSTS header conditional on TLS — `Strict-Transport-Security` is no longer sent over plain HTTP connections, per RFC 6797
- fix: prevent decompression bombs in archive extraction by counting actual bytes written instead of trusting tar header sizes
- fix: protect session store with `sync.Mutex` to prevent concurrent map read/write panics
- fix: `generateRandomSecret()` now returns an error instead of silently falling back to a time-based secret
- fix: remove `GIN_MODE` from `isDevMode()` check — development-only code paths are no longer accidentally enabled by Gin's debug mode
- fix: add `ReadHeaderTimeout` (10s) and `IdleTimeout` (120s) to HTTP server to mitigate slowloris attacks

### Added

- feat: JWT revocation infrastructure — new migration `000013_jwt_revocation` creates `revoked_tokens` table; new `TokenRepository` with `RevokeToken`, `IsTokenRevoked`, and `CleanupExpiredRevocations` methods; daily cleanup goroutine in server startup
- feat: pagination support with `limit`/`offset` query params and `{items, total, limit, offset}` envelope for module versions, provider versions, provider docs, mirrored providers, and mirror config versions
- feat: background job registry with `Job` interface and `Registry` providing `Register`, `StartAll`, `StopAll` lifecycle management
- feat: migration `000014_terraform_mirror_gpg_config` adds `custom_gpg_key` and `skip_gpg_verify` columns to `terraform_mirror_configs`
- feat: checksum sidecar `.sha256` files for local storage — avoids re-reading entire files to compute checksums in `GetMetadata()`
- feat: migration file count parity test ensuring every `.up.sql` has a matching `.down.sql`

### Changed

- refactor: replace all `fmt.Printf`/`fmt.Println` logging with structured `log/slog` calls in audit shipper, SCM linking, and SCM publisher
- refactor: replace `getResourceType()` string-scanning helpers with `c.FullPath()` switch statement in audit middleware
- refactor: remove custom `itoa()` and `min()` functions in favour of stdlib `strconv.Itoa()` and Go builtin `min()`
- refactor: remove `contains()` and `indexOf()` helper functions from audit middleware
- chore: add HA limitation comments to `RateLimiter` (in-memory token bucket) and `docContentCache` (in-memory TTL cache)
- chore: add Swagger annotations to `ServeModuleFile`, `UploadModule`, and `UploadProviderVersion` handlers
- chore: bump Go version from 1.26.0 to 1.26.1
- chore: bump Docker runtime image from `alpine:3.19` to `alpine:3.21`; add `TARGETARCH` build arg for multi-platform builds
- chore: raise CI coverage threshold from 65% to 75%; add per-package coverage gate (80% for auth and middleware)
- chore: add `golangci-lint` step to CI pipeline with `.golangci.yml` configuration

---

## [0.2.30] - 2026-03-25

### Fixed

- fix: switch doc-index and provider-version pagination from next-page sentinel to length-based detection — the registry v2 API never populates `meta.pagination.next-page`; `GetProviderDocIndexByVersion` now fetches all pages (1,500+ entries for large providers like azurerm) and `resolveProviderVersionID` pages through all provider-version pages to handle providers with more than 100 releases

---

## [0.2.29] - 2026-03-25

### Fixed

- fix: backfill doc index for existing provider versions with no docs — the mirror sync job now checks the doc count when skipping already-complete versions; if zero docs exist (due to a prior failed doc fetch), it fetches and stores the doc index without re-downloading binaries

---

## [0.2.28] - 2026-03-25

### Fixed

- fix: resolve numeric v2 provider-version ID before fetching doc index — `resolveProviderVersionID` now calls `GET /v2/providers/{namespace}/{name}` to obtain the provider's numeric ID then `GET /v2/providers/{id}/provider-versions` to find the matching semver entry

---

## [0.2.25] - 2026-03-24

### Added

- feat: expose real version and build date from `GET /version` — new endpoint returns `{"version":"x.y.z","build_date":"..."}` populated at build time via ldflags injected by GoReleaser and Docker `--build-arg`

### Fixed

- fix: resolve GoReleaser dirty-state failure — deployment-configs tarball now written to `/tmp/` to avoid untracked file detection
- fix: upload deployment-configs tarball via `gh release upload` — GoReleaser's `extra_files` glob rejects absolute paths; tarball attachment moved to a post-GoReleaser step

### Maintenance

- chore: migrate release workflow to GoReleaser — replaces 5-platform matrix build job and hand-rolled `sha256sum` + release upload steps; binary names and checksums file unchanged
- chore: upgrade GitHub Actions to Node 24 compatible versions

---

## [0.2.27] - 2026-03-24

### Fixed

- fix: fetch provider doc index from v2 API with version-specific filtering — replaces the v1 non-versioned endpoint with the upstream registry's v2 `provider-docs` API (`filter[provider-version]`), fixing empty doc listings for mirrored providers where the stored language or version didn't match

---

## [0.2.26] - 2026-03-24

### Fixed

- fix: add `/version` proxy location to Helm nginx ConfigMap — the ConfigMap was missing the location block, causing the SPA fallback to intercept backend API requests in Kubernetes deployments
- fix: remove `go mod tidy` and swag doc generation from Dockerfile — both steps fail in environments with corporate TLS interception; `swagger.json` is committed to the repo by CI and `go.sum` already pins all dependencies

### Maintenance

- chore: add PR template, CI changelog enforcement, and collection script — `.github/PULL_REQUEST_TEMPLATE.md` pre-fills the changelog section; `pr-checks.yml` fails PRs without a valid entry; `collect-changelog.sh` automates release-time changelog collection

---

## [0.2.25] - 2026-03-24

### Added

- feat: expose real version and build date from `GET /version` — new endpoint returns `{"version":"x.y.z","build_date":"..."}` populated at build time via ldflags injected by GoReleaser and Docker `--build-arg`

### Fixed

- fix: resolve GoReleaser dirty-state failure — deployment-configs tarball now written to `/tmp/` to avoid untracked file detection
- fix: upload deployment-configs tarball via `gh release upload` — GoReleaser's `extra_files` glob rejects absolute paths; tarball attachment moved to a post-GoReleaser step

### Maintenance

- chore: migrate release workflow to GoReleaser — replaces 5-platform matrix build job and hand-rolled `sha256sum` + release upload steps; binary names and checksums file unchanged
- chore: upgrade GitHub Actions to Node 24 compatible versions

---

## [0.2.28] - 2026-03-25

### Fixed

- fix: resolve numeric v2 provider-version ID before fetching doc index — `GetProviderDocIndexByVersion` was passing the semver string as `filter[provider-version]` to the upstream registry's v2 `provider-docs` API, which requires the numeric JSON:API provider-version ID; this caused HTTP 400 errors during mirror sync, leaving doc index entries empty and the provider documentation tab blank in the UI

---

## [0.2.27] - 2026-03-24

### Fixed

- fix: fetch provider doc index from v2 API with version-specific filtering — replaces the v1 non-versioned endpoint with the upstream registry's v2 `provider-docs` API (`filter[provider-version]`), fixing empty doc listings for mirrored providers where the stored language or version didn't match

---

## [0.2.26] - 2026-03-24

### Fixed

- fix: add `/version` proxy location to Helm nginx ConfigMap — the ConfigMap was missing the location block, causing the SPA fallback to intercept backend API requests in Kubernetes deployments
- fix: remove `go mod tidy` and swag doc generation from Dockerfile — both steps fail in environments with corporate TLS interception; `swagger.json` is committed to the repo by CI and `go.sum` already pins all dependencies

### Maintenance

- chore: add PR template, CI changelog enforcement, and collection script — `.github/PULL_REQUEST_TEMPLATE.md` pre-fills the changelog section; `pr-checks.yml` fails PRs without a valid entry; `collect-changelog.sh` automates release-time changelog collection

---

## [0.2.25] - 2026-03-24

### Added

- feat: expose real version and build date from `GET /version` — new endpoint returns `{"version":"x.y.z","build_date":"..."}` populated at build time via ldflags injected by GoReleaser and Docker `--build-arg`

### Fixed

- fix: resolve GoReleaser dirty-state failure — deployment-configs tarball now written to `/tmp/` to avoid untracked file detection
- fix: upload deployment-configs tarball via `gh release upload` — GoReleaser's `extra_files` glob rejects absolute paths; tarball attachment moved to a post-GoReleaser step

### Maintenance

- chore: migrate release workflow to GoReleaser — replaces 5-platform matrix build job and hand-rolled `sha256sum` + release upload steps; binary names and checksums file unchanged
- chore: upgrade GitHub Actions to Node 24 compatible versions

---

## [0.2.23] - 2026-03-22

### Added

- feat: provider documentation browsing — new `provider_version_docs` table stores doc metadata fetched from the HashiCorp registry v1 API during mirror sync; two new endpoints (`GET /api/v1/providers/:namespace/:type/versions/:version/docs` and `GET /api/v1/providers/:namespace/:type/versions/:version/docs/:category/:slug`) serve the doc index and proxy markdown content from the registry v2 API with a 15-minute in-memory TTL cache

---

## [0.2.22] - 2026-03-21

### Fixed

- fix: ADO `FetchTags` now adds `peelTags=true` and uses `peeledObjectId` as the commit SHA for annotated tags — migration script creates annotated tags whose `objectId` is the tag-object SHA, not the commit SHA, causing `DownloadSourceArchive` to 404 with `versionType=commit`
- fix: `LinkModuleToSCM` auto-detects the repository's true default branch via `FetchRepository` when `default_branch` is omitted, instead of always defaulting to `"main"` — repos migrated from ADO with `master` as default branch now store correct metadata
- fix: `UpdateSCMLink` no longer overwrites optional string fields with empty strings on partial update — fields absent from the request body now preserve their existing values
- fix: `GetModule` response now includes `created_by_name` (user display name) and per-version `published_by` / `published_by_name` — these were already populated by the DB join but excluded from the `gin.H` response map

### Changed

- test: `api-test` integration tool now covers `PUT /api/v1/admin/modules/{id}` (UpdateModuleRecord), `POST /api/v1/admin/providers` (CreateProviderRecord), and `GET /api/v1/admin/providers/{id}` (GetProviderByID)

---

## [0.2.21] - 2026-03-21

### Fixed

- fix: add snake_case JSON tags to `models.APIKey` — `organization_id` was decoding as empty on the client side because Go serialized fields as PascalCase without explicit tags (#88)
- fix: add `organization_id` to `CreateProviderRecordRequest` and correct `created_by` type assertion (`uuid.UUID` → `string`) in provider create handler (#89)

### Added

- feat: `GET /api/v1/admin/modules/{id}` endpoint — required for Terraform provider `ImportState` on module resources (#90)
- feat: `PUT /api/v1/admin/providers/{id}` endpoint for updating provider record description and source (#91)

---

## [0.2.20] - 2026-03-21

### Fixed

- fix: add snake_case JSON tags to `models.Provider` — without them `CreateProviderRecord` and `GetProviderByID` responses decoded to empty structs on the client, leaving `organization_id` blank on every Read (#84, #86)
- fix: add `organization_id`, `source`, and `created_by` to `GetModule` response — their absence caused a provider inconsistency error on every module update step since `UpdateModuleRecord` returns the full struct but `GetModule` did not (#85, #86)

---

## [0.2.19] - 2026-03-20

### Fixed

- fix: org creator membership fails silently due to wrong type assertion — `c.Get("user_id")` returns a `string`, not `uuid.UUID`; the incorrect assertion always silently failed, leaving org creators without membership and causing 403 on all member-gated endpoints (#80, #82)
- fix: add postgres healthcheck and required env vars (`TFR_DATABASE_SSL_MODE`, `ENCRYPTION_KEY`, `TFR_JWT_SECRET`) to `docker-compose.test.yml` so the acceptance-test stack starts correctly (#82)

### Added

- feat: `PUT /api/v1/admin/modules/{id}` endpoint for updating module records — the repository layer already had `UpdateModule`; only the HTTP handler and route registration were missing (#81, #82)

---

## [0.2.18] - 2026-03-20

### Fixed

- fix: mirror config detail **Latest Version** field now shows the highest semver version rather than the first version returned by the upstream registry (#74)
- fix: storage config creation no longer unconditionally activates the new config — `activate=true` must be explicitly passed to make it active (#75)
- fix: org creation now auto-adds the requesting user as an admin member so subsequent API calls succeed without a separate membership step (#76)

### Added

- feat: `POST /api/v1/admin/providers` and `GET /api/v1/admin/providers/:id` CRUD endpoints for provider records, enabling the Terraform provider `registry_provider_record` resource to create and read provider entries by UUID (#77)

---

## [0.2.17] - 2026-03-17

### Fixed

- fix: semver sort no longer crashes on pre-release or build-metadata version strings (e.g. `5.0.0-beta`, `4.0.0-rc1`, `1.2.3+build`) — `NULLIF` only guarded against empty strings; the new `REGEXP_REPLACE(..., '[-+].*$', '')` strips suffixes before `SPLIT_PART` and `CAST` in all four semver `ORDER BY` expressions. Resolves the provider search 500 and the mirror detail "No providers synced" empty-state (#69)

---

## [0.2.16] - 2026-03-17

### Fixed

- fix: module card, terraform binary mirror list, and mirror config detail modal now sort versions by semver instead of upload/sync time — `SearchModulesWithStats`, `TerraformMirrorRepository.ListVersions`, and `ListMirroredProviderVersions` all used `created_at`/`synced_at` ordering
- fix: harden semver sort in `SearchProvidersWithStats` (v0.2.15) to guard against empty split parts with `COALESCE(CAST(NULLIF(...) AS INTEGER), 0)`

---

## [0.2.15] - 2026-03-17

### Fixed

- fix: provider card shows latest semver version instead of latest uploaded version — `SearchProvidersWithStats` was ordering the `latest_version` subquery by upload time; now sorts by semver major/minor/patch so the correct highest version is always shown (#62)

---

## [0.2.14] - 2026-03-17

### Fixed

- fix: broaden OIDC email fallback to cover all Azure AD UPN claim variants (`preferred_username`, `upn`, `unique_name`) and log the specific extraction error for diagnosis

---

## [0.2.13] - 2026-03-17

### Fixed

- fix: OIDC login fails for Azure Entra ID when `email` claim is absent — fall back to `preferred_username` (UPN) so login works without requiring the optional `email` claim to be added to the App Registration

---

## [0.2.12] - 2026-03-17

### Fixed

- fix: stream provider and Terraform binary downloads to a temp file instead of buffering entire zip in memory — eliminates OOM kills for large providers (e.g. AWS ~500 MB) on memory-constrained deployments (#54)

---

## [0.2.11] - 2026-03-17

### Fixed

- fix: AuditMiddleware logs failed write operations even when `LogFailedRequests=false` — removed erroneous `&& isReadOp` guard from the failed-request skip condition (#29)

---

## [0.2.10] - 2026-03-17

### Fixed

- fix: resolve FK violation in `SetStorageConfigured` where `uuid.Nil` violated the `storage_configured_by → users(id)` FK, silently leaving `storage_configured = false` after a successful setup wizard save (#51)
- fix: log encryption error when storage credential encryption fails in setup wizard (#51)

---

## [0.2.9] - 2026-03-17

### Fixed

- fix: run frontend nginx on port 8080 so non-root container can bind without NET_BIND_SERVICE capability (#49)

---

## [0.2.8] - 2026-03-17

### Fixed

- fix: make frontend pod security context configurable via Helm values to support rootless nginx on AKS (#47)

---

## [0.2.7] - 2026-03-17

### Fixed

- fix: correct helm liveness and startup probe path from /healthz to /health (#44)

---

## [0.2.6] - 2026-03-16

### Fixed

- fix: reset stale `in_progress` mirror sync status on startup so mirrors are automatically re-scheduled after a backend restart or ECS task replacement (#42)

### Changed

- chore: add `.gitattributes` to enforce LF line endings repo-wide (#42)

---

## [0.2.5] - 2026-03-08

### Fixed

- fix: make mirror provider lookup deterministic by preferring organization-scoped providers over NULL-org fallback, preventing network mirror index/version mismatch errors during `terraform init` (#39)

---

## [0.2.4] - 2026-03-06

### Fixed

- fix: restore provider download count tracking for network mirror protocol — download counts were silently dropped for S3, Azure, GCS, and local storage without ServeDirectly after v0.2.3 moved tracking to ServeFileHandler, which is only reachable for local+ServeDirectly (#36, #37)

---

## [0.2.3] - 2026-03-05

### Fixed

- fix: move mirror download tracking to file serve handler — User-Agent parsing fails with Terraform 1.14.6 which omits platform info; now tracks via URL path at `/v1/files/` which always contains os/arch (#20)

---

## [0.2.2] - 2026-03-05

### Fixed

- fix: track provider downloads via network mirror protocol by parsing client User-Agent for platform detection (#18)

---

## [0.2.1] - 2026-03-05

### Fixed

- fix: compute and serve correct `h1:` dirhash for provider mirror packages, resolving `terraform init` checksum mismatch (#11)

### Added

- test: expand test coverage across API handlers (admin, mirror, modules, providers, setup), database repositories (modules, providers, terraform mirror), and CLI utilities (api-test, check-db, fix-migration, hash) (#15)

### Changed

- docs: update and expand documentation across all sections (CLAUDE.md, README.md, deployment, configuration, troubleshooting, observability, architecture, development, OIDC, terraform-cli, api-reference) (#14)

### Removed

- chore: remove legacy unused utility files (`backend/clean-db.sql`, `backend/fix-migration.sql`, `backend/cmd/test-api`) (#15)

---

## [0.2.0] - 2026-03-04

### Fixed

- Fix `TriggerManualSync` not releasing `activeSyncsMutex` after marking a sync active, causing all subsequent sync requests to block indefinitely (#3)
- Fix terraform mirror status response returning equal `version_count` and `platform_count` because `COUNT(*)` was used instead of `COUNT(DISTINCT v.id)` for versions (#4)
- Fix swagger auto-commit being rejected by GitHub when two CI runs regenerated the file concurrently; add rebase before push (#6)
- Fix Dockerfile health check using `https://` against an HTTP-only server (#8)
- Fix NetworkPolicy (`allow-backend-ingress`) silently dropping direct Gateway/load-balancer traffic to the backend on AKS/EKS/GKE overlays (#8)
- Fix HPA oscillation in production overlay caused by `spec.replicas` being re-applied on every `kubectl apply` (#8)
- Fix liveness probe using `/health` (dependency-checking endpoint) — now uses `/healthz`; readiness probe correctly uses `/health` (#8)
- Fix stale Azure-specific `<ACR_NAME>.azurecr.io` placeholder in the generic production overlay image references (#8)
- Fix production overlay base URL patch being a no-op `registry.example.com` value (#8)
- Fix deployment documentation environment variable names to use `TFR_` prefix throughout (#8)

### Added

- Add `startupProbe` on `/healthz` to backend Kustomize and Helm deployments (#8)
- Add `readOnlyRootFilesystem: true` with `/tmp` emptyDir volume to backend container (#8)
- Add pod and container `securityContext` to Helm frontend Deployment to match Kustomize base (#8)
- Add `serviceAccountName` to Helm frontend Deployment (#8)
- Add `topologySpreadConstraints` patch to generic production overlay (#8)
- Add GKE Cloud SQL Auth Proxy sidecar patch to `overlays/gke/patches/backend-cloudsql-proxy.yaml` (#8)
- Add nginx `Permissions-Policy` security header to frontend nginx ConfigMap (#8)
- Add cloud-specific Helm values files: `values-aks.yaml`, `values-eks.yaml`, `values-gke.yaml` (#8)
- Add Helm templates for Gateway API, ClusterIssuer, NetworkPolicy, SecretProviderClass (#8)
- Add `docs/deployment/` directory with cloud-specific guides (AKS, EKS, GKE: prerequisites, deployment, operations) (#8)
- Add database backup procedures and PVC Backup & Restore section to deployment documentation (#8)

### Changed

- Default Helm `cors.allowedOrigins` from `["*"]` to `[]` — requires explicit configuration (#8)
- Default Helm `networkPolicy.enabled` from `false` to `true` (#8)
- Default Helm `securityContext.readOnlyRootFilesystem` from `false` to `true` (#8)
- Return `202 Accepted` instead of `409 Conflict` when a concurrent mirror sync is already in progress (#3)

---

## [0.1.0] - 2026-03-04

- Initial commit

