<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
