<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
