# Terraform Registry Backend — Roadmap

**Baseline:** v0.7.0 (2026-04-17)
**Goal:** Close enterprise-adoption gaps identified in the 2026-04-17 independent evaluation and reach verifiable parity with Terraform Enterprise, Artifactory, and Spacelift for the registry surface area.

This roadmap is organized into **phases** (sequencing) and **tracks** (parallel workstreams). Multiple agents may claim tracks concurrently. Items marked `↔` have a cross-repo dependency with `terraform-registry-frontend`.

---

## Cross-repo dependency summary

The following items require coordinated work with `terraform-registry-frontend`:

| Backend item                     | Frontend item                   | Topic                |
| -------------------------------- | ------------------------------- | -------------------- |
| B2.1 (SAML connector)            | B2.1 (SAML login picker)        | SAML login flow      |
| B2.2 (LDAP connector)            | B2.2 (LDAP login form)          | LDAP login flow      |
| B2.3 (SCIM endpoints)            | B2.3 (SCIM admin page)          | SCIM provisioning    |
| B2.4 (OIDC refresh)              | A1.1 (httpOnly cookie auth)     | Auth token migration |
| D3.4 (Per-org quotas)            | E4.4 (Quota dashboard)          | Org quota management |
| E4.1 (Module deprecation API)    | E4.1 (Deprecation banner)       | Module deprecation   |
| E4.3 (OPA/Rego policy)           | E4.2 (Policy results in upload) | Policy evaluation    |
| E4.4 (Module test orchestration) | E4.3 (Test results UI)          | Module test display  |
| E4.2 (OCI endpoint)              | E4.5 (OCI pull snippet)         | OCI distribution     |
| E0.2 (Module resync re-analysis) | — (uses existing detail page)   | Module metadata      |
| H0.2 (Release workflow)          | H0.3 (Release workflow)         | CI/CD streamlining   |

---

## Legend

- **Size:** S (<1d), M (1–3d), L (1–2w), XL (>2w)
- **Priority:** P0 (adoption blocker), P1 (high), P2 (medium), P3 (nice-to-have)
- **Track:** A = Supply chain / SecOps · B = Enterprise identity · C = Compliance / crypto · D = Operability · E = Protocol / features · F = Observability · G = Data layer · H = CI/CD

---

## Phase 0 — Quick wins (all parallel; target: 1 sprint)

### A0.1 · Add `SECURITY.md` at repo root · [P0/S]

- Disclosure policy, supported-versions matrix, PGP contact, CVE acknowledgment SLAs (48h / 7d / 30d).
- Template: mirror frontend `SECURITY.md` structure.
- **Files:** `SECURITY.md`, `README.md` (add link), `.github/SECURITY_CONTACTS`
- **AC:** File present; linked from README; referenced in `.github/SECURITY_CONTACTS`.

### A0.2 · Add `CODE_OF_CONDUCT.md` · [P0/S]

- Contributor Covenant 2.1.
- **Files:** `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md` (add link)
- **AC:** File present; linked from CONTRIBUTING.md.

### A0.3 · Pin Docker base-image digests · [P0/S]

- `backend/Dockerfile`: replace `golang:1.26-alpine` and `alpine:3.19` tags with `@sha256:<digest>`.
- Add Dependabot entry for `docker` ecosystem.
- **Files:** `backend/Dockerfile`, `.github/dependabot.yml`
- **AC:** Digests pinned; Dependabot config updated.

### A0.4 · Add SBOM generation to GoReleaser · [P0/S]

- `.goreleaser.yml`: add `sboms:` block using `syft`.
- Generate CycloneDX + SPDX JSON per artifact.
- Attach to GitHub release.
- **Files:** `.goreleaser.yml`, `.github/workflows/release.yml`
- **AC:** `make release` dry-run produces `*.sbom.cdx.json` and `*.sbom.spdx.json`.

### A0.5 · Add cosign keyless signing · [P0/S]

- `.goreleaser.yml`: add `signs:` block using `cosign sign-blob --yes` with GitHub OIDC.
- Sign container images in `.github/workflows/release.yml` via `cosign sign --yes <image>@<digest>`.
- Publish signature verification one-liner in README.
- **Files:** `.goreleaser.yml`, `.github/workflows/release.yml`, `README.md`
- **AC:** `cosign verify-blob` + `cosign verify` succeed for a tagged release.

### C0.1 · Document Go minimum toolchain · [P1/S]

- Add to README: "Minimum Go: 1.26. Tested against 1.26.1."
- Add `go` directive in `go.mod` pinning minor version.
- **Files:** `README.md`, `backend/go.mod`
- **AC:** README + go.mod aligned.

### D0.1 · Remove `continue-on-error: true` on E2E job · [P1/S]

- `.github/workflows/ci.yml`: make E2E a required gate on `main`; schedule nightly full matrix separately.
- **Files:** `.github/workflows/ci.yml`
- **AC:** `main` branch protection includes E2E job.

### H0.1 · Publish gosec baseline drift gate · [P1/S]

- Add PR check comparing `gosec-results.json` vs `gosec-baseline.json`.
- Fail PR if new findings exceed baseline.
- Script: `backend/scripts/gosec-compare.py` (already exists — wire into CI).
- **Files:** `.github/workflows/ci.yml`, `.github/workflows/pr-checks.yml`
- **AC:** PR comments show diff; CI fails on net-new HIGH findings.

### E0.1 · Fix audit log "unknown" resource type · [P1/S]

- `backend/internal/middleware/audit.go` `getResourceType()` returns `"unknown"` for endpoints not matching known prefixes (`/api/v1/storage/*`, `/api/v1/setup/*`, admin endpoints).
- Add mappings for all current API route prefixes: `storage`, `setup`, `roles`, `scm-providers`, `webhooks`, `scanning`, `approvals`, `terraform-mirrors`, `binary-mirrors`.
- Ensure future route additions have a corresponding audit resource type (add CI lint or table-driven test).
- **Files:** `backend/internal/middleware/audit.go`, `backend/internal/middleware/audit_test.go`
- **AC:** No audit log entry produced with `resource_type = "unknown"` for any documented API route; regression test covers all route prefixes.
- **Source:** UAT

### E0.2 · Module resync must re-run HCL analyzer · [P1/M]

- Currently, module resync only re-downloads the archive but does **not** re-run the HCL analyzer. Modules uploaded before the analyzer was improved (or with analyzer bugs) are stuck with stale/missing inputs/outputs metadata.
- On resync (or a new "re-analyze" action), re-extract inputs, outputs, provider requirements, and version constraints from the module archive using `backend/internal/analyzer/`.
- Store updated metadata; surface via existing module-version detail API.
- Consider a bulk re-analyze admin endpoint for all versions of a module (or all modules).
- **Files:** `backend/internal/services/module_service.go`, `backend/internal/analyzer/`, `backend/internal/api/module_routes.go`
- **AC:** After resync, previously-missing inputs/outputs appear on the module version detail endpoint; E2E test confirms.
- **Source:** UAT
- **↔ Frontend:** existing ModuleDetailPage already renders inputs/outputs — no frontend change needed if API contract unchanged.

### H0.2 · Streamline release workflow · [P1/M]

- **Problem (from UAT):** Current `CLAUDE.md` release process has high friction — merge conflicts between `prepare-release.yml` output and concurrent feature merges, redundant CI runs (full CI on release branch + again on tag), manual `release.yml` dispatch due to `GITHUB_TOKEN` limitations, and manual Helm/Kustomize image-tag bumps across multiple files (`values-aks.yaml`, `values-eks.yaml`, `values-gke.yaml`, `eks/kustomization.yaml`, `gke/kustomization.yaml`).
- Evaluate and implement best-practice improvements:
  1. **Single-commit release:** `prepare-release.yml` should produce a single atomic commit (CHANGELOG + version bump) directly on `main` via rebase, not a merge-commit PR, to eliminate merge conflicts.
  2. **Tag-triggered release:** Auto-tag on version-bump commit detection (skip manual dispatch); `release.yml` triggers on `v*` tag push.
  3. **Skip redundant CI:** Release workflow should use the CI artifacts from the tag-triggering commit (not re-run lint/test/build). Use `workflow_call` with artifact passthrough or `actions/download-artifact`.
  4. **Auto-bump deployment manifests:** `prepare-release.yml` bumps Helm `Chart.yaml` `appVersion` in the same release commit. Kustomize overlays keep `<IMAGE_TAG>` placeholders (substituted by per-environment CD pipelines via `kustomize edit set image`). Post-release job in `release.yml` opens a cross-repo PR to bump frontend image tag when the backend tag is known.
  5. **Document streamlined flow** in `CLAUDE.md` and `CONTRIBUTING.md`.
- **Files:** `.github/workflows/prepare-release.yml`, `.github/workflows/release.yml`, `.github/workflows/auto-tag.yml`, `CLAUDE.md`, `CONTRIBUTING.md`
- **AC:** Release from merge-to-main to published GitHub Release + pushed Docker image requires ≤1 manual step (approve the auto-PR or click "merge"); no merge conflicts on CHANGELOG; deployment manifests auto-updated.
- **Source:** UAT
- **↔ Frontend H0.3:** Coordinate release cadence and shared deployment-manifest updates.

### F0.1 · Emit business-event Prometheus metrics · [P2/S]

- Add counters: `registry_module_publishes_total{org}`, `registry_provider_publishes_total{org}`, `registry_storage_bytes{org,kind}`, `registry_downloads_total{org,kind}`.
- Wire into existing handlers in `backend/internal/api/`.
- Publish sample Grafana dashboard JSON.
- **Files:** `backend/internal/api/*.go` (handlers), `backend/internal/telemetry/metrics.go`, `docs/observability.md`
- **AC:** Metrics visible on `/metrics`; sample Grafana dashboard JSON in `docs/observability.md`.

---

## Phase 1 — Supply chain + security hardening (parallel tracks)

### Track A — Supply chain

#### A1.1 · Rekor transparency log integration · [P0/M]

- Ensure cosign signatures pushed to public Rekor.
- Document `cosign verify --certificate-identity-regexp` pattern.
- **Files:** `.github/workflows/release.yml`, `docs/deployment.md`
- **AC:** Rekor entry URL printed in release notes.

#### A1.2 · SLSA Level 3 build provenance · [P1/M]

- Upgrade from basic attestation to SLSA L3 via `slsa-framework/slsa-github-generator`.
- Isolated builder, non-falsifiable provenance, signed.
- **Files:** `.github/workflows/release.yml`
- **AC:** `slsa-verifier verify-artifact` passes.

#### A1.3 · Vendor ReDoc + Swagger UI locally · [P1/M]

- Remove CDN dependency (`cdn.jsdelivr.net`) that leaks into air-gapped installs.
- Bundle assets into `backend/docs/embed.go`.
- **Files:** `backend/docs/embed.go`, `backend/cmd/server/main.go`
- **AC:** Air-gap install serves API docs with no external calls.

### Track C — Crypto / FIPS

#### C1.1 · FIPS-140-3 build variant · [P0/L]

- Add `make build-fips` target using Go `GOEXPERIMENT=boringcrypto` (or go-fips toolchain).
- Publish separate `*-fips` binaries and `fips` container tag.
- `/version` endpoint reports `"crypto_mode": "fips" | "standard"`.
- **Files:** `Makefile`, `backend/Dockerfile.fips`, `.goreleaser.yml`, `backend/cmd/server/main.go`
- **AC:** `goversion -m bin/registry-fips` shows boringcrypto; FIPS image tagged and signed.

#### C1.2 · Rotate bcrypt cost + document rationale · [P1/M]

- Confirm bcrypt cost ≥ 12; add ADR `docs/adr/0011-password-hashing.md`.
- Add migration path for upgrading existing hashes on next login.
- **Files:** `backend/internal/auth/apikey.go`, `docs/adr/0011-password-hashing.md`
- **AC:** ADR merged; upgrade path tested.

### Track H — CI hardening

#### H1.1 · Dependency review action + OSV scan on PR · [P1/M]

- Add `actions/dependency-review-action` on PRs.
- Add `osv-scanner` nightly scan of `go.sum`.
- **Files:** `.github/workflows/pr-checks.yml`, `.github/workflows/scheduled-build.yml`
- **AC:** Alerts file new GitHub issues automatically.

#### H1.2 · Add `trivy fs` scan of final image in CI · [P2/S]

- Scan SBOM for CVE >= HIGH; fail build.
- **Files:** `.github/workflows/ci.yml`
- **AC:** CI log shows Trivy summary; gate active.

---

## Phase 2 — Enterprise identity (↔ frontend Track B)

### Track B — Identity

#### B2.1 · SAML 2.0 IdP connector · [P0/L]

- New package `backend/internal/auth/saml/` using `crewjam/saml`.
- Support SP-initiated + IdP-initiated flows.
- Metadata endpoint `/auth/saml/metadata`; ACS at `/auth/saml/acs`.
- Group claim → scope mapping reusing existing role-template model.
- Config: multiple IdPs per deployment; per-org IdP binding optional.
- **Files:** `backend/internal/auth/saml/*.go`, `backend/internal/config/config.go`, `backend/internal/api/auth_routes.go`
- **AC:** Tested against Okta, Entra ID SAML, ADFS, Ping; integration test in `cmd/api-test`.
- **↔ Frontend B2.1:** Login page provider-picker must list SAML IdPs.

#### B2.2 · LDAP / Active Directory connector · [P0/L]

- New package `backend/internal/auth/ldap/` using `go-ldap/ldap`.
- Simple bind + StartTLS/LDAPS; group lookup via `memberOf` or nested-group search.
- Connection pooling + failover across multiple DCs.
- Group-DN → scope mapping.
- **Files:** `backend/internal/auth/ldap/*.go`, `backend/internal/config/config.go`, `backend/internal/api/auth_routes.go`
- **AC:** Tested against OpenLDAP + Active Directory; CI integration test with `osixia/docker-openldap`.

#### B2.3 · SCIM 2.0 provisioning endpoints · [P0/L]

- Implement `/scim/v2/Users`, `/scim/v2/Groups` per RFC 7644.
- Token-authenticated per-IdP; scope `admin` or new `scim:provision`.
- JIT deprovisioning (deactivate on SCIM delete; soft-delete users).
- **Files:** `backend/internal/api/scim/*.go`, `backend/internal/auth/scopes.go`, `backend/internal/db/models/user.go`
- **AC:** Okta + Entra SCIM connectors successfully provision/deprovision; integration test in CI.
- **↔ Frontend B2.3:** SCIM admin page.

#### B2.4 · OIDC refresh token + silent renew · [P1/M]

- Implement refresh-token rotation in `internal/auth/oidc/`.
- Add `/auth/refresh` endpoint.
- Set auth token as `HttpOnly; Secure; SameSite=Strict` cookie.
- Add double-submit CSRF pattern: non-HttpOnly `csrf` cookie + `X-CSRF-Token` header validation on mutating requests.
- **Files:** `backend/internal/auth/oidc/provider.go`, `backend/internal/middleware/csrf.go`, `backend/internal/api/auth_routes.go`
- **AC:** Token auto-refreshes before expiry; compatible with Entra, Okta, Auth0, Keycloak. Frontend httpOnly migration unblocked.
- **↔ Frontend A1.1:** httpOnly cookie auth migration.

#### B2.5 · Per-principal rate limiting · [P1/M]

- Extend `middleware/ratelimit.go` with token bucket keyed by `user_id` or `api_key_id`.
- Allow admin override per org.
- **Files:** `backend/internal/middleware/ratelimit.go`, `backend/internal/config/config.go`
- **AC:** Compromised API key cannot DoS; new metric `registry_ratelimit_exceeded_total{principal_type}`.

#### B2.6 · mTLS client authentication · [P2/M]

- Optional mTLS mode for machine-to-machine callers.
- Cert-subject → scope mapping via config.
- **Files:** `backend/internal/auth/mtls/*.go`, `backend/internal/config/config.go`
- **AC:** `terraform init` with `--client-cert` succeeds end-to-end.

---

## Phase 3 — Compliance + operability (parallel tracks)

### Track C — Compliance

#### C3.1 · Air-gapped install guide · [P0/L]

- New `docs/air-gap-install.md`: offline image bundle via `docker save`, scanner-DB pre-seeding (Trivy offline DB, Checkov rules), internal CA trust, private module upstream config.
- `make airgap-bundle` target producing tarball.
- **Files:** `docs/air-gap-install.md`, `Makefile`, `scripts/airgap-bundle.sh`
- **AC:** Clean-room test on an egress-blocked VM; success recorded.

#### C3.2 · Published threat model (STRIDE) · [P0/M]

- Create `docs/threat-model.md` with DFD, trust boundaries, mitigations per STRIDE category.
- Include assumptions + residual risks.
- **Files:** `docs/threat-model.md`, `SECURITY.md` (add link)
- **AC:** Reviewed by external security reviewer; linked from SECURITY.md.

#### C3.3 · SOC2 / ISO27001 control mapping · [P1/L]

- `docs/compliance/soc2-mapping.md` + `docs/compliance/iso27001-mapping.md` with control → feature → evidence source.
- Audit log immutability (append-only; periodic hash-chain export).
- Legal-hold API to prevent cleanup job from deleting flagged logs.
- Audit-log export endpoint: NDJSON or OCSF format.
- **Files:** `docs/compliance/*.md`, `backend/internal/audit/export.go`, `backend/internal/audit/legal_hold.go`, `backend/internal/api/audit_routes.go`
- **AC:** Mapping reviewed; immutability test in CI.

#### C3.4 · GDPR / data-subject tooling · [P1/M]

- `/admin/users/:id/export` (JSON data export).
- `/admin/users/:id/erase` (tombstone user records, preserve audit trail per regulation).
- **Files:** `backend/internal/api/user_routes.go`, `backend/internal/services/user_service.go`
- **AC:** Integration tests confirm behavior.

#### C3.5 · Data residency + multi-region DR documentation · [P2/M]

- Document: single-region, multi-region-active-passive, multi-region-active-active storage strategies.
- Add example Terraform for cross-region PG replica + S3 CRR.
- **Files:** `docs/data-residency.md`, `deployments/terraform/aws/multi-region/`
- **AC:** `deployments/terraform/aws/multi-region/` sample.

### Track D — Operability

#### D3.1 · Version upgrade runbook · [P0/M]

- `docs/upgrade-guide.md`: per-version breaking changes, migration behavior, rollback strategy, pre-flight checks.
- Add `registry upgrade preflight` CLI subcommand that validates DB state before a version jump.
- **Files:** `docs/upgrade-guide.md`, `backend/cmd/server/upgrade.go`
- **AC:** Dry-run upgrade from 0.6.x → 0.7.x documented + tested.

#### D3.2 · Validated DR drill runbook with RPO/RTO numbers · [P0/M]

- Execute timed restore from pg_dump + object-store snapshot.
- Record RPO (target: <15min) / RTO (target: <2h).
- Publish results in `docs/disaster-recovery.md`.
- **Files:** `docs/disaster-recovery.md`, `scripts/dr-drill.sh`
- **AC:** Drill log appended; automation script in `scripts/dr-drill.sh`.

#### D3.3 · Chaos / soak test suite · [P1/L]

- New `cmd/chaos-test/` binary that injects failures: Redis down, S3 5xx, PG connection storm.
- Nightly workflow `.github/workflows/chaos.yml`.
- **Files:** `cmd/chaos-test/*.go`, `.github/workflows/chaos.yml`
- **AC:** Pass rate > 95% for 24h soak on a canary environment.

#### D3.4 · Per-org quotas + chargeback metrics · [P1/M]

- New table `org_quotas` (storage_bytes_limit, publishes_per_day, downloads_per_day).
- Soft-warn at 80%, hard-deny at 100%.
- Prometheus: `registry_quota_utilization_ratio{org,resource}`.
- **Files:** `backend/internal/db/models/org_quota.go`, `backend/internal/db/migrations/025_*.up.sql`, `backend/internal/middleware/quota.go`, `backend/internal/api/admin_routes.go`
- **AC:** E2E test: quota breach returns 429 with `X-Quota-Reset` header.
- **↔ Frontend E4.4:** Quota dashboard.

#### D3.5 · Backup-to-object-store automation · [P2/M]

- Scheduled job inside registry (or separate sidecar) performing `pg_dump` to S3/Blob/GCS with lifecycle retention.
- Encryption with KMS key.
- **Files:** `backend/internal/jobs/backup_job.go`, `backend/internal/config/config.go`
- **AC:** Scheduled backup tested; restore validated.

### Track G — Data layer

#### G3.1 · Optional MySQL support · [P2/L]

- Abstract queries in `backend/internal/db/` behind dialect interface.
- Add MySQL migrations (parallel to PG set).
- Publish `values-mysql.yaml` Helm variant.
- **Files:** `backend/internal/db/dialect_*.go`, `backend/internal/db/migrations_mysql/`, `deployments/helm/values-mysql.yaml`
- **AC:** CI matrix includes MySQL; all tests pass.

#### G3.2 · Migration rollback documentation · [P1/M]

- For each of 24 migrations, document whether reversible + rollback steps.
- **Files:** `backend/internal/db/migrations/README.md`
- **AC:** Doc merged; referenced from upgrade-guide.

---

## Phase 4 — Feature expansion (parallel tracks)

### Track E — Protocol & features

#### E4.1 · Module deprecation API · [P0/L]

- Per Terraform CLI ≥1.10 spec: registry returns `deprecation` block on module versions.
- New fields on `modules_versions`: `deprecated`, `deprecation_reason`, `replacement_source`.
- Admin API endpoints for deprecation CRUD.
- `terraform init` surfaces warning.
- **Files:** `backend/internal/db/models/module_version.go`, `backend/internal/db/migrations/026_*.up.sql`, `backend/internal/api/module_routes.go`
- **AC:** `terraform init` prints deprecation notice; API conformance test.
- **↔ Frontend E4.1:** Deprecation banner on module detail page; admin toggle.

#### E4.2 · OCI distribution endpoint for modules · [P1/L]

- Add `backend/internal/api/oci/` implementing OCI distribution spec v1.1.
- Modules mirror-pushable/pullable as OCI artifacts (media type `application/vnd.opentofu.modulepkg`).
- **Files:** `backend/internal/api/oci/*.go`, `backend/internal/api/routes.go`
- **AC:** `oras push` + `oras pull` round-trip succeeds; Harbor federation tested.
- **↔ Frontend E4.5:** OCI pull snippet on module detail.

#### E4.3 · Policy engine integration (OPA/Rego + Conftest) · [P1/L]

- New `backend/internal/policy/` evaluates Rego bundles on module publish + on consumer metadata endpoint.
- Admin-configurable bundle sources (OCI, HTTP, S3).
- Block/warn modes per policy.
- **Files:** `backend/internal/policy/*.go`, `backend/internal/config/config.go`, `backend/internal/api/module_routes.go`
- **AC:** Example "no public S3 buckets" policy blocks non-compliant upload.
- **↔ Frontend E4.2:** Policy results in upload flow.

#### E4.4 · Module test orchestration on publish · [P1/L]

- Trigger ephemeral `terraform init && terraform validate && terraform test` sandbox against declared examples on upload.
- Store results alongside version metadata.
- Sandbox: ephemeral container with no cloud credentials (validate-only) OR optional cloud-creds runner per org.
- **Files:** `backend/internal/jobs/module_test_job.go`, `backend/internal/services/module_service.go`
- **AC:** Malformed example blocks publish with clear error.
- **↔ Frontend E4.3:** Test results UI.

#### E4.5 · Inbound webhook / run-task approval surface · [P2/M]

- Add `/webhooks/approvals/:token` endpoint for external CI systems to approve pending publishes.
- Signed tokens, single-use.
- **Files:** `backend/internal/api/webhook_routes.go`, `backend/internal/services/approval_service.go`
- **AC:** Jenkins/GitHub Actions approval round-trip tested.

#### E4.6 · Optional mTLS / IP allowlist on binary mirror · [P2/M]

- `config.yaml`: `binary_mirror.auth: none|allowlist|mtls`.
- **Files:** `backend/internal/config/config.go`, `backend/internal/middleware/binary_mirror_auth.go`
- **AC:** Locked-down mode rejects anonymous; open mode preserves protocol compliance.

#### E4.7 · Bulk namespace import tooling · [P2/M]

- New `cmd/registry-import/` CLI: given a public namespace, mirror all modules/versions into the registry.
- Respects pull-through cache.
- **Files:** `backend/cmd/registry-import/*.go`
- **AC:** Import `terraform-aws-modules` end-to-end; idempotent reruns.

### Track F — Observability extensions

#### F4.1 · Trace-based SLO dashboards · [P1/M]

- Exemplar wiring between metrics and OTel traces.
- Publish Grafana dashboard + Prometheus recording rules.
- **Files:** `deployments/observability/grafana-dashboard.json`, `deployments/observability/recording-rules.yml`
- **AC:** Dashboards render; p95 latency alert rule firing tested.

#### F4.2 · Structured audit log export (OCSF) · [P2/M]

- Convert audit events to OCSF JSON on export endpoint.
- **Files:** `backend/internal/audit/ocsf_exporter.go`, `backend/internal/api/audit_routes.go`
- **AC:** Splunk/Elastic-ingestible sample verified.

---

## Phase 5 — Continuous hardening (ongoing)

### H5.1 · Fuzz testing on parsers · [P2/M]

- `go test -fuzz` targets for HCL parser, provider-binary unpacker, SCM webhook payload parsers.
- Nightly workflow.
- **Files:** `backend/internal/analyzer/*_fuzz_test.go`, `backend/internal/scm/*_fuzz_test.go`, `.github/workflows/fuzz.yml`
- **AC:** Corpus committed; CI runs 10min fuzz per target.

### H5.2 · Coverage floor raise · [P2/M]

- Raise backend coverage floor from 80% → 85% over two minor versions.
- **Files:** `.github/workflows/ci.yml`
- **AC:** CI threshold updated; deltas tracked.

### H5.3 · `CODEOWNERS` auto-request on ADR/docs changes · [P3/S]

- Ensure security-sensitive paths require security team review.
- **Files:** `.github/CODEOWNERS`
- **AC:** Test PR blocked until security approver reviews.

---

## Milestones

| Version    | Target content                                                           |
| ---------- | ------------------------------------------------------------------------ |
| **0.8.0**  | Phase 0 complete + Phase 1 Tracks A, C, H                                |
| **0.9.0**  | Phase 2 (SAML + LDAP + SCIM + refresh tokens + httpOnly cookies)         |
| **0.10.0** | Phase 3 (compliance + operability + migration rollback docs)             |
| **0.11.0** | Phase 4 Track E items E4.1, E4.3, E4.4                                   |
| **1.0.0**  | All P0/P1 items complete; FIPS variant published; SOC2 mapping published |

---

## Scope boundaries

**Included:** Backend server, protocol implementations, deployment artifacts under this repo.

**Explicitly excluded:** Frontend UI changes (see `terraform-registry-frontend/ROADMAP.md`), terraform-pipeline-templates changes, third-party scanner internals.

---

## How to contribute to this roadmap

1. Pick an item by ID (e.g., `B2.1`).
2. Open an issue titled `[roadmap:B2.1] <short title>`; link the roadmap line.
3. Submit PR referencing the issue and update this file's checkbox when merged.
4. Cross-repo items (`↔`) must coordinate via linked issues to `terraform-registry-frontend`.
