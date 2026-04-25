# CLAUDE.md — Terraform Registry Backend

## Development Workflow

All changes follow this workflow. Do not deviate from it.

### Branches

- `main` — the single long-lived branch. All work branches off `main`; all PRs target `main`.
  **Must always exist — never delete.**
- Feature/fix branches are created from `main` and deleted after their PR is squash-merged.

```bash
# After a feature/fix PR is merged:
git push origin --delete fix/short-description   # remove remote branch
git branch -d fix/short-description              # remove local branch
git remote prune origin                          # prune stale remote-tracking refs
```

### Conventional Commits

PR titles (and ideally commit messages) must follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<optional scope>): <description>
```

| Type | When to use | Version bump |
| ---- | ----------- | ------------ |
| `feat` | New user-facing feature | minor |
| `fix` | Bug fix | patch |
| `perf` | Performance improvement | patch |
| `refactor` | Code restructure (no behavior change) | none |
| `docs` | Documentation only | none |
| `test` | Adding or fixing tests | none |
| `ci` | CI/CD workflow changes | none |
| `chore` | Maintenance, deps, tooling | none |
| `deps` | Dependency updates | none |
| `security` | Security fix | patch |
| `revert` | Reverts a previous commit | patch |

Breaking changes: append `!` to the type (`feat!:`) **or** add a `BREAKING CHANGE:` footer.
These trigger a **major** version bump.

### Step-by-step

1. **Open a GitHub issue** describing the bug or feature before writing any code.

2. **Create a branch from `main`**:

   ```bash
   git fetch origin
   git checkout -b fix/short-description origin/main
   # or: feat/short-description, docs/topic, etc.
   ```

3. **Implement the change.**

4. **Before committing — run the full local quality gate** (CI will reject anything that fails these):

   ```bash
   cd backend

   # Format & vet
   go fmt ./...
   go vet ./...

   # Tests with coverage (must stay ≥ 80%) When looking for additional functions to test, skip functions with "// coverage:skip:{REASON}"
   # If you find functions with out coverage that cannot be easily tested, add the comment above. This will help you focus on functions that
   # can easily be tested.
   go test ./internal/... ./pkg/... -coverprofile=coverage.out -covermode=atomic
   go run ./scripts/coverfilter -in coverage.out -out coverage.filtered.out -root .
   go tool cover -func=coverage.filtered.out | grep "^total:"

   # Security scan — fix or suppress new findings before pushing
   # Linux/CI:
   gosec -fmt=json -out=gosec-results.json ./...
   # Windows (paths must be quoted):
   # gosec -fmt=json -out="gosec-results.json" "./..."
   #
   # Compare against committed baseline to detect new findings
   python scripts/gosec-compare.py --results gosec-results.json --baseline gosec-baseline.json --base-dir .
   # If the baseline needs updating (after fixing or suppressing findings):
   # Linux: bash scripts/update-gosec-baseline.sh
   # Windows: gosec -fmt=json -out="gosec-baseline.json" "./..."
   ```

   Do not push until all of the above pass locally.

5. **Commit — no co-author attribution**:

   ```bash
   git add <specific files>
   git commit -m "fix: short description of what was fixed

   Closes #<issue-number>"
   ```

   Do not add `Co-Authored-By:` trailers or `🤖 Generated with [Claude Code]` footers to commit messages or PR bodies.

6. **Push to origin**:

   ```bash
   git push -u origin fix/short-description
   ```

7. **Open a PR targeting `main`**:

   ```bash
   gh pr create --base main --title "fix: short description" --body "Closes #<issue>"
   ```

   - PR title must follow Conventional Commits — enforced by `pr-checks.yml`.
   - Squash-merge into `main` when approved.

### Parallel agents — coordination rules

When multiple agents run concurrently, follow these rules to avoid conflicts:

- **Never assign two agents to work on the same files at the same time.** If their scopes overlap (e.g. both touch the same handler or config file), serialise them.
- **Do not edit `CHANGELOG.md` in any branch.** It is bot-maintained by release-please; manual edits will conflict.
- **Each agent rebases on `origin/main` immediately before pushing.** After any sibling PR is merged, remaining open branches must rebase again before their own merge.

### Releasing a version

Releases are fully automated via `release-please.yml`. See [RELEASING.md](RELEASING.md) for complete documentation.

**Short version:**

1. **Merge feature/fix PRs to `main`** using Conventional Commit titles.

2. **release-please maintains an open release PR** titled `chore(main): release X.Y.Z`.
   It auto-updates `CHANGELOG.md` and `deployments/helm/Chart.yaml` as commits accumulate.
   Review it at any time to see what will ship.

3. **When ready to release**, review and **squash-merge** the release-please PR.
   That is the only required human action — no manual dispatch.

4. **`release.yml` fires automatically** from the tag pushed by the GitHub App.
   It runs CI, builds Go binaries via GoReleaser, pushes the Docker image to ghcr.io,
   attaches SLSA Level 3 provenance, signs with cosign, creates the GitHub Release,
   and updates the wiki version badge.

#### Hotfix flow

Create a `fix/` branch from `main`, merge with a `fix:` commit title. release-please
bumps the patch version in the open release PR. Merge the release PR to ship.

#### Manual fallback

If `release-please.yml` fails, see [RELEASING.md](RELEASING.md) for the manual procedure.

---

## Project Overview

An enterprise-grade private Terraform Registry implementing all three HashiCorp protocols:

- **Module Registry Protocol** (`/v1/modules/`)
- **Provider Registry Protocol** (`/v1/providers/`)
- **Provider Network Mirror Protocol** (`/v1/mirror/`)

Current version: **v0.8.2**. All phases 1–6 complete; Phase 7 (testing & documentation) in progress.

Frontend UI lives in a separate repository: [terraform-registry-frontend](https://github.com/sethbacon/terraform-registry-frontend)

---

## Repository Structure

```txt
terraform-registry-backend/
├── backend/                  # Go 1.26 backend service
│   ├── cmd/                  # Entry points (server, check-db, fix-migration, hash, test-api)
│   ├── internal/
│   │   ├── api/              # Gin HTTP handlers (modules, providers, mirror, admin, webhooks)
│   │   ├── auth/             # JWT, API keys, OIDC, Azure AD
│   │   ├── storage/          # Pluggable backends (local, azure, s3, gcs)
│   │   ├── db/               # PostgreSQL layer (sqlx, golang-migrate, models, repositories)
│   │   ├── middleware/        # Auth, RBAC, audit, rate limiting, security headers
│   │   ├── jobs/             # Background jobs (mirror sync, tag verifier)
│   │   ├── services/         # Business logic (scm_publisher)
│   │   ├── scm/              # SCM connectors (GitHub, GitLab, Azure DevOps, Bitbucket)
│   │   ├── mirror/           # Upstream registry client
│   │   ├── validation/       # Archive, GPG, semver, README extraction
│   │   ├── crypto/           # AES-256 token encryption
│   │   ├── config/           # Viper-based configuration
│   │   └── audit/            # Audit logging
│   ├── pkg/checksum/         # Public checksum utilities
│   ├── Dockerfile            # Multi-stage Go build
│   ├── go.mod                # Go 1.26.1
│   └── config.example.yaml   # Configuration template
├── deployments/              # Docker Compose, Kubernetes, Helm, Bicep, CloudFormation, Terraform IaC
├── docs/                     # API quick reference, authentication guide, architecture, etc.
├── scripts/                  # Utility scripts
├── test-modules/             # Sample Terraform modules
├── test-providers/           # Sample demo provider
├── test-terraform/           # Terraform configuration examples
└── azure-devops-extension/   # Azure DevOps extension (deferred/WIP)
```

---

## Tech Stack

### Backend Stack

| Concern        | Technology                                                         |
| -------------- | ------------------------------------------------------------------ |
| Language       | Go 1.26.1                                                          |
| HTTP Framework | Gin                                                                |
| Database       | PostgreSQL 14+ via sqlx                                            |
| Migrations     | golang-migrate (24 migrations (000001–000024))                     |
| Auth           | JWT (golang-jwt/jwt v5), API keys, OIDC (coreos/go-oidc), Azure AD |
| Config         | Viper (`TFR_` env prefix overrides YAML)                           |
| Storage        | Local filesystem, Azure Blob, S3-compatible, GCS                   |
| GPG            | ProtonMail/go-crypto                                               |
| Encryption     | AES-256 (golang.org/x/crypto)                                      |
| Semver         | hashicorp/go-version                                               |
| UUID           | google/uuid                                                        |

---

## Common Commands

### Backend

```bash
cd backend

# Install dependencies
go mod download

# Run database migrations (also runs automatically on server start)
go run cmd/server/main.go migrate up

# Start development server
go run cmd/server/main.go serve

# Run all tests
go test ./...

# Build production binary
go build -o terraform-registry ./cmd/server

# Cross-compile for Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o terraform-registry ./cmd/server

# Format code
go fmt ./...

# Vet code
go vet ./...

# Utility tools
go run cmd/check-db/main.go                                           # Test database connectivity
go run cmd/fix-migration/main.go --dry-run                            # Preview dirty migration state
go run cmd/fix-migration/main.go                                      # Repair dirty migration state
go run cmd/hash/main.go -key <api-key>                                # Generate API key hash
go build -o api-test.exe ./cmd/api-test && ./api-test.exe -url <url> -key <key>  # End-to-end API smoke test
```

### Docker Compose (Quickstart)

```bash
cd deployments

# Development (starts backend + postgres; use frontend repo for UI)
docker-compose up -d

# Production
docker-compose -f docker-compose.prod.yml up -d
```

---

## Configuration

Copy and edit the template before running the backend:

```bash
cp backend/config.example.yaml backend/config.yaml
```

Key environment variables (all prefixed `TFR_`):

```bash
# Database
TFR_DATABASE_HOST=localhost
TFR_DATABASE_PORT=5432
TFR_DATABASE_NAME=terraform_registry
TFR_DATABASE_USER=registry
TFR_DATABASE_PASSWORD=<password>
TFR_DATABASE_SSL_MODE=disable

# Server
TFR_SERVER_HOST=0.0.0.0
TFR_SERVER_PORT=8080
TFR_SERVER_BASE_URL=http://localhost:8080

# Storage backend: local | azure | s3 | gcs
TFR_STORAGE_DEFAULT_BACKEND=local
TFR_STORAGE_LOCAL_BASE_PATH=/app/storage

# Security (required in production)
TFR_JWT_SECRET=<openssl rand -hex 32>
ENCRYPTION_KEY=<32-byte key>

# Auth providers
TFR_AUTH_API_KEYS_ENABLED=true
TFR_AUTH_OIDC_ENABLED=false
TFR_AUTH_AZURE_AD_ENABLED=false

# Multi-tenancy
TFR_MULTI_TENANCY_ENABLED=false
TFR_MULTI_TENANCY_DEFAULT_ORGANIZATION=default

# Telemetry / Prometheus
TFR_TELEMETRY_ENABLED=true
TFR_TELEMETRY_METRICS_PROMETHEUS_PORT=9090
```

---

## Architecture Conventions

### Backend Layering

```txt
HTTP Handler (api/)
  → Middleware chain: Auth → RBAC → Audit → Security
  → Service / Repository (services/, db/repositories/)
  → Database (db/models/, PostgreSQL)
  → Storage Backend (storage/)
```

- **Factory pattern** for storage backends and SCM connectors.
- **Repository pattern** for all database access — never query the DB directly from handlers.
- **Interface-based** storage abstraction; add new backends by implementing `storage.Backend`.
- **UUID primary keys** throughout for distributed compatibility.
- **JSONB columns** used for flexible fields (scopes, configs).
- All responses follow a consistent JSON envelope; errors include `status` and `message`.

### Database

- 24 migrations (000001–000024) in `backend/internal/db/migrations/`.
- Migrations run automatically at startup; use `migrate up/down` for manual control.
- Always add a new migration file rather than editing existing ones.

### API Endpoints (summary)

- Service discovery: `GET /.well-known/terraform.json`
- Modules: `GET|POST /v1/modules/`
- Providers: `GET|POST /v1/providers/`
- Mirror: `GET /v1/mirror/`
- Admin: `GET|POST|PUT|DELETE /v1/admin/{users,organizations,roles,mirrors,...}`
- All versioned routes under `/v1/`.

---

## Authentication & Authorization

- **JWT** — issued at login, stateless, short-lived.
- **API Keys** — scoped bearer tokens for CI/CD; hashed in the database.
- **RBAC** — roles assigned per organization; scopes include `modules:read`, `modules:write`, `providers:read`, `providers:write`, `mirrors:manage`, `admin:*`, etc.
- **OIDC** — generic OpenID Connect provider support. Can be configured via setup wizard (DB-stored, encrypted) or config file.
- **Azure AD / Entra ID** — dedicated integration with group-to-role mapping.
- **Setup Token** — one-time `Authorization: SetupToken <token>` scheme for first-run configuration. Separate from JWT/API key auth.
- Audit logs record every mutating action with user ID, IP, and timestamp.

### Setup Wizard (First-Run)

- On first startup, a one-time setup token is generated and printed to logs.
- Setup endpoints (`/api/v1/setup/*`) are authenticated via `SetupTokenMiddleware`.
- Configured OIDC is stored encrypted in `oidc_config` table (DB takes precedence over config file).
- OIDC provider is swapped at runtime via `atomic.Pointer` — no restart required.
- After `POST /api/v1/setup/complete`, setup token is invalidated and endpoints return 403 permanently.
- Pre-provisioned admin user is linked to OIDC identity on first login via email matching in `GetOrCreateUserFromOIDC`.
- See `docs/initial-setup.md` for full documentation.

---

## Storage Backends

Configured via `TFR_STORAGE_DEFAULT_BACKEND`. Implement `storage.Backend` interface to add backends.

| Backend              | Config Prefix         |
| -------------------- | --------------------- |
| Local filesystem     | `TFR_STORAGE_LOCAL_*` |
| Azure Blob Storage   | `TFR_STORAGE_AZURE_*` |
| AWS S3 / compatible  | `TFR_STORAGE_S3_*`    |
| Google Cloud Storage | `TFR_STORAGE_GCS_*`   |

---

## SCM Integrations

Webhook-based automatic publishing triggered by Git tags. Supported:

- **GitHub** — `internal/scm/github/`
- **GitLab** — `internal/scm/gitlab/`
- **Azure DevOps** — `internal/scm/azuredevops/`
- **Bitbucket** — `internal/scm/bitbucket/`

Add new SCM providers by implementing the SCM interface and registering in `internal/scm/factory.go`.

---

## Deployment Options

| Option                        | Location                              |
| ----------------------------- | ------------------------------------- |
| Docker Compose (dev)          | `deployments/docker-compose.yml`      |
| Docker Compose (prod)         | `deployments/docker-compose.prod.yml` |
| Standalone binary + systemd   | `deployments/binary/`                 |
| Kubernetes + Kustomize        | `deployments/kubernetes/`             |
| Helm Chart                    | `deployments/helm/`                   |
| Azure Container Apps          | `deployments/azure-container-apps/`   |
| AWS ECS                       | `deployments/aws-ecs/`                |
| Google Cloud Run              | `deployments/google-cloud-run/`       |
| Terraform IaC (AWS/Azure/GCP) | `deployments/terraform/`              |

---

## API Documentation (Swagger / OpenAPI)

The backend generates OpenAPI 2.0 (Swagger) documentation using [swaggo/swag](https://github.com/swaggo/swag) annotations in handler source code.

**Architecture:**

- Swagger annotations live in Go handler files as `// @` comments
- `swag init -g cmd/server/main.go --outputTypes json` generates `backend/docs/swagger.json`
- The JSON spec is embedded into the binary at compile time via `go:embed`
- The backend serves it at `GET /swagger.json`
- A standalone Swagger UI is served at `/api-docs/` via CDN

**Annotation rules (mandatory):**

- **Every new handler** must have a complete annotation block before it is committed.
- **Every modified handler** must have its annotation block updated to match.
- Use `// @Security     Bearer` for authenticated endpoints.
- Use `{param}` in `@Router` paths (swag style), not `:param` (Gin style).
- All `@Tags` values must be title-cased and drawn from the established vocabulary:
  `Authentication`, `API Keys`, `Users`, `Organizations`, `Modules`, `Providers`,
  `Security Scanning`, `Storage`, `SCM Providers`, `SCM OAuth`, `SCM Linking`,
  `Mirror`, `Mirror Protocol`, `RBAC`, `Stats`, `System`, `Webhooks`, `SCIM`
- After adding or changing any annotation, run `swag init` and update `docs/SWAGGER_ANNOTATION_CHECKLIST.md`.

**Annotation template:**

```go
// @Summary      Short one-line summary
// @Description  Longer description of what this endpoint does.
// @Tags         TagName
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path    string  true   "Resource ID (UUID)"
// @Param        body  body    SomeRequestType  true  "Request payload"
// @Success      200  {object}  SomeResponseType
// @Failure      400  {object}  map[string]interface{}  "Bad request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      404  {object}  map[string]interface{}  "Not found"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/resource/{id} [get]
func (h *Handler) MethodName(c *gin.Context) {
```

---

## Development Notes

- CI/CD pipelines are configured in `.github/workflows/` (ci.yml, release.yml, release-please.yml, weekly-security.yml).
- No `.golangci.yml` is present; use `go fmt` and `go vet` manually.
- The `azure-devops-extension/` directory is deferred/work-in-progress.
- `test-modules/`, `test-providers/`, and `test-terraform/` contain sample artifacts for local testing.
- `CHANGELOG.md` tracks version history.

---

## Repository Security Hardening (applied 2026-04-09)

### Branch Protection

**`main` branch:**
- Required status checks (strict — branch must be up-to-date): `Backend Tests & Quality`, `Security Scan (gosec)`, `Docker Build Smoke Test`, `Deployment Config Validation`, `Conventional PR Title`
- Required pull request reviews: 1 approving review, dismiss stale reviews, require code owner review
- Enforce admins: no (admin/owner can bypass review requirements as sole maintainer)
- Required conversation resolution: yes
- Force pushes: blocked
- Branch deletion: blocked
- `terraform-registry-release-bot` GitHub App is allowed to bypass for release commits and tags

### Merge Strategy

- **Squash merge** — all feature/fix branches → `main`
- **Rebase merges** — disabled
- **Merge commits** — disabled
- **Delete branch on merge** — enabled; feature/fix branches are cleaned up automatically
- **Allow update branch** — enabled; PRs can pull in base branch changes via GitHub UI
- **Web commit signoff required** — enabled; all web-based commits require DCO signoff

> **GitHub repo settings required:** "Allow squash merging" must be enabled.
> "Allow merge commits" and "Allow rebase merging" remain disabled.

### Dependency Management

- **Dependabot vulnerability alerts** — enabled
- **Dependabot automated security fixes** — enabled
- **Dependabot version updates** — configured via `.github/dependabot.yml` for Go modules and GitHub Actions (biweekly)

### Code Ownership

- **CODEOWNERS** file at `.github/CODEOWNERS` — `@sethbacon` owns all files; `backend/`, `.github/`, `deployments/`, and `.goreleaser.yml` require explicit owner review

### Security Features (GitHub)

- Secret scanning: enabled
- Secret scanning push protection: enabled
- gosec security scanning in CI with baseline tracking
- golangci-lint static analysis in CI
- `go vet` and race-detector-enabled tests in CI
- All GitHub Actions pinned to full commit SHAs
- Scheduled weekly builds with auto-issue on failure
- **SLSA provenance attestation** on Docker images and GoReleaser binaries via `actions/attest-build-provenance`
- **SBOM generation** via syft in GoReleaser (`sboms:` block)
- **Cosign keyless signing** on Docker images and checksum files via Sigstore (verify with `cosign verify`)

### Repository Topics

`terraform`, `terraform-registry`, `go`, `gin`, `postgresql`, `infrastructure-as-code`, `private-registry`

### Remaining Recommendations (not yet applied)

- **Enable secret scanning non-provider patterns and validity checks** for broader secret detection
