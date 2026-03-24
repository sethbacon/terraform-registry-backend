# CLAUDE.md — Terraform Registry Backend

## Development Workflow

All changes follow this workflow. Do not deviate from it.

### Branches

- `main` — production-ready, tagged releases only. **Must always exist — never delete.**
- `development` — integration branch; all feature/fix branches merge here first. **Must always exist — never delete.**
- Feature/fix branches are created from `development`, never from `main`. Delete them from remote after their PR is merged; clean up locally with `git branch -d`.

```bash
# After a feature/fix PR is merged:
git push origin --delete fix/short-description   # remove remote branch
git branch -d fix/short-description              # remove local branch
git remote prune origin                          # prune stale remote-tracking refs
```

### Step-by-step

1. **Open a GitHub issue** describing the bug or feature before writing any code.

2. **Create a branch from `development`**:

   ```bash
   git fetch origin
   git checkout -b fix/short-description origin/development
   # or: feature/short-description
   ```

3. **Implement the change.**

4. **Before committing — run the full local quality gate** (CI will reject anything that fails these):

   ```bash
   cd backend

   # Format & vet
   go fmt ./...
   go vet ./...

   # Tests with coverage (must stay ≥ 65%)
   go test ./... -coverprofile=coverage.out -covermode=atomic
   go tool cover -func=coverage.out | grep "^total:"

   # Security scan — fix or suppress new findings before pushing
   gosec ./...
   ```

   Do not push until all of the above pass locally.

5. **Commit — no co-author attribution**:

   ```bash
   git add <specific files>
   git commit -m "fix: short description of what was fixed

   Closes #<issue-number>"
   ```

   Do not add `Co-Authored-By:` trailers or `🤖 Generated with [Claude Code]` footers to commit messages or PR bodies.

6. **Rebase onto `development` before pushing** to minimise merge conflicts with sibling branches:

   ```bash
   git fetch origin
   git rebase origin/development
   ```

7. **Push to origin**:

   ```bash
   git push -u origin fix/short-description
   ```

8. **Open a PR from the feature branch → `development`**:

   Include a `## Changelog` section in the PR body with the entry that should appear in `CHANGELOG.md` for this change (format: `- type: description`). **Do not edit `CHANGELOG.md` in the branch** — changelog entries are collected from merged PR bodies at release time.

   ```bash
   gh pr create --base development --title "fix: short description" --body "$(cat <<'EOF'
   Closes #<issue>

   ## Changelog
   - fix: short description of what was fixed
   EOF
   )"
   ```

   - Squash-merge into `development` when approved.

9. **Open a PR from `development` → `main`** when the integration branch is ready to ship:

   ```bash
   gh pr create --base main --title "chore: release vX.Y.Z" --body "..."
   ```

### Parallel agents — coordination rules

When multiple agents run concurrently, follow these rules to avoid conflicts:

- **Never assign two agents to work on the same files at the same time.** If their scopes overlap (e.g. both touch the same handler or config file), serialise them.
- **Do not edit `CHANGELOG.md` in any branch.** Changelog entries live in PR bodies only (see step 8 above). This eliminates the most common parallel-agent conflict.
- **Each agent rebases on `origin/development` immediately before pushing** (step 6 above). After any sibling PR is merged, remaining open branches must rebase again before their own merge.

### Releasing a version

When a release is called for:

1. Collect the `## Changelog` sections from all PR bodies merged since the last release.

2. Update `CHANGELOG.md` on `development` — promote `[Unreleased]` to the new version with today's date and paste the collected entries:

   ```markdown
   ## [X.Y.Z] - YYYY-MM-DD
   ### Fixed
   - fix: ...
   ### Added
   - feat: ...
   ```

3. Commit directly on `development` and push (**no tag yet**):

   ```bash
   git commit -m "chore: release vX.Y.Z"
   git push origin development
   ```

4. **UAT — local build validation** before merging to `main`:

   ```bash
   cd deployments
   docker compose -f docker-compose.yml build --no-cache backend
   docker compose -f docker-compose.yml up -d
   ```

   Verify the backend starts, connects to the database, and responds on its health endpoint.
   If the stack includes the frontend, run a quick end-to-end smoke test (e.g. `terraform init`
   against a mirrored provider or module) to confirm downloads work. **Do not merge to `main`
   until the local build passes.**

5. Merge `development` → `main` via PR (step 7 above).

6. **After the PR is merged**, tag the commit that landed on `main` and push the tag:

   ```bash
   git fetch origin
   git tag vX.Y.Z origin/main
   git push origin vX.Y.Z
   ```

   > **Why tag after the merge?** The release PR produces a new merge commit SHA on `main`.
   > Tagging on `development` before the merge leaves the tag pointing at the wrong commit —
   > it will never appear in `main`'s history as a tagged release.

7. **Trigger the release workflow.** The `push` tag trigger can silently fail if the tag was
   previously pushed pointing to a different commit. Always verify the workflow fired within
   ~60 seconds by checking:

   ```bash
   gh run list --workflow=release.yml --limit=3
   ```

   If no new run appears, trigger it manually:

   ```bash
   gh workflow run release.yml --ref vX.Y.Z
   ```

   The workflow will: run CI → build multi-platform binaries → push Docker image to
   `ghcr.io/sethbacon/terraform-registry-backend:vX.Y.Z` → create a GitHub Release.

---

## Project Overview

An enterprise-grade private Terraform Registry implementing all three HashiCorp protocols:

- **Module Registry Protocol** (`/v1/modules/`)
- **Provider Registry Protocol** (`/v1/providers/`)
- **Provider Network Mirror Protocol** (`/v1/mirror/`)

Current version: **v1.0.0**. All phases 1–6 complete; Phase 7 (testing & documentation) in progress.

Frontend UI lives in a separate repository: [terraform-registry-frontend](https://github.com/sethbacon/terraform-registry-frontend)

---

## Repository Structure

```txt
terraform-registry-backend/
├── backend/                  # Go 1.24 backend service
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
│   ├── go.mod                # Go 1.24.0
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
| Language       | Go 1.24.0                                                          |
| HTTP Framework | Gin                                                                |
| Database       | PostgreSQL 14+ via sqlx                                            |
| Migrations     | golang-migrate (28 migrations)                                     |
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

- 28 versioned SQL migrations in `backend/internal/db/migrations/`.
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
  `Storage`, `SCM Providers`, `SCM OAuth`, `SCM Linking`, `Mirror`, `Mirror Protocol`,
  `RBAC`, `Stats`, `System`, `Webhooks`
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

- CI/CD pipelines are configured in `.github/workflows/` (ci.yml, release.yml, scheduled-build.yml).
- No `.golangci.yml` is present; use `go fmt` and `go vet` manually.
- The `azure-devops-extension/` directory is deferred/work-in-progress.
- `test-modules/`, `test-providers/`, and `test-terraform/` contain sample artifacts for local testing.
- `CHANGELOG.md` tracks version history.
