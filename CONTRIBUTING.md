# Contributing to Enterprise Terraform Registry — Backend

Thank you for your interest in contributing. This project implements the full suite of HashiCorp Terraform protocols and is designed for enterprise deployments — contributions that uphold correctness, security, and protocol compliance are especially welcome.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Backend (Go) Standards](#backend-go-standards)
- [Database Migrations](#database-migrations)
- [Adding a New Storage Backend](#adding-a-new-storage-backend)
- [Adding a New SCM Connector](#adding-a-new-scm-connector)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
- [Documentation](#documentation)

---

## Code of Conduct

This project expects all participants to interact with each other professionally and respectfully. Harassment, discrimination, or disruptive behavior of any kind is not acceptable.

---

## Getting Started

### Prerequisites

- Go 1.24 or later
- PostgreSQL 14+
- Docker and Docker Compose

### Fork and Clone

```bash
git clone https://github.com/sethbacon/terraform-registry-backend.git
cd terraform-registry-backend
```

### Local Setup

```bash
# Start PostgreSQL via Docker Compose (simplest approach)
cd deployments
docker-compose up -d db

# Configure the backend
cd ../backend
cp config.example.yaml config.yaml
# Edit config.yaml: set database credentials to match docker-compose defaults

# Run database migrations
go run cmd/server/main.go migrate up

# Start the backend (port 8080)
go run cmd/server/main.go serve
```

For the frontend UI, see [terraform-registry-frontend](https://github.com/sethbacon/terraform-registry-frontend).

> **DEV_MODE**: When `TFR_DEV_MODE=true` is set in the backend, a dev login shortcut
> is available that bypasses OIDC. This is used by E2E tests and is never compiled
> into production builds — it is gated behind a runtime config check.

---

## Development Workflow

### Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/short-description` | `feat/s3-multipart-upload` |
| Bug fix | `fix/issue-description` | `fix/webhook-signature-validation` |
| Documentation | `docs/topic` | `docs/deployment-guide` |
| Refactor | `refactor/area` | `refactor/scm-connector-interface` |

### Commit Messages

- Use the **imperative mood**: "Add feature" not "Added feature"
- Keep the subject line under **72 characters**
- Leave a blank line, then explain **why** the change is needed in the body
- Reference issues with `Fixes #123` or `Closes #123`

### One Change Per Commit

Keep commits focused on a single logical change. This makes code review easier and keeps the git history useful as documentation.

---

## Backend (Go) Standards

### Formatting and Vetting

Every commit must pass:

```bash
cd backend
go fmt ./...
go vet ./...
```

Neither command should produce any output (warnings = failure).

### Code Comments

Comments are part of the code and are held to the same quality standard:

- **Package-level doc comments** are required for every new package.
- **Exported symbols** must have doc comments.
- **Comments must explain WHY, not just WHAT.**

### Swagger Annotations

Every new or modified HTTP handler **must** have a complete Swagger annotation block:

```go
// @Summary      Short one-line summary
// @Description  Longer description of what this endpoint does.
// @Tags         TagName
// @Security     Bearer
// @Accept       json
// @Produce      json
// @Param        id    path    string  true  "Resource ID (UUID)"
// @Success      200  {object}  SomeResponseType
// @Failure      400  {object}  map[string]interface{}  "Bad request"
// @Failure      401  {object}  map[string]interface{}  "Unauthorized"
// @Failure      500  {object}  map[string]interface{}  "Internal server error"
// @Router       /api/v1/resource/{id} [get]
func (h *Handler) MethodName(c *gin.Context) {
```

After adding or updating annotations, regenerate the spec:

```bash
cd backend
swag init -g cmd/server/main.go --outputTypes json
```

Then rebuild the binary (the spec is embedded at compile time). Add or update the entry in `docs/SWAGGER_ANNOTATION_CHECKLIST.md`. See `CLAUDE.md` for the full annotation rules.

### Architecture Conventions

- **Repository pattern**: all database access goes through `internal/db/repositories/`. Handlers must never query the database directly.
- **Factory pattern**: storage backends and SCM connectors register themselves via `init()` — do not add manual registration calls in `main.go`.
- **Error handling**: return meaningful errors; do not swallow them. Use `fmt.Errorf("context: %w", err)` to preserve the error chain.
- **Context propagation**: pass `context.Context` through all I/O calls; respect cancellation.

---

## Database Migrations

- **Never edit existing migration files.** The migration system treats file content as immutable.
- Create a new numbered pair: `000029_description.up.sql` and `000029_description.down.sql`.
- The down migration must fully reverse the up migration.
- Test both directions before submitting:

  ```bash
  migrate -database "postgres://..." -path backend/internal/db/migrations down 1
  migrate -database "postgres://..." -path backend/internal/db/migrations up
  ```

---

## Adding a New Storage Backend

1. Create a new package under `backend/internal/storage/<name>/`.
2. Implement the `storage.Backend` interface defined in `backend/internal/storage/storage.go`.
3. Register the backend in its `init()` function by calling `factory.Register("<name>", NewBackend)`.
4. Add configuration fields to `backend/internal/config/config.go` under the `StorageConfig` struct.
5. Add environment variable documentation to `docs/configuration.md`.
6. Add unit tests covering at least `Upload`, `Download`, `GetURL`, and `Delete`.

---

## Adding a New SCM Connector

1. Create a new package under `backend/internal/scm/<provider>/`.
2. Implement the `scm.Connector` interface defined in `backend/internal/scm/connector.go`.
3. Register the connector kind in `backend/internal/scm/registry.go`.
4. Add the new provider type constant to `backend/internal/scm/types.go`.
5. Update the frontend's SCM providers admin page (in `terraform-registry-frontend`).
6. Add a database migration if new columns are needed in `scm_providers`.
7. Add unit tests for the connector's webhook signature validation logic.

---

## Testing Requirements

Before submitting a pull request:

```bash
# All tests must pass
cd backend
go test ./...
```

New packages should include unit tests for core logic. Security-sensitive code (authentication, signature verification, checksum validation) requires tests by default — PRs adding such code without tests will not be merged.

---

## Pull Request Process

1. **Open an issue first** for substantial changes.
2. Write a clear PR description:
   - What changed and why
   - How you tested it
   - Screenshots or curl examples for API changes
   - Link to the issue being resolved
3. All CI checks must pass.
4. At least one reviewer approval is required before merging.
5. **Squash merge** is preferred to keep the main branch history clean.
6. The PR author is responsible for resolving merge conflicts.

---

## Reporting Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub's private security advisory feature](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) to report issues privately. Include:

- A clear description of the vulnerability
- Steps to reproduce
- The potential impact
- Any suggested mitigations

We will respond within 5 business days and coordinate a fix and disclosure timeline.

---

## Documentation

Documentation is a first-class deliverable:

- **New features**: update the relevant section of `README.md` and any applicable `docs/` files.
- **Configuration changes**: update `docs/configuration.md` with the new `TFR_*` variable(s), type, default, and description.
- **New deployment options**: add a section to `docs/deployment.md`.
- **API changes**: update the Swagger annotation on the handler and regenerate `backend/docs/swagger.json`.
- **Architecture changes**: update `docs/architecture.md` if the component or data flow diagram changes.

PRs that introduce user-visible features without corresponding documentation updates will be asked to add documentation before merge.
