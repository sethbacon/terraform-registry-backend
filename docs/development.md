# Development Guide

This document describes how to set up a local development environment, generate API docs, and run tests.

Prerequisites

- Go 1.24+
- Docker & Docker Compose (for test environment)
- Make (optional)

Install tools

1. Install `swag` (OpenAPI generator):

    ```bash
    go install github.com/swaggo/swag/cmd/swag@latest
    ```

Generate Swagger JSON

```bash
cd backend
swag init -g cmd/server/main.go --outputTypes json
# Commit backend/docs/swagger.json if changed
```

Run backend (dev)

```bash
# use DEV_MODE in development to enable dev-login endpoints used by E2E
DEV_MODE=true go run cmd/server/main.go serve
```

For all `TFR_*` environment variables and their YAML equivalents, see the [Configuration Reference](configuration.md).

Makefile targets (repo root)

- `make swag` — regenerate Swagger JSON
- `make backend-test` — run `go test ./...`
- `make test-compose-up` — start the Docker Compose test stack
- `make test-compose-down` — stop the Docker Compose test stack

For frontend development and E2E setup, see [terraform-registry-frontend](https://github.com/sethbacon/terraform-registry-frontend).

Test Coverage

CI enforces a minimum threshold on `go test ./... -coverprofile=coverage.out`. The build fails if total statement coverage drops below **65%**. The aspirational goal is **70%** ("good for production" per Graphite / Google's "commendable" benchmark).

Component targets follow a risk-based approach:

| Component category | Packages | Target |
| --- | --- | --- |
| Security & core auth | `internal/auth`, `internal/middleware`, `internal/crypto` | 85–95% |
| Core business logic | `internal/db/repositories`, `internal/mirror`, `internal/audit`, `internal/validation`, `internal/scm` | 85–95% |
| APIs & handlers | `internal/api/...` | 75–85% |
| Background jobs & services | `internal/jobs`, `internal/services` | 70–80% |
| Storage backends | `internal/storage/...` | 70–80% |
| Config & utilities | `internal/config`, `internal/telemetry` | 70–80% |
| Generated / migration code | `internal/db` (schema init) | Excluded — no meaningful unit-testable logic |

Measure coverage locally:

```bash
cd backend
go test ./internal/... -coverprofile=coverage.out -covermode=atomic
# Total
go tool cover -func=coverage.out | grep "^total:"
# HTML report (opens in browser)
go tool cover -html=coverage.out
# Per-package sorted by coverage ascending (spot lowest-covered packages)
go tool cover -func=coverage.out | grep -v "^total:" | awk '{print $NF, $0}' | sort -V
```

Troubleshooting

- If `swag init` reports missing annotations, check `docs/SWAGGER_ANNOTATION_CHECKLIST.md`.
