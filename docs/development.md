<!-- markdownlint-disable MD013 -->
# Development Guide

This document describes how to set up a local development environment, generate API docs, and run tests.

## Prerequisites

- Go 1.26+
- Docker & Docker Compose (for test environment)
- Make (optional)

## Install Tools

1. Install `swag` (OpenAPI generator):

    ```bash
    go install github.com/swaggo/swag/cmd/swag@latest
    ```

## Generate Swagger JSON

```bash
cd backend
swag init -g cmd/server/main.go --outputTypes json
# Commit backend/docs/swagger.json if changed
```

## Run Backend (Dev)

```bash
# use DEV_MODE in development to enable dev-login endpoints used by E2E
DEV_MODE=true go run cmd/server/main.go serve
```

For all `TFR_*` environment variables and their YAML equivalents, see the [Configuration Reference](configuration.md).

## Makefile Targets

- `make swag` — regenerate Swagger JSON
- `make backend-test` — run `go test ./...`
- `make test-compose-up` — start the Docker Compose test stack
- `make test-compose-down` — stop the Docker Compose test stack

For frontend development and E2E setup, see [terraform-registry-frontend](https://github.com/sethbacon/terraform-registry-frontend).

## Test Coverage

CI enforces a minimum threshold on filtered coverage from `go test ./internal/... ./pkg/... -race -coverprofile=coverage.out`. The build fails if total statement coverage drops below the hard floor of **80%**. The aspirational goal is **85%** (target by the Phase 5 / H5.2 milestone, per Graphite / Google's "commendable" benchmark).

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

### Measure Coverage Locally

To match CI exactly, run the same package set with `-race`, then apply the
`coverfilter` step that excludes integration-only functions (those whose doc
comment carries a `coverage:skip:` marker) from the denominator:

```bash
cd backend
go test ./internal/... ./pkg/... -race -coverprofile=coverage.out -covermode=atomic
# Filter integration-only functions, mirroring CI
go run ./scripts/coverfilter -in coverage.out -out coverage.filtered.out -root .
# Total (this is the number CI compares against the 80% floor)
go tool cover -func=coverage.filtered.out | grep "^total:"
# HTML report (opens in browser)
go tool cover -html=coverage.filtered.out
# Per-package sorted by coverage ascending (spot lowest-covered packages)
go tool cover -func=coverage.filtered.out | grep -v "^total:" | awk '{print $NF, $0}' | sort -V
```

## Troubleshooting

- If `swag init` reports missing annotations, check `docs/SWAGGER_ANNOTATION_CHECKLIST.md`.
