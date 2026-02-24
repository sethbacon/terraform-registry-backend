<!-- markdownlint-disable MD024 -->

# Enterprise Terraform Registry — Backend

A fully-featured, enterprise-grade Terraform registry implementing all three HashiCorp protocols with multi-tenancy support.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/sethbacon/52d7faafe77a38f35ea962247c7ec210/raw/coverage.json)](https://github.com/sethbacon/terraform-registry-backend/actions/workflows/ci.yml)

## Features

### Terraform Protocol Support

- **Module Registry Protocol** - Complete implementation for hosting and discovering Terraform modules
- **Provider Registry Protocol** - Full provider hosting with platform-specific binaries
- **Provider Network Mirror Protocol** - Efficient provider mirroring and caching

### Authentication & Authorization

- **API Key Authentication** - Secure token-based access with scoped permissions
- **OIDC Integration** - Generic OIDC provider support for SSO
- **Azure AD / Entra ID** - Native Azure Active Directory integration
- **Role-Based Access Control (RBAC)** - Fine-grained permissions with organization roles

### Multi-Tenancy

- **Organization Management** - Isolated namespaces for teams and projects
- **User Management** - Comprehensive user administration
- **Organization Membership** - Role-based team collaboration (owner, admin, member, viewer)
- **Configurable Modes** - Single-tenant or multi-tenant deployment

### SCM Integration

- **GitHub Integration** - Connect modules to GitHub repositories with OAuth
- **Azure DevOps Integration** - Native support for Azure Repos
- **GitLab Integration** - Full GitLab repository support
- **Bitbucket Data Center** - Support for self-hosted Bitbucket instances with PAT authentication
- **Webhook Support** - Automatic publishing on repository events

### Storage Backends

- **Local Filesystem** - Direct file serving for development and simple deployments
- **Azure Blob Storage** - Cloud storage with SAS tokens, CDN URLs, and flexible access tiers
- **AWS S3 / S3-Compatible** - Support for AWS S3, MinIO, DigitalOcean Spaces with presigned URLs
- **Google Cloud Storage** - Native GCS integration with signed URLs and resumable uploads
- **Pluggable Architecture** - Extensible storage interface for adding new backends

### Deployment Options

- **Docker Compose** - Complete development and production setups
- **Kubernetes + Kustomize** - Production-ready manifests
- **Helm Chart** - Fully parameterized Helm chart
- **Azure Container Apps** - Bicep templates
- **AWS ECS Fargate** - CloudFormation stack
- **Google Cloud Run** - Knative services
- **Standalone Binary** - Systemd service with Nginx reverse proxy
- **Terraform IaC** - Infrastructure-as-Code for AWS, Azure, and GCP

### Terraform Binary Mirror

- **Multi-Config Mirror** — Multiple named mirror configs coexist; independently mirror HashiCorp Terraform, OpenTofu, or custom upstream sources side-by-side
- **Tool Support** — `terraform`, `opentofu`, and `custom` tool types with per-config upstream URL
- **Supply-Chain Security** — GPG signature verification against the embedded HashiCorp release key (OpenTofu support configurable)
- **Platform Filtering** — Optionally restrict which `os/arch` combinations are downloaded and served
- **Public Download API** — Unauthenticated endpoints at `/terraform/binaries/:name/versions/…` compatible with Terraform's [network mirror protocol](https://developer.hashicorp.com/terraform/internals/provider-network-mirror-protocol)
- **Prometheus Metric** — `terraform_binary_downloads_total` counter with `{version, os, arch}` labels

### Observability & CI/CD

- **Prometheus Metrics** - Nine named application metrics on a dedicated scrape port (default 9090)
- **Structured Logging** - stdlib `slog` with JSON (production) and text (development) formats
- **pprof Profiling** - Opt-in profiling server on a configurable port
- **GitHub Actions CI/CD** - Build, vet, race-detector tests, gosec security scan, Docker build, multi-platform releases
- **Bi-weekly Dependabot** - Automated Go module and Actions dependency updates

## Architecture

```txt
┌────────────────────────────────────────────────────┐
│              React TypeScript SPA                  │
│  (see terraform-registry-frontend)                 │
└──────────────────┬─────────────────────────────────┘
                   │ REST API / Protocol Endpoints
┌──────────────────▼─────────────────────────────────┐
│              Go 1.24 Backend (Gin)                 │
│  Modules API │ Providers API │ Mirror │ Admin       │
│  Terraform Binary Mirror                           │
│  Auth: JWT │ API Keys │ OIDC │ Azure AD │ RBAC      │
│  SCM: GitHub │ Azure DevOps │ GitLab │ Bitbucket   │
│  Storage: Local │ Azure Blob │ S3 │ GCS            │
└──────────────────┬─────────────────────────────────┘
                   │
          ┌────────┴────────┐
          │   PostgreSQL    │
          └─────────────────┘
```

## Installation

### Prerequisites

- Go 1.24 or later
- PostgreSQL 14+
- Docker & Docker Compose (for containerized deployment)

### Quick Start with Docker Compose

```bash
# Clone the repository
git clone https://github.com/sethbacon/terraform-registry-backend.git
cd terraform-registry-backend

# Start all services (backend + postgres; frontend served separately)
cd deployments
docker-compose up -d

# Backend API: http://localhost:8080
# PostgreSQL:  localhost:5432
# Prometheus metrics: http://localhost:9090/metrics
```

> For the web UI, see [terraform-registry-frontend](https://github.com/sethbacon/terraform-registry-frontend).

### First-Run Setup

On first startup, the server prints a one-time **setup token** to the logs. Use this token to configure the registry through the web wizard at `/setup` or via the setup API. The wizard guides you through:

1. OIDC provider configuration (authentication)
2. Storage backend configuration (where modules/providers are stored)
3. Initial admin user setup

See [Initial Setup Guide](docs/initial-setup.md) for full details, including headless/curl-based setup.

### Manual Setup

```bash
cd backend

# Install dependencies
go mod download

# Set up configuration
cp config.example.yaml config.yaml
# Edit config.yaml with your settings

# Run database migrations
go run cmd/server/main.go migrate up

# Start the server
go run cmd/server/main.go serve
```

## Configuration

All configuration can be set via environment variables (prefix: `TFR_`) or YAML config file.

```bash
# Database
export TFR_DATABASE_HOST=localhost
export TFR_DATABASE_PORT=5432
export TFR_DATABASE_USER=registry
export TFR_DATABASE_PASSWORD=your_password
export TFR_DATABASE_NAME=terraform_registry
export TFR_DATABASE_SSL_MODE=disable

# Server
export TFR_SERVER_PORT=8080
export TFR_SERVER_HOST=0.0.0.0
export TFR_SERVER_BASE_URL=http://localhost:8080

# Storage (choose one: local | azure | s3 | gcs)
export TFR_STORAGE_DEFAULT_BACKEND=local
export TFR_STORAGE_LOCAL_BASE_PATH=/var/lib/terraform-registry

# Authentication
export TFR_AUTH_API_KEYS_ENABLED=true
export TFR_AUTH_OIDC_ENABLED=false
export TFR_AUTH_AZURE_AD_ENABLED=false

# Security
export TFR_JWT_SECRET=your_jwt_secret          # min 32 chars in production
export ENCRYPTION_KEY=your_32_byte_encryption_key
```

See `backend/config.example.yaml` for a complete configuration reference.
See [Configuration Reference](docs/configuration.md) for detailed guidance.

## Monitoring & Observability

The registry exposes Prometheus metrics on a dedicated port (default **9090**).

```bash
# View all metrics
curl -s http://localhost:9090/metrics

# Check HTTP request rates
curl -s http://localhost:9090/metrics | grep '^http_requests_total'
```

### Prometheus + Grafana Stack

```bash
cd deployments
docker-compose --profile monitoring up -d
# Prometheus UI: http://localhost:9091
# Grafana:       http://localhost:3001  (admin / admin)
```

See [Observability Reference](docs/observability.md) for Grafana dashboard setup and alert rules.

## Usage with Terraform

```hcl
terraform {
  required_providers {
    mycloud = {
      source  = "registry.example.com/myorg/mycloud"
      version = "~> 1.0"
    }
  }
}

module "vpc" {
  source  = "registry.example.com/myorg/vpc/aws"
  version = "2.1.0"
}
```

### Publishing Modules

```bash
curl -X POST https://registry.example.com/api/v1/modules \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "file=@module.tar.gz" \
  -F "namespace=myorg" \
  -F "name=vpc" \
  -F "system=aws" \
  -F "version=1.0.0"
```

### Publishing Providers

```bash
curl -X POST https://registry.example.com/api/v1/providers \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "file=@terraform-provider-mycloud_1.0.0_linux_amd64.zip" \
  -F "namespace=myorg" \
  -F "type=mycloud" \
  -F "version=1.0.0" \
  -F "os=linux" \
  -F "arch=amd64" \
  -F "gpg_public_key=@public_key.asc"
```

## Development

### Running Tests

```bash
cd backend
go test ./...
```

### Building

```bash
cd backend
go build -o terraform-registry cmd/server/main.go
```

## Documentation

- [Changelog](CHANGELOG.md) - Version history and changes
- [Contributing](CONTRIBUTING.md) - How to contribute to this project
- [Architecture](docs/architecture.md) - System design and component interactions
- [API Reference](docs/api-reference.md) - API documentation guide
- [Observability Reference](docs/observability.md) - Prometheus metrics catalogue
- [Configuration Reference](docs/configuration.md) - All `TFR_*` environment variables
- [Deployment Guide](docs/deployment.md) - Production deployment for all platforms
- [Troubleshooting](docs/troubleshooting.md) - Common issues and diagnostic tools
- [Development Guide](docs/development.md) - Local development setup
- [OIDC Configuration](docs/oidc_configuration.md) - SSO provider setup

**Frontend:** [terraform-registry-frontend](https://github.com/sethbacon/terraform-registry-frontend)

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests. Key requirements:

- `go fmt ./...` and `go vet ./...` must pass
- New handlers require Swagger annotations
- New features require documentation updates
- Security issues must be reported privately (see CONTRIBUTING.md)

## License

This project is licensed under the Apache License, Version 2.0 — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [HashiCorp Terraform](https://www.terraform.io/) - Module and Provider protocols
- [Gin Web Framework](https://gin-gonic.com/) - Go HTTP framework

---

Built for the Terraform community
