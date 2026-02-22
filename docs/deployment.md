# Deployment Guide

This guide covers all supported deployment options for the Enterprise Terraform Registry.
Choose the option that matches your environment and operational model.

## Deployment Options

| Option | Best For | Location |
| --- | --- | --- |
| Docker Compose (dev) | Local development, quick evaluation | `deployments/docker-compose.yml` |
| Docker Compose (prod) | Small teams, single-host production | `deployments/docker-compose.prod.yml` |
| Kubernetes + Kustomize | Enterprise, multi-replica, GitOps | `deployments/kubernetes/` |
| Helm Chart | Kubernetes with parameterized config | `deployments/helm/` |
| Azure Container Apps | Azure-native, serverless scaling | `deployments/azure-container-apps/` |
| AWS ECS Fargate | AWS-native, fully managed | `deployments/aws-ecs/` |
| Google Cloud Run | GCP-native, serverless | `deployments/google-cloud-run/` |
| Standalone Binary + systemd | On-premise, VMs, maximum control | `deployments/binary/` |
| Terraform IaC | Reproducible cloud infrastructure | `deployments/terraform/` |

---

## Pre-Deployment Checklist

Before deploying to production, prepare the following:

```bash
# 1. Generate a JWT signing secret (minimum 32 characters)
openssl rand -hex 32

# 2. Generate an encryption key for SCM OAuth tokens
openssl rand -hex 16   # produces 32 hex chars = 16 bytes key material

# 3. Generate a strong database password
openssl rand -base64 32

# 4. Choose and configure a storage backend
#    (local for single-node, cloud storage for multi-node or HA)

# 5. Configure your authentication provider
#    (API keys only, or OIDC/Azure AD for SSO)

# 6. Decide on single-tenant vs multi-tenant mode
#    (TFR_MULTI_TENANCY_ENABLED=false for most deployments)

# 7. Obtain a TLS certificate for your domain
#    (Let's Encrypt via Certbot, or from your cloud provider's certificate service)
```

---

## Docker Compose

### Development

The default Docker Compose file starts the backend, frontend, and PostgreSQL:

```bash
cd deployments
docker-compose up -d

# Services:
#   Backend:    http://localhost:8080
#   Frontend:   http://localhost:3000
#   PostgreSQL: localhost:5432
```

Database credentials and other config are set in `deployments/.env` (created from the
compose file defaults). To customize, copy and edit the example file:

```bash
cp deployments/.env.production.example deployments/.env
```

### Production

The production override removes the development frontend server, uses pre-built images,
sets resource limits, and reads secrets from an env file:

```bash
cd deployments
cp .env.production.example .env.production
# Edit .env.production with your secrets and domain

docker-compose -f docker-compose.prod.yml up -d
```

Key differences from dev:

- Backend and frontend use pre-built Docker images (tag configurable via `IMAGE_TAG`)
- All secrets loaded from `.env.production` (do not commit this file)
- Resource limits set to prevent runaway memory usage
- `restart: always` ensures services come back after host reboots

---

## Kubernetes + Kustomize

### Structure

```txt
deployments/kubernetes/
├── base/                  # Base resources (apply to all environments)
│   ├── namespace.yaml
│   ├── configmap.yaml     # Non-secret config values
│   ├── secret.yaml        # Secret template (populate before applying)
│   ├── deployment-backend.yaml
│   ├── deployment-frontend.yaml
│   ├── service-backend.yaml
│   ├── service-frontend.yaml
│   ├── ingress.yaml
│   └── pdb.yaml           # PodDisruptionBudget (minAvailable: 1)
├── overlays/
│   ├── dev/               # 1 replica, debug logging, DEV_MODE enabled
│   └── production/        # 3 replicas, HPA (3-10), warn logging, 50Gi PVC
```

### Deploying

```bash
# Development
kubectl apply -k deployments/kubernetes/overlays/dev

# Production
# 1. Create the secret with real values
kubectl create secret generic terraform-registry \
  --from-literal=jwt-secret=$(openssl rand -hex 32) \
  --from-literal=database-password=yourpassword \
  --from-literal=encryption-key=$(openssl rand -hex 16) \
  -n terraform-registry

# 2. Apply the overlay
kubectl apply -k deployments/kubernetes/overlays/production
```

The production overlay includes:

- **HPA** scaling backend from 3 to 10 replicas based on CPU (70%) and memory (80%)
- **PDB** ensuring at least 1 replica is available during voluntary disruptions
- **50Gi PVC** for local storage (replace with a cloud storage backend for multi-replica deployments)

> **Important:** Local filesystem storage (`TFR_STORAGE_DEFAULT_BACKEND=local`) does not
> work correctly with multiple replicas unless all pods share the same PVC (ReadWriteMany).
> Use a cloud storage backend (Azure Blob, S3, GCS) for multi-replica Kubernetes deployments.

---

## Helm Chart

The Helm chart provides the most flexible deployment option for Kubernetes, supporting
all storage backends, optional frontend deployment, and ingress customization.

```bash
# Preview the rendered manifests
helm template terraform-registry deployments/helm/ \
  --set config.baseUrl=https://registry.example.com \
  --set config.jwtSecret=$(openssl rand -hex 32) \
  --set config.databasePassword=yourpassword \
  --set storage.backend=s3 \
  --set storage.s3.bucket=my-registry-bucket \
  --set storage.s3.region=us-east-1

# Install to Kubernetes
helm install terraform-registry deployments/helm/ \
  --namespace terraform-registry \
  --create-namespace \
  -f my-values.yaml
```

Key values in `values.yaml` to override:

| Value | Description |
| --- | --- |
| `config.baseUrl` | Public URL returned to Terraform CLI (required) |
| `config.jwtSecret` | JWT signing secret (required, min 32 chars) |
| `config.databasePassword` | PostgreSQL password |
| `config.encryptionKey` | SCM OAuth token encryption key |
| `storage.backend` | `local` \| `azure` \| `s3` \| `gcs` |
| `ingress.enabled` | Enable ingress resource |
| `ingress.hostname` | Ingress hostname |
| `ingress.tls.enabled` | Enable TLS on ingress |
| `backend.replicas` | Number of backend replicas |
| `autoscaling.enabled` | Enable HPA |
| `frontend.enabled` | Deploy frontend container |

See `deployments/helm/values.yaml` for the full annotated values file.

---

## Azure Container Apps

Uses Bicep templates for Azure-native deployment. Resources created:

- Container Apps Environment (shared)
- Backend Container App (internal ingress, 8080, 1–10 replicas)
- Frontend Container App (external ingress, 80, 1–5 replicas)
- Log Analytics workspace

```bash
cd deployments/azure-container-apps

# Edit parameters.json with your values (resource group, images, secrets)
cp parameters.json.example parameters.json
# Edit parameters.json

# Deploy using Bicep
az deployment group create \
  --resource-group my-resource-group \
  --template-file main.bicep \
  --parameters @parameters.json

# Or use the helper script
./deploy.sh my-resource-group myacr.azurecr.io
```

The backend app is configured with internal ingress only — it is not directly exposed to the internet. The frontend app (external ingress) proxies API calls to the backend within the Container Apps environment.

---

## AWS ECS Fargate

A full CloudFormation stack is provided:

```bash
cd deployments/aws-ecs

# Edit and deploy the CloudFormation stack
aws cloudformation deploy \
  --template-file cloudformation.yaml \
  --stack-name terraform-registry \
  --parameter-overrides \
    Environment=production \
    DomainName=registry.example.com \
    CertificateArn=arn:aws:acm:us-east-1:...:certificate/... \
  --capabilities CAPABILITY_IAM

# Or use the helper script
./deploy.sh
```

Resources created:

- VPC with public and private subnets + NAT gateway
- ECS cluster with backend and frontend Fargate services
- Application Load Balancer with HTTPS (ACM certificate required)
- RDS PostgreSQL in private subnets
- S3 bucket for storage
- ECR repositories for container images
- Secrets Manager secrets for credentials
- IAM roles with least-privilege policies
- CloudWatch log groups

The backend task pulls secrets from Secrets Manager at container startup. Container images must be pushed to ECR before deploying:

```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker build -t <account>.dkr.ecr.us-east-1.amazonaws.com/terraform-registry-backend:latest backend/
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/terraform-registry-backend:latest
```

---

## Google Cloud Run

```bash
cd deployments/google-cloud-run

# Configure gcloud
gcloud config set project my-gcp-project

# Deploy using the helper script (handles Artifact Registry push + service deployment)
./deploy.sh my-gcp-project us-central1 registry.example.com

# Or deploy manually
gcloud run services replace backend-service.yaml --region us-central1
gcloud run services replace frontend-service.yaml --region us-central1
```

Resources managed by the deployment:

- Cloud Run services (backend + frontend)
- Cloud SQL PostgreSQL (private IP, VPC connector required)
- GCS bucket for storage
- Secret Manager secrets for credentials
- Artifact Registry for container images
- Service account with minimum required IAM roles
- VPC connector for private database access

The backend service uses the VPC connector to reach Cloud SQL via private IP. The Cloud SQL socket path is mounted into the container automatically by Cloud Run's Cloud SQL proxy integration.

---

## Standalone Binary + systemd

Best for on-premise deployments or VMs where you want maximum control over the runtime environment.

```bash
cd deployments/binary

# 1. Build the backend binary
cd ../../backend
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o terraform-registry ./cmd/server

# 2. Build the frontend
cd ../frontend
npm install && npm run build

# 3. Run the install script (creates user, copies files, installs services)
sudo ./deployments/binary/install.sh
```

The install script:

1. Creates a `registry` system user
2. Copies the binary to `/usr/local/bin/terraform-registry`
3. Copies the built frontend to `/var/www/terraform-registry`
4. Installs the systemd unit (`terraform-registry.service`)
5. Installs the nginx site configuration

### Configuration

Copy and edit the environment file:

```bash
sudo cp /etc/terraform-registry/environment.example /etc/terraform-registry/environment
sudo nano /etc/terraform-registry/environment
```

The systemd unit reads secrets from `/etc/terraform-registry/environment` (mode 0600, owned by root). This file is equivalent to a `.env` file for the service.

### Nginx

The nginx configuration at `deployments/binary/nginx-registry.conf` provides:

- TLS termination with Let's Encrypt (Certbot)
- HSTS header
- Reverse proxy to backend (`localhost:8080`)
- SPA fallback for React Router
- Static asset caching for frontend files
- Gzip compression

```bash
sudo cp deployments/binary/nginx-registry.conf /etc/nginx/sites-available/terraform-registry
sudo ln -s /etc/nginx/sites-available/terraform-registry /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## Terraform IaC

Complete Infrastructure-as-Code configurations are provided for AWS, Azure, and GCP.

```bash
# AWS
cd deployments/terraform/aws
terraform init
terraform plan -var="domain=registry.example.com" -var="image_tag=1.0.0"
terraform apply

# Azure
cd deployments/terraform/azure
terraform init
terraform plan -var="location=eastus" -var="image_tag=1.0.0"
terraform apply

# GCP
cd deployments/terraform/gcp
terraform init
terraform plan -var="project_id=my-project" -var="image_tag=1.0.0"
terraform apply
```

Each Terraform configuration:

- Defaults to the native cloud storage backend (S3 for AWS, Azure Blob for Azure, GCS for GCP)
- Supports all 4 storage backends via variables
- Exposes outputs for the deployed service URLs and key resource identifiers
- Includes all supporting infrastructure (networking, database, secrets management, IAM)

See `variables.tf` in each directory for the full list of tunable parameters.

---

## Health Checks

The backend exposes a health endpoint:

```bash
GET /health
# Returns 200 OK with JSON:
# {"status": "ok", "database": "ok", "storage": "ok"}

# Or for just liveness (no dependency checks):
GET /healthz
# Returns 200 OK: {"status": "ok"}
```

Use `/health` for Kubernetes readiness probes (checks DB + storage connectivity) and `/healthz` for liveness probes (just process alive).

---

## First-Run Setup

After deploying, initialize the registry:

1. **Apply database migrations** (automatic on startup, but verify):

   ```bash
   # Standalone binary
   terraform-registry migrate up

   # Docker Compose
   docker-compose exec backend terraform-registry migrate up
   ```

2. **Create the first admin user** via the admin API or the admin setup endpoint:

   ```bash
   # The first user created via OIDC login is automatically an admin
   # For API key-only setups, use the dev endpoint (requires DEV_MODE=true):
   curl -X POST http://localhost:8080/auth/dev/login \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@example.com", "name": "Admin"}'
   ```

3. **Configure storage** via Admin → Storage in the web UI (or via environment variables)

4. **Create your first API key** via Admin → API Keys → Create Key

5. **Verify with Terraform**:

   ```hcl
   terraform {
     required_providers {
       test = {
         source = "registry.example.com/myorg/test"
       }
     }
   }
   ```

   ```bash
   terraform init   # should resolve successfully
   ```

---

## TLS / HTTPS

TLS should always be terminated in production. Options:

1. **Ingress/Load Balancer TLS** (recommended for Kubernetes/Cloud): handled by the ingress controller or cloud load balancer. The backend itself runs plain HTTP internally.

2. **Nginx TLS termination** (recommended for standalone binary): nginx handles certificates (Let's Encrypt via Certbot) and proxies plain HTTP to the Go backend on localhost.

3. **Go-level TLS** (available but not recommended): set `TFR_SECURITY_TLS_ENABLED=true` with cert and key paths. Use only when a reverse proxy is not available.

For Let's Encrypt on a standalone binary:

```bash
sudo certbot --nginx -d registry.example.com
# Certbot automatically edits the nginx config to add TLS and sets up auto-renewal
```

---

## Deployment Checklist

Use this checklist before every production deployment.
All items are required unless explicitly marked *(optional)*.

### 1. Pre-deployment Verification

#### Source & Versioning

- [ ] All CI checks pass on the commit to be deployed (`ci.yml` green)
- [ ] The deployment tag (`v*.*.*`) has been pushed and `release.yml` completed successfully
- [ ] `git log` shows no unreviewed emergency commits on the release branch
- [ ] `CHANGELOG.md` has been updated for this release

#### Security Scan

- [ ] `gosec` job in the latest CI run produced **no** unacknowledged HIGH findings
- [ ] `npm audit --audit-level=high` is clean for the frontend bundle
- [ ] Docker image has been scanned (e.g., `docker scout cves <image>`) with no CRITICAL CVEs
- [ ] All secrets to be rotated have been rotated and the new values are staged in the secret store

### 2. Environment Variables

Verify each variable is set in the target environment before deploying. For the complete list of `TFR_*` variables, types, defaults, and YAML equivalents, see the [Configuration Reference](configuration.md).

#### Required — Database

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | PostgreSQL DSN `postgres://user:pass@host:5432/dbname?sslmode=require` |
| `DB_MAX_OPEN_CONNS` | Max open connections (suggest: `25`) |
| `DB_MAX_IDLE_CONNS` | Max idle connections (suggest: `5`) |

- [ ] `DATABASE_URL` is set and resolves from the deployment host
- [ ] Database credentials are sourced from the secret store (not hard-coded)

#### Required — Storage

| Variable | Description |
| --- | --- |
| `STORAGE_BACKEND` | `s3`, `gcs`, `azure`, or `local` |
| `STORAGE_BUCKET` | Name of the storage bucket / container |

Storage-backend-specific:

##### AWS S3

- [ ] `AWS_REGION` set
- [ ] IAM role or `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` configured
- [ ] Bucket exists and the service account has `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`

##### GCS

- [ ] `GOOGLE_APPLICATION_CREDENTIALS` or Workload Identity configured
- [ ] Bucket exists with appropriate ACLs

##### Azure Blob

- [ ] `AZURE_STORAGE_ACCOUNT` and `AZURE_STORAGE_KEY` (or managed identity) configured
- [ ] Container exists

##### Local

- [ ] `STORAGE_LOCAL_PATH` points to a persistent volume (not ephemeral container storage)

#### Required — Authentication / Authorization

| Variable | Description |
| --- | --- |
| `AUTH_ENABLED` | `true` in production |
| `OIDC_ISSUER_URL` | OIDC provider discovery URL |
| `OIDC_CLIENT_ID` | Registered client ID |
| `OIDC_CLIENT_SECRET` | Registered client secret (from secret store) |

- [ ] OIDC provider is reachable from the deployment host
- [ ] Redirect URI(s) registered in the OIDC provider match the deployment URL
- [ ] Admin user(s) are seeded or will be provisioned on first login

#### Required — Server

| Variable | Description |
| --- | --- |
| `PORT` | HTTP port (default `8080`) |
| `BASE_URL` | Public-facing URL including scheme, e.g., `https://registry.example.com` |
| `DEV_MODE` | Must be `false` in production |
| `LOG_FORMAT` | `json` recommended for production |
| `LOG_LEVEL` | `info` or `warn` for production |

- [ ] `DEV_MODE=false`
- [ ] `BASE_URL` matches the DNS entry that will serve traffic

#### Optional — Observability

| Variable | Description |
| --- | --- |
| `METRICS_ENABLED` | `true` to expose `/metrics` (Prometheus scrape target) |
| `SENTRY_DSN` | Sentry error-tracking DSN *(optional)* |

### 3. Database Migrations

- [ ] A database backup has been taken immediately before migrating
- [ ] The migration is idempotent (re-running it is safe)
- [ ] Migration command confirmed:

  ```bash
  cd backend && go run ./cmd/migrate up
  ```

  or via Docker:

  ```bash
  docker run --rm \
    -e DATABASE_URL="$DATABASE_URL" \
    ghcr.io/sethbacon/terraform-registry-backend:<version> \
    migrate up
  ```

- [ ] Migration completed with exit code 0 and the expected number of migrations applied
- [ ] No long-running table locks were observed during migration (`pg_stat_activity`)

### 4. TLS / SSL

- [ ] Valid TLS certificate is in place (Let's Encrypt, ACM, or corporate CA)
- [ ] Certificate covers all hostnames that will receive traffic
- [ ] Certificate expiry is **more than 30 days away** (`openssl s_client -connect host:443 | openssl x509 -noout -dates`)
- [ ] HTTPS redirects are enforced (HTTP → HTTPS 301/308)
- [ ] HSTS header (`Strict-Transport-Security`) is present in responses
- [ ] TLSv1.0 and TLSv1.1 are disabled; TLSv1.2+ only

### 5. DNS

- [ ] DNS record points to the correct load-balancer / IP
- [ ] TTL on the A/CNAME record is low enough for fast rollback (suggest: ≤ 300 s during active change window)
- [ ] `dig +short <hostname>` from an external resolver returns the correct address

### 6. Deployment-Method-Specific Steps

#### Docker Compose (Production Rollout)

```bash
# 1. Pull the new image
docker compose -f deployments/docker-compose.prod.yml pull

# 2. Run migrations
docker compose -f deployments/docker-compose.prod.yml run --rm backend migrate up

# 3. Rolling restart
docker compose -f deployments/docker-compose.prod.yml up -d --no-deps backend

# 4. Verify
docker compose -f deployments/docker-compose.prod.yml ps
docker compose -f deployments/docker-compose.prod.yml logs --tail=50 backend
```

- [ ] Image pulled successfully
- [ ] Migrations completed (step 2)
- [ ] Container is `Up (healthy)` in `ps` output
- [ ] No ERROR lines in first 50 log lines

#### Kubernetes (Helm)

```bash
# 1. Update image tag in values override
#    image.tag: v<version>

# 2. Dry-run first
helm upgrade terraform-registry deployments/helm/terraform-registry \
  --namespace registry \
  -f my-values.yaml \
  --dry-run

# 3. Apply
helm upgrade terraform-registry deployments/helm/terraform-registry \
  --namespace registry \
  -f my-values.yaml \
  --wait --timeout=5m

# 4. Verify rollout
kubectl rollout status deployment/terraform-registry -n registry
kubectl get pods -n registry
```

- [ ] Helm diff reviewed before applying
- [ ] `kubectl rollout status` shows successful rollout
- [ ] All pods are `Running`; no `CrashLoopBackOff`

#### Standalone Binary

```bash
# 1. Download binary + verify checksum
curl -LO https://github.com/sethbacon/terraform-registry-backend/releases/download/v<version>/terraform-registry-linux-amd64
curl -LO https://github.com/sethbacon/terraform-registry-backend/releases/download/v<version>/checksums.txt
sha256sum --check --ignore-missing checksums.txt

# 2. Replace binary
sudo systemctl stop terraform-registry
sudo install -m 755 terraform-registry-linux-amd64 /usr/local/bin/terraform-registry

# 3. Run migrations
terraform-registry migrate up

# 4. Restart service
sudo systemctl start terraform-registry
sudo systemctl status terraform-registry
```

- [ ] Checksum verified before installing
- [ ] Service started successfully (`active (running)`)
- [ ] `journalctl -u terraform-registry -n 50` shows no ERROR lines

### 7. Post-deployment Smoke Tests

Run these immediately after deployment.

```bash
BASE="https://registry.example.com"

# Health endpoint
curl -sf "${BASE}/health" | jq .

# Metrics endpoint (if enabled)
curl -sf "${BASE}/metrics" | grep terraform_registry_

# API — list providers (unauthenticated, should return 401 or empty list)
curl -s "${BASE}/v1/providers" | jq .

# API — login endpoint
curl -s "${BASE}/v1/auth/login"
```

- [ ] `/health` returns `{"status":"ok"}` (HTTP 200)
- [ ] `/metrics` returns Prometheus text (HTTP 200)
- [ ] API endpoints respond (correct HTTP codes even if auth-gated)
- [ ] No 500 errors in application logs for the first 5 minutes post-deploy

### 8. Monitoring Verification

- [ ] Prometheus is scraping the new instance (`up{job="terraform-registry"} == 1`)
- [ ] Grafana dashboard loads and shows data (if configured)
- [ ] Alert rules are active and connected to notification channels
- [ ] Error-rate alert (`http_requests_total{status=~"5.."}`) is **not** firing

### 9. Rollback Procedure

If a critical issue is discovered after deployment:

#### Rollback Docker Compose

```bash
# Rollback to previous image tag
docker compose -f deployments/docker-compose.prod.yml \
  up -d --no-deps \
  -e "IMAGE_TAG=v<previous-version>" backend
```

#### Rollback Kubernetes

```bash
helm rollback terraform-registry -n registry
kubectl rollout status deployment/terraform-registry -n registry
```

#### Rollback Standalone Binary

```bash
sudo systemctl stop terraform-registry
sudo install -m 755 /usr/local/bin/terraform-registry.prev /usr/local/bin/terraform-registry
sudo systemctl start terraform-registry
```

#### Database Rollback

> **Warning:** Only roll back the database if the new schema is not yet being used by live traffic.
> Rolling back a schema migration after writes have occurred can cause data loss.

```bash
# Review migration state first
terraform-registry migrate status

# Roll back the last migration
terraform-registry migrate down 1
```

- [ ] Rollback decision logged in the incident channel
- [ ] Rollback completed and verified via smoke tests (Section 7)
- [ ] Post-mortem scheduled

### 10. Sign-off

| Role     | Name | Date |
| -------- | ---- | ---- |
| Engineer |      |      |
| Reviewer |      |      |
