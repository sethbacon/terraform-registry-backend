# Air-Gapped Installation Guide

This guide describes how to deploy the Terraform Registry in a network-isolated
(air-gapped) environment with **no internet egress**. All container images,
scanner databases, and dependencies are pre-bundled for offline installation.

## Prerequisites

| Requirement          | Minimum Version | Notes                                      |
| -------------------- | --------------- | ------------------------------------------ |
| Docker               | 20.10+          | Or containerd/Podman with `docker load`    |
| PostgreSQL           | 14+             | Can be bundled or existing                 |
| Disk space           | 2 GB            | For images + scanner DB                    |
| Internal CA (if TLS) | —               | See [CA Trust](#internal-ca-trust) section |

## Step 1: Build the Air-Gap Bundle

On a **connected** machine, run the bundle script from the repository root:

```bash
# Bundle with default settings (latest images, no scanner DB)
make airgap-bundle

# Bundle with specific versions and Trivy offline DB
./scripts/airgap-bundle.sh \
  --backend-image ghcr.io/org/terraform-registry-backend:0.10.0 \
  --frontend-image ghcr.io/org/terraform-registry-frontend:0.10.0 \
  --scanner trivy \
  --output ./airgap-bundle
```

This produces a tarball containing:

```
airgap-bundle/
├── images/
│   ├── backend.tar.gz       # Backend container image
│   ├── frontend.tar.gz      # Frontend container image
│   └── postgres.tar.gz      # PostgreSQL 16 image
├── scanner-db/              # Offline scanner DB (if --scanner specified)
├── helm/                    # Helm chart archive
├── certs/
│   └── README.md            # CA trust configuration guide
├── load-images.sh           # Image loading helper
├── MANIFEST.md              # Bundle contents manifest
└── SHA256SUMS               # Integrity checksums
```

## Step 2: Transfer Bundle to Air-Gapped Environment

Transfer the tarball to the target environment using your approved method:

- USB/removable media through a data diode
- Secure file transfer to a bastion host
- Approved cross-domain transfer mechanism

### Verify Integrity

After transfer, verify the checksums:

```bash
tar xzf terraform-registry-airgap-*.tar.gz
cd airgap-bundle
sha256sum -c SHA256SUMS
```

## Step 3: Load Container Images

```bash
# Load all images into the local Docker daemon
./load-images.sh

# Or load into a private container registry
docker load < images/backend.tar.gz
docker tag ghcr.io/org/terraform-registry-backend:0.10.0 \
  registry.internal.example.com/terraform-registry-backend:0.10.0
docker push registry.internal.example.com/terraform-registry-backend:0.10.0

# Repeat for frontend and postgres images
```

## Step 4: Configure for Air-Gap Operation

### config.yaml

Key settings for air-gapped deployments:

```yaml
server:
  host: "0.0.0.0"
  port: 5000
  tls:
    enabled: true
    cert_file: "/certs/server.crt"
    key_file: "/certs/server.key"

database:
  host: "postgres.internal"
  port: 5432
  name: "terraform_registry"

storage:
  type: "filesystem"          # or s3 with internal MinIO/Ceph
  filesystem:
    path: "/data/modules"

auth:
  oidc:
    enabled: false            # Disable if IdP is unreachable
  api_keys:
    enabled: true             # Use API keys for machine access

# Disable features that require internet access
scanning:
  enabled: true
  tool: "trivy"
  binary_path: "/usr/local/bin/trivy"
  # Point Trivy to the offline DB
  # Set TRIVY_CACHE_DIR=/scanner-db/trivy in the container environment

# Disable telemetry
telemetry:
  enabled: false
```

### Environment Variables

```bash
# Core
TFR_DATABASE_HOST=postgres.internal
TFR_DATABASE_PORT=5432
TFR_DATABASE_NAME=terraform_registry
TFR_SERVER_TLS_ENABLED=true
ENCRYPTION_KEY=<your-encryption-key>

# Disable outbound connections
TFR_TELEMETRY_ENABLED=false

# Trivy offline mode
TRIVY_CACHE_DIR=/scanner-db/trivy
TRIVY_SKIP_DB_UPDATE=true
TRIVY_SKIP_JAVA_DB_UPDATE=true
TRIVY_OFFLINE_SCAN=true
```

## Step 5: Scanner Database Pre-Seeding

### Trivy Offline DB

If you included `--scanner trivy` in the bundle:

```bash
# Mount the offline DB into the backend container
docker run -d \
  -v $(pwd)/scanner-db/trivy:/root/.cache/trivy \
  -e TRIVY_SKIP_DB_UPDATE=true \
  -e TRIVY_SKIP_JAVA_DB_UPDATE=true \
  -e TRIVY_OFFLINE_SCAN=true \
  ghcr.io/org/terraform-registry-backend:0.10.0
```

To update the Trivy DB periodically:
1. On a connected machine: `trivy image --download-db-only --cache-dir ./trivy-db`
2. Transfer `./trivy-db/` to the air-gapped host.
3. Replace the mounted volume and restart the backend.

### Checkov Offline

```bash
# On a connected machine, bundle Checkov + dependencies
pip download checkov -d ./checkov-packages/

# On the air-gapped host
pip install --no-index --find-links=./checkov-packages/ checkov
```

## Step 6: Deploy

### Docker Compose

```bash
# Modify docker-compose.prod.yml to use local image references
docker compose -f docker-compose.prod.yml up -d
```

### Kubernetes / Helm

```bash
# Install from the bundled chart
helm install terraform-registry ./helm/terraform-registry-*.tgz \
  --set backend.image.repository=registry.internal.example.com/terraform-registry-backend \
  --set backend.image.tag=0.10.0 \
  --set frontend.image.repository=registry.internal.example.com/terraform-registry-frontend \
  --set frontend.image.tag=0.10.0 \
  --set postgresql.image.repository=registry.internal.example.com/postgres \
  --set postgresql.image.tag=16-alpine
```

## Internal CA Trust

If your environment uses an internal certificate authority:

### Option A: Build a derived image

```dockerfile
FROM ghcr.io/org/terraform-registry-backend:0.10.0
COPY internal-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
```

### Option B: Mount at runtime

```bash
docker run -d \
  -v /path/to/internal-ca.crt:/usr/local/share/ca-certificates/internal-ca.crt:ro \
  --entrypoint sh \
  ghcr.io/org/terraform-registry-backend:0.10.0 \
  -c "update-ca-certificates && /usr/bin/terraform-registry"
```

### Option C: Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: internal-ca
data:
  internal-ca.crt: |
    -----BEGIN CERTIFICATE-----
    <your CA certificate>
    -----END CERTIFICATE-----
---
# In the deployment, mount and trust:
volumes:
  - name: ca-cert
    configMap:
      name: internal-ca
volumeMounts:
  - name: ca-cert
    mountPath: /usr/local/share/ca-certificates/internal-ca.crt
    subPath: internal-ca.crt
```

## Private Module Upstream Configuration

To mirror modules from an **internal** upstream registry (e.g., another Terraform Registry instance or Artifactory):

```yaml
# config.yaml
pull_through:
  enabled: true
  upstream_url: "https://registry.internal.example.com"
  # If the upstream requires authentication:
  upstream_token: "${UPSTREAM_REGISTRY_TOKEN}"
```

## Verification

After deployment, verify the air-gapped installation:

```bash
# 1. Health check
curl -k https://localhost:5000/health

# 2. Verify no outbound connections (from the host)
# Watch network traffic — there should be zero external DNS lookups or connections
tcpdump -i any 'not (host postgres.internal or host localhost)' -c 10

# 3. Test module upload and download
terraform login registry.internal.example.com
cd examples/module-consumer/
terraform init

# 4. Verify scanner works offline (if enabled)
curl -k https://localhost:5000/api/v1/admin/scanning/status
```

## Updating an Air-Gapped Deployment

1. On a connected machine, rebuild the bundle with new image tags.
2. Transfer the new bundle.
3. Verify checksums.
4. Load new images: `./load-images.sh`
5. Run database migrations: the backend auto-migrates on startup.
6. Restart services with the new image tags.
7. Verify health: `curl -k https://localhost:5000/health`

See also: [Upgrade Guide](upgrade-guide.md) for version-specific migration notes.

## Troubleshooting

### Images fail to load

```
Error: invalid tar header
```

The tarball may be corrupted during transfer. Re-verify checksums and re-transfer.

### Scanner reports "database not found"

Ensure the offline DB volume is mounted correctly and the `TRIVY_SKIP_DB_UPDATE=true` environment variable is set.

### TLS certificate errors

Ensure your internal CA certificate is trusted inside the container. See [Internal CA Trust](#internal-ca-trust).

### PostgreSQL connection refused

Verify the database is running and reachable from the backend container's network namespace. In Docker Compose, ensure both services are on the same network.
