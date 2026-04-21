#!/usr/bin/env bash
# airgap-bundle.sh — Build an offline installation bundle for air-gapped environments.
#
# This script packages all runtime artifacts needed to deploy the Terraform
# Registry in a network-isolated environment:
#   - Backend container image (docker save)
#   - Frontend container image (docker save)
#   - Trivy offline vulnerability DB (optional)
#   - Checkov rules bundle (optional)
#   - Helm chart archive
#   - Internal CA trust instructions
#
# Usage:
#   ./scripts/airgap-bundle.sh [--backend-image IMAGE] [--frontend-image IMAGE] \
#       [--scanner trivy|checkov|none] [--output DIR]
#
# Example:
#   ./scripts/airgap-bundle.sh \
#       --backend-image ghcr.io/org/terraform-registry-backend:0.10.0 \
#       --frontend-image ghcr.io/org/terraform-registry-frontend:0.10.0 \
#       --scanner trivy \
#       --output /tmp/airgap-bundle
#
set -euo pipefail

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------
BACKEND_IMAGE="${BACKEND_IMAGE:-ghcr.io/terraform-registry/backend:latest}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-ghcr.io/terraform-registry/frontend:latest}"
SCANNER="none"
OUTPUT_DIR="./airgap-bundle"
HELM_CHART_DIR="./deployments/helm"

# --------------------------------------------------------------------------
# Parse arguments
# --------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-image)  BACKEND_IMAGE="$2"; shift 2 ;;
    --frontend-image) FRONTEND_IMAGE="$2"; shift 2 ;;
    --scanner)        SCANNER="$2"; shift 2 ;;
    --output)         OUTPUT_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# --------------------------------------------------------------------------
# Validate prerequisites
# --------------------------------------------------------------------------
for cmd in docker tar; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: Required command '$cmd' not found in PATH." >&2
    exit 1
  fi
done

echo "==> Creating air-gap bundle in ${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}/images" "${OUTPUT_DIR}/scanner-db" "${OUTPUT_DIR}/helm" "${OUTPUT_DIR}/certs"

# --------------------------------------------------------------------------
# 1. Save container images
# --------------------------------------------------------------------------
echo "==> Pulling and saving backend image: ${BACKEND_IMAGE}"
docker pull "${BACKEND_IMAGE}"
docker save "${BACKEND_IMAGE}" | gzip > "${OUTPUT_DIR}/images/backend.tar.gz"

echo "==> Pulling and saving frontend image: ${FRONTEND_IMAGE}"
docker pull "${FRONTEND_IMAGE}"
docker save "${FRONTEND_IMAGE}" | gzip > "${OUTPUT_DIR}/images/frontend.tar.gz"

# --------------------------------------------------------------------------
# 2. Save PostgreSQL image (commonly needed)
# --------------------------------------------------------------------------
PG_IMAGE="postgres:16-alpine"
echo "==> Pulling and saving PostgreSQL image: ${PG_IMAGE}"
docker pull "${PG_IMAGE}"
docker save "${PG_IMAGE}" | gzip > "${OUTPUT_DIR}/images/postgres.tar.gz"

# --------------------------------------------------------------------------
# 3. Scanner offline DB
# --------------------------------------------------------------------------
case "${SCANNER}" in
  trivy)
    echo "==> Downloading Trivy offline vulnerability DB..."
    if command -v trivy &>/dev/null; then
      trivy image --download-db-only --cache-dir "${OUTPUT_DIR}/scanner-db/trivy"
      echo "  Trivy DB cached at ${OUTPUT_DIR}/scanner-db/trivy"
    else
      echo "  WARN: 'trivy' not found — download the DB manually:"
      echo "    trivy image --download-db-only --cache-dir ${OUTPUT_DIR}/scanner-db/trivy"
    fi
    ;;
  checkov)
    echo "==> Downloading Checkov rules bundle..."
    if command -v checkov &>/dev/null; then
      checkov --download-external-modules-from-registry false \
              --list 2>/dev/null > "${OUTPUT_DIR}/scanner-db/checkov-rules.txt" || true
      echo "  Checkov rules list saved. Copy the Checkov package and its dependencies."
    else
      echo "  WARN: 'checkov' not found — install via pip and bundle the package."
    fi
    ;;
  none)
    echo "==> Skipping scanner DB (--scanner=none)"
    ;;
  *)
    echo "ERROR: Unsupported scanner '${SCANNER}'. Use trivy, checkov, or none." >&2
    exit 1
    ;;
esac

# --------------------------------------------------------------------------
# 4. Package Helm chart
# --------------------------------------------------------------------------
if [[ -d "${HELM_CHART_DIR}" ]]; then
  echo "==> Packaging Helm chart..."
  if command -v helm &>/dev/null; then
    helm package "${HELM_CHART_DIR}" --destination "${OUTPUT_DIR}/helm/"
  else
    echo "  WARN: 'helm' not found — copying chart directory as-is."
    cp -r "${HELM_CHART_DIR}" "${OUTPUT_DIR}/helm/chart"
  fi
else
  echo "==> Skipping Helm chart (directory ${HELM_CHART_DIR} not found)"
fi

# --------------------------------------------------------------------------
# 5. Copy CA trust helper
# --------------------------------------------------------------------------
cat > "${OUTPUT_DIR}/certs/README.md" << 'CERT_README'
# Internal CA Trust Configuration

If your air-gapped environment uses an internal certificate authority (CA),
the registry containers must trust that CA.

## Backend container (Alpine-based)

```bash
# Copy your CA certificate into the container's trust store
docker run -v /path/to/ca.crt:/usr/local/share/ca-certificates/internal-ca.crt \
  --entrypoint sh ghcr.io/terraform-registry/backend:latest \
  -c "update-ca-certificates && /usr/bin/terraform-registry"
```

Or build a derived image:

```dockerfile
FROM ghcr.io/terraform-registry/backend:latest
COPY internal-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
```

## Frontend container (nginx-based)

The frontend container typically doesn't make outbound TLS calls, but if your
nginx config proxies to HTTPS upstreams, add the CA cert similarly.

## Kubernetes

Mount your CA bundle as a ConfigMap and add it to the container's trust store
via an init container or volume mount to `/usr/local/share/ca-certificates/`.
CERT_README

# --------------------------------------------------------------------------
# 6. Create manifest and checksum
# --------------------------------------------------------------------------
echo "==> Creating bundle manifest..."
cat > "${OUTPUT_DIR}/MANIFEST.md" << EOF
# Air-Gap Bundle Manifest

**Created:** $(date -u +%Y-%m-%dT%H:%M:%SZ)
**Backend image:** ${BACKEND_IMAGE}
**Frontend image:** ${FRONTEND_IMAGE}
**Scanner:** ${SCANNER}

## Contents

| Path                        | Description                     |
| --------------------------- | ------------------------------- |
| images/backend.tar.gz       | Backend container image         |
| images/frontend.tar.gz      | Frontend container image        |
| images/postgres.tar.gz      | PostgreSQL 16 image             |
| scanner-db/                 | Scanner offline DB (if any)     |
| helm/                       | Helm chart archive              |
| certs/README.md             | Internal CA trust instructions  |
| load-images.sh              | Helper script to load images    |
| MANIFEST.md                 | This file                       |
| SHA256SUMS                  | Checksums for all artifacts     |

## Quick Start

1. Copy this bundle to the air-gapped host.
2. Run \`./load-images.sh\` to import container images.
3. Deploy via Helm or docker-compose using the loaded images.
4. See \`certs/README.md\` for internal CA trust setup.
EOF

# --------------------------------------------------------------------------
# 7. Create image loader helper
# --------------------------------------------------------------------------
cat > "${OUTPUT_DIR}/load-images.sh" << 'LOADER'
#!/usr/bin/env bash
# Load all container images from the air-gap bundle into the local Docker daemon.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Loading container images..."
for img in "${SCRIPT_DIR}"/images/*.tar.gz; do
  echo "  Loading $(basename "$img")..."
  docker load < "$img"
done
echo "Done. All images loaded."
LOADER
chmod +x "${OUTPUT_DIR}/load-images.sh"

# --------------------------------------------------------------------------
# 8. Generate checksums
# --------------------------------------------------------------------------
echo "==> Generating checksums..."
(cd "${OUTPUT_DIR}" && find . -type f ! -name 'SHA256SUMS' -exec sha256sum {} + > SHA256SUMS)

# --------------------------------------------------------------------------
# 9. Create final tarball
# --------------------------------------------------------------------------
BUNDLE_NAME="terraform-registry-airgap-$(date +%Y%m%d).tar.gz"
echo "==> Creating tarball: ${BUNDLE_NAME}"
tar -czf "${BUNDLE_NAME}" -C "$(dirname "${OUTPUT_DIR}")" "$(basename "${OUTPUT_DIR}")"

echo ""
echo "Air-gap bundle created successfully:"
echo "  Directory: ${OUTPUT_DIR}/"
echo "  Tarball:   ${BUNDLE_NAME}"
echo "  Size:      $(du -sh "${BUNDLE_NAME}" | cut -f1)"
