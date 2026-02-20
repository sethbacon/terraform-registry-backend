#!/usr/bin/env bash
# Deploy Terraform Registry to Azure Container Apps using the Azure CLI.
# Usage: ./deploy.sh
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Container images pushed to ACR
#   - PostgreSQL Flexible Server provisioned
#
# Environment variables (set before running):
#   RESOURCE_GROUP        - Azure resource group name
#   LOCATION              - Azure region (default: eastus)
#   ENV_NAME              - Container Apps environment name (default: terraform-registry)
#   ACR_NAME              - Azure Container Registry name
#   BACKEND_IMAGE         - Full backend image reference
#   FRONTEND_IMAGE        - Full frontend image reference
#   DATABASE_HOST         - PostgreSQL FQDN
#   DATABASE_NAME         - Database name (default: terraform_registry)
#   DATABASE_USER         - Database user (default: registry)
#   DATABASE_PASSWORD     - Database password (required)
#   JWT_SECRET            - JWT signing secret (required)
#   ENCRYPTION_KEY        - AES-256 encryption key (required)
#   CUSTOM_DOMAIN         - Custom domain (optional)

set -euo pipefail

# Defaults
LOCATION="${LOCATION:-eastus}"
ENV_NAME="${ENV_NAME:-terraform-registry}"
DATABASE_NAME="${DATABASE_NAME:-terraform_registry}"
DATABASE_USER="${DATABASE_USER:-registry}"

# Validate required vars
for var in RESOURCE_GROUP ACR_NAME BACKEND_IMAGE FRONTEND_IMAGE DATABASE_HOST DATABASE_PASSWORD JWT_SECRET ENCRYPTION_KEY; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var is required but not set." >&2
    exit 1
  fi
done

echo "==> Creating resource group (if needed)..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none 2>/dev/null || true

echo "==> Creating Container Apps environment..."
az containerapp env create \
  --name "${ENV_NAME}-env" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --output none

# Get ACR credentials
ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)
ACR_USERNAME=$(az acr credential show --name "$ACR_NAME" --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name "$ACR_NAME" --query 'passwords[0].value' -o tsv)

BASE_URL="https://${ENV_NAME}-frontend.${LOCATION}.azurecontainerapps.io"
if [ -n "${CUSTOM_DOMAIN:-}" ]; then
  BASE_URL="https://${CUSTOM_DOMAIN}"
fi

echo "==> Deploying backend..."
az containerapp create \
  --name "${ENV_NAME}-backend" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "${ENV_NAME}-env" \
  --image "$BACKEND_IMAGE" \
  --registry-server "$ACR_LOGIN_SERVER" \
  --registry-username "$ACR_USERNAME" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 8080 \
  --ingress internal \
  --cpu 0.5 \
  --memory 1.0Gi \
  --min-replicas 1 \
  --max-replicas 10 \
  --secrets \
    "database-password=${DATABASE_PASSWORD}" \
    "jwt-secret=${JWT_SECRET}" \
    "encryption-key=${ENCRYPTION_KEY}" \
  --env-vars \
    "TFR_SERVER_HOST=0.0.0.0" \
    "TFR_SERVER_PORT=8080" \
    "TFR_SERVER_BASE_URL=${BASE_URL}" \
    "TFR_DATABASE_HOST=${DATABASE_HOST}" \
    "TFR_DATABASE_PORT=5432" \
    "TFR_DATABASE_NAME=${DATABASE_NAME}" \
    "TFR_DATABASE_USER=${DATABASE_USER}" \
    "TFR_DATABASE_PASSWORD=secretref:database-password" \
    "TFR_DATABASE_SSL_MODE=require" \
    "TFR_JWT_SECRET=secretref:jwt-secret" \
    "ENCRYPTION_KEY=secretref:encryption-key" \
    "TFR_SECURITY_TLS_ENABLED=false" \
    "TFR_STORAGE_DEFAULT_BACKEND=azure" \
    "TFR_AUTH_API_KEYS_ENABLED=true" \
    "TFR_LOGGING_LEVEL=info" \
    "TFR_LOGGING_FORMAT=json" \
    "DEV_MODE=false" \
  --output none

echo "==> Deploying frontend..."
az containerapp create \
  --name "${ENV_NAME}-frontend" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "${ENV_NAME}-env" \
  --image "$FRONTEND_IMAGE" \
  --registry-server "$ACR_LOGIN_SERVER" \
  --registry-username "$ACR_USERNAME" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 80 \
  --ingress external \
  --cpu 0.25 \
  --memory 0.5Gi \
  --min-replicas 1 \
  --max-replicas 5 \
  --output none

FRONTEND_FQDN=$(az containerapp show \
  --name "${ENV_NAME}-frontend" \
  --resource-group "$RESOURCE_GROUP" \
  --query 'properties.configuration.ingress.fqdn' -o tsv)

echo ""
echo "==> Deployment complete!"
echo "    Frontend URL: https://${FRONTEND_FQDN}"
echo ""
echo "Next steps:"
echo "  1. Configure Azure Blob Storage env vars on the backend container app"
echo "  2. (Optional) Bind a custom domain: az containerapp hostname bind ..."
echo "  3. Verify: curl https://${FRONTEND_FQDN}/health"
