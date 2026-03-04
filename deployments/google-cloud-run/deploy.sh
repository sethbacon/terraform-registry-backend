#!/usr/bin/env bash
# Deploy Terraform Registry to Google Cloud Run using gcloud CLI.
# Usage: ./deploy.sh
#
# Prerequisites:
#   - gcloud CLI installed and authenticated
#   - APIs enabled: run.googleapis.com, sqladmin.googleapis.com, secretmanager.googleapis.com
#   - Container images built locally or in Artifact Registry
#   - Cloud SQL instance provisioned
#
# Environment variables (set before running):
#   PROJECT_ID            - GCP project ID (required)
#   REGION                - GCP region (default: us-central1)
#   BACKEND_IMAGE         - Backend image URI (optional, defaults to Artifact Registry)
#   FRONTEND_IMAGE        - Frontend image URI (optional, defaults to Artifact Registry)
#   CLOUD_SQL_INSTANCE    - Cloud SQL connection name: PROJECT:REGION:INSTANCE (required)
#   VPC_CONNECTOR         - VPC connector name (optional, for private Cloud SQL)
#   DATABASE_PASSWORD     - Database password (required)
#   JWT_SECRET            - JWT signing secret (required)
#   ENCRYPTION_KEY        - AES-256 encryption key (required)
#   GCS_BUCKET            - GCS bucket for storage (required)
#   CUSTOM_DOMAIN         - Custom domain (optional)

set -euo pipefail

REGION="${REGION:-us-central1}"

# Validate required vars
for var in PROJECT_ID CLOUD_SQL_INSTANCE DATABASE_PASSWORD JWT_SECRET ENCRYPTION_KEY GCS_BUCKET; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var is required but not set." >&2
    exit 1
  fi
done

# Default images
BACKEND_IMAGE="${BACKEND_IMAGE:-${REGION}-docker.pkg.dev/${PROJECT_ID}/terraform-registry/backend:latest}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-${REGION}-docker.pkg.dev/${PROJECT_ID}/terraform-registry/frontend:latest}"

echo "==> Project: ${PROJECT_ID}"
echo "    Region: ${REGION}"
echo ""

# Set project
gcloud config set project "$PROJECT_ID"

# Ensure required APIs are enabled
echo "==> Enabling required APIs..."
gcloud services enable \
  run.googleapis.com \
  secretmanager.googleapis.com \
  sqladmin.googleapis.com \
  artifactregistry.googleapis.com \
  --quiet

# Create Artifact Registry repository (if needed)
echo "==> Creating Artifact Registry repository (if needed)..."
gcloud artifacts repositories describe terraform-registry \
  --location="$REGION" --format="value(name)" 2>/dev/null || \
gcloud artifacts repositories create terraform-registry \
  --repository-format=docker \
  --location="$REGION" \
  --description="Terraform Registry container images"

# Create secrets (if they don't exist)
echo "==> Creating secrets in Secret Manager..."
for secret_name in terraform-registry-db-password terraform-registry-jwt-secret terraform-registry-encryption-key; do
  gcloud secrets describe "$secret_name" --project="$PROJECT_ID" 2>/dev/null || \
    gcloud secrets create "$secret_name" --replication-policy="automatic" --project="$PROJECT_ID"
done

# Set secret values
echo "$DATABASE_PASSWORD" | gcloud secrets versions add terraform-registry-db-password --data-file=- --project="$PROJECT_ID"
echo "$JWT_SECRET" | gcloud secrets versions add terraform-registry-jwt-secret --data-file=- --project="$PROJECT_ID"
echo "$ENCRYPTION_KEY" | gcloud secrets versions add terraform-registry-encryption-key --data-file=- --project="$PROJECT_ID"

# Create service account
SA_NAME="terraform-registry-backend"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "==> Creating service account..."
gcloud iam service-accounts describe "$SA_EMAIL" 2>/dev/null || \
  gcloud iam service-accounts create "$SA_NAME" \
    --display-name="Terraform Registry Backend"

# Grant permissions
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/cloudsql.client" --quiet

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/secretmanager.secretAccessor" --quiet

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/storage.objectAdmin" --quiet

# Push images
echo "==> Configuring Docker for Artifact Registry..."
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

echo "==> Pushing backend image..."
docker tag terraform-registry-backend:latest "$BACKEND_IMAGE" 2>/dev/null || true
docker push "$BACKEND_IMAGE"

echo "==> Pushing frontend image..."
docker tag terraform-registry-frontend:latest "$FRONTEND_IMAGE" 2>/dev/null || true
docker push "$FRONTEND_IMAGE"

# Build VPC connector flag
VPC_FLAG=""
if [ -n "${VPC_CONNECTOR:-}" ]; then
  VPC_FLAG="--vpc-connector=${VPC_CONNECTOR} --vpc-egress=private-ranges-only"
fi

# Deploy backend
echo "==> Deploying backend service..."
gcloud run deploy terraform-registry-backend \
  --image="$BACKEND_IMAGE" \
  --region="$REGION" \
  --platform=managed \
  --port=8080 \
  --cpu=1 \
  --memory=1Gi \
  --min-instances=1 \
  --max-instances=10 \
  --concurrency=80 \
  --timeout=300 \
  --service-account="$SA_EMAIL" \
  --ingress=internal-and-cloud-load-balancing \
  --add-cloudsql-instances="$CLOUD_SQL_INSTANCE" \
  --set-secrets="TFR_DATABASE_PASSWORD=terraform-registry-db-password:latest,TFR_JWT_SECRET=terraform-registry-jwt-secret:latest,ENCRYPTION_KEY=terraform-registry-encryption-key:latest" \
  --set-env-vars="TFR_SERVER_HOST=0.0.0.0,TFR_SERVER_PORT=8080,TFR_DATABASE_HOST=/cloudsql/${CLOUD_SQL_INSTANCE},TFR_DATABASE_PORT=5432,TFR_DATABASE_NAME=terraform_registry,TFR_DATABASE_USER=registry,TFR_DATABASE_SSL_MODE=disable,TFR_SECURITY_TLS_ENABLED=false,TFR_STORAGE_DEFAULT_BACKEND=gcs,TFR_STORAGE_GCS_BUCKET=${GCS_BUCKET},TFR_STORAGE_GCS_PROJECT_ID=${PROJECT_ID},TFR_AUTH_API_KEYS_ENABLED=true,TFR_LOGGING_LEVEL=info,TFR_LOGGING_FORMAT=json,DEV_MODE=false" \
  ${VPC_FLAG} \
  --no-allow-unauthenticated \
  --quiet

# Deploy frontend
echo "==> Deploying frontend service..."
gcloud run deploy terraform-registry-frontend \
  --image="$FRONTEND_IMAGE" \
  --region="$REGION" \
  --platform=managed \
  --port=80 \
  --cpu=0.5 \
  --memory=256Mi \
  --min-instances=1 \
  --max-instances=5 \
  --concurrency=200 \
  --timeout=60 \
  --allow-unauthenticated \
  --quiet

# Get URLs
BACKEND_URL=$(gcloud run services describe terraform-registry-backend --region="$REGION" --format="value(status.url)")
FRONTEND_URL=$(gcloud run services describe terraform-registry-frontend --region="$REGION" --format="value(status.url)")

echo ""
echo "==> Deployment complete!"
echo "    Backend URL:  ${BACKEND_URL}"
echo "    Frontend URL: ${FRONTEND_URL}"
echo ""
echo "Next steps:"
echo "  1. Update TFR_SERVER_BASE_URL on the backend to match the frontend URL or custom domain"
echo "  2. Configure nginx in the frontend image to proxy API requests to the backend URL"
echo "  3. (Optional) Set up a custom domain: gcloud run domain-mappings create --service=terraform-registry-frontend --domain=${CUSTOM_DOMAIN:-registry.example.com}"
echo "  4. Verify: curl ${FRONTEND_URL}/"
