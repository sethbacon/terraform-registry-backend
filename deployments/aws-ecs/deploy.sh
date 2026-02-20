#!/usr/bin/env bash
# Deploy Terraform Registry to AWS ECS Fargate using the AWS CLI.
# Usage: ./deploy.sh
#
# Prerequisites:
#   - AWS CLI v2 installed and configured
#   - Container images built locally
#   - ECR repositories created (or use the CloudFormation stack)
#
# Environment variables (set before running):
#   AWS_REGION            - AWS region (default: us-east-1)
#   STACK_NAME            - CloudFormation stack name (default: terraform-registry)
#   BACKEND_IMAGE         - Backend image URI (required if not using ECR push)
#   FRONTEND_IMAGE        - Frontend image URI (required if not using ECR push)
#   DB_PASSWORD           - RDS password (required, min 16 chars)
#   JWT_SECRET            - JWT signing secret (required, min 32 chars)
#   ENCRYPTION_KEY        - AES-256 encryption key (required, 32 bytes)
#   DB_INSTANCE_CLASS     - RDS instance class (default: db.t3.micro)
#   DOMAIN_NAME           - Custom domain (optional)
#   CERTIFICATE_ARN       - ACM cert ARN for HTTPS (optional)

set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="${STACK_NAME:-terraform-registry}"
DB_INSTANCE_CLASS="${DB_INSTANCE_CLASS:-db.t3.micro}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Validate required vars
for var in DB_PASSWORD JWT_SECRET ENCRYPTION_KEY; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var is required but not set." >&2
    exit 1
  fi
done

# Default image URIs to ECR repos if not set
BACKEND_IMAGE="${BACKEND_IMAGE:-${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${STACK_NAME}-backend:latest}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${STACK_NAME}-frontend:latest}"

echo "==> Deploying CloudFormation stack: ${STACK_NAME}"
echo "    Region: ${AWS_REGION}"
echo "    Backend Image: ${BACKEND_IMAGE}"
echo "    Frontend Image: ${FRONTEND_IMAGE}"
echo ""

# Build parameters
PARAMS=(
  "ParameterKey=BackendImage,ParameterValue=${BACKEND_IMAGE}"
  "ParameterKey=FrontendImage,ParameterValue=${FRONTEND_IMAGE}"
  "ParameterKey=DBPassword,ParameterValue=${DB_PASSWORD}"
  "ParameterKey=JwtSecret,ParameterValue=${JWT_SECRET}"
  "ParameterKey=EncryptionKey,ParameterValue=${ENCRYPTION_KEY}"
  "ParameterKey=DBInstanceClass,ParameterValue=${DB_INSTANCE_CLASS}"
)

if [ -n "${DOMAIN_NAME:-}" ]; then
  PARAMS+=("ParameterKey=DomainName,ParameterValue=${DOMAIN_NAME}")
fi

if [ -n "${CERTIFICATE_ARN:-}" ]; then
  PARAMS+=("ParameterKey=CertificateArn,ParameterValue=${CERTIFICATE_ARN}")
fi

aws cloudformation deploy \
  --template-file "${SCRIPT_DIR}/cloudformation.yaml" \
  --stack-name "$STACK_NAME" \
  --parameter-overrides "${PARAMS[@]}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --region "$AWS_REGION"

echo ""
echo "==> Stack deployed. Fetching outputs..."
aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$AWS_REGION" \
  --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
  --output table

echo ""
echo "==> Pushing images to ECR..."
aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

# Tag and push images if they differ from ECR URIs
BACKEND_ECR="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${STACK_NAME}-backend:latest"
FRONTEND_ECR="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${STACK_NAME}-frontend:latest"

echo "    Pushing backend image..."
docker tag terraform-registry-backend:latest "$BACKEND_ECR" 2>/dev/null || true
docker push "$BACKEND_ECR"

echo "    Pushing frontend image..."
docker tag terraform-registry-frontend:latest "$FRONTEND_ECR" 2>/dev/null || true
docker push "$FRONTEND_ECR"

echo ""
echo "==> Forcing new deployment..."
aws ecs update-service \
  --cluster "$STACK_NAME" \
  --service "${STACK_NAME}-backend" \
  --force-new-deployment \
  --region "$AWS_REGION" \
  --output text --query 'service.serviceName'

aws ecs update-service \
  --cluster "$STACK_NAME" \
  --service "${STACK_NAME}-frontend" \
  --force-new-deployment \
  --region "$AWS_REGION" \
  --output text --query 'service.serviceName'

echo ""
echo "==> Deployment complete!"
echo ""
echo "Next steps:"
echo "  1. Store the RDS endpoint in Secrets Manager as ${STACK_NAME}/database-host"
echo "  2. Wait for services to stabilize: aws ecs wait services-stable --cluster ${STACK_NAME} --services ${STACK_NAME}-backend ${STACK_NAME}-frontend"
echo "  3. (Optional) Configure custom domain DNS to point to the ALB"
