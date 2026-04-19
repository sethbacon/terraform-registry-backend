# EKS Prerequisites — Terraform Registry

Resources and tooling required before deploying to AWS EKS.

---

## 1. Required tools

| Tool            | Min version | Install                                                               |
| --------------- | ----------- | --------------------------------------------------------------------- |
| AWS CLI (`aws`) | 2.x         | <https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html> |
| `eksctl`        | 0.170       | <https://eksctl.io/installation/>                                     |
| kubectl         | 1.28        | `aws eks install-kubectl`                                             |
| Helm            | 3.12        | <https://helm.sh/docs/intro/install/>                                 |

```bash
aws configure
# Set: AWS Access Key ID, Secret Access Key, Default region, Output format
```

---

## 2. AWS resources to provision

### 2a. Amazon ECR Repositories

```bash
aws ecr create-repository \
  --repository-name terraform-registry-backend \
  --region <AWS_REGION>

aws ecr create-repository \
  --repository-name terraform-registry-frontend \
  --region <AWS_REGION>

# Authenticate and push images
aws ecr get-login-password --region <AWS_REGION> | \
  docker login --username AWS \
  --password-stdin <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com

docker tag terraform-registry-backend:latest \
  <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/terraform-registry-backend:v0.8.1
docker push <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/terraform-registry-backend:v0.8.1

docker tag terraform-registry-frontend:latest \
  <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/terraform-registry-frontend:v0.8.1
docker push <ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/terraform-registry-frontend:v0.8.1
```

### 2b. Amazon RDS for PostgreSQL

```bash
# Create a subnet group first (using existing VPC subnets, created with EKS cluster)
# Or provision via CloudFormation / Terraform

aws rds create-db-instance \
  --db-instance-identifier terraform-registry-db \
  --db-instance-class db.t3.medium \
  --engine postgres \
  --engine-version 16.2 \
  --master-username registry \
  --master-user-password <STRONG_PASSWORD> \
  --db-name terraform_registry \
  --storage-type gp2 \
  --allocated-storage 32 \
  --backup-retention-period 7 \
  --no-publicly-accessible \
  --vpc-security-group-ids <SG_ID>
```

Note the `Endpoint.Address` output — this is your `<RDS_ENDPOINT>`.

### 2c. Amazon S3 Bucket

```bash
aws s3api create-bucket \
  --bucket terraform-registry-artifacts-<ACCOUNT_ID> \
  --region <AWS_REGION>

aws s3api put-public-access-block \
  --bucket terraform-registry-artifacts-<ACCOUNT_ID> \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

aws s3api put-bucket-versioning \
  --bucket terraform-registry-artifacts-<ACCOUNT_ID> \
  --versioning-configuration Status=Enabled
```

### 2d. AWS Secrets Manager

```bash
# Store secrets as individual entries:
aws secretsmanager create-secret \
  --name "terraform-registry/jwt-secret" \
  --secret-string "$(openssl rand -hex 32)" \
  --region <AWS_REGION>

aws secretsmanager create-secret \
  --name "terraform-registry/encryption-key" \
  --secret-string "$(openssl rand -hex 16)" \
  --region <AWS_REGION>

aws secretsmanager create-secret \
  --name "terraform-registry/database-password" \
  --secret-string "<STRONG_PASSWORD>" \
  --region <AWS_REGION>
```

### 2e. IAM Policy for the Registry workload

```bash
cat > terraform-registry-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::terraform-registry-artifacts-<ACCOUNT_ID>",
        "arn:aws:s3:::terraform-registry-artifacts-<ACCOUNT_ID>/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],
      "Resource": "arn:aws:secretsmanager:<AWS_REGION>:<ACCOUNT_ID>:secret:terraform-registry/*"
    }
  ]
}
EOF

aws iam create-policy \
  --policy-name TerraformRegistryPolicy \
  --policy-document file://terraform-registry-policy.json
```

---

## 3. EKS cluster creation

```bash
eksctl create cluster \
  --name terraform-registry-cluster \
  --region <AWS_REGION> \
  --version 1.30 \
  --nodegroup-name standard-nodes \
  --node-type t3.large \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 6 \
  --zones <REGION>a,<REGION>b,<REGION>c \
  --with-oidc \
  --ssh-access \
  --ssh-public-key <KEY_PAIR_NAME> \
  --managed

aws eks update-kubeconfig \
  --region <AWS_REGION> \
  --name terraform-registry-cluster
```

---

## 4. IRSA setup

```bash
# Associate OIDC (already done by eksctl --with-oidc, verify with:)
aws eks describe-cluster --name terraform-registry-cluster \
  --query "cluster.identity.oidc.issuer" --output text

# Create IRSA service account + role
eksctl create iamserviceaccount \
  --namespace terraform-registry \
  --name terraform-registry \
  --cluster terraform-registry-cluster \
  --region <AWS_REGION> \
  --role-name terraform-registry-irsa \
  --attach-policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/TerraformRegistryPolicy \
  --approve

# Get role ARN for overlay patch
aws iam get-role --role-name terraform-registry-irsa \
  --query "Role.Arn" --output text
```

---

## 5. AWS Load Balancer Controller

```bash
# Download IAM policy for LBC
curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.7.2/docs/install/iam_policy.json

aws iam create-policy \
  --policy-name AWSLoadBalancerControllerIAMPolicy \
  --policy-document file://iam_policy.json

# Create IRSA for LBC
eksctl create iamserviceaccount \
  --cluster terraform-registry-cluster \
  --namespace kube-system \
  --name aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve

# Install LBC via Helm
helm repo add eks https://aws.github.io/eks-charts
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=terraform-registry-cluster \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller
```

---

## 6. Secrets Store CSI Driver + ASCP

```bash
# Install CSI driver
helm repo add secrets-store-csi-driver \
  https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store \
  secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true

# Install AWS provider (ASCP)
kubectl apply -f https://raw.githubusercontent.com/aws/secrets-store-csi-driver-provider-aws/main/deployment/aws-provider-installer.yaml
```

---

## 7. cert-manager

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml

helm repo add jetstack https://charts.jetstack.io --force-update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true \
  --set "featureGates=ExperimentalGatewayAPISupport=true"
```

---

## 8. Public subnets tagged for ALB

EKS public subnets must be tagged for the LBC ALB auto-discovery:

```bash
aws ec2 create-tags \
  --resources <PUBLIC_SUBNET_ID_1> <PUBLIC_SUBNET_ID_2> <PUBLIC_SUBNET_ID_3> \
  --tags Key=kubernetes.io/role/elb,Value=1 \
  Key=kubernetes.io/cluster/terraform-registry-cluster,Value=shared
```

---

## Placeholder reference

| Placeholder        | Value                                                                                                                                  |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `<ACCOUNT_ID>`     | `aws sts get-caller-identity --query Account --output text`                                                                            |
| `<AWS_REGION>`     | e.g. `us-east-1`                                                                                                                       |
| `<RDS_ENDPOINT>`   | `aws rds describe-db-instances --db-instance-identifier terraform-registry-db --query "DBInstances[0].Endpoint.Address" --output text` |
| `<S3_BUCKET_NAME>` | `terraform-registry-artifacts-<ACCOUNT_ID>`                                                                                            |
| `<IRSA_ROLE_NAME>` | `terraform-registry-irsa`                                                                                                              |
| `<HOSTNAME>`       | Your public DNS name                                                                                                                   |
| `<OPS_EMAIL>`      | Email for Let's Encrypt                                                                                                                |
