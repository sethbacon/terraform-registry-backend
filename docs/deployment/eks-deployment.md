# EKS Deployment Guide — Terraform Registry

Complete all steps in [eks-prerequisites.md](eks-prerequisites.md) first.

---

## Step 1 — Fill in placeholder values

Collect the values you captured during prerequisites:

| Placeholder        | How to get it                                                                                                                          |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `<ACCOUNT_ID>`     | `aws sts get-caller-identity --query Account --output text`                                                                            |
| `<AWS_REGION>`     | Your chosen region                                                                                                                     |
| `<RDS_ENDPOINT>`   | `aws rds describe-db-instances --db-instance-identifier terraform-registry-db --query "DBInstances[0].Endpoint.Address" --output text` |
| `<S3_BUCKET_NAME>` | `terraform-registry-artifacts-<ACCOUNT_ID>`                                                                                            |
| `<IRSA_ROLE_NAME>` | `terraform-registry-irsa`                                                                                                              |
| `<HOSTNAME>`       | Your public DNS name                                                                                                                   |
| `<EMAIL>`          | Your ops email                                                                                                                         |
| `<IMAGE_TAG>`      | `v0.8.2`                                                                                                                               |

---

## Step 2 — Deploy

### Option A: Helm

```bash
cp deployments/helm/values-eks.yaml deployments/helm/values-eks-prod.yaml
# Edit values-eks-prod.yaml — replace every <PLACEHOLDER>

helm upgrade --install terraform-registry ./deployments/helm \
  --namespace terraform-registry --create-namespace \
  -f deployments/helm/values-eks-prod.yaml \
  --wait --timeout 5m

# Apply the SecretProviderClass separately (not in the Helm chart for EKS)
# Edit deployments/kubernetes/overlays/eks/secretproviderclass.yaml, then:
kubectl apply -f deployments/kubernetes/overlays/eks/secretproviderclass.yaml
```

### Option B: Kustomize

```bash
# Edit all overlay files, replace every <PLACEHOLDER>:
#   overlays/eks/gateway.yaml              → hostname
#   overlays/eks/httproute.yaml            → hostname (x3)
#   overlays/eks/certificate.yaml          → dnsNames
#   overlays/eks/clusterissuer.yaml        → email (x2)
#   overlays/eks/secretproviderclass.yaml  → AWS_REGION, ACCOUNT_ID
#   overlays/eks/patches/serviceaccount-irsa.yaml → role-arn annotation
#   overlays/eks/patches/configmap-eks.yaml → RDS endpoint, S3 bucket, hostname
#   overlays/eks/kustomization.yaml        → ECR repo, image tag

kubectl apply -k deployments/kubernetes/overlays/eks/
```

---

## Step 3 — Verify ALB provisioning

```bash
kubectl get gateway -n terraform-registry -w
# Wait for ADDRESS field to show the ALB DNS name

kubectl describe gateway terraform-registry-gateway -n terraform-registry
```

---

## Step 4 — Configure DNS

```bash
ALB_DNS=$(kubectl get gateway terraform-registry-gateway \
  -n terraform-registry -o jsonpath='{.status.addresses[0].value}')
echo "ALB DNS: $ALB_DNS"
```

Create a CNAME record (or ALIAS for Route53) pointing `registry.yourdomain.com` to `$ALB_DNS`.

> **Note:** For Route53 ALIAS records, select "Alias to Application and Classic Load Balancer" and select the correct region and ALB.

---

## Step 5 — Verify certificate and application

```bash
# Certificate (takes 1-3 minutes after DNS propagates)
kubectl get certificate -n terraform-registry -w

# All pods running
kubectl get pods -n terraform-registry

# Smoke test
curl https://registry.yourdomain.com/health
curl https://registry.yourdomain.com/.well-known/terraform.json
```

---

## Step 6 — Promote to production TLS

```bash
kubectl delete secret terraform-registry-tls -n terraform-registry

# Helm
helm upgrade terraform-registry ./deployments/helm \
  -n terraform-registry -f deployments/helm/values-eks-prod.yaml \
  --set gatewayAPI.certManagerIssuer=letsencrypt-prod

# Kustomize: edit overlays/eks/certificate.yaml → letsencrypt-prod, then apply
```

---

## Troubleshooting

### ALB not provisioning

```bash
kubectl logs -n kube-system \
  -l app.kubernetes.io/name=aws-load-balancer-controller --tail=50
```

- Verify public subnets are tagged with `kubernetes.io/role/elb=1`.
- Verify IRSA role for LBC has the required IAM policy.

### Secrets not syncing

```bash
kubectl describe secretproviderclass terraform-registry-secrets -n terraform-registry
kubectl logs -n kube-system -l app=csi-secrets-store-provider-aws
```

- Verify the IRSA role has `secretsmanager:GetSecretValue` on the secrets.
- Verify the secret ARNs in the `SecretProviderClass` are correct.
