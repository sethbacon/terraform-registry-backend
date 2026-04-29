<!-- markdownlint-disable MD013 -->
# Cloud-Specific Kubernetes Deployment Guides

This directory contains step-by-step Kubernetes deployment guides for the major
managed-Kubernetes offerings (AKS, EKS, GKE). They cover provider-specific
prerequisites such as ingress controllers, secret stores, and managed databases.

For all other deployment options (Docker Compose, standalone binary, Helm
overview, Azure Container Apps, AWS ECS, GCP Cloud Run, Terraform IaC), see the
top-level [Deployment Guide](../deployment.md).

## Cloud-Specific Guides

| Target                     | Method            | Guide                                              |
| -------------------------- | ----------------- | -------------------------------------------------- |
| **AKS — new cluster**      | Helm or Kustomize | [aks-new-cluster.md](aks-new-cluster.md)           |
| **AKS — existing cluster** | Helm or Kustomize | [aks-existing-cluster.md](aks-existing-cluster.md) |
| **AWS EKS**                | Helm or Kustomize | [eks-deployment.md](eks-deployment.md)             |
| **Google GKE**             | Helm or Kustomize | [gke-deployment.md](gke-deployment.md)             |

For non-Kubernetes targets (Docker Compose, standalone binary, Azure Container
Apps, AWS ECS Fargate, GCP Cloud Run, full-infra Terraform), see the
[main Deployment Guide](../deployment.md) and the corresponding
`deployments/<target>/` directory.

## Kubernetes Deployment Methods

Two deployment methods are provided for Kubernetes (AKS, EKS, GKE, and generic):

### 1. Helm (recommended)

The Helm chart at `deployments/helm/` deploys both the backend and frontend in a single release.

```bash
# Standard Kubernetes (non-AKS) with default values
helm upgrade --install terraform-registry ./deployments/helm \
  --namespace terraform-registry --create-namespace \
  --set externalDatabase.host=<DB_HOST> \
  --set security.jwtSecret=<JWT_SECRET> \
  --set security.encryptionKey=<ENC_KEY>

# AKS with Application Gateway for Containers + Key Vault
helm upgrade --install terraform-registry ./deployments/helm \
  --namespace terraform-registry --create-namespace \
  -f deployments/helm/values-aks.yaml

# EKS with AWS Load Balancer Controller + Secrets Manager
helm upgrade --install terraform-registry ./deployments/helm \
  --namespace terraform-registry --create-namespace \
  -f deployments/helm/values-eks.yaml

# GKE with GKE built-in Gateway + Secret Manager CSI
helm upgrade --install terraform-registry ./deployments/helm \
  --namespace terraform-registry --create-namespace \
  -f deployments/helm/values-gke.yaml
```

### 2. Kustomize

Five overlays are provided at `deployments/kubernetes/overlays/`:

| Overlay       | Description                                                                                   |
| ------------- | --------------------------------------------------------------------------------------------- |
| `dev/`        | Development (1 replica, debug logging, small PVC)                                             |
| `production/` | Generic production (3 replicas, larger resources, pinned images)                              |
| `aks/`        | **AKS-specific** (AGfC Gateway API, Key Vault CSI, Workload Identity, NetworkPolicy)          |
| `eks/`        | **EKS-specific** (AWS LBC Gateway API, ASCP Secrets Manager, IRSA, NetworkPolicy)             |
| `gke/`        | **GKE-specific** (GKE built-in Gateway, Secret Manager CSI, Workload Identity, NetworkPolicy) |

```bash
# AKS deployment
kubectl apply -k deployments/kubernetes/overlays/aks/

# EKS deployment
kubectl apply -k deployments/kubernetes/overlays/eks/

# GKE deployment
kubectl apply -k deployments/kubernetes/overlays/gke/

# Generic production
kubectl apply -k deployments/kubernetes/overlays/production/
```

## Ingress Architecture

### AKS — Application Gateway for Containers

Uses **Application Gateway for Containers (AGfC)** with the Kubernetes **Gateway API** (v1 GA):

```txt
Internet
    │
    ▼
Application Gateway for Containers (AGfC)
    │  GatewayClass: azure-alb-external
    │  Gateway: terraform-registry-gateway
    │
    ├─ /api/* /v1/* /.well-known/* /terraform/* ──▶ backend:8080
    │  /health /ready /swagger.json /webhooks/*
    │
    └─ /* (catch-all) ──────────────────────────▶ frontend:80 ──▶ backend:8080
                                                    (nginx SPA)    (proxy for
                                                                   remaining paths)
```

### EKS — AWS Load Balancer Controller

Uses **AWS Application Load Balancer (ALB)** via the **Kubernetes Gateway API**:

```txt
Internet
    │
    ▼
ALB (internet-facing)
    │  GatewayClass: aws-application-lb
    │  Gateway: terraform-registry-gateway
    │
    ├─ /api/* /v1/* /.well-known/* /terraform/* ──▶ backend:8080
    └─ /* (catch-all) ──────────────────────────▶ frontend:80
```

### GKE — Built-in GKE Gateway Controller

Uses the **GKE built-in external Application Load Balancer** via **Kubernetes Gateway API**:

```txt
Internet
    │
    ▼
GKE External ALB
    │  GatewayClass: gke-l7-global-external-managed (pre-provisioned)
    │  Gateway: terraform-registry-gateway
    │
    ├─ /api/* /v1/* /.well-known/* /terraform/* ──▶ backend:8080
    └─ /* (catch-all) ──────────────────────────▶ frontend:80
```

### Generic Kubernetes (non-cloud)

Uses the legacy nginx `Ingress` resource with `ingressClassName: nginx`. The upstream
`ingress-nginx` project ended maintenance in March 2026. Plan to migrate.

## Key Architecture Decisions

- **No in-cluster PostgreSQL**: The chart and manifests expect an external database (Azure Database for PostgreSQL Flexible Server for AKS; Amazon RDS for EKS; Cloud SQL for GKE). No StatefulSet for Postgres is deployed.
- **Storage**: Default is `local` (PVC). For cloud deployments with multiple replicas, switch to `azure` (Azure Blob), `s3` (Amazon S3), or `gcs` (Google Cloud Storage). See the cloud-specific values files.
- **Secrets**: For AKS use Azure Key Vault + Secrets Store CSI Driver. For EKS use AWS Secrets Manager + ASCP. For GKE use GCP Secret Manager + CSI provider. For other environments use Sealed Secrets, External Secrets Operator, or CI/CD injection.
- **Frontend k8s manifests live in the backend repo**: A single Helm release or `kubectl apply -k` deploys both services.

## Quick Links

### AKS

- [AKS Prerequisites](aks-prerequisites.md) — Required Azure resources and cluster features
- [AKS New Cluster Guide](aks-new-cluster.md) — Full setup walkthrough from scratch
- [AKS Existing Cluster Guide](aks-existing-cluster.md) — Deploy into an existing AKS cluster
- [AKS Operations](aks-operations.md) — Upgrades, certificate renewal, scaling, troubleshooting

### EKS

- [EKS Prerequisites](eks-prerequisites.md) — Required AWS resources and cluster setup
- [EKS Deployment Guide](eks-deployment.md) — Deploy the registry to EKS

### GKE

- [GKE Prerequisites](gke-prerequisites.md) — Required GCP resources and cluster setup
- [GKE Deployment Guide](gke-deployment.md) — Deploy the registry to GKE
