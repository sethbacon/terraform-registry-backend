# GKE Prerequisites — Terraform Registry

Resources and tooling required before deploying to Google Kubernetes Engine.

---

## 1. Required tools

| Tool                        | Min version | Install                                              |
| --------------------------- | ----------- | ---------------------------------------------------- |
| Google Cloud CLI (`gcloud`) | 474+        | <https://cloud.google.com/sdk/docs/install>          |
| `gke-gcloud-auth-plugin`    | latest      | `gcloud components install gke-gcloud-auth-plugin`   |
| kubectl                     | 1.28        | `gcloud components install kubectl`                  |
| Helm                        | 3.12        | <https://helm.sh/docs/intro/install/>                |

```bash
gcloud auth login
gcloud auth application-default login
gcloud config set project <PROJECT_ID>
gcloud config set compute/region <REGION>
```

---

## 2. Enable required APIs

```bash
gcloud services enable \
  container.googleapis.com \
  artifactregistry.googleapis.com \
  sqladmin.googleapis.com \
  storage.googleapis.com \
  secretmanager.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com
```

---

## 3. GCP resources to provision

### 3a. Artifact Registry

```bash
gcloud artifacts repositories create terraform-registry \
  --repository-format=docker \
  --location=<REGION>

# Authenticate and push images
gcloud auth configure-docker <REGION>-docker.pkg.dev

docker tag terraform-registry-backend:latest \
  <REGION>-docker.pkg.dev/<PROJECT_ID>/terraform-registry/terraform-registry-backend:v1.0.0
docker push <REGION>-docker.pkg.dev/<PROJECT_ID>/terraform-registry/terraform-registry-backend:v1.0.0

docker tag terraform-registry-frontend:latest \
  <REGION>-docker.pkg.dev/<PROJECT_ID>/terraform-registry/terraform-registry-frontend:v1.0.0
docker push <REGION>-docker.pkg.dev/<PROJECT_ID>/terraform-registry/terraform-registry-frontend:v1.0.0
```

### 3b. Cloud SQL for PostgreSQL

```bash
gcloud sql instances create terraform-registry-db \
  --database-version=POSTGRES_16 \
  --tier=db-g1-small \
  --region=<REGION> \
  --no-assign-ip \
  --enable-google-private-path

gcloud sql databases create terraform_registry \
  --instance=terraform-registry-db

gcloud sql users create registry \
  --instance=terraform-registry-db \
  --password=<STRONG_PASSWORD>
```

> **Note:** `--no-assign-ip --enable-google-private-path` creates a private-IP-only instance. The Cloud SQL Auth Proxy in the GKE pod handles connectivity via IAM.

### 3c. Google Cloud Storage bucket

```bash
gcloud storage buckets create gs://terraform-registry-artifacts-<PROJECT_ID> \
  --location=<REGION> \
  --uniform-bucket-level-access

# Enable versioning
gcloud storage buckets update gs://terraform-registry-artifacts-<PROJECT_ID> \
  --versioning
```

### 3d. GCP Secret Manager

```bash
# Create secrets
printf "$(openssl rand -hex 32)" | \
  gcloud secrets create terraform-registry-jwt-secret \
  --replication-policy=automatic --data-file=-

printf "$(openssl rand -hex 16)" | \
  gcloud secrets create terraform-registry-encryption-key \
  --replication-policy=automatic --data-file=-

printf "<STRONG_PASSWORD>" | \
  gcloud secrets create terraform-registry-database-password \
  --replication-policy=automatic --data-file=-
```

### 3e. Google Service Account (GSA)

```bash
gcloud iam service-accounts create terraform-registry-sa \
  --display-name="Terraform Registry Service Account"

GSA_EMAIL="terraform-registry-sa@<PROJECT_ID>.iam.gserviceaccount.com"

# Grant roles
gcloud storage buckets add-iam-policy-binding \
  gs://terraform-registry-artifacts-<PROJECT_ID> \
  --member="serviceAccount:$GSA_EMAIL" \
  --role=roles/storage.objectAdmin

gcloud secrets add-iam-policy-binding terraform-registry-jwt-secret \
  --member="serviceAccount:$GSA_EMAIL" --role=roles/secretmanager.secretAccessor

gcloud secrets add-iam-policy-binding terraform-registry-encryption-key \
  --member="serviceAccount:$GSA_EMAIL" --role=roles/secretmanager.secretAccessor

gcloud secrets add-iam-policy-binding terraform-registry-database-password \
  --member="serviceAccount:$GSA_EMAIL" --role=roles/secretmanager.secretAccessor

# Cloud SQL client role (for Auth Proxy sidecar)
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:$GSA_EMAIL" \
  --role=roles/cloudsql.client
```

---

## 4. GKE cluster creation

```bash
gcloud container clusters create terraform-registry-cluster \
  --region=<REGION> \
  --release-channel=regular \
  --num-nodes=1 \
  --machine-type=e2-standard-4 \
  --workload-pool=<PROJECT_ID>.svc.id.goog \
  --enable-ip-alias \
  --enable-network-policy \
  --gateway-api=standard \
  --addons=GcsFuseCsiDriver

# Get cluster credentials
gcloud container clusters get-credentials \
  terraform-registry-cluster --region=<REGION>
```

> `--gateway-api=standard` installs Gateway API CRDs and enables the GKE built-in Gateway controller.
> `--enable-network-policy` enables Calico for NetworkPolicy enforcement.
> `--workload-pool` enables GKE Workload Identity.

---

## 5. GKE Workload Identity binding

```bash
# Bind Kubernetes ServiceAccount to GSA
gcloud iam service-accounts add-iam-policy-binding $GSA_EMAIL \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:<PROJECT_ID>.svc.id.goog[terraform-registry/terraform-registry]"
```

---

## 6. Secrets Store CSI Driver + GCP provider

```bash
helm repo add secrets-store-csi-driver \
  https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store \
  secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true \
  --set enableSecretRotation=true

# GCP provider
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp/main/deploy/provider-gcp-plugin.yaml
```

---

## 7. cert-manager

```bash
helm repo add jetstack https://charts.jetstack.io --force-update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true \
  --set "featureGates=ExperimentalGatewayAPISupport=true"
```

---

## Placeholder reference

| Placeholder         | Value                                       |
| ------------------- | ------------------------------------------- |
| `<PROJECT_ID>`      | `gcloud config get-value project`           |
| `<REGION>`          | e.g. `us-central1`                          |
| `<GSA_NAME>`        | `terraform-registry-sa`                     |
| `<AR_REPO>`         | `terraform-registry`                        |
| `<GCS_BUCKET_NAME>` | `terraform-registry-artifacts-<PROJECT_ID>` |
| `<HOSTNAME>`        | Your public DNS name                        |
| `<OPS_EMAIL>`       | Email for Let's Encrypt                     |
