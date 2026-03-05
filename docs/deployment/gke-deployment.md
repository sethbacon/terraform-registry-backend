# GKE Deployment Guide — Terraform Registry

Complete all steps in [gke-prerequisites.md](gke-prerequisites.md) first.

---

## Step 1 — Cloud SQL Auth Proxy sidecar

The GKE overlay connects to Cloud SQL via the **Cloud SQL Auth Proxy** sidecar,
which handles IAM authentication and TLS. Add the sidecar to the backend Deployment.

Create `overlays/gke/patches/backend-cloudsql-proxy.yaml`:

```yaml
# Strategic merge patch: add Cloud SQL Auth Proxy sidecar to backend Deployment.
# Replace <PROJECT_ID>, <REGION>, and <INSTANCE_NAME> before applying.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: terraform-registry
spec:
  template:
    spec:
      containers:
        - name: cloud-sql-proxy
          image: gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.11.0
          args:
            - "--structured-logs"
            - "--port=5432"
            - "<PROJECT_ID>:<REGION>:<INSTANCE_NAME>"
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
          resources:
            requests:
              memory: 64Mi
              cpu: 10m
            limits:
              memory: 128Mi
              cpu: 100m
```

Add this patch to `overlays/gke/kustomization.yaml`:

```yaml
patches:
  # ... existing patches ...
  - path: patches/backend-cloudsql-proxy.yaml
    target:
      kind: Deployment
      name: backend
```

---

## Step 2 — Fill in placeholder values

| Placeholder         | How to get it                               |
| ------------------- | ------------------------------------------- |
| `<PROJECT_ID>`      | `gcloud config get-value project`           |
| `<REGION>`          | Your chosen region                          |
| `<AR_REPO>`         | `terraform-registry`                        |
| `<GSA_NAME>`        | `terraform-registry-sa`                     |
| `<GCS_BUCKET_NAME>` | `terraform-registry-artifacts-<PROJECT_ID>` |
| `<HOSTNAME>`        | Your public DNS name                        |
| `<EMAIL>`           | Your ops email                              |
| `<INSTANCE_NAME>`   | `terraform-registry-db`                     |
| `<IMAGE_TAG>`       | `v1.0.0`                                    |

---

## Step 3 — Reserve a static IP (recommended)

```bash
gcloud compute addresses create terraform-registry-ip --global

REGISTRY_IP=$(gcloud compute addresses describe terraform-registry-ip \
  --global --format='value(address)')
echo "Reserved IP: $REGISTRY_IP"
```

Configure `gateway.yaml` to use this IP (add annotation):

```yaml
  annotations:
    networking.gke.io/stable-ip-address: "true"
    networking.gke.io/certmap: ""   # only if using GCP Certificate Manager
```

---

## Step 4 — Deploy

### Option A: Helm

```bash
cp deployments/helm/values-gke.yaml deployments/helm/values-gke-prod.yaml
# Edit values-gke-prod.yaml — replace every <PLACEHOLDER>
# Also add Cloud SQL proxy sidecar via backend.extraContainers (or use Kustomize)

helm upgrade --install terraform-registry ./deployments/helm \
  --namespace terraform-registry --create-namespace \
  -f deployments/helm/values-gke-prod.yaml \
  --wait --timeout 5m

# Apply SecretProviderClass separately
kubectl apply -f deployments/kubernetes/overlays/gke/secretproviderclass.yaml
```

### Option B: Kustomize

```bash
# Edit all overlay files, replace every <PLACEHOLDER>:
#   overlays/gke/gateway.yaml               → hostname
#   overlays/gke/httproute.yaml             → hostname (x3)
#   overlays/gke/certificate.yaml           → dnsNames
#   overlays/gke/clusterissuer.yaml         → email (x2)
#   overlays/gke/secretproviderclass.yaml   → PROJECT_ID (x3)
#   overlays/gke/patches/serviceaccount-workload-identity.yaml → GSA_NAME@PROJECT_ID
#   overlays/gke/patches/configmap-gke.yaml → GCS bucket, PROJECT_ID, hostname
#   overlays/gke/patches/backend-cloudsql-proxy.yaml → PROJECT_ID, REGION, INSTANCE_NAME
#   overlays/gke/kustomization.yaml         → Artifact Registry repo, image tag

kubectl apply -k deployments/kubernetes/overlays/gke/
```

---

## Step 5 — Configure DNS

```bash
GATEWAY_IP=$(kubectl get gateway terraform-registry-gateway \
  -n terraform-registry -o jsonpath='{.status.addresses[0].value}')
echo "Gateway IP: $GATEWAY_IP"
```

Create an A record in Cloud DNS (or your external DNS provider):

```bash
# Cloud DNS example:
gcloud dns record-sets create registry.yourdomain.com. \
  --zone=<MANAGED_ZONE> \
  --type=A \
  --ttl=300 \
  --rrdatas="$GATEWAY_IP"
```

---

## Step 6 — Verify certificate and application

```bash
kubectl get gateway,httproute,certificate -n terraform-registry

# Application smoke test
curl https://registry.yourdomain.com/health
curl https://registry.yourdomain.com/.well-known/terraform.json
```

---

## Step 7 — Promote to production TLS

```bash
kubectl delete secret terraform-registry-tls -n terraform-registry

# Helm
helm upgrade terraform-registry ./deployments/helm \
  -n terraform-registry -f deployments/helm/values-gke-prod.yaml \
  --set gatewayAPI.certManagerIssuer=letsencrypt-prod

# Kustomize: edit overlays/gke/certificate.yaml → letsencrypt-prod, then apply
```

---

## GKE-specific notes

### Google-managed certificates (alternative to cert-manager)

If you prefer Google-managed certificates over cert-manager, annotate the Gateway:

```yaml
metadata:
  annotations:
    networking.gke.io/certmap: <CERT_MAP_NAME>
```

And provision the certificate using GCP Certificate Manager:

```bash
gcloud certificate-manager certificates create terraform-registry-cert \
  --domains="registry.yourdomain.com"

gcloud certificate-manager maps create terraform-registry-cert-map

gcloud certificate-manager maps entries create terraform-registry-cert-entry \
  --map=terraform-registry-cert-map \
  --certificates=terraform-registry-cert \
  --hostname=registry.yourdomain.com
```

Remove the `cert-manager.io/cluster-issuer` annotation from the Gateway
and the `certificate.yaml` from the overlay when using this approach.

### Troubleshooting

```bash
# Gateway controller logs
kubectl logs -n kube-system -l k8s-app=glbc --tail=50

# HTTPRoute status (check for "Accepted" and "ResolvedRefs")
kubectl describe httproute backend-routes -n terraform-registry

# GCP Secret Manager access (run as test pod with GSA identity)
kubectl run test-gsm --image=google/cloud-sdk:latest \
  --restart=Never --rm -it \
  --serviceaccount=terraform-registry \
  -n terraform-registry \
  -- gcloud secrets versions access latest \
     --secret=terraform-registry-jwt-secret
```
