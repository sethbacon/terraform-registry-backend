# AKS New Cluster — Deployment Guide

This guide walks through provisioning all required Azure infrastructure and deploying
the Terraform Registry to a brand-new AKS cluster using Helm.

Complete [aks-prerequisites.md](aks-prerequisites.md) first to understand what is required.

---

## Variables Used in This Guide

Set these shell variables once and reuse throughout:

```bash
# Azure
SUBSCRIPTION_ID="<UUID>"
RESOURCE_GROUP="tfr-prod-rg"
LOCATION="eastus"

# AKS
CLUSTER_NAME="tfr-aks"
NODE_COUNT=3           # Minimum 3 for zone spread + PDB
VM_SIZE="Standard_D4s_v3"
VNET_NAME="tfr-vnet"

# Registry
ACR_NAME="tfrregistry"    # Must be globally unique, alphanumeric only, 5-50 chars

# PostgreSQL
PG_SERVER="tfr-postgres"
PG_ADMIN_USER="registry"
PG_ADMIN_PASSWORD="<GENERATE_WITH: openssl rand -hex 24>"

# Storage
STORAGE_ACCOUNT="tfrblob$(openssl rand -hex 4)"  # Must be globally unique

# Key Vault
KEY_VAULT_NAME="tfr-kv-$(openssl rand -hex 4)"   # Must be globally unique

# AGfC
AGFC_NAME="tfr-agfc"

# Managed Identity
REGISTRY_IDENTITY_NAME="terraform-registry-identity"
ALB_IDENTITY_NAME="alb-controller-identity"

# Application
HOSTNAME="registry.company.com"          # Replace with your domain
OPS_EMAIL="ops@company.com"
IMAGE_TAG="v1.0.0"
```

---

## Step 1 — Create Azure Infrastructure

### 1.1 Resource Group and VNet

```bash
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

az network vnet create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VNET_NAME" \
  --address-prefix 10.0.0.0/8

# AKS node subnet
az network vnet subnet create \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name aks-subnet \
  --address-prefix 10.240.0.0/16

# AGfC subnet (delegated, /24 or smaller)
az network vnet subnet create \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name agfc-subnet \
  --address-prefix 10.225.0.0/24

az network vnet subnet update \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name agfc-subnet \
  --delegations Microsoft.ServiceNetworking/trafficControllers
```

### 1.2 Container Registry

```bash
az acr create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACR_NAME" \
  --sku Standard \
  --location "$LOCATION"
```

### 1.3 PostgreSQL Flexible Server

```bash
AKS_SUBNET_ID=$(az network vnet subnet show \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name aks-subnet --query id -o tsv)

az postgres flexible-server create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$PG_SERVER" \
  --location "$LOCATION" \
  --admin-user "$PG_ADMIN_USER" \
  --admin-password "$PG_ADMIN_PASSWORD" \
  --sku-name Standard_D2ds_v5 \
  --tier GeneralPurpose \
  --version 16 \
  --storage-size 32 \
  --backup-retention 7

az postgres flexible-server db create \
  --resource-group "$RESOURCE_GROUP" \
  --server-name "$PG_SERVER" \
  --database-name terraform_registry

# Allow connections from AKS (update firewall rule after cluster is created)
# For sandbox: allow all Azure services temporarily
az postgres flexible-server firewall-rule create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$PG_SERVER" \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0
```

### 1.4 Storage Account

```bash
az storage account create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$STORAGE_ACCOUNT" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --https-only true \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false

az storage container create \
  --account-name "$STORAGE_ACCOUNT" \
  --name terraform-registry \
  --auth-mode login
```

### 1.5 Key Vault + Secrets

```bash
az keyvault create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$KEY_VAULT_NAME" \
  --location "$LOCATION" \
  --enable-rbac-authorization true

# Store secrets
az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
  --name jwt-secret --value "$(openssl rand -hex 32)"

az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
  --name encryption-key --value "$(openssl rand -hex 16)"

az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
  --name database-password --value "$PG_ADMIN_PASSWORD"

# Store blob account key (used when not using Workload Identity for storage)
BLOB_KEY=$(az storage account keys list \
  --resource-group "$RESOURCE_GROUP" \
  --account-name "$STORAGE_ACCOUNT" \
  --query '[0].value' -o tsv)
az keyvault secret set --vault-name "$KEY_VAULT_NAME" \
  --name azure-blob-account-key --value "$BLOB_KEY"
```

### 1.6 Managed Identities

```bash
# Registry application identity
az identity create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$REGISTRY_IDENTITY_NAME" \
  --location "$LOCATION"

REGISTRY_CLIENT_ID=$(az identity show -g "$RESOURCE_GROUP" \
  -n "$REGISTRY_IDENTITY_NAME" --query clientId -o tsv)
REGISTRY_PRINCIPAL_ID=$(az identity show -g "$RESOURCE_GROUP" \
  -n "$REGISTRY_IDENTITY_NAME" --query principalId -o tsv)

# ALB Controller identity
az identity create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ALB_IDENTITY_NAME" \
  --location "$LOCATION"

ALB_CLIENT_ID=$(az identity show -g "$RESOURCE_GROUP" \
  -n "$ALB_IDENTITY_NAME" --query clientId -o tsv)
ALB_PRINCIPAL_ID=$(az identity show -g "$RESOURCE_GROUP" \
  -n "$ALB_IDENTITY_NAME" --query principalId -o tsv)

# Grant registry identity: Key Vault Secret User
KEY_VAULT_ID=$(az keyvault show --name "$KEY_VAULT_NAME" --query id -o tsv)
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee-object-id "$REGISTRY_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$KEY_VAULT_ID"

# Grant registry identity: Storage Blob Data Contributor
STORAGE_ID=$(az storage account show -g "$RESOURCE_GROUP" \
  -n "$STORAGE_ACCOUNT" --query id -o tsv)
az role assignment create \
  --role "Storage Blob Data Contributor" \
  --assignee-object-id "$REGISTRY_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$STORAGE_ID"

# Grant ALB Controller identity: Reader + AGfC Configuration Manager on resource group
RG_ID=$(az group show --name "$RESOURCE_GROUP" --query id -o tsv)
az role assignment create \
  --role "Reader" \
  --assignee-object-id "$ALB_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$RG_ID"

az role assignment create \
  --role "AppGw for Containers Configuration Manager" \
  --assignee-object-id "$ALB_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$RG_ID"
```

### 1.7 Application Gateway for Containers

```bash
az network alb create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$AGFC_NAME" \
  --location "$LOCATION"

az network alb frontend create \
  --resource-group "$RESOURCE_GROUP" \
  --name registry-frontend \
  --alb-name "$AGFC_NAME"

AGFC_ID=$(az network alb show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$AGFC_NAME" --query id -o tsv)
```

---

## Step 2 — Create AKS Cluster

```bash
AKS_SUBNET_ID=$(az network vnet subnet show \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name aks-subnet --query id -o tsv)

az aks create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --location "$LOCATION" \
  --node-count "$NODE_COUNT" \
  --node-vm-size "$VM_SIZE" \
  --vnet-subnet-id "$AKS_SUBNET_ID" \
  --network-plugin azure \
  --network-policy azure \
  --enable-oidc-issuer \
  --enable-workload-identity \
  --enable-addons azure-keyvault-secrets-provider \
  --attach-acr "$ACR_NAME" \
  --zones 1 2 3 \
  --generate-ssh-keys

# Get credentials
az aks get-credentials \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --overwrite-existing

kubectl get nodes
```

---

## Step 3 — Create Federated Credentials

```bash
OIDC_ISSUER=$(az aks show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --query oidcIssuerProfile.issuerURL -o tsv)

# Registry application identity → terraform-registry ServiceAccount
az identity federated-credential create \
  --name terraform-registry-aks \
  --identity-name "$REGISTRY_IDENTITY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:terraform-registry:terraform-registry" \
  --audiences "api://AzureADTokenExchange"

# ALB Controller identity → alb-controller ServiceAccount
az identity federated-credential create \
  --name alb-controller-aks \
  --identity-name "$ALB_IDENTITY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:azure-alb-system:alb-controller-sa" \
  --audiences "api://AzureADTokenExchange"
```

---

## Step 4 — Install Kubernetes Add-ons

### 4.1 Gateway API CRDs

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml
kubectl wait --for=condition=Established crd/gateways.gateway.networking.k8s.io --timeout=60s
```

### 4.2 cert-manager

```bash
helm repo add jetstack https://charts.jetstack.io --force-update

helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true \
  --set featureGates="ExperimentalGatewayAPISupport=true"

kubectl wait --for=condition=Ready pods --all -n cert-manager --timeout=120s
```

### 4.3 ALB Controller

```bash
helm install azure-alb-controller \
  oci://mcr.microsoft.com/application-lb/charts/azure-alb-controller \
  --namespace azure-alb-system \
  --create-namespace \
  --set albController.namespace=azure-alb-system \
  --set albController.podIdentity.clientID="$ALB_CLIENT_ID"

kubectl wait --for=condition=Ready pods --all -n azure-alb-system --timeout=120s
```

---

## Step 5 — Push Container Images to ACR

```bash
az acr login --name "$ACR_NAME"

# Build and push backend (from terraform-registry-backend repo root)
docker build -t "$ACR_NAME.azurecr.io/terraform-registry-backend:$IMAGE_TAG" ./backend
docker push "$ACR_NAME.azurecr.io/terraform-registry-backend:$IMAGE_TAG"

# Build and push frontend (from terraform-registry-frontend repo root)
docker build -t "$ACR_NAME.azurecr.io/terraform-registry-frontend:$IMAGE_TAG" \
  --build-arg VITE_MODE=production ./frontend
docker push "$ACR_NAME.azurecr.io/terraform-registry-frontend:$IMAGE_TAG"
```

---

## Step 6 — Deploy the Terraform Registry

### Option A: Deploy with Helm

```bash
helm upgrade --install terraform-registry \
  ./deployments/helm \
  --namespace terraform-registry \
  --create-namespace \
  --set backend.image.repository="$ACR_NAME.azurecr.io/terraform-registry-backend" \
  --set backend.image.tag="$IMAGE_TAG" \
  --set frontend.image.repository="$ACR_NAME.azurecr.io/terraform-registry-frontend" \
  --set frontend.image.tag="$IMAGE_TAG" \
  --set server.baseUrl="https://$HOSTNAME" \
  --set externalDatabase.host="$PG_SERVER.postgres.database.azure.com" \
  --set storage.backend=azure \
  --set storage.azure.accountName="$STORAGE_ACCOUNT" \
  --set storage.azure.containerName=terraform-registry \
  --set storage.persistence.enabled=false \
  --set workloadIdentity.enabled=true \
  --set workloadIdentity.clientId="$REGISTRY_CLIENT_ID" \
  --set keyVault.enabled=true \
  --set keyVault.name="$KEY_VAULT_NAME" \
  --set keyVault.tenantId="$(az account show --query tenantId -o tsv)" \
  --set keyVault.clientId="$REGISTRY_CLIENT_ID" \
  --set gatewayAPI.enabled=true \
  --set gatewayAPI.albId="$AGFC_ID" \
  --set gatewayAPI.hostname="$HOSTNAME" \
  --set gatewayAPI.certManagerIssuer=letsencrypt-staging \
  --set gatewayAPI.email="$OPS_EMAIL" \
  --set ingress.enabled=false \
  --set networkPolicy.enabled=true \
  --set autoscaling.enabled=true
```

Alternatively, copy `deployments/helm/values-aks.yaml`, fill in all placeholders, and run:

```bash
helm upgrade --install terraform-registry ./deployments/helm \
  --namespace terraform-registry --create-namespace \
  -f my-values-aks.yaml
```

### Option B: Deploy with Kustomize

Edit all `<PLACEHOLDER>` values in the overlay files first:

```bash
# Files to edit:
#   deployments/kubernetes/overlays/aks/kustomization.yaml   (image tags + ACR name)
#   deployments/kubernetes/overlays/aks/gateway.yaml          (albId, hostname)
#   deployments/kubernetes/overlays/aks/httproute.yaml        (hostname)
#   deployments/kubernetes/overlays/aks/secretproviderclass.yaml (clientId, keyvaultName, tenantId)
#   deployments/kubernetes/overlays/aks/clusterissuer.yaml    (email)
#   deployments/kubernetes/overlays/aks/certificate.yaml      (hostname)
#   deployments/kubernetes/overlays/aks/patches/serviceaccount-workload-identity.yaml (clientId)
#   deployments/kubernetes/overlays/aks/patches/configmap-aks.yaml (DB host, storage account, hostname)

kubectl apply -k deployments/kubernetes/overlays/aks/
```

---

## Step 7 — Configure DNS

After the Gateway is created and the ALB Controller reconciles it:

```bash
# Wait for the Gateway to have an address (can take 1-2 minutes)
kubectl get gateway -n terraform-registry --watch

# Get the public IP
GATEWAY_IP=$(kubectl get gateway -n terraform-registry terraform-registry-gateway \
  -o jsonpath='{.status.addresses[0].value}')
echo "Gateway IP: $GATEWAY_IP"
```

Create an A record in your DNS zone: `$HOSTNAME → $GATEWAY_IP`

For Azure DNS:

```bash
az network dns record-set a add-record \
  --resource-group <DNS_RESOURCE_GROUP> \
  --zone-name company.com \
  --record-set-name registry \
  --ipv4-address "$GATEWAY_IP"
```

---

## Step 8 — Verify Certificate Issuance

The cert-manager Certificate request was created during the Helm install. Once DNS
propagates (verify with `dig +short $HOSTNAME`), cert-manager will complete the ACME
HTTP-01 challenge automatically.

```bash
# Check certificate status
kubectl get certificate -n terraform-registry

# Detailed status (look for Ready: True)
kubectl describe certificate terraform-registry-tls -n terraform-registry

# If using Helm: certificate name is <release-name>-tls
kubectl describe certificate terraform-registry-tls -n terraform-registry
```

Once the staging certificate issues successfully, promote to the production issuer:

```bash
# With Helm
helm upgrade terraform-registry ./deployments/helm \
  --namespace terraform-registry \
  --reuse-values \
  --set gatewayAPI.certManagerIssuer=letsencrypt-prod

# With Kustomize: edit certificate.yaml issuerRef.name to letsencrypt-prod, then:
kubectl apply -k deployments/kubernetes/overlays/aks/
```

---

## Step 9 — Verify Deployment

```bash
# All pods should be Running/Ready
kubectl get pods -n terraform-registry

# Gateway should have a valid address
kubectl get gateway -n terraform-registry

# HTTPRoutes should show Accepted / Programmed
kubectl get httproute -n terraform-registry -o wide

# Check backend health
kubectl port-forward -n terraform-registry svc/terraform-registry-backend 8080:8080 &
curl http://localhost:8080/health
curl http://localhost:8080/ready

# Check full stack
curl https://$HOSTNAME/health
curl https://$HOSTNAME/.well-known/terraform.json

# Check logs
kubectl logs -n terraform-registry \
  -l app.kubernetes.io/component=backend \
  --tail=100 -f
```

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---|---|---|
| Pods stuck in `ContainerCreating` | CSI volume can't mount | Check `kubectl describe pod -n terraform-registry <pod>` for SecretProviderClass errors; verify Key Vault name, clientId, tenantId |
| Pods in `CrashLoopBackOff` | Missing env var or DB connection failed | Check `kubectl logs`; verify `TFR_DATABASE_HOST` in ConfigMap patch |
| Gateway has no IP | ALB Controller not running | Check `kubectl get pods -n azure-alb-system`; verify ALB Controller federated credential |
| Certificate in `False` / challenge failing | DNS not propagated or HTTP-01 unreachable | Verify `dig +short $HOSTNAME` returns Gateway IP; check `kubectl describe challenge -n terraform-registry` |
| 502 Bad Gateway | Backend pods not ready | Check backend readiness probe; check `kubectl get endpoints -n terraform-registry` |
