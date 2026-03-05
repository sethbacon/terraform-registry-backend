# AKS Prerequisites

Before deploying the Terraform Registry to Azure Kubernetes Service, provision all
required Azure resources and ensure the AKS cluster has the necessary features enabled.

## Required Tooling

| Tool | Minimum Version | Install |
|---|---|---|
| Azure CLI (`az`) | 2.61.0 | `brew install azure-cli` or [docs.microsoft.com](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| `kubectl` | 1.29+ | `az aks install-cli` |
| `helm` | 3.12+ | `brew install helm` or [helm.sh](https://helm.sh/docs/intro/install/) |
| `kustomize` | 5.0+ | `brew install kustomize` (optional — `kubectl apply -k` includes kustomize) |

```bash
az login
az account set --subscription "<SUBSCRIPTION_ID>"
```

## Required Azure Resources

### 1. Resource Group

```bash
az group create --name <RESOURCE_GROUP> --location eastus
```

### 2. Azure Container Registry (ACR)

```bash
az acr create \
  --resource-group <RESOURCE_GROUP> \
  --name <ACR_NAME> \
  --sku Standard

# Push images (see build instructions in the backend and frontend repos)
az acr login --name <ACR_NAME>
docker push <ACR_NAME>.azurecr.io/terraform-registry-backend:v1.0.0
docker push <ACR_NAME>.azurecr.io/terraform-registry-frontend:v1.0.0
```

### 3. Azure Database for PostgreSQL Flexible Server

```bash
az postgres flexible-server create \
  --resource-group <RESOURCE_GROUP> \
  --name <POSTGRES_SERVER_NAME> \
  --location eastus \
  --admin-user registry \
  --admin-password '<STRONG_PASSWORD>' \
  --sku-name Standard_D2s_v3 \
  --tier GeneralPurpose \
  --version 16 \
  --public-access None     # Use private endpoint or VNet integration for production

# Create the database
az postgres flexible-server db create \
  --resource-group <RESOURCE_GROUP> \
  --server-name <POSTGRES_SERVER_NAME> \
  --database-name terraform_registry
```

> **Note:** For sandbox testing with public access, use `--public-access 0.0.0.0` temporarily. For production, configure VNet integration and firewall rules.

### 4. Azure Storage Account + Blob Container

```bash
az storage account create \
  --resource-group <RESOURCE_GROUP> \
  --name <STORAGE_ACCOUNT_NAME> \
  --sku Standard_LRS \
  --kind StorageV2 \
  --https-only true \
  --min-tls-version TLS1_2

az storage container create \
  --account-name <STORAGE_ACCOUNT_NAME> \
  --name terraform-registry \
  --auth-mode login
```

### 5. Azure Key Vault + Secrets

```bash
az keyvault create \
  --resource-group <RESOURCE_GROUP> \
  --name <KEY_VAULT_NAME> \
  --location eastus \
  --enable-rbac-authorization true

# Create secrets
az keyvault secret set --vault-name <KEY_VAULT_NAME> \
  --name jwt-secret \
  --value "$(openssl rand -hex 32)"

az keyvault secret set --vault-name <KEY_VAULT_NAME> \
  --name encryption-key \
  --value "$(openssl rand -hex 16)"

az keyvault secret set --vault-name <KEY_VAULT_NAME> \
  --name database-password \
  --value '<STRONG_PASSWORD>'   # Same password used when creating the PostgreSQL server

# Only needed if NOT using Workload Identity for Blob Storage access:
az keyvault secret set --vault-name <KEY_VAULT_NAME> \
  --name azure-blob-account-key \
  --value "$(az storage account keys list -g <RESOURCE_GROUP> -n <STORAGE_ACCOUNT_NAME> --query '[0].value' -o tsv)"
```

### 6. User-Assigned Managed Identity

```bash
az identity create \
  --resource-group <RESOURCE_GROUP> \
  --name terraform-registry-identity

# Capture the client ID for later use
IDENTITY_CLIENT_ID=$(az identity show \
  --resource-group <RESOURCE_GROUP> \
  --name terraform-registry-identity \
  --query clientId -o tsv)

IDENTITY_PRINCIPAL_ID=$(az identity show \
  --resource-group <RESOURCE_GROUP> \
  --name terraform-registry-identity \
  --query principalId -o tsv)
```

#### Grant Key Vault access (Key Vault Secret User role)

```bash
KEY_VAULT_ID=$(az keyvault show \
  --name <KEY_VAULT_NAME> --query id -o tsv)

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee-object-id "$IDENTITY_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$KEY_VAULT_ID"
```

#### Grant Blob Storage access (optional — alternative to account key)

```bash
STORAGE_ID=$(az storage account show \
  --resource-group <RESOURCE_GROUP> \
  --name <STORAGE_ACCOUNT_NAME> --query id -o tsv)

az role assignment create \
  --role "Storage Blob Data Contributor" \
  --assignee-object-id "$IDENTITY_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$STORAGE_ID"
```

### 7. Application Gateway for Containers (AGfC)

AGfC requires a dedicated subnet with `Microsoft.ServiceNetworking/trafficControllers` delegation.

```bash
# Create or use existing VNet — the AKS cluster VNet is typically the right target.
# AGfC subnet must be /24 or smaller and delegated.
az network vnet subnet create \
  --resource-group <RESOURCE_GROUP> \
  --vnet-name <VNET_NAME> \
  --name agfc-subnet \
  --address-prefix 10.225.0.0/24

az network vnet subnet update \
  --resource-group <RESOURCE_GROUP> \
  --vnet-name <VNET_NAME> \
  --name agfc-subnet \
  --delegations Microsoft.ServiceNetworking/trafficControllers

# Create AGfC resource
az network alb create \
  --resource-group <RESOURCE_GROUP> \
  --name <AGFC_NAME>

# Create Frontend (public-facing IP/DNS)
az network alb frontend create \
  --resource-group <RESOURCE_GROUP> \
  --name registry-frontend \
  --alb-name <AGFC_NAME>

# Note the AGfC resource ID for use in values-aks.yaml / kustomize overlay
az network alb show \
  --resource-group <RESOURCE_GROUP> \
  --name <AGFC_NAME> \
  --query id -o tsv
```

### 8. DNS Record

After the AKS deployment creates a Gateway that references the AGfC, the ALB Controller
provisions a public IP. Retrieve the IP and create your DNS A record:

```bash
# Run after deploying — the IP is available once the Gateway is fully reconciled
kubectl get gateway -n terraform-registry terraform-registry-gateway \
  -o jsonpath='{.status.addresses[0].value}'
```

Create an A record in your DNS zone pointing `<HOSTNAME>` to that IP before attempting
certificate issuance (the ACME HTTP-01 challenge requires DNS resolution).

---

## Required AKS Cluster Features

The AKS cluster must have the following features enabled:

| Feature | Flag | Notes |
|---|---|---|
| OIDC Issuer | `--enable-oidc-issuer` | Required for Workload Identity |
| Workload Identity | `--enable-workload-identity` | Required for Key Vault CSI + Managed Identity |
| Secrets Store CSI Driver | `--enable-addons azure-keyvault-secrets-provider` | Required for Key Vault secret sync |
| Azure CNI Networking | `--network-plugin azure` (or `azure-overlay`) | Required for NetworkPolicy enforcement and AGfC |
| ACR Attach | `--attach-acr <ACR_NAME>` | Grants AKS pull access to ACR without explicit pull secrets |

Check existing cluster features:

```bash
az aks show --resource-group <RG> --name <CLUSTER_NAME> \
  --query '{oidcIssuerProfile:oidcIssuerProfile,securityProfile:securityProfile,addonProfiles:addonProfiles}' \
  -o json
```

Enable missing features on an existing cluster:

```bash
# Enable OIDC Issuer (required before Workload Identity)
az aks update --resource-group <RG> --name <CLUSTER_NAME> --enable-oidc-issuer

# Enable Workload Identity (requires OIDC Issuer)
az aks update --resource-group <RG> --name <CLUSTER_NAME> --enable-workload-identity

# Enable Secrets Store CSI Driver add-on
az aks enable-addons \
  --resource-group <RG> \
  --name <CLUSTER_NAME> \
  --addons azure-keyvault-secrets-provider

# Attach ACR
az aks update \
  --resource-group <RG> \
  --name <CLUSTER_NAME> \
  --attach-acr <ACR_NAME>
```

---

## Workload Identity Federated Credential

After the AKS cluster and managed identity are created, link them with a federated credential:

```bash
OIDC_ISSUER=$(az aks show \
  --resource-group <RG> \
  --name <CLUSTER_NAME> \
  --query oidcIssuerProfile.issuerURL -o tsv)

az identity federated-credential create \
  --name terraform-registry-aks \
  --identity-name terraform-registry-identity \
  --resource-group <RESOURCE_GROUP> \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:terraform-registry:terraform-registry" \
  --audiences "api://AzureADTokenExchange"
```

The `--subject` must match:
- Kubernetes namespace: `terraform-registry`
- Kubernetes ServiceAccount name: `terraform-registry`

---

## Kubernetes Add-ons to Install

Two Helm-based add-ons must be installed into the cluster before deploying the registry.

### cert-manager

```bash
helm repo add jetstack https://charts.jetstack.io --force-update

helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true \
  --set featureGates="ExperimentalGatewayAPISupport=true"

# Verify
kubectl get pods -n cert-manager
```

> **Important:** `ExperimentalGatewayAPISupport=true` is required for cert-manager to create
> `HTTPRoute` resources for the ACME HTTP-01 challenge. Without this, certificate issuance will fail.

### ALB Controller (AGfC)

The ALB Controller reconciles `Gateway` and `HTTPRoute` resources into AGfC configuration.

```bash
# The ALB Controller requires its own managed identity for ARM operations.
az identity create \
  --resource-group <RESOURCE_GROUP> \
  --name alb-controller-identity

ALB_CLIENT_ID=$(az identity show \
  --resource-group <RESOURCE_GROUP> \
  --name alb-controller-identity \
  --query clientId -o tsv)

ALB_PRINCIPAL_ID=$(az identity show \
  --resource-group <RESOURCE_GROUP> \
  --name alb-controller-identity \
  --query principalId -o tsv)

# Grant Reader + AppGW for Containers Configuration Manager on the resource group
RESOURCE_GROUP_ID=$(az group show --name <RESOURCE_GROUP> --query id -o tsv)
az role assignment create \
  --role "Reader" \
  --assignee-object-id "$ALB_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$RESOURCE_GROUP_ID"

az role assignment create \
  --role "AppGw for Containers Configuration Manager" \
  --assignee-object-id "$ALB_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$RESOURCE_GROUP_ID"

# Federated credential for ALB Controller ServiceAccount
OIDC_ISSUER=$(az aks show -g <RG> -n <CLUSTER_NAME> \
  --query oidcIssuerProfile.issuerURL -o tsv)

az identity federated-credential create \
  --name alb-controller-fedcred \
  --identity-name alb-controller-identity \
  --resource-group <RESOURCE_GROUP> \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:azure-alb-system:alb-controller-sa" \
  --audiences "api://AzureADTokenExchange"

# Install ALB Controller
helm install azure-alb-controller \
  oci://mcr.microsoft.com/application-lb/charts/azure-alb-controller \
  --namespace azure-alb-system \
  --create-namespace \
  --set albController.namespace=azure-alb-system \
  --set albController.podIdentity.clientID="$ALB_CLIENT_ID"

# Verify
kubectl get pods -n azure-alb-system
```

### Gateway API CRDs

Install Gateway API CRDs if not already present on the cluster:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml
```

Verify:

```bash
kubectl get crd gateways.gateway.networking.k8s.io
kubectl get crd httproutes.gateway.networking.k8s.io
```

---

## Summary Checklist

Before running the deployment:

- [ ] ACR created and images pushed
- [ ] PostgreSQL Flexible Server created, `terraform_registry` database created
- [ ] Storage Account and blob container created
- [ ] Key Vault created with secrets: `jwt-secret`, `encryption-key`, `database-password`
- [ ] User-Assigned Managed Identity created with Key Vault Secret User role
- [ ] AGfC resource and Frontend created; subnet delegated
- [ ] AKS cluster has OIDC Issuer, Workload Identity, Secrets Store CSI Driver, Azure CNI
- [ ] Federated credential created (terraform-registry identity → AKS OIDC → ServiceAccount)
- [ ] cert-manager installed with `ExperimentalGatewayAPISupport=true`
- [ ] ALB Controller installed with its own managed identity
- [ ] Gateway API CRDs installed
- [ ] DNS record created (or ready to create after first deploy)
