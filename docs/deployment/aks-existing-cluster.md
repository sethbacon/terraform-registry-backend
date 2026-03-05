# AKS Existing Cluster — Deployment Guide

This guide covers deploying the Terraform Registry into an existing AKS cluster.

## Prerequisites Check

Run the following to verify your cluster has the required features:

```bash
RESOURCE_GROUP="<RG>"
CLUSTER_NAME="<CLUSTER>"

az aks show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --query '{
    oidcEnabled: oidcIssuerProfile.enabled,
    workloadIdentityEnabled: securityProfile.workloadIdentity.enabled,
    networkPlugin: networkProfile.networkPlugin,
    networkPolicy: networkProfile.networkPolicy,
    csiDriverEnabled: addonProfiles.azureKeyvaultSecretsProvider.enabled
  }' -o json
```

Required values:
- `oidcEnabled: true`
- `workloadIdentityEnabled: true`
- `networkPlugin: "azure"` or `"azure-overlay"` (required for NetworkPolicy)
- `csiDriverEnabled: true`

### Enable Missing Features

Enable features on the existing cluster as needed:

```bash
# Enable OIDC Issuer (required before Workload Identity)
# WARNING: This operation may cause a brief node pool rolling restart.
az aks update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --enable-oidc-issuer

# Enable Workload Identity (safe to run on running clusters)
az aks update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --enable-workload-identity

# Enable Secrets Store CSI Driver add-on
az aks enable-addons \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --addons azure-keyvault-secrets-provider

# Attach ACR for image pull without explicit pull secrets
az aks update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --attach-acr "<ACR_NAME>"
```

> **Note on NetworkPolicy**: Changing `networkPlugin` or `networkPolicy` on an existing cluster
> is a destructive operation that requires cluster recreation. If your cluster uses Kubenet,
> set `networkPolicy.enabled=false` in Helm values and manage ingress security via Azure NSGs.

---

## Provision Required Azure Resources

If not already provisioned, create the Azure resources listed in [aks-prerequisites.md](aks-prerequisites.md). At minimum you need:

1. PostgreSQL Flexible Server + `terraform_registry` database
2. Storage Account + blob container
3. Key Vault + secrets (`jwt-secret`, `encryption-key`, `database-password`)
4. User-Assigned Managed Identity with Key Vault Secret User role
5. Application Gateway for Containers resource + Frontend

---

## Create Federated Credential

Link the managed identity to the Kubernetes ServiceAccount in this cluster:

```bash
OIDC_ISSUER=$(az aks show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --query oidcIssuerProfile.issuerURL -o tsv)

az identity federated-credential create \
  --name terraform-registry-aks \
  --identity-name "<REGISTRY_IDENTITY_NAME>" \
  --resource-group "<RESOURCE_GROUP>" \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:terraform-registry:terraform-registry" \
  --audiences "api://AzureADTokenExchange"
```

---

## Install Kubernetes Add-ons

### Check if Gateway API CRDs are present

```bash
kubectl get crd gateways.gateway.networking.k8s.io 2>&1 | grep -v "Error" || \
  kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml
```

### Check if cert-manager is installed

```bash
kubectl get pods -n cert-manager 2>/dev/null || {
  helm repo add jetstack https://charts.jetstack.io --force-update
  helm upgrade --install cert-manager jetstack/cert-manager \
    --namespace cert-manager --create-namespace \
    --set crds.enabled=true \
    --set featureGates="ExperimentalGatewayAPISupport=true"
}
```

If cert-manager is already installed, verify the feature gate is enabled:

```bash
kubectl get deployment cert-manager -n cert-manager \
  -o jsonpath='{.spec.template.spec.containers[0].args}' | tr ',' '\n' | grep Gateway
```

If `ExperimentalGatewayAPISupport=true` is not present, upgrade cert-manager:

```bash
helm upgrade cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --reuse-values \
  --set featureGates="ExperimentalGatewayAPISupport=true"
```

### Check if ALB Controller is installed

```bash
kubectl get pods -n azure-alb-system 2>/dev/null | grep alb-controller || {
  echo "ALB Controller not found — install it following aks-prerequisites.md"
}
```

---

## Namespace Isolation

If the `terraform-registry` namespace already exists (e.g. from a previous deployment):

```bash
# Check existing resources
kubectl get all -n terraform-registry

# If doing a fresh install into existing namespace, clean up first:
# kubectl delete namespace terraform-registry  # WARNING: deletes all resources
# kubectl create namespace terraform-registry
```

For upgrading an existing Helm release:

```bash
helm list -n terraform-registry
helm history terraform-registry -n terraform-registry
```

---

## Deploy

### Helm Upgrade/Install

Copy `deployments/helm/values-aks.yaml` and fill in your values:

```bash
cp deployments/helm/values-aks.yaml my-values.yaml
# Edit my-values.yaml — replace all <PLACEHOLDER> values

helm upgrade --install terraform-registry ./deployments/helm \
  --namespace terraform-registry \
  --create-namespace \
  -f my-values.yaml

# Verify rollout
kubectl rollout status deployment/terraform-registry-backend -n terraform-registry
kubectl rollout status deployment/terraform-registry-frontend -n terraform-registry
```

### Kustomize Apply

Edit all placeholder values in `deployments/kubernetes/overlays/aks/` (see comments in each file):

```bash
kubectl apply -k deployments/kubernetes/overlays/aks/

# Watch pod start-up
kubectl get pods -n terraform-registry --watch
```

---

## Post-Deploy Verification

```bash
# Pods should be Running
kubectl get pods -n terraform-registry

# Gateway address assigned
kubectl get gateway -n terraform-registry

# HTTPRoutes accepted
kubectl get httproute -n terraform-registry -o wide

# Certificate issued (may take a few minutes after DNS propagates)
kubectl get certificate -n terraform-registry

# Health check via port-forward
kubectl port-forward svc/terraform-registry-backend 8080:8080 -n terraform-registry &
curl http://localhost:8080/health

# Full HTTPS stack
curl https://<HOSTNAME>/health
curl https://<HOSTNAME>/.well-known/terraform.json
```

---

## Rollback

```bash
# List Helm history
helm history terraform-registry -n terraform-registry

# Rollback to previous revision
helm rollback terraform-registry -n terraform-registry
```
