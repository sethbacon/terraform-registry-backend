# AKS Operations

Day-2 operational procedures for the Terraform Registry on AKS.

---

## Upgrading

### Helm Upgrade

```bash
# Pull latest chart changes
git pull

# Upgrade keeping existing values, only changing the image tag
helm upgrade terraform-registry ./deployments/helm \
  --namespace terraform-registry \
  --reuse-values \
  --set backend.image.tag=v0.8.2 \
  --set frontend.image.tag=v0.8.2

# Monitor rollout
kubectl rollout status deployment/terraform-registry-backend -n terraform-registry
kubectl rollout status deployment/terraform-registry-frontend -n terraform-registry
```

### Kustomize Upgrade

```bash
# Edit overlays/aks/kustomization.yaml — update image newTag values, then:
kubectl apply -k deployments/kubernetes/overlays/aks/

# Watch rolling update
kubectl get pods -n terraform-registry --watch
```

### Rolling Update Behaviour

The backend and frontend Deployments use the default `RollingUpdate` strategy.

With `minAvailable: 1` (PDB) and `replicas: 3` (production):
- Maximum 1 pod is unavailable during a rolling update
- The HPA allows scaling down to `minReplicas: 3`
- Plan for at least `replicas + 1` schedulable nodes during node pool upgrades

---

## Certificate Management

### cert-manager Auto-Renewal

cert-manager automatically renews Let's Encrypt certificates before expiry (default: 30 days before the 90-day expiry). No manual intervention is needed in normal operation.

### Check Certificate Status

```bash
kubectl get certificate -n terraform-registry
kubectl describe certificate terraform-registry-tls -n terraform-registry

# Check the renewal schedule
kubectl get certificate terraform-registry-tls -n terraform-registry \
  -o jsonpath='{.status.renewalTime}'
```

### Force Renewal (emergency re-issue)

```bash
# Delete the existing certificate Secret — cert-manager will re-issue immediately
kubectl delete secret terraform-registry-tls -n terraform-registry
```

### Promote Staging → Production Issuer

Used when first going live or after a staging certificate has proven the ACME flow works.

```bash
# Helm
helm upgrade terraform-registry ./deployments/helm \
  --namespace terraform-registry \
  --reuse-values \
  --set gatewayAPI.certManagerIssuer=letsencrypt-prod

# Kustomize: edit certificate.yaml issuerRef.name to letsencrypt-prod, then apply
```

After changing the issuer, delete the old certificate Secret to trigger immediate re-issue:

```bash
kubectl delete secret terraform-registry-tls -n terraform-registry
kubectl get certificate -n terraform-registry --watch
```

---

## Rotating Secrets in Azure Key Vault

When you update a secret value in Key Vault, the Secrets Store CSI Driver does **not**
automatically update running pods. The new value is picked up on the next pod restart.

### Rotate a secret

```bash
# Update the secret in Key Vault
az keyvault secret set --vault-name <KEY_VAULT_NAME> \
  --name jwt-secret \
  --value "$(openssl rand -hex 32)"

# Restart backend pods to pick up the new value
kubectl rollout restart deployment/terraform-registry-backend -n terraform-registry

# Verify the rollout
kubectl rollout status deployment/terraform-registry-backend -n terraform-registry
```

### Enable auto-rotation (CSI Driver feature)

The Secrets Store CSI Driver can poll Key Vault periodically:

```bash
# Check if auto-rotation is enabled on the CSI driver add-on
kubectl get daemonset secrets-store-csi-driver -n kube-system \
  -o jsonpath='{.spec.template.spec.containers[0].args}' | tr ' ' '\n' | grep rotation
```

Enable via AKS add-on parameters (requires cluster update):

```bash
az aks update \
  --resource-group <RG> \
  --name <CLUSTER> \
  --enable-secret-rotation \
  --rotation-poll-interval 2m
```

---

## Scaling

### Manual Scaling

```bash
# Scale backend replicas immediately
kubectl scale deployment/terraform-registry-backend \
  --replicas=5 -n terraform-registry

# Scale frontend
kubectl scale deployment/terraform-registry-frontend \
  --replicas=3 -n terraform-registry
```

### HPA Status

```bash
kubectl get hpa -n terraform-registry
kubectl describe hpa terraform-registry-backend -n terraform-registry
```

### Adjust HPA Bounds (Helm)

```bash
helm upgrade terraform-registry ./deployments/helm \
  --namespace terraform-registry \
  --reuse-values \
  --set autoscaling.minReplicas=5 \
  --set autoscaling.maxReplicas=20
```

---

## Accessing Logs

```bash
# Backend logs (all replicas, follow)
kubectl logs -n terraform-registry \
  -l app.kubernetes.io/component=backend \
  --tail=100 -f

# Frontend logs
kubectl logs -n terraform-registry \
  -l app.kubernetes.io/component=frontend \
  --tail=50 -f

# Previous crashed pod
kubectl logs -n terraform-registry <POD_NAME> --previous

# Structured JSON logs with jq
kubectl logs -n terraform-registry \
  -l app.kubernetes.io/component=backend \
  --tail=200 | jq 'select(.level == "error")'
```

With Azure Monitor / Container Insights, query logs from Log Analytics:

```kusto
ContainerLogV2
| where ContainerName == "backend"
| where TimeGenerated > ago(1h)
| where LogMessage contains "error"
| project TimeGenerated, LogMessage
| order by TimeGenerated desc
```

---

## Connecting to the Database

### Port-forward to PostgreSQL (for admin tasks)

```bash
# If PostgreSQL allows connections from AKS node pool IPs, port-forward via a debug pod:
kubectl run pg-debug --rm -it \
  --namespace terraform-registry \
  --image=postgres:16-alpine \
  --env="PGPASSWORD=<PASSWORD>" \
  -- psql -h <PG_SERVER>.postgres.database.azure.com \
          -U registry \
          -d terraform_registry
```

### Check active connections

```sql
SELECT count(*), state, wait_event_type, wait_event
FROM pg_stat_activity
WHERE datname = 'terraform_registry'
GROUP BY state, wait_event_type, wait_event
ORDER BY count DESC;
```

---

## Troubleshooting Checklist

### Pods Not Starting

```bash
# Get pod events
kubectl describe pod <POD_NAME> -n terraform-registry

# Common causes:
# 1. CSI volume can't mount (Key Vault access denied)
#    → Check managed identity federated credential and Key Vault RBAC roles
#    → kubectl describe secretproviderclasssecret -n terraform-registry

# 2. Image pull failure (ACR access)
#    → Verify AKS → ACR attachment: az aks check-acr --name <CLUSTER> --acr <ACR>

# 3. Resource limits too low
#    → kubectl top pods -n terraform-registry
```

### Backend CrashLoopBackOff

```bash
kubectl logs <POD_NAME> -n terraform-registry --previous

# Common causes:
# - TFR_DATABASE_HOST is empty or wrong FQDN
#   → Check: kubectl get configmap terraform-registry-config -n terraform-registry -o yaml
# - Database password wrong
#   → Check Key Vault secret: az keyvault secret show --vault-name <KV> --name database-password
# - TFR_JWT_SECRET shorter than 32 chars
#   → Regenerate: openssl rand -hex 32
```

### Gateway Has No IP / Stays in Programmed=False

```bash
kubectl describe gateway terraform-registry-gateway -n terraform-registry

# Common causes:
# - ALB Controller not running
kubectl get pods -n azure-alb-system
# - alb-id annotation wrong (check ARM resource ID format)
# - Missing role assignment for ALB Controller identity
```

### Certificate Stuck in Pending

```bash
kubectl describe certificate terraform-registry-tls -n terraform-registry
kubectl get challenges -n terraform-registry
kubectl describe challenge -n terraform-registry <CHALLENGE_NAME>

# Common causes:
# - DNS A record not yet propagated
#   → dig +short <HOSTNAME> should return the Gateway IP
# - HTTP-01 challenge HTTPRoute not created (cert-manager feature gate missing)
#   → kubectl get httproute -n terraform-registry (look for cm-acme-http-solver-)
# - Gateway port 80 not accessible from public internet
#   → Verify AGfC security rules / NSG
```

### NetworkPolicy Blocking Traffic

```bash
# Temporarily disable NetworkPolicy to test if it's the cause
kubectl delete networkpolicy --all -n terraform-registry

# If traffic flows without NetworkPolicy, check the individual rules:
kubectl get networkpolicy -n terraform-registry
kubectl describe networkpolicy <POLICY_NAME> -n terraform-registry
```

---

## Monitoring

### Prometheus / Grafana

The backend exposes Prometheus metrics at port 9090 (`/metrics`). Pod annotations
enable scraping by a Prometheus operator:

```yaml
prometheus.io/scrape: "true"
prometheus.io/port: "9090"
prometheus.io/path: "/metrics"
```

Enable a `ServiceMonitor` (if using prometheus-operator):

```bash
helm upgrade terraform-registry ./deployments/helm \
  --namespace terraform-registry \
  --reuse-values \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.labels.release=kube-prometheus-stack
```

### Azure Monitor / Container Insights

Enable Container Insights for the cluster:

```bash
az aks enable-addons \
  --resource-group <RG> \
  --name <CLUSTER> \
  --addons monitoring
```

---

## Maintenance and Patching

### Node Pool Upgrades

During an AKS node pool upgrade, Kubernetes drains nodes. The PDB (`minAvailable: 1`)
ensures at least one backend pod is running throughout:

```bash
# Check available upgrade versions
az aks get-upgrades --resource-group <RG> --name <CLUSTER> -o table

# Upgrade (performs rolling node replacement)
az aks upgrade --resource-group <RG> --name <CLUSTER> --kubernetes-version 1.31.0

# Monitor progress
kubectl get nodes --watch
```
