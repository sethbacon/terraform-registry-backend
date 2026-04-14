# Secrets Rotation Guide

This document describes step-by-step procedures for rotating the three main secrets used by the Terraform Registry backend: the JWT signing secret, the encryption key (for SCM OAuth tokens), and OIDC client secrets.

---

## Overview

| Secret             | Purpose                                         | Rotation Impact                                         | Zero-Downtime?                       |
| ------------------ | ----------------------------------------------- | ------------------------------------------------------- | ------------------------------------ |
| `TFR_JWT_SECRET`   | Signs authentication JWTs                       | Invalidates existing sessions unless file-watch is used | Yes (with `TFR_JWT_SECRET_FILE`)     |
| `ENCRYPTION_KEY`   | Encrypts SCM OAuth tokens at rest (AES-256-GCM) | Old tokens unreadable unless dual-key is used           | Yes (with `ENCRYPTION_KEY_PREVIOUS`) |
| OIDC Client Secret | Authenticates the registry to the IdP           | OIDC login fails until all pods have the new secret     | Rolling restart                      |

---

## 1. JWT Secret Rotation

### Option A: File-Based Hot-Reload (Recommended, Zero-Downtime)

The backend supports watching a secret file for changes using `fsnotify`. When the file is updated, the signing key is atomically swapped. Tokens signed with the previous key remain valid for a configurable overlap period (default: 5 minutes).

**Prerequisites:**
- Set `TFR_JWT_SECRET_FILE` to the path of a file containing the JWT secret.
- The file must be readable by the backend process.
- In Kubernetes, use a projected volume from a Secret or an external secrets operator.

**Steps:**

1. **Generate a new secret:**
   ```bash
   openssl rand -hex 32 > /tmp/new-jwt-secret
   ```

2. **Update the Kubernetes Secret** (or your secrets manager):
   ```bash
   kubectl create secret generic registry-jwt-secret \
     --from-file=jwt-secret=/tmp/new-jwt-secret \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

3. **Wait for volume projection.** Kubernetes propagates Secret updates to mounted volumes within the kubelet sync period (default: 60-120 seconds). The backend detects the file change via `fsnotify` and swaps the key atomically.

4. **Monitor logs** for confirmation:
   ```
   INFO JWT secret reloaded from file  path=/etc/secrets/jwt-secret  length=64
   ```

5. **After the overlap period** (default 5 minutes), the previous key is cleared automatically:
   ```
   INFO JWT previous secret cleared after overlap period
   ```

6. **Clean up** the temporary file:
   ```bash
   rm /tmp/new-jwt-secret
   ```

### Option B: Environment Variable Rotation (Requires Restart)

If not using file-watch (`TFR_JWT_SECRET_FILE` is unset), rotating the JWT secret requires restarting all pods.

**Steps:**

1. **Generate a new secret:**
   ```bash
   NEW_SECRET=$(openssl rand -hex 32)
   ```

2. **Update the Kubernetes Secret:**
   ```bash
   kubectl create secret generic registry-secrets \
     --from-literal=TFR_JWT_SECRET="$NEW_SECRET" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

3. **Rolling restart the backend:**
   ```bash
   kubectl rollout restart deployment/terraform-registry-backend
   ```

4. **Impact:** All existing JWT sessions are invalidated. Users must log in again. API keys (which use bcrypt hashing, not JWT) are unaffected.

---

## 2. Encryption Key Rotation (AES-256-GCM)

The encryption key protects SCM OAuth tokens stored in the database. The backend supports dual-key decryption for zero-downtime rotation.

### How Dual-Key Decryption Works

- `ENCRYPTION_KEY` is the current (primary) key used for all new encryption operations.
- `ENCRYPTION_KEY_PREVIOUS` is the old key used only for decryption fallback.
- When decrypting, the backend tries the current key first. If GCM authentication fails (indicating the token was encrypted with a different key), it retries with the previous key.
- This allows a seamless transition: new tokens are encrypted with the new key, old tokens are still readable via the previous key.

### Step-by-Step Procedure

1. **Generate a new encryption key:**
   ```bash
   NEW_KEY=$(openssl rand -hex 16)   # produces 32 hex chars = 32 bytes
   echo "New key: $NEW_KEY"
   ```

2. **Record the current key as the previous key.** Retrieve the current value of `ENCRYPTION_KEY` from your secrets manager.

3. **Update the Kubernetes Secret** with both keys:
   ```bash
   kubectl create secret generic registry-secrets \
     --from-literal=ENCRYPTION_KEY="$NEW_KEY" \
     --from-literal=ENCRYPTION_KEY_PREVIOUS="$OLD_KEY" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

4. **Rolling restart the backend:**
   ```bash
   kubectl rollout restart deployment/terraform-registry-backend
   ```

5. **Verify** that existing SCM connections still work:
   - Navigate to a module with an SCM repository link.
   - Trigger a tag push or verify the webhook integration is functional.
   - Check logs for decryption errors (there should be none).

6. **(Optional) Re-encrypt all tokens** with the new key. This eliminates the dependency on the previous key. You can do this by:
   - Iterating all `scm_providers` rows with encrypted tokens.
   - Decrypting with the dual-key cipher and re-encrypting with only the current key.
   - A future version of the registry will include a built-in admin command for this.

7. **Remove the previous key** once all tokens have been re-encrypted (or after a sufficient grace period):
   ```bash
   kubectl create secret generic registry-secrets \
     --from-literal=ENCRYPTION_KEY="$NEW_KEY" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```
   Then rolling restart the backend again.

### Timeline Recommendation

| Step                             | When                        |
| -------------------------------- | --------------------------- |
| Set new key + previous key       | Day 0                       |
| Rolling restart                  | Day 0                       |
| Re-encrypt all tokens (optional) | Day 0 - Day 7               |
| Remove previous key              | Day 7+ (after verification) |

---

## 3. OIDC Client Secret Rotation

OIDC client secrets are configured via `TFR_AUTH_OIDC_CLIENT_SECRET` (or `TFR_AUTH_AZURE_AD_CLIENT_SECRET` for Azure AD). These are used during the OAuth2 authorization code exchange and are not stored in the database.

### Steps

1. **Generate a new client secret** in your Identity Provider (IdP):
   - Azure AD / Entra ID: App Registrations > Certificates & Secrets > New Client Secret.
   - Okta: Applications > Client Credentials > Generate New Secret.
   - Google: APIs & Services > Credentials > OAuth 2.0 Client > Reset Secret.
   - Keycloak: Clients > Credentials > Regenerate Secret.

2. **Important:** Most IdPs allow multiple active client secrets simultaneously. Add the new secret **before** revoking the old one to avoid a window where no valid secret exists.

3. **Update the Kubernetes Secret:**
   ```bash
   kubectl create secret generic registry-oidc-secrets \
     --from-literal=OIDC_CLIENT_SECRET="new-secret-value" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

4. **Rolling restart the backend:**
   ```bash
   kubectl rollout restart deployment/terraform-registry-backend
   ```

5. **Test** by performing an OIDC login through the UI.

6. **Revoke the old client secret** in the IdP once all pods are running with the new secret.

---

## 4. Database Password Rotation

While not a registry-specific secret, the database password (`TFR_DATABASE_PASSWORD`) should also be rotated periodically.

### Steps

1. **Change the password in PostgreSQL:**
   ```sql
   ALTER USER registry WITH PASSWORD 'new-secure-password';
   ```

2. **Update the Kubernetes Secret:**
   ```bash
   kubectl create secret generic registry-db-secrets \
     --from-literal=TFR_DATABASE_PASSWORD="new-secure-password" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

3. **Rolling restart the backend:**
   ```bash
   kubectl rollout restart deployment/terraform-registry-backend
   ```

---

## 5. Best Practices

- **Use a secrets manager** (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault) rather than plain Kubernetes Secrets. Use the External Secrets Operator or Secrets Store CSI Driver to sync secrets into the cluster.
- **Automate rotation** on a schedule (e.g., every 90 days for JWT and encryption keys, every 180 days for OIDC client secrets).
- **Monitor for decryption errors** after rotation. Set up alerts on log messages containing "decryption" or "GCM auth" failures.
- **Never commit secrets** to source control, Helm values files, or Docker images.
- **Test rotation in staging** before performing it in production.
- **Keep an audit trail** of when secrets were rotated and by whom.

---

## 6. Configuration Reference

| Variable                          | Description                                                             |
| --------------------------------- | ----------------------------------------------------------------------- |
| `TFR_JWT_SECRET`                  | JWT signing secret (env var, requires restart to rotate)                |
| `TFR_JWT_SECRET_FILE`             | Path to file containing JWT secret (file-watch, zero-downtime rotation) |
| `ENCRYPTION_KEY`                  | Current AES-256-GCM encryption key for SCM OAuth tokens                 |
| `ENCRYPTION_KEY_PREVIOUS`         | Previous encryption key (decryption fallback during rotation)           |
| `TFR_AUTH_OIDC_CLIENT_SECRET`     | OIDC client secret                                                      |
| `TFR_AUTH_AZURE_AD_CLIENT_SECRET` | Azure AD client secret                                                  |
| `TFR_DATABASE_PASSWORD`           | PostgreSQL password                                                     |
