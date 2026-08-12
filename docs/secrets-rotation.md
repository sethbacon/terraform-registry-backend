<!-- markdownlint-disable MD013 MD060 -->
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

The backend supports watching a secret file for changes using `fsnotify`. When the file is updated, the signing key is atomically swapped. Tokens signed with the previous key remain valid for an overlap period set by `TFR_JWT_SECRET_OVERLAP` (a Go duration such as `10m`; default: 5 minutes). An unset, unparseable or non-positive value uses the default — the overlap only widens the window in which an *old* key still validates, so it is not worth failing a deploy over.

The watch starts only when `TFR_JWT_SECRET_FILE` is set. If it is set and the file cannot be read or watched, the server **refuses to start** rather than falling back to `TFR_JWT_SECRET` — otherwise a rotation you believed was live would silently never happen.

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

   ```text
   INFO JWT secret reloaded from file  path=/etc/secrets/jwt-secret  length=64
   ```

5. **After the overlap period** (default 5 minutes), the previous key is cleared automatically:

   ```text
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

   `ENCRYPTION_KEY` is consumed directly as raw AES-256 key bytes — there is no
   password-based key derivation. Always generate it with a CSPRNG as shown above;
   never type a passphrase by hand. At startup the backend refuses to start if
   `ENCRYPTION_KEY`'s estimated entropy looks low (e.g. a human-typed passphrase or a
   repeated pattern) — regenerate and rotate the key rather than reaching for
   `TFR_ALLOW_LOW_ENTROPY_ENCRYPTION_KEY`, which only exists as a temporary bridge to
   restart an existing deployment while you rotate to a stronger key (see
   [docs/initial-setup.md](initial-setup.md)).

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

6. **(Optional) Re-encrypt every stored secret** with the new key, removing the dependency on the previous key:

   ```bash
   terraform-registry bind-secrets
   ```

   This decrypts through the dual-key path (so rows still on the old key are read via
   `ENCRYPTION_KEY_PREVIOUS`) and re-encrypts with the **current** key. It covers every
   encrypted column — SCM provider credentials, user OAuth tokens, storage-backend
   credentials, the OIDC client secret, SMTP and LDAP passwords — not just
   `scm_providers`.

   **This only re-encrypts rows that are not yet row-bound.** Read that limitation
   carefully, because it changes what this step can do for you:

   - **If you have not yet run the row-binding migration below** (the usual case on a
     first rotation after upgrading), every row is unbound, so this one command does
     both jobs: it binds each secret to its row *and* lands it on the current key.
   - **If your rows are already bound**, this command detects them as converted and
     **skips them** — it will not re-encrypt them onto the new key. That detection
     succeeds via the dual-key fallback, so a bound row sitting on the previous key
     looks "already done" to it. There is no re-encrypt-only command today; keep
     `ENCRYPTION_KEY_PREVIOUS` in place, or re-enter those credentials, until one exists.

   Confirm what actually happened before moving to step 7:

   ```bash
   terraform-registry bind-secrets verify   # exits non-zero if any row is unbound
   ```

   Note this verifies **binding**, not which key a row is encrypted under. It passing
   does not by itself prove you can safely drop `ENCRYPTION_KEY_PREVIOUS`.

7. **Remove the previous key** once all tokens have been re-encrypted (or after a sufficient grace period).

   Be sure step 6 actually re-encrypted, rather than skipping already-bound rows — see
   the limitation there. Removing `ENCRYPTION_KEY_PREVIOUS` while any row is still
   encrypted under it makes that secret **permanently unreadable**, by the service and
   by `bind-secrets` alike, and it has to be re-entered by an administrator. When in
   doubt, keep the previous key: an extra key in a secrets manager is cheap, and this
   is not a reversible mistake.

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

### One-Time: Bind Stored Secrets to Their Rows

This is a **one-time migration per deployment**, not a recurring rotation. Nothing
breaks if you skip it — but the protection it adds does not apply to your existing
data until you run it.

**What it protects against.** A stored ciphertext used to carry no indication of
*where* it belonged. Anyone able to write to the database could copy one row's
encrypted value into another row — one SCM provider's client secret into another's,
one channel's webhook target into another channel — and AES-GCM would accept it,
because nothing in the ciphertext contradicted the move. Each secret is now bound to
its own row and column, so a moved value fails to decrypt.

Reading tolerates both forms, so this is safe to run whenever suits you, and safe not
to run at all.

**Run it:**

```bash
# Convert every stored secret that is not yet bound.
terraform-registry bind-secrets

# Report what remains, writing nothing.
terraform-registry bind-secrets verify
```

In a container the binary is at `/app/terraform-registry`, so:

```bash
kubectl exec deploy/terraform-registry -- /app/terraform-registry bind-secrets verify
```

Both need `ENCRYPTION_KEY` (and `ENCRYPTION_KEY_PREVIOUS`, if set) — the same values
the server runs with. The conversion happens in the application because AES-GCM
re-encryption needs the key; there is no SQL migration that can do it.

**Safe to re-run and safe to interrupt.** An already-bound row is detected and
skipped rather than re-encrypted, so a run that dies halfway is resumed by running it
again. Nothing is written in `verify` mode.

**A row reported as `failed`** could not be decrypted *at all* — a wrong key, or
corruption. That is a pre-existing problem this command did not cause and cannot
repair; it is reported and stepped over so the remaining rows still convert. Such a
secret has to be re-entered by an administrator.

**Interaction with key rotation** (this is the non-obvious part): the conversion
decrypts through the same dual-key path the server uses, then re-encrypts with the
**current** key. So running `bind-secrets` during a rotation window also completes
the re-encryption step for every row it touches — the "Re-encrypt all tokens
(optional)" line in the timeline above. Running it *before* removing
`ENCRYPTION_KEY_PREVIOUS` is therefore strictly better than running it after: after
removal, any row still on the old key can no longer be read by anything, including
this command.

**Why `verify` exists.** Until it reports zero, the service must keep accepting
unbound ciphertexts — which is the weakness being retired. It exits non-zero while
any row remains unbound, so it can gate a release or a runbook step rather than
relying on someone reading the output. A future version will require bound values and
drop the tolerance; `verify` returning zero is what tells you that upgrade is safe.

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
     --from-literal=TFR_AUTH_OIDC_CLIENT_SECRET="new-secret-value" \
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

### Database Password Rotation Steps

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
