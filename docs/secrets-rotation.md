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

6. **Re-encrypt every stored secret** under the new key, removing the dependency on the previous key:

   ```bash
   terraform-registry rekey-secrets
   ```

   This is the step that makes the rotation finishable, and it is **not optional** if you
   intend to reach step 7. It reads each secret through the dual-key path (so rows still
   on the old key are read via `ENCRYPTION_KEY_PREVIOUS`) and re-seals it with the
   **current** key, under the same row binding it already had. It covers every swept
   encrypted column — SCM provider client secrets and GitHub App private keys,
   storage-backend credentials, the OIDC client secret, notification channel targets,
   SMTP and LDAP passwords. See [What `rekey-secrets` covers](#what-rekey-secrets-covers)
   for the two columns it deliberately does not.

   A row already on the current key is left untouched, so the command is safe to re-run
   and cheap to run again after an interruption. A row that is not yet bound to its row
   is bound *and* re-encrypted in the same pass, so you do not need to run `bind-secrets`
   first.

   **Do not use `bind-secrets` for this.** It converts a ciphertext's *form* and skips any
   row it can already open — and that check goes through the dual-key fallback, so a row
   that is bound but still sealed under the previous key looks finished to it. On a first
   rotation after upgrading, when nothing is bound yet, it happens to re-encrypt as a side
   effect; on every rotation after that it re-encrypts nothing.

7. **Remove the previous key** — but only once the gate says it is safe:

   ```bash
   terraform-registry rekey-secrets verify   # exits non-zero while any row needs the previous key
   ```

   **A zero exit from this command is the only thing that authorises removing
   `ENCRYPTION_KEY_PREVIOUS`.** It writes nothing. It re-checks every swept row against a
   cipher holding *only* the current key, so unlike `bind-secrets verify` it can tell
   "opened with the current key" from "opened with the previous one" — which is the
   question this step actually turns on.

   A non-zero exit means at least one row still requires the previous key, or could not be
   read at all. Both hold the gate shut, and both are logged per column with a row id.

   Removing `ENCRYPTION_KEY_PREVIOUS` while any row is still encrypted under it makes that
   secret **permanently unreadable**, by the service and by these commands alike, and it
   has to be re-entered by an administrator. There is no undo. When the gate is red, keep
   the previous key: an extra key in a secrets manager is cheap.

   ```bash
   kubectl create secret generic registry-secrets \
     --from-literal=ENCRYPTION_KEY="$NEW_KEY" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

   Then rolling restart the backend again.

### Timeline Recommendation

| Step                                            | When                                |
| ----------------------------------------------- | ----------------------------------- |
| Set new key + previous key                      | Day 0                               |
| Rolling restart                                  | Day 0                               |
| `rekey-secrets` (re-encrypt everything)         | Day 0 - Day 7                       |
| `rekey-secrets verify` returns zero             | Before removing the previous key    |
| Remove previous key                             | Day 7+ (only after the gate is green) |

### Completing a Rotation: `rekey-secrets`

**Why a second command.** `bind-secrets` answers *"is every ciphertext bound to its
row?"*; `rekey-secrets` answers *"is every ciphertext readable without the previous
key?"*. Those look like the same question and are not: a row can be bound and still be
sealed under the key you are about to delete, and the read path will not tell you,
because it silently falls back.

**Run it:**

```bash
# Re-encrypt every swept secret under the current ENCRYPTION_KEY.
terraform-registry rekey-secrets

# Report what still needs ENCRYPTION_KEY_PREVIOUS, writing nothing.
terraform-registry rekey-secrets verify
```

In a container the binary is at `/app/terraform-registry`, so:

```bash
kubectl exec deploy/terraform-registry -- /app/terraform-registry rekey-secrets verify
```

Both need `ENCRYPTION_KEY` and — until the rotation is complete — `ENCRYPTION_KEY_PREVIOUS`,
the same values the server runs with. If `ENCRYPTION_KEY` is not the key the service is
actually sealing with, the command refuses before reading a single row rather than
re-encrypting your estate under a key nothing else has.

**Safe to re-run and safe to interrupt.** Rows are written one at a time, and a row is
skipped once it is bound and on the current key, so a second run is a no-op and an
interrupted run is resumed by running it again. Nothing is written in `verify` mode.

**A row reported as `failed`** could not be decrypted at all, or is bound to a *different*
row than the one it was found in. Neither is re-sealed into place: doing so would mint a
valid binding for a value that was moved, which is the exact tampering the binding exists
to detect. A failed row is logged with its column and row id, and holds the verify gate
shut — "one row could not be read" is not evidence that the previous key can go.

<a id="what-rekey-secrets-covers"></a>

**What `rekey-secrets` covers.** Every column the maintenance registry sweeps: notification
channel targets, all four `storage_config` credentials, the OIDC client secret, the
`scm_providers` client secret and GitHub App private key, and the SMTP and LDAP passwords
inside `system_settings`. These are the secrets only an administrator could re-enter.

Two encrypted columns are **not** swept, and `rekey-secrets verify` returning zero says
nothing about them:

| Column                                    | Why it is not swept                                                                                         |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `scm_provider_tokens.access_token_encrypted` | A cache with an expiry. Entries are re-minted from the identity provider, so the table converts itself.       |
| `scm_oauth_tokens.access_token_encrypted` / `refresh_token_encrypted` | Per-user OAuth tokens. Rows are re-sealed whenever a token is refreshed; a row that is not refreshed before the previous key is removed becomes unreadable, and that user re-links their SCM account to restore it. |

Neither needs an administrator to recover, which is why the rotation is not blocked on
them — but if you would rather not have users re-link, leave `ENCRYPTION_KEY_PREVIOUS` in
place for a token-refresh cycle after the gate goes green.

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
**current** key — but only for rows it actually converts. A row that is *already*
bound is skipped, and that skip is decided by an open that falls back to
`ENCRYPTION_KEY_PREVIOUS`, so a bound row still sealed under the old key looks
finished here.

The practical consequence: `bind-secrets` re-encrypts as a side effect on the first
rotation after upgrading (when nothing is bound yet) and on no rotation after that. It
is not the re-encryption step and `bind-secrets verify` is not the rotation gate — use
[`rekey-secrets`](#completing-a-rotation-rekey-secrets) for both. Run either one
*before* removing `ENCRYPTION_KEY_PREVIOUS`: after removal, any row still on the old
key can no longer be read by anything, including these commands.

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
