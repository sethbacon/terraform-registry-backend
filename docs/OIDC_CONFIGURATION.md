# OIDC Configuration Guide

This document provides comprehensive instructions for configuring OpenID Connect (OIDC) authentication with the Terraform Registry, supporting multiple enterprise identity providers.

## Table of Contents

1. [OIDC Overview](#oidc-overview)
2. [Configuration Basics](#configuration-basics)
3. [Supported Providers](#supported-providers)
4. [Provider-Specific Guides](#provider-specific-guides)
5. [Testing & Troubleshooting](#testing--troubleshooting)
6. [Security Best Practices](#security-best-practices)
7. [Production Deployment Checklist](#production-deployment-checklist)
8. [Support & Resources](#support--resources)

---

## OIDC Overview

### What is OIDC?

OpenID Connect (OIDC) is an authentication layer built on top of OAuth 2.0 that allows applications to verify user identity and obtain basic profile information through registered identity providers. It's widely used in enterprise environments for:

- **Single Sign-On (SSO)** - Users authenticate once and access multiple applications
- **Centralized Identity Management** - One source of truth for user identities
- **Federated Authentication** - Users authenticate using their corporate identity
- **Standards-Based Integration** - Works with any OIDC-compliant provider

### How It Works in Terraform Registry

1. User clicks "Login with [Provider]"
2. User is redirected to the identity provider's login page
3. User authenticates with their corporate credentials
4. Identity provider redirects back with an authorization code
5. Backend exchanges the code for ID token and access token
6. Backend validates the ID token signature and claims
7. User is authenticated with JWT token and logged into Terraform Registry

### Required OIDC Claims

The Terraform Registry requires the following claims from the ID token:

- **`sub` (Subject)** - Unique identifier for the user (required)
- **`email`** - User's email address (required)
- **`name`** - User's display name (optional, defaults to email if not provided)

Additional claims can be used for role mapping and organization assignment through custom configurations.

---

## Configuration Basics

> **First-time setup?** If you're setting up a new registry, the easiest way to configure OIDC is through the [Setup Wizard](initial-setup.md). It handles OIDC provider configuration, storage backend, and admin user creation in a single guided flow. The setup wizard stores OIDC configuration securely in the database with encrypted client secrets.

### Configuration Methods

OIDC can be configured in two ways:

1. **Setup Wizard (recommended for new deployments)** — Use the web UI at `/setup` or the setup API endpoints. Configuration is stored encrypted in the database.
2. **Config file / environment variables** — Set values in `config.yaml` or via environment variables. This is the traditional approach and is still fully supported.

If both database and file-based configurations exist, the **database configuration takes precedence**.

### Important Note: Redirect URL Endpoint

The OIDC redirect URL must be configured correctly. The standard endpoint is:

```txt
https://registry.example.com/api/v1/auth/callback
```

This endpoint MUST match exactly what you configure in your OIDC provider - including:

- Protocol (http/https)
- Domain and port
- Exact path: `/api/v1/auth/callback`
- No trailing slashes

### Environment Variables

Configure OIDC using environment variables with the `TFR_AUTH_OIDC_` prefix:

```bash
# Enable OIDC authentication
export TFR_AUTH_OIDC_ENABLED=true

# OIDC issuer URL (e.g., https://accounts.google.com, https://login.microsoftonline.com/tenant-id/v2.0)
export TFR_AUTH_OIDC_ISSUER_URL=https://your-oidc-provider/.well-known/openid-configuration

# OAuth 2.0 Client ID
export TFR_AUTH_OIDC_CLIENT_ID=your_client_id

# OAuth 2.0 Client Secret
export TFR_AUTH_OIDC_CLIENT_SECRET=your_client_secret

# Redirect URL after successful authentication
# Should match exactly what's configured in your OIDC provider
export TFR_AUTH_OIDC_REDIRECT_URL=https://registry.example.com/api/v1/auth/callback

# Scopes to request from identity provider (default: openid,email,profile)
export TFR_AUTH_OIDC_SCOPES=openid,email,profile

# JWT Secret for signing authentication tokens (required, minimum 32 characters)
export TFR_JWT_SECRET=your_jwt_secret_minimum_32_chars_random_string
```

### YAML Configuration

Alternatively, configure OIDC in `config.yaml`:

```yaml
server:
  base_url: "https://registry.example.com"

auth:
  oidc:
    enabled: true
    issuer_url: "https://your-oidc-provider/..."
    client_id: "your_client_id"
    client_secret: "your_client_secret"
    redirect_url: "https://registry.example.com/api/v1/auth/callback"
    scopes:
      - "openid"
      - "email"
      - "profile"
      - "groups"  # Optional: for group-based role mapping

security:
  cors:
    allowed_origins:
      - "https://registry.example.com"
      - "https://app.registry.example.com"
```

### JWT Secret Configuration

The JWT secret is used to sign authentication tokens. It must be:

- **At least 32 characters long**
- **Cryptographically random** (not a memorable phrase)
- **Consistent across all instances** (if running multiple replicas)
- **Rotated regularly** in production (annually or per security policy)

Generate a secure JWT secret:

```bash
# Using OpenSSL
openssl rand -hex 32

# Using dd
dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64

# Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Finding Your Issuer URL

The OIDC issuer URL is the base endpoint for your identity provider. It should resolve to a `.well-known/openid-configuration` endpoint. Common formats:

- **Generic OIDC**: `https://your-oidc-provider.com`
- **Google**: `https://accounts.google.com`
- **Okta**: `https://your-domain.okta.com`
- **Azure AD**: `https://login.microsoftonline.com/{tenant-id}/v2.0`
- **Keycloak**: `https://keycloak.example.com/auth/realms/{realm}`

To verify, append `/.well-known/openid-configuration` to the URL - it should return JSON with endpoint metadata.

---

## Supported Providers

### Azure AD / Microsoft Entra ID

**Best for:** Enterprises using Microsoft 365, Teams, or other Azure services

- **Maturity:** Production-ready, widely used
- **Features:** Group claims, conditional access, device management
- **Scopes:** `openid`, `email`, `profile` (groups optional)
- **Protocol:** OAuth 2.0 + OIDC v1.0
- **Variants:** Single-tenant, multi-tenant (common), or account type specific

### Auth0

**Best for:** SaaS applications, quick deployment

- **Maturity:** Production-ready
- **Features:** Social login, multi-factor authentication, extensive integrations
- **Scopes:** `openid`, `email`, `profile`, `identities`
- **Protocol:** OAuth 2.0 + OIDC v1.0

### Okta

**Best for:** Enterprise identity management, complex RBAC requirements

- **Maturity:** Production-ready, enterprise-grade
- **Features:** Policies, group synchronization, lifecycle management, MFA
- **Scopes:** `openid`, `email`, `profile`, `groups`
- **Protocol:** OAuth 2.0 + OIDC v1.0
- **Issuer URL pattern:** `https://your-org.okta.com/oauth2/default` or custom authorization server

### Keycloak

**Best for:** Self-hosted identity management, open-source deployments

- **Maturity:** Production-ready
- **Features:** User federation, custom realm roles, SAML/OIDC bridging
- **Scopes:** `openid`, `email`, `profile`, `roles`
- **Protocol:** OAuth 2.0 + OIDC v1.0

### Google Workspace

**Best for:** Organizations using Google Workspace (Gmail, Docs, Sheets)

- **Maturity:** Production-ready
- **Features:** Workspace organization verification, email domain validation
- **Scopes:** `openid`, `email`, `profile`
- **Protocol:** OAuth 2.0 + OIDC v1.0

### Okta Workforce Identity Cloud

**Best for:** Customer identity and access management (CIAM)

- **Maturity:** Production-ready
- **Features:** Consumer identity, API access management, passwordless auth
- **Scopes:** Customizable per application
- **Protocol:** OAuth 2.0 + OIDC v1.0

### PingIdentity / Ping One

**Best for:** Hybrid identity environments, legacy system integration

- **Maturity:** Production-ready, enterprise-grade
- **Features:** Multi-protocol support, risk assessment, device management
- **Scopes:** `openid`, `email`, `profile`, `identities`
- **Protocol:** OAuth 2.0 + OIDC v1.0

---

## Provider-Specific Guides

### Azure AD / Microsoft Entra ID (Recommended for Microsoft Shops)

Azure AD is Microsoft's identity platform and is ideal for organizations already using Microsoft services.

#### Step 1: Register Application in Azure Portal

1. Navigate to **Azure Active Directory** → **App Registrations** → **New registration**
2. Enter application name: `Terraform Registry`
3. Set supported account types to your organization's requirement:
   - **Accounts in this organizational directory only** (Single-tenant)
   - **Accounts in any organizational directory** (Multi-tenant)
   - **Accounts in any organizational directory and personal accounts** (Most permissive)
4. Set Redirect URI:
   - Platform: **Web**
   - URI: `https://registry.example.com/api/v1/auth/callback`
5. Click **Register**

#### Step 2: Configure Application Settings

1. Go to **Certificates & secrets**
2. Create a new **Client secret**
   - Set expiration (1-2 years typical for production)
   - Copy the secret value (you'll need this - it's shown only once!)
3. Go to **API permissions**
4. Add permission: **Microsoft Graph** → **Delegated permissions**
   - Search and add: `email`, `profile`, `openid`, `User.Read`
5. Grant admin consent (if you have permissions)

#### Step 3: Obtain Configuration Values

1. Go to **Overview**
2. Copy:
   - **Application (client) ID** → `TFR_AUTH_OIDC_CLIENT_ID`
   - **Directory (tenant) ID** → Used to construct issuer URL

#### Step 4: Configure Terraform Registry

For **single-tenant** (users from your organization only):

```bash
export TFR_AUTH_OIDC_ENABLED=true
export TFR_AUTH_OIDC_ISSUER_URL=https://login.microsoftonline.com/8f5f3c5f-9c2e-4c3d-9b8f-3c5f9c2e4c3d/v2.0
# Replace the UUID with your Directory (tenant) ID

export TFR_AUTH_OIDC_CLIENT_ID=your_app_id
export TFR_AUTH_OIDC_CLIENT_SECRET=your_client_secret
export TFR_AUTH_OIDC_REDIRECT_URL=https://registry.example.com/api/v1/auth/callback
export TFR_JWT_SECRET=your_32_char_random_secret
```

For **multi-tenant** (users from any Azure AD):

```bash
export TFR_AUTH_OIDC_ENABLED=true
export TFR_AUTH_OIDC_ISSUER_URL=https://login.microsoftonline.com/common/v2.0
# "common" allows any Azure AD tenant to authenticate

export TFR_AUTH_OIDC_CLIENT_ID=your_app_id
export TFR_AUTH_OIDC_CLIENT_SECRET=your_client_secret
export TFR_AUTH_OIDC_REDIRECT_URL=https://registry.example.com/api/v1/auth/callback
export TFR_JWT_SECRET=your_32_char_random_secret
```

Or use Azure AD-specific configuration:

```bash
export TFR_AUTH_AZURE_AD_ENABLED=true
export TFR_AUTH_AZURE_AD_TENANT_ID=8f5f3c5f-9c2e-4c3d-9b8f-3c5f9c2e4c3d
export TFR_AUTH_AZURE_AD_CLIENT_ID=your_app_id
export TFR_AUTH_AZURE_AD_CLIENT_SECRET=your_client_secret
export TFR_AUTH_AZURE_AD_REDIRECT_URL=https://registry.example.com/api/v1/auth/callback
export TFR_JWT_SECRET=your_32_char_random_secret
```

#### Step 5: Map Groups (Optional)

To use Azure AD group memberships for role assignment:

1. Add **optional claim** in **Token configuration**:
   - Claim type: `groups`
   - Token type: ID
2. Select "Security groups"
3. Query attribute: `displayName`

---

### Okta (Recommended for Pure Identity Management)

Okta is a best-in-class identity platform with excellent enterprise support.

#### Step 1: Create OIDC Application in Okta

1. Log in to Okta Admin Console
2. Go to **Applications** → **Applications** → **Create App Integration**
3. Select **OIDC - OpenID Connect**
4. Select **Web Application**
5. Enter application name: `Terraform Registry`
6. Set sign-in redirect URIs:
   - `https://registry.example.com/api/v1/auth/callback`
7. Set sign-out redirect URI: `https://registry.example.com`
8. Click **Save**

#### Step 2: Retrieve Credentials

1. Go to **General** tab
2. Copy:
   - **Client ID** → `TFR_AUTH_OIDC_CLIENT_ID`
   - **Client Secret** → `TFR_AUTH_OIDC_CLIENT_SECRET`
3. Note your Okta domain (e.g., `dev-123456.okta.com`)

#### Step 4: Configure Terraform Registry for Okta

```bash
export TFR_AUTH_OIDC_ENABLED=true
export TFR_AUTH_OIDC_ISSUER_URL=https://dev-123456.okta.com
export TFR_AUTH_OIDC_CLIENT_ID=your_client_id
export TFR_AUTH_OIDC_CLIENT_SECRET=your_client_secret
export TFR_AUTH_OIDC_REDIRECT_URL=https://registry.example.com/api/v1/auth/callback
export TFR_AUTH_OIDC_SCOPES=openid,email,profile,groups
export TFR_JWT_SECRET=your_32_char_random_secret
```

#### Step 4: Map Groups (Optional)

1. In Okta, go to **Security** → **API** → **Authorization Servers** → **default**
2. Go to **Claims** tab
3. Add claim:
   - Name: `groups`
   - Include in token types: ID Token
   - Value type: Groups
   - Filter: `Regex` match `.*`

---

### Google Workspace (Recommended for Google-Centric Organizations)

Google Workspace integrates seamlessly with GSuite organizations.

#### Step 1: Create OAuth Credentials

1. Open [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project or select existing one
3. Go to **APIs & Services** → **Create Credentials** → **OAuth client ID**
4. If prompted, configure OAuth consent screen first:
   - User type: Internal (for workspace) or External
   - Add scopes: `openid`, `email`, `profile`
5. Application type: **Web application**
6. Add Authorized redirect URIs:
   - `https://registry.example.com/api/v1/auth/callback`
7. Click **Create**

#### Step 2: Retrieve Google Credentials

Copy the displayed:

- **Client ID** → `TFR_AUTH_OIDC_CLIENT_ID`
- **Client Secret** → `TFR_AUTH_OIDC_CLIENT_SECRET`

#### Step 3: Configure Terraform Registry for Google

```bash
export TFR_AUTH_OIDC_ENABLED=true
export TFR_AUTH_OIDC_ISSUER_URL=https://accounts.google.com
export TFR_AUTH_OIDC_CLIENT_ID=your_client_id.apps.googleusercontent.com
export TFR_AUTH_OIDC_CLIENT_SECRET=your_client_secret
export TFR_AUTH_OIDC_REDIRECT_URL=https://registry.example.com/api/v1/auth/callback
export TFR_JWT_SECRET=your_32_char_random_secret
```

#### Step 4: Restrict to Google Workspace (Optional)

To only allow your workspace organization:

1. In Google Cloud Console, go to **APIs & Services** → **OAuth consent screen**
2. Under "Authorized domains", add your Google Workspace domain
3. This restricts login to users in your workspace organization

---

### Keycloak (Self-Hosted Option)

Keycloak is open-source and suitable for organizations wanting full control.

#### Step 1: Create OIDC Client in Keycloak

1. Log in to Keycloak Admin Console
2. Select realm (or create one)
3. Go to **Clients** → **Create**
4. Enter Client ID: `terraform-registry`
5. Client Protocol: `openid-connect`
6. Click **Save**

#### Step 2: Configure Client Settings

1. Go to **Access Type**: Set to `confidential`
2. Go to **Valid Redirect URIs**:
   - Add: `https://registry.example.com/api/v1/auth/callback`
3. Go to **Credentials** tab
   - Copy **Client Secret**
4. Save

#### Step 3: Configure Terraform Registry

```bash
export TFR_AUTH_OIDC_ENABLED=true
export TFR_AUTH_OIDC_ISSUER_URL=https://keycloak.example.com/auth/realms/your-realm
export TFR_AUTH_OIDC_CLIENT_ID=terraform-registry
export TFR_AUTH_OIDC_CLIENT_SECRET=your_client_secret
export TFR_AUTH_OIDC_REDIRECT_URL=https://registry.example.com/api/v1/auth/callback
export TFR_JWT_SECRET=your_32_char_random_secret
```

---

## Testing & Troubleshooting

### Verify OIDC Configuration

Before deploying, verify your OIDC provider configuration:

```bash
# Check if issuer URL is accessible and returns OpenID configuration
curl -s https://your-issuer-url/.well-known/openid-configuration | jq .

# Should return JSON with:
# - authorization_endpoint
# - token_endpoint
# - userinfo_endpoint
# - jwks_uri
```

### Test OIDC/Azure AD Login Flow

1. Open Terraform Registry in browser: `https://registry.example.com`
2. Look for login button or authentication link
3. Click to initiate OIDC flow
4. You should be redirected to your identity provider's login page
5. Log in with your credentials
6. You should be redirected back to the registry with a session
7. You should see your authenticated user profile

### Test OIDC Login via API

```bash
# Redirect to OIDC provider
curl -X GET "https://registry.example.com/api/v1/auth/login?provider=oidc"
# This redirects to your identity provider

# After successful login and callback, you'll receive a JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Test authenticated endpoint
curl https://registry.example.com/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"

# Should return your user information
```

### Create and Test API Key

```bash
# After authenticating, create an API key
curl -X POST https://registry.example.com/api/v1/apikeys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Key",
    "scopes": ["modules:read", "providers:read"]
  }'

# Save the returned key from response
API_KEY="tfr_abc123..."

# Test with the API key
curl https://registry.example.com/api/v1/modules/search \
  -H "Authorization: Bearer $API_KEY"
```

### Common Configuration Errors

#### 1. Invalid Issuer URL

**Symptom:** "failed to create OIDC provider" error in logs

**Solution:**

- Verify issuer URL is correct (no trailing slashes)
- Test with curl: `curl https://your-issuer-url/.well-known/openid-configuration`
- Should return JSON configuration, not 404 or 500 error
- Check that server has internet access and can reach the issuer

#### 2. Redirect URI Mismatch

**Symptom:** "redirect_uri_mismatch" or "invalid_request" from provider

**Solution:**

- Ensure `TFR_AUTH_OIDC_REDIRECT_URL` exactly matches configured URI in provider
- Common mistakes:
  - `http://` vs `https://`
  - Missing or extra trailing slashes
  - Wrong port number
  - Missing full path: `/api/v1/auth/callback`
- Example correct format: `https://registry.example.com/api/v1/auth/callback`

#### 3. Missing Required Claims

**Symptom:** "ID token missing 'email' claim" error

**Solution:**

- Verify scopes include `email` and `profile`
- Check that user's identity provider account has email configured
- Test with different identity provider user account
- Add additional scopes if needed: `export TFR_AUTH_OIDC_SCOPES="openid,email,profile,groups"`

#### 4. Invalid Client Credentials

**Symptom:** "invalid_grant" or "invalid_client" from identity provider during token exchange

**Solution:**

- Verify client ID and secret are correct (copy-paste from provider, no extra spaces)
- Ensure client secret hasn't expired (Azure AD secrets expire after 1-2 years)
- Check that application is still registered and active in provider
- Regenerate credentials if uncertain
- For Azure AD: Check that the app hasn't been disabled

#### 5. JWT Token Errors

**Symptom:** "invalid token signature" or "token validation failed"

**Solution:**

- Ensure `TFR_JWT_SECRET` is set and at least 32 characters
- Verify same JWT secret is used across all registry instances (for multi-instance deployments)
- Check JWT secret hasn't been changed (invalidates existing tokens)
- Users will need to log in again if secret is rotated

#### 6. CORS Errors in Browser

**Symptom:** "Access to XMLHttpRequest... has been blocked by CORS policy"

**Solution:**

- Add frontend URL to CORS allowed origins in config
- Example error: Accessing `https://registry.example.com` from different origin
- Configure CORS:

```bash
# In config.yaml
security:
  cors:
    allowed_origins:
      - "https://registry.example.com"
      - "https://app.registry.example.com"
```

### Debug Mode

Enable debug logging to troubleshoot OIDC issues:

```bash
export TFR_LOGGING_LEVEL=debug
export TFR_LOGGING_FORMAT=json

# Watch logs during login attempt
docker-compose logs -f backend | grep -i "oidc\|auth\|token"
```

Look for:

- Token exchange requests
- Claim verification steps
- Discovery document retrieval
- JWKS key loading

---

## Security Best Practices

### 1. JWT Secret Management

- Use a cryptographically random secret (minimum 32 characters)
- Never commit to version control
- Rotate periodically in production (annually recommended)
- Use same secret across all registry instances
- Store in secure secret management system (AWS Secrets Manager, Azure Key Vault, etc.)

```bash
# Generate secure JWT secret
openssl rand -hex 32
```

### 2. HTTPS in Production

- Always use HTTPS (TLS 1.2+) for production deployments
- Obtain SSL certificate from trusted CA (Let's Encrypt, cloud provider, etc.)
- Redirect HTTP to HTTPS
- Set Strict-Transport-Security header (HSTS)

### 3. Client Credentials

- Store client ID and secret in secure secret management system
- Never log or expose credentials
- Rotate credentials annually or per company security policy
- For Azure AD: Consider using certificates instead of secrets for higher security

### 4. Redirect URI Restrictions

- Only register valid callback URLs in OIDC provider
- Use exact, full paths (not wildcards)
- Restrict to HTTPS in production
- Regularly audit registered URIs

### 5. Scopes & Permissions

- Request minimum required scopes (principle of least privilege)
- Start with: `openid`, `email`, `profile`
- Add `groups` only if using group-based RBAC
- Avoid requesting overly permissive scopes

### 6. Token Expiration

- Use reasonable JWT expiration times (24 hours typical)
- API keys should have optional expiration dates
- Implement token refresh mechanism for long-lived sessions
- Monitor for and invalidate compromised tokens

### 7. CORS Configuration

- Restrict allowed origins in production
- Never use `*` wildcard in production
- Only allow trusted frontend domains
- Use minimum required HTTP methods

```yaml
security:
  cors:
    allowed_origins:
      - "https://registry.example.com"
    allowed_methods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
```

### 8. Monitoring & Audit Logging

- Enable audit logging for authentication events
- Monitor failed login attempts
- Monitor API key usage
- Set up alerts for suspicious patterns
- Regularly review authentication logs

### 9. Multi-Factor Authentication

- Consider enabling MFA in your OIDC provider
- Okta, Azure AD, Auth0 all support MFA
- Reduces risk of compromised passwords
- Enterprise-recommended security practice

### 10. Regular Security Updates

- Keep OIDC provider client libraries up to date
- Monitor for security advisories
- Rotate credentials on schedule
- Perform regular security audits

---

## Production Deployment Checklist

The [Deployment Checklist](deployment.md#deployment-checklist) covers all general
pre-deployment verification (TLS, secrets management, environment variables, database
migrations, DNS, smoke tests, monitoring, and rollback).

The following OIDC-specific items supplement that checklist:

- [ ] Set production OIDC provider issuer URL (`OIDC_ISSUER_URL`)
- [ ] Register the production redirect URI in the OIDC provider (must match `BASE_URL`)
- [ ] Update CORS allowed origins to production domain(s)
- [ ] Verify that email and profile claims are returned correctly by the provider
- [ ] Test the complete end-to-end login flow (browser → OIDC provider → callback → session)
- [ ] Confirm audit logging captures login and logout events
- [ ] Schedule regular reviews of the registered OIDC application credentials and scopes

---

## Support & Resources

- **OIDC Specification**: <https://openid.net/specs/openid-connect-core-1_0.html>
- **RFC 6749 (OAuth 2.0)**: <https://tools.ietf.org/html/rfc6749>
- **coreos/go-oidc** (library used): <https://github.com/coreos/go-oidc>
- **Provider Documentation**:
  - [Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/)
  - [Okta](https://developer.okta.com/docs/)
  - [Auth0](https://auth0.com/docs)
  - [Google](https://developers.google.com/identity/protocols/oauth2)
  - [Keycloak](https://www.keycloak.org/documentation)

For support with Terraform Registry OIDC configuration:

1. Check implementation plan for current features
2. Review codebase in `/backend/internal/auth/`
