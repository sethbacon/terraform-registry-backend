# 4. JWT + API Key Dual Authentication

**Status**: Accepted

## Context

The registry serves two fundamentally different client types:

1. **Human users** who interact through the web UI and need session-based authentication with OIDC/Azure AD single sign-on.
2. **Machine clients** (CI/CD pipelines, `terraform init`, automation scripts) that need non-interactive, long-lived credentials.

A single authentication scheme cannot serve both well:
- JWT tokens from OIDC are short-lived (hours) and require browser-based login flows -- unsuitable for CI/CD.
- API keys are long-lived and stateless but lack the identity federation and SSO capabilities humans expect.

The codebase implements both in `internal/auth/jwt.go` (JWT creation/validation with `TFR_JWT_SECRET`) and `internal/auth/apikey.go` (API key validation against bcrypt hashes in the `api_keys` table). The `AuthMiddleware` in `internal/middleware/` tries JWT first, then API key, extracting scopes from either source.

## Decision

Support dual authentication: JWT tokens for human users and API keys for machine clients.

- **JWT tokens** are issued after OIDC/Azure AD authentication. They carry `user_id`, `email`, `scopes`, and a `jti` (JWT ID) for revocation. Signed with `TFR_JWT_SECRET` using HMAC-SHA256.
- **API keys** are prefixed strings (`tfr_*`) whose SHA-256 hash is stored in the `api_keys` table. They carry explicit scopes, optional expiration dates, and are tied to a creating user.
- **`Authorization` header** accepts both: `Bearer <jwt_token>` and `Bearer <api_key>`.
- The `AuthMiddleware` attempts JWT validation first; if that fails, it looks up the key hash in the database. This ordering is intentional: JWT validation is a pure crypto operation (fast, no DB hit), while API key lookup requires a database query.
- Both paths produce the same Gin context shape: `user_id`, `email`, `scopes` -- downstream handlers are authentication-scheme-agnostic.

## Consequences

**Easier**:
- Human users get SSO through OIDC/Azure AD with short-lived tokens.
- CI/CD pipelines use long-lived API keys with minimal scopes (least privilege).
- API key expiration and revocation provide lifecycle management.
- Token revocation via `jwt_revoked_tokens` table enables immediate session invalidation.
- `.terraformrc` credential blocks work naturally with API keys.

**Harder**:
- Two authentication code paths must be maintained and tested.
- JWT secret management is critical -- loss invalidates all sessions (mitigated by `TFR_JWT_SECRET_FILE` and rotation support).
- API key hashes in the database add a query per machine-client request (mitigated by the JWT-first check order).
- Users must understand which authentication method to use in which context.
