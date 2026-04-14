# 7. Setup Wizard One-Time Token

**Status**: Accepted

## Context

The registry needs a secure first-run experience. When deployed fresh, there are no users, no OIDC configuration, and no API keys -- creating a bootstrapping problem. The administrator must configure OIDC, create the first admin user, and set up storage, but these operations normally require authentication.

Common approaches:
1. **Environment variable with admin credentials** -- simple but error-prone (credentials in deployment manifests, forgotten after setup).
2. **First-request-wins** -- whoever hits the setup endpoint first becomes admin. Insecure in shared environments.
3. **One-time setup token** -- generated at first boot, printed to server logs, used once to complete setup, then invalidated.

The implementation in `cmd/server/main.go` (`handleSetupToken`) and `internal/middleware/setup.go` uses approach 3.

## Decision

Use a cryptographically generated one-time setup token for bootstrapping:

- **Token generation**: On first boot (when `system_settings.setup_completed` is false and no token hash exists), generate 32 random bytes, base64url-encode them with a `tfr_setup_` prefix.
- **Storage**: Only the bcrypt hash (cost 12) of the token is stored in `system_settings.setup_token_hash`. The raw token is never persisted.
- **Delivery**: The raw token is printed to server logs with prominent framing. Optionally written to a file specified by `SETUP_TOKEN_FILE` (for Kubernetes secret mounting).
- **Authentication**: Setup endpoints use `Authorization: SetupToken <token>` header, processed by `SetupTokenMiddleware` which is separate from the normal JWT/API key auth chain.
- **Rate limiting**: A dedicated per-IP rate limiter (5 attempts per minute) prevents brute-force attacks on the setup token.
- **Invalidation**: After setup completes, the token hash is removed and `setup_completed` is set to true. The setup endpoints become inaccessible.
- **Restart resilience**: If the server restarts before setup completes, the existing hash is preserved and the previously generated token remains valid.

## Consequences

**Easier**:
- Secure bootstrapping with no pre-shared credentials in deployment manifests.
- The token is cryptographically strong (256 bits of entropy).
- Bcrypt storage means even database access does not reveal the raw token.
- Rate limiting prevents online brute-force attacks.
- The setup UI (`/setup` in the frontend) provides a guided wizard experience.
- Token file output supports automated deployment pipelines.

**Harder**:
- The token is only visible in server logs at first boot -- if logs are not captured, the token is lost (mitigated by `SETUP_TOKEN_FILE`).
- Operators must have log access to retrieve the token, which may require kubectl access in Kubernetes.
- If the token is lost, recovery requires deleting the `setup_token_hash` row from `system_settings` and restarting the server.
- The setup wizard is a separate auth flow from normal operations, adding code complexity in middleware.
