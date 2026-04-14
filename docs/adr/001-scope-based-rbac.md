# 1. Scope-Based RBAC

**Status**: Accepted

## Context

The registry needs an authorization model that controls access to modules, providers, mirrors, users, organizations, SCM integrations, audit logs, and scanning results. Two common approaches exist:

1. **Role-based access control (RBAC)** with predefined roles (e.g., Admin, Editor, Viewer) where each role grants a fixed set of permissions.
2. **Scope-based access control** with fine-grained permission strings (e.g., `modules:read`, `providers:write`, `admin`) assigned directly to users and API keys.

Terraform registries serve diverse organizational structures. Some teams need a user who can publish modules but not manage mirrors. Others need CI/CD API keys with write access to a single namespace. Coarse roles like "Editor" cannot express these distinctions without either creating an explosion of specialized roles or granting overly broad permissions.

The codebase defines permissions in `internal/auth/scopes.go` with 16 distinct scopes covering modules, providers, mirrors, users, organizations, SCM, API keys, audit, scanning, and an `admin` wildcard. Scopes are stored as string arrays on API keys and in JWT claims.

## Decision

Use fine-grained scope strings as the primary authorization mechanism:

- Each API key and JWT token carries an explicit list of scopes (e.g., `["modules:read", "modules:write"]`).
- The `admin` scope acts as a wildcard, granting all permissions.
- Write/manage scopes implicitly grant their corresponding read scope (e.g., `modules:write` implies `modules:read`).
- Route-level middleware (`RequireScope`, `RequireAnyScope`) enforces scopes before handlers execute.
- Role templates (stored in the `role_templates` table) provide convenience groupings but are expanded to scopes at assignment time, not enforced at runtime.

## Consequences

**Easier**:
- API keys can be created with minimal required permissions (principle of least privilege).
- New resource types can be added by defining a new scope string without modifying existing roles.
- CI/CD integrations get precisely scoped tokens that cannot accidentally modify unrelated resources.
- Authorization logic is simple: check if the token's scope list includes the required scope.

**Harder**:
- Users and administrators must understand the scope model when creating API keys.
- Role templates must be maintained as a convenience layer to avoid requiring everyone to manually select scopes.
- Scope lists in JWT claims increase token size slightly compared to a single role string.
