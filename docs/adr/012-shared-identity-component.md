<!-- markdownlint-disable MD013 -->
# 12. Shared Identity Component

**Status**: Accepted

## Context

The registry began life as a standalone application: it owns its users,
organizations, API keys, role templates, OIDC config, audit logs, and JWT
revocation list, all in its own `public` schema, and it ships the auth
primitives (JWT signing/validation, API-key generation/validation, scope
checking) inline in `internal/auth/`.

A second application in the same product family — the Terraform State Manager
(TSM) — needs the *same* identity primitives and, for some operators, the *same*
identity store. If each app reimplements JWT claims, bcrypt API-key hashing,
scope semantics, and host normalization, the two implementations drift: a token
minted by one app fails to validate in the other, scope wildcards diverge, and
the "is this the same user?" question has no defensible answer. Two forces are
in tension:

1. **Standalone must stay standalone.** The overwhelmingly common deployment is
   a single registry with no sibling. None of this can add a service to deploy,
   change default behavior, or require a shared database. The registry must run
   exactly as before when no sibling is configured.

2. **Coupled deployments must share one identity, not two synced copies.** When
   an operator deliberately runs the registry and TSM together, a user,
   organization, or API key should be *one* row that both apps read — not a
   replication pipeline between two stores that can fall out of sync.

We also already had a concrete cross-app feature that surfaces the coupling: the
"Consumed by" panel (which managed states reference a given registry module).
That join only works if both apps agree on the JWT issuer, the scope model, and
the canonical host identity of the registry.

## Decision

Extract the identity and suite-coupling primitives into a single shared Go
**library** — [`terraform-suite-identity`](https://github.com/sethbacon/terraform-suite-identity)
(`github.com/sethbacon/terraform-suite-identity`, pinned at `v0.16.0` in
`backend/go.mod`) — and link it into the registry binary. It is a library, not a
service: there is nothing extra to deploy.

### What the shared module owns

- **JWT** — `identity/auth.TokenManager` performs signing, validation, JTI
  stamping, and the previous-key overlap during rotation. The registry's
  `internal/auth/jwt.go` keeps only `TFR_JWT_SECRET` resolution and the
  `fsnotify` file watch (`TFR_JWT_SECRET_FILE`) that drives rotation; it
  delegates `Generate`/`Validate` to the `TokenManager`. The `iss` claim is the
  app-stable id `"terraform-registry"`. `auth.Claims` is a re-export of
  `identityauth.Claims`.
- **API keys** — `internal/auth/apikey.go` delegates generation, validation, and
  header extraction to `identity/auth`. Length, display-prefix length, and the
  bcrypt cost (see [ADR-0011](0011-password-hashing.md)) are the module's
  constants; the registry only fixes the `tfr_` key prefix.
- **Scopes** — the generic checker (admin wildcard, write-implies-read) and the
  identity-core scope strings (`users:*`, `organizations:*`, `apikeys:manage`,
  `audit:read`, `admin`) live in `identity/auth`. The registry's
  `internal/auth/scopes.go` *injects* its own domain scopes (`modules:*`,
  `providers:*`, `mirrors:*`, `scm:*`, `scanning:read`, `scim:provision`) and the
  read/write pairs, then calls `identityauth.HasScope` et al.
- **Canonical host** — `identity/suite.CanonicalHost` normalizes a host so the
  cross-app join compares like-for-like (lowercase, strip scheme/trailing dot,
  fold IDN to punycode, drop default ports). See [Canonical host
  resolution](../canonical-host.md).
- **Suite manifest, version negotiation, and discovery** — `identity/suite`
  defines the capability `Manifest`, MAJOR-token compatibility
  (`NegotiateCompat`), and the polling `DiscoveryClient`. The package has *no*
  application or web-framework dependencies, so both apps import it identically
  and the contract cannot drift.
- **Shared identity schema + migrations** — the module carries the `identity`
  schema migrations and `identity.RunMigrations`, so the table shapes are owned
  in one place rather than copied into each app's migration set.

### Detect-and-attach ownership model

The shared store is **opt-in and additive**, gated by environment flags that all
default to off so production behavior is unchanged until explicitly enabled
(`cmd/server/main.go`):

- `TFR_IDENTITY_MIGRATIONS_ENABLED=true` runs `identity.RunMigrations` at startup,
  creating/updating the `identity` schema alongside `public`. Safe and reversible;
  it does not change runtime routing on its own.
- `TFR_IDENTITY_SCHEMA_ENABLED=true` opens a dedicated pool whose `search_path`
  is `<schema>,public` (`TFR_IDENTITY_SCHEMA_NAME`, default `identity`) and routes
  identity reads/writes there. Feature tables (modules, providers, mirrors) keep
  using the primary `public` pool.

The phrase "detect-and-attach" describes how the app *behaves toward whatever it
finds* rather than provisioning it:

- The feature-table FK repoint (migration `000038_feature_fk_to_identity`) is
  guarded by `IF EXISTS (… schema_name = 'identity')`: it repoints
  `public.{modules,providers,…}` FKs from `public.{users,organizations}` to
  `identity.{users,organizations}` **only when the identity schema is present**,
  and is a no-op otherwise. The same binary therefore does the right thing
  whether or not a shared store has been attached.
- Under a shared identity *database*, exactly one app must own seeding of the
  system role templates, or the apps overwrite each other's role → scope mapping
  on every restart. `TFR_SUITE_ROLE_SEED_OWNER` (`self` | `registry` | `tsm`,
  default `self`) selects the owner via `SuiteConfig.ShouldSeedRoles`. The
  shared schema seeds identity-core scopes; the registry layers its own domain
  scopes onto the system roles at startup, idempotently.

### Standalone vs coupled suite design

Runtime coupling is discovered, never assumed. `TFR_SUITE_SIBLING_URL` empty
(the default) means fully standalone — nothing is polled and the registry
behaves exactly as it always has. When a sibling URL is set, the registry:

- Publishes its own manifest at `GET /api/v1/suite/manifest`
  (`internal/api/suite.go`, `buildSuiteManifest`) advertising its app id, public
  URL, identity issuer/`sharedStore`/schema, and capabilities (`modules.v1`,
  `providers.v1`, `mirror.v1`, `oci.v1`).
- Runs a background `suite.DiscoveryClient` that polls the sibling's manifest,
  negotiates schema-MAJOR compatibility, and exposes the last-good result as
  `active` / `degraded` / `unreachable`. Degraded/unreachable windows never leak
  a stale identity assertion to the SPA.
- Server-proxies the "Consumed by" lookup to the sibling
  (`moduleConsumersHandler`), authenticated with the shared
  `X-Suite-Service-Token` (`TFR_SUITE_SIBLING_TOKEN`). Whenever the sibling is
  absent, unreachable, or the token is unset, the proxy returns an empty list and
  the panel simply hides — the registry stays fully standalone.

Single sign-on is asserted to the UI only when **both** apps set their shared-store
flag (`TFR_SUITE_IDENTITY_SHARED_STORE` here and its sibling), so the SPA never
claims seamless SSO that the deployment cannot deliver.

## Consequences

**Easier**:

- One canonical implementation of JWT, API keys, scope checking, and host
  normalization, so a token, key, or scope means the same thing in every suite
  app and cannot silently drift.
- The registry stays a single self-contained binary: the shared component is a
  linked library, with nothing extra to deploy and no behavioral change by
  default.
- Coupled operators get one identity store (one user, one org, one key across the
  suite) rather than a replication pipeline.
- Cross-app features (the "Consumed by" join) have a defensible contract: agreed
  issuer, agreed scope model, agreed canonical host.

**Harder**:

- A shared library version must be kept compatible across two repos; the manifest
  schema is therefore strictly additive (never remove or repurpose a field) and
  compatibility is gated on the MAJOR token only.
- The shared-store path adds operational surface — migration enablement, the
  schema cutover, the cross-schema FK repoint (migration 000038, see
  [identity-schema.md](../identity-schema.md)), and single-owner role seeding —
  that standalone deployments never touch but that coupled operators must
  understand.
- Identity behavior is split between the shared module and the registry's
  injection points (`internal/auth/scopes.go`, the secret resolution in
  `jwt.go`), so a contributor changing auth must look in two places.

## Related

- [ADR-001](001-scope-based-rbac.md) — Scope-Based RBAC (the scope model now
  provided by the shared module's checker).
- [ADR-004](004-jwt-plus-apikey-dual-auth.md) — JWT + API Key Dual Authentication
  (both schemes now delegate to the shared `identity/auth` package).
- [ADR-0011](0011-password-hashing.md) — Password and API Key Hashing.
- [docs/identity-schema.md](../identity-schema.md) — operating the shared
  identity schema and the cutover.
- [docs/canonical-host.md](../canonical-host.md) — canonical-host resolution for
  the suite "Consumed by" join.
