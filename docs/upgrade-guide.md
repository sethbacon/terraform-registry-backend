<!-- markdownlint-disable MD013 -->
# Version Upgrade Guide

This guide documents the upgrade process between Terraform Registry versions,
including breaking changes, migration behavior, rollback strategies, and
pre-flight validation.

## General Upgrade Procedure

### Pre-flight Checks

Before upgrading, run the preflight validation command:

```bash
# Binary
./terraform-registry upgrade preflight --config config.yaml

# Docker
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml \
  ghcr.io/sethbacon/terraform-registry-backend:NEW_VERSION \
  upgrade preflight --config /app/config.yaml
```

The preflight check validates:

- Database connectivity and current schema version
- Required schema migrations for the target version
- Storage backend accessibility
- Configuration compatibility (deprecated/removed settings)
- Available disk space for migration

### Standard Upgrade Steps

1. **Back up the database:**

   ```bash
   pg_dump -Fc terraform_registry > backup-$(date +%Y%m%d).dump
   ```

2. **Back up object storage** (if not using versioned buckets)

3. **Run preflight checks** (see above)

4. **Stop the current backend** (in rolling deployments, use a maintenance window for major upgrades)

5. **Deploy the new version:**
   - Docker: update image tag in compose/k8s manifests
   - Binary: replace the binary

6. **Start the backend** — migrations run automatically on startup

7. **Verify health:**

   ```bash
   curl -s https://registry.example.com/health | jq
   curl -s https://registry.example.com/version | jq
   ```

8. **Verify key functionality:**
   - Module listing: `terraform providers mirror`
   - Module download: `terraform init` in a consumer project
   - Admin UI login

### Rollback Strategy

If issues are found after upgrade:

1. **Stop the new version**
2. **Restore the database backup:**

   ```bash
   pg_restore -d terraform_registry backup-YYYYMMDD.dump
   ```

3. **Deploy the previous version**
4. **Verify functionality**

> **Important:** Some migrations are irreversible. See the per-version notes
> below and the [Migration Rollback Documentation](../backend/internal/db/migrations/README.md)
> for details on which migrations can be reversed.

---

## Version-Specific Upgrade Notes

> **Coverage.** Detailed notes exist for the upgrade paths listed below: the
> `0.6`–`0.10` series, the major boundaries (`1.x → 2.0`, `2.x → 3.0`,
> `3.x → 4.0`), and the most recent release. The intervening minor releases are
> **not** individually
> documented here — they introduced no breaking changes, which is why they were
> released as minors. For anything not listed, `CHANGELOG.md` is authoritative:
> every release is recorded there, and any breaking change appears under a
> `⚠ BREAKING CHANGES` heading.
>
> Concretely, across every release from `0.10.1` to `3.5.0` there are exactly **two**
> breaking changes, both captured below. `5.0.0` carries two further ones, each with its
> own note: the platform-admin carrier move (#766) and the `devops`/`auditor` role-template
> scope correction (#891). Absence of a note for your specific version
> pair means there was nothing version-specific to do beyond the standard procedure
> above — not that the note is missing.

### Any version → the release carrying migration `000056` — feature-table foreign keys into identity are dropped

**Not breaking, and nothing to do.** Listed here because it repairs an outage some
deployments are living with right now.

**Applies to:** every deployment. It **fixes** any deployment where the `identity` schema
exists but `TFR_IDENTITY_SCHEMA_ENABLED` is unset — including step 1 of the cutover
rollout in `docs/identity-schema.md`, and any install that set
`TFR_IDENTITY_MIGRATIONS_ENABLED=true` without cutting over. On those, the constraints
added by `000038`/`000045` resolved at `identity` while every row carried a `public` id, so
`POST /api/v1/modules` returned `500 {"error":"Failed to claim namespace"}` and the network
mirror's pull-through cache could not populate a provider. Issue #883.

**Migrations:**

- `000056_drop_identity_attribution_fks` — drops 24 foreign keys from the registry's
  feature tables to `users`/`organizations`, by constraint name, in every topology.
  Idempotent, scans no data, drops no index, and holds `ACCESS EXCLUSIVE` only
  momentarily. Identity's own tables keep their foreign keys.

**Behaviour change to be aware of:** deleting a user no longer fails, and no longer nulls
attribution columns, when that user published a module or provider — a deleted user's UUID
can remain in `created_by` / `published_by`. Every read `LEFT JOIN`s it, so the effect is a
blank author. The deployment-critical invariants moved to application code: organization
deletion is still refused with `409` while the organization owns claims or artifacts, and
user deletion now destroys the principal's SCM OAuth tokens explicitly.

**Rollback:** the down migration is a deliberate **no-op**. Re-adding the constraints
validates the whole table and would fail on exactly the deployments the up migration
repaired, leaving the migration version dirty; `NOT VALID` would silently restore the
outage for new writes. The `.down.sql` carries the reasoning and by-hand restore SQL.

### 4.x → 5.0.0 — the `devops` and `auditor` role templates gain `scanning:read`

**Breaking, and it bites one topology only.** Issue #891. Independent of the
platform-admin carrier change below, which is the other breaking change in this
major; both touch role templates and neither depends on the other.

**Applies to:** deployments running the identity-schema cutover
(`TFR_IDENTITY_SCHEMA_ENABLED=true`) with `TFR_SUITE_ROLE_SEED_OWNER` naming this
application. **Default-topology deployments are unaffected** — their role templates have
carried `scanning:read` since migration `000018`, and neither role-template seed runs
there.

#### What was wrong

Registry states its role → scope policy twice: as SQL, in the migrations, and as Go, in
`models.PredefinedRoleTemplates()`. Migration `000018` granted `scanning:read` to `devops`
and `auditor`; the Go list never followed. Both seeds upsert that list with
`scopes = EXCLUDED.scopes`, so on a cutover deployment **every boot removed the scope from
both templates**, in both tables:

- `registry_role_templates` — what this application authorizes against since the phase-3b
  read cutover.
- `role_templates` — what the state manager adopts `devops` and `auditor` from (it defines
  neither name itself), and what a rollback to a pre-3b registry image authorizes against.

It presented as "the scanning pages are empty for our auditors", never as an error, because
it removed authority rather than granting it.

#### What changes on upgrade

On the first boot of this release, principals holding `devops` or `auditor` in an affected
deployment gain `scanning:read`: the per-version scan result, `GET
/api/v1/admin/scanning/stats`, `GET /api/v1/admin/scanning/scans/{id}`, and the
scanner-version endpoints. That is what migration `000018` granted them and what the seed
has been taking back on every restart since.

Scan records are tenant-scoped (issue #783), so this is read access within the organizations
a principal already belongs to, not across the deployment.

The same seed also writes the shared `role_templates`, so the state manager's copies of
`devops` and `auditor` gain the scope too. It confers nothing there — `scanning:read` is not
in that application's scope vocabulary — but it will appear in its role-template listings.

#### If you do not want it

Move the affected members to a role template of your own that omits `scanning:read`. Editing
the **system** template instead does not hold: the seed overwrites system templates by name
on the next boot, which is the whole mechanism this note is about.

#### Migrations, rollback, and the guard

- **Migrations:** none. Migration `000018` already made this change in SQL; this release
  makes the Go list agree with it.
- **Rollback:** deploy the previous image. Its seed removes the scope again on its first
  boot, which is the pre-upgrade behaviour.
- **Guard:** `internal/db/rolepolicy` derives the role → scope policy back out of the
  migration files, and a test diffs it against the Go list in both directions. A migration
  that grants a scope the list omits, and a list that grants a scope no migration granted,
  both turn a PR red.

### 4.x → the release carrying #876 — an mTLS mapping granting `admin` must name a user, or the server will not start

**Breaking for one narrow class of deployment, and it fails at startup rather
than at request time.** It affects you only if `security.mtls.enabled: true`
AND one of your `security.mtls.mappings` lists `admin` among its scopes.

#### What changes

An mTLS subject mapping used to publish its configured scopes verbatim, so
`scopes: ["admin"]` made the certificate holder a platform administrator
directly from the config file — with no `platform_admins` row, no `granted_by`,
no audit entry, and no revocation short of editing configuration and
restarting. Every other credential class had already moved to the carrier in
`5.0.0` (sessions resolved through it, API keys stripped of `admin`), so this
was the last path that answered "who is a platform administrator?" from
somewhere else. The floor could not see it either: it counts database rows, and
this administrator lived in a YAML file.

A mapping carrying `admin` now has to name the user the certificate acts as:

```yaml
security:
  mtls:
    mappings:
      - subject: "CN=break-glass"
        scopes: ["admin"]
        user_id: "3f1c9a02-6d4e-4a1b-9f77-2b8e5c0d1a44"   # NEW, and required for `admin`
```

`user_id` is optional for every other mapping — an ordinary machine credential
needs no user behind it — and nothing changes for those.

Naming a user does not by itself grant anything. The carrier is consulted on
**every request** for that user, exactly as it is for a browser session, so
`admin` holds only while they hold a carrier row and revoking it disarms the
certificate on the next request rather than at the next restart.

A repeated `subject` is now refused too. It previously took the last mapping in
the file silently, which was untidy when a mapping was only a scope list and
unacceptable once one can name a principal.

#### What you will see if you are affected

The server refuses to start, naming the subject:

```
failed to initialize mTLS provider: mtls.mappings: subject "CN=ci" carries the
`admin` scope with no user_id. Platform administration is held in the
platform_admins carrier, which is keyed on a user; set user_id to the UUID of
the user this certificate acts as (and grant them platform administration
through POST /api/v1/admin/platform-admins), or remove `admin` from the mapping
```

#### Before you deploy

1. Search your config for `mtls`. If `enabled` is `false` or absent, stop —
   nothing here applies.
2. If any mapping lists `admin`, decide who that certificate acts as, and
   confirm they hold a carrier row:

   ```bash
   curl -s -H "Authorization: Bearer $TOKEN" \
     "$REGISTRY/api/v1/admin/platform-admins" | jq '.platform_admins[].user_id'
   ```

   Grant it with `POST /api/v1/admin/platform-admins` if not.
3. Add `user_id` to the mapping, then deploy.

Removing `admin` from the mapping entirely is also a complete answer if the
certificate did not need platform-wide reach.

### 4.x → 5.0.0 — platform-admin authority moves to the `platform_admins` carrier

**Breaking, and the action is required BEFORE the deploy on one class of
deployment only.** Read the whole note if you run `TFR_IDENTITY_DATABASE_*`.

#### What changes

Until this release a principal was a platform administrator if they held a row
in `platform_admins` **or** an organization membership whose role template
carried the `admin` scope — the org-less session scope union (#652). From
`5.0.0` the carrier is the only source. Concretely:

- The auth middleware **strips `admin`** from a session whose principal has no
  `platform_admins` row, and adds it to one that does. An API key never carries
  it at all.
- Migration `000054` **removes `admin` from every role template**, replacing it
  with the `org_owner` scope set — everything the template conferred except the
  platform-wide reach — so its holders keep administering their organizations
  and stop administering the platform.
- **Assigning an admin-bearing role template as an organization membership role
  is refused** (`403`), for every caller including a platform administrator.
  This is issue #766's original recommendation.
- **`POST`/`PUT /api/v1/admin/role-templates` refuse `admin` in `scopes`**
  (`400`), so the removal cannot be undone through the API.
- **`POST /api/v1/setup/admin` writes only the carrier.** No organization
  membership; the response drops `organization` and `role` and reports
  `platform_admin: true`. A failed carrier grant is now a `500` rather than a
  flagged `200`.

#### What you have to do

**Nothing, on a default deployment.** Migration `000054` re-runs the carrier
backfill before it removes anything, so anyone holding the `admin` template —
including administrators granted it after the `000051`/`000053` backfills ran —
gains a `platform_admins` row in the same transaction. It then asserts an
administrator survived and **refuses to apply**, rolling everything back, if one
did not.

**If identity lives in a separate database (`TFR_IDENTITY_DATABASE_*`):** the
migration runs on the registry connection and cannot see your users,
memberships or role templates, so it cannot back-fill them and cannot detect
that it has not. Populate `platform_admins` **before** deploying `5.0.0` — the
SQL, which must carry its own `audit_outbox` intent, is in
[The administrator floor](administrator-floor.md#remediation). Verify with

```sql
SELECT pa.user_id FROM platform_admins pa;   -- registry connection
```

and confirm each id exists in your identity database's `users` table.

#### Verifying after the deploy

```sql
SELECT * FROM admin_floor_violations;                    -- expect zero rows
SELECT name, scopes FROM role_templates WHERE scopes @> '["admin"]'::jsonb;  -- expect zero rows
```

`GET /api/v1/admin/platform-admins` lists the administrators; `/api/v1/auth/me`
shows the effective scopes of the caller.

#### Rolling back

Roll the **binary** back first, then `migrate ... goto 53`. The down migration
restores the seeded `admin` template's `["admin"]` scope and migration
`000053`'s `admin_floor_violations` definition. It does **not** restore custom
templates that carried `admin` (they were not recorded) and does **not** delete
backfilled carrier grants — deleting them would strip real authority from real
people. Restoring the template while `5.0.0` is still running achieves nothing:
that binary strips `admin` from the session union regardless.

### 4.0.x → 4.1.0 — `terraform-suite-identity` v0.25.0

**Action required before the deploy, on one setting only.** Every other change in
this bump is internal (renamed accessors, a mandatory tenant parameter, a mailer
field) and is covered by the build.

#### The egress allow-list now governs authentication

The shared identity module routes **all** of its outbound traffic through the
deployment's SSRF egress guard as of v0.25.0: the OIDC discovery document, the
JWKS signing keys that decide which ID tokens are valid, the authorization-code
token exchange that carries the `client_secret`, and the suite sibling-discovery
poll. That guard's default policy denies loopback, RFC 1918, link-local
(including `169.254.169.254`), CGNAT and IPv6 ULA.

`security.egress.allowlist` (`TFR_SECURITY_EGRESS_ALLOWLIST`) already existed and
already **widens** the deny-list. What changed is what it covers.

*Action:* if your identity provider or your suite sibling lives on an internal
address, add its **hostname** to the list **before** deploying. A denied IdP is
not a failed login — the process refuses to construct the OIDC provider at
startup, naming the endpoint. A public IdP (Entra, Okta cloud, Google, Auth0)
needs nothing. See
[OIDC_CONFIGURATION.md](OIDC_CONFIGURATION.md#self-hosted-idp-the-egress-allow-list-is-required)
and the [Egress Allow-List](configuration.md#egress-allow-list-ssrf-guard)
reference.

```yaml
security:
  egress:
    allowlist:
      - keycloak.corp.internal
```

`AllowInsecureIssuer` / `DEV_MODE` does **not** cover it: the scheme rule and the
destination rule are separate on purpose.

#### Identity schema migration `000007` runs at startup

`identity.RunMigrations` runs on the startup path, so this DDL lands on a live
database during the deploy. It drops the foreign keys on `audit_logs.user_id` and
`audit_logs.organization_id` (those columns are a historical record of who acted,
not live references — every `ON DELETE` action is wrong for one), changes
`api_keys.user_id` to `ON DELETE CASCADE` so a credential cannot outlive its
principal, and adds and backfills `audit_logs.actor_email` so attribution
survives the `users` row. **No read semantics change.**

*Action (inventory, not DDL):* the migration cannot repair history. Run both
queries around the deploy and deal with anything unexpected:

```sql
-- Audit rows with no owning organization. Anything not written unowned by design
-- is a formerly-owned row a past organization delete re-homed into the platform
-- bucket.
SELECT date_trunc('day', created_at) AS day, action, count(*)
  FROM identity.audit_logs
 WHERE organization_id IS NULL
 GROUP BY 1, 2 ORDER BY 1 DESC;

-- API keys with no owning user. Anything not a deliberate organization service
-- credential is a deleted user's personal key that is still authenticating.
SELECT id, organization_id, name, key_prefix, created_at, last_used_at
  FROM identity.api_keys
 WHERE user_id IS NULL ORDER BY created_at;
```

`000007`'s down migration is best-effort and lossy (it must null the retained
rows to re-create the foreign keys, and it drops `actor_email`). Prefer rolling
forward.

#### Behaviour changes with no compile error

- **`Bearer` is matched case-insensitively** on the API-key header, per RFC 7235
  §2.1 / RFC 6750 §2.1. This only ever accepts more — `bearer <key>` used to be
  rejected. The credential itself is still case-sensitive. No action.
- **In-flight OIDC logins at the moment of deploy fail and must be retried.** The
  callback now requires both the nonce and the PKCE verifier for the login, and
  refuses before any network call if either is missing. A state entry written by
  the previous version carries both, so only logins mid-flight across the restart
  are affected.
- **An ID token with no `nonce` claim is now rejected.** Every authorization
  request this registry builds carries a nonce, so a response without one means
  the provider dropped the binding.
- **The audit export NDJSON gains an `actor_email` field**, between `created_at`
  and the existing `user_email`. `actor_email` is the address as it stood when the
  entry was written and survives the actor's deletion; `user_email` is the
  actor's current address and goes null once the user is gone. Downstream
  consumers that pin a field set need updating.

### 0.6.x → 0.7.0

**Breaking Changes:**

- Minimum PostgreSQL version raised to 14 (was 12)
- `TFR_AUTH_SECRET` environment variable renamed to `ENCRYPTION_KEY`
- API key format changed from UUID to prefixed format (`tfr_...`)

**Migrations:**

- `000020_search_indexes` — adds full-text search indexes (may take several minutes on large databases)
- `000021_setup_scanning` — adds scanning configuration tables
- `000022_storage_migration` — adds storage migration state tracking
- `000023_audit_retention` — adds audit log retention configuration

**Pre-flight:**

```bash
./terraform-registry upgrade preflight --config config.yaml
```

**Rollback:** Migrations 000020–000023 are all reversible. Run `migrate down` to version 19 before deploying 0.6.x.

### 0.7.x → 0.8.0

**Breaking Changes:**

- OIDC configuration moved from flat fields to nested structure in `config.yaml`
- Deprecated `auth.oidc_issuer_url` — use `auth.oidc.issuer_url` instead
- Redis is now required for multi-pod deployments (rate limiting + session state)

**Migrations:**

- `000024_module_deprecation` — adds deprecation fields to module_versions
- `000025_org_idp_binding` — adds per-org IdP binding support

**New Features Requiring Configuration:**

- SAML 2.0: configure in `auth.saml` section
- LDAP: configure in `auth.ldap` section
- SCIM: enable in `auth.scim.enabled: true`

**Pre-flight:**

```bash
./terraform-registry upgrade preflight --config config.yaml
```

**Rollback:** Migrations 000024–000025 are reversible. Note: SAML/LDAP user records created during 0.8.0 operation will be orphaned on rollback.

### 0.8.x → 0.9.0

**Breaking Changes:**

- None expected

**Migrations:**

- `000026_org_quotas` — adds per-org quota tables

> Note: Legal hold for audit logs is implemented in application code
> (`backend/internal/audit/legal_hold.go`), not via a dedicated migration.

**Pre-flight:**

```bash
./terraform-registry upgrade preflight --config config.yaml
```

### 0.9.x → 0.10.0

**Breaking Changes:**

- Audit log cleanup job now respects legal holds. Ensure any active investigations have holds in place before upgrading.

**New Features:**

- GDPR data-subject export/erasure endpoints
- OCSF audit log export format
- Air-gap installation support (`make airgap-bundle`)

**Pre-flight:**

```bash
./terraform-registry upgrade preflight --config config.yaml
```

### 0.18.x → 1.0.0

**No breaking changes.** 1.0.0 was a version marker (released via `Release-As: 1.0.0`
in #316) signalling API stability, not a change in behaviour. Upgrade using the
standard procedure.

### 1.x → 2.0.0

**Breaking Changes:**

- Feature-table foreign keys are repointed from `public.{users,organizations}` to
  `identity.{users,organizations}` (#451). This **drops and recreates 22 constraints**.

**Applies to:** deployments that have completed the identity-schema cutover. On
non-cutover deployments the migration is a **no-op**.

**Migrations:**

- `000038_feature_fk_to_identity` — the FK repoint described above.

**Pre-flight:** run the preflight check, and on a large database expect the constraint
recreation to hold locks briefly — schedule accordingly rather than during peak write
traffic.

**Rollback:** `000038` is reversible.

> **Superseded.** Migration `000056` drops these 24 constraints outright (issue #883):
> a target chosen at migration time from schema *existence* cannot be right in both
> topologies, and under `TFR_IDENTITY_DATABASE_*` it cannot be expressed at all. If you
> are upgrading past `000056`, this note is history — see the note at the top of this
> section list.

### 2.x → 3.0.0

**Breaking Changes:**

- Adopts `terraform-suite-identity` v0.17.0 (#614), which brings three
  behaviour changes worth checking before deploying:
  - **`email_verified` is now enforced** on IdP logins. Users whose IdP does not
    assert `email_verified` (or asserts `false`) will be refused. Verify your IdP
    emits this claim before upgrading, or you can lock out your own users.
  - **`ClientSecretCiphertext`** changes how SSO client secrets are stored.
  - **`ScopeAdmin` guard** tightens which callers may grant the admin scope.

**Also in 3.0.0** (not breaking, but security-relevant): OIDC/Azure AD logins are now
bound with a nonce and PKCE (#612), and `/organizations/:id*` routes enforce
per-organization membership (#611) — if you have automation using a token that held
`organizations:write` via one organization to act on another, it will now receive 403.

**Migrations:** none specific to the identity adoption.

**Rollback:** code-only; rolling back the binary restores the previous behaviour.

### 3.5.x → 3.6.0

The exact version is whatever release first contains PRs #712 and #724 — confirm
against `CHANGELOG.md`. Both entries below are **behavior changes that activate on
upgrade with no configuration change**, so review them before deploying.

**Audit configuration becomes active (#659, PR #712):**

`audit.log_read_operations`, `audit.log_failed_requests` and `audit.shippers` were
previously parsed and validated but **never actually used** — the audit middleware
was wired with hardcoded `nil`s. That was the bug; those settings are now honored.

If you already have any of them set, upgrading changes runtime behavior immediately:

- `log_read_operations: true` — GET/read-path audit rows begin being written. On a
  busy registry this can change audit table growth rate sharply; check retention and
  disk headroom first.
- `log_failed_requests: true` — failed-request rows begin being written.
- `shippers: [...]` — a configured external shipper **starts receiving traffic**. The
  registry begins making outbound calls to an endpoint that has never received them,
  which may be unexpected volume for a webhook/SIEM target.

**Recommended:** review your `audit.*` block before upgrading and comment out anything
you did not intend to be live. To keep the previous effective behavior, unset these keys.

**Audit log reads are scoped to the caller's organizations (#719, PR #724):**

`GET /api/v1/admin/audit-logs` previously returned **every organization's** audit trail
to any holder of `audit:read`. Because `audit:read` is granted per-organization by the
`auditor` role template but arrives in the session token as part of a flat, org-less
scope union, that crossed the tenant boundary.

After upgrade:

- Platform admins (the `admin` wildcard scope) still see all organizations.
- A non-admin auditor sees only the organizations they belong to.
- A caller belonging to **multiple** organizations had to pass `organization_id`
  explicitly, or the request returned `400`.

> **Superseded — read the 3.6.x → 3.7.0 section below before relying on this.**
> The `400` for multi-organization callers was a workaround for a shared audit
> filter that could carry only one organization at a time. It is **gone**: such a
> caller is now scoped to every organization they hold `audit:read` in, in a
> single request. The 3.6.0 fix also covered only the **list** endpoint; the
> by-id read and the export stream kept returning every tenant's rows until
> 3.7.0.

**Action required** if you have tooling, dashboards, or exports that read this endpoint
with a non-admin token and expect estate-wide results: either grant that principal the
`admin` scope deliberately, or update the caller to iterate per organization.

**Credential invalidation on authority reduction (#732, #736):**

Reducing a principal's authority now invalidates the credentials that carry a
*snapshot* of it. Previously only JWT sessions were swept, and only at some events;
API keys were never swept at all, because an API key's scopes **and** its owning
`organization_id` are frozen on the `api_keys` row at creation and are read straight
back out by the auth middleware. An offboarded member kept a working
`modules:write` / `providers:write` credential into the organization's namespaces
indefinitely.

These sweeps **activate on upgrade with no configuration change**, and they DELETE
API keys. An API key's secret is displayed once at creation and cannot be recovered:
a deleted key must be re-issued and re-distributed to whatever consumes it (CI
pipelines, Terraform `credentials` blocks, automation). Review the list below against
your own automation before upgrading.

Events that now delete a principal's organization-bound API keys:

- Removal from an organization (`DELETE /api/v1/organizations/:id/members/:user_id`).
- A member's role-template reassignment (`PUT .../members/:user_id`) — **only** when
  the new template grants strictly less; a promotion deletes nothing.
- A role template's scopes being **narrowed**, or the template being deleted. Adding
  scopes, or merely reordering the list, sweeps nothing.
- IdP group-mapping deprovisioning at OIDC/SAML/LDAP login.
- An IdP group change that maps a user to a **lower** role at OIDC/SAML/LDAP login —
  same rule as the administrative reassignment above: a promotion deletes nothing, a
  demotion deletes exactly the keys that now over-ask. Note that this fires on
  *login*, so it applies to users your IdP re-scopes without anyone touching the
  registry.
- User deletion (`DELETE /api/v1/users/:id`) and GDPR erasure
  (`POST /api/v1/admin/users/:id/erase`).

Only keys asking for **more than the principal retains** are deleted; a key entirely
within the remaining authority survives. Scope comparison honors the `admin` wildcard
and the read/write implications, and is order-insensitive.

**SCIM deactivation now destroys credentials.** `DELETE /scim/v2/Users/{id}`, and a
PUT or PATCH setting `active: false`, now revoke the user's sessions and delete
**every** API key they hold in **every** organization — not just their memberships.
If your IdP deactivates and later reactivates users (a common lifecycle for
contractors or leave-of-absence), reactivation restores memberships but **cannot**
restore API keys; they must be re-issued.

> **SCIM PUT semantics changed with this.** `active` is now optional: a PUT that
> **omits** it leaves the user's authority untouched, where previously an omitted
> `active` was indistinguishable from `active: false` and silently deprovisioned the
> user. If you have an IdP or script relying on a partial PUT to deactivate users,
> it must now send `"active": false` explicitly.

**Sessions the IdP login path does not revoke.** At OIDC/SAML/LDAP login the API-key
family is swept but the JWT revoke-all watermark is deliberately **not** moved: the
reconciliation runs microseconds before the same request mints the user's new session
token, whose `iat` is floored to the second, so moving the watermark would revoke the
token being issued and the user could never log in. The token minted by that login is
derived after the change and already carries the reduced authority. The user's
**other** live sessions, from earlier logins, are **not** covered — they keep the
pre-reduction scopes until their own TTL expires. If you need an IdP-driven reduction
to retire every existing session immediately, perform the equivalent administrative
action (member removal, role reassignment, or a role-template edit), which does move
the watermark.

Responses from these endpoints may carry `revocation_incomplete: true`. The authority
change itself succeeded, but part of the credential sweep did not — treat it as an
open incident and re-run the action. This is now reported by
`PUT /api/v1/admin/role-templates/{id}` and `PUT /api/v1/organizations/{id}/members/{user_id}`
as well, which previously answered a clean `200` regardless. On those two endpoints the
flag is an **additional field on the existing success body**, not a new envelope.

**Also in this change: organization-bound API keys are re-verified at the point their
binding is established, not only on namespace mutations.**

`AuthMiddleware` and `OptionalAuthMiddleware` now look up the key owner's current
membership on every API-key-authenticated request, and:

- **reject the key (`401`)** when its owner is no longer a member of the organization
  it is bound to;
- **narrow the request's scopes** to the intersection of the key's frozen scopes and
  what the owner's current role template grants (by scope semantics, so an `admin`
  role template retains everything);
- **reject the key (`401`)** when it has no owning user — see the migration note below.

This costs **one additional indexed query per API-key request**, on a path that already
performs a key-prefix lookup, a bcrypt comparison, and a user load. Previously the
re-verification existed only inside the namespace authorizer, so any route not wrapped
by it — the admin surface, `/apikeys`, SCIM — consumed the frozen `organization_id` and
scope list with no check at all.

Long-lived keys belonging to users who have since been offboarded or downgraded will
begin failing on upgrade. That is the intended correction, but **audit for it before
deploying** if you have automation running under a personal key.

**Migration `000050_quarantine_orphaned_api_keys` — read this if you have ever deleted
a user.**

In the shared identity schema, `identity.api_keys.user_id` is
`REFERENCES identity.users(id) ON DELETE SET NULL`. Deleting a principal therefore
**detached** their API keys instead of destroying them, and the detached row kept its
`organization_id` and its frozen scopes. Until this release the authorizer read a
userless organization-bound key as an "organization service credential" and skipped the
membership check entirely — so a deleted user's key kept publishing into that
organization's namespaces.

The code changes close this going forward (every user-deletion site sweeps first) and
fail closed at the point of use. Neither helps rows that were **already** detached, so
this migration retires them: every `api_keys` row with `user_id IS NULL` and no earlier
expiry has `expires_at` set to `NOW()`. It runs against `identity.api_keys` when the
identity schema exists and against `public.api_keys` always, logs a `WARNING` with the
row count when it changes anything, and is idempotent.

Retiring **all** of them is safe because the registry has no way to mint one: API keys
are created only by `POST /api/v1/apikeys` (owner taken from the authenticated caller)
and by key rotation (which copies the previous owner). A userless row is either a
detached personal key or a hand-written `INSERT`.

- **If you deliberately created a userless key by direct SQL**, it is now expired *and*
  refused by the point-of-use guard. Re-issue it through the API so it is bound to a
  real principal; a service account with its own membership is the supported shape.
- **The down migration is a no-op.** `expires_at = NOW()` is indistinguishable from an
  expiry an operator set on purpose, so blanket-clearing it would re-arm exactly the
  credentials the migration retired. Individual rows can be restored by hand
  (`UPDATE identity.api_keys SET expires_at = NULL WHERE id = '<uuid>'`), though the
  point-of-use guard still refuses userless keys until the binary is rolled back.
- **Non-default `TFR_IDENTITY_SCHEMA_NAME`:** the migration hardcodes the `identity.`
  schema literal, exactly like migrations `000038` and `000045`. Edit the file, or run
  the statement by hand, if you renamed the schema.

To see what will be quarantined before you upgrade:

```sql
SELECT id, organization_id, name, key_prefix, scopes, created_at, last_used_at
  FROM identity.api_keys
 WHERE user_id IS NULL AND (expires_at IS NULL OR expires_at > NOW());
```

**Migrations:** `000050_quarantine_orphaned_api_keys` (data-only; irreversible down).
No other change in this section requires one.

**Rollback:** the code changes are all code-only; rolling back the binary restores the
previous behavior. Note that API keys deleted by a sweep are **not** restored by a
rollback, and neither are the keys quarantined by migration `000050`.

### 3.5.x → 4.0.0

This section was staged before the batch had a version and said "whatever release
first contains the tenant-scoping batch for issue #719". It shipped as **4.0.0**.

Every entry below is a **behavior change that activates on upgrade with no
configuration change**. The common thread: routes that read, list, create or
delete rows of an organization-owned table now bind the row's owning
organization to one the caller is a verified member of. Previously several did
not, so a principal scoped to one organization could see or act on another's
rows. Item 9 is the same principle from the other side: a table with **no**
organization column is a platform-wide resource, so changing it requires
platform-wide authority rather than an organization-grantable scope. Items 10 and
11 close the two remaining ways the binding could be bypassed at the source —
creating a row in an organization other than the one the request was authorized
against, and presenting a credential whose ceiling was read from its owner
instead of from itself.

> **REQUIRES A SHARED-MODULE BUMP.** The audit-log half of this work lives in
> `terraform-suite-identity` (`identity/store`), where the three audit read
> accessors gained a mandatory `AuditScope` parameter. This release does not
> build against `terraform-suite-identity v0.20.3`; the module must be published
> and the dependency bumped first. See "Shared module" below.

**Who is affected in general:** any non-admin automation — CI tokens, dashboards,
exporters, provisioning scripts — that relied on a route returning estate-wide
results. Platform admins (the `admin` wildcard scope) are unaffected everywhere
below; that scope deliberately crosses organization boundaries.

**1. Membership is no longer sufficient — the role template must grant the scope.**

The biggest single behavior change, and the one most likely to surprise. A
request is now scoped to the organizations where the caller's **role template**
grants the scope the route requires, not merely to the organizations they belong
to. A viewer in an organization can no longer list what an operator there may
manage. This aligns the list/create axes with the `/:id` axes of the same
families, which already required the scope in the target organization.

*Action:* if automation loses access to a route it previously reached, check the
principal's role template in that organization — it is likely missing the
route's scope (`mirrors:read`, `mirrors:manage`, `scm:manage`,
`organizations:read`, `audit:read`).

**2. Organization-bound API keys now work on these routes — and are confined to
their organization.**

An API key carries an organization binding fixed at creation. That binding is now
authoritative for the key. Two consequences:

- A **userless** organization service key (`api_keys.user_id IS NULL`, the normal
  shape for CI) previously had no memberships to resolve and silently received
  empty lists and `403`s **on its own organization**. It now works.
- A key issued to a user who belongs to other organizations is confined to the
  organization the key names, regardless of the owner's other memberships.

**3. Creating a row without naming an organization no longer lands in the default
organization.**

`POST /api/v1/admin/mirrors` and `POST /api/v1/scm-providers` used to fall back to
the default organization when `organization_id` was omitted, with no membership
check — so a non-member wrote into the default organization by leaving the field
out. Now:

- A **platform admin** keeps the default-organization fallback.
- A caller with the required scope in exactly **one** organization gets that one.
- A caller with the scope in **more than one** organization receives `400` and
  must name `organization_id` explicitly.
- A caller with the scope in **no** organization receives `403`.

*Action:* multi-organization automation that creates mirrors or SCM providers
must start sending `organization_id`.

**4. `{"organization_id": ""}` on `PUT /api/v1/admin/mirrors/:id` is now
platform-admin only.**

An empty string cleared the column, and a mirror configuration with a NULL
organization is resolved back to the **default organization** at sync time — so
this re-parented the row into the default organization without naming it. Only
platform admins may clear the field; everyone else receives `403`.

**5. Rows with no owning organization are visible to platform admins only, on
every route.**

One rule now applies everywhere: a NULL `organization_id` means "no tenant has
been asserted", not "belongs to everyone". Concretely:

- `GET /api/v1/admin/policies` no longer returns global (NULL-organization)
  mirror policies to non-admins. It previously did, while `GET
  /api/v1/admin/policies/:id` refused the same rows to the same caller — the two
  axes disagreed, and they now agree on the closed answer.
- `GET /api/v1/admin/version-approvals` no longer shows terraform-binary or
  scanner-binary versions to non-admins. Those hang off platform-level configs
  with no organization at all. Provider-mirror versions are unaffected and remain
  visible to members of the owning organization.
- `POST /api/v1/admin/policies` with `organization_id` omitted creates a global
  policy and is now platform-admin only; other callers receive `403` and must
  name an organization.

*Action:* if a non-admin dashboard relied on seeing global policies or terraform
binary approvals, grant `admin` deliberately or move that view behind an
admin-scoped credential.

**6. Approval requests take their organization from the mirror configuration, not
from the requester.**

`POST /api/v1/admin/approvals` previously stamped the new row with the
**requester's** ambient organization. It now resolves the owning organization of
the `mirror_config_id` in the body and requires `mirrors:manage` there. Filing a
request against another organization's mirror configuration returns `403`.

Note the response body change: `organization_id` on the created approval is now
the configuration's owner. Automation that asserted it matched the caller's
organization must be updated.

**7. Newly scoped read endpoints.**

These previously returned platform-wide results to any holder of the route's
scope and are now scoped to the caller's organizations:

| Endpoint | Note |
| --- | --- |
| `GET /api/v1/admin/audit-logs/:id` | out-of-scope entries report `404`, not `403` |
| `GET /api/v1/admin/audit-logs/export` | the predicate is applied in SQL; the stream never carries other tenants' rows |
| `GET /api/v1/admin/version-approvals` | plus `/pending-count`, which now counts only in-scope versions |
| `GET /api/v1/admin/version-approvals/:id/events` | out-of-scope versions report `404` |
| `GET /api/v1/admin/namespaces` | and `/:namespace`, which reports `404` for out-of-scope namespaces |
| `GET /api/v1/organizations` | non-admins see only their own organizations; `total` changes accordingly |
| `GET /api/v1/organizations/search` | searches within the caller's organizations only |
| `GET /api/v1/admin/modules/:id` | `403` for a module owned by another organization; previously any holder of `modules:read` could fetch the whole row, `organization_id` included, by UUID |
| `GET /api/v1/admin/providers/:id` | `403` for a provider owned by another organization; same shape as the module route above |

The two by-id artifact reads are the READ siblings of `PUT /api/v1/admin/modules/:id`
and `PUT /api/v1/admin/providers/:id`, which have carried namespace-organization
authorization since #555. They now use the same authorizer, so ownership is
resolved identically on both axes: the namespace claim wins, falling back to the
artifact row's own organization. The public protocol reads
(`GET /api/v1/modules/:namespace/:name/:system` and friends) are unchanged —
they resolve against the default organization and were never cross-tenant.

The dashboard's pending-approval badge will drop for non-admin users — it was
previously counting other tenants' pending versions.

**8. SCIM deprovisioning is confined to the provisioner's organizations.**

`DELETE /scim/v2/Users/:id`, `PUT` with `active:false`, and both `PATCH replace`
forms all removed the target's memberships in **every** organization. They now
remove memberships only where the caller holds `scim:provision`; skipped
organizations are logged at INFO with the user and organization id.

*Action, important:* if your IdP integration authenticates with a non-admin
credential, a leaver will now be deprovisioned only from the organizations that
credential covers — a **partial** deprovision that previously appeared total.
Give the IdP connector an `admin`-scoped credential to preserve estate-wide
deprovisioning, which is the intended configuration for a SCIM connector.

**9. Changing the Terraform binary mirror now requires the `admin` scope, not
`mirrors:manage`.**

`terraform_mirror_configs` has no `organization_id` column: one configuration is
the Terraform/OpenTofu binary supply chain for **every** tenant, and the versions,
platforms and sync-history rows hanging off it inherit that. `mirrors:manage`
does not carry platform-wide authority — the seeded `devops` and `org_owner` role
templates grant it through membership in a single organization — so the following
routes moved to the platform-wide `admin` scope (issue #734), applying to
org-less rows the same rule item 5 above already states:

| Route | Previously | Now |
| --- | --- | --- |
| `POST /api/v1/admin/terraform-mirrors` | `mirrors:manage` | `admin` |
| `PUT /api/v1/admin/terraform-mirrors/:id` | `mirrors:manage` | `admin` |
| `DELETE /api/v1/admin/terraform-mirrors/:id` | `mirrors:manage` | `admin` |
| `POST /api/v1/admin/terraform-mirrors/:id/sync` | `mirrors:manage` | `admin` |
| `DELETE /api/v1/admin/terraform-mirrors/:id/versions/:version` | `mirrors:manage` | `admin` |
| `POST /api/v1/admin/terraform-mirrors/:id/versions/:version/deprecate` | `mirrors:manage` | `admin` |
| `DELETE /api/v1/admin/terraform-mirrors/:id/versions/:version/deprecate` | `mirrors:manage` | `admin` |

This covers the verification settings specifically: `gpg_verify`,
`verify_github_attestation` and `requires_approval` are all set through
`PUT /:id`, and weakening any of them changes what every tenant's Terraform CLI
accepts. Repointing `upstream_url` is in the same request body.

The **read** routes are unchanged and stay on `mirrors:read`: the whole family's
`GET`s (`/releases-gpg-keys`, list/get config, status, versions, platforms and
history). These tables carry no tenant data and no credentials, and the binary
mirror is a shared service whose catalogue and health tenant operators
legitimately need to see.

*Action:* an operator who managed the binary mirror with a `devops` or
`org_owner` role loses the ability to create, edit, sync, delete or deprecate it
and receives `403`; the admin UI's Terraform Mirrors page stays viewable but its
actions fail for them. Move that work to an `admin`-scoped credential. Any CI
job that calls `POST /:id/sync` on a `mirrors:manage` token needs its token
re-issued with `admin`. Nothing about the mirror's runtime behaviour changes —
already-synced binaries keep serving from `/terraform/binaries`, and the
scheduled sync job is unaffected.

**10. Creating a namespaced row binds it to the organization the namespace guard
authorized — a body naming another one is now `403`, admins included.**

Four create paths decided the new row's owning organization independently of the
route guard that had just authorized the request: they took it from the request
body or fell back to `GetDefaultOrganization`, neither of which was the value the
guard verified. The organization a request was *authorized against* and the
organization the row *landed in* were two independent values (issue #778).

| Route | Owning organization was | Now |
| --- | --- | --- |
| `POST /api/v1/admin/providers` | body / default org | the namespace's authorized owner |
| `POST /api/v1/admin/modules/create` | body / default org | the namespace's authorized owner |
| `POST /api/v1/modules` (upload) | body / default org | the namespace's authorized owner |
| `POST /api/v1/providers` (upload) | body / default org | the namespace's authorized owner |

This is distinct from item 3, which covers `/admin/mirrors` and `/scm-providers`
and resolves the organization from the caller's memberships. Here it comes from
the **namespace**, and it applies to platform administrators too: naming an
organization other than the namespace's owner is refused rather than silently
overridden.

Two side effects are corrections, not regressions. The existence check ahead of
each insert ran against the same wrong organization, and `providers`/`modules`
are unique per organization — so a genuine collision in the authorized
organization was invisible: provider record create returned `500` from the unique
constraint where it should have returned `409`, and provider upload created a
**second** row instead of adding a version to the first.

*Action:* automation that publishes to a namespace it does not own, or that sends
an `organization_id` in the body that differs from the namespace's owner, now
receives `403`. Drop the field and let the namespace decide. Check for duplicate
provider rows created by the pre-fix upload path before upgrading:

```sql
SELECT namespace, name, count(*), array_agg(organization_id)
  FROM providers GROUP BY namespace, name HAVING count(*) > 1;
```

**11. Every authority ceiling is bounded by the presenting credential — API keys
can no longer widen themselves, cross organizations, or refresh.**

An API key's creation ceiling was computed from the **owning user's** role, never
from the credential presenting the request. `/apikeys` carries no `RequireScope`
(self-service key management is deliberately open to any authenticated caller)
and CSRF is exempt for API-key callers, so a key deliberately narrowed to
`modules:read` could `POST {"scopes":["admin"]}` and receive a platform-wide key
whenever its owner held the admin role. Narrowing a machine credential provided
no containment at all (issue #733).

The ceiling is now intersected with the scopes the presenting credential itself
carries, everywhere a user record decides authority on a path an API key can
reach:

| Path | Behaviour change for an API-key caller |
| --- | --- |
| `POST /api/v1/apikeys` | cannot create a key holding a scope the caller does not hold |
| `PUT /api/v1/apikeys/:id` | cannot widen a key beyond the caller's own scopes |
| `POST /api/v1/apikeys/:id/rotate` | `403` if the stored scopes exceed the new ceiling |
| role-template assignment | cannot assign a template beyond the caller's own scopes |
| `POST /api/v1/auth/refresh` | refused for API-key callers entirely |
| any org-scoped admin route | a key bound to organization A can no longer administer B |

**Interactive sessions are unaffected** — a JWT session *is* the user's full
authority by construction, so the intersection is a no-op for the UI. Keys that
already match their owner's authority are likewise unaffected.

*Action:* two cases need attention before upgrading.

- **Rotation is the sharp edge.** Rotation previously copied the old key's scopes
  and authorized on ownership alone, making it a scope-laundering primitive. A
  key whose stored scopes exceed what its owner's current role grants now returns
  `403` on rotate. Reduce the key's scopes first, then rotate — or re-issue it.
- **Any CI job calling `/auth/refresh` with an API key breaks.** That exchange
  minted a session token from the owner's cross-org scope union and dropped the
  key's organization binding, so a key was exchangeable for an unbounded JWT.
  There is no ceiling to intersect on a session token, so the endpoint is now
  restricted to the credential family it refreshes. API keys are long-lived and
  do not need refreshing; rotate them at `/apikeys/:id/rotate` instead.

Find keys that will fail rotation:

```sql
SELECT k.id, k.name, k.organization_id, k.key_prefix, k.scopes
  FROM identity.api_keys k WHERE k.revoked_at IS NULL;
```

then compare each row's `scopes` against what its owner's current role template
grants. Anything broader is a key that was widened under the old rule.

**Shared module:** this release requires a `terraform-suite-identity` version
newer than `v0.20.3`. `AuditRepository.ListAuditLogs`, `.GetAuditLog` and
`.StreamAuditLogs` take a mandatory `AuditScope`; its zero value selects nothing,
so a caller that forgets tenancy gets no rows rather than every tenant's.

#### Required merge order

This is a **breaking change to a shared module consumed by two backends**, so the
three repositories cannot be merged independently. The signature change is not
additive: the accessors gained a required parameter, so any consumer still on
`v0.20.3` fails to compile the moment it is bumped, and any consumer left
un-bumped keeps the leak. Merge in this order:

1. **`terraform-suite-identity`** — merge and **publish** the `AuditScope` work as
   a new tagged release (a minor bump: the three accessor signatures are
   source-breaking for every caller).
2. **`terraform-registry-backend`** (this repository) — bump `backend/go.mod` off
   `terraform-suite-identity v0.20.3` to the tag from step 1, then merge. **The
   branch as staged deliberately still pins `v0.20.3` and therefore does not
   build**: the pin is the forcing function that keeps step 1 from being skipped.
   Do not paper over it with a `replace` directive — a `replace` makes the build
   green locally while the published artifact still embeds `v0.20.3` and contains
   no `AuditScope` symbol at all.
3. **`terraform-state-manager-backend`** — bump to the same tag and update its
   three call sites (`internal/api/admin.go`, `internal/api/admin_write.go`,
   `internal/api/admin_audit_export.go`). Tracked as
   `sethbacon/terraform-state-manager-backend#331`.

Steps 2 and 3 may land in either order once step 1 is published, but **both must
land in the same release round**: a consumer left on `v0.20.3` still returns every
tenant's audit rows.

TSM should pass **`AuditScopeOrganizationsAndUnowned(...)`**, not
`AuditScopeOrganizations(...)`. That is not a preference — it is the exact
semantics of the in-memory filter TSM already applies today
(`internal/api/admin.go`, `auditLogsInAdminOrgs`), which passes through rows whose
`organization_id` is absent and otherwise requires the caller to hold `admin` in
the owning organization. TSM writes such rows deliberately
(`internal/api/audit_ingest.go` nils the column for federated ingest). Choosing
`AuditScopeOrganizations` would silently *hide* platform events that organization
admins are the intended reviewers of; choosing `AuditScopeAllOrganizations` would
restore the leak. The push-down is exact, not approximate: `identity.audit_logs.organization_id`
is a nullable `UUID`, so it is either NULL or a real organization — the empty-string
case the in-memory filter also tolerates is unrepresentable in the column.

**Migrations:** none.

**Rollback:** code-only; rolling back the binary restores the previous behavior.
Rolling back also requires reverting the shared-module bump.

---

## Upgrade Preflight CLI Reference

```text
Usage: terraform-registry upgrade preflight [flags]

Flags:
  --config string     Path to config.yaml (overrides CONFIG_PATH; falls back to environment variables)
  --verbose           Show the detail message for every check, not just warnings/failures

Examples:
  terraform-registry upgrade preflight
  terraform-registry upgrade preflight --config config.yaml --verbose
```

The current/target versions and the pending-migration set are derived
automatically: the current schema version is read from `schema_migrations`, and
the target version is the binary's own build version. The command validates
state and reports readiness; it never applies migrations (those run on the next
`serve` startup), so there is no separate dry-run mode.

### Preflight Check Output

```text
Terraform Registry — Upgrade Preflight
=======================================
Binary version:   1.0.0
Build date:       2026-04-29T00:00:00Z

  ✓ Configuration
  ✓ Database: Connected (PostgreSQL 16.2 ...)
  ✓ PostgreSQL version: Version 16.x
  ✓ Schema: Current schema version: 40
  ✓ Encryption key: Present
  ✓ Storage backend: Type: s3
  ⚠ Redis: Not configured — required for multi-pod deployments

Result: READY TO UPGRADE (with warnings)
```

---

## Skip-Version Upgrades

Sequential upgrades (0.7 → 0.8 → 0.9) are recommended. Skip-version upgrades
(0.7 → 0.9) are supported because migrations are applied incrementally, but:

- Read **all** intermediate version notes for breaking changes
- Run preflight with `--from` and `--to` to validate the full migration chain
- Test in a staging environment first

---

## References

- [Disaster Recovery](disaster-recovery.md) — backup and restore procedures
- [Migration Rollback Documentation](../backend/internal/db/migrations/README.md)
- [Configuration Reference](configuration.md)
- [Deployment Guide](deployment.md)
