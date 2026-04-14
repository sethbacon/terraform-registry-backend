# 2. PostgreSQL as Primary Store

**Status**: Accepted

## Context

The Terraform Registry needs a persistent data store for modules, providers, users, API keys, audit logs, mirror configurations, scan results, organizations, RBAC policies, OIDC configuration, and webhook events. The initial schema (migration `000001_initial_schema.up.sql`) creates 20+ tables with foreign key relationships, UUID primary keys, JSON columns, and full-text potential.

Candidate database systems:

1. **SQLite** -- zero-dependency embedded database. Simple to deploy but lacks concurrent write support, making it unsuitable for multi-pod Kubernetes deployments.
2. **PostgreSQL** -- full-featured relational database with strong JSON support, full-text search, and mature replication for HA.
3. **MySQL/MariaDB** -- relational but weaker JSON support and fewer advanced features (no `gen_random_uuid()`, no native `tsvector`).

The registry is designed to run as a multi-replica Kubernetes deployment behind a load balancer. Concurrent writes from multiple pods are a baseline requirement. The schema uses PostgreSQL-specific features: `gen_random_uuid()` for primary keys, `TIMESTAMP WITH TIME ZONE` throughout, `jsonb` columns for flexible metadata, and the `uuid` data type.

## Decision

Use PostgreSQL as the sole required database backend:

- All metadata is stored in PostgreSQL (modules, providers, versions, users, API keys, organizations, audit logs, OIDC config, SCM integrations, mirror configs, scan results, webhook events, system settings).
- Connection pooling via `database/sql` with configurable `MaxConnections` and `MinIdleConnections`.
- Migrations managed by `golang-migrate` with sequential numbered files (`000001` through `000011+`).
- Configuration via `TFR_DATABASE_*` environment variables or `database.*` YAML keys.
- Auto-migration on startup (`serve` command) so containers are always at the latest schema version.

## Consequences

**Easier**:
- Rich query capabilities: JOINs across modules/versions/providers, aggregation for statistics, and future full-text search (GIN indexes on `tsvector` columns).
- Strong consistency: ACID transactions protect against partial writes during module publishing.
- Mature tooling: `pg_dump`/`pg_restore` for backups, streaming replication for HA, PgBouncer for connection pooling.
- UUID primary keys enable future multi-region or federated registry scenarios.

**Harder**:
- PostgreSQL is a required external dependency -- cannot run the registry as a single self-contained binary (unlike SQLite-based alternatives).
- Operators must provision and manage a PostgreSQL instance (or use a managed service).
- Schema migrations must be carefully written to be backwards-compatible for zero-downtime deployments.
- Testing requires a PostgreSQL instance (mitigated by Docker Compose test configuration).
