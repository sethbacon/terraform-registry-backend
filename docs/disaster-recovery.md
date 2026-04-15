# Disaster Recovery

This document covers backup and restore procedures, RTO/RPO targets, failover playbooks, and DR drill procedures for the Terraform Registry.

## Table of Contents

1. [Overview](#overview)
2. [Backup Procedures](#backup-procedures)
3. [Restore Procedures](#restore-procedures)
4. [RTO/RPO Targets](#rtorpo-targets)
5. [Failover Playbook](#failover-playbook)
6. [DR Drill Checklist](#dr-drill-checklist)

---

## Overview

The Terraform Registry consists of three stateful components that must be backed up:

1. **PostgreSQL database** -- stores all metadata: modules, providers, users, API keys, audit logs, mirror configurations, scan results.
2. **Storage backend** -- holds module archives (.tar.gz), provider binaries, and mirrored artifacts. Supported backends: local filesystem, S3, Azure Blob Storage, GCS.
3. **Secrets** -- JWT signing key (`TFR_JWT_SECRET`), encryption key (`ENCRYPTION_KEY`), OIDC client secrets, and SCM OAuth tokens (encrypted in DB).

Loss of any component requires a specific recovery procedure. This document covers each scenario.

---

## Backup Procedures

### PostgreSQL Database

#### Daily Full Backup (pg_dump)

Run `pg_dump` daily to produce a logical backup. This is the simplest approach and works for registries with up to ~100 GB of data.

```bash
# Full logical backup (compressed, custom format for selective restore)
pg_dump \
  --host=$TFR_DATABASE_HOST \
  --port=$TFR_DATABASE_PORT \
  --username=$TFR_DATABASE_USER \
  --dbname=$TFR_DATABASE_NAME \
  --format=custom \
  --compress=9 \
  --file="/backups/terraform_registry_$(date +%Y%m%d_%H%M%S).dump"
```

For Kubernetes deployments, use the optional Helm CronJob (see `deployments/helm/templates/cronjob-backup.yaml`) by setting `backup.enabled=true` in values.yaml.

#### Continuous WAL Archiving (Point-in-Time Recovery)

For production deployments requiring RPO < 1 hour, enable PostgreSQL WAL archiving:

```ini
# postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'aws s3 cp %p s3://my-backup-bucket/wal/%f'  # or equivalent for Azure/GCS
```

This enables point-in-time recovery (PITR) to any moment between backups.

#### Recommended Schedule

| Method         | Frequency          | Retention | RPO                 |
| -------------- | ------------------ | --------- | ------------------- |
| pg_dump (full) | Daily at 02:00 UTC | 30 days   | 24 hours            |
| WAL archiving  | Continuous         | 7 days    | Minutes             |
| pg_basebackup  | Weekly             | 4 weeks   | N/A (base for PITR) |

### Storage Backend

#### S3

Enable versioning on the bucket for point-in-time recovery of individual objects:

```bash
aws s3api put-bucket-versioning \
  --bucket my-registry-bucket \
  --versioning-configuration Status=Enabled
```

Enable cross-region replication for geographic redundancy. Use S3 lifecycle rules to transition old versions to Glacier after 30 days.

#### Azure Blob Storage

Enable soft-delete with a 30-day retention period:

```bash
az storage blob service-properties delete-policy update \
  --account-name myregistryaccount \
  --enable true \
  --days-retained 30
```

Enable blob versioning for point-in-time recovery. Use geo-redundant storage (GRS or RA-GRS) for cross-region protection.

#### GCS

Enable object versioning:

```bash
gsutil versioning set on gs://my-registry-bucket
```

Use dual-region or multi-region buckets for geographic redundancy. Configure lifecycle rules to delete old versions after 30 days.

#### Local Storage

When using local filesystem storage, back up the storage directory (default `/app/storage`) using standard filesystem backup tools:

```bash
# rsync to a backup location
rsync -avz /app/storage/ /backups/storage/

# Or tar archive
tar czf "/backups/storage_$(date +%Y%m%d).tar.gz" /app/storage/
```

For Kubernetes with PVC, use Velero or a CSI snapshot driver to snapshot the PersistentVolume.

### Secrets Backup

Secrets should be managed through a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, etc.) with its own backup procedures. At minimum, document and securely store:

- `TFR_JWT_SECRET` -- loss means all existing JWT tokens become invalid (users must re-authenticate)
- `ENCRYPTION_KEY` -- loss means all encrypted SCM OAuth tokens become unreadable (must be re-linked)
- OIDC client secrets -- can be regenerated from the identity provider

---

## Restore Procedures

### Scenario 1: Database Restore (Data Corruption or Loss)

1. **Stop the registry** to prevent writes during restore:
   ```bash
   kubectl scale deployment terraform-registry-backend --replicas=0
   ```

2. **Restore from pg_dump**:
   ```bash
   # Drop and recreate the database
   dropdb --host=$HOST --username=$USER terraform_registry
   createdb --host=$HOST --username=$USER terraform_registry

   # Restore from backup
   pg_restore \
     --host=$HOST \
     --username=$USER \
     --dbname=terraform_registry \
     --verbose \
     --clean \
     --if-exists \
     /backups/terraform_registry_20260414_020000.dump
   ```

3. **For point-in-time recovery** (requires WAL archives):
   ```bash
   # Stop PostgreSQL
   # Restore base backup
   # Configure recovery.conf / postgresql.conf with:
   restore_command = 'aws s3 cp s3://my-backup-bucket/wal/%f %p'
   recovery_target_time = '2026-04-14 15:30:00 UTC'
   # Start PostgreSQL -- it replays WAL up to the target time
   ```

4. **Start the registry**:
   ```bash
   kubectl scale deployment terraform-registry-backend --replicas=2
   ```

5. **Verify** by checking `/health` and `/ready` endpoints, then listing modules via the API.

### Scenario 2: Storage Backend Restore

#### S3 / Azure / GCS

Use the cloud provider's object versioning to restore deleted or overwritten artifacts:

```bash
# S3: restore a specific object version
aws s3api get-object \
  --bucket my-registry-bucket \
  --key modules/namespace/name/system/1.0.0/archive.tar.gz \
  --version-id $VERSION_ID \
  restored-archive.tar.gz
```

#### Local Storage from Backup

```bash
rsync -avz /backups/storage/ /app/storage/
```

### Scenario 3: Full Cluster Recovery

1. Deploy a new Kubernetes cluster (or restore from cluster backup).
2. Install the Helm chart with the same `values.yaml`.
3. Restore the database from backup (Scenario 1).
4. Restore storage backend (Scenario 2) or rely on cloud-native storage HA.
5. Provide the same secrets (`TFR_JWT_SECRET`, `ENCRYPTION_KEY`).
6. Verify by running the DR drill checklist below.

---

## RTO/RPO Targets

| Deployment Tier | RPO (Recovery Point Objective) | RTO (Recovery Time Objective) | Configuration                                                                                         |
| --------------- | ------------------------------ | ----------------------------- | ----------------------------------------------------------------------------------------------------- |
| **Development** | 24 hours                       | 4 hours                       | Daily pg_dump, local storage                                                                          |
| **Standard**    | 1 hour                         | 30 minutes                    | WAL archiving + daily pg_dump, cloud storage with versioning                                          |
| **Enterprise**  | ~0 (near-zero)                 | 15 minutes                    | Streaming replication + WAL archiving, cloud storage with cross-region replication, warm standby pods |

### Standard Tier (Recommended)

- **RPO 1 hour**: WAL archiving ships transaction logs every few minutes. Worst case, you lose the last batch of WAL files.
- **RTO 30 minutes**: Restore from latest pg_dump (5-10 min for typical registries), replay WAL to target time (5-15 min), restart pods (2-5 min).

### Enterprise Tier

- **RPO near-zero**: PostgreSQL streaming replication to a hot standby ensures every committed transaction is replicated.
- **RTO 15 minutes**: Automatic failover via Patroni/pgBouncer promotes the standby within seconds. Application pods self-heal through Kubernetes.

---

## Failover Playbook

### PostgreSQL Failover

#### With Streaming Replication (Patroni/pgBouncer)

1. Patroni detects primary failure (health check timeout, default 30s).
2. Patroni promotes the replica with the most recent WAL position.
3. pgBouncer connection pool updates its backend target to the new primary.
4. Registry pods reconnect automatically through the pgBouncer service.
5. **No manual intervention required** -- verify via monitoring dashboards.

#### Without Streaming Replication (Manual Failover)

1. Detect failure via `/ready` endpoint returning 503 or Prometheus alert.
2. Restore database from latest backup (see Restore Procedures).
3. Update `TFR_DATABASE_HOST` to point to the new database instance.
4. Restart registry pods.

### Storage Backend Failover

- **S3/Azure/GCS**: Cloud-native HA handles failures transparently. No manual action needed. For regional outages, switch to the cross-region replica bucket and update the storage configuration.
- **Local storage**: If the PersistentVolume is lost, restore from backup. Consider migrating to cloud storage for production.

### Application Pod Recovery

Kubernetes handles pod recovery automatically:

1. **Liveness probe** (`/health`) detects unresponsive pods -- Kubernetes restarts them.
2. **Readiness probe** (`/ready`) removes unhealthy pods from the Service -- traffic is routed only to healthy instances.
3. **PodDisruptionBudget** ensures at least `minAvailable` pods during voluntary disruptions.
4. **HorizontalPodAutoscaler** (if enabled) scales up under load.

---

## DR Drill Checklist

Perform a DR drill quarterly to validate recovery procedures. Use a non-production environment.

### Pre-Drill Preparation

- [ ] Confirm backup retention has recent backups available
- [ ] Prepare a separate namespace or cluster for the drill
- [ ] Document the current database schema version (`SELECT version FROM schema_migrations`)
- [ ] Record the current module/provider count for post-recovery validation

### Drill Execution

- [ ] **Database restore**: Restore the latest pg_dump to the drill environment
- [ ] **Schema validation**: Verify schema version matches production
- [ ] **Data validation**: Confirm module count, provider count, and user count match
- [ ] **API smoke test**: Hit `/health`, `/ready`, list modules, download a module archive
- [ ] **Authentication test**: Log in via OIDC and API key
- [ ] **Storage restore** (if applicable): Restore storage backend and verify module downloads
- [ ] **Measure RTO**: Record total time from drill start to first successful API call
- [ ] **Measure RPO**: Compare latest audit log timestamp in the restored DB to the drill start time

### Post-Drill

- [ ] Document actual RTO and RPO achieved
- [ ] Log any issues encountered and remediation steps
- [ ] Update runbook if procedures have changed
- [ ] File issues for any gaps found
- [ ] Schedule the next quarterly drill
