# Data Residency & Multi-Region Deployment

This document describes deployment strategies for data residency compliance and
multi-region disaster recovery. It covers single-region, active-passive, and
active-active topologies.

## Overview

The Terraform Registry stores two categories of persistent data:

1. **Metadata** — stored in PostgreSQL (users, modules, providers, audit logs, configuration)
2. **Artifacts** — stored in object storage (module archives, provider binaries, checksums)

Data residency requirements are met by ensuring both categories reside in the
required geographic region(s).

---

## Single-Region Deployment (Default)

The simplest topology: all components in one cloud region.

```
┌─────────────────────────────────────┐
│           Region: us-east-1         │
│                                     │
│  ┌──────────┐    ┌──────────────┐   │
│  │ Backend  │───▶│ PostgreSQL   │   │
│  │ Frontend │    │ (RDS/Cloud   │   │
│  └──────────┘    │  SQL/etc.)   │   │
│       │          └──────────────┘   │
│       │          ┌──────────────┐   │
│       └─────────▶│ S3 Bucket    │   │
│                  │ (same region)│   │
│                  └──────────────┘   │
└─────────────────────────────────────┘
```

**Data residency:** All data stays in the chosen region.

**RPO/RTO:** Depends on backup frequency and restoration speed (see
[Disaster Recovery](disaster-recovery.md)).

---

## Multi-Region Active-Passive

One primary region handles all traffic; a standby region receives replicated
data for failover.

```
┌─────────────────────────────┐     ┌─────────────────────────────┐
│     Primary: eu-west-1      │     │    Standby: eu-central-1    │
│                             │     │                             │
│  ┌──────────┐               │     │               ┌──────────┐ │
│  │ Backend  │───┐           │     │           ┌───│ Backend  │ │
│  │ Frontend │   │           │     │           │   │ (standby)│ │
│  └──────────┘   ▼           │     │           ▼   └──────────┘ │
│         ┌──────────────┐    │     │   ┌──────────────┐         │
│         │ PostgreSQL   │────┼──▶──┼──▶│ PG Read      │         │
│         │ (Primary)    │    │     │   │ Replica      │         │
│         └──────────────┘    │     │   └──────────────┘         │
│         ┌──────────────┐    │     │   ┌──────────────┐         │
│         │ S3 Bucket    │────┼──▶──┼──▶│ S3 Bucket    │         │
│         │ (CRR enabled)│    │     │   │ (replica)    │         │
│         └──────────────┘    │     │   └──────────────┘         │
└─────────────────────────────┘     └─────────────────────────────┘
```

### PostgreSQL Replication

#### AWS (RDS)

```hcl
resource "aws_db_instance" "primary" {
  identifier     = "terraform-registry-primary"
  engine         = "postgres"
  engine_version = "16"
  instance_class = "db.r6g.large"
  multi_az       = true

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
}

resource "aws_db_instance" "replica" {
  identifier          = "terraform-registry-replica"
  replicate_source_db = aws_db_instance.primary.arn
  instance_class      = "db.r6g.large"

  # Cross-region replica
  provider = aws.eu_central_1
}
```

#### Azure (Flexible Server)

```hcl
resource "azurerm_postgresql_flexible_server" "primary" {
  name                = "terraform-registry-primary"
  resource_group_name = azurerm_resource_group.primary.name
  location            = "westeurope"
  sku_name            = "GP_Standard_D2s_v3"
  version             = "16"

  geo_redundant_backup_enabled = true
}

# Geo-restore or read replica for DR
```

#### GCP (Cloud SQL)

```hcl
resource "google_sql_database_instance" "primary" {
  name             = "terraform-registry-primary"
  database_version = "POSTGRES_16"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-8192"
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }
}

resource "google_sql_database_instance" "replica" {
  name                 = "terraform-registry-replica"
  master_instance_name = google_sql_database_instance.primary.name
  database_version     = "POSTGRES_16"
  region               = "europe-west4"

  replica_configuration {
    failover_target = true
  }
}
```

### Object Storage Cross-Region Replication

#### AWS S3

```hcl
resource "aws_s3_bucket" "primary" {
  bucket = "terraform-registry-modules-primary"
}

resource "aws_s3_bucket_versioning" "primary" {
  bucket = aws_s3_bucket.primary.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_replication_configuration" "primary" {
  bucket = aws_s3_bucket.primary.id
  role   = aws_iam_role.replication.arn

  rule {
    id     = "cross-region-replication"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.replica.arn
      storage_class = "STANDARD"
    }
  }
}

resource "aws_s3_bucket" "replica" {
  provider = aws.eu_central_1
  bucket   = "terraform-registry-modules-replica"
}
```

#### Azure Blob

```hcl
resource "azurerm_storage_account" "primary" {
  name                     = "tfregistryprimary"
  resource_group_name      = azurerm_resource_group.primary.name
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "GRS"  # Geo-redundant storage
}
```

#### GCS

```hcl
resource "google_storage_bucket" "primary" {
  name     = "terraform-registry-modules-primary"
  location = "EU"  # Multi-region

  versioning {
    enabled = true
  }
}
```

### Failover Procedure

1. Promote the PostgreSQL replica to primary.
2. Update the backend config to point to the promoted database.
3. Update DNS to point to the standby region's load balancer.
4. Verify health: `curl https://<standby-lb>/health`

**Target RPO:** < 15 minutes (replication lag)
**Target RTO:** < 2 hours (manual failover) or < 15 minutes (automated)

---

## Multi-Region Active-Active

Both regions serve traffic simultaneously. This requires application-level
conflict resolution and is significantly more complex.

```
┌─────────────────────────────┐     ┌─────────────────────────────┐
│     Region A: us-east-1     │     │     Region B: us-west-2     │
│                             │     │                             │
│  ┌──────────┐               │     │               ┌──────────┐ │
│  │ Backend  │───┐           │     │           ┌───│ Backend  │ │
│  │ Frontend │   │           │     │           │   │ Frontend │ │
│  └──────────┘   ▼           │     │           ▼   └──────────┘ │
│         ┌──────────────┐    │     │   ┌──────────────┐         │
│         │ PostgreSQL   │◀───┼──▶──┼──▶│ PostgreSQL   │         │
│         │ (CockroachDB │    │     │   │ (CockroachDB │         │
│         │  or Citus)   │    │     │   │  or Citus)   │         │
│         └──────────────┘    │     │   └──────────────┘         │
│         ┌──────────────┐    │     │   ┌──────────────┐         │
│         │ S3 Bucket    │◀───┼──▶──┼──▶│ S3 Bucket    │         │
│         └──────────────┘    │     │   └──────────────┘         │
└─────────────────────────────┘     └─────────────────────────────┘
              ▲                                   ▲
              └──────── Global Load Balancer ──────┘
```

### Considerations

- **Database:** Standard PostgreSQL does not support multi-master. Options:
  - CockroachDB (PostgreSQL-compatible, native multi-region)
  - Citus (distributed PostgreSQL)
  - Application-level routing: writes go to primary, reads are local
- **Object storage:** S3 Cross-Region Replication with versioning handles
  eventual consistency. Module uploads must be idempotent.
- **Conflict resolution:** Module publish operations should use the module's
  SHA-256 checksum as a deduplication key to handle concurrent publishes.

### When to Use Active-Active

Active-active is recommended only when:
- Regulatory requirements mandate data processing in multiple jurisdictions simultaneously
- Latency requirements (< 50ms) cannot be met from a single region for all users
- Uptime SLA exceeds 99.99%

For most deployments, **active-passive** provides sufficient DR with much lower
operational complexity.

---

## Data Residency Checklist

| Requirement                  | How to Satisfy                                                                                             |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| All data in a single country | Deploy all components in a single region within that country                                               |
| Database encryption at rest  | Enable RDS/Cloud SQL/Azure encryption (default for managed services)                                       |
| Object storage encryption    | Enable SSE-S3/SSE-KMS (AWS), Azure SSE, or GCS CMEK                                                        |
| Encryption key residency     | Use a regional KMS key (e.g., AWS KMS in the target region)                                                |
| Audit log retention          | Configure `audit_retention.retention_days` per regulation; use legal holds for investigation periods       |
| Cross-border transfer        | Ensure replication targets are in permitted regions; document legal basis (e.g., SCCs, adequacy decisions) |
| Data subject rights          | GDPR export/erasure endpoints available at `/admin/users/:id/export` and `/admin/users/:id/erase`          |

---

## Example Multi-Region Terraform

See `deployments/terraform/aws/multi-region/` for a complete active-passive
example with:
- Cross-region RDS replica
- S3 cross-region replication
- Route53 health-check failover
- IAM roles for replication

---

## References

- [Disaster Recovery](disaster-recovery.md) — RPO/RTO targets and drill procedures
- [Capacity Planning](capacity-planning.md) — sizing guidance per tier
- [Air-Gap Installation](air-gap-install.md) — offline deployment for isolated environments
