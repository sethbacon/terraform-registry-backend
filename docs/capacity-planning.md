# Capacity Planning

This guide provides sizing recommendations for the Terraform Registry across different deployment scales.

## Table of Contents

1. [Database Sizing](#database-sizing)
2. [Storage Sizing](#storage-sizing)
3. [Compute Recommendations](#compute-recommendations)
4. [Network Bandwidth](#network-bandwidth)

---

## Database Sizing

### Row Estimates by Registry Size

| Table                | Small (<100 modules) | Medium (100-1,000 modules) | Large (1,000+ modules) |
| -------------------- | -------------------- | -------------------------- | ---------------------- |
| `modules`            | ~100                 | ~1,000                     | ~10,000                |
| `module_versions`    | ~500                 | ~10,000                    | ~100,000               |
| `providers`          | ~20                  | ~100                       | ~500                   |
| `provider_versions`  | ~100                 | ~1,000                     | ~5,000                 |
| `provider_platforms` | ~500                 | ~5,000                     | ~25,000                |
| `users`              | ~10                  | ~100                       | ~1,000                 |
| `api_keys`           | ~20                  | ~200                       | ~2,000                 |
| `audit_logs`         | ~10,000/month        | ~100,000/month             | ~1,000,000/month       |
| `module_scans`       | ~500                 | ~10,000                    | ~100,000               |
| `mirror_versions`    | ~100                 | ~5,000                     | ~50,000                |

### Audit Log Growth Rate

The `audit_logs` table is typically the largest and fastest-growing table. Estimate growth with:

```
monthly_audit_rows = avg_requests_per_day * 30 * audit_log_ratio
```

Where `audit_log_ratio` depends on configuration:
- `audit.log_read_operations: false` (default): ~10-20% of requests generate audit entries
- `audit.log_read_operations: true`: ~80-100% of requests generate audit entries

**Example**: 10,000 requests/day with read logging disabled:
- Monthly rows: 10,000 * 30 * 0.15 = 45,000 rows
- Row size: ~500 bytes average
- Monthly growth: ~22 MB

Configure `audit_retention_days` (default 90) to prevent unbounded growth. The audit cleanup job runs daily and deletes entries older than the retention period in batches.

### Database Disk Sizing

| Registry Size | Estimated DB Size (without audit) | With 90-day Audit Retention | Recommended Disk |
| ------------- | --------------------------------- | --------------------------- | ---------------- |
| Small         | 50-200 MB                         | 100-500 MB                  | 5 GB             |
| Medium        | 200 MB - 2 GB                     | 1-5 GB                      | 20 GB            |
| Large         | 2-10 GB                           | 10-50 GB                    | 100 GB           |

### Connection Pool Sizing

The default `maxConnections: 25` is suitable for most deployments. Tune based on:

```
recommended_pool = (backend_replicas * 2) + background_jobs + headroom
```

Where:
- `backend_replicas * 2`: Each pod uses ~2 connections for request handling
- `background_jobs`: Mirror sync, scanner, expiry notifier, audit cleanup (~4 connections)
- `headroom`: 5-10 connections for spikes

**Example**: 3 replicas: (3 * 2) + 4 + 5 = 15 connections. The default of 25 provides comfortable headroom.

For large deployments (10+ replicas), consider using PgBouncer as a connection pooler to multiplex connections.

---

## Storage Sizing

### Module Archives

Average module archive size varies by module complexity:

| Module Type                           | Average Archive Size |
| ------------------------------------- | -------------------- |
| Simple (single resource)              | 5-20 KB              |
| Medium (multiple resources, examples) | 50-200 KB            |
| Complex (full infrastructure stacks)  | 200 KB - 2 MB        |

**Formula**: `total_module_storage = num_module_versions * avg_archive_size`

**Example**: 10,000 module versions at 100 KB average = ~1 GB

### Provider Binaries

Provider binaries are significantly larger than modules. Each provider version includes binaries for multiple platforms:

| Component       | Size per Platform |
| --------------- | ----------------- |
| Provider binary | 20-200 MB         |
| SHA256SUMS file | ~1 KB             |
| GPG signature   | ~1 KB             |

**Formula**: `total_provider_storage = num_provider_versions * platforms_per_version * avg_binary_size`

**Example**: 100 provider versions * 6 platforms * 80 MB = ~48 GB

### Mirror Storage

If using the provider network mirror, storage grows with the number of mirrored providers:

| Mirror Scope                                 | Estimated Storage |
| -------------------------------------------- | ----------------- |
| 5 providers, latest 3 versions, 4 platforms  | ~5 GB             |
| 20 providers, latest 5 versions, 6 platforms | ~50 GB            |
| Full hashicorp/* mirror                      | 500+ GB           |

### Terraform Binary Mirror

The Terraform/OpenTofu binary mirror stores binaries for each version and platform:

| Mirror Scope                      | Estimated Storage |
| --------------------------------- | ----------------- |
| Latest 5 versions, 6 platforms    | ~2 GB             |
| Latest 20 versions, all platforms | ~15 GB            |
| All stable versions               | 50+ GB            |

### Storage Sizing Summary

| Registry Size | Modules Only | + Providers | + Mirrors | Recommended |
| ------------- | ------------ | ----------- | --------- | ----------- |
| Small         | 100 MB       | 5 GB        | 10 GB     | 20 GB       |
| Medium        | 1 GB         | 50 GB       | 100 GB    | 200 GB      |
| Large         | 10 GB        | 200 GB      | 500 GB    | 1 TB        |

---

## Compute Recommendations

### Backend Pods

| Registry Size | CPU Request | CPU Limit | Memory Request | Memory Limit | Replicas |
| ------------- | ----------- | --------- | -------------- | ------------ | -------- |
| Small         | 100m        | 500m      | 128 Mi         | 512 Mi       | 2        |
| Medium        | 250m        | 1000m     | 256 Mi         | 1 Gi         | 3        |
| Large         | 500m        | 2000m     | 512 Mi         | 2 Gi         | 5-10     |

Key factors affecting compute requirements:
- **Module scanning**: The scanner job is CPU-intensive. Each worker can consume up to 500m CPU during a scan. Adjust `scanning.workerCount` based on available resources.
- **Mirror sync**: Syncing providers from upstream registries is network-bound but requires moderate CPU for checksum verification.
- **Request handling**: Typical API requests are lightweight. Large file uploads (module archives, provider binaries) require more memory.

### Frontend Pods (Nginx)

The frontend is a static site served by Nginx. Resource requirements are minimal:

| Registry Size | CPU Request | CPU Limit | Memory Request | Memory Limit | Replicas |
| ------------- | ----------- | --------- | -------------- | ------------ | -------- |
| All sizes     | 50m         | 200m      | 64 Mi          | 128 Mi       | 2        |

### PostgreSQL

| Registry Size | CPU     | Memory | Storage IOPS |
| ------------- | ------- | ------ | ------------ |
| Small         | 1 vCPU  | 2 GB   | 100          |
| Medium        | 2 vCPU  | 4 GB   | 500          |
| Large         | 4+ vCPU | 8+ GB  | 1000+        |

Use managed database services (RDS, Cloud SQL, Azure Database for PostgreSQL) for production deployments. Enable connection pooling (PgBouncer) for large deployments.

### HorizontalPodAutoscaler Recommendations

For production deployments, enable the HPA:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

---

## Network Bandwidth

### Mirror Sync Bandwidth

Mirror sync downloads provider binaries from upstream registries. Estimate bandwidth based on sync frequency and mirror scope:

```
sync_bandwidth = providers_synced * versions_per_sync * platforms * avg_binary_size / sync_window
```

**Example**: Syncing 10 providers, 2 new versions each, 6 platforms, 80 MB average, over a 1-hour window:
- Total data: 10 * 2 * 6 * 80 MB = 9.6 GB
- Bandwidth: 9.6 GB / 3600 s = ~22 Mbps sustained

### Client Download Bandwidth

Estimate based on concurrent `terraform init` operations:

```
download_bandwidth = concurrent_inits * avg_download_size
```

- Module downloads: 100 KB average (lightweight)
- Provider downloads: 80 MB average (heavy)

**Example**: 50 concurrent `terraform init` each downloading one provider:
- Peak bandwidth: 50 * 80 MB = 4 GB burst
- With caching/mirrors: significantly reduced

### Recommendations

| Registry Size | Minimum Bandwidth | Recommended |
| ------------- | ----------------- | ----------- |
| Small         | 100 Mbps          | 100 Mbps    |
| Medium        | 1 Gbps            | 1 Gbps      |
| Large         | 1 Gbps            | 10 Gbps     |

For large deployments, consider:
- Placing the registry in the same region/VPC as your CI/CD runners to minimize latency
- Using CDN (CloudFront, Azure CDN, Cloud CDN) in front of the storage backend for provider binary downloads
- Enabling HTTP/2 on the ingress for multiplexed connections
