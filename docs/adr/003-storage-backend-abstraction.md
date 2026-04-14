# 3. Storage Backend Abstraction

**Status**: Accepted

## Context

Terraform module archives and provider binaries must be stored durably and served to clients. Different deployment environments have different storage capabilities:

- **Local development**: local filesystem is simplest.
- **AWS**: S3 is the natural choice.
- **Azure**: Azure Blob Storage.
- **GCP**: Google Cloud Storage.

The registry must support all these backends without requiring code changes when switching between them. Additionally, the `module_versions` and `provider_platforms` tables track which storage backend holds each artifact via a `storage_backend` column, enabling future migration between backends.

## Decision

Implement the Storage interface pattern with a factory registry:

1. **`Storage` interface** (`internal/storage/storage.go`) defines six methods: `Upload`, `Download`, `Delete`, `GetURL`, `Exists`, `GetMetadata`.
2. **Factory registry** (`internal/storage/factory.go`) maps backend type strings (`"local"`, `"s3"`, `"azure"`, `"gcs"`) to constructor functions.
3. **Backend packages** (`internal/storage/local/`, `internal/storage/s3/`, `internal/storage/azure/`, `internal/storage/gcs/`) each implement the `Storage` interface and register themselves via `init()` functions.
4. **Blank imports** in the router package trigger `init()` registration without the factory needing to know about concrete backends.
5. **`NewStorage(cfg)`** in the factory selects the backend from `cfg.Storage.DefaultBackend`.

This follows the plugin/registry pattern: adding a new backend (e.g., MinIO, SFTP) requires only implementing the interface, registering via `init()`, and adding a blank import.

## Consequences

**Easier**:
- Adding new storage backends requires no changes to existing code -- just a new package with `init()` and a blank import.
- All handlers and services depend on the `Storage` interface, not concrete implementations.
- `GetURL` with TTL enables signed URL generation for cloud backends and direct serving for local storage.
- Per-artifact backend tracking enables future storage migration features.

**Harder**:
- Each backend must implement all six interface methods, even if some are trivial (e.g., `GetMetadata` on local storage).
- Testing requires either real cloud credentials or mock implementations.
- The `init()` registration pattern makes the dependency graph implicit rather than explicit.
- Signed URL behavior differs across backends (S3 presigned URLs vs. Azure SAS tokens vs. GCS signed URLs), requiring careful abstraction.
