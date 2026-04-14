# 10. Binary Mirror Custom Protocol

**Status**: Accepted

## Context

Terraform and OpenTofu release official binaries for each version across multiple platforms (linux/amd64, darwin/arm64, windows/amd64, etc.). Organizations often need to:

1. Pin and distribute approved Terraform versions to all developers and CI/CD pipelines.
2. Operate in air-gapped environments where `releases.hashicorp.com` is unreachable.
3. Enforce version policies (e.g., only stable releases, minimum version requirements).
4. Track which Terraform versions are actually being used across the organization.

Unlike the Provider Network Mirror Protocol (ADR 009), there is no official Terraform protocol for mirroring Terraform binaries themselves. The `terraform` CLI does not have a built-in mechanism to download itself from a mirror.

## Decision

Implement a custom HTTP API for Terraform/OpenTofu binary distribution:

### API Design (`internal/api/terraform_binaries/`)

Public, unauthenticated endpoints scoped to a named mirror configuration:

- `GET /terraform/binaries/:name/versions` -- list all synced versions
- `GET /terraform/binaries/:name/versions/latest` -- resolve the latest version
- `GET /terraform/binaries/:name/versions/:version` -- version detail with platform list
- `GET /terraform/binaries/:name/versions/:version/:os/:arch` -- download URL (signed, time-limited)

### Background Sync (`TerraformMirrorSyncJob`)

- Periodically syncs from `releases.hashicorp.com` (Terraform) or the configured upstream.
- Downloads binaries, SHA256SUMS, and GPG signatures.
- Stores in the configured storage backend alongside provider archives.
- Respects version filters: `stable_only`, `version_filter` (regex), platform selection.
- Download counts tracked per version/platform for usage analytics.

### Version Filtering

Mirror configurations support:
- `stable_only: true` -- skip pre-release versions (alpha, beta, rc).
- `version_filter` -- regex pattern to match specific version ranges.
- Platform selection -- sync only the platforms your organization uses.

### Named Mirror Configs

Multiple mirror configurations can coexist (e.g., one for Terraform, one for OpenTofu), each with independent version filters and sync schedules. The `:name` path parameter identifies which mirror to query.

## Consequences

**Easier**:
- Air-gapped environments can distribute approved Terraform versions without internet access.
- Version pinning and filtering ensure only approved versions are available.
- Download tracking provides visibility into Terraform version adoption across the organization.
- Signed download URLs from the storage backend prevent unauthorized direct access.
- Multiple mirror configs support both Terraform and OpenTofu from the same registry.

**Harder**:
- No standard protocol exists -- clients must use custom scripts or wrapper tools to download from this API (unlike the provider mirror which Terraform supports natively).
- Storage requirements grow with each new Terraform release (~100 MB per platform per version).
- GPG signature verification on the server side adds complexity.
- The sync job must handle upstream release cadence and avoid downloading unnecessary platforms.
- This is a custom API, so it cannot leverage Terraform's built-in provider installation configuration. Integration requires tooling or documentation for teams.
