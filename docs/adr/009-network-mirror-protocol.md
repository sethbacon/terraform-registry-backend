# 9. Network Mirror Protocol

**Status**: Accepted

## Context

Terraform's [Provider Network Mirror Protocol](https://developer.hashicorp.com/terraform/internals/provider-network-mirror-protocol) allows `terraform init` to download provider binaries from a local cache instead of the public Terraform Registry. This is critical for:

1. **Air-gapped environments**: Networks with no internet access must have a local source for provider binaries.
2. **Reliability**: Upstream registry outages do not block `terraform init`.
3. **Performance**: Local downloads are faster than cross-internet fetches, especially for large provider binaries (50-200 MB each).
4. **Compliance**: Some organizations require all binaries to pass through an approved internal registry.

The protocol defines two endpoints:
- `GET /terraform/providers/{hostname}/{namespace}/{type}/index.json` -- list available versions
- `GET /terraform/providers/{hostname}/{namespace}/{type}/{version}.json` -- list platforms for a version with download URLs and hashes

## Decision

Implement the Terraform Provider Network Mirror Protocol v1 as a first-class feature:

- **Mirror handlers** in `internal/api/mirror/` implement both protocol endpoints.
- **Unauthenticated by design**: The protocol specification requires these endpoints to be publicly accessible (Terraform CLI does not send credentials for mirror discovery).
- **Pull-through caching**: When `pull_through` is enabled on a mirror configuration, the registry automatically downloads missing provider versions from the upstream registry on first request, caching them locally for future requests.
- **Background sync job** (`MirrorSyncJob`): Periodically syncs configured provider mirrors from upstream, pre-populating the cache so clients do not experience first-request latency.
- **Mirror configuration**: Each mirror config specifies hostname, namespace, type, and sync settings. Stored in the database with admin-only management endpoints.
- **Organization scoping**: Mirrors can be scoped to specific organizations in multi-tenant deployments.

### Client Configuration

Users configure their `~/.terraformrc` to point at the registry:

```hcl
provider_installation {
  network_mirror {
    url = "https://registry.example.com/terraform/providers/"
  }
}
```

## Consequences

**Easier**:
- Air-gapped deployments can use Terraform normally by pointing at the private registry.
- Provider binary caching reduces bandwidth costs and download times.
- Pull-through mode provides a transparent caching proxy experience.
- The background sync job keeps the mirror warm without client-triggered delays.
- Standard Terraform configuration -- no custom tooling needed on the client side.

**Harder**:
- Mirror storage requirements can be substantial (50-200 MB per provider per platform per version).
- Pull-through mode introduces complexity: upstream availability affects first requests for uncached providers.
- Mirror sync failures must be monitored to detect upstream registry outages.
- Hash verification (zh: prefix for zip hashes) must match exactly to prevent Terraform from rejecting mirrors.
- The unauthenticated nature means access control must be enforced at the network level (e.g., NetworkPolicy, ingress rules) if needed.
