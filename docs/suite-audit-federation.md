# Suite Audit Federation

When the Terraform Registry is deployed alongside the Terraform State Manager
(TSM) as a coupled suite, the registry can **federate its audit trail to TSM** so
TSM's admin Audit Log page shows a single, unified record of write operations
across both apps. This is an optional, operator-enabled feature; it requires no
code change on either side.

## How it works

The registry already writes every audited action to its own database and can
*ship* a copy of each entry to external destinations via the built-in audit
**webhook shipper** (`internal/audit/shipper.go`). Federation is just a webhook
shipper whose destination is TSM's ingest endpoint:

```
registry audit middleware ──ship──▶ POST {tsm}/api/v1/audit/ingest ──▶ identity.audit_logs
```

TSM records the entry in the shared `identity.audit_logs` table — the same trail
its Audit Log page reads — tagging it `federated: true` (plus `source_app` and the
original `source_timestamp`, `auth_method`, and `status_code` in metadata).

## Preconditions

Federation is only **coherent under a shared identity store**, and TSM enforces
this — it accepts entries only when `sharedStore` is asserted (advertised by TSM,
the ingest side, as the `audit.ingest.v1` manifest capability; the registry's own
manifest advertises only `modules.v1`/`providers.v1`/`mirror.v1`/`oci.v1`) and
rejects them otherwise:

1. **Shared identity store.** Both apps point at one physical identity database
   (one host + one database name). Only then do the registry's `user_id` /
   `organization_id` resolve in TSM's identity tables; otherwise a merged
   timeline would mis-attribute actors and the `audit_logs` foreign key would
   reject the row. Set `identity.sharedStore: true` (TSM `TSM_SUITE_IDENTITY_SHARED_STORE=true`).
2. **Shared suite service token.** The header token this app sends must equal
   TSM's `TSM_SUITE_SERVICE_TOKEN`. Reuse the same value already used to gate the
   "Consumed by" read — i.e. this app's `TFR_SUITE_SIBLING_TOKEN`.
3. **Reachability.** The registry pods must be able to reach TSM's public URL.

If any precondition is unmet, leave federation off. The registry continues to
record its own audit trail locally; only the cross-app unified view is absent.

## Configuration

Audit shippers are a structured list, so they are configured in `config.yaml`
(not via environment variables). Add a `webhook` shipper to `audit.shippers`:

```yaml
audit:
  enabled: true
  shippers:
    - enabled: true
      type: webhook
      webhook:
        url: https://tsm.example.com/api/v1/audit/ingest
        headers:
          # Must equal TSM's TSM_SUITE_SERVICE_TOKEN.
          X-Suite-Service-Token: ${TFR_SUITE_SIBLING_TOKEN}
          # Optional — labels the federated rows in TSM's trail.
          X-Suite-Source-App: terraform-registry
        timeout_secs: 5
        batch_size: 0           # 0 = ship each entry immediately
        flush_interval_secs: 0
```

`${TFR_SUITE_SIBLING_TOKEN}` is expanded from the environment, so the token
itself stays in a secret and never appears in the config file.

> **Note on the Helm chart.** The chart configures the backend through
> environment variables, which cannot express a structured shipper list. To use
> federation in a chart deployment, mount a `config.yaml` containing the
> `audit.shippers` block above (e.g. via a ConfigMap/Secret volume) — the backend
> auto-discovers `config.yaml` in the standard locations. A first-class chart
> value for this can be added if there is demand.

## Verifying

After enabling, perform an audited action in the registry (e.g. publish or delete
a module) and confirm it appears in TSM's admin Audit Log marked as federated.
Shipping is best-effort and asynchronous: delivery failures are logged on the
registry side (`failed to ship audit log`) and never block the original request.
