# 8. Module Scanning Architecture

**Status**: Accepted

## Context

Enterprise Terraform registries need security scanning of published modules to detect misconfigurations, compliance violations, and vulnerabilities before they reach production infrastructure. The scanning ecosystem includes multiple tools (Trivy, Terrascan, Snyk, Checkov) each with different strengths, output formats, and licensing.

The registry must:
1. Support multiple scanning tools without coupling to any single vendor.
2. Run scans asynchronously (scanning can take minutes for large modules).
3. Store normalized results for consistent display regardless of tool.
4. Allow supply-chain protection (version pinning of the scanner binary).

## Decision

Implement a pluggable scanner architecture with a background job:

### Scanner Interface (`internal/scanner/scanner.go`)

```go
type Scanner interface {
    Name() string
    Version(ctx context.Context) (string, error)
    ScanDirectory(ctx context.Context, dir string) (*ScanResult, error)
}
```

Five implementations: `trivy`, `terrascan`, `snyk`, `checkov`, and `custom`. The `custom` scanner allows arbitrary CLI tools with configurable `VersionArgs`, `ScanArgs`, and `OutputFormat` (SARIF or JSON).

### Normalized Results (`ScanResult`)

All scanners produce a `ScanResult` with `CriticalCount`, `HighCount`, `MediumCount`, `LowCount`, `HasFindings`, and `RawJSON` (raw tool output stored as-is for detailed viewing).

### Background Job (`internal/jobs/module_scanner_job.go`)

- `ModuleScannerJob` follows the same polling pattern as `APIKeyExpiryNotifier`.
- Polls for pending scan records at configurable intervals (default 5 minutes).
- Dispatches scans to a worker pool (configurable `WorkerCount`, default 2).
- Each scan: downloads module archive from storage, extracts to temp directory, runs scanner, stores results.
- Optimistic locking via `MarkScanning` prevents duplicate processing.
- Stale scan recovery resets records stuck in `scanning` state for >30 minutes.

### Supply-Chain Protection

- `ExpectedVersion` config pin: if the installed binary version does not match, the job refuses to start.
- The actual scanner version is recorded with each scan result for audit purposes.

### Scan Lifecycle

1. Module version published -> scan record created with status `pending`.
2. Scanner job picks up pending record -> status `scanning`.
3. Scanner completes -> status `completed` or `error` with results stored.

## Consequences

**Easier**:
- Operators choose their preferred scanner tool via a single config value.
- New scanners can be added by implementing the three-method interface.
- The `custom` scanner supports any CLI tool with SARIF or JSON output, enabling tools not yet natively supported.
- Scans are non-blocking: module publishing completes immediately, scan runs in the background.
- Version pinning prevents supply-chain attacks via compromised scanner binaries.

**Harder**:
- The scanner binary must be installed in the container image (not included in the registry image itself).
- Different scanners may produce different severity mappings for the same issue.
- The worker pool is bounded but scan duration is unpredictable, potentially causing queue buildup.
- SARIF parsing for the custom scanner requires handling tool-specific SARIF extensions.
