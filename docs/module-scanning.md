# Module Security Scanning

The registry can automatically scan every uploaded Terraform module for security misconfigurations and vulnerabilities. When enabled, a background job picks up each newly uploaded module version, runs the configured scanner against the extracted archive, and stores the results. Results are viewable in the web UI on the module detail page and via the admin API.

Scanning is **disabled by default**. The scanner binary must be installed on the server before the feature is enabled.

---

## How It Works

1. A module version is uploaded via the API or UI.
2. The upload handler creates a `pending` scan record in the database.
3. The `module-scanner` background job polls the database every `scan_interval_mins` minutes.
4. For each pending record the job downloads the module archive from storage, extracts it to a temporary directory, and invokes the scanner binary.
5. Results (severity counts and raw JSON output) are stored in the `module_scans` table.
6. The temporary directory is deleted immediately after the scan completes.
7. Results are visible in the UI (Security Scan panel on the module detail page) and via `GET /api/v1/admin/modules/{namespace}/{name}/{system}/versions/{version}/scan`.

---

## Supported Scanners

| Tool | `tool` value | License | Notes |
|---|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | `trivy` | Apache 2.0 | Recommended. Scans vulnerabilities, secrets, and IaC misconfigurations. |
| [Checkov](https://github.com/bridgecrewio/checkov) | `checkov` | Apache 2.0 | Broad Terraform policy coverage. Python-based. |
| [Terrascan](https://github.com/tenable/terrascan) | `terrascan` | Apache 2.0 | Purpose-built for IaC. Single binary. |
| [Snyk](https://snyk.io/) | `snyk` | Proprietary (free tier available) | Requires authentication (`snyk auth`). |
| Custom binary | `custom` | — | Any tool that writes SARIF or JSON to stdout. |

---

## Quick Start (Trivy — Recommended)

### 1. Install Trivy

**Linux / macOS (official install script):**
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
trivy --version
```

**Debian / Ubuntu:**
```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

**macOS (Homebrew):**
```bash
brew install trivy
```

**Docker-based (no install):**

If you run the registry in a container, add Trivy to your Docker image:
```dockerfile
FROM ghcr.io/aquasecurity/trivy:latest AS trivy
FROM your-registry-base-image
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
```

### 2. Configure the Registry

```yaml
# config.yaml
scanning:
  enabled: true
  tool: trivy
  binary_path: /usr/local/bin/trivy   # or wherever trivy is installed
  timeout: 5m
  worker_count: 2
  scan_interval_mins: 5
```

Or with environment variables:
```bash
export TFR_SCANNING_ENABLED=true
export TFR_SCANNING_TOOL=trivy
export TFR_SCANNING_BINARY_PATH=/usr/local/bin/trivy
```

### 3. Restart the Backend

The scanner job starts automatically when the server starts. Confirm it started:
```
INFO module scanner: started tool=trivy version=0.58.0
```

If the binary is missing or misconfigured, the server logs a warning and continues running with scanning disabled — it does not crash:
```
INFO module scanner: disabled (scanning.binary_path not set)
```
or:
```
ERROR module scanner: failed to construct scanner error="scanner binary not accessible at ..."
```

---

## Configuration Reference

All options live under the `scanning:` key in `config.yaml` or use the `TFR_SCANNING_` environment variable prefix.

| YAML key | Environment variable | Type | Default | Description |
|---|---|---|---|---|
| `enabled` | `TFR_SCANNING_ENABLED` | bool | `false` | Master toggle. Set to `true` to activate. |
| `tool` | `TFR_SCANNING_TOOL` | string | — | Scanner backend: `trivy`, `checkov`, `terrascan`, `snyk`, or `custom`. |
| `binary_path` | `TFR_SCANNING_BINARY_PATH` | string | — | Absolute path to the scanner executable on the server. |
| `expected_version` | `TFR_SCANNING_EXPECTED_VERSION` | string | — | If set, the job refuses to run if the installed binary reports a different version. Supply-chain protection. |
| `severity_threshold` | `TFR_SCANNING_SEVERITY_THRESHOLD` | string | (all) | Comma-separated list of severities to record, e.g. `CRITICAL,HIGH`. Findings below the threshold are omitted from counts. |
| `timeout` | `TFR_SCANNING_TIMEOUT` | duration | `5m` | Maximum time a single scan may run before it is killed. |
| `worker_count` | `TFR_SCANNING_WORKER_COUNT` | int | `2` | Number of scans to run concurrently. |
| `scan_interval_mins` | `TFR_SCANNING_SCAN_INTERVAL_MINS` | int | `5` | How often (in minutes) the job polls for pending scans. |
| `version_args` | `TFR_SCANNING_VERSION_ARGS` | string[] | — | **Custom tool only.** CLI arguments to retrieve the binary version, e.g. `["--version"]`. |
| `scan_args` | `TFR_SCANNING_SCAN_ARGS` | string[] | — | **Custom tool only.** CLI arguments passed before the target directory, e.g. `["iac", "test", "--json"]`. |
| `output_format` | `TFR_SCANNING_OUTPUT_FORMAT` | string | — | **Custom tool only.** How to parse the tool's output: `sarif` or `json`. |

---

## Scanner-Specific Setup

### Trivy

Trivy requires no authentication. The registry invokes:
```
trivy fs --format json --scanners vuln,secret,misconfig --exit-code 0 --quiet <dir>
```

**Air-gapped environments:** Trivy downloads its vulnerability database on first use. In air-gapped deployments, pre-populate the database:
```bash
# On a machine with internet access
trivy image --download-db-only
# Copy ~/.cache/trivy to the server's trivy cache directory
```

Or set `TRIVY_NO_PROGRESS=true` and `TRIVY_OFFLINE_SCAN=true` to disable network access.

**Recommended config:**
```yaml
scanning:
  enabled: true
  tool: trivy
  binary_path: /usr/local/bin/trivy
  timeout: 5m
  worker_count: 2
  scan_interval_mins: 5
```

---

### Checkov

Checkov is Python-based. Install via pip:
```bash
pip3 install checkov
which checkov   # e.g. /usr/local/bin/checkov
checkov --version
```

Or in a container:
```dockerfile
RUN pip3 install checkov
```

The registry invokes:
```
checkov -d <dir> -o json --quiet
```

**Note:** Checkov exits with code `1` when checks fail, which is normal. The registry handles this correctly.

**Recommended config:**
```yaml
scanning:
  enabled: true
  tool: checkov
  binary_path: /usr/local/bin/checkov
  timeout: 10m   # checkov can be slower than trivy
  worker_count: 1
  scan_interval_mins: 5
```

---

### Terrascan

Install the single binary:
```bash
# Linux amd64
curl -L "https://github.com/tenable/terrascan/releases/latest/download/terrascan_Linux_x86_64.tar.gz" | tar xz terrascan
mv terrascan /usr/local/bin/
terrascan version
```

The registry invokes:
```
terrascan scan -t terraform -d <dir> -o json
```

**Recommended config:**
```yaml
scanning:
  enabled: true
  tool: terrascan
  binary_path: /usr/local/bin/terrascan
  timeout: 5m
  worker_count: 2
  scan_interval_mins: 5
```

---

### Snyk

Snyk requires authentication before it can scan. Install and authenticate:
```bash
npm install -g snyk
snyk auth   # opens browser to authenticate with your Snyk account
snyk --version
```

Or in a container using an API token:
```bash
snyk auth $SNYK_TOKEN
```

The registry invokes:
```
snyk iac test <dir> --json
```

**Note:** Snyk exits with code `1` when vulnerabilities are found, which is normal. The registry handles this correctly.

**Recommended config:**
```yaml
scanning:
  enabled: true
  tool: snyk
  binary_path: /usr/local/bin/snyk
  timeout: 5m
  worker_count: 1   # Snyk has rate limits on free tier
  scan_interval_mins: 5
```

---

### Custom Tool

Use `custom` when you have an internal scanner or a tool not natively supported. The binary must:
- Accept the target directory as its last argument
- Write results to **stdout**
- Output either **SARIF** (any conformant SARIF 2.1.0 JSON) or **JSON** with a `vulnerabilities` array where each entry has a `severity` field

**Example — tfsec (SARIF output):**
```yaml
scanning:
  enabled: true
  tool: custom
  binary_path: /usr/local/bin/tfsec
  output_format: sarif
  version_args: ["--version"]
  scan_args: ["--format", "sarif"]
  timeout: 5m
  worker_count: 2
  scan_interval_mins: 5
```

**Example — internal tool (JSON output):**
```yaml
scanning:
  enabled: true
  tool: custom
  binary_path: /opt/internal/scanner
  output_format: json
  version_args: ["version"]
  scan_args: ["scan", "--output", "json"]
  timeout: 10m
  worker_count: 1
  scan_interval_mins: 10
```

For `output_format: json`, the expected output schema is:
```json
{
  "vulnerabilities": [
    { "severity": "CRITICAL" },
    { "severity": "HIGH" },
    { "severity": "MEDIUM" }
  ]
}
```

Severity values are matched case-insensitively to `critical`, `high`, `medium`, `low`.

For `output_format: sarif`, any conformant SARIF 2.1.0 document is accepted. Severity is read from `result.properties.severity` or `rule.properties.security-severity`.

---

## Supply-Chain Version Pinning

To prevent a compromised or unexpected scanner binary from being used, set `expected_version`. The job will refuse to run — and log an error — if the installed binary's reported version does not match exactly:

```yaml
scanning:
  enabled: true
  tool: trivy
  binary_path: /usr/local/bin/trivy
  expected_version: "0.58.0"   # must match exactly what `trivy --version` reports
```

When the version drifts (e.g. after a system package update), the scanner stops and logs:
```
ERROR module scanner: binary version mismatch — refusing to run
  tool=trivy expected=0.58.0 actual=0.59.1
  action=update scanning.expected_version in config or reinstall the expected binary
```

Update `expected_version` after deliberately upgrading the scanner binary.

---

## Kubernetes Deployment

When running in Kubernetes, install the scanner binary in the same container as the registry backend. Example using Trivy in a Helm values override:

```yaml
# values-override.yaml
extraInitContainers:
  - name: install-trivy
    image: aquasec/trivy:0.58.0
    command: ["cp", "/usr/local/bin/trivy", "/shared/trivy"]
    volumeMounts:
      - name: scanner-bin
        mountPath: /shared

extraVolumes:
  - name: scanner-bin
    emptyDir: {}

extraVolumeMounts:
  - name: scanner-bin
    mountPath: /opt/scanners

env:
  - name: TFR_SCANNING_ENABLED
    value: "true"
  - name: TFR_SCANNING_TOOL
    value: "trivy"
  - name: TFR_SCANNING_BINARY_PATH
    value: "/opt/scanners/trivy"
```

---

## Viewing Scan Results

Results are available in two places:

**Web UI:** Open any module's detail page, select a version, and the **Security Scan** panel appears in the right sidebar (visible to users with `admin` or `modules:write` scope).

**API:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://registry.example.com/api/v1/admin/modules/myorg/vpc/aws/versions/1.0.0/scan
```

Response:
```json
{
  "id": "...",
  "scanner": "trivy",
  "scanner_version": "0.58.0",
  "status": "findings",
  "scanned_at": "2025-04-09T12:00:00Z",
  "critical_count": 0,
  "high_count": 2,
  "medium_count": 5,
  "low_count": 3,
  "raw_results": { ... }
}
```

**Status values:**

| Status | Meaning |
|---|---|
| `pending` | Scan is queued, not yet started. |
| `scanning` | Scan is actively running. |
| `clean` | Scan completed with zero findings. |
| `findings` | Scan completed with one or more findings. |
| `error` | Scan failed. Check `error_message` for details. |

---

## Troubleshooting

**No scans are running:**
- Check `scanning.enabled: true` is set.
- Verify the binary path: `ls -la /usr/local/bin/trivy`.
- Check server logs for `module scanner:` lines at startup.
- Ensure the registry process has execute permission on the binary.

**All scans show `error` status:**
- Check the `error_message` field in the scan API response.
- Common causes: binary path wrong, insufficient permissions, scanner requires authentication (Snyk), or timeout too short for large modules.

**Scanner binary version mismatch:**
- Update `expected_version` to match the installed binary, or reinstall the expected version.

**Scans are slow / backing up:**
- Increase `worker_count` (default: 2) to process more scans concurrently.
- Reduce `timeout` if modules are small and scans are hanging.
- Check available CPU on the server — scanner binaries are CPU-intensive.

**`pending` scans left after a crash:**
- The job automatically resets scan records stuck in `scanning` state for more than 30 minutes on startup. No manual intervention is needed for normal restarts.
