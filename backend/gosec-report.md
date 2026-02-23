# Backend Security Scan Report — gosec

**Scan date:** 2026-02-23 (local full scan)
**Previous scan:** 2026-02-23 (CI run, unfiltered)
**Tool:** [gosec](https://github.com/securego/gosec) v2.23.0
**Scope:** `./...` (all Go packages)
**Filters:** none
**Files scanned:** 112 | **Lines scanned:** 31,898 | **nosec suppressions:** 2

---

## Summary

| Severity | 2026-02-17 | 2026-02-19 | 2026-02-23 (CI) | 2026-02-23 (local) | After fixes |
| --- | --- | --- | --- | --- | --- |
| HIGH | 48 | 49 | 45 | 48 | **46** |
| MEDIUM | 33 | 35 | 5 | 37 | **35** |
| LOW | 0 | 0 | 11 | 12 | **12** |
| **Total** | **81** | **84** | **61** | **97** | **93** |

> **Note on CI vs local scan:** The 2026-02-23 CI run used a `dev` gosec build that did not emit G701, G117,
> or G304. The local full scan restores those rules and also surfaces G101 and G114.
> The local scan is the authoritative baseline going forward.

### Rule-level breakdown

| Rule | 2026-02-19 | 2026-02-23 (local) | After fixes | Δ net | Severity | Category | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G101 | 0 | 1 | **0** ✅ | **+1** | HIGH | Hardcoded credentials | **Fixed** (nosec) |
| G108 | 0 | 0 | 0 ✅ | — | HIGH | pprof endpoint | Previously fixed ✅ |
| G114 | 0 | 2 | **0** ✅ | **+2** | MEDIUM | HTTP server no timeout | **Fixed** |
| G115 | 2 | 2 | 2 | — | HIGH | Integer overflow | False positive |
| G117 | 20 | **22** | 22 | **+2** | MEDIUM | Secret field pattern | False positive |
| G201 | 3 | 3 | 3 | — | MEDIUM | SQL string formatting | False positive |
| G202 | 1 | 1 | 1 | — | MEDIUM | SQL string concat | False positive |
| G304 | 10 | 8 | 8 | **-2** | MEDIUM | File inclusion via variable | Accepted risk |
| G305 | 1 | 1 | 1 | — | MEDIUM | File traversal (zip/tar) | False positive |
| G701 | 10 | 4 | 4 | **-6** | HIGH | SQL injection (taint) | False positive |
| G703 | 0 | 0 | 0 ✅ | — | HIGH | Path traversal (env var) | Previously fixed ✅ |
| G704 | 37 | 41 | 41 | **+4** | HIGH | SSRF (taint) | Accepted risk |
| G706 | 0 | 12 | 12 | **+12** | LOW | Log injection (taint) | Accepted risk |

3 net-new findings (G101 ×1, G114 ×2) were fixed immediately — see Fixed Findings (2026-02-23 local) below.

---

---

## New Findings (2026-02-23 — local full scan)

### G101 HIGH/LOW — Potential hardcoded credentials — **FIXED (nosec)**

**File:** `internal/scm/azuredevops/connector.go:31`

**Finding:** gosec flags `entraTokenURLTemplate` as potential hardcoded credentials.

**Analysis:** The flagged constants are Microsoft Entra ID OAuth 2.0 URL templates:

```go
entraAuthURLTemplate  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
entraTokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
```

These are public well-known Microsoft endpoint URLs with a `%s` placeholder for the tenant ID.
No credentials (passwords, secrets, tokens) are present. Detection confidence is LOW.

**Fix applied:** Added `// #nosec G101` annotation with explanation comment. No code change required.

---

### G114 MEDIUM/HIGH — HTTP servers without timeout support (×2) — **FIXED**

**File:** `cmd/server/main.go:172, 184`

**Finding:** `http.ListenAndServe` does not allow setting read/write timeouts, leaving the
metrics and pprof side-channel servers vulnerable to slow-client / resource-exhaustion attacks.

**Analysis:** Although these are internal-only ports, defense-in-depth requires timeouts.
A misconfigured firewall or container network policy could expose these ports. Timeouts cost nothing.

**Fix applied:** Replaced both `http.ListenAndServe(addr, handler)` calls with explicit `http.Server`
struct instances with `ReadTimeout` and `WriteTimeout`:

- Metrics server: 10s read / 10s write (short scrape window)
- pprof server: 30s read / 30s write (profiling requests can be slower)

---

### G117 MEDIUM — Secret field pattern (+2, total now 22)

Two additional anonymous struct fields (`AccessToken`, `RefreshToken`) in
`internal/scm/azuredevops/connector.go` (lines 135–136, 186–187) are now flagged.
These are local response-parsing structs for Entra ID token responses — same false-positive pattern
as all other G117 findings.

**Verdict: FALSE POSITIVE — data model fields for API response parsing, not embedded secrets.**

---

### G706 LOW — Log injection (+1, total now 12)

The new `SETUP_TOKEN_FILE` path-rejection warning log (`cmd/server/main.go:316`) introduced
in our G703 fix is flagged. The logged value is the operator-supplied env var string —
not user request input.

**Accepted risk:** Operator config value; same pattern as all other G706 findings.

---

## Fixed Findings (2026-02-23 — local full scan)

### G101 — Potential hardcoded credentials (1 fixed)

Added `// #nosec G101` annotation with explanation on `entraAuthURLTemplate` /
`entraTokenURLTemplate` constants in `internal/scm/azuredevops/connector.go`.
Constants are public Microsoft OAuth endpoint URL templates, not credentials.

### G114 — HTTP server without read/write timeouts (2 fixed)

Replaced `http.ListenAndServe` with explicit `http.Server` structs in `cmd/server/main.go`:

| Server | ReadTimeout | WriteTimeout |
| --- | --- | --- |
| Prometheus metrics (`:9090`) | 10s | 10s |
| pprof (`:6060`) | 30s | 30s |

---

## New Findings (2026-02-23 — CI run)

### G108 HIGH — pprof profiling endpoint exposed — **FIXED**

**File:** `cmd/server/main.go:36`

**Finding:** `_ "net/http/pprof"` blank import auto-registers `/debug/pprof` handlers on `http.DefaultServeMux`.

**Analysis:** The Gin router is the handler for the main API server — `http.DefaultServeMux` is never passed
to `http.ListenAndServe` on the API address. pprof is served exclusively on a separate internal port
(`cfg.Telemetry.Profiling.Port`, default 6060) and only when `cfg.Telemetry.Profiling.Enabled=true`.
The handlers are unreachable via the public API listener regardless of configuration.

**Fix applied:** Added `// #nosec G108` annotation with explanation comment on the import. No behavioural
change needed; the architecture already isolates pprof correctly.

---

### G703 HIGH — Path traversal via `SETUP_TOKEN_FILE` environment variable — **FIXED**

**File:** `cmd/server/main.go:308`

**Finding:** `os.WriteFile(tokenFile, ...)` where `tokenFile` is sourced directly from `os.Getenv("SETUP_TOKEN_FILE")`.

**Analysis:** `SETUP_TOKEN_FILE` is an operator-supplied environment variable for container secret mounting.
An operator who sets it to a malicious path (e.g., `../../etc/cron.d/x`) already has host/container
admin access, making this a low-realistic-risk finding. However, defense-in-depth validation is
straightforward and appropriate.

**Fix applied:** Added `..` component check on the raw value and `filepath.Clean` before `os.WriteFile`.
Values containing `..` are rejected with a warning log. `// #nosec G703` annotation added at the write
site with explanation.

---

### G704 HIGH — SSRF via taint analysis (+4, total now 41)

Four additional `http.DefaultClient.Do(req)` call sites detected across the existing connector files.
All follow the identical admin-configured URL pattern accepted in previous scans.

**Accepted risk:** Same as all prior G704 findings. Total count updated to 41 in the table above.

---

### G706 LOW — Log injection via taint analysis (11 new findings, new rule)

All 11 findings are in server startup logging or cleanup error paths:

| File | Lines |
| --- | --- |
| `cmd/server/main.go` | L119, L122, L148, L309, L311, L332, L345 |
| `internal/api/admin/mirror.go` | L452 |
| `internal/api/admin/terraform_mirror.go` | L428 |
| `internal/api/modules/upload.go` | L249 |
| `internal/api/providers/upload.go` | L362 |

**Analysis:** All logged values are internal: database version integers, file paths constructed by the
application, error objects, or operator-supplied configuration strings. No raw user request input is
logged at these sites. Log injection is only exploitable when: (a) logs are parsed by a security tool
that can be confused by embedded newlines, and (b) the attacker controls the logged value. Neither
condition applies here.

**Accepted risk:** Internal values only; not user-controlled input. No code change required.

---

## New Findings (2026-02-19)

### G115 HIGH — Integer overflow conversion (1 new, total now 2)

**File:** `internal/scm/azuredevops/connector.go:520`

**Finding:** `int64(f.UncompressedSize64)` — gosec flags `uint64 → int64` conversion.

**Analysis:** `f.UncompressedSize64` comes from `archive/zip.File.UncompressedSize64`. A zip entry
with an uncompressed size > `math.MaxInt64` (≈ 9.2 EB) would overflow. In practice, the zip
source is an authenticated SCM repository and this size is never remotely approached.

**Verdict: FALSE POSITIVE — no realistic overflow; zip sizes are bounded by the format and practical limits.**

---

### G110 MEDIUM — Potential decompression bomb (1 new in azuredevops connector, total now 2) — **FIXED**

**File:** `internal/scm/azuredevops/connector.go:542`

**Finding:** `io.Copy` from a `zip.Reader` with no size limit.

**Fix applied:** Both G110 sites fixed immediately — see **Fixed Findings (2026-02-19)** below.

---

### G304 MEDIUM — File inclusion via variable (+3 net, total now 10)

`scm_publisher.go` gained 7 new G304 hits as new file operation code paths were added.
`local.go` reduced from 7 to 3 hits (4 removed via refactoring). Net change: +3.

| File | Lines now flagged |
| --- | --- |
| `internal/storage/local/local.go` | L61, L91, L177 |
| `internal/services/scm_publisher.go` | L117, L144, L264, L293, L354, L505, L542 |

**Analysis:** Same accepted-risk pattern as documented previously. Storage paths and publisher
paths are derived from validated namespace/name/version components, not raw user input.
Path traversal is prevented at the API layer.

**Accepted risk:** Inherent to filesystem storage and SCM archive extraction. Path construction
uses validated components throughout.

---

### G704 HIGH — SSRF via taint analysis (distribution shift, count unchanged at 37)

`internal/audit/shipper.go:305` is now flagged (SSRF); one other site resolved elsewhere,
keeping the total at 37. The new `shipper.go` entry follows the same admin-configured URL
pattern as all other G704 findings.

**Accepted risk:** Same as all G704 findings — admin-controlled configuration URLs.

---

## Fixed Findings (2026-02-23)

### G108 — pprof endpoint exposed (1 fixed)

Added `// #nosec G108` annotation with architectural explanation. No runtime change — Gin router
never uses `DefaultServeMux`; pprof is only reachable on its own internal port when explicitly enabled.

### G703 — Path traversal via `SETUP_TOKEN_FILE` (1 fixed)

Added validation: reject values containing `..` path-traversal sequences; apply `filepath.Clean`
before the `os.WriteFile` call; suppress with `// #nosec G703` and explanation comment.

---

## Fixed Findings (2026-02-19)

### G110 — Potential decompression bomb (2 fixed)

`io.Copy` calls with no size limit during archive extraction, vulnerable to decompression bombs.
Both sites fixed by wrapping the source reader in `io.LimitReader(r, maxExtractBytes)` (500 MB cap).
A package-level constant `maxExtractBytes = 500 << 20` was added to each file.

| File | Change |
| --- | --- |
| `internal/services/scm_publisher.go` | `io.Copy(f, tr)` → `io.Copy(f, io.LimitReader(tr, maxExtractBytes))` |
| `internal/scm/azuredevops/connector.go` | `io.Copy(tw, rc)` → `io.Copy(tw, io.LimitReader(rc, maxExtractBytes))` |

---

## Previously Fixed Findings (2026-02-17)

### G301 — Directory permissions should be 0750 or less (5 fixed)

Directories were created with `0755` (world-executable/readable). Changed to `0750`.

| File | Line | Change |
| --- | --- | --- |
| `internal/storage/local/local.go` | 34 | `0755` → `0750` (storage root) |
| `internal/storage/local/local.go` | 52 | `0755` → `0750` (upload subdirs) |
| `internal/services/scm_publisher.go` | 154 | `0755` → `0750` (temp extract dir) |
| `internal/services/scm_publisher.go` | 215 | `0755` → `0750` (tar dir entries) |
| `internal/services/scm_publisher.go` | 219 | `0755` → `0750` (tar file parent dirs) |

### G302 — File permissions should be 0600 or less (2 fixed)

Audit log files were created with `0644` (world-readable). Changed to `0600`.
Audit logs may contain sensitive user/action information and should be owner-readable only.

| File | Line | Change |
| --- | --- | --- |
| `internal/audit/shipper.go` | 325 | `0644` → `0600` (NewFileShipper) |
| `internal/audit/shipper.go` | 387 | `0644` → `0600` (rotate) |

---

## False Positives (no action required)

### G701 — SQL injection via taint analysis (10 occurrences)

**File:** `internal/api/admin/stats.go` (lines 61, 67, 73, 82, 88, 97, 103, 109, 116, 119)

**Finding:** gosec's taint analysis flags `QueryRowContext` calls even when the SQL string
is a **hardcoded string literal** with no user input. All 10 flagged queries are of the form:

```go
h.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users")
```

No user-controlled data is interpolated. These are entirely static SQL strings.
**Verdict: FALSE POSITIVE — gosec taint analysis overly broad on QueryRowContext.**

---

### G117 — Exported struct field matches secret pattern (20 occurrences)

**Files:** `internal/scm/provider.go`, `internal/scm/types.go`, and various SCM connectors.

**Finding:** Structs with a field named `Secret` (e.g., webhook secrets, OAuth tokens) in their
JSON representation. These are **data model fields** for API request/response bodies and
repository/provider configurations — not hardcoded credential strings.

**Verdict: FALSE POSITIVE — naming convention for webhook secrets, not embedded credentials.**

---

### G201/G202 — SQL string formatting / concatenation (4 occurrences, unchanged)

**Files:** `internal/db/repositories/provider_repository.go` (L585, L593–601),
`internal/db/repositories/module_repository.go` (L405), `internal/db/repositories/audit_repository.go` (L135)

**Finding:** `fmt.Sprintf` is used to compose SQL queries with a `whereClause` variable.

**Analysis:** The `whereClause` is built exclusively from SQL structural fragments containing
`$N` parameterized placeholders. No user input is embedded in the format string — all
user-controlled values (`query`, `namespace`, `orgID`) are passed as separate `args` to
the query driver. Example:

```go
// whereClause = "WHERE p.organization_id = $1 AND p.namespace ILIKE $2"
countQuery := fmt.Sprintf("SELECT COUNT(*) FROM providers p %s", whereClause)
r.db.QueryRowContext(ctx, countQuery, args...)  // user values in args, not in SQL string
```

**Verdict: FALSE POSITIVE — correct parameterized query pattern; structure is dynamic, values are not.**

---

### G305 — File traversal when extracting zip/tar archive (1 occurrence)

**File:** `internal/services/scm_publisher.go:250`

**Finding:** `io.Copy` writes to a file with a variable path from a tar header.

**Analysis:** Path traversal protection is explicitly implemented immediately before the write:

```go
target := filepath.Join(dest, header.Name)
if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
    return fmt.Errorf("invalid file path: %s", header.Name)
}
```

This is the canonical Go path traversal mitigation. gosec does not recognize it.

**Verdict: FALSE POSITIVE — traversal check already in place.**

---

### G115 — Integer overflow conversion (1 occurrence, scm_publisher.go only; azuredevops connector covered in New Findings)

**File:** `internal/services/scm_publisher.go:264`

**Finding:** `os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))` —
gosec reports `int64 → uint32` conversion risk.

**Analysis:** `os.FileMode` is `uint32`. `header.Mode` is `int64` from the tar spec, but
represents a Unix file mode (always ≤ 0o7777 = 4095), which trivially fits in uint32.
No realistic tar archive will have a mode value that causes overflow.

**Verdict: FALSE POSITIVE — no realistic overflow; tar modes are bounded by the format spec.**

---

## Accepted Risk (documented)

### G704 — SSRF via taint analysis (41 occurrences)

**Files:** `internal/scm/gitlab/connector.go` (many), `internal/scm/github/connector.go`,
`internal/scm/azuredevops/connector.go`, `internal/scm/bitbucket/connector.go`,
`internal/mirror/upstream.go`, `internal/audit/shipper.go` (L305)

**Finding:** HTTP requests are made to URLs derived from configuration (base URL + path).

**Analysis:** The URLs are sourced from:

1. Administrator-configured SCM provider settings (GitHub base URL, GitLab instance URL, etc.)
2. Mirror upstream registry URLs configured by administrators

An administrator who provides a malicious URL is misusing their own privileges.
The application does not forward arbitrary user-supplied URLs. No non-admin user can
inject URLs into these code paths.

**Accepted risk:** SSRF via admin-controlled configuration. Future enhancement: add an
explicit URL allowlist validation step when saving SCM provider configurations.

---

### G304 — File inclusion via variable (10 occurrences)

**Files:** `internal/storage/local/local.go` (L61, L91, L177), `internal/services/scm_publisher.go` (L117, L144, L264, L293, L354, L505, L542)

**Finding:** Files are opened/read/written using path variables.

**Analysis:** This is expected and necessary behavior for a filesystem storage backend
and SCM archive extraction. Storage paths are generated internally from namespaced keys
(e.g., `modules/ns/name/v/file.tar.gz`). Publisher paths are constructed from tar/zip
headers after path traversal validation.
User-controlled input does not reach these calls directly — paths are constructed by the
application from validated namespace/name/version components.

**Accepted risk:** Storage backend and publisher inherently require variable file paths. Path traversal
is prevented at the API and archive extraction layers.

---

## Run Command

```bash
cd backend
gosec -fmt json -out gosec-report.json -severity medium -confidence medium ./...
gosec -fmt text ./...
```
