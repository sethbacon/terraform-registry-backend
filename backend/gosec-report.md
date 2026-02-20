# Backend Security Scan Report — gosec

**Scan date:** 2026-02-19
**Previous scan:** 2026-02-17
**Tool:** [gosec](https://github.com/securego/gosec) v2.23.0
**Scope:** `./...` (all Go packages)
**Filters:** `-severity medium -confidence medium`
**Files scanned:** 96 | **Lines scanned:** 26,563 (was 25,036; +1,527 lines)

---

## Summary

| Severity | 2026-02-17 | 2026-02-19 | After fixes | Delta |
| --- | --- | --- | --- | --- |
| HIGH | 48 | 49 | 49 | +1 |
| MEDIUM | 33 | 37 | 35 | **+2** |
| LOW | 0 | 0 | 0 | — |
| **Total** | **81** | **86** | **84** | **+3** |

The 2 G110 decompression-bomb findings were fixed immediately (see Fixed Findings below).

### Rule-level breakdown

| Rule | 2026-02-17 | 2026-02-19 | After fixes | Δ net | Severity | Category |
| --- | --- | --- | --- | --- | --- | --- |
| G115 | 1 | 2 | 2 | **+1** | HIGH | Integer overflow |
| G701 | 10 | 10 | 10 | — | HIGH | SQL injection (taint) |
| G704 | 37 | 37 | 37 | — | HIGH | SSRF (taint) |
| G110 | 1 | 2 | **0** ✅ | **-1** | MEDIUM | Decompression bomb |
| G117 | 20 | 20 | 20 | — | MEDIUM | Secret field pattern |
| G201 | 3 | 3 | 3 | — | MEDIUM | SQL string formatting |
| G202 | 1 | 1 | 1 | — | MEDIUM | SQL string concat |
| G304 | 7 | 10 | 10 | **+3** | MEDIUM | File inclusion via variable |
| G305 | 1 | 1 | 1 | — | MEDIUM | File traversal (zip/tar) |

All 49 HIGH-severity findings are **false positives** or **accepted risk** (documented below).
The 5 net-new findings since the previous scan are documented below; 2 of them (G110) were immediately fixed.

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

### G704 — SSRF via taint analysis (37 occurrences)

**Files:** `internal/scm/gitlab/connector.go` (many), `internal/scm/github/connector.go`,
`internal/scm/azuredevops/connector.go`, `internal/scm/bitbucket/connector.go`,
`internal/mirror/upstream.go`, `internal/audit/shipper.go` (L305, new in this scan)

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
