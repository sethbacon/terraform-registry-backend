#!/usr/bin/env python3
"""
gosec-compare.py — diff a fresh gosec scan against the committed baseline.

Usage:
    python3 scripts/gosec-compare.py \\
        --results  gosec-results.json \\
        --baseline gosec-baseline.json \\
        --base-dir /path/to/backend \\
        --output   /tmp/issue-body.md   # optional; written when new findings exist

Exit codes:
    0  No new unsuppressed findings.
    1  One or more new findings detected (CI should create a GitHub issue).
"""

import argparse
import json
import os
import sys
from pathlib import Path


def _anchor(code: str) -> str:
    """Return all meaningful code lines, with gosec line-number prefixes stripped.

    Uses the full snippet gosec reports (not just the first two lines) so that
    structurally similar but distinct findings — e.g. Go's repetitive
    io.ReadAll(resp.Body)/resp.Body.Close() error-handling idiom recurring at
    different call sites in the same file — don't collapse onto the same
    fingerprint (#655). Line numbers are still stripped from each line so the
    fingerprint keeps surviving line-number drift from unrelated edits
    elsewhere in the file.
    """
    stripped = []
    for raw in code.splitlines():
        s = raw.strip()
        if not s:
            continue
        # gosec format: "123: actual code"
        if ": " in s:
            s = s.split(": ", 1)[1].strip()
        stripped.append(s)
    return " | ".join(stripped)


# Top-level directories that immediately follow the module root in any path layout.
# Used to strip OS-specific absolute prefixes for cross-platform fingerprinting.
_MODULE_ROOT_MARKERS = (
    "/internal/", "/cmd/", "/pkg/", "/scripts/",
    "/api/", "/docs/", "/test/", "/vendor/",
)


def _normalize_path(raw_file: str, base_dir: Path) -> str:
    """
    Return a portable, platform-independent relative path.

    Handles three situations:
    - Path is already relative (CI, Linux)
    - Path is absolute on the same OS (local dev, same platform)
    - Path is absolute on a *different* OS (Windows baseline loaded in Linux CI)
    """
    # Normalise to forward slashes first.
    norm = raw_file.replace("\\", "/")
    base_fwd = str(base_dir).replace("\\", "/").rstrip("/") + "/"

    # Happy-path: base_dir prefix matches.
    if norm.startswith(base_fwd):
        return norm[len(base_fwd):]

    # Cross-platform fallback: find the first known module-root marker.
    # e.g. "C:/dev/…/backend/internal/foo/bar.go" → "internal/foo/bar.go"
    for marker in _MODULE_ROOT_MARKERS:
        idx = norm.find(marker)
        if idx >= 0:
            return norm[idx + 1:]  # drop the leading "/"

    # Last resort: return as-is (normalised slashes).
    return norm


def fingerprint(issue: dict, base_dir: Path) -> str:
    """
    Stable fingerprint that survives line-number drift *and* OS path differences.
    Key: rule_id + relative_file + details_string + first-two-code-lines-content
    """
    rule = issue.get("rule_id", "")
    rel = _normalize_path(issue.get("file", ""), base_dir)
    details = issue.get("details", "")
    anchor = _anchor(issue.get("code", ""))
    return f"{rule}:{rel}:{details}:{anchor}"


def load_findings(path: str, base_dir: Path) -> tuple[dict, dict]:
    """Return (fingerprint→issue dict of unsuppressed findings, stats dict)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    issues = data.get("Issues") or []
    active = [i for i in issues if not i.get("nosec", False)]
    fps: dict[str, dict] = {}
    for issue in active:
        fp = fingerprint(issue, base_dir)
        fps[fp] = issue
    return fps, data.get("Stats", {})


def scan_integrity_problems(path: str) -> list[str]:
    """Reasons this gosec run must not be read as a clean scan.

    A run that analysed nothing writes `"Issues": []` — byte-identical to a run
    that analysed everything and found nothing. Everything downstream then works
    correctly on an empty universe: no fingerprints, so no new findings, so
    exit 0, so a green required check certifying a scan that never happened.
    `gosec ... || true` in CI discards the one signal that would have shown it.

    Stats.files was already being read here, and printed. Printing a number into
    the log of a run that passes is not a check — nobody opens it.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    problems: list[str] = []

    files = (data.get("Stats") or {}).get("files")
    if not files:
        problems.append(
            f"gosec reports {files!r} files scanned. An empty result set from an "
            "empty scan is indistinguishable from a clean one, so this cannot be "
            "read as passing."
        )

    # gosec records per-package compile failures here and still exits reporting
    # whatever it managed to parse. Findings from a package that did not build
    # are absent rather than absent-because-clean.
    errors = data.get("Golang errors") or {}
    if errors:
        where = ", ".join(sorted(errors)[:5])
        problems.append(
            f"gosec recorded Go compile errors in {len(errors)} package(s) "
            f"({where}). Those packages were not analysed, so the finding set is "
            "incomplete rather than clean."
        )

    return problems


def _rel(issue: dict, base_dir: Path) -> str:
    return _normalize_path(issue.get("file", "?"), base_dir)


def build_issue_body(new_issues: list[dict], resolved_count: int, base_dir: Path) -> str:
    ref = os.environ.get("GITHUB_REF_NAME", "<branch>")
    sha = os.environ.get("GITHUB_SHA", "<sha>")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "<owner/repo>")
    run_id = os.environ.get("GITHUB_RUN_ID", "<run>")

    lines = [
        "## \U0001f6a8 New gosec Security Findings",
        "",
        f"The security scan found **{len(new_issues)} new finding(s)** not present in the committed baseline.",
        "",
        "| | |",
        "|---|---|",
        f"| Branch | `{ref}` |",
        f"| Commit | `{sha[:12]}` |",
        f"| Workflow run | [{run_id}]({server}/{repo}/actions/runs/{run_id}) |",
        f"| Resolved (now gone) | {resolved_count} |",
        "",
        "### New Findings",
        "",
    ]

    for issue in new_issues:
        rule = issue.get("rule_id", "?")
        severity = issue.get("severity", "?")
        confidence = issue.get("confidence", "?")
        details = issue.get("details", "?")
        line = issue.get("line", "?")
        code = issue.get("code", "").strip()
        cwe = issue.get("cwe") or {}
        cwe_str = f" — [CWE-{cwe['id']}]({cwe['url']})" if cwe else ""
        rel = _rel(issue, base_dir)

        lines += [
            f"#### `{rule}` · {severity}/{confidence} — {details}{cwe_str}",
            f"**File:** `{rel}` line {line}",
            "```go",
            code,
            "```",
            "",
            f"> If this is a false positive, add `// #nosec {rule} -- <reason>` to the flagged line, "
            f"then regenerate the baseline with `bash scripts/update-gosec-baseline.sh` and commit both.",
            "",
        ]

    lines += [
        "---",
        "_Auto-created by the [`gosec` CI job](/.github/workflows/ci.yml). "
        "Close once all findings are fixed, suppressed, or added to the baseline with justification._",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare gosec results to baseline.")
    parser.add_argument("--results",  required=True, help="Path to fresh gosec JSON output")
    parser.add_argument("--baseline", required=True, help="Path to committed baseline JSON")
    parser.add_argument("--base-dir", default=".",    help="Repo base dir for relative paths")
    parser.add_argument("--output",   default=None,   help="Write issue body markdown to this file")
    args = parser.parse_args()

    base_dir = Path(args.base_dir).resolve()

    # Before comparing anything: a comparison against an empty scan is arithmetic
    # on nothing, and it produces the same exit 0 as a genuinely clean repo.
    problems = scan_integrity_problems(args.results)
    if problems:
        print("\U0001f6a8 gosec did not produce a usable scan:")
        for problem in problems:
            print(f"  - {problem}")
        body = "\n".join(
            ["## gosec produced no usable scan", ""]
            + [f"- {problem}" for problem in problems]
            + [
                "",
                "This is not a report of new findings. The scan itself did not run "
                "to completion, so the comparison against the baseline was skipped "
                "rather than passed.",
            ]
        )
        if args.output:
            Path(args.output).write_text(body, encoding="utf-8")
        sys.exit(1)

    current,  stats_cur  = load_findings(args.results,  base_dir)
    baseline, stats_base = load_findings(args.baseline, base_dir)

    new_fps      = set(current) - set(baseline)
    resolved_fps = set(baseline) - set(current)

    new_issues      = [current[fp]  for fp in sorted(new_fps)]
    resolved_issues = [baseline[fp] for fp in sorted(resolved_fps)]

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"Files scanned  : {stats_cur.get('files', '?')}")
    print(f"Lines scanned  : {stats_cur.get('lines', '?')}")
    print(f"nosec suppressed: {stats_cur.get('nosec', '?')}")
    print(f"Active findings: {len(current)}  (baseline: {len(baseline)})")
    print(f"New            : {len(new_issues)}")
    print(f"Resolved       : {len(resolved_issues)}")

    if resolved_issues:
        print("\n\u2705 Resolved (in baseline but no longer present — consider pruning baseline):")
        for i in resolved_issues:
            print(f"  [{i['rule_id']}] {_rel(i, base_dir)}:{i.get('line','?')} — {i.get('details','')}")

    if not new_issues:
        print("\n\u2705 No new security findings — scan clean.")
        sys.exit(0)

    # ── New findings ───────────────────────────────────────────────────────────
    print("\n\U0001f6a8 NEW findings not in baseline:")
    for i in new_issues:
        print(f"  [{i['rule_id']}] {i.get('severity','?')}/{i.get('confidence','?')} "
              f"{_rel(i, base_dir)}:{i.get('line','?')} — {i.get('details','')}")

    body = build_issue_body(new_issues, len(resolved_issues), base_dir)

    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
        print(f"\nIssue body written to: {args.output}")

    sys.exit(1)


if __name__ == "__main__":
    main()
