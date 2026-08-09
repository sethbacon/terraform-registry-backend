#!/usr/bin/env python3
"""osv_triage.py — decide whether OSV-Scanner findings should fail the build.

OSV-Scanner exits non-zero for ANY known vulnerability, including advisories
that have no released fix. Gating merges on those makes the check permanently
red through no fault of the PR — the only way to "fix" it is to wait for
upstream — which trains everyone to ignore a security gate.

So this splits findings in two:

  * **fixable** — the advisory names a fixed version for the package we
    actually have. The dependency can be upgraded, so this FAILS the job.
  * **unfixable** — no fixed version published yet. Reported as a warning
    annotation and in the job summary, but does NOT fail the job.

Reachability is deliberately not considered here; the separate govulncheck job
covers that axis.

Usage:
    python3 scripts/osv_triage.py osv-results.json
    python3 scripts/osv_triage.py osv-results.json --issue-body report.md

--issue-body writes the same rendered report to a file so the weekly workflow
can use it as a GitHub issue body. Before this existed, the weekly run filed an
issue whose entire content was "Please review the workflow logs" for ANY
finding, fixable or not -- so an advisory with no published fix (issue #776 was
one) reopened a fresh, contentless issue every week that had to be triaged by
hand against logs that expire.

Exit codes: 0 = nothing fixable (may still have warned), 1 = fixable findings.
"""

from __future__ import annotations

import json
import os
import sys


def _fixed_versions(vuln: dict, pkg_name: str, ecosystem: str) -> list[str]:
    """Fixed versions this advisory publishes for pkg_name, if any.

    Only `affected` entries matching the package we actually depend on count —
    an advisory can cover several packages, and a fix for a sibling package
    does not make our version upgradable.
    """
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        apkg = affected.get("package") or {}
        if apkg.get("name") != pkg_name:
            continue
        # Ecosystem is compared only when both sides declare one.
        aeco = apkg.get("ecosystem")
        if aeco and ecosystem and aeco != ecosystem:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed.append(event["fixed"])
    return sorted(set(fixed))


def triage(data: dict) -> tuple[list[dict], list[dict]]:
    """Split findings into (fixable, unfixable), each a list of flat dicts."""
    fixable: list[dict] = []
    unfixable: list[dict] = []
    for result in data.get("results") or []:
        source = (result.get("source") or {}).get("path", "?")
        for package in result.get("packages") or []:
            pkg = package.get("package") or {}
            name = pkg.get("name", "?")
            version = pkg.get("version", "?")
            ecosystem = pkg.get("ecosystem", "")
            for vuln in package.get("vulnerabilities") or []:
                fixed = _fixed_versions(vuln, name, ecosystem)
                entry = {
                    "id": vuln.get("id", "?"),
                    "package": name,
                    "version": version,
                    "source": source,
                    "fixed": fixed,
                }
                (fixable if fixed else unfixable).append(entry)
    return fixable, unfixable


def _describe(entry: dict) -> str:
    where = f"{entry['package']}@{entry['version']} ({entry['source']})"
    if entry["fixed"]:
        return f"{entry['id']}: {where} — fixed in {', '.join(entry['fixed'])}"
    return f"{entry['id']}: {where} — no fixed version published"


def render(fixable: list[dict], unfixable: list[dict]) -> str:
    lines = ["## OSV-Scanner triage", ""]
    if fixable:
        lines += [f"### ❌ Fixable ({len(fixable)}) — upgrade required", ""]
        lines += [f"- {_describe(e)}" for e in fixable] + [""]
    if unfixable:
        lines += [
            f"### ⚠️ No fix available ({len(unfixable)}) — not blocking",
            "",
            "Tracked, but no upstream fix exists yet, so these do not fail the "
            "build. See the govulncheck job for whether they are reachable.",
            "",
        ]
        lines += [f"- {_describe(e)}" for e in unfixable] + [""]
    if not fixable and not unfixable:
        lines.append("No vulnerabilities reported.")
    return "\n".join(lines)


def main() -> int:
    args = sys.argv[1:]
    issue_body_path = None
    if "--issue-body" in args:
        i = args.index("--issue-body")
        if i + 1 >= len(args):
            print("--issue-body requires a path", file=sys.stderr)
            return 2
        issue_body_path = args[i + 1]
        del args[i : i + 2]
    if len(args) != 1:
        print(
            "usage: osv_triage.py <osv-results.json> [--issue-body <path>]",
            file=sys.stderr,
        )
        return 2
    path = args[0]

    def _bail(message: str) -> int:
        """Fail closed, and leave a body behind if one was asked for.

        The caller creates an issue whenever this exits non-zero and reads the
        body file unconditionally, so not writing one here would turn a scanner
        failure into a confusing "file not found" crash in a later workflow
        step instead of a report that says what actually went wrong.
        """
        print(f"::error::{message}", file=sys.stderr)
        if issue_body_path:
            with open(issue_body_path, "w", encoding="utf-8") as fh:
                fh.write(
                    "## OSV-Scanner triage\n\n"
                    f"❌ Could not triage the scan results: {message}\n\n"
                    "The scanner did not produce usable output, so this run "
                    "proves nothing about the dependency tree. Treat it as a "
                    "failed scan, not a clean one.\n"
                )
        return 1

    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        # No results file means the scanner failed before writing output —
        # fail closed rather than silently passing the gate.
        return _bail(f"OSV results file not found: {path}")
    except json.JSONDecodeError as exc:
        return _bail(f"OSV results file is not valid JSON: {exc}")

    fixable, unfixable = triage(data)

    for entry in unfixable:
        print(f"::warning::{_describe(entry)}")
    for entry in fixable:
        print(f"::error::{_describe(entry)}")

    summary = render(fixable, unfixable)
    print(summary)
    if issue_body_path:
        with open(issue_body_path, "w", encoding="utf-8") as fh:
            fh.write(summary + "\n")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")

    if fixable:
        print(
            f"\n{len(fixable)} vulnerability(ies) have a published fix — "
            "upgrade the affected dependencies.",
            file=sys.stderr,
        )
        return 1
    if unfixable:
        print(
            f"\n{len(unfixable)} vulnerability(ies) have no published fix; "
            "not failing the build.",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
