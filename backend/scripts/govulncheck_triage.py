#!/usr/bin/env python3
"""govulncheck_triage.py — decide whether govulncheck findings should fail the build.

govulncheck exits non-zero for ANY reachable vulnerability, including advisories
that have no released fix. Gating merges on those makes the check permanently
red through no fault of the PR — the only way to "fix" it is to wait for
upstream — which trains everyone to ignore a security gate. This mirrors the
split scripts/osv_triage.py already applies to OSV-Scanner:

  * **fixable** — the advisory publishes a fixed version, so the dependency can
    be upgraded. FAILS the job.
  * **unfixable** — no fixed version published yet. Reported as a warning
    annotation and in the job summary, but does NOT fail the job.

The axis this script adds over osv_triage.py is reachability. govulncheck emits
a finding per scan level, and only a symbol-level one — a trace whose first
frame names a function — means "your code actually calls this". Findings that
are merely present in the module graph are reported as context and never gate,
because osv_triage.py already gates the "is there a fix available" axis across
the whole dependency tree.

Usage:
    python3 scripts/govulncheck_triage.py govulncheck-results.json
    python3 scripts/govulncheck_triage.py govulncheck-results.json --issue-body report.md

Exit codes: 0 = nothing fixable (may still have warned), 1 = fixable findings.
"""

from __future__ import annotations

import json
import os
import sys


def _messages(raw: str):
    """Yield each Message in govulncheck's JSON stream.

    The output is a series of concatenated objects rather than one array, so it
    has to be decoded incrementally.
    """
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(raw):
        while idx < len(raw) and raw[idx].isspace():
            idx += 1
        if idx >= len(raw):
            break
        message, idx = decoder.raw_decode(raw, idx)
        yield message


def triage(raw: str) -> tuple[list[dict], list[dict], list[dict]]:
    """Split findings into (fixable, unfixable, not_called), each flat dicts.

    Raises ValueError if the stream carries no config message, which means the
    scan never ran to completion — a truncated stream is still valid JSON with
    zero findings, and would otherwise read as a clean result.
    """
    saw_config = False
    called: dict[str, dict] = {}
    uncalled: dict[str, dict] = {}

    for message in _messages(raw):
        if "config" in message:
            saw_config = True
        finding = message.get("finding")
        if not finding:
            continue
        osv = finding.get("osv")
        trace = finding.get("trace") or []
        if not osv or not trace:
            continue
        frame = trace[0]
        entry = {
            "id": osv,
            "module": frame.get("module", "?"),
            "version": frame.get("version", "?"),
            "fixed": finding.get("fixed_version", ""),
        }
        # Frames are ordered vulnerable-symbol first; only a symbol-level
        # finding names a function.
        if frame.get("function"):
            called[osv] = entry
        else:
            uncalled.setdefault(osv, entry)

    if not saw_config:
        raise ValueError("no config message — govulncheck did not run to completion")

    for osv in called:
        uncalled.pop(osv, None)

    fixable = [e for e in called.values() if e["fixed"]]
    unfixable = [e for e in called.values() if not e["fixed"]]
    key = lambda e: e["id"]  # noqa: E731
    return sorted(fixable, key=key), sorted(unfixable, key=key), sorted(
        uncalled.values(), key=key
    )


def _describe(entry: dict) -> str:
    where = f"{entry['module']}@{entry['version']}"
    if entry["fixed"]:
        return f"{entry['id']}: {where} — fixed in {entry['fixed']}"
    return f"{entry['id']}: {where} — no fixed version published"


def render(fixable: list[dict], unfixable: list[dict], not_called: list[dict]) -> str:
    lines = ["## govulncheck triage", ""]
    if fixable:
        lines += [f"### ❌ Reachable and fixable ({len(fixable)}) — upgrade required", ""]
        lines += [f"- {_describe(e)}" for e in fixable] + [""]
    if unfixable:
        lines += [
            f"### ⚠️ Reachable, no fix available ({len(unfixable)}) — not blocking",
            "",
            "Your code calls these, but there is nothing to upgrade to yet, so "
            "they do not fail the build. They start failing the moment upstream "
            "publishes a fix.",
            "",
        ]
        lines += [f"- {_describe(e)}" for e in unfixable] + [""]
    if not_called:
        lines += [
            f"### Present but not called ({len(not_called)})",
            "",
            "In the module graph, but no call path reaches them. OSV-Scanner "
            "triage covers whether these are upgradable.",
            "",
        ]
        lines += [f"- {_describe(e)}" for e in not_called] + [""]
    if not fixable and not unfixable and not not_called:
        lines.append("No vulnerabilities reported.")
    return "\n".join(lines)


def main() -> int:
    # The report uses non-ASCII (— ❌ ⚠️). CI runners are UTF-8, but a redirected
    # stdout on a cp1252 console is not, and the crash looks like a scan failure.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

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
            "usage: govulncheck_triage.py <govulncheck-results.json> "
            "[--issue-body <path>]",
            file=sys.stderr,
        )
        return 2
    path = args[0]

    def _bail(message: str) -> int:
        """Fail closed, and leave a body behind if one was asked for.

        Matches osv_triage.py: the caller reads the body file unconditionally,
        so not writing one turns a scanner failure into a confusing "file not
        found" crash in a later step instead of a report saying what went wrong.
        """
        print(f"::error::{message}", file=sys.stderr)
        if issue_body_path:
            with open(issue_body_path, "w", encoding="utf-8") as fh:
                fh.write(
                    "## govulncheck triage\n\n"
                    f"❌ Could not triage the scan results: {message}\n\n"
                    "The scanner did not produce usable output, so this run "
                    "proves nothing about the dependency tree. Treat it as a "
                    "failed scan, not a clean one.\n"
                )
        return 1

    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return _bail(f"govulncheck results file not found: {path}")

    try:
        fixable, unfixable, not_called = triage(raw)
    except json.JSONDecodeError as exc:
        return _bail(f"govulncheck results file is not valid JSON: {exc}")
    except ValueError as exc:
        return _bail(str(exc))

    for entry in unfixable:
        print(f"::warning::{_describe(entry)}")
    for entry in fixable:
        print(f"::error::{_describe(entry)}")

    summary = render(fixable, unfixable, not_called)
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
            f"\n{len(fixable)} reachable vulnerability(ies) have a published fix — "
            "upgrade the affected dependencies.",
            file=sys.stderr,
        )
        return 1
    if unfixable:
        print(
            f"\n{len(unfixable)} reachable vulnerability(ies) have no published "
            "fix; not failing the build.",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
