#!/usr/bin/env python3
"""Sync repository documentation into the GitHub wiki.

This script mirrors selected markdown files from the repository into a
local clone of the GitHub wiki, applying the conventions GitHub wikis
use (page-name-with-dashes filenames, no subdirectories, no relative
.md links). It is intended to run from CI on every push to ``main``
that touches documentation, but can also be run locally:

    python scripts/sync-wiki.py --wiki <path-to-wiki-clone>

The script is idempotent: re-running with no source changes produces
no diff in the wiki working tree.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent

# Source files (relative to REPO_ROOT). Order controls the sidebar order
# inside each group.
DOCS_DIR = REPO_ROOT / "docs"
TOP_LEVEL_PAGES: list[str] = [
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "RELEASING.md",
    "CHANGELOG.md",
]

# Subdirectory display labels for the sidebar.
SECTION_LABELS = {
    "_top": "Overview",
    "docs": "Documentation",
    "docs/deployment": "Deployment",
    "docs/compliance": "Compliance",
    "docs/adr": "Architecture Decisions",
}

# Files we never publish to the wiki.
EXCLUDE_NAMES = {
    "CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    "THIRD_PARTY_NOTICES.md",
    "NOTICE",
    "LICENSE",
}

# ---------------------------------------------------------------------------
# Path conversion
# ---------------------------------------------------------------------------

ACRONYMS = {
    "adr": "ADR",
    "aks": "AKS",
    "eks": "EKS",
    "gke": "GKE",
    "api": "API",
    "rbac": "RBAC",
    "oidc": "OIDC",
    "jwt": "JWT",
    "cli": "CLI",
    "scm": "SCM",
    "soc2": "SOC2",
    "iso27001": "ISO27001",
    "pprof": "pprof",
}


def titlecase_token(token: str) -> str:
    if not token:
        return token
    lower = token.lower()
    if lower in ACRONYMS:
        return ACRONYMS[lower]
    # Normalize SHOUTING_CASE filenames (README, CONTRIBUTING, ...) to Title Case.
    if token.isupper() and len(token) > 1:
        return token[:1].upper() + token[1:].lower()
    return token[:1].upper() + token[1:]


def stem_to_pagename(stem: str) -> str:
    parts = re.split(r"[-_]", stem)
    return "-".join(titlecase_token(p) for p in parts if p)


def repo_path_to_wiki_name(rel_path: str) -> str:
    """Convert a repo-relative markdown path to a wiki page filename.

    Examples:
        docs/api-reference.md            -> API-Reference.md
        docs/deployment/aks-new-cluster.md -> Deployment-AKS-New-Cluster.md
        docs/adr/001-scope-based-rbac.md -> ADR-001-Scope-Based-RBAC.md
        README.md                        -> Home.md
    """
    if rel_path == "README.md":
        return "Home.md"
    p = Path(rel_path)
    stem = p.stem
    parent_parts = list(p.parent.parts)
    # Drop a leading "docs" prefix; everything else is preserved as a
    # capitalized prefix.
    if parent_parts and parent_parts[0] == "docs":
        parent_parts = parent_parts[1:]
    name_parts = []
    for part in parent_parts:
        name_parts.append(stem_to_pagename(part))
    name_parts.append(stem_to_pagename(stem))
    return "-".join(name_parts) + ".md"


# ---------------------------------------------------------------------------
# Link rewriting
# ---------------------------------------------------------------------------

LINK_RE = re.compile(r"(!?)\[([^\]]*)\]\(([^)]+)\)")


def build_link_map(source_files: list[Path]) -> dict[str, str]:
    """Return mapping from various forms of repo-relative path -> wiki page name (no .md)."""
    m: dict[str, str] = {}
    for src in source_files:
        rel = src.relative_to(REPO_ROOT).as_posix()
        wiki_stem = repo_path_to_wiki_name(rel)[:-3]  # strip .md
        # forms we want to match in links
        m[rel] = wiki_stem
        m[Path(rel).name] = wiki_stem  # bare filename
        # also the ./ form
        m["./" + rel] = wiki_stem
    return m


def rewrite_link(target: str, link_map: dict[str, str], current_dir: str) -> str:
    """Rewrite a single link target to its wiki form, or return unchanged."""
    raw = target.strip()
    # Skip absolute URLs, anchors, and mailto.
    if (
        re.match(r"^[a-zA-Z]+://", raw)
        or raw.startswith("#")
        or raw.startswith("mailto:")
    ):
        return target
    # Split off optional anchor.
    anchor = ""
    if "#" in raw:
        path_part, anchor = raw.split("#", 1)
        anchor = "#" + anchor
    else:
        path_part = raw
    if not path_part:
        return target
    # Resolve the target relative to the source file's directory.
    if path_part.startswith("/"):
        normalized = path_part.lstrip("/")
    else:
        normalized = os.path.normpath(os.path.join(current_dir, path_part)).replace(
            "\\", "/"
        )
    if normalized in link_map:
        return link_map[normalized] + anchor
    # Try just the bare filename (relative file in same dir).
    base = os.path.basename(normalized)
    if base in link_map:
        return link_map[base] + anchor
    return target


def rewrite_links(content: str, link_map: dict[str, str], current_dir: str) -> str:
    def repl(match: re.Match[str]) -> str:
        bang, text, target = match.group(1), match.group(2), match.group(3)
        if bang == "!":  # image; leave alone
            return match.group(0)
        new_target = rewrite_link(target, link_map, current_dir)
        return f"[{text}]({new_target})"

    return LINK_RE.sub(repl, content)


# ---------------------------------------------------------------------------
# Page transformation
# ---------------------------------------------------------------------------

DISABLE_COMMENT_RE = re.compile(
    r"^\s*<!--\s*markdownlint-disable[^>]*-->\s*\r?\n", re.MULTILINE
)


def transform_page(
    content: str,
    rel_path: str,
    link_map: dict[str, str],
    source_url_base: str,
) -> str:
    """Transform a single page's content for the wiki."""
    # Strip markdownlint disable comments — wiki rendering doesn't use them.
    content = DISABLE_COMMENT_RE.sub("", content, count=5)
    current_dir = str(Path(rel_path).parent.as_posix())
    if current_dir == ".":
        current_dir = ""
    content = rewrite_links(content, link_map, current_dir)
    # Add a small footer noting the source.
    footer = (
        f"\n\n---\n\n"
        f"_This page is auto-generated from "
        f"[`{rel_path}`]({source_url_base}/{rel_path}). "
        f"Edit the source file in the repository, not the wiki._\n"
    )
    return content.rstrip() + footer


# ---------------------------------------------------------------------------
# Sidebar / Home
# ---------------------------------------------------------------------------


def sidebar_section(title: str, entries: list[tuple[str, str]]) -> str:
    if not entries:
        return ""
    lines = [f"### {title}"]
    for label, page in entries:
        lines.append(f"- [{label}]({page})")
    return "\n".join(lines) + "\n"


def display_label_from_page(page: str) -> str:
    return page.replace("-", " ")


def build_sidebar(grouped: dict[str, list[tuple[str, str]]]) -> str:
    parts = ["## Navigation\n"]
    parts.append("- [Home](Home)\n")
    order = ["_top", "docs", "docs/deployment", "docs/adr", "docs/compliance"]
    for key in order:
        if key not in grouped:
            continue
        title = SECTION_LABELS.get(key, key)
        parts.append(sidebar_section(title, grouped[key]))
    # Anything else (shouldn't happen, but stable fallback).
    for key in sorted(grouped.keys()):
        if key in order:
            continue
        title = SECTION_LABELS.get(key, key)
        parts.append(sidebar_section(title, grouped[key]))
    return "\n".join(parts).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Source discovery
# ---------------------------------------------------------------------------


def discover_sources() -> list[Path]:
    files: list[Path] = []
    for name in TOP_LEVEL_PAGES:
        p = REPO_ROOT / name
        if p.is_file():
            files.append(p)
    if DOCS_DIR.is_dir():
        for p in sorted(DOCS_DIR.rglob("*.md")):
            if p.name in EXCLUDE_NAMES:
                continue
            files.append(p)
    return files


def group_for_sidebar(rel_path: str) -> str:
    p = Path(rel_path)
    parts = p.parts
    if len(parts) == 1:
        return "_top"
    if parts[0] == "docs":
        if len(parts) == 2:
            return "docs"
        return f"docs/{parts[1]}"
    return parts[0]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def read_version() -> str | None:
    manifest = REPO_ROOT / ".release-please-manifest.json"
    if manifest.is_file():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            for v in data.values():
                return v
        except Exception:  # pragma: no cover
            return None
    return None


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wiki",
        required=True,
        type=Path,
        help="Path to a local clone of the wiki repository.",
    )
    parser.add_argument(
        "--source-url-base",
        default="https://github.com/sethbacon/terraform-registry-backend/blob/main",
        help="Base URL used in the auto-generated source-link footer.",
    )
    args = parser.parse_args(argv)
    wiki: Path = args.wiki.resolve()
    if not (wiki / ".git").exists() and not (wiki.parent / ".git").exists():
        # Allow either: an actual git clone OR any directory (for dry runs).
        print(f"warning: {wiki} does not look like a git clone", file=sys.stderr)

    sources = discover_sources()
    if not sources:
        print("No source markdown files found; nothing to do.", file=sys.stderr)
        return 1

    link_map = build_link_map(sources)

    # Wipe previously-generated *.md files in the wiki root (preserve hidden,
    # _Footer.md if hand-curated, and any non-md assets like images/).
    for existing in wiki.glob("*.md"):
        existing.unlink()

    grouped: dict[str, list[tuple[str, str]]] = {}
    for src in sources:
        rel = src.relative_to(REPO_ROOT).as_posix()
        wiki_name = repo_path_to_wiki_name(rel)
        wiki_stem = wiki_name[:-3]
        content = src.read_text(encoding="utf-8")
        transformed = transform_page(
            content, rel, link_map, args.source_url_base.rstrip("/")
        )
        (wiki / wiki_name).write_text(transformed, encoding="utf-8", newline="\n")
        if rel != "README.md":  # README becomes Home, don't list separately
            grouped.setdefault(group_for_sidebar(rel), []).append(
                (display_label_from_page(wiki_stem), wiki_stem)
            )

    # Always (re)write _Sidebar.md.
    (wiki / "_Sidebar.md").write_text(
        build_sidebar(grouped), encoding="utf-8", newline="\n"
    )

    # Optionally append a version badge to Home.md.
    version = read_version()
    if version:
        home = wiki / "Home.md"
        if home.is_file():
            home_text = home.read_text(encoding="utf-8")
            badge = f"\n\n> **Version:** v{version}\n"
            if "**Version:**" not in home_text.split("\n", 5)[-1]:
                # insert badge right after the first heading line
                lines = home_text.splitlines(keepends=True)
                for i, line in enumerate(lines):
                    if line.startswith("# "):
                        lines.insert(i + 1, badge)
                        break
                home.write_text("".join(lines), encoding="utf-8", newline="\n")

    print(f"Synced {len(sources)} pages to {wiki}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
