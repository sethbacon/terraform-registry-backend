#!/usr/bin/env bash
# update-gosec-baseline.sh — regenerate gosec-baseline.json from a fresh scan.
#
# Run this after:
#   - Adding or removing #nosec annotations
#   - Fixing real security findings
#   - Adding new accepted-risk findings to the codebase
#
# Then commit gosec-baseline.json alongside the code change.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Running gosec to regenerate baseline..."
cd "$BACKEND_DIR"
gosec -fmt json -out gosec-baseline.json ./...

echo ""
echo "gosec-baseline.json updated."
echo "Review with: git diff gosec-baseline.json"
echo "Then commit: git add gosec-baseline.json && git commit -m 'security: update gosec baseline'"
