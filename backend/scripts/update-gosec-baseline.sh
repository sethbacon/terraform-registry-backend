#!/usr/bin/env bash
# update-gosec-baseline.sh — regenerate gosec-baseline.json from a fresh scan.
#
# Run this after:
#   - Adding or removing #nosec annotations
#   - Fixing real security findings
#   - Adding new accepted-risk findings to the codebase
#
# gosec-baseline.json is the accepted-risk register for this backend: any finding
# it contains is silently suppressed by CI's gosec-compare.py (see .github/CODEOWNERS,
# which requires @security-team review on this file). If this run adds any NEW
# unsuppressed (nosec:false) finding to the baseline — i.e. you are accepting a risk
# rather than just absorbing line-number drift on already-accepted findings — you
# must pass -r/--reason so the acceptance is recorded in gosec-baseline-exceptions.md.
#
# Usage:
#   bash scripts/update-gosec-baseline.sh
#   bash scripts/update-gosec-baseline.sh --reason "G104: intentionally unchecked, see #123"
#
# Then commit gosec-baseline.json (and gosec-baseline-exceptions.md, if updated)
# alongside the code change.
set -euo pipefail

REASON=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--reason)
      REASON="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [-r|--reason \"justification text\"]" >&2
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASELINE="$BACKEND_DIR/gosec-baseline.json"
EXCEPTIONS_LOG="$BACKEND_DIR/gosec-baseline-exceptions.md"

BEFORE_COUNT=0
if [[ -f "$BASELINE" ]]; then
  BEFORE_COUNT=$(jq '[.Issues[]? | select(.nosec == false)] | length' "$BASELINE")
fi

echo "Running gosec to regenerate baseline..."
cd "$BACKEND_DIR"
gosec -fmt json -out gosec-baseline.json ./...

AFTER_COUNT=$(jq '[.Issues[]? | select(.nosec == false)] | length' "$BASELINE")

echo ""
echo "gosec-baseline.json updated (${BEFORE_COUNT} -> ${AFTER_COUNT} unsuppressed findings)."

if [[ "$AFTER_COUNT" -gt "$BEFORE_COUNT" ]]; then
  if [[ -z "$REASON" ]]; then
    echo "" >&2
    echo "ERROR: this regeneration added $((AFTER_COUNT - BEFORE_COUNT)) new accepted-risk" >&2
    echo "finding(s) to the baseline (findings that were not already in it, and are not" >&2
    echo "suppressed with an inline // #nosec comment). Re-run with a justification:" >&2
    echo "" >&2
    echo "  bash scripts/update-gosec-baseline.sh --reason \"<why this is accepted>\"" >&2
    echo "" >&2
    exit 1
  fi
  {
    echo ""
    echo "## $(date -u +%Y-%m-%d) — $(git -C "$BACKEND_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo ""
    echo "- **Findings:** ${BEFORE_COUNT} -> ${AFTER_COUNT} (+$((AFTER_COUNT - BEFORE_COUNT)))"
    echo "- **Reason:** ${REASON}"
  } >> "$EXCEPTIONS_LOG"
  echo "Recorded justification in $(basename "$EXCEPTIONS_LOG")."
fi

echo "Review with: git diff gosec-baseline.json"
echo "Then commit: git add gosec-baseline.json gosec-baseline-exceptions.md && git commit -m 'security: update gosec baseline'"

