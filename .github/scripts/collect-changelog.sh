#!/usr/bin/env bash
# .github/scripts/collect-changelog.sh
#
# Collects ## Changelog entries from PR bodies merged to development since
# the last release tag and prints a formatted CHANGELOG.md block.
#
# Usage:
#   .github/scripts/collect-changelog.sh [previous-tag]
#   .github/scripts/collect-changelog.sh v0.2.25
#
# If previous-tag is omitted the most recent git tag is used automatically.
# Requires: gh CLI, jq

set -euo pipefail

PREVIOUS_TAG="${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo "")}"

if [ -z "$PREVIOUS_TAG" ]; then
  echo "No previous tag found — collecting all merged PRs." >&2
  SINCE_FILTER=""
else
  SINCE_DATE=$(git log -1 --format=%cI "$PREVIOUS_TAG" 2>/dev/null || echo "")
  echo "Collecting entries merged after $PREVIOUS_TAG ($SINCE_DATE)" >&2
  SINCE_FILTER="merged:>${SINCE_DATE}"
fi

# Fetch merged PRs to development
PRS=$(gh pr list \
  --base development \
  --state merged \
  --search "$SINCE_FILTER" \
  --json number,title,body,mergedAt \
  --limit 100)

PR_COUNT=$(echo "$PRS" | jq 'length')
echo "Found $PR_COUNT merged PRs to development since $PREVIOUS_TAG" >&2
echo "" >&2

TODAY=$(date -u +%Y-%m-%d)
NEW_VERSION="${2:-UNRELEASED}"

echo "## [$NEW_VERSION] - $TODAY"
echo ""

declare -A SECTIONS
SECTIONS[feat]=""
SECTIONS[fix]=""
SECTIONS[chore]=""
SECTIONS[docs]=""
SECTIONS[perf]=""
SECTIONS[refactor]=""

MISSING=()

while IFS= read -r pr; do
  NUMBER=$(echo "$pr" | jq -r '.number')
  TITLE=$(echo "$pr" | jq -r '.title')
  BODY=$(echo "$pr" | jq -r '.body // ""')

  # Extract bullet lines under ## Changelog until next ## header
  ENTRIES=$(printf '%s' "$BODY" | awk '/^## Changelog/{found=1;next} found && /^##/{exit} found && /^- /{print}')

  if [ -z "$ENTRIES" ]; then
    MISSING+=("#$NUMBER: $TITLE")
    continue
  fi

  while IFS= read -r entry; do
    TYPE=$(echo "$entry" | sed 's/^- \([a-z]*\):.*/\1/')
    if [[ -v SECTIONS[$TYPE] ]]; then
      SECTIONS[$TYPE]+="$entry"$'\n'
    else
      SECTIONS[chore]+="$entry"$'\n'
    fi
  done <<< "$ENTRIES"
done < <(echo "$PRS" | jq -c '.[]')

# Print sections in order
for section_key in feat fix perf refactor docs chore; do
  content="${SECTIONS[$section_key]}"
  if [ -n "$content" ]; then
    case $section_key in
      feat)     echo "### Added" ;;
      fix)      echo "### Fixed" ;;
      perf)     echo "### Performance" ;;
      refactor) echo "### Changed" ;;
      docs)     echo "### Documentation" ;;
      chore)    echo "### Maintenance" ;;
    esac
    echo "$content"
  fi
done

# Warn about PRs with no changelog entry
if [ ${#MISSING[@]} -gt 0 ]; then
  echo "" >&2
  echo "⚠️  These PRs had no ## Changelog entry:" >&2
  for m in "${MISSING[@]}"; do
    echo "   $m" >&2
  done
fi
