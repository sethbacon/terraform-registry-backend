#!/usr/bin/env bash
# Assert per-package coverage minimums for security-critical packages
set -euo pipefail
PACKAGES=(
  "github.com/terraform-registry/terraform-registry/internal/auth"
  "github.com/terraform-registry/terraform-registry/internal/middleware"
)
MIN=80
for pkg in "${PACKAGES[@]}"; do
  # Use the full import path (no "./" prefix) so go test treats it as a module path.
  coverage=$(go test -coverprofile=/tmp/pkg-coverage.out "${pkg}/..." 2>/dev/null && \
    go tool cover -func=/tmp/pkg-coverage.out | grep "^total:" | awk '{print $3}' | tr -d '%')
  if awk -v cov="${coverage}" -v thr="${MIN}" 'BEGIN { exit !(cov + 0 < thr + 0) }'; then
    echo "FAIL: ${pkg} coverage ${coverage}% is below minimum ${MIN}%"
    exit 1
  fi
  echo "PASS: ${pkg} coverage ${coverage}% >= ${MIN}%"
done
echo "All package coverage checks passed"
