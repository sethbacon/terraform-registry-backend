#!/usr/bin/env bash
# Assert per-package coverage minimums for security-critical packages.
# Tests only the exact package (not sub-packages) to avoid diluting the total
# with low-coverage sub-packages like auth/azuread or auth/oidc.
set -euo pipefail

# "package|minimum" pairs. Minimums follow the risk-based tiering documented
# in ci.yml's coverage-threshold step comment (85-95% security/core logic),
# set a few points below each package's actual coverage at the time this gate
# was added so it catches regressions without blocking on aspirational targets.
PACKAGES=(
  "github.com/terraform-registry/terraform-registry/internal/auth|79"
  "github.com/terraform-registry/terraform-registry/internal/middleware|79"
  "github.com/terraform-registry/terraform-registry/internal/db/repositories|85"
  "github.com/terraform-registry/terraform-registry/internal/archiver|80"
  "github.com/terraform-registry/terraform-registry/internal/api/modules|62"
  "github.com/terraform-registry/terraform-registry/internal/api/providers|77"
  "github.com/terraform-registry/terraform-registry/internal/mirror|83"
  "github.com/terraform-registry/terraform-registry/internal/policy|77"
)
for entry in "${PACKAGES[@]}"; do
  pkg="${entry%%|*}"
  min="${entry##*|}"
  # Test the exact package only (not sub-packages) and discard stdout/stderr.
  go test -coverprofile=/tmp/pkg-coverage.out "${pkg}" >/dev/null 2>&1 || true
  coverage=$(go tool cover -func=/tmp/pkg-coverage.out | grep "^total:" | awk '{print $3}' | tr -d '%')
  if awk -v cov="${coverage}" -v thr="${min}" 'BEGIN { exit !(cov + 0 < thr + 0) }'; then
    echo "FAIL: ${pkg} coverage ${coverage}% is below minimum ${min}%"
    exit 1
  fi
  echo "PASS: ${pkg} coverage ${coverage}% >= ${min}%"
done
echo "All package coverage checks passed"
