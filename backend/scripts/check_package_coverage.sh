#!/usr/bin/env bash
# Assert per-package coverage minimums for security-critical packages.
# Tests only the exact package (not sub-packages) so a low-coverage sub-package
# can't quietly dilute its parent's total — each sub-package that needs a floor
# gets its own explicit entry below instead.
set -euo pipefail

# "package|minimum" pairs. Minimums follow the risk-based tiering documented in
# ci.yml's coverage-threshold step comment (85-95% for security/core logic,
# 80% repo-wide hard floor for everything else). auth, middleware, and
# db/repositories are held to that 80% floor (and additionally target the
# 85-95% tier); minimums are set a few points below each package's actual
# coverage at the time this gate was last reviewed so it catches regressions
# without requiring every run to hit the exact current number. SSO provider
# sub-packages (azuread/ldap/mtls/oidc/saml) and api/modules are explicit
# exceptions, carved out below the 80% floor rather than silently excluded:
# each gets its own dedicated minimum pinned to its actual current coverage
# (well under 80% for several of them) so regressions are still caught, while
# raising them to the floor remains separate, not-yet-done test-writing work.
PACKAGES=(
  "github.com/terraform-registry/terraform-registry/internal/auth|87"
  "github.com/terraform-registry/terraform-registry/internal/auth/azuread|64"
  "github.com/terraform-registry/terraform-registry/internal/auth/ldap|34"
  "github.com/terraform-registry/terraform-registry/internal/auth/mtls|96"
  "github.com/terraform-registry/terraform-registry/internal/auth/oidc|98"
  "github.com/terraform-registry/terraform-registry/internal/auth/saml|56"
  "github.com/terraform-registry/terraform-registry/internal/middleware|82"
  "github.com/terraform-registry/terraform-registry/internal/db/repositories|85"
  "github.com/terraform-registry/terraform-registry/internal/archiver|80"
  "github.com/terraform-registry/terraform-registry/internal/api/modules|65"
  "github.com/terraform-registry/terraform-registry/internal/api/providers|80"
  "github.com/terraform-registry/terraform-registry/internal/mirror|83"
  "github.com/terraform-registry/terraform-registry/internal/policy|80"
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
