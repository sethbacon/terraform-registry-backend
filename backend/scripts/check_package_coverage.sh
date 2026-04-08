#!/usr/bin/env bash
# Assert per-package coverage minimums for security-critical packages
set -e
PACKAGES=(
  "github.com/terraform-registry/terraform-registry/internal/auth"
  "github.com/terraform-registry/terraform-registry/internal/middleware"
)
MIN=80
for pkg in "${PACKAGES[@]}"; do
  coverage=$(go test -coverprofile=/tmp/pkg-coverage.out "./$pkg/..." 2>/dev/null && \
    go tool cover -func=/tmp/pkg-coverage.out | grep "^total:" | awk '{print $3}' | tr -d '%')
  if (( $(echo "$coverage < $MIN" | bc -l) )); then
    echo "FAIL: $pkg coverage $coverage% is below minimum $MIN%"
    exit 1
  fi
done
echo "All package coverage checks passed"
