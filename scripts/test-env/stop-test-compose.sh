#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
echo "Stopping test compose from ${ROOT_DIR}"
docker compose -f "${ROOT_DIR}/deployments/docker-compose.test.yml" down --volumes
echo "Test compose stopped and volumes removed."
