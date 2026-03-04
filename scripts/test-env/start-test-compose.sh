#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
echo "Starting test compose from ${ROOT_DIR}"
docker compose -f "${ROOT_DIR}/deployments/docker-compose.test.yml" up -d --build
echo "Services started. Backend: http://localhost:8080, Frontend: http://localhost:3000"
