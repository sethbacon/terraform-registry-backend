#!/usr/bin/env bash
# dr-drill.sh — Automated disaster recovery drill for the Terraform Registry.
#
# This script validates backup/restore procedures by:
#   1. Taking a fresh database backup (pg_dump)
#   2. Restoring it to a test database
#   3. Verifying data integrity (row counts, schema version)
#   4. Optionally verifying object storage backup
#   5. Recording RPO/RTO metrics
#
# Usage:
#   ./scripts/dr-drill.sh [--db-host HOST] [--db-name NAME] [--db-user USER]
#       [--test-db-name NAME] [--skip-storage] [--output FILE]
#
# Prerequisites:
#   - pg_dump and pg_restore available
#   - psql available
#   - Database credentials (via env or flags)
#
set -euo pipefail

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------
DB_HOST="${TFR_DATABASE_HOST:-localhost}"
DB_PORT="${TFR_DATABASE_PORT:-5432}"
DB_NAME="${TFR_DATABASE_NAME:-terraform_registry}"
DB_USER="${TFR_DATABASE_USER:-postgres}"
TEST_DB_NAME="dr_drill_restore_$(date +%s)"
SKIP_STORAGE=false
OUTPUT_FILE=""
DRILL_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DRILL_LOG=""

# --------------------------------------------------------------------------
# Parse arguments
# --------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --db-host)      DB_HOST="$2"; shift 2 ;;
    --db-port)      DB_PORT="$2"; shift 2 ;;
    --db-name)      DB_NAME="$2"; shift 2 ;;
    --db-user)      DB_USER="$2"; shift 2 ;;
    --test-db-name) TEST_DB_NAME="$2"; shift 2 ;;
    --skip-storage) SKIP_STORAGE=true; shift ;;
    --output)       OUTPUT_FILE="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
log() {
  local msg="[$(date -u +%H:%M:%S)] $1"
  echo "$msg"
  DRILL_LOG="${DRILL_LOG}${msg}\n"
}

elapsed_since() {
  local start_epoch=$1
  local now_epoch
  now_epoch=$(date +%s)
  echo $(( now_epoch - start_epoch ))
}

cleanup() {
  log "Cleaning up test database ${TEST_DB_NAME}..."
  psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
    -c "DROP DATABASE IF EXISTS ${TEST_DB_NAME};" 2>/dev/null || true
  if [[ -f "${BACKUP_FILE:-}" ]]; then
    rm -f "$BACKUP_FILE"
  fi
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Pre-flight
# --------------------------------------------------------------------------
log "=== Terraform Registry DR Drill ==="
log "Started: ${DRILL_START}"
log "Source database: ${DB_HOST}:${DB_PORT}/${DB_NAME}"
log "Test database: ${TEST_DB_NAME}"

for cmd in pg_dump pg_restore psql; do
  if ! command -v "$cmd" &>/dev/null; then
    log "ERROR: Required command '$cmd' not found"
    exit 1
  fi
done

# Verify source database connectivity
log "Verifying source database connectivity..."
STEP_START=$(date +%s)
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" >/dev/null
log "  Source database reachable ($(elapsed_since $STEP_START)s)"

# --------------------------------------------------------------------------
# Step 1: Backup
# --------------------------------------------------------------------------
log ""
log "=== Step 1: Database Backup ==="
BACKUP_FILE="/tmp/dr-drill-backup-$(date +%Y%m%d%H%M%S).dump"
STEP_START=$(date +%s)

log "  Running pg_dump (custom format)..."
pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -Fc "$DB_NAME" > "$BACKUP_FILE"
BACKUP_SIZE=$(stat -c%s "$BACKUP_FILE" 2>/dev/null || stat -f%z "$BACKUP_FILE" 2>/dev/null || echo "unknown")
BACKUP_DURATION=$(elapsed_since $STEP_START)

log "  Backup complete: ${BACKUP_FILE}"
log "  Size: ${BACKUP_SIZE} bytes"
log "  Duration: ${BACKUP_DURATION}s"

# --------------------------------------------------------------------------
# Step 2: Restore to test database
# --------------------------------------------------------------------------
log ""
log "=== Step 2: Database Restore ==="
STEP_START=$(date +%s)

log "  Creating test database ${TEST_DB_NAME}..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
  -c "CREATE DATABASE ${TEST_DB_NAME};"

log "  Restoring from backup..."
pg_restore -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$TEST_DB_NAME" \
  --no-owner --no-acl "$BACKUP_FILE" 2>/dev/null || true
RESTORE_DURATION=$(elapsed_since $STEP_START)

log "  Restore complete"
log "  Duration: ${RESTORE_DURATION}s"

# --------------------------------------------------------------------------
# Step 3: Verify data integrity
# --------------------------------------------------------------------------
log ""
log "=== Step 3: Data Integrity Verification ==="
STEP_START=$(date +%s)
VERIFY_PASS=true

# Schema version
ORIGINAL_SCHEMA=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
  -tAc "SELECT MAX(version) FROM schema_migrations;" 2>/dev/null || echo "unknown")
RESTORED_SCHEMA=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$TEST_DB_NAME" \
  -tAc "SELECT MAX(version) FROM schema_migrations;" 2>/dev/null || echo "unknown")

if [[ "$ORIGINAL_SCHEMA" == "$RESTORED_SCHEMA" ]]; then
  log "  ✓ Schema version matches: ${ORIGINAL_SCHEMA}"
else
  log "  ✗ Schema version mismatch: original=${ORIGINAL_SCHEMA}, restored=${RESTORED_SCHEMA}"
  VERIFY_PASS=false
fi

# Row count verification for critical tables
for table in users modules providers api_keys organizations audit_logs; do
  ORIGINAL_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
    -tAc "SELECT COUNT(*) FROM ${table};" 2>/dev/null || echo "N/A")
  RESTORED_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$TEST_DB_NAME" \
    -tAc "SELECT COUNT(*) FROM ${table};" 2>/dev/null || echo "N/A")

  if [[ "$ORIGINAL_COUNT" == "$RESTORED_COUNT" ]]; then
    log "  ✓ ${table}: ${ORIGINAL_COUNT} rows"
  else
    log "  ✗ ${table}: original=${ORIGINAL_COUNT}, restored=${RESTORED_COUNT}"
    VERIFY_PASS=false
  fi
done

VERIFY_DURATION=$(elapsed_since $STEP_START)
log "  Verification duration: ${VERIFY_DURATION}s"

# --------------------------------------------------------------------------
# Step 4: Object storage verification (optional)
# --------------------------------------------------------------------------
if [[ "${SKIP_STORAGE}" == "false" ]]; then
  log ""
  log "=== Step 4: Object Storage Verification ==="
  log "  Checking storage backend accessibility..."

  # Check S3 (if AWS CLI available)
  if command -v aws &>/dev/null && [[ -n "${TFR_STORAGE_S3_BUCKET:-}" ]]; then
    STEP_START=$(date +%s)
    OBJECT_COUNT=$(aws s3 ls "s3://${TFR_STORAGE_S3_BUCKET}/" --recursive --summarize 2>/dev/null | grep "Total Objects:" | awk '{print $3}' || echo "N/A")
    log "  S3 bucket ${TFR_STORAGE_S3_BUCKET}: ${OBJECT_COUNT} objects"
    log "  Duration: $(elapsed_since $STEP_START)s"
  fi

  # Check Azure Blob (if az CLI available)
  if command -v az &>/dev/null && [[ -n "${TFR_STORAGE_AZURE_CONTAINER:-}" ]]; then
    STEP_START=$(date +%s)
    BLOB_COUNT=$(az storage blob list --container-name "${TFR_STORAGE_AZURE_CONTAINER}" --query "length(@)" 2>/dev/null || echo "N/A")
    log "  Azure container ${TFR_STORAGE_AZURE_CONTAINER}: ${BLOB_COUNT} blobs"
    log "  Duration: $(elapsed_since $STEP_START)s"
  fi

  # Check filesystem
  if [[ -d "${TFR_STORAGE_FILESYSTEM_PATH:-/data/modules}" ]]; then
    FILE_COUNT=$(find "${TFR_STORAGE_FILESYSTEM_PATH:-/data/modules}" -type f 2>/dev/null | wc -l)
    log "  Filesystem: ${FILE_COUNT} files"
  fi
else
  log ""
  log "=== Step 4: Object Storage Verification (SKIPPED) ==="
fi

# --------------------------------------------------------------------------
# Step 5: Calculate RPO/RTO
# --------------------------------------------------------------------------
log ""
log "=== DR Metrics ==="
TOTAL_RTO=$((BACKUP_DURATION + RESTORE_DURATION + VERIFY_DURATION))
log "  Backup duration (RPO window):  ${BACKUP_DURATION}s"
log "  Restore duration:              ${RESTORE_DURATION}s"
log "  Verification duration:         ${VERIFY_DURATION}s"
log "  Total RTO (backup+restore):    ${TOTAL_RTO}s"
log ""

if [[ "${VERIFY_PASS}" == "true" ]]; then
  log "=== DRILL RESULT: PASS ==="
else
  log "=== DRILL RESULT: FAIL — data integrity issues detected ==="
fi

DRILL_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
log "Completed: ${DRILL_END}"

# --------------------------------------------------------------------------
# Step 6: Write output report
# --------------------------------------------------------------------------
if [[ -n "${OUTPUT_FILE}" ]]; then
  cat > "${OUTPUT_FILE}" << EOF
{
  "drill_start": "${DRILL_START}",
  "drill_end": "${DRILL_END}",
  "source_database": "${DB_HOST}:${DB_PORT}/${DB_NAME}",
  "backup_size_bytes": ${BACKUP_SIZE:-0},
  "backup_duration_seconds": ${BACKUP_DURATION},
  "restore_duration_seconds": ${RESTORE_DURATION},
  "verification_duration_seconds": ${VERIFY_DURATION},
  "total_rto_seconds": ${TOTAL_RTO},
  "schema_version_original": "${ORIGINAL_SCHEMA}",
  "schema_version_restored": "${RESTORED_SCHEMA}",
  "data_integrity_pass": ${VERIFY_PASS},
  "result": "$([ "${VERIFY_PASS}" == "true" ] && echo "PASS" || echo "FAIL")"
}
EOF
  log "Report written to: ${OUTPUT_FILE}"
fi
