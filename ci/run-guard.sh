#!/usr/bin/env bash
# usage: run-guard.sh <schema.sql> <pass|fail>
#   pass — guard must exit 0 (clean schema)
#   fail — guard must exit non-zero (schema with violations)
set -euo pipefail

SCHEMA="${1:?usage: run-guard.sh <schema.sql> <pass|fail>}"
EXPECT="${2:?usage: run-guard.sh <schema.sql> <pass|fail>}"
DB_URL="${DATABASE_URL:?DATABASE_URL is not set}"

echo "--- loading $SCHEMA"
psql "$DB_URL" -v ON_ERROR_STOP=1 -q -f "$SCHEMA"

echo "--- running rls-guard"
set +e
psql "$DB_URL" -v ON_ERROR_STOP=1 -f rls-guard.sql
rc=$?
set -e

if [ "$EXPECT" = "pass" ]; then
  if [ "$rc" -ne 0 ]; then
    echo "::error::rls-guard reported findings on a clean schema (rc=$rc)"
    exit 1
  fi
  echo "OK: guard passed on clean schema"
elif [ "$EXPECT" = "fail" ]; then
  if [ "$rc" -eq 0 ]; then
    echo "::error::rls-guard missed known violations (rc=0)"
    exit 1
  fi
  echo "OK: guard correctly caught violations (rc=$rc)"
else
  echo "unknown expectation: $EXPECT (want pass|fail)"
  exit 2
fi
