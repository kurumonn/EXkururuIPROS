#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8787}"
WORKSPACE="${WORKSPACE:-lab}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

echo "failure injection checks: base=$BASE_URL workspace=$WORKSPACE"

echo "[1] admin token missing should be 401"
code_1=$(curl -sS -o /dev/null -w "%{http_code}" "$BASE_URL/api/v1/admin/workspaces/waf/?workspace_slug=$WORKSPACE")
echo "  status=$code_1"

if [[ -n "$ADMIN_TOKEN" ]]; then
  echo "[2] invalid admin token should be 403"
  code_2=$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}x" \
    "$BASE_URL/api/v1/admin/workspaces/waf/?workspace_slug=$WORKSPACE")
  echo "  status=$code_2"
fi

echo "[3] sensor auth missing should be 401/403"
code_3=$(curl -sS -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/api/v1/workspaces/$WORKSPACE/sensors/demo/events/batch/" \
  -H "Content-Type: application/json" \
  -d '{"events":[]}')
echo "  status=$code_3"

echo "[4] rate limit smoke test (summary endpoint)"
codes=$(for _ in $(seq 1 80); do curl -sS -o /dev/null -w "%{http_code}\n" "$BASE_URL/api/v1/dashboard/summary/"; done)
count_429=$(echo "$codes" | awk '$1=="429"{c++} END{print c+0}')
echo "  http_429_count=$count_429"

echo "[5] health endpoint should stay available"
code_5=$(curl -sS -o /dev/null -w "%{http_code}" "$BASE_URL/healthz")
echo "  status=$code_5"

echo "done"
