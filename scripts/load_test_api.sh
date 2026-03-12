#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8787}"
CONCURRENCY="${CONCURRENCY:-20}"
TOTAL_REQUESTS="${TOTAL_REQUESTS:-1000}"
TIMEOUT_SEC="${TIMEOUT_SEC:-5}"
OUT_FILE="${OUT_FILE:-/tmp/kururuIPROS-loadtest.tsv}"

if ! command -v xargs >/dev/null 2>&1; then
  echo "xargs is required" >&2
  exit 1
fi

rm -f "$OUT_FILE"
touch "$OUT_FILE"

echo "start load test: base=$BASE_URL concurrency=$CONCURRENCY total=$TOTAL_REQUESTS"

seq "$TOTAL_REQUESTS" | xargs -n1 -P"$CONCURRENCY" -I{} bash -c '
  start_ms=$(date +%s%3N)
  code=$(curl -sS -o /dev/null -m "'"$TIMEOUT_SEC"'" -w "%{http_code}" "'"$BASE_URL"'/api/v1/dashboard/summary/" || echo "000")
  end_ms=$(date +%s%3N)
  rt_ms=$((end_ms - start_ms))
  echo -e "{}\t${code}\t${rt_ms}" >> "'"$OUT_FILE"'"
'

total=$(wc -l < "$OUT_FILE" | tr -d " ")
ok=$(awk -F"\t" '$2 ~ /^2/ {c++} END{print c+0}' "$OUT_FILE")
too_many=$(awk -F"\t" '$2 == "429" {c++} END{print c+0}' "$OUT_FILE")
failed=$((total - ok))
p95=$(awk -F"\t" 'BEGIN{n=0} {a[n++]=$3} END{if(n==0){print 0; exit}; asort(a); idx=int((n-1)*0.95)+1; print a[idx]}' "$OUT_FILE")
p99=$(awk -F"\t" 'BEGIN{n=0} {a[n++]=$3} END{if(n==0){print 0; exit}; asort(a); idx=int((n-1)*0.99)+1; print a[idx]}' "$OUT_FILE")

echo "result:"
echo "  total=$total ok_2xx=$ok non_2xx=$failed http_429=$too_many"
echo "  p95_ms=$p95 p99_ms=$p99"
echo "  detail=$OUT_FILE"
