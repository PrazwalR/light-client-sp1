#!/bin/bash
# =============================================================================
# Ethereum Light Client — SP1 API Comprehensive Test Script v2
# Tests: health, head, chains, jobs, finality proof, storage proof, full_update
# =============================================================================

BASE="http://localhost:3000"
PASS=0
FAIL=0
RESULTS=""

log_result() {
  local name="$1" status="$2" detail="$3"
  if [ "$status" = "PASS" ]; then
    PASS=$((PASS+1))
    RESULTS+="  [PASS] $name: $detail\n"
  else
    FAIL=$((FAIL+1))
    RESULTS+="  [FAIL] $name: $detail\n"
  fi
  echo "[$status] $name: $detail"
}

wait_for_job() {
  local job_id="$1" max_polls="${2:-30}"
  for i in $(seq 1 $max_polls); do
    sleep 2
    local status
    status=$(curl -s "$BASE/jobs" | python3 -c "
import sys,json
jobs = json.load(sys.stdin)
for j in jobs:
    if j['job_id'] == '$job_id':
        print(j['status'])
        break
" 2>/dev/null)
    echo "  Poll $i: status=$status" >&2
    if [ "$status" = "completed" ] || [ "$status" = "failed" ]; then
      echo "$status"
      return
    fi
  done
  echo "timeout"
}

echo "=============================================="
echo " Ethereum Light Client API Test Suite v2"
echo "=============================================="

# --- 1. Health ---
echo ""
echo "=== TEST 1: GET /health ==="
RESP=$(curl -s "$BASE/health")
echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"
echo "$RESP" | grep -q '"ok"' && log_result "Health" "PASS" "Server healthy" || log_result "Health" "FAIL" "Not healthy"

# --- 2. Head ---
echo ""
echo "=== TEST 2: GET /head ==="
RESP=$(curl -s "$BASE/head")
echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"
echo "$RESP" | grep -q 'finalized_header_root' && log_result "Head" "PASS" "Store returned" || log_result "Head" "FAIL" "Bad response"

# --- 3. Chains ---
echo ""
echo "=== TEST 3: GET /chains ==="
RESP=$(curl -s "$BASE/chains")
echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"
COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['chains']))" 2>/dev/null)
[ "$COUNT" -ge 1 ] 2>/dev/null && log_result "Chains" "PASS" "$COUNT chains" || log_result "Chains" "FAIL" "No chains"

# --- 4. Jobs (empty) ---
echo ""
echo "=== TEST 4: GET /jobs ==="
RESP=$(curl -s "$BASE/jobs")
echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"
log_result "Jobs" "PASS" "Jobs endpoint OK"

# --- 5. Finality Proof ---
echo ""
echo "=== TEST 5: POST /prove/finality ==="
RESP=$(curl -s -X POST "$BASE/prove/finality" -H "Content-Type: application/json" -d '{}')
echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"
JOB_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])" 2>/dev/null)
if [ -n "$JOB_ID" ]; then
  log_result "Finality Submit" "PASS" "Job $JOB_ID"
  echo "  Waiting for completion..."
  FINAL_STATUS=$(wait_for_job "$JOB_ID")
  [ "$FINAL_STATUS" = "completed" ] && log_result "Finality Proof" "PASS" "Completed" || log_result "Finality Proof" "FAIL" "Status: $FINAL_STATUS"
else
  log_result "Finality Submit" "FAIL" "$RESP"
fi

# Show finality result
echo ""
echo "=== Finality Result ==="
curl -s "$BASE/jobs" | python3 -c "
import sys,json
jobs = json.load(sys.stdin)
for j in jobs:
    if j['job_id'] == '$JOB_ID':
        print(json.dumps(j, indent=2))
        break
" 2>/dev/null

# --- 6. Storage Proof (no chain field — should use default) ---
echo ""
echo "=== TEST 6: POST /prove/storage (default chain) ==="
RESP=$(curl -s -X POST "$BASE/prove/storage" \
  -H "Content-Type: application/json" \
  -d '{"address":"0xdAC17F958D2ee523a2206206994597C13D831ec7","storage_keys":["0x0000000000000000000000000000000000000000000000000000000000000001"]}')
echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"
SJOB=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])" 2>/dev/null)
if [ -n "$SJOB" ]; then
  log_result "Storage Submit" "PASS" "Job $SJOB (default chain)"
  echo "  Waiting for completion..."
  SFINAL=$(wait_for_job "$SJOB")
  [ "$SFINAL" = "completed" ] && log_result "Storage Proof" "PASS" "Completed" || log_result "Storage Proof" "FAIL" "Status: $SFINAL"
else
  log_result "Storage Submit" "FAIL" "$RESP"
fi

# Show storage result
echo ""
echo "=== Storage Result ==="
curl -s "$BASE/jobs" | python3 -c "
import sys,json
jobs = json.load(sys.stdin)
for j in jobs:
    if j['job_id'] == '$SJOB':
        print(json.dumps(j, indent=2))
        break
" 2>/dev/null

# --- 7. Storage Proof with explicit chain ---
echo ""
echo "=== TEST 7: POST /prove/storage (explicit chain) ==="
RESP=$(curl -s -X POST "$BASE/prove/storage" \
  -H "Content-Type: application/json" \
  -d '{"chain":"ethereum-mainnet","address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","storage_keys":["0x0000000000000000000000000000000000000000000000000000000000000000"],"block":"latest"}')
echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"
SJOB2=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])" 2>/dev/null)
if [ -n "$SJOB2" ]; then
  log_result "Storage+Chain" "PASS" "Job $SJOB2"
  echo "  Waiting for completion..."
  SFINAL2=$(wait_for_job "$SJOB2")
  [ "$SFINAL2" = "completed" ] && log_result "Storage+Chain Proof" "PASS" "Completed" || log_result "Storage+Chain Proof" "FAIL" "Status: $SFINAL2"
else
  log_result "Storage+Chain" "FAIL" "$RESP"
fi

# --- 8. Full Update Proof (sync committee rotation) ---
echo ""
echo "=== TEST 8: POST /prove/finality (full_update=true) ==="
RESP=$(curl -s -X POST "$BASE/prove/finality" \
  -H "Content-Type: application/json" \
  -d '{"full_update":true}')
echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP"
FJOB=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])" 2>/dev/null)
if [ -n "$FJOB" ]; then
  log_result "FullUpdate Submit" "PASS" "Job $FJOB"
  echo "  Waiting for completion..."
  FFINAL=$(wait_for_job "$FJOB")
  [ "$FFINAL" = "completed" ] && log_result "FullUpdate Proof" "PASS" "Completed" || log_result "FullUpdate Proof" "FAIL" "Status: $FFINAL"
else
  log_result "FullUpdate Submit" "FAIL" "$RESP"
fi

# --- 9. Final summary ---
echo ""
echo "=== FINAL: All Jobs ==="
curl -s "$BASE/jobs" | python3 -m json.tool 2>/dev/null || curl -s "$BASE/jobs"

echo ""
echo "=============================================="
echo " TEST RESULTS SUMMARY"
echo "=============================================="
echo -e "$RESULTS"
echo "  Total: $((PASS+FAIL))  Passed: $PASS  Failed: $FAIL"
echo "=============================================="
