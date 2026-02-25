#!/bin/bash
# Test all Light Client API Server endpoints on localhost:3000

BASE="http://localhost:3000"

echo "=== Light Client API Server Test Suite ==="
echo ""

echo "--- 1. GET /health ---"
curl -s "$BASE/health"
echo ""
echo ""

echo "--- 2. GET /head ---"
curl -s "$BASE/head"
echo ""
echo ""

echo "--- 3. GET /chains ---"
curl -s "$BASE/chains"
echo ""
echo ""

echo "--- 4. GET /jobs ---"
curl -s "$BASE/jobs"
echo ""
echo ""

echo "--- 5. POST /prove/finality (empty JSON body) ---"
RESULT=$(curl -s -X POST -H "Content-Type: application/json" -d '{}' "$BASE/prove/finality")
echo "$RESULT"
echo ""
echo ""

echo "--- 6. Waiting 15s for finality proof to complete ---"
sleep 15

echo "--- 7. GET /jobs (after finality proof) ---"
curl -s "$BASE/jobs"
echo ""
echo ""

echo "--- 8. POST /prove/storage (USDC slot 0) ---"
RESULT2=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","storage_keys":["0x0000000000000000000000000000000000000000000000000000000000000000"]}' \
  "$BASE/prove/storage")
echo "$RESULT2"
echo ""
echo ""

echo "--- 9. POST /prove/finality (full_update=true) ---"
RESULT3=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"bls":false,"full_update":true}' \
  "$BASE/prove/finality")
echo "$RESULT3"
echo ""
echo ""

echo "--- 10. Waiting 20s for remaining jobs ---"
sleep 20

echo "--- 11. GET /jobs (final state) ---"
curl -s "$BASE/jobs"
echo ""
echo ""

echo "=== API Tests Complete ==="
