#!/bin/bash
# Get full finality update data from Lodestar
echo "=== FINALITY UPDATE ==="
curl -s "https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/light_client/finality_update" \
  -H 'Accept: application/json' | python3 -m json.tool 2>/dev/null | head -100

echo ""
echo ""
echo "=== LIGHT CLIENT UPDATES (period 1000) ==="
curl -s "https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/light_client/updates?start_period=1000&count=1" \
  -H 'Accept: application/json' | python3 -m json.tool 2>/dev/null | head -100

echo ""
echo ""
echo "=== BOOTSTRAP (using a recent finalized block root) ==="
# First get finalized checkpoint to find a block root
curl -s "https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/states/finalized/finality_checkpoints" \
  -H 'Accept: application/json' | python3 -m json.tool 2>/dev/null

echo ""
echo "DONE"
