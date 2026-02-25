#!/bin/bash
# Test various Beacon API URL formats
INFURA_KEY="fba92cb083044034b177f647a3c882fb"

echo "=== Format 1: eth2 subdomain ==="
curl -s "https://eth2-beacon-mainnet.infura.io/eth/v1/beacon/genesis" \
  -H "Authorization: Basic $(echo -n ":${INFURA_KEY}" | base64)" | head -c 500
echo ""

echo ""
echo "=== Format 2: mainnet with /eth/ prefix ==="
curl -s "https://mainnet.infura.io/eth/v1/beacon/genesis" | head -c 500
echo ""

echo ""
echo "=== Format 3: Public Lodestar beacon ==="
curl -s "https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/genesis" \
  -H 'Accept: application/json' | head -c 500
echo ""

echo ""
echo "=== Format 4: Public Lodestar finality update ==="
curl -s "https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/light_client/finality_update" \
  -H 'Accept: application/json' | head -c 2000
echo ""

echo ""
echo "=== Format 5: Infura beacon v3 style ==="
curl -s "https://mainnet.infura.io/v3/${INFURA_KEY}" \
  -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false],"id":1}' | head -c 500
echo ""

echo ""
echo "=== Format 6: QuickNode-style Infura ==="
curl -s "https://${INFURA_KEY}:@eth2-beacon-mainnet.infura.io/eth/v1/beacon/genesis" | head -c 500
echo ""

echo ""
echo "DONE"
