#!/bin/bash
# Detailed check of completed jobs
curl -s http://localhost:3000/jobs > /tmp/jobs.json
python3 << 'PYEOF'
import json
with open('/tmp/jobs.json') as f:
    data = json.load(f)
for j in data:
    jid = j.get('id', '?')[:12]
    s = j.get('status', '?')
    t = j.get('job_type', '?')
    err = j.get('error')
    pv = j.get('public_values')
    proof = j.get('proof')
    print(f'--- Job {jid} ---')
    print(f'  Type: {t}  Status: {s}')
    if err:
        print(f'  Error: {str(err)[:200]}')
    if pv:
        if isinstance(pv, dict):
            for k, v in pv.items():
                val = str(v)
                if len(val) > 80:
                    val = val[:80] + '...'
                print(f'  PV.{k}: {val}')
        else:
            print(f'  PV: {str(pv)[:200]}')
    has_proof = proof is not None
    if has_proof:
        proof_str = str(proof)
        print(f'  Proof: {len(proof_str)} chars')
    print()
PYEOF
