#!/bin/bash
# Quick check of job statuses
curl -s http://localhost:3000/jobs > /tmp/jobs.json
python3 << 'PYEOF'
import json
with open('/tmp/jobs.json') as f:
    data = json.load(f)
if isinstance(data, list):
    for j in data:
        keys = list(j.keys())
        jid = j.get('job_id', j.get('id', 'unknown'))[:8]
        s = j.get('status', 'unknown')
        t = j.get('proof_type', 'unknown')
        has_proof = 'YES' if j.get('proof') else 'NO'
        err = str(j.get('error', ''))[:80]
        print(f'{jid}  {s:12s}  {t:12s}  proof={has_proof}  err={err}')
    print(f'Total: {len(data)} jobs')
    if data:
        print(f'Keys: {list(data[0].keys())}')
else:
    print(f'Response is not a list: {type(data)}')
    print(str(data)[:200])
PYEOF
