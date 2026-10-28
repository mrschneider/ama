#!/usr/bin/env bash
# AMA experiment 006 — QoS (rate limiting) + DTN (store-and-forward).
#
# QoS: src declares max_msgs_per_sec = 3 and fires SIX sends back-to-back
# at t~1.5s. Its token bucket covers the first 3; sends 4-6 are refused
# with qos_throttled journaled — backpressure is explicit, never silent.
#
# DTN: dtn declared dtn=true. The experiment kills dtn's process at
# t~1.0s (before src sends). src's sends then reach a DEAD destination:
# instead of failing, the kernel takes CUSTODY of the in-budget bundles
# (dtn_stored). The watchdog's heartbeat timeout respawns dtn at ~4s;
# the respawned agent re-registers and the kernel FLUSHES its held
# backlog in priority order (dtn_delivered) BEFORE the welcome — the
# agent resumes from its checkpoint and drains its backlog. Custody
# transfer + store-and-forward + TTL, end to end.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf /tmp/ama_exp /tmp/ama_dbg_agent_*
mkdir -p /tmp/ama_exp
rm -f /tmp/ama_exp.sock
pkill -9 -x ama 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
pkill -9 -x firecracker 2>/dev/null || true
sleep 1

timeout 40 ./target/debug/ama serve \
  --manifest experiments/manifest_006.json \
  --agentd ./target/debug/ama-agentd &
KERNEL_PID=$!

# kill dtn's PROCESS at t~1.0s — the offline destination DTN exists for
sleep 1
DTN_PID=$(python3 - <<'PYEOF'
import json
for l in open('/tmp/ama_exp/ledger.jsonl'):
    try:
        e = json.loads(l)
        if e['ev'] == 'spawned' and e['detail']['name'] == 'dtn':
            print(e['detail']['pid'])
            break
    except Exception:
        pass
PYEOF
)
kill -9 "$DTN_PID" 2>/dev/null || true

# t~6s: by now src has sent (its task sleeps 2s, and agent startup jitter
# is ~1.5s, so the offline window must be WIDE — a 2s window raced the
# sends and the test flaked). NOW the destination "comes back": a fresh
# agentd process for the same name registers and the kernel flushes the
# held backlog to it
sleep 5
./target/debug/ama-agentd --socket /tmp/ama_exp.sock \
  --task experiments/tasks_006/dtn.json &
DTN_RESTART_PID=$!

python3 experiments/wait_ledger_quiet.py 2 35
kill $DTN_RESTART_PID 2>/dev/null || true
kill $KERNEL_PID 2>/dev/null || true
wait $KERNEL_PID 2>/dev/null || true

python3 - <<'PYEOF'
import sys

results = []
import json

events = []
for l in open('/tmp/ama_exp/ledger.jsonl'):
    try:
        events.append(json.loads(l))
    except json.JSONDecodeError:
        pass
def ok(label, cond):
    if not cond and __import__("os").environ.get("GITHUB_ACTIONS"):
        print(f"::error::FAIL: {label}", flush=True)
    results.append(bool(cond))
    print(("PASS: " if cond else "FAIL: ") + label)

uin_of = {e['detail']['name']: e['detail']['uin']
          for e in events if e['ev'] == 'spawned'}
completed = {e['detail']['uin'] for e in events if e['ev'] == 'completed'}

throttled = [e for e in events if e['ev'] == 'qos_throttled']
stored = [e for e in events if e['ev'] == 'dtn_stored']
flushed = sorted(
    (e for e in events if e['ev'] == 'dtn_delivered'),
    key=lambda x: x['seq'])
expired = [e for e in events if e['ev'] == 'dtn_expired']

ok("qos: 3 sends within the bucket were accepted (sent attempts 4-6 throttled)",
   len(throttled) == 3 and
   sorted(e['detail']['body']['n'] for e in throttled) == [4, 5, 6])

ok("dtn: custody taken for the offline destination (3 bundles stored)",
   len(stored) == 3 and
   sorted(e['detail']['body']['n'] for e in stored) == [1, 2, 3])

ok("dtn: backlog delivered in order on re-registration",
   len(flushed) == 3 and
   [e['detail']['body']['n'] for e in flushed] == [1, 2, 3])
ok("dtn: no bundle expired inside the TTL window", len(expired) == 0)

ok("dtn: the respawned agent completed after draining its backlog",
   uin_of.get('dtn') in completed)
ok("qos: the throttled sender still completed its task",
   uin_of.get('src') in completed)

print(f"\nledger: {len(events)} events")
all_pass = (
    len(throttled) == 3 and len(stored) == 3 and len(flushed) == 3
    and len(expired) == 0
    and uin_of.get('dtn') in completed and uin_of.get('src') in completed
)
print("EXPERIMENT_006:", "PASS" if all_pass else "FAIL")
if not (all_pass and all(results)) and __import__("os").environ.get("GITHUB_ACTIONS"):
    try:
        tail = open("/tmp/ama_exp/ledger.jsonl").read().splitlines()[-12:]
        for line in tail:
            print(f"::error::ledger: {line}", flush=True)
    except Exception:
        pass
sys.exit(0 if all_pass and all(results) else 1)
PYEOF
