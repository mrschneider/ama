#!/usr/bin/env bash
# AMA experiment 008 — DTN routing: multi-hop relays, custody
# acknowledgements, fragmentation and reassembly.
#
# Topology: src --(route: far via relay1)--> relay1 --(next: relay2)-->
# relay2 --> far. `far` is DTN-enabled and is killed at t~1s, so it is
# offline for the whole trip.
#
#  1. src sends a ~620 B body; max_bundle_bytes=700 splits it into TWO
#     fragments, each routed independently (dtn_fragmented).
#  2. The kernel consults the manifest route and hands each fragment to
#     relay1 as a `bundle` frame (dtn_relayed, hop 1).
#  3. relay1 ACKNOWLEDGES custody (custody_ack → the kernel deletes its
#     copy: dtn_custody_ack) and names relay2 as the next hop.
#  4. relay2 does the same and, having no next hop, the kernel stores
#     custody for `far` (hop 2) — WITHOUT re-applying the static table
#     (that is what would loop the bundle back to relay1).
#  5. `far` comes back (fresh agentd process), registers, and the kernel
#     reassembles the two fragments into ONE message and delivers it.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf /tmp/ama_exp /tmp/ama_dbg_agent_*
mkdir -p /tmp/ama_exp
rm -f /tmp/ama_exp.sock
pkill -9 -x ama 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
sleep 1

timeout 45 ./target/debug/ama serve \
  --manifest experiments/manifest_008.json \
  --agentd ./target/debug/ama-agentd &
KERNEL_PID=$!

# t~1s: the destination goes offline (max_respawns=0 keeps it offline)
sleep 1
FAR_PID=$(python3 - <<'PYEOF'
import json
for l in open('/tmp/ama_exp/ledger.jsonl'):
    try:
        e = json.loads(l)
        if e['ev'] == 'spawned' and e['detail']['name'] == 'far':
            print(e['detail']['pid'])
            break
    except Exception:
        pass
PYEOF
)
kill -9 "$FAR_PID" 2>/dev/null || true

# t~8s: the destination comes back — the fragments must reassemble
sleep 7
./target/debug/ama-agentd --socket /tmp/ama_exp.sock \
  --task experiments/tasks_008/far.json &
FAR2=$!

python3 experiments/wait_ledger_quiet.py 2 35
kill $FAR2 2>/dev/null || true
kill $KERNEL_PID 2>/dev/null || true
wait $KERNEL_PID 2>/dev/null || true

python3 - <<'PYEOF'
import json
import sys

results = []

events = []
for l in open('/tmp/ama_exp/ledger.jsonl'):
    try:
        events.append(json.loads(l))
    except json.JSONDecodeError:
        pass

def ok(label, cond, extra=""):
    if not cond and __import__("os").environ.get("GITHUB_ACTIONS"):
        detail = f" | {extra}" if extra else ""
        print(f"::error::FAIL: {label}{detail}", flush=True)
    results.append(bool(cond))
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + extra) if extra and not cond else ""))

uin_of = {e['detail']['name']: e['detail']['uin']
          for e in events if e['ev'] == 'spawned'}
relay1, relay2 = uin_of.get('relay1'), uin_of.get('relay2')

frag = [e for e in events if e['ev'] == 'dtn_fragmented']
relayed = [e for e in events if e['ev'] == 'dtn_relayed']
acks = [e for e in events if e['ev'] == 'dtn_custody_ack']
delivered = [e for e in events if e['ev'] == 'dtn_delivered' and 'body' in e['detail']]
hop_limit = [e for e in events if e['ev'] == 'dtn_hop_limit']

# --- fragmentation -------------------------------------------------------
ok("fragmentation: the oversized body was split and journaled",
   len(frag) == 1 and frag[0]['detail']['fragments'] == 2,
   f"{[e['detail'] for e in frag]}")

# --- multi-hop -----------------------------------------------------------
to_r1 = [e for e in relayed if e['detail'].get('relay') == relay1]
to_r2 = [e for e in relayed if e['detail'].get('relay') == relay2]
ok("routing: both fragments reached relay1 (static route for 'far')",
   len(to_r1) == 2, f"to_relay1={[e['detail'] for e in to_r1]}")
ok("routing: relay1 handed them to relay2 with an incremented hop count",
   len(to_r2) == 2 and all(e['detail']['hops'] == 2 for e in to_r2),
   f"to_relay2={[e['detail'] for e in to_r2][:2]}")
ok("routing: no bundle looped (the in-transit bundle is not re-routed "
   "by the static table)", len(to_r1) == 2,
   f"relay1 forwards={len(to_r1)}")
ok("routing: the hop budget was never exhausted on a 2-hop path",
   len(hop_limit) == 0, f"{[e['detail'] for e in hop_limit]}")

# --- custody acknowledgements -------------------------------------------
released = sum(e['detail'].get('released', 0) for e in acks)
ok("custody: every fragment was acknowledged individually (4 acks, 4 released)",
   len(acks) == 4 and released == 4,
   f"acks={[e['detail'] for e in acks]}")

# --- reassembly + delivery ----------------------------------------------
ok("reassembly: the destination received exactly ONE message, not fragments",
   len(delivered) == 1, f"delivered={[e['detail'] for e in delivered][:2]}")
pad_len = len(delivered[0]['detail']['body']['pad']) if delivered else 0
ok("reassembly: the delivered body is the WHOLE original payload (600 chars)",
   pad_len == 600, f"pad_len={pad_len}")

print(f"\nledger: {len(events)} events")
all_pass = (
    len(frag) == 1 and frag[0]['detail']['fragments'] == 2
    and len(to_r1) == 2 and len(to_r2) == 2
    and all(e['detail']['hops'] == 2 for e in to_r2)
    and len(hop_limit) == 0 and len(acks) == 4 and released == 4
    and len(delivered) == 1 and pad_len == 600
)
print("EXPERIMENT_008:", "PASS" if all_pass else "FAIL")
# a validator that PRINTS FAIL but exits 0 hides a broken guarantee from CI
# (F03): the exit status accumulates every ok() check, which is strictly
# stronger than the all_pass aggregate
if not (all_pass and all(results)) and __import__("os").environ.get("GITHUB_ACTIONS"):
    try:
        tail = open("/tmp/ama_exp/ledger.jsonl").read().splitlines()[-12:]
        for line in tail:
            print(f"::error::ledger: {line}", flush=True)
    except Exception:
        pass
sys.exit(0 if all_pass and all(results) else 1)
PYEOF
