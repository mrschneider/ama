#!/usr/bin/env bash
# AMA experiment 005 — the DEEPEST isolation tier: a real Firecracker
# microVM per agent. Agent `a` is an ordinary host process (UDS + JSON);
# agent `vm1` is booted INSIDE its own Firecracker VM (per-agent tap,
# per-agent initramfs with the static agentd + task baked in). The guest
# agentd connects BACK to the kernel over the tap; the envelope contract,
# capability checks and wire format are byte-identical to the host tiers.
#
# Requires: /dev/kvm writable (udev rule), ufw allow from 172.16.0.0/12,
# vm/bin/{firecracker,busybox}, vm/vmlinux-6.1.155, vm/agentd-static.
set -euo pipefail
# F10: operator authority is a CREDENTIAL — the kernel and this
# operator CLI must share it; agents are stripped of it at spawn
export AMA_OPERATOR_TOKEN="ama-local-operator-token"
cd "$(dirname "$0")/.."
rm -rf /tmp/ama_exp /tmp/ama_vm* /tmp/ama_dbg_agent_*
mkdir -p /tmp/ama_exp
rm -f /tmp/ama_exp.sock
# hygiene: no VM/kernel/agentd from earlier runs may survive
pkill -9 -x firecracker 2>/dev/null || true
pkill -9 -x ama 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
sleep 1
# the tap is recreated by boot_agent.sh if missing
sudo ip tuntap del dev ama_tap1 mode tap 2>/dev/null || true

timeout 30 ./target/debug/ama serve \
  --manifest experiments/manifest_005.json \
  --agentd ./target/debug/ama-agentd &
KERNEL_PID=$!
sleep 22
./target/debug/ama ps --socket /tmp/ama_exp.sock > /tmp/ama_exp/ps.json 2>/dev/null || true
kill $KERNEL_PID 2>/dev/null || true
wait $KERNEL_PID 2>/dev/null || true
pkill -9 -x firecracker 2>/dev/null || true

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

name_of = {d['detail']['uin']: d['detail']['name'] for d in events if d['ev'] == 'spawned'}
completed = {name_of.get(d['detail']['uin']) for d in events if d['ev'] == 'completed'}

pings = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('body') == {'ping': 'from-vm'}]
pongs = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('body') == {'pong': 'host'}]
ok("microvm ipc: the agent INSIDE the Firecracker VM pinged the host agent",
   any(name_of.get(d['detail']['from']) == 'vm1' and name_of.get(d['detail']['to']) == 'a' for d in pings))
ok("microvm ipc: the host agent ponged back INTO the VM",
   any(name_of.get(d['detail']['from']) == 'a' and name_of.get(d['detail']['to']) == 'vm1' for d in pongs))
ok("microvm ipc: BOTH agents completed the round trip", {'a', 'vm1'} <= completed)

try:
    ps = json.loads(open('/tmp/ama_exp/ps.json').read().strip())
    iso = {a['name']: a.get('isolation', '') for a in ps['agents']}
    ok("process table: vm1 ran in a microvm", iso.get('vm1') == 'microvm')
except Exception as e:
    ok(f"process table readable ({e})", False)

print(f"\nledger: {len(events)} events")
all_pass = ('a' in completed and 'vm1' in completed) and pings and pongs
print("EXPERIMENT_005:", "PASS" if all_pass else "FAIL")
if not (all_pass and all(results)) and __import__("os").environ.get("GITHUB_ACTIONS"):
    # ONE annotation: GitHub drops workflow commands beyond 10/step
    parts = []
    try:
        import os as _os
        _lp = _os.environ.get("LEDGER", "/tmp/ama_exp/ledger.jsonl")
        lines = open(_lp).read().splitlines()
        parts.append(f"LEDGER {len(lines)} events: first 8")
        parts.extend(l[:340] for l in lines[:8])
        if len(lines) > 8:
            parts.append("last 16:")
            parts.extend(l[:340] for l in lines[-16:])
    except Exception as e:
        parts.append(f"LEDGER unreadable: {e}")
    try:
        parts.append("PS: " + open("/tmp/ama_exp/ps.json").read().replace(" ", "")[:600])
    except Exception:
        pass
    import glob as _g
    for f in sorted(_g.glob("/tmp/ama_dbg_agent_*.stderr")):
        try:
            tail = [l for l in open(f).read().splitlines() if l.strip()][-3:]
            for l in tail:
                parts.append(f"{f.split('/')[-1]}: {l[:250]}")
        except Exception:
            pass
    try:
        kl = open("/tmp/ama_exp/kernel.err").read().splitlines()[-4:]
        parts.extend(f"k: {l[:250]}" for l in kl)
    except Exception:
        pass
    print("::error title=evidence::" + "%0A".join(parts), flush=True)
    try:
        open(_os.path.join(_os.path.dirname(_lp), ".evidence_printed"), "w").write("1")
    except Exception:
        pass
sys.exit(0 if all_pass and all(results) else 1)
PYEOF
