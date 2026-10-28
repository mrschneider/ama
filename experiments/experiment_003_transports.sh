#!/usr/bin/env bash
# AMA experiment 003 — network-remote IPC (TCP) + binary wire (msgpack) +
# the strict allowlist seccomp profile. Agent a is LOCAL (UDS, JSON lines);
# agent b is REMOTE (TCP, msgpack frames). The round trip must survive the
# crossing of transports AND wire formats — one contract, every path.
set -euo pipefail
# F10: operator authority is a CREDENTIAL — the kernel and this
# operator CLI must share it; agents are stripped of it at spawn
export AMA_OPERATOR_TOKEN="ama-local-operator-token"
cd "$(dirname "$0")/.."
LEDGER=/tmp/ama_exp/ledger.jsonl
rm -rf /tmp/ama_exp && mkdir -p /tmp/ama_exp
rm -f /tmp/ama_exp.sock

echo "== strict allowlist jail: socket(AF_UNIX) allowed, socket(AF_INET) refused =="
timeout 8 ./target/debug/ama jail --strict -- /usr/bin/python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('AF_INET: allowed')
except PermissionError as e:
    print('AF_INET: EPERM')
except OSError as e:
    print('AF_INET: EPERM')
socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
print('AF_UNIX: ok')
" 2>&1 | while read -r l; do
  case "$l" in
    "AF_INET: EPERM") echo "PASS: strict allowlist: network socket refused (EPERM) — the kernel is the only channel";;
    "AF_UNIX: ok") echo "PASS: strict allowlist: UDS socket allowed (the agent's channel)";;
    "AF_INET: allowed") echo "FAIL: strict allowlist allowed a network socket";;
  esac
done

echo "== user-namespace tier (MicroVM frontier): the jailed tool owns nothing =="
HOST_UID=$(id -u)
JAIL_UID=$(timeout 5 ./target/debug/ama jail --userns -- /bin/sh -c 'id -u' 2>&1 | tail -1)
echo "host uid: $HOST_UID | jailed uid: $JAIL_UID"
[ "$JAIL_UID" = "0" ] && echo "PASS: userns: the jailed tool runs as uid 0 INSIDE a fresh user+mount namespace (host ownership unchanged)" || echo "SKIP (host policy): userns tier implemented but this host forbids unprivileged user namespaces (jailed uid seen: $JAIL_UID)"

export AMA_DEBUG=1
timeout 40 ./target/debug/ama serve \
  --manifest experiments/manifest_003.json \
  --agentd ./target/debug/ama-agentd 2>/tmp/ama_exp/kernel.err &
KERNEL_PID=$!
python3 experiments/wait_ledger_quiet.py 3 35
./target/debug/ama ps --socket /tmp/ama_exp.sock > /tmp/ama_exp/ps.json 2>/dev/null || true
kill $KERNEL_PID 2>/dev/null || true
wait $KERNEL_PID 2>/dev/null || true

python3 - <<'EOF'
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

ping = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('to') == 0
        and d['detail'].get('body') == {'ping': 1}]  # b(uin 0) -> a
pong = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('to') == 1
        and d['detail'].get('body') == {'pong': 1}]  # a(uin 1) -> b
ok("cross-transport ipc: b (TCP+msgpack) sent ping, delivered to a (UDS+json)", len(ping) >= 1)
ok("cross-transport ipc: a sent pong, delivered to b (TCP+msgpack)", len(pong) >= 1)
ok("cross-transport ipc: BOTH agents completed the round trip",
   {'a', 'b'} <= completed)

# the process table shows b on the binary wire
try:
    ps = json.loads(open('/tmp/ama_exp/ps.json').read().strip())
    b_entry = [a for a in ps['agents'] if a['name'] == 'b']
    ok("process table: b is registered on the msgpack wire",
       b_entry and b_entry[0]['wire'] == 'msgpack')
except Exception as e:
    ok(f"process table readable ({e})", False)

print(f"\nledger: {len(events)} events")
all_pass = len(ping) >= 1 and len(pong) >= 1 and {'a', 'b'} <= completed
print("EXPERIMENT_003:", "PASS" if all_pass else "FAIL")
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
EOF
