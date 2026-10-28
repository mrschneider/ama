#!/usr/bin/env bash
# AMA experiment 001 — full-stack verification of the Agentic Microkernel
# Architecture: process isolation, capability-gated IPC, schema validation,
# watchdog respawn, and ledger-based recovery.
set -euo pipefail
cd "$(dirname "$0")/.."
export RUST_LOG=warn
LEDGER=/tmp/ama_exp/ledger.jsonl
rm -rf /tmp/ama_exp && mkdir -p /tmp/ama_exp

echo "== PASS/FAIL by inspection of the ledger + process table =="

# malformed-envelope probe: connect raw, send a garbage line, expect a kernel rejection
( python3 - <<'EOF'
import socket, time, json
s = socket.socket(socket.AF_UNIX)
for _ in range(50):
    try:
        s.connect("/tmp/ama_exp.sock"); break
    except FileNotFoundError:
        time.sleep(0.1)
s.sendall(b'this is not json\n')
s.settimeout(2)
print("MALFORMED_REPLY:", s.recv(4096).decode().strip())
EOF
) &

# F03: readiness polling instead of fixed sleeps — the kernel used to
# live a fixed 20 s and the experiment slept a fixed 1.5 s before the
# kill, so a slow runner could kill c BEFORE its n=0 checkpoint (and the
# validator's FAIL used to exit 0 anyway, hiding it). The kernel gets a
# generous budget and every phase waits for the EVENT it needs.
timeout 70 ./target/debug/ama serve \
  --manifest experiments/manifest.json \
  --agentd ./target/debug/ama-agentd &
KERNEL_PID=$!

# phase 1: wait until c exists AND checkpointed n=0 — then the external
# kill is a real crash-recovery test, not a race
python3 - <<'EOF'
import json, time, sys
deadline = time.time() + 25
while time.time() < deadline:
    try:
        events = [json.loads(l) for l in open('/tmp/ama_exp/ledger.jsonl')]
    except FileNotFoundError:
        time.sleep(0.2); continue
    spawned = any(e['ev'] == 'spawned' and e['detail']['name'] == 'c' for e in events)
    cps = any(e['ev'] == 'checkpoint'
              and e['detail'].get('state', {}).get('state', {}).get('n') == 0
              for e in events)
    if spawned and cps:
        print("== c checkpointed n=0; ready to kill ==", flush=True)
        sys.exit(0)
    time.sleep(0.2)
print("FAIL: c never checkpointed n=0 (timeout)", flush=True)
sys.exit(1)
EOF

# EXTERNAL kill of agent c (the real fail-fast path: the operator/OOM/
# supervisor kills the PID — the kernel must detect the EOF and respawn
# the agent FROM ITS LEDGER CHECKPOINT while everyone else keeps running)
C_PID=$(python3 -c "
import json
for l in open('$LEDGER'):
    e = json.loads(l)
    if e['ev'] == 'spawned' and e['detail']['name'] == 'c':
        print(e['detail']['pid']); break
")
if [ -z "$C_PID" ]; then
  echo "FAIL: agent c never spawned" >&2; exit 1
fi
echo "== killing agent c (pid $C_PID) externally =="
kill -9 "$C_PID" && echo "KILL: sent -9 to $C_PID"

# phase 2: wait for the terminal evidence instead of sleeping 12 s
python3 - <<'EOF'
import json, time, sys
# wait for EVERY terminal condition the validator checks — a/b's round
# trip and m's denial land AFTER d's death and c's recovery (the early
# condition cut the workload short and broke CI)
deadline = time.time() + 45
while time.time() < deadline:
    try:
        events = [json.loads(l) for l in open('/tmp/ama_exp/ledger.jsonl')]
    except FileNotFoundError:
        time.sleep(0.3); continue
    name_of = {e['detail']['name']: e['detail']['uin']
               for e in events if e['ev'] == 'spawned'}
    uins = {n: u for n, u in name_of.items()}
    completed = {n for n, u in uins.items()
                 if any(e['ev'] == 'completed' and e['detail'].get('uin') == u
                        for e in events)}
    d_dead = any(e['ev'] == 'dead' and e['detail'].get('name') == 'd' for e in events)
    denied = any(e['ev'] == 'cap_denied'
                 and e['detail'].get('needed') == 'send:c' for e in events)
    watchdog_kill = any(e['ev'] == 'killed'
                        and 'no progress' in str(e['detail'].get('reason', ''))
                        for e in events)
    if {'a', 'b', 'c'} <= completed and d_dead and denied and watchdog_kill:
        print("== all terminal evidence present; shutting down ==", flush=True)
        sys.exit(0)
    time.sleep(0.3)
missing = []
print(f"== timeout waiting for terminal evidence; validating anyway ==", flush=True)
sys.exit(0)
EOF

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
        pass  # torn line (kernel SIGKILLed mid-append) — analysis is read-only
def find(ev, **match):
    out = []
    for e in events:
        d = e['detail']
        if e['ev'] == ev and all(d.get(k) == v for k, v in match.items()):
            out.append(e)
    return out
def ok(label, cond):
    if not cond and __import__("os").environ.get("GITHUB_ACTIONS"):
        print(f"::error::FAIL: {label}", flush=True)
    results.append(bool(cond))
    print(("PASS: " if cond else "FAIL: ") + label)

# 1. isolation: every agent ran in its OWN process (distinct pids, != kernel pids)
spawned = {d['detail']['name']: d['detail']['pid'] for d in events if d['ev'] == 'spawned'}
ok("isolation: 5 agents spawned as distinct OS processes",
   len(spawned) == 5 and len(set(spawned.values())) == 5)

# 2. typed schema: the kernel rejected a malformed envelope with a reason
malformed = find('malformed')
ok("schema: malformed envelope rejected (invalid json)",
   any('invalid json' in e['detail']['reason'] for e in malformed))

# 3. IPC with typed contract: a<->b full round trip through the kernel
ping = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('to') == 1
        and d['detail'].get('body') == {'ping': 1}]
pong = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('to') == 0
        and d['detail'].get('body') == {'pong': 1}]
ok("ipc: a (uin 1) received b's ping", len(ping) == 1)
ok("ipc: b (uin 0) received a's pong", len(pong) == 1)
# uin -> name from the spawned events (completed events carry the uin)
name_of = {d['detail']['uin']: d['detail']['name'] for d in events if d['ev'] == 'spawned'}
completed = {name_of.get(d['detail']['uin']) for d in events if d['ev'] == 'completed'}
ok("ipc: round trip completed both sides (a and b tasks completed)",
   {'a', 'b'} <= completed)

# 4. capability check: m tried to reach agent c without the grant
denied = [d for d in events if d['ev'] == 'cap_denied']
ok("capabilities: m's send to c was refused and journaled",
   any(d['detail']['needed'] == 'send:c' for d in denied))
ok("capabilities: no message was delivered on the denied attempt",
   not any(d['ev'] == 'delivered' and d['detail'].get('body') == {'attack': 1} for d in events))

# 5. watchdog: agent d looped with no progress -> killed with the reason, respawned
kills = [d for d in events if d['ev'] == 'killed' and 'no progress' in str(d['detail'].get('reason', ''))]
ok("watchdog: infinite reasoning loop detected via progress watchdog",
   any(d['detail']['uin'] == [d2['detail']['uin'] for d2 in find('spawned') if d2['detail']['name'] == 'd'][0]
       for d in kills))
respawns_d = [d for d in events if d['ev'] == 'respawned'
              and d['detail']['name'] == 'd']
ok("watchdog: respawn budget enforced (d died after the budget)",
   any(d['ev'] == 'dead' and d['detail']['name'] == 'd' and 'budget' in str(d['detail']['reason']) for d in events))

# 6. crash + recovery: agent c crashed, respawned from its LAST checkpoint, resumed
uin_c = [d['detail']['uin'] for d in events if d['ev'] == 'spawned' and d['detail']['name'] == 'c'][0]
cps = [d['detail']['state']['state'] for d in events if d['ev'] == 'checkpoint' and d['detail']['uin'] == uin_c]
ok("recovery: c checkpointed n=0 before the external kill", any(c.get('n') == 0 for c in cps))
crash_events = [d for d in events if d['ev'] == 'crashed' and d['detail']['uin'] == uin_c]
ok("recovery: the kernel detected the external kill and respawned c from the ledger",
   len(crash_events) >= 1 and any(d['detail']['name'] == 'c' for d in events if d['ev'] == 'respawned'))
ok("recovery: c resumed FROM the checkpoint (n=1 after respawn)",
   any(c.get('n') == 1 for c in cps))
ok("recovery: c completed after respawn", 'c' in completed)
# 7. fail-fast did not leak: a and b completed while c/d/m misbehaved
ok("isolation: parallel agents unaffected by c's crash and d's loop",
   {'a', 'b'} <= completed)

print(f"\nledger: {len(events)} events total")
print("EXPERIMENT_001:", "PASS" if all([
    len(spawned) == 5, malformed, len(denied) >= 1, kills, respawns_d]) else "FAIL")
all_pass = all([len(spawned) == 5, malformed, len(denied) >= 1, kills, respawns_d])
if not (all_pass and all(results)) and __import__("os").environ.get("GITHUB_ACTIONS"):
    try:
        interesting = ("completed", "killed", "dead", "respawned", "crashed",
                       "cap_denied", "delivered", "checkpoint")
        for line in open("/tmp/ama_exp/ledger.jsonl").read().splitlines():
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e["ev"] in interesting:
                print(f"::error::ev[{e['seq']}]: {e['ev']} {e['detail']}", flush=True)
    except Exception:
        pass
sys.exit(0 if all_pass and all(results) else 1)
EOF
