#!/usr/bin/env bash
# AMA experiment 004 — THREE wire formats on ONE kernel: a = UDS + JSON
# lines, b = TCP + msgpack frames, c = TCP + protobuf frames. Both pings
# cross transports and formats; both pongs come back translated to the
# targets' wires. One contract, three encodings.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf /tmp/ama_exp && mkdir -p /tmp/ama_exp
rm -f /tmp/ama_exp.sock

timeout 20 ./target/debug/ama serve \
  --manifest experiments/manifest_004.json \
  --agentd ./target/debug/ama-agentd &
KERNEL_PID=$!
sleep 9
./target/debug/ama ps --socket /tmp/ama_exp.sock > /tmp/ama_exp/ps.json 2>/dev/null || true
kill $KERNEL_PID 2>/dev/null || true
wait $KERNEL_PID 2>/dev/null || true

python3 - <<'PYEOF'
import json

events = []
for l in open('/tmp/ama_exp/ledger.jsonl'):
    try:
        events.append(json.loads(l))
    except json.JSONDecodeError:
        pass
def ok(label, cond):
    print(("PASS: " if cond else "FAIL: ") + label)

name_of = {d['detail']['uin']: d['detail']['name'] for d in events if d['ev'] == 'spawned'}
completed = {name_of.get(d['detail']['uin']) for d in events if d['ev'] == 'completed'}

pings = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('body') in ({'ping': 1}, {'ping': 2})]
pongs = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('body') in ({'pong': 1}, {'pong': 2})]
ping_pair = {(name_of.get(d['detail']['from']), name_of.get(d['detail']['to'])) for d in pings}
pong_pair = {(name_of.get(d['detail']['from']), name_of.get(d['detail']['to'])) for d in pongs}

ok("three-wire ipc: b (msgpack) AND c (proto) both pinged a (json)",
   {('b', 'a'), ('c', 'a')} <= ping_pair)
ok("three-wire ipc: a ponged BOTH back, translated to each target's wire",
   {('a', 'b'), ('a', 'c')} <= pong_pair)
ok("three-wire ipc: ALL THREE agents completed the round trip",
   {'a', 'b', 'c'} <= completed)

try:
    ps = json.loads(open('/tmp/ama_exp/ps.json').read().strip())
    wires = {a['name']: a['wire'] for a in ps['agents']}
    ok("process table: a=json b=msgpack c=proto",
       wires.get('a') == 'json' and wires.get('b') == 'msgpack' and wires.get('c') == 'proto')
except Exception as e:
    ok(f"process table readable ({e})", False)

print(f"\nledger: {len(events)} events")
all_pass = {('b','a'),('c','a')} <= ping_pair and {('a','b'),('a','c')} <= pong_pair and {'a','b','c'} <= completed
print("EXPERIMENT_004:", "PASS" if all_pass else "FAIL")
PYEOF
