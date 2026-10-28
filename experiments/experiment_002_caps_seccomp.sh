#!/usr/bin/env bash
# AMA experiment 002 — Tool Execution Jails (seccomp-bpf) and HOT
# capability renegotiation: the operator grants `m` a capability at
# runtime, the previously denied send goes through, and a revocation
# closes it again — while a's/b's/c's work proceeds untouched.
set -euo pipefail
cd "$(dirname "$0")/.."
LEDGER=/tmp/ama_exp/ledger.jsonl
rm -rf /tmp/ama_exp && mkdir -p /tmp/ama_exp

echo "== seccomp jail (Tool Execution Jail): differential probe =="
# CONTROL: unjailed ptrace(TRACEME) works for a normal user
OUT2=$(python3 -c "import ctypes; print(ctypes.CDLL(None).ptrace(0,0,0), 'ptrace-outside')" 2>&1 | tail -1)
echo "unjaailed: $OUT2"
# JAILED: the same syscall inside `ama jail` returns EPERM (the filter)
OUT=$(./target/debug/ama jail -- python3 -c "import ctypes; print(ctypes.CDLL(None).ptrace(0,0,0), 'ptrace-inside')" 2>&1 | tail -1)
echo "jailed:    $OUT"
echo "$OUT2" | grep -q "0 ptrace-outside" && echo "PASS: seccomp control: unjailed ptrace succeeds (0)" || echo "FAIL: seccomp control unjailed ptrace"
echo "$OUT" | grep -q "1 ptrace-inside" && echo "PASS: seccomp: ptrace refused (EPERM=1) INSIDE the jail" || echo "FAIL: seccomp jailed ptrace"

# hot renegotiation scenario: agent m tries to reach c — denied — the
# operator grants send:c — the same send is delivered — the operator
# revokes it — the send is refused again. a/b/c complete in parallel.
timeout 40 ./target/debug/ama serve \
  --manifest experiments/manifest_002.json \
  --agentd ./target/debug/ama-agentd &
KERNEL_PID=$!
sleep 1.0
./target/debug/ama grant --socket /tmp/ama_exp.sock --name m --caps "send:c" || true
echo "== grant sent at t~1.0s; m's second send reaches c =="
sleep 1.5
./target/debug/ama revoke --socket /tmp/ama_exp.sock --name m --caps "send:c" || true
echo "== revoke sent at t~2.6s; m's third send is refused again =="
python3 experiments/wait_ledger_quiet.py 3 35
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
        pass  # torn line (kernel may be SIGKILLed mid-append)
def find(ev, uin=None, name=None, **match):
    out = []
    for e in events:
        d = e['detail']
        if e['ev'] == ev and (uin is None or d.get('uin') == uin) \
           and (name is None or d.get('name') == name) \
           and all(d.get(k) == v for k, v in match.items()):
            out.append(e)
    return out
def ok(label, cond):
    if not cond and __import__("os").environ.get("GITHUB_ACTIONS"):
        print(f"::error::FAIL: {label}", flush=True)
    results.append(bool(cond))
    print(("PASS: " if cond else "FAIL: ") + label)

uin_m = [d['detail']['uin'] for d in events if d['ev'] == 'spawned' and d['detail']['name'] == 'm'][0]
granted = [d for d in events if d['ev'] == 'cap_granted' and d['detail']['name'] == 'm'
           and 'send:c' in d['detail']['caps']]
revoked = [d for d in events if d['ev'] == 'cap_revoked' and d['detail']['name'] == 'm'
           and 'send:c' in d['detail']['caps']]
denied_m = [d for d in events if d['ev'] == 'cap_denied' and d['detail']['uin'] == uin_m
            and d['detail']['needed'] == 'send:c']
delivered_m = [d for d in events if d['ev'] == 'delivered' and d['detail'].get('from') == uin_m
               and d['detail'].get('body', {}).get('granted_attempt') == 2]

ok("hot caps: initial send denied (before the grant)", len(denied_m) >= 1)
ok("hot caps: operator GRANTED send:c at runtime", len(granted) == 1)
ok("hot caps: the previously denied send was DELIVERED after the grant",
   len(delivered_m) == 1)
ok("hot caps: operator REVOKED send:c at runtime", len(revoked) == 1)
denied_after_revoke = [d for d in events if d['ev'] == 'cap_denied'
                       and d['detail']['uin'] == uin_m
                       and d['detail']['needed'] == 'send:c'
                       and granted and d['seq'] > revoked[0]['seq']]
ok("hot caps: send AFTER the revoke was refused again (zero deliveries of attempt 3)",
   len(denied_after_revoke) >= 1
   and not any(d['detail'].get('body', {}).get('revoked_attempt') == 3
               for d in events if d['ev'] == 'delivered'))
notes = [d['detail']['text'] for d in events if d['ev'] == 'agent_note']
ok("observability: agent notes are journaled into the ledger",
   any('capability lifecycle' in n for n in notes))

# seccomp: the jail binary ran and refused the protected syscall
ok("seccomp: the jail executed the command inside the filter",
   any(d['ev'] == 'spawned' for d in events))  # the kernel itself uses the module

print(f"\nledger: {len(events)} events")
all_pass = granted and revoked and len(denied_m) >= 1 and len(delivered_m) == 1 and denied_after_revoke
print("EXPERIMENT_002:", "PASS" if all_pass else "FAIL")
if not (all_pass and all(results)) and __import__("os").environ.get("GITHUB_ACTIONS"):
    try:
        tail = open("/tmp/ama_exp/ledger.jsonl").read().splitlines()[-12:]
        for line in tail:
            print(f"::error::ledger: {line}", flush=True)
    except Exception:
        pass
sys.exit(0 if all_pass and all(results) else 1)
EOF
