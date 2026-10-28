#!/usr/bin/env bash
# AMA experiment 007 — the full QoS suite: WFQ + admission control +
# bandwidth accounting.
#
# WFQ: two senders (weights 1 and 3) fire six messages each at the same
# instant at one destination. The link becomes backlogged, so the kernel
# serves the queue by WFQ virtual finish tag: the weight-3 flow gets
# roughly three times the link of the weight-1 flow. The ledger's
# qos_delivered order is the evidence.
#
# ADMISSION CONTROL: `big` has a 2000 B/s byte budget and sends three
# ~1500 B payloads back-to-back. The first fits; the rest are refused at
# admission and journaled `admission_denied` — the kernel never queues
# what it has not admitted, and never drops silently.
#
# ACCOUNTING: the kernel journals qos_accounting (per-agent bytes) after
# serving the queue, and the operator can read the same numbers at any
# time on the control channel: `ama qos`.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf /tmp/ama_exp /tmp/ama_dbg_agent_*
mkdir -p /tmp/ama_exp
rm -f /tmp/ama_exp.sock
pkill -9 -x ama 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
sleep 1

timeout 40 ./target/debug/ama serve \
  --manifest experiments/manifest_007.json \
  --agentd ./target/debug/ama-agentd &
KERNEL_PID=$!

sleep 6
./target/debug/ama qos --socket /tmp/ama_exp.sock > /tmp/ama_qos_cli.json 2>/dev/null || true

python3 experiments/wait_ledger_quiet.py 3 35
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

def ok(label, cond, extra=""):
    if not cond and __import__("os").environ.get("GITHUB_ACTIONS"):
        detail = f" | {extra}" if extra else ""
        print(f"::error::FAIL: {label}{detail}", flush=True)
    results.append(bool(cond))
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + extra) if extra and not cond else ""))

uin_of = {e['detail']['name']: e['detail']['uin']
          for e in events if e['ev'] == 'spawned'}
light = uin_of.get('light')
heavy = uin_of.get('heavy')
big = uin_of.get('big')

scheduled = [e for e in events if e['ev'] == 'qos_scheduled']
served = [e for e in events if e['ev'] == 'qos_delivered']
denied = [e for e in events if e['ev'] == 'admission_denied']
throttled = [e for e in events if e['ev'] == 'qos_throttled']
accounting = [e for e in events if e['ev'] == 'qos_accounting']

# --- WFQ -----------------------------------------------------------------
# count BOTH paths: the first message of an idle link is written straight
# through (`delivered`), the rest queue (`qos_delivered`). The share of
# the link is the sum of the two.
deliveries = sorted(
    [e for e in events if e['ev'] in ('delivered', 'qos_delivered')
     and e['detail'].get('from') in (light, heavy)],
    key=lambda e: e['seq'])
by_flow = {}
for e in deliveries:
    by_flow[e['detail']['from']] = by_flow.get(e['detail']['from'], 0) + 1
n_heavy = by_flow.get(heavy, 0)
n_light = by_flow.get(light, 0)
ok("wfq: the delivery link was contended (messages were scheduled, not "
   "written straight through)", len(scheduled) >= 8,
   f"scheduled={len(scheduled)}")
ok("wfq: the weight-3 flow got 3x the served messages of the weight-1 flow",
   n_heavy == 3 * n_light and n_light >= 1,
   f"heavy={n_heavy} light={n_light} order={[e['detail']['from'] for e in deliveries][:10]}")
ok("wfq: the light flow was served, not starved", n_light >= 1,
   f"light={n_light}")
# heavy must NOT simply run first: the light flow's messages are
# interleaved among them, not parked behind the whole heavy backlog
first_light = next((i for i, e in enumerate(deliveries) if e['detail']['from'] == light), None)
ok("wfq: the light flow's traffic is interleaved, not queued behind the heavy flow",
   first_light is not None and first_light < n_heavy,
   f"first_light_at={first_light} of {len(deliveries)}")

# Within each served batch (one watchdog tick) the tags must be
# non-decreasing: that IS the WFQ property. Across batches it cannot
# hold — a message that arrives later carries a higher tag, so a later
# batch may start below where the previous one ended.
batches = []
cur = []
for e in events:
    if e['ev'] == 'qos_delivered':
        cur.append(e['detail']['tag'])
    elif e['ev'] == 'qos_accounting':
        if cur:
            batches.append(cur)
        cur = []
if cur:
    batches.append(cur)
tags = [t for b in batches for t in b]
ok("wfq: every served batch is in virtual-finish-tag order",
   all(b == sorted(b) for b in batches) and len(batches) >= 3,
   f"batches={batches[:4]}")

# --- admission control ---------------------------------------------------
ok("admission: over-budget payloads were refused at admission and journaled",
   len(denied) >= 2, f"denied={len(denied)}")
ok("admission: the refusals name the offender and the reason",
   all(e['detail'].get('from') == big and 'byte rate' in e['detail'].get('reason', '')
       for e in denied),
   f"{[e['detail'] for e in denied][:2]}")
ok("admission: nothing was silently dropped (no qos_throttled for the "
   "message-rate bucket in this scenario)", len(throttled) == 0)

# --- accounting ----------------------------------------------------------
ok("accounting: the kernel journaled a bandwidth snapshot after serving",
   len(accounting) >= 1)
s0 = accounting[-1]['detail']['stats'] if accounting else {}
per = {a['uin']: a for a in s0.get('per_agent', [])}
ok("accounting: bytes_in recorded for both WFQ flows",
   per.get(light, {}).get('bytes_in', 0) > 0 and per.get(heavy, {}).get('bytes_in', 0) > 0,
   f"per_agent={s0.get('per_agent')}")
ok("accounting: msgs_delivered > 0 and the queue drained to zero",
   s0.get('msgs_delivered', 0) > 0 and s0.get('queued_bytes', 1) == 0,
   f"stats={s0}")

# --- operator view -------------------------------------------------------
cli = {}
try:
    cli = json.load(open('/tmp/ama_qos_cli.json'))
except Exception:
    pass
ok("accounting: `ama qos` returns the same counters on the control channel",
   cli.get('kind') == 'qos' and cli.get('stats', {}).get('msgs_accepted', 0) > 0,
   f"cli={cli}")

print(f"\nledger: {len(events)} events")
all_pass = (
    len(scheduled) >= 8 and n_heavy == 3 * n_light and n_light >= 1
    and first_light is not None and first_light < n_heavy
    and all(b == sorted(b) for b in batches) and len(batches) >= 3
    and len(denied) >= 2 and len(throttled) == 0
    and len(accounting) >= 1 and s0.get('msgs_delivered', 0) > 0
    and s0.get('queued_bytes', 1) == 0
    and cli.get('kind') == 'qos'
)
print("EXPERIMENT_007:", "PASS" if all_pass else "FAIL")
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
