#!/usr/bin/env bash
# AMA experiment 011 — the operator surface and the journal lifecycle.
#
# The operator verbs are the contract between a human (or a watchdog) and
# a running kernel. This experiment proves:
#
#   1. `ama stats` serves ONE JSON line: journal growth (seq, active
#      bytes, archive count/bytes), the process table BY STATE, the
#      delivery queue and both connection budgets.
#   2. `ama inspect --name <agent>` returns exactly the entry `ama ps`
#      shows for that agent — the same snapshot, filtered.
#   3. `ama rotate --keep N` rolls the active journal segment and
#      retains the NEWEST N archives — and the retention is JOURNALED
#      (`ledger_rotated`), so a deletion of history is as auditable as
#      the writes that produced it.
#   4. The journal survives the rotation: the checkpoint written BEFORE
#      the rotate is still recoverable afterwards.
#   5. A CONTROL verb without the operator credential is refused — the
#      new verbs are not a way around F10.
set -euo pipefail
# F10: operator authority is a CREDENTIAL — the kernel and this
# operator CLI must share it; agents are stripped of it at spawn
export AMA_OPERATOR_TOKEN="ama-local-operator-token"
export AMA_LEDGER_VERBOSE=1
cd "$(dirname "$0")/.."
export LEDGER=/tmp/ama_exp11/ledger.jsonl
rm -rf /tmp/ama_exp11
mkdir -p /tmp/ama_exp11
rm -f /tmp/ama_exp11.sock /tmp/ama_exp11.sock.ctl
pkill -9 -x ama 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
sleep 1

timeout 60 ./target/debug/ama serve \
  --manifest experiments/manifest_011.json \
  --agentd ./target/debug/ama-agentd 2>/tmp/ama_exp11/kernel.err &
KERNEL_PID=$!

python3 - <<'PYEOF'
import json
import os
import socket
import subprocess
import sys
import time

results = []
SOCK = "/tmp/ama_exp11.sock"
CTL = SOCK + ".ctl"
LEDGER = "/tmp/ama_exp11/ledger.jsonl"
TOKEN = os.environ["AMA_OPERATOR_TOKEN"]
CLI = "./target/debug/ama"


def ok(label, cond, extra=""):
    results.append(bool(cond))
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + extra) if extra and not cond else ""),
          flush=True)


def events():
    """The FULL journal: the active file PLUS the archived segments (the
    kernel reads them the same way — a rotation moves the history aside,
    it does not delete it)."""
    out = []
    paths = []
    try:
        for f in sorted(os.listdir("/tmp/ama_exp11")):
            if f.endswith(".jsonl"):
                paths.append(os.path.join("/tmp/ama_exp11", f))
    except FileNotFoundError:
        pass
    for p in paths:
        try:
            for l in open(p):
                l = l.strip()
                if not l:
                    continue
                try:
                    out.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
        except FileNotFoundError:
            pass
    out.sort(key=lambda e: e.get("seq", 0))
    return out


def wait_for(pred, timeout=25, what=""):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def cli(*args):
    r = subprocess.run([CLI, *args], capture_output=True, text=True,
                       env={**os.environ, "AMA_OPERATOR_TOKEN": TOKEN})
    return r.stdout.strip(), r.returncode


# wait for the agents to register and checkpoint
wait_for(lambda: sum(1 for e in events() if e["ev"] == "registered") >= 2,
         what="both agents registered")
wait_for(lambda: sum(1 for e in events() if e["ev"] == "checkpoint") >= 2,
         what="both agents checkpointed")

# ---- 1. ama stats ----------------------------------------------------
out, rc = cli("stats", "--socket", SOCK)
ok("stats: the verb succeeds", rc == 0, out)
try:
    st = json.loads(out)
except Exception as e:
    st = {}
    ok("stats: the reply is ONE JSON line", False, f"{e}: {out[:200]}")
else:
    ok("stats: the reply is ONE JSON line", st.get("kind") == "stats", out[:200])
s = st.get("stats", {})
ok("stats: the journal growth is reported",
   isinstance(s.get("ledger", {}).get("seq"), int) and s["ledger"]["seq"] > 0, out[:200])
ok("stats: the journal byte counters are reported",
   "active_bytes" in s.get("ledger", {}) and "total_bytes" in s.get("ledger", {}), out[:200])
ok("stats: the process table is reported BY STATE",
   s.get("agents", {}).get("total", 0) >= 2
   and sum(s["agents"]["by_state"].values()) == s["agents"]["total"], out[:200])
ok("stats: the delivery queue is reported",
   "msgs_delivered" in s.get("delivery", {}), out[:200])
ok("stats: both connection budgets are reported",
   "active" in s.get("connections", {}) and "active" in s.get("control_connections", {}), out[:200])
ok("stats: the kernel uptime is reported",
   isinstance(s.get("uptime_ms"), int) and s["uptime_ms"] > 0, out[:200])

# ---- 2. ama inspect matches ama ps ----------------------------------
ps_out, ps_rc = cli("ps", "--socket", SOCK)
try:
    ps = {a["name"]: a for a in json.loads(ps_out)["agents"]}
except Exception:
    ps = {}
ok("ps: the verb succeeds", ps_rc == 0 and ps, ps_out[:200])
ins_out, ins_rc = cli("inspect", "--socket", SOCK, "--name", "a")
ok("inspect: the verb succeeds", ins_rc == 0, ins_out[:200])
try:
    one = json.loads(ins_out)
except Exception:
    one = {}
ok("inspect: it returns exactly ONE entry", isinstance(one, dict) and one.get("name") == "a",
   ins_out[:200])
ok("inspect: the entry is the SAME as the one ps shows",
   ps.get("a") == one, f"ps={ps.get('a')} inspect={one}")
missing_out, missing_rc = cli("inspect", "--socket", SOCK, "--name", "nobody")
ok("inspect: an unknown agent is an error, not an empty success",
   missing_rc != 0, f"rc={missing_rc} out={missing_out[:120]}")

# ---- 3. rotate + retention ------------------------------------------
before = len(events())
out, rc = cli("rotate", "--socket", SOCK, "--keep", "2")
ok("rotate: the verb succeeds", rc == 0, out)
try:
    rot = json.loads(out)
except Exception:
    rot = {}
ok("rotate: the reply names the retention", rot.get("kind") == "rotated", out[:200])
archives = [f for f in os.listdir("/tmp/ama_exp11") if ".segment-" in f]
ok("rotate: the segment was rolled (an archive exists)", len(archives) >= 1, str(archives))

# The rolled segment holds the PRE-rotation history: the raw checkpoint
# events must be in it (a rotation moves history aside, it does not
# delete it).
archived_cp = 0
for f in archives:
    try:
        with open(os.path.join("/tmp/ama_exp11", f)) as fh:
            for l in fh:
                if '"checkpoint"' in l:
                    archived_cp += 1
    except FileNotFoundError:
        pass
ok("recovery: the raw checkpoint events moved into the archive",
   archived_cp >= 1, f"archived checkpoints={archived_cp}")

# The ACTIVE file is now a snapshot: its `checkpoints` map IS the recovery
# index a respawn reads.
snap = []
try:
    with open(LEDGER) as f:
        for l in f:
            l = l.strip()
            if not l:
                continue
            try:
                snap.append(json.loads(l))
            except json.JSONDecodeError:
                pass
except FileNotFoundError:
    pass
snapshots = [e for e in snap if e["ev"] == "ledger_snapshot"]
ok("recovery: the active journal is a checkpoint SNAPSHOT after the roll",
   len(snapshots) == 1, str([e["ev"] for e in snap]))
cp_index = snapshots[0]["detail"].get("checkpoints", {}) if snapshots else {}
ok("recovery: the snapshot carries the checkpoint index", bool(cp_index), str(cp_index))
ok("recovery: the checkpoint state survived the rotation",
   any(isinstance(v, dict) and v.get("state", {}).get("n") == 0
       for v in cp_index.values()) if isinstance(cp_index, dict) else False,
   str(cp_index))

# roll again: the retention must now prune the OLDEST archive
out2, rc2 = cli("rotate", "--socket", SOCK, "--keep", "1")
try:
    rot2 = json.loads(out2)
except Exception:
    rot2 = {}
pruned = rot2.get("pruned", [])
ok("rotate: the retention pruned the oldest archive", len(pruned) >= 1, out2[:200])
archives_after = [f for f in os.listdir("/tmp/ama_exp11") if ".segment-" in f]
ok("rotate: exactly ONE archive is retained", len(archives_after) == 1, str(archives_after))
ok("rotate: the ACTIVE journal was not deleted",
   os.path.exists(LEDGER), LEDGER)

# the retention is journaled — in the journal that SURVIVED the retention
evs = events()
rotations = [e for e in evs if e["ev"] == "ledger_rotated"]
ok("audit: the rotation is journaled", len(rotations) >= 1, str(len(rotations)))
ok("audit: the journal records what was pruned",
   bool(rotations) and "pruned" in rotations[-1]["detail"], str(rotations[-1:]))
ok("audit: the rotation happened AFTER the workload (event order)",
   bool(rotations) and rotations[-1]["seq"] > before, str(rotations[-1:]))

# ---- 5. the new verbs need the operator credential ------------------
try:
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(CTL)
    c.sendall((json.dumps({"kind": "ctl_stats"}) + "\n").encode())
    c.settimeout(5)
    reply = c.recv(4096).decode().strip()
except Exception as e:
    reply = f"error: {e}"
try:
    parsed = json.loads(reply)
except Exception:
    parsed = {}
ok("authority: ctl_stats without the credential is refused",
   parsed.get("kind") == "error", reply[:200])
refusals = [e for e in events() if e["ev"] == "ctl_refused"]
ok("audit: the refusal is journaled", len(refusals) >= 1, str(len(refusals)))

# the agent socket refuses control verbs entirely (F02)
try:
    c2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c2.connect(SOCK)
    c2.sendall((json.dumps({"kind": "ctl_rotate", "token": TOKEN}) + "\n").encode())
    c2.settimeout(5)
    reply2 = c2.recv(4096).decode().strip()
except Exception as e:
    reply2 = f"error: {e}"
ok("authority: ctl_rotate is refused on the AGENT socket",
   "error" in reply2 and "operator socket" in reply2, reply2[:200])

print(f"\nledger: {len(events())} events")
all_pass = all(results)
print("EXPERIMENT_011:", "PASS" if all_pass else "FAIL")
sys.exit(0 if all_pass else 1)
PYEOF
VALIDATOR_RC=$?

kill $KERNEL_PID 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
exit $VALIDATOR_RC
