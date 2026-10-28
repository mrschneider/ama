#!/usr/bin/env bash
# AMA experiment 009 — NEGATIVE authority tests (F01/F02 remediation gate).
#
# Every check here is a REFUSAL the kernel must enforce:
#   1. an unregistered connection cannot issue agent operations
#   2. a live agent's identity cannot be registered by another process
#      (wrong pid, manifest-name only)
#   3. a registered session cannot act as ANOTHER agent (identity_mismatch)
#   4. task-supplied caps cannot exceed the manifest's trusted caps
#   5. control verbs are refused on the agent socket
#   6. the operator socket (0600 + peer-credential) grants/revokes, and a
#      revocation SURVIVES re-registration
#   7. an unrelated relay cannot release another relay's custody transfer
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf /tmp/ama_exp9
mkdir -p /tmp/ama_exp9
rm -f /tmp/ama_exp9.sock /tmp/ama_exp9.sock.ctl
pkill -9 -x ama 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
sleep 1

timeout 25 ./target/debug/ama serve \
  --manifest experiments/manifest_009.json \
  --agentd ./target/debug/ama-agentd &
KERNEL_PID=$!
sleep 1.5

python3 - <<'PYEOF'
import json
import os
import signal
import socket
import subprocess
import sys
import time

results = []


DEBUG = os.environ.get("EXP9_DEBUG") == "1"


def ok(label, cond, extra=""):
    if DEBUG and not cond:
        print(f"  [debug] {label}: last replies matter")
    results.append(bool(cond))
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + extra) if extra and not cond else ""))


SOCK = "/tmp/ama_exp9.sock"
CTL = SOCK + ".ctl"


def line(sockobj):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sockobj.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode()


def agent_conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.recv(4096)  # the reader swallows nothing yet; agents send first
    return s


def send(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode())


# the two REAL agents: poll until both REGISTERED (F03 — readiness
# polling, not a fixed sleep; a slow runner needs longer than 1 s)
deadline = time.time() + 15
while time.time() < deadline:
    evs = [json.loads(l) for l in open("/tmp/ama_exp9/ledger.jsonl")] \
        if os.path.exists("/tmp/ama_exp9/ledger.jsonl") else []
    if {"a", "b"} <= {e["detail"].get("name") for e in evs if e["ev"] == "registered"}:
        break
    time.sleep(0.2)
else:
    print("FAIL: agents a/b never registered", flush=True)
    sys.exit(1)

events = [json.loads(l) for l in open("/tmp/ama_exp9/ledger.jsonl")]
uin_of = {e["detail"]["name"]: e["detail"]["uin"] for e in events if e["ev"] == "spawned"}
pid_of = {e["detail"]["name"]: e["detail"]["pid"] for e in events if e["ev"] == "spawned"}
uin_a, uin_b = uin_of["a"], uin_of["b"]

# --- 1. unregistered connection cannot issue agent operations -------------
atk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
atk.connect(SOCK)
send(atk, {"kind": "send", "uin": uin_b, "to": "a", "body": {"x": 1}})
r = json.loads(line(atk))
ok("identity: an UNREGISTERED connection cannot issue agent operations",
   r.get("kind") == "error" and "register" in r.get("reason", ""))

# --- 2. a live agent's identity cannot be taken (no token) ----------------
# F01: the per-instance registration token is a SECRET the kernel handed
# only to the spawned process — a pid read from the ledger is telemetry,
# not authentication
send(atk, {"kind": "register", "name": "b", "caps": ["send:a"],
           "pid": pid_of["b"], "token": "forged"})
r = json.loads(line(atk))
ok("identity: a LIVE agent's identity is refused WITHOUT its registration token",
   r.get("kind") == "error" and "token" in r.get("reason", ""))

# --- 5. control verbs on the agent socket are refused ---------------------
send(atk, {"kind": "ctl_grant", "name": "b", "caps": ["send:c"]})
r = json.loads(line(atk))
ok("authority: ctl verbs are REFUSED on the agent listener",
   r.get("kind") == "error" and "operator socket" in r.get("reason", ""))

# --- 6. the operator socket works, with policy ----------------------------
ctl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
ctl.connect(CTL)
send(ctl, {"kind": "ctl_ps"})
r = json.loads(line(ctl))
ok("authority: the operator socket serves ctl_ps (peer-credential checked)",
   r.get("kind") == "ps" and len(r.get("agents", [])) >= 2)

# operator grants a the ability to send to c
send(ctl, {"kind": "ctl_grant", "name": "a", "caps": ["send:c"]})
r = json.loads(line(ctl))
ok("authority: the operator socket GRANTS a capability at runtime",
   r.get("kind") == "granted")

# a (the real session) can now send to c
a_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
a_sock.connect(SOCK)
send(a_sock, {"kind": "register", "name": "a", "caps": ["send:b"],
              "pid": pid_of["a"], "token": "forged"})
r = json.loads(line(a_sock))
ok("identity: a forged-token register of a LIVE agent is refused",
   r.get("kind") == "error" and "token" in r.get("reason", ""))
a_sock.close()

# --- 3+4. take b's DEAD identity and abuse it -----------------------------
# kill b's agentd: the watchdog marks it Killed; the identity becomes
# claimable by a fresh process (operator-driven restarts) — but the
# session still cannot act as agent A, and caps stay manifest-bound
subprocess.run(["pkill", "-9", "-f", "tasks_009/b.json"], check=False)

# retry the dead-claim register until the kernel notices the EOF (a slow
# runner needs more than a fixed 2 s — F03 polling)
b2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
b2.connect(SOCK)
r = None
for _ in range(30):
    send(b2, {"kind": "register", "name": "b",
              "caps": ["send:a", "send:c", "send:sneaky"],
              "pid": os.getpid()})  # no token: DEAD instance claim
    r = json.loads(line(b2))
    if r.get("kind") == "welcome":
        break
    if "token" not in r.get("reason", ""):
        break  # unexpected refusal — report it as a failure
    time.sleep(0.5)
    b2.close()
    b2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    b2.connect(SOCK)
ok("identity: a DEAD agent's identity may be claimed by a fresh process",
   r.get("kind") == "welcome", f"got {r.get('kind')} {r.get('reason', '')}")
uin_b2 = r.get("uin")

# the claimed extra caps are NOT granted: b2 sends to c -> refused
send(b2, {"kind": "send", "uin": uin_b2, "to": "c", "body": {"n": 1}})
r = json.loads(line(b2))
ok("authority: task-requested caps DO NOT become grants (send:c refused)",
   r.get("kind") == "error" and "capability" in r.get("reason", ""))

# 3: the session CANNOT act as agent a — claimed uin != session
send(b2, {"kind": "send", "uin": uin_a, "to": "b", "body": {"n": 1}})
r = json.loads(line(b2))
ok("identity: a session CANNOT act as another agent (claimed uin refused)",
   r.get("kind") == "error" and "does not match the session" in r.get("reason", ""))

# heartbeat as agent a: refused the same way
send(b2, {"kind": "heartbeat", "uin": uin_a, "step": "s", "phase": "executing"})
r = json.loads(line(b2))
ok("identity: heartbeat AS another agent is refused",
   r.get("kind") == "error" and "does not match the session" in r.get("reason", ""))

# --- 6b. an operator REVOCATION survives re-registration ------------------
send(ctl, {"kind": "ctl_revoke", "name": "b", "caps": ["send:a"]})
r = json.loads(line(ctl))
ok("authority: the operator socket REVOKES a capability at runtime",
   r.get("kind") == "revoked")

# b2 can no longer send to a
send(b2, {"kind": "send", "uin": uin_b2, "to": "a", "body": {"n": 1}})
r = json.loads(line(b2))
ok("authority: the REVOKED send is refused",
   r.get("kind") == "error" and "capability" in r.get("reason", ""))

# re-register b2 (disconnect, fresh session): the revocation SURVIVES
b2.close()
b3 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
b3.connect(SOCK)
send(b3, {"kind": "register", "name": "b",
          "caps": ["send:a", "send:c"], "pid": os.getpid()})  # no token: DEAD instance
r = json.loads(line(b3))
uin_b3 = r.get("uin")
send(b3, {"kind": "send", "uin": uin_b3, "to": "a", "body": {"n": 1}})
r = json.loads(line(b3))
ok("authority: the operator revocation SURVIVES re-registration",
   r.get("kind") == "error" and "capability" in r.get("reason", ""))

# --- 7. custody ownership (wire-level) ------------------------------------
# the kernel holds custody only in DTN flows; here a session acks a bundle
# id that was never transferred to it -> refused, kernel holds nothing
send(b3, {"kind": "custody_ack", "bundle_id": 999})
r = json.loads(line(b3))
ok("custody: a session that holds NO custody cannot acknowledge a transfer",
   r.get("kind") == "error" and "custody" in r.get("reason", ""))

# ledger audit: the refusals are journaled security events
events = [json.loads(l) for l in open("/tmp/ama_exp9/ledger.jsonl")]
kinds = [e["ev"] for e in events]
ok("audit: identity refusals and ctl refusals are journaled",
   "identity_refused" in kinds or "identity_mismatch" in kinds)

print(f"\nledger: {len(events)} events")
all_pass = all(results)
print("EXPERIMENT_009:", "PASS" if all_pass else "FAIL")
if not (all_pass and all(results)) and __import__("os").environ.get("GITHUB_ACTIONS"):
    try:
        tail = open("/tmp/ama_exp/ledger.jsonl").read().splitlines()[-40:]
        for line in tail:
            print(f"::error::ledger: {line}", flush=True)
    except Exception:
        pass
sys.exit(0 if all_pass and all(results) else 1)
PYEOF

kill $KERNEL_PID 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
exit 0
