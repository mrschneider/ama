#!/usr/bin/env bash
# AMA experiment 009 — NEGATIVE authority tests (F01/F02/F10 remediation gate).
#
# Every check here is a REFUSAL the kernel must enforce:
#   1. an unregistered connection cannot issue agent operations
#   2. an instance identity cannot be registered without its CURRENT
#      token — live, dead, or stale (F10: no unauthenticated claims)
#   3. a registered session cannot act as ANOTHER agent (identity_mismatch)
#   4. task-supplied caps never become grants (and an OMITTED manifest
#      policy grants NOTHING — F10)
#   5. control verbs are refused on the agent socket
#   6. the operator socket needs the operator CREDENTIAL (F10) — and a
#      peer whose pid is a spawned agent is refused at the DOOR even
#      holding a valid credential
#   7. operator grants/revocations survive a restart, and only the
#      operator's explicit ctl_restart brings a dead identity back
#   8. custody refusals + security events journaled
set -euo pipefail
# F10: operator authority is a CREDENTIAL — the kernel and this
# operator CLI must share it; agents are stripped of it at spawn
export AMA_OPERATOR_TOKEN="ama-local-operator-token"
cd "$(dirname "$0")/.."
# evidence blocks (and abort_evidence.sh) read $LEDGER — 009 keeps its
# own ledger directory
export LEDGER=/tmp/ama_exp9/ledger.jsonl
export AMA_DEBUG=1
set -E
# an abort before the validator must still leave evidence (F03)
trap 'echo "::error title=abort::experiment aborted at line $LINENO (cmd: ${BASH_COMMAND:0:100})"; bash experiments/abort_evidence.sh || true' ERR
rm -rf /tmp/ama_exp9
mkdir -p /tmp/ama_exp9
rm -f /tmp/ama_exp9.sock /tmp/ama_exp9.sock.ctl
pkill -9 -x ama 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
sleep 1

# F03: readiness polling inside the validator replaces fixed sleeps —
# the kernel gets a generous budget because every phase waits for an
# EVENT, never for the clock
timeout 60 ./target/debug/ama serve \
  --manifest experiments/manifest_009.json \
  --agentd ./target/debug/ama-agentd 2>/tmp/ama_exp9/kernel.err &
KERNEL_PID=$!

python3 - <<'PYEOF'
import glob
import json
import os
import socket
import subprocess
import sys
import time

results = []
SOCK = "/tmp/ama_exp9.sock"
CTL = SOCK + ".ctl"
LEDGER = "/tmp/ama_exp9/ledger.jsonl"
OPERATOR_TOKEN = os.environ["AMA_OPERATOR_TOKEN"]


def ok(label, cond, extra=""):
    results.append(bool(cond))
    print(("PASS: " if cond else "FAIL: ") + label + ((" | " + extra) if extra and not cond else ""))


def line(sockobj):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sockobj.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode()


def send(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode())


def events():
    try:
        return [json.loads(l) for l in open(LEDGER)]
    except FileNotFoundError:
        return []


def ctl_conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(CTL)
    return s


def ctl(s, obj):
    """operator verb WITH the credential; returns the parsed reply"""
    send(s, dict(obj, token=OPERATOR_TOKEN))
    return json.loads(line(s))


def ps(s):
    r = ctl(s, {"kind": "ctl_ps"})
    return {a["name"]: a for a in r.get("agents", [])} if r.get("kind") == "ps" else {}


def wait_for(pred, timeout=20, what=""):
    """F03: poll the LEDGER / ps until `pred` holds — never sleep-and-hope"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.2)
    print(f"  [timeout] {what}", flush=True)
    return False


def register_error(sock_path, req, want, timeout=20):
    """Open a FRESH connection and send `req`, retrying until the refusal
    we are testing appears. Right after a kill the entry can still read
    as Running for a moment, whose refusal is a different (legitimate)
    message — polling for `want` keeps the check about ITS claim."""
    deadline = time.time() + timeout
    r = None
    while time.time() < deadline:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        send(s, req)
        r = json.loads(line(s))
        if r.get("kind") == "error" and want in r.get("reason", ""):
            return r, s
        s.close()
        time.sleep(0.3)
    return r, None


def env_token(pid):
    """Instance credential of a spawned agent, read from its /proc entry —
    the same way any same-uid process could. This is NOT the operator
    credential (agents never receive AMA_OPERATOR_TOKEN and the kernel is
    non-dumpable); it is per-instance authenticity, and the test needs it
    only to prove that EVEN a correct token cannot cross instance lines."""
    raw = open(f"/proc/{pid}/environ", "rb").read()
    for item in raw.split(b"\0"):
        if item.startswith(b"AMA_REGISTER_TOKEN="):
            return item.split(b"=", 1)[1].decode()
    return None


# ---- readiness: the manifest's agents are up (F03) -----------------------
def registered_names():
    return {e["detail"].get("name") for e in events() if e["ev"] == "registered"}


assert wait_for(lambda: {"a", "b", "x"} <= registered_names(), 20,
                "agents a/b/x never registered"), "agents failed to register"
ev = events()
uin_of = {e["detail"]["name"]: e["detail"]["uin"] for e in ev if e["ev"] == "spawned"}
pid_of = {e["detail"]["name"]: e["detail"]["pid"] for e in ev if e["ev"] == "spawned"}
uin_a, uin_b = uin_of["a"], uin_of["b"]

# ---- 1. unregistered connection cannot issue agent operations ------------
atk = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
atk.connect(SOCK)
send(atk, {"kind": "send", "uin": uin_b, "to": "a", "body": {"x": 1}})
r = json.loads(line(atk))
ok("identity: an UNREGISTERED connection cannot issue agent operations",
   r.get("kind") == "error" and "register" in r.get("reason", ""))

# ---- 2. a LIVE identity cannot be taken without its token ---------------
send(atk, {"kind": "register", "name": "b", "caps": ["send:a"],
           "pid": pid_of["b"], "token": "forged"})
r = json.loads(line(atk))
ok("identity: a LIVE agent's identity is refused WITHOUT its registration token",
   r.get("kind") == "error" and "token" in r.get("reason", ""))

# ---- 5. control verbs on the agent socket are refused -------------------
send(atk, {"kind": "ctl_grant", "name": "b", "caps": ["send:c"]})
r = json.loads(line(atk))
ok("authority: ctl verbs are REFUSED on the agent listener",
   r.get("kind") == "error" and "operator socket" in r.get("reason", ""))

# ---- 6a. the operator socket works, WITH the credential -----------------
ctl_sock = ctl_conn()
r = ctl(ctl_sock, {"kind": "ctl_ps"})
ok("authority: the operator socket serves ctl_ps (peer-credential + token)",
   r.get("kind") == "ps" and len(r.get("agents", [])) >= 3,
   f"got {r}")

# and WITHOUT the credential on the CONTROL socket itself — this is
# exactly what an agent could present, since agents are stripped of
# AMA_OPERATOR_TOKEN at spawn (and the kernel is non-dumpable, so they
# cannot read it back from /proc)
bare = ctl_conn()
send(bare, {"kind": "ctl_ps"})
r = json.loads(line(bare))
bare.close()
ok("authority: a control connection WITHOUT the operator credential is refused",
   r.get("kind") == "error" and "token" in r.get("reason", ""), f"got {r}")

# ---- 6b. operator grants at runtime -------------------------------------
r = ctl(ctl_sock, {"kind": "ctl_grant", "name": "a", "caps": ["send:c"]})
ok("authority: the operator socket GRANTS a capability at runtime",
   r.get("kind") == "granted", f"got {r}")

# a forged-token register of a LIVE agent is still refused
send(atk, {"kind": "register", "name": "a", "caps": ["send:b"],
           "pid": pid_of["a"], "token": "forged"})
r = json.loads(line(atk))
ok("identity: a forged-token register of a LIVE agent is refused",
   r.get("kind") == "error" and "token" in r.get("reason", ""))
atk.close()

# ---- 4b. an OMITTED capability policy grants NOTHING (F10) --------------
# agent x's manifest entry declares no caps while its TASK asks for
# send:c — the manifest is the trusted source, so x's effective caps are
# empty even though the task requested one
p = ctl(ctl_sock, {"kind": "ctl_ps"})
x_caps = p.get("agents", [{}])
x_caps = next((a["caps"] for a in x_caps if a["name"] == "x"), None)
ok("authority: an OMITTED manifest cap policy yields NO grants (x has none)",
   x_caps == [], f"x caps = {x_caps!r}")

# ---- operator policy on a DEAD identity + authorized restart ------------
# steal b's instance token while it is alive, then kill it (manifest
# max_respawns=0: the kernel judges it Dead and does NOT respawn)
token_b1 = env_token(pid_of["b"])
ok("setup: b's instance token readable for the test", bool(token_b1))
subprocess.run(["pkill", "-9", "-f", "tasks_009/b.json"], check=False)


def b_dead_at_least(n):
    return len([e for e in events()
                if e["ev"] == "dead" and e["detail"].get("name") == "b"]) >= n


assert wait_for(lambda: b_dead_at_least(1), 15, "b never judged dead"), "b not dead"

# ---- 2b. a DEAD identity cannot be claimed WITHOUT a credential ---------
r, s = register_error(SOCK, {"kind": "register", "name": "b",
                             "caps": ["send:a", "send:c", "send:sneaky"],
                             "pid": os.getpid()}, want="token")
ok("identity: a DEAD agent's identity may NOT be claimed without its token",
   r.get("kind") == "error" and "token" in r.get("reason", ""),
   f"got {r}")
if s:
    s.close()

# operator revokes a capability while b is dead (policy, not process state)
r = ctl(ctl_sock, {"kind": "ctl_revoke", "name": "b", "caps": ["send:a"]})
ok("authority: the operator socket REVOKES a capability at runtime",
   r.get("kind") == "revoked", f"got {r}")

# the EXPLICIT restart: only the operator can bring the dead entry back
r = ctl(ctl_conn(), {"kind": "ctl_restart", "name": "b"})
ok("authority: ctl_restart brings a dead identity back (operator-authorized)",
   r.get("kind") == "restarted", f"got {r}")


def b_registered_again():
    evs = [e for e in events() if e["ev"] == "registered"
           and e["detail"].get("name") == "b"]
    return len(evs) >= 2


assert wait_for(b_registered_again, 20, "restarted b never re-registered"), "restart failed"

# the revocation SURVIVED the restart: fresh b's effective caps lack send:a
p = ctl(ctl_conn(), {"kind": "ctl_ps"})
b_caps = next((a["caps"] for a in p.get("agents", []) if a["name"] == "b"), None)
ok("authority: the operator revocation SURVIVES an authorized restart",
   isinstance(b_caps, list) and "send:a" not in b_caps, f"b caps = {b_caps!r}")

# ---- 2c. the STALE token of the pre-restart instance is rejected --------
r, s = register_error(SOCK, {"kind": "register", "name": "b",
                             "caps": ["send:a"], "pid": os.getpid(),
                             "token": token_b1}, want="token")
ok("identity: the STALE token of a replaced instance is rejected",
   r.get("kind") == "error" and "token" in r.get("reason", ""),
   f"got {r}")
if s:
    s.close()

# kill the RESTARTED b (again max_respawns=0 -> Dead, token unchanged)
ev = events()
# a RESPAWN journals `respawned` (not `spawned`) — the fresh pid lives
# there; taking the last `spawned` handed us the dead pid (reused by
# some other process -> EACCES instead of ENOENT)
pid_b2 = [e["detail"]["pid"] for e in ev
          if e["ev"] in ("spawned", "respawned")
          and e["detail"].get("name") == "b"][-1]
token_b2 = env_token(pid_b2)
ok("setup: restarted b's token readable for the test", bool(token_b2))
subprocess.run(["pkill", "-9", "-f", "tasks_009/b.json"], check=False)
assert wait_for(lambda: b_dead_at_least(2), 15, "restarted b never died"), "b2 not dead"

# ---- 2d. an AUTHENTICATED claim of the dead identity (current token) ----
send_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
send_sock.connect(SOCK)
send(send_sock, {"kind": "register", "name": "b",
                 "caps": ["send:a", "send:c"], "pid": os.getpid(),
                 "token": token_b2})
r = json.loads(line(send_sock))
ok("identity: the CURRENT token holder may take the dead identity",
   r.get("kind") == "welcome", f"got {r}")
uin_b2 = r.get("uin")

# ---- 6c. THE DOOR: this session's pid is now in the agent table ---------
# ...so even a CORRECT operator credential is refused on a fresh control
# connection. This is the acceptance check: a real agent process cannot
# invoke ctl_grant through a fresh connection to the control socket.
door = ctl_conn()
send(door, {"kind": "ctl_grant", "name": "a", "caps": ["send:sneaky"],
            "token": OPERATOR_TOKEN})
door.settimeout(3)
try:
    raw = line(door)
except (socket.timeout, OSError):
    raw = ""   # refused at the door: no reply, connection dropped
door.close()
ok("authority: a spawned agent's PID is refused at the ctl DOOR "
   "even with a valid operator credential",
   raw == "" or ("error" in raw and "granted" not in raw),
   f"reply={raw!r}")

# ---- 3+4. session checks: caps stay manifest-bound, identity is bound ---
send(send_sock, {"kind": "send", "uin": uin_b2, "to": "c", "body": {"n": 1}})
r = json.loads(line(send_sock))
ok("authority: task-requested caps DO NOT become grants (send:c refused)",
   r.get("kind") == "error" and "capability" in r.get("reason", ""),
   f"got {r}")

send(send_sock, {"kind": "send", "uin": uin_a, "to": "b", "body": {"n": 1}})
r = json.loads(line(send_sock))
ok("identity: a session CANNOT act as another agent (claimed uin refused)",
   r.get("kind") == "error" and "does not match the session" in r.get("reason", ""),
   f"got {r}")

send(send_sock, {"kind": "heartbeat", "uin": uin_a, "step": "s", "phase": "executing"})
r = json.loads(line(send_sock))
ok("identity: heartbeat AS another agent is refused",
   r.get("kind") == "error" and "does not match the session" in r.get("reason", ""),
   f"got {r}")

# ---- 8. custody ownership (wire-level) ----------------------------------
send(send_sock, {"kind": "custody_ack", "bundle_id": 999})
r = json.loads(line(send_sock))
ok("custody: a session that holds NO custody cannot acknowledge a transfer",
   r.get("kind") == "error" and "custody" in r.get("reason", ""),
   f"got {r}")

# ---- ledger audit: the refusals are journaled security events -----------
kinds = [e["ev"] for e in events()]
ok("audit: identity refusals AND ctl refusals are journaled",
   "identity_refused" in kinds and "ctl_refused" in kinds,
   f"kinds={sorted(set(kinds))}")

print(f"\nledger: {len(events())} events")
all_pass = all(results)
print("EXPERIMENT_009:", "PASS" if all_pass else "FAIL")
if not (all_pass and all(results)) and os.environ.get("GITHUB_ACTIONS"):
    # ONE annotation: GitHub drops workflow commands beyond 10/step
    parts = []
    try:
        lines = open(LEDGER).read().splitlines()
        parts.append(f"LEDGER {len(lines)} events: first 8")
        parts.extend(l[:340] for l in lines[:8])
        if len(lines) > 8:
            parts.append("last 16:")
            parts.extend(l[:340] for l in lines[-16:])
    except Exception as e:
        parts.append(f"LEDGER unreadable: {e}")
    for f in sorted(glob.glob("/tmp/ama_dbg_agent_*.stderr")):
        try:
            tail = [l for l in open(f).read().splitlines() if l.strip()][-3:]
            for l in tail:
                parts.append(f"{f.split('/')[-1]}: {l[:250]}")
        except Exception:
            pass
    try:
        kl = open("/tmp/ama_exp9/kernel.err").read().splitlines()[-4:]
        parts.extend(f"k: {l[:250]}" for l in kl)
    except Exception:
        pass
    print("::error title=evidence::" + "%0A".join(parts), flush=True)
    try:
        open("/tmp/ama_exp9/.evidence_printed", "w").write("1")
    except Exception:
        pass
sys.exit(0 if all_pass and all(results) else 1)
PYEOF

kill $KERNEL_PID 2>/dev/null || true
pkill -9 -x ama-agentd 2>/dev/null || true
exit 0