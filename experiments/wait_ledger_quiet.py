"""Wait until the ledger goes quiet (no new events for `quiet_s` seconds).

Usage: python3 experiments/wait_ledger_quiet.py [quiet_s] [max_s]

The workload journals every meaningful transition (delivered, completed,
checkpoint, dead, ...), so a quiet ledger means the work is done — on a
slow runner the same work just takes longer. Always exits 0: the
VALIDATOR decides pass/fail; this only replaces fixed sleeps with
readiness polling (F03).
"""
import json
import os
import sys
import time

quiet_s = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
max_s = float(sys.argv[2]) if len(sys.argv) > 2 else 35.0
ledger = os.environ.get("AMA_LEDGER", "/tmp/ama_exp/ledger.jsonl")

deadline = time.time() + max_s
last_count = -1
last_change = time.time()
while time.time() < deadline:
    try:
        with open(ledger) as f:
            n = sum(1 for _ in f)
    except FileNotFoundError:
        n = -1
    if n != last_count:
        last_count = n
        last_change = time.time()
    elif time.time() - last_change >= quiet_s:
        print(f"== ledger quiet for {quiet_s}s ({max(0, n)} events); validating ==", flush=True)
        sys.exit(0)
    time.sleep(0.3)
print(f"== max wait {max_s}s reached; validating anyway ==", flush=True)
sys.exit(0)