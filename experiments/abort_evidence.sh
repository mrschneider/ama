#!/usr/bin/env bash
# Dump post-mortem evidence as GitHub annotations: ledger tail, agentd
# stderr files, process table. Called from experiment ERR traps — a
# `set -e` abort before the validator used to be undiagnosable on CI
# (stdout of passing/failing steps is admin-only).
[ -n "${GITHUB_ACTIONS:-}" ] || exit 0

if [ -f /tmp/ama_exp/ledger.jsonl ]; then
  head -12 /tmp/ama_exp/ledger.jsonl | while IFS= read -r l; do
    echo "::error title=abort-ledger::${l:0:400}"
  done
fi

if [ -f /tmp/ama_exp/kernel.err ]; then
  tail -6 /tmp/ama_exp/kernel.err | while IFS= read -r l; do
    echo "::error title=kernel::${l:0:300}"
  done
fi

for f in /tmp/ama_dbg_agent_*.stderr; do
  [ -f "$f" ] || continue
  tail -3 "$f" | while IFS= read -r l; do
    echo "::error title=$(basename "$f")::${l:0:300}"
  done
done

if [ -f /tmp/ama_exp/ps.json ]; then
  echo "::error title=abort-ps::$(tr -d ' \n' < /tmp/ama_exp/ps.json | head -c 800)"
fi
exit 0