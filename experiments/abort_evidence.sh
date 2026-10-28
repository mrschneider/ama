#!/usr/bin/env bash
# Dump post-mortem evidence as GitHub annotations: ledger count + head
# + tail, kernel/agentd stderr, process table. Called from experiment
# ERR traps — a `set -e` abort before the validator used to be
# undiagnosable on CI (step stdout is admin-only).
[ -n "${GITHUB_ACTIONS:-}" ] || exit 0

if [ -f /tmp/ama_exp/ledger.jsonl ]; then
  echo "::error title=abort-ledger::total $(wc -l < /tmp/ama_exp/ledger.jsonl) events; first 5:"
  head -5 /tmp/ama_exp/ledger.jsonl | while IFS= read -r l; do
    echo "::error title=ledger::${l:0:400}"
  done
  echo "::error title=abort-ledger::last 10:"
  tail -10 /tmp/ama_exp/ledger.jsonl | while IFS= read -r l; do
    echo "::error title=ledger::${l:0:400}"
  done
fi

if [ -f /tmp/ama_exp/kernel.err ]; then
  echo "::error title=kernel::exists, $(wc -l < /tmp/ama_exp/kernel.err) lines; tail:"
  tail -4 /tmp/ama_exp/kernel.err | while IFS= read -r l; do
    echo "::error title=kernel::${l:0:300}"
  done
else
  echo "::error title=kernel::kernel.err MISSING"
fi

echo "::error title=dbgfiles::$(ls /tmp/ama_dbg_agent_*.stderr 2>/dev/null | tr '\n' ' ')"
for f in /tmp/ama_dbg_agent_*.stderr; do
  [ -f "$f" ] || continue
  tail -2 "$f" | while IFS= read -r l; do
    echo "::error title=$(basename "$f")::${l:0:300}"
  done
done

if [ -f /tmp/ama_exp/ps.json ]; then
  echo "::error title=abort-ps::$(tr -d ' \n' < /tmp/ama_exp/ps.json | head -c 700)"
fi

KP=$(pgrep -x ama | head -1 || true)
if [ -n "${KP:-}" ]; then
  echo "::error title=kpid::ama pid $KP alive; AMA_DEBUG in env: $(tr '\0' '\n' < /proc/$KP/environ | grep -c AMA_DEBUG || true)"
else
  echo "::error title=kpid::ama process NOT FOUND"
fi
echo "::error title=procs::$(pgrep -af 'ama-agentd|target/debug/ama ' | sed 's/.*bin\///' | cut -c1-90 | tr '\n' '|' | head -c 600)"
exit 0