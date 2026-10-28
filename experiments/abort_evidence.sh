#!/usr/bin/env bash
# ONE annotation carrying ALL post-mortem evidence — GitHub Actions
# drops workflow-command annotations beyond 10 PER STEP (this cost us
# every section after the 10th line), and multi-line messages must use
# %0A. Called from experiment ERR traps: a `set -e` abort before the
# validator used to be undiagnosable on CI (step stdout is admin-only).
[ -n "${GITHUB_ACTIONS:-}" ] || exit 0
# the validator's own evidence annotation supersedes this dump
LEDGER="${LEDGER:-/tmp/ama_exp/ledger.jsonl}"
EXPDIR="$(dirname "$LEDGER")"
[ -f "$EXPDIR/.evidence_printed" ] && exit 0

EVIDENCE=""
add() { EVIDENCE="${EVIDENCE}%0A$1"; }

if [ -f "$LEDGER" ]; then
  add "LEDGER total $(wc -l < "$LEDGER"): first 5:"
  while IFS= read -r l; do add "${l:0:350}"; done < <(head -5 "$LEDGER")
  add "LEDGER last 12:"
  while IFS= read -r l; do add "${l:0:350}"; done < <(tail -12 "$LEDGER")
else
  add "LEDGER MISSING"
fi

if [ -f /tmp/ama_exp/kernel.err ]; then
  add "KERNELERR $(wc -l < /tmp/ama_exp/kernel.err) lines, tail 5:"
  while IFS= read -r l; do add "k: ${l:0:250}"; done < <(tail -5 /tmp/ama_exp/kernel.err)
else
  add "KERNELERR MISSING"
fi

add "DBGFILES: $(ls /tmp/ama_dbg_agent_*.stderr 2>/dev/null | tr '\n' ' ')"
for f in /tmp/ama_dbg_agent_*.stderr; do
  [ -f "$f" ] || continue
  while IFS= read -r l; do add "$(basename "$f"): ${l:0:250}"; done < <(tail -3 "$f")
done

if [ -f /tmp/ama_exp/ps.json ]; then
  add "PS: $(tr -d ' \n' < /tmp/ama_exp/ps.json | head -c 600)"
fi

KP=$(pgrep -x ama | head -1 || true)
if [ -n "${KP:-}" ]; then
  add "KPID: pid $KP alive; AMA_DEBUG in env: $(tr '\0' '\n' < /proc/$KP/environ | grep -c AMA_DEBUG || true)"
else
  add "KPID: ama process NOT FOUND"
fi
add "PROCS: $(pgrep -af 'ama-agentd|target/debug/ama ' | sed 's/.*bin\///' | cut -c1-80 | tr '\n' ';' | head -c 500)"

echo "::error title=AMA evidence::${EVIDENCE}"
exit 0