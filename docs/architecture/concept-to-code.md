# Concept-to-code map (brief → implementation)

| Brief section | Concept | Where it lives | Verified by |
|---|---|---|---|
| §1 Executive | Process Table & Lifecycle | `ama-core/src/lib.rs` `Kernel`/`ProcEntry` | experiment: 5 spawned, distinct PIDs |
| §1 Executive | Global State Ledger (immutable) | `Ledger` (append-only JSONL, seq + ts) | ledger replay: last checkpoint wins |
| §1 Executive | IPC Router | `Router` (UDS listener, thread-per-conn) | experiment: a↔b ping/pong journaled |
| §2 Sandboxes | Process isolation | `spawn_agent` (own PID, ephemeral memory) | distinct PIDs; crash ≠ sibling corruption |
| §2 Sandboxes | Resource limits | `sandbox.rs` cgroup v2 (best-effort) | works when the cgroup dir is writable |
| §3 IPC | Typed message contract | `Envelope::parse` strict per-kind schema | malformed envelope rejected + journaled |
| §3 IPC | Capability-based security | `check_cap` on every send | m's send to c refused + journaled |
| §4 Health | Heartbeat watchdog | `sweep()` every 200 ms | d's stale progress killed with reason |
| §4 Health | Infinite-loop detection | progress watchdog (`executing` phase only) | blocked ≠ loop; loop dies after K sweeps |
| §4 Health | Atomic respawn | `respawn()` from `last_checkpoint` | c killed externally → resumed at step → completed |
| §4 Health | Respawn budget | `max_respawns` → `Dead` | d reached budget, stopped restarting |
| §3 IPC | Prompt-injection containment | crash of a rogue agent is isolated; peers unaffected | a/b completed while c/d/m failed |

## Invariants

1. Agents never hold global state — only the ledger does.
2. Every cross-agent message passes capability check first; refusals are
   journaled.
3. A process failure is retried at most `max_respawns` times, then
   marked `Dead` — the system degrades, it does not spin.
4. Recovery state comes ONLY from the ledger's last checkpoint for that
   UIN — the fresh process's memory is never trusted.
