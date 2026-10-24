# AMA — Agentic Microkernel Architecture

A microkernel architecture for reliable multi-agent systems, translated
from the QNX Neutrino microkernel design into the world of AI agent
execution: agents are **OS processes**, IPC is **typed message passing**
over Unix Domain Sockets, global state is an **append-only ledger**,
failures are contained by **isolation** and healed by **atomic respawn
from the last checkpoint**.

Everything below is **implemented and verified by running it**: the
experiment in `experiments/` executes the real kernel with 5 real agent
processes and asserts every behaviour from the ledger — see
[Verified results](#verified-results).

## A protocol run

```
ama serve --manifest manifest.json --agentd ./ama-agentd   # the Executive
```

Each agent in the manifest is spawned as its own OS process (`ama-agentd
--task <task.json>`): it registers on the kernel's UDS socket, then
executes its task — `send`, `wait`, `checkpoint`, `sleep`, `loop`,
`crash` — talking to the kernel and to other agents ONLY through typed
envelopes.

## What the kernel guarantees (v0.1)

**Minimal Executive (§1)** — the kernel holds only: the process table
(UIN, PID, capabilities, last heartbeat), the IPC router, and the
append-only ledger. Agents never write global state; they checkpoint
THEIR OWN state into the ledger and are recovered from it.

**Typed message passing (§3)** — every envelope is validated against a
strict per-kind schema by the kernel: `register`, `heartbeat` (with
`executing`/`blocked` phase — the watchdog distinguishes infinite
reasoning loops from legitimate I/O waits), `send`, `checkpoint`,
`done`. A malformed envelope is refused with a reason and journaled.

**Capability-based access (§3)** — an agent can only send to a target
listed in its process-table grants. A refused send is a journaled
security event (`cap_denied`), never a silent drop.

**Watchdog + fail-fast recovery (§4)** — heartbeat timeout AND a
progress watchdog (same reasoning step for K sweeps while `executing`)
kill the suspect with the reason journaled. Respawn is atomic: a fresh
process inherits the last ledger checkpoint and resumes. A respawn
budget turns persistent crashers into `dead` instead of restarting
forever.

**Isolation (§2)** — each agent is a separate PID; its ephemeral memory
dies with the process. cgroup v2 memory/CPU limits are applied
best-effort when `/sys/fs/cgroup/ama` is writable.

## Verified results

`experiments/experiment_001_isolation.sh` (14 s end-to-end, 5 real
processes):

```
PASS: isolation: 5 agents spawned as distinct OS processes
PASS: schema: malformed envelope rejected (invalid json)
PASS: ipc: a (uin 1) received b's ping
PASS: ipc: b (uin 0) received a's pong
PASS: ipc: round trip completed both sides (a and b tasks completed)
PASS: capabilities: m's send to c was refused and journaled
PASS: capabilities: no message was delivered on the denied attempt
PASS: watchdog: infinite reasoning loop detected via progress watchdog
PASS: watchdog: respawn budget enforced (d died after the budget)
PASS: recovery: c checkpointed n=0 before the external kill
PASS: recovery: the kernel detected the external kill and respawned c from the ledger
PASS: recovery: c resumed FROM the checkpoint (n=1 after respawn)
PASS: isolation: parallel agents unaffected by c's crash and d's loop
EXPERIMENT_001: PASS
```

Scenario: `b` pings `a` (typed envelope, capability-checked, journaled);
`a` pongs back and both complete. `c` checkpoints, is killed externally
(`kill -9`, the OOM/operator path), resumes from its ledger checkpoint
at the exact step it died on, and completes. `d` runs an infinite
reasoning loop — the progress watchdog detects the stuck step in
`executing` phase, kills it, and exhausts the respawn budget. `m`
attempts to reach an agent it has no capability for — refused and
journaled. All five ran as distinct OS processes.

## Deliberately not implemented (v0.1)

- **MicroVM tool-jails**: the brief's "Tool Execution Jails" — agents
  that execute LLM-generated code inside nested ephemeral VMs. The
  process boundary is the v0.1 isolation unit; cgroup pinning is
  best-effort.
- **seccomp-bpf syscall filters**: same frontier.
- **Network-distributed message passing**: v0.1 is single-host UDS by
  design (the brief rejects network brokers for the local case).
- **FlatBuffers/protobuf wire format**: strict per-kind JSON schema
  validation in the kernel — the enforcement point is the kernel.
- **Hot capability renegotiation**: grants are fixed at registration.

## Layout

- `ama-core/` — the kernel library: envelopes, ledger, process table,
  router, watchdog, supervisor, sandbox
- `ama-agentd/` — the agent-side process (`ama-agentd`)
- `ama-cli/` — the `ama` binary (`serve`, `ps`)
- `experiments/` — runnable E2E proof + task manifests
- `docs/research/qnx-microkernel.md` — the QNX design sources this
  architecture is translated from, with the deliberate-scope notes

## Build

```bash
cargo build            # ama-core (lib) + ama-agentd + ama
cargo test             # unit tests
bash experiments/experiment_001_isolation.sh   # the E2E proof
```

## License

Apache-2.0.
