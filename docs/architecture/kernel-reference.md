# AMA kernel reference

Deep reference for the README: the full kernel contract, the verified
experiment transcripts, and the release history. The README stays lean;
everything lives here.

## What the kernel guarantees

**Minimal Executive (§1)** — the kernel holds only the process table
(UIN, PID, capabilities, last heartbeat), the IPC router, and the
append-only ledger. Agents checkpoint their *own* state into the ledger
and are recovered from it.

**Typed message passing (§3)** — every envelope is validated against a
strict per-kind schema: `register`, `heartbeat` (with
`executing`/`blocked` phase — the watchdog distinguishes infinite
reasoning loops from legitimate I/O waits), `send`, `checkpoint`,
`done`. Malformed envelopes are refused with a reason and journaled.

**Capability-based access (§3)** — an agent can only send to targets
listed in its process-table grants. Refused sends are journaled
(`cap_denied`).

**QoS: scheduling, admission, accounting (§3)** — a real stack, not a
single throttle:

- **Weighted Fair Queueing.** The kernel models the delivery link with a
  per-tick byte budget (`link_bytes_per_tick`). When the link is
  backlogged, messages are served by virtual finish tag
  `F = max(V, F_flow) + len / weight` with the clock `V` advancing by
  `len / capacity` (start-time fair queueing). An agent with `weight: 3`
  gets three times the link of `weight: 1`, and never starves it. An
  idle link is work-conserving: the message is written straight through
  with zero added latency.
- **Admission control.** A byte-rate bucket per sender
  (`max_bytes_per_sec`, or the kernel-wide
  `admission_max_bytes_per_sec`) plus a hard bound on the queue
  (`admission_max_queue_bytes`). A refused message never enters the
  kernel: it is journaled `admission_denied` with the reason.
- **Bandwidth accounting.** Bytes in/out per agent, queue depth and peak,
  accepted/delivered/throttled/denied counters — journaled as
  `qos_accounting` after every served batch and readable at any time on
  the operator-only control channel (`ama qos`).

**DTN: custody, routing, fragments (§3)** — an agent may declare
`dtn: true`. A send to it while it is disconnected does not fail: the
kernel takes **custody** of the bundle, holds it with a TTL, and delivers
it on the next registration. On top of that store-and-forward core:

- **Multi-hop relays.** A manifest `routes` entry says "to reach `far`,
  hand the bundle to `relay`". The kernel hands custody to the relay as a
  `bundle` frame; the relay re-emits it (`relay`), optionally naming the
  next hop itself. Every hop increments the count and `max_hops` caps the
  path — a bundle that would travel too far is dropped with
  `dtn_hop_limit`, never silently looped or stored forever.
- **Custody acknowledgements.** A relay that accepts a bundle sends
  `custody_ack`; the kernel then deletes its own copy
  (`dtn_custody_ack`) — custody transfers exactly once, per fragment.
- **Fragmentation and reassembly.** A body above `max_bundle_bytes`
  travels as numbered fragments, each routed independently; the receiving
  kernel delivers ONE reassembled message when the set completes
  (`dtn_reassembled`). An incomplete set expires like any other bundle.

Every transition is journaled: `dtn_stored`, `dtn_relayed`,
`dtn_custody_ack`, `dtn_delivered`, `dtn_fragmented`, `dtn_hop_limit`,
`dtn_expired`. This is the Bundle Protocol idea reduced to what a kernel
can honestly implement.

**Watchdog + fail-fast recovery (§4)** — heartbeat timeout *and* a
progress watchdog (same reasoning step for K sweeps while `executing`)
kill the suspect with the reason journaled. Respawn is atomic: a fresh
process inherits the last checkpoint and resumes.

**Isolation tiers (§2)** — from shallow to deep:

1. **OS process** — each agent is a separate PID; ephemeral memory dies
   with the process. cgroup v2 memory/CPU limits are applied
   best-effort when `/sys/fs/cgroup/ama` is writable.
2. **Seccomp jail** — `ama-agentd` jails *itself* with raw seccomp-BPF
   (no libseccomp): a denylist of host-dangerous syscalls — `ptrace`,
   `mount`, module loading, `bpf`, `userfaultfd`, `setns`, `unshare` —
   returns EPERM, with `PR_SET_NO_NEW_PRIVS` so privileges can never be
   regained. Tools run inside the same filter via `ama jail -- <cmd>`.
   Differential probe: unjailed `ptrace(TRACEME)` succeeds; the same
   call inside the jail returns EPERM.
3. **Strict allowlist** — `ama jail --strict` flips to default-DENY with
   an explicit x86_64 allowlist where `socket()` is allowed **only for
   AF_UNIX**: `socket(AF_INET)` returns EPERM while `socket(AF_UNIX)`
   works — the kernel is the agent's only channel.
4. **User namespace** — `ama jail --userns` runs the tool in a fresh
   user+mount namespace before the seccomp filter (uid 0 inside, host
   ownership unchanged). Hosts that forbid unprivileged user namespaces
   get an explicit SKIP, not a fake pass.
5. **MicroVM (Firecracker-class)** — the deepest tier. An agent with
   `isolation: "microvm"` runs inside its own Firecracker microVM.
   The PID the kernel watches *is* the whole VM (the boot script `exec`s
   firecracker); SIGKILL tears the VM down, respawn boots a fresh VM
   from the ledger checkpoint. Per-agent tap networking
   (`172.16.<1+uin>.0/24` — VMs cannot see each other's traffic),
   per-agent initramfs (static musl agentd + task baked in), kernel
   bridge listening on `0.0.0.0` for the tap. The VM boundary replaces
   the seccomp jail inside the guest; the three-wire contract is
   byte-identical across the VM boundary.

**Network-remote IPC (§3)** — the kernel accepts agents over TCP
(`tcp_port` in the manifest) with the identical envelope contract and
capability checks; an agent sets `transport: "tcp"` in its spec. The
round trip crosses transports **and** wire formats transparently.

**Binary wire formats (§3)** — every connection speaks JSON lines, or
length-prefixed msgpack (`0xFF` magic), or Protobuf (`0x0A` magic),
decided by the first byte. The kernel answers each connection in *its*
format and translates cross-format messages at the target's wire.

**Hot capability renegotiation (§3)** — the operator grants and revokes
capabilities at runtime over a control connection (`ama grant --name m
--caps send:c` / `ama revoke`); agents can never reach the control
channel. A send attempt after revocation is refused again — even for a
capability that previously worked.

**Agent observability** — agents journal notes into the ledger
(`note`/`agent_note` events), so agent-visible failures appear in the
same auditable stream as kernel events.

## Verified results (experiments 001 + 002)

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

Scenario: `b` pings `a` (typed envelope, capability-checked,
journaled); `a` pongs back and both complete. `c` checkpoints, is
killed externally (`kill -9`, the OOM/operator path), resumes from its
ledger checkpoint at the exact step it died on, and completes. `d`
runs an infinite reasoning loop — the progress watchdog detects the
stuck step, kills it, and exhausts the respawn budget. `m` attempts to
reach an agent it has no capability for — refused and journaled. All
five ran as distinct OS processes.

`experiments/experiment_002_caps_seccomp.sh` (12 s end-to-end):
```
PASS: seccomp control: unjailed ptrace succeeds (0)
PASS: seccomp: ptrace refused (EPERM=1) INSIDE the jail
PASS: hot caps: initial send denied (before the grant)
PASS: hot caps: operator GRANTED send:c at runtime
PASS: hot caps: the previously denied send was DELIVERED after the grant
PASS: hot caps: operator REVOKED send:c at runtime
PASS: hot caps: send AFTER the revoke was refused again (zero deliveries of attempt 3)
PASS: observability: agent notes are journaled into the ledger
EXPERIMENT_002: PASS  (40 ledger events)
```

`experiments/experiment_006_qos_dtn.sh` (11 s end-to-end):
```
PASS: qos: 3 sends within the bucket were accepted (sent attempts 4-6 throttled)
PASS: dtn: custody taken for the offline destination (3 bundles stored)
PASS: dtn: backlog delivered in order on re-registration
PASS: dtn: no bundle expired inside the TTL window
PASS: dtn: the respawned agent completed after draining its backlog
PASS: qos: the throttled sender still completed its task
EXPERIMENT_006: PASS
```

Further experiments: `003_transports` (TCP + msgpack + allowlist +
userns), `004_wires` (three wires on ONE kernel), `005_microvm`
(Firecracker tier), `007_qos_suite` (WFQ weights under a contended link,
admission control, bandwidth accounting), `008_dtn_routing` (two relays,
custody acks, fragmentation across hops).

## Release history

| Version | Highlights |
|---|---|
| **v0.7.0** | Hot-path performance: persistent ledger handle, single serialization, merged delivery locks, tail-scan checkpoints, O(1) name lookup, splice/write_envelope JSON |
| **v0.6.0** | Weighted fair queueing, admission control, bandwidth accounting; DTN multi-hop routing, custody acks, fragmentation |
| v0.5.0 | Per-sender QoS (token bucket + priority) and DTN store-and-forward custody |
| v0.4.0 | Protobuf wire, Firecracker microVM tier (one VM per agent), CI + tag-driven releases |
| v0.3.0 | Strict seccomp allowlist, TCP transports, msgpack wire, user-namespace tier |
| v0.2.0 | seccomp jails, hot capability grant/revoke |
| v0.1.0 | Kernel MVP: process table, IPC router, ledger, watchdog, respawn |

Assets per release: `ama-x86_64-linux-gnu.tar.gz` and
`ama-x86_64-linux-musl.tar.gz` plus their `.sha256` checksums. Releases
are built and verified by CI on the tag (unit tests + experiments
001–004 and 006).

## Experiment catalogue

```bash
bash experiments/experiment_001_isolation.sh   # isolation + watchdog + recovery
bash experiments/experiment_002_caps_seccomp.sh # seccomp jail + hot capabilities
bash experiments/experiment_003_transports.sh  # TCP + msgpack + allowlist + userns
bash experiments/experiment_004_wires.sh       # protobuf wire: 3 wires on ONE kernel
bash experiments/experiment_005_microvm.sh     # Firecracker microVM tier (needs /dev/kvm + ufw allow 172.16.0.0/12)
bash experiments/experiment_006_qos_dtn.sh     # per-sender rate limits + DTN custody for an offline agent
bash experiments/experiment_007_qos_suite.sh   # WFQ weights + admission control + bandwidth accounting
bash experiments/experiment_008_dtn_routing.sh # multi-hop relays + custody acks + fragmentation
```