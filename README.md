# AMA — Agentic Microkernel Architecture

[![CI](https://github.com/mrschneider/ama/actions/workflows/ci.yml/badge.svg)](https://github.com/mrschneider/ama/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/mrschneider/ama?sort=semver)](https://github.com/mrschneider/ama/releases/latest)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Run AI agents as OS processes. Contain every failure. Prove every guarantee.**

AMA is a microkernel for reliable multi-agent systems — a faithful
translation of the QNX Neutrino microkernel design into the world of AI
agent execution.

Instead of a framework that trusts agents to behave, AMA gives every
agent a **hard operating-system boundary**:

| Agent concern | AMA mechanism |
|---|---|
| Agents are isolated | Each agent is its own OS process (up to a full Firecracker microVM) |
| Agents communicate | Typed message passing over UDS/TCP, capability-checked |
| State is trusted | Global state is an **append-only ledger** — agents never write it |
| Agents fail | The kernel detects, kills, and **respawns from the last checkpoint** |
| Agents misbehave | seccomp jails, strict allowlists, user namespaces, microVMs |

Everything below is **implemented and verified by running it** — five
real agent processes, end-to-end experiments, every assertion taken
from the ledger. See [Verified results](#verified-results).

## Getting started

Prebuilt archives are published on every tagged release:
`ama-x86_64-linux-gnu.tar.gz` and `ama-x86_64-linux-musl.tar.gz` (static
— the same build the microVM tier boots), each with a `.sha256`:

```bash
# latest release → https://github.com/mrschneider/ama/releases/latest
BASE=https://github.com/mrschneider/ama/releases/latest/download
curl -LO $BASE/ama-x86_64-linux-musl.tar.gz
curl -LO $BASE/ama-x86_64-linux-musl.tar.gz.sha256
sha256sum -c ama-x86_64-linux-musl.tar.gz.sha256
tar xzf ama-x86_64-linux-musl.tar.gz    # puts ama + ama-agentd at the root
```

Each archive also carries the VM scripts, the experiments and the docs,
so a release tarball is a runnable distribution.

From source:

```bash
# 1. Fetch the external VM assets (Firecracker, guest kernel, busybox)
#    and build the static agentd — the repo does not commit binaries
./setup.sh

# 2. Start the kernel ("the Executive") with a manifest of agents
ama serve --manifest manifest.json --agentd ./ama-agentd
```

## Contributing & security

- `CONTRIBUTING.md` — the rules of the road: experiments are the
  executable specification, `cargo fmt`/`clippy -D warnings` are CI-
  enforced, the kernel stays minimal, refusals are journaled.
- `SECURITY.md` — how to report vulnerabilities privately, plus the
  explicit scope and design boundaries of the isolation model.
- `.github/workflows/ci.yml` — fmt, clippy (debug *and* release),
  unit tests, and experiments 001–004 + 006 on every push/PR; the
  microVM experiment is documented but not run in CI (needs `/dev/kvm`).
- `.github/workflows/release.yml` — tag-driven releases: verify →
  cross-compile gnu+musl → checksums → GitHub Release.

Then each agent is spawned as its own OS process (`ama-agentd --task
task.json`) and executes its task — `send`, `wait`, `checkpoint`,
`sleep`, `loop`, `crash` — talking to the kernel and to other agents
ONLY through typed envelopes. Watch the ledger: every send, refusal,
kill, respawn and checkpoint is there.

## Why it matters

- **Reliability by construction.** A crashed or stuck agent is killed by
  the watchdog and respawned atomically from its ledger checkpoint — it
  resumes at the exact step it died on. A respawn budget turns
  persistent crashers into `dead` instead of restarting forever.
- **Security you can audit.** Every send is capability-checked against
  the process table; refusals are journaled security events, never
  silent drops. Operators grant and revoke capabilities *at runtime*
  from a control channel agents cannot reach.
- **Isolation in tiers.** Pick the depth: OS process → seccomp jail →
  strict allowlist (Unix sockets only) → user namespace →
  **Firecracker microVM**, one VM per agent with its own tap subnet.
- **Three wire formats, one kernel.** JSON lines, length-prefixed
  msgpack (`0xFF`), and Protobuf (`0x0A`) — decided per connection, with
  the kernel translating cross-wire at the target. Over UDS **and** TCP
  with the identical envelope contract.
- **Observability for free.** Agents journal notes into the same ledger
  as kernel events, so a seccomp refusal or capability denial appears in
  the same auditable stream.

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
   `isolation: "microvm"` runs inside its **own Firecracker microVM**.
   The PID the kernel watches *is* the whole VM (the boot script `exec`s
   firecracker); SIGKILL tears the VM down, respawn boots a fresh VM
   from the ledger checkpoint. Per-agent tap networking
   (`172.16.<1+uin>.0/24` — VMs cannot see each other's traffic),
   per-agent initramfs (static musl agentd + task baked in), kernel
   bridge listening on `0.0.0.0` for the tap. The VM boundary replaces
   the seccomp jail inside the guest; the three-wire contract is
   byte-identical across the VM boundary.

<p align="center">
  <img src="docs/assets/microvm-tier.svg" alt="The AMA microVM tier: the host kernel (process table, IPC router, ledger, TCP bridge with per-agent taps) bridging two Firecracker microVMs, each running the static musl agentd behind its own tap subnet, with the VM boundary as the jail" width="70%">
</p>

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

Scenario: `b` pings `a` (typed envelope, capability-checked,
journaled); `a` pongs back and both complete. `c` checkpoints, is
killed externally (`kill -9`, the OOM/operator path), resumes from its
ledger checkpoint at the exact step it died on, and completes. `d`
runs an infinite reasoning loop — the progress watchdog detects the
stuck step, kills it, and exhausts the respawn budget. `m` attempts to
reach an agent it has no capability for — refused and journaled. All
five ran as distinct OS processes.

Further experiments: `003_transports` (TCP + msgpack + allowlist +
userns), `004_wires` (three wires on ONE kernel), `005_microvm`
(Firecracker tier), `006_qos_dtn` (rate limiting + store-and-forward
custody for an offline destination), `007_qos_suite` (WFQ weights under
a contended link, admission control, bandwidth accounting),
`008_dtn_routing` (two relays, custody acks, fragmentation across hops).

## Deliberately not implemented (v0.5)

- **Trusted execution** — all tiers are host-enforced. A VM booting a
  malicious kernel is not contained (Firecracker assumes a trusted
  guest kernel image; the vmlinux here is the Firecracker CI build).
- **Live migration** — the microVM tier is cold: respawn = fresh VM
  from the checkpoint, no hot migration between hosts.
- **QoS beyond this kernel** — the link is a per-tick byte budget, not a
  shaped NIC: no per-destination links, no ECN/queue-management (RED),
  no cross-kernel federation of the accounting counters.
- **DTN routing beyond a static table** — routes are declared in the
  manifest: no neighbour discovery, no dynamic metric, no
  retransmission when a relay accepts custody and then loses the bundle
  (the kernel keeps its copy until the ack, not until delivery), and no
  bundle security (no signatures, no encryption at the bundle layer).

## Releases

| Version | Highlights |
|---|---|
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

## Layout

- `ama-core/` — the kernel library: envelopes, ledger, process table,
  router, watchdog, supervisor, sandbox
- `ama-agentd/` — the agent-side process (`ama-agentd`)
- `ama-cli/` — the `ama` binary (`serve`, `ps`, `jail`, `grant`,
  `revoke`)
- `vm/` — the microVM tier: `boot_agent.sh` (per-agent tap +
  firecracker), `assemble_initramfs.sh` (per-agent initramfs),
  `guest-init.sh` (guest PID 1); `vm/bin/firecracker`,
  `vm/vmlinux-6.1.155` and `vm/agentd-static` are fetched/built by
  `./setup.sh` (binaries are not committed)
- `experiments/` — runnable E2E proof + task manifests
- `docs/research/qnx-microkernel.md` — the QNX design sources this
  architecture is translated from, with the deliberate-scope notes

## Build

```bash
cargo build            # ama-core (lib) + ama-agentd + ama
cargo test             # unit tests
bash experiments/experiment_001_isolation.sh   # isolation + watchdog + recovery
bash experiments/experiment_002_caps_seccomp.sh # seccomp jail + hot capabilities
bash experiments/experiment_003_transports.sh  # TCP + msgpack + allowlist + userns
bash experiments/experiment_004_wires.sh       # protobuf wire: 3 wires on ONE kernel
bash experiments/experiment_005_microvm.sh     # Firecracker microVM tier (needs /dev/kvm + ufw allow 172.16.0.0/12)
bash experiments/experiment_006_qos_dtn.sh     # per-sender rate limits + DTN custody for an offline agent
bash experiments/experiment_007_qos_suite.sh   # WFQ weights + admission control + bandwidth accounting
bash experiments/experiment_008_dtn_routing.sh # multi-hop relays + custody acks + fragmentation
```

## License

Apache-2.0.
