# Research: QNX Neutrino microkernel → Agentic Microkernel Architecture (AMA)

## What the canonical source establishes

The QNX Neutrino microkernel (`procnto`) is deliberately minimal: it implements
only threads, message passing, signals, clocks, timers, and the sync primitives.
Everything else (file I/O, devices) lives in *optional processes*. The entire OS
is built on these calls (source: openqnx.com / qnx.com, "The QNX Neutrino
Microkernel", System Architecture).

Principles we translate into AMA:

1. **Protected address spaces per process.** "Each process is MMU-protected
   from each other" — a process is the container of trust. In AMA each agent is
   an OS process with its own PID; the kernel holds it as a `Child` and can
   terminate it atomically. Corrupt reasoning dies with its process.

2. **Message passing as THE primitive.** QNX's Send/Receive/Reply is
   synchronous, copies data explicitly between address spaces, and the kernel
   attaches no meaning to content — but well-defined message types exist.
   AMA translates this to: one newline-delimited, **typed envelope** schema over
   Unix Domain Sockets; agents may not open any other channel; the kernel
   validates the schema and refuses unknown kinds.

3. **Channels and connections map to file descriptors.** QNX: a server creates a
   channel, clients attach connections that map directly into FDs — "we have
   eliminated yet another layer of translation". AMA: the kernel owns one UDS
   listening socket; every agent connection IS its channel; the routing table is
   the process table itself (name → UIN → connection).

4. **Capability-gated reachability.** QNX grounds security in "who may connect
   to which channel"; MsgKeyData keys messages "to allow security checks". AMA
   generalizes it explicitly: an agent can only send to a target (or call a
   tool) if its process-table entry carries the cryptographic-level grant —
   the kernel refuses and journals the denial instead of forwarding.

5. **Agents never touch global state.** There is no global mutable state in the
   kernel at all — only the append-only ledger. Agents checkpoint THEIR OWN
   state into it. Recovery = re-instantiate the process and hand it its last
   checkpoint. (QNX analog: procnto is the arbiter; user processes hold their
   own memory.)

6. **Fail-fast + atomic respawn.** QNX's reliability argument is that the
   microkernel is small enough to be correct and drivers can crash without
   taking the system down. AMA's supervisor: heartbeat + progress watchdog;
   a suspected agent is SIGKILLed, its ephemeral memory simply disappears with
   the process, and a fresh instance is respawned from the last ledger
   checkpoint while other agents keep running.

## Translation table

| QNX Neutrino | AMA |
|---|---|
| procnto microkernel | `ama-core` kernel (single-threaded state, thread-per-connection I/O) |
| Process (MMU-protected) | Agent process spawned from a manifest, distinct PID |
| ChannelCreate / ConnectAttach | Kernel UDS socket + per-agent connection stored in the process table |
| MsgSend/MsgReply (typed, content-blind) | Typed JSON envelope kinds (register/welcome/heartbeat/send/sent/denied/msg/checkpoint/acked) |
| MsgKeyData security checks | Capability grants per process entry; kernel refuses + journals |
| procnto as arbiter of all state | Append-only ledger; agents checkpoint their own state |
| Driver crash ≠ system crash | Agent crash/timeout → SIGKILL → respawn from checkpoint |

## Deliberately not implemented in v0.1 (honest scope)

- seccomp-bpf filters and full cgroup v2 pinning: `sandbox.rs` applies cgroup
  memory/CPU limits on a best-effort basis when `/sys/fs/cgroup/ama` is
  writable; a MicroVM per agent (the brief's "Tool Execution Jails") is
  roadmap — the process boundary is the v0.1 isolation unit.
- protobuf/FlatBuffers wire format: newline-delimited JSON with strict
  per-kind schema validation in the kernel (the kernel rejects malformed
  envelopes — the enforcement point is the kernel, not the encoder).
- distributed (network-remote) message passing: QNX spans it transparently;
  AMA v0.1 is single-host UDS by design (the brief explicitly rejects
  network brokers for the local case).

## Sources

- The QNX Neutrino Microkernel — System Architecture,
  https://openqnx.com/static/neutrino/sys_arch/kernel.html
- The QNX Neutrino Microkernel (6.5.0 docs),
  http://qnx.com/developers/docs/6.5.0SP1/neutrino/sys_arch/kernel.html
- Interprocess Communication (IPC) — QNX Neutrino 6.4.1,
  http://qnx.co.jp/developers/docs/6.4.1/neutrino/sys_arch/ipc.html
