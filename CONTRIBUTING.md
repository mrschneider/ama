# Contributing to AMA

Thanks for your interest in contributing. AMA is a systems project:
the kernel, the agent daemon and the jail tiers must behave
deterministically, and the experiments in `experiments/` are the
executable specification of that behaviour. Please keep them passing.

## Project layout

| Directory | Contents |
|---|---|
| `ama-core/` | kernel library: envelopes, ledger, process table, router, watchdog, supervisor, sandbox |
| `ama-agentd/` | the agent-side process |
| `ama-cli/` | the `ama` binary (`serve`, `ps`, `jail`, `grant`, `revoke`) |
| `vm/` | Firecracker microVM tier (boot scripts, initramfs assembly, guest init, musl agentd) |
| `experiments/` | runnable E2E proof — the executable specification |
| `docs/` | architecture assets and the QNX design research |

## Getting started

```bash
cargo build
cargo test
bash experiments/experiment_001_isolation.sh
```

## Rules of the road

1. **Every kernel behaviour change must keep the experiments green.**
   If you add a guarantee, add an assertion to (or a new) experiment
   script. If you change a behaviour, the assertion that proves it must
   still pass. The scripts under `experiments/` are the source of truth
   for what the kernel actually does — the README describes them, not
   the other way around.
2. **`cargo fmt` and `cargo clippy -- -D warnings` are required.** The
   CI workflow (`.github/workflows/ci.yml`) enforces both on every PR.
   Run `cargo fmt --all` before committing.
3. **Keep the kernel minimal (§1).** The Executive holds only the
   process table, the IPC router, and the append-only ledger. New
   features belong in agents, tasks, or the daemon unless they
   genuinely require kernel-level trust.
4. **Refusals are journaled, never silent.** Any capability denial,
   schema rejection, watchdog kill or isolation refusal must be written
   to the ledger as a security event.
5. **Wire compatibility is a contract.** All three wire formats (JSON,
   msgpack `0xFF`, protobuf `0x0A`) must round-trip the full kernel↔agent
   vocabulary. If you add an envelope kind, add it to every wire
   translator, or the experiment_004 assertions will fail.
6. **No credential material in the repo.** Task manifests, experiment
   fixtures and the `vm/` assets must stay free of tokens, keys and
   host paths that leak identity.

## Pull requests

- One logical change per PR; reference the experiment that covers it.
- Describe the failure mode the change prevents, not just the feature.
- CI must be green (fmt, clippy in debug *and* release, unit tests,
  experiments 001–004). `experiment_005_microvm` is not run in CI — it
  needs `/dev/kvm` — so please run it locally if your change touches
  the microVM tier (`vm/`, spawn/respawn paths, transport bridging).

## Local pre-flight (recommended)

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --release -- -D warnings
cargo test --workspace
bash experiments/experiment_001_isolation.sh
bash experiments/experiment_002_caps_seccomp.sh
bash experiments/experiment_003_transports.sh
bash experiments/experiment_004_wires.sh
```

## License

By contributing you agree that your contributions are licensed under
the Apache-2.0 license that covers this repository.
