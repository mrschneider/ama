# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x   | ✅ |
| < 0.4   | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately to the maintainers via [GitHub Security Advisories
("Report a vulnerability" on the Security tab of this
repository)](https://github.com/mrschneider/ama/security/advisories/new).
Include:

- the affected component (`ama-core` kernel, `ama-agentd`, `ama-cli`,
  `vm/` tier),
- the isolation tier involved (process / seccomp jail / allowlist /
  user namespace / microVM),
- a minimal reproduction or an experiment-script patch that
  demonstrates it,
- your assessment of impact and severity.

You will receive an acknowledgement within 72 hours. Fixes are
prioritized by severity; coordinated disclosure is preferred, and
reporters are credited in the release notes unless they prefer
otherwise.

## Scope and design boundaries

AMA's security model is **host-enforced isolation with an auditable
ledger**. In scope:

- capability check bypass (a send reaching a target the agent has no
  grant for, or reaching the control channel),
- ledger integrity (torn lines, duplicate sequence numbers, forged
  events),
- isolation escape from any tier: seccomp jail, strict allowlist,
  user namespace, or the Firecracker microVM (guest-to-host),
- watchdog bypass (an agent appearing alive while not progressing, or
  a live agent being killed incorrectly),
- respawn/recovery correctness (state loss beyond the last checkpoint,
  double-respawn races),
- wire-format schema validation (a malformed or forged envelope being
  accepted).

Explicitly **out of scope** (see README "Deliberately not
implemented"):

- trusted execution — a VM booting a malicious guest kernel image,
- live migration of microVMs,
- denial of service by resource exhaustion from an agent that is
  already inside its jail (cgroup limits are best-effort by design).

## Isolation tier expectations

Each tier is a distinct boundary with a distinct threat model. A
seccomp filter assumes a non-malicious but buggy agent binary; the
microVM tier assumes a **trusted guest kernel image** and contains
fully hostile *userland* inside the VM. Defense in depth is expected:
the default agent deployment should be tier ≥ 2 (seccomp jail) and
hostile tool code belongs in tier 5 (microVM).
