# Resource and recovery validation

Validated locally on 2026-11-03. These are development measurements, not a
production capacity claim or a physical power-loss certification.

The regression suite covers frame bounds before body reads, total read
deadlines despite slow progress, connection admission and writer lifetimes,
shared outbound budgets across reconnects, in-flight byte reservations,
single-charge queued admission, unserviceable link-head rejection, dropped
queue accounting, delivery without watchdog sweeps, custody byte limits and
indexed acknowledgements, checkpoint recovery including misses, segment
rotation and history, interrupted activation, failed durability poisoning,
and external inode replacement.

The release review probes measured a no-expiry custody sweep at 10,000 bundles
at about 0.03 microseconds per call, compared with about 1.89 milliseconds in
the review baseline. Missing-checkpoint lookups after 10,000 and 100,000 WAL
events round below 0.01 milliseconds; the baseline reread the WAL and took
about 3.2 and 32 milliseconds respectively. Both binary-wire oversize probes
now reject with InvalidData without requesting a body read.

The existing send benchmark accepted all 5,000 messages for each payload and
its socket peer consumed 7,590,000 bytes. Acceptance throughput was approximately
149k, 140k and 101k messages/second for 64, 256 and 1,024 byte payloads. The
review baseline was approximately 383k, 297k and 144k respectively. The new
shared reservation locks, elapsed-time accounting and filesystem checks add
cost to the fast path. These figures measure acceptance throughput, not
end-to-end delivery latency, and are single-run local results. Ledger appends
were approximately 2.1–3.0 microseconds; checkpoint acknowledgements additionally
pay the filesystem sync cost. Correct bounded behavior and durable checkpoint
acknowledgements take priority over the former unbounded fast-path numbers.

Run `cargo test --locked --workspace`, debug and release Clippy with warnings
as errors, experiments 001–004 and 006–010, and
`python3 tests/validators_fail_closed.py`. Experiment 010 is a deterministic
Rust failure-probe gate, rather than an evidence-ledger Python validator.
Experiment 005 requires KVM; no microVM implementation was changed.

## Hot-path follow-up (v0.12.0)

Measured on the same development host (Intel N100, 4 cores, no turbo
headroom, production services resident), best-of-7 alternating runs of the
same binaries.

- `ledger.append`: 3.45 -> 3.26 microseconds per call (min 3.39 -> 3.17),
  about 5.6%. Each append now performs TWO syscalls instead of three:
  `strace -c` over 500,000 appends reports 500,001 `write` plus 500,007
  `statx` (1,000,092 total) where the previous build reported 1,500,092. The
  removed call was a per-append `fstat` that re-derived the identity of an
  inode an open handle cannot change. The identity is cached at (re)open
  time instead, and the path statx stays per append, so an external rename is
  still detected on the very next append. The record is framed in a reused
  per-thread buffer, which also removes one heap allocation and its growth
  reallocs per event.
- `route_send` at 64 bytes, 4 concurrent senders, 80,000 messages: about
  144,000 -> 150,000 messages per second aggregate (about 4%; the noise floor
  of that harness on this host is plus or minus 4%, and single-sender runs are
  inside it). The capability check and the destination snapshot now share one
  process-table pass instead of two, and the outbound queue handle is taken
  from that pass instead of a third lookup.
- Semantics delta, stated: a revoke that lands while a send is in flight can no
  longer pass the capability check and still be delivered. The check and the
  delivery decision are one critical section now.
- Still open, deliberately: the per-append `statx` (about 21% of the append)
  is what keeps external rotation detection prompt.
