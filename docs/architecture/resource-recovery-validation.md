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
