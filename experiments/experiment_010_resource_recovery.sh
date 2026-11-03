#!/usr/bin/env bash
# Executable regression gate for bounded resources, fair delivery and ledger recovery.
# These deterministic failure probes use socket pairs and temporary ledgers;
# unlike the process experiments they do not kill running AMA instances.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --locked -p ama-core enterprise_tests:: -- --test-threads=1
printf '%s\n' 'EXPERIMENT_010: PASS'
