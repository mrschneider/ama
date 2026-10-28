#!/usr/bin/env bash
# assemble_initramfs.sh — build a per-agent initramfs for the ama microVM tier.
#
# Usage: assemble_initramfs.sh <out.cpio.gz> <agentd_static> <task.json> \
#            <guest_ip> <host_ip> <port> <agent_name> <register_token>
#
# The initramfs is EPHEMERAL: each VM gets its own, assembled from the
# task file this agent should run. The guest runs the static ama-agentd,
# which connects BACK to the kernel over TCP (the tap interface's host
# IP). The contract inside the VM is byte-identical to the host tiers —
# the VM is a transport-transparent isolation boundary.
set -euo pipefail
OUT="$1"; AGENTD="$2"; TASK="$3"; GIP="$4"; HIP="$5"; PORT="$6"; NAME="$7"; TOKEN="$8"
ROOT=$(mktemp -d /tmp/ama_initramfs.XXXXXX)
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT/bin" "$ROOT/etc" "$ROOT/proc" "$ROOT/sys" "$ROOT/dev" "$ROOT/tmp"
cp "$(dirname "$0")/bin/busybox"      "$ROOT/bin/busybox"
cp "$AGENTD"                          "$ROOT/bin/ama-agentd"
cp "$TASK"                            "$ROOT/etc/task.json"
sed -e "s/__GUEST_IP__/$GIP/" -e "s/__HOST_IP__/$HIP/" \
    -e "s/__PORT__/$PORT/" -e "s/__NAME__/$NAME/" \
    -e "s/__TOKEN__/$TOKEN/" \
    "$(dirname "$0")/guest-init.sh" > "$ROOT/init"
chmod +x "$ROOT/init" "$ROOT/bin/ama-agentd" "$ROOT/bin/busybox"

# newc cpio format, gzipped — Firecracker boots it as the kernel's rootfs
(cd "$ROOT" && find . | cpio -o -H newc --owner 0:0 2>/dev/null) | gzip -9 > "$OUT"
echo "initramfs: $OUT ($(du -h "$OUT" | cut -f1))"
