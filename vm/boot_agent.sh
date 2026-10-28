#!/usr/bin/env bash
# boot_agent.sh — boot ONE ama agent inside its own Firecracker microVM.
#
# Usage: boot_agent.sh <uin> <task_path> <kernel_tcp_port> <register_token>
#
# The script is exec'd BY the ama kernel as the agent's process: it
# assembles the per-agent initramfs, wires a private tap, and `exec`s
# firecracker — so the PID the kernel watches IS the firecracker process.
# SIGKILL to that PID = the VM dies = the agent dies. Respawn = a fresh
# VM from the ledger checkpoint. The deepest isolation tier: the tool
# code runs in a real VM, hostile or not.
#
# Per-agent network: each agent gets its own /24 (172.16.<1+uin>.0/24)
# — VMs cannot see each other's traffic, only the kernel's tap IP.
set -euo pipefail
VM_DIR="$(cd "$(dirname "$0")" && pwd)"
UIN="$1"; TASK="$2"; PORT="$3"; TOKEN="$4"

KERNEL_IMG="$VM_DIR/vmlinux-6.1.155"
FC="$VM_DIR/bin/firecracker"
BUSYBOX="$VM_DIR/bin/busybox"

TAP="ama_tap$UIN"
GUEST_IP="172.16.$((UIN + 1)).2"
HOST_IP="172.16.$((UIN + 1)).1"
RUN="/tmp/ama_vm$UIN"
mkdir -p "$RUN"

# private tap for THIS VM (kernel sudo if not root; needs CAP_NET_ADMIN)
if ! ip link show "$TAP" >/dev/null 2>&1; then
    [ "$(id -u)" = 0 ] || SUDO=sudo
    $SUDO ip tuntap add dev "$TAP" mode tap
    $SUDO ip addr add "$HOST_IP/24" dev "$TAP"
    $SUDO ip link set "$TAP" up
fi

# per-agent initramfs: static agentd + this agent's task, baked in
"$VM_DIR/assemble_initramfs.sh" \
    "$RUN/initramfs.cpio.gz" \
    "$VM_DIR/agentd-static" \
    "$TASK" \
    "$GUEST_IP" "$HOST_IP" "$PORT" "vm$UIN" "$TOKEN" \
    >/dev/null

# firecracker config — a config-file boot STARTS the instance immediately
cat > "$RUN/vm.json" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$KERNEL_IMG",
    "initrd_path": "$RUN/initramfs.cpio.gz",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
  },
  "machine-config": {"vcpu_count": 1, "mem_size_mib": 128, "smt": false},
  "drives": [],
  "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "$TAP"}]
}
EOF

# the pid of THIS script becomes the firecracker process — the kernel's
# watchdog (SIGKILL) tears the whole VM down; stdout = VM serial console
exec "$FC" --api-sock "$RUN/api.sock" --config-file "$RUN/vm.json"
