#!/bin/busybox sh
# ama guest init — runs as PID 1 INSIDE the microVM. Ephemeral by
# construction: the VM dies with the agent process, the guest's
# ephemeral memory dies with the VM.
/bin/busybox --install -s /bin 2>/dev/null
mkdir -p /proc /sys /dev /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

# static networking — the host tap was configured by the boot script;
# these values are baked in at initramfs assembly time. Every step logs:
# a guest that reports "net up" while eth0 never configured hides the
# real failure (experiment 005: zero packets left the VM).
echo "[guest] links:"; ip link 2>&1
ip link set lo up 2>&1
ip link set eth0 up 2>&1
ip addr add __GUEST_IP__/24 dev eth0 2>&1
ip route add default via __HOST_IP__ 2>&1
ip addr 2>&1
# outbound connectivity probe: if the guest cannot even REACH the host
# tap IP, the agentd's connect will hang forever — log it loudly
ping -c 2 -W 1 __HOST_IP__ 2>&1 || echo "[guest] OUTBOUND PING FAILED"
echo "[guest] net up — starting ama-agentd (name=__NAME__)"
# AMA_VM=1 tells the agentd it is ALREADY inside the VM jail: no seccomp
# self-filter (the strict allowlist denies socket(AF_INET) — the guest
# NEEDS it to reach the kernel over the tap; a dead PID 1 = kernel panic)
export AMA_VM=1
# F10: the instance credential is baked into THIS initramfs by the
# kernel-spawned launch script — the VM tier authenticates exactly like
# every other tier (no more "VM agents may claim their identity unaided")
export AMA_REGISTER_TOKEN=__TOKEN__
/bin/ama-agentd --tcp __HOST_IP__:__PORT__ --task /etc/task.json
# RESCUE: if the agentd dies, PID 1 must not exit (kernel panic) —
# park forever so the kernel watchdog sees the VM alive/timeout cleanly
echo "[guest] agentd exited rc=$? — parking (avoid init panic)"
while true; do sleep 3600; done
