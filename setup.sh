#!/usr/bin/env bash
# setup.sh — fetch the external VM assets the ama microVM tier needs.
#
# The repo deliberately does NOT commit binaries (a 43 MB kernel image
# in git bloats every clone forever). Instead, this script fetches the
# pinned upstream artifacts once and places them where the tier expects
# them:
#
#   vm/bin/firecracker   — Firecracker v1.17.0 (github.com/firecracker-microvm)
#   vm/bin/busybox       — busybox 1.35.0 musl static (busybox.net)
#   vm/vmlinux-6.1.155   — guest kernel (Firecracker CI artifacts bucket)
#
# agentd-static is NOT downloaded: it is built from this repo with
#   cargo build --release --target x86_64-unknown-linux-musl -p ama-agentd
#   cp target/x86_64-unknown-linux-musl/release/ama-agentd vm/agentd-static
set -euo pipefail
VM_DIR="$(cd "$(dirname "$0")" && pwd)/vm"
BIN="$VM_DIR/bin"
ARCH="$(uname -m)"
[ "$ARCH" = "x86_64" ] || { echo "the microVM tier is x86_64-only (found $ARCH)"; exit 1; }

mkdir -p "$BIN"

fetch() { # fetch <url> <dest>
    if [ -s "$2" ]; then
        echo "present: $2"
        return
    fi
    echo "fetching: $1"
    curl -fSL --retry 3 -o "$2" "$1"
}

# --- firecracker v1.17.0 ---
# F09: downloaded binaries are VERIFIED against a pinned sha256 — a
# supply-chain silent skip is how a hostile mirror becomes the isolation
# boundary. AMA_ALLOW_UNVERIFIED=1 is the explicit, journaled escape hatch
# for offline development.
FC_VERSION="v1.17.0"
FC_SHA="${FC_SHA:-}"
if [ ! -s "$BIN/firecracker" ]; then
    TGZ=$(mktemp /tmp/fc.tgz.XXXXXX)
    fetch "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-${ARCH}.tgz" "$TGZ"
    if [ -z "$FC_SHA" ] || [ "$FC_SHA" = "SKIP" ]; then
        if [ "${AMA_ALLOW_UNVERIFIED:-0}" != "1" ]; then
            echo "ERROR: set FC_SHA=<sha256 of the firecracker tgz> before downloading" >&2
            echo "       (or AMA_ALLOW_UNVERIFIED=1 to accept an UNVERIFIED download)" >&2
            exit 1
        fi
        echo "WARNING: firecracker downloaded WITHOUT integrity verification (AMA_ALLOW_UNVERIFIED=1)" >&2
    else
        echo "$FC_SHA  $TGZ" | sha256sum -c - || { echo "firecracker checksum MISMATCH" >&2; exit 1; }
    fi
    tar xzf "$TGZ" -C /tmp
    cp "/tmp/release-${FC_VERSION}-${ARCH}/firecracker-${FC_VERSION}-${ARCH}" "$BIN/firecracker"
    rm -f "$TGZ" "/tmp/release-${FC_VERSION}-${ARCH}/firecracker-${FC_VERSION}-${ARCH}"
fi
chmod +x "$BIN/firecracker"

# --- busybox 1.35.0 (musl static) ---
BUSYBOX_SHA="${BUSYBOX_SHA:-}"
if [ ! -s "$BIN/busybox" ]; then
    fetch "https://busybox.net/downloads/binaries/1.35.0-${ARCH}-linux-musl/busybox" "$BIN/busybox"
    if [ -z "$BUSYBOX_SHA" ] || [ "$BUSYBOX_SHA" = "SKIP" ]; then
        if [ "${AMA_ALLOW_UNVERIFIED:-0}" != "1" ]; then
            echo "ERROR: set BUSYBOX_SHA=<sha256> before downloading" >&2
            exit 1
        fi
        echo "WARNING: busybox downloaded WITHOUT integrity verification (AMA_ALLOW_UNVERIFIED=1)" >&2
    else
        echo "$BUSYBOX_SHA  $BIN/busybox" | sha256sum -c - || { echo "busybox checksum MISMATCH" >&2; exit 1; }
    fi
fi
chmod +x "$BIN/busybox"

# --- guest kernel from the Firecracker CI artifacts bucket ---
KERNEL_KEY="firecracker-ci/20260107-89702a77e4c2-0/${ARCH}/vmlinux-6.1.155"
fetch "https://s3.amazonaws.com/spec.ccfc.min/${KERNEL_KEY}" "$VM_DIR/vmlinux-6.1.155"

# --- build the static agentd ---
if [ ! -s "$VM_DIR/agentd-static" ]; then
    echo "building vm/agentd-static (musl static-pie)..."
    cargo build --release --target x86_64-unknown-linux-musl -p ama-agentd
    cp target/x86_64-unknown-linux-musl/release/ama-agentd "$VM_DIR/agentd-static"
fi

# --- host prerequisites ---
if [ ! -w /dev/kvm ]; then
    echo "WARNING: /dev/kvm is not writable by $(id -un)."
    echo "  Firecracker needs it; grant once via a udev rule (see README)."
fi

echo "vm assets ready:"
du -h "$BIN/firecracker" "$BIN/busybox" "$VM_DIR/vmlinux-6.1.155" "$VM_DIR/agentd-static" 2>/dev/null
