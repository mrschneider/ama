//! `ama` — the operator CLI.
//!
//!   ama serve --manifest m.json --agentd <path> [--cgroups]   run the kernel
//!   ama ps --socket <path>                                    process table dump
//!   ama inspect --socket <path> --name <agent>                one entry
//!
//! `ps`/`inspect` use a CONTROL connection (kind "ctl_*" envelopes). The
//! kernel enforces that control verbs are only accepted on connections
//! that never registered as agents — agents cannot control the kernel.

use ama_core::AgentSpecTuple;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::exit;

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let mut socket = String::new();
    let mut manifest = String::new();
    let mut agentd = String::new();
    let mut cgroups = false;
    let mut name = String::new();
    let mut caps = String::new();
    let mut strict = false;
    let mut userns = false;
    let mut rest: Vec<String> = Vec::new();
    let mut collecting_rest = false; // after `--`: the jailed command
    while let Some(a) = args.next() {
        if a == "--" {
            collecting_rest = true;
            continue;
        }
        if collecting_rest {
            rest.push(a);
            continue;
        }
        match a.as_str() {
            "--socket" => socket = args.next().unwrap_or_default(),
            "--manifest" => manifest = args.next().unwrap_or_default(),
            "--agentd" => agentd = args.next().unwrap_or_default(),
            "--cgroups" => cgroups = true,
            "--name" => name = args.next().unwrap_or_default(),
            "--caps" => caps = args.next().unwrap_or_default(),
            "--strict" => strict = true,
            "--userns" => userns = true,
            other => {
                rest.push(other.to_string());
                rest.extend(args);
                break;
            }
        }
    }
    // F02: operator verbs live on the DEDICATED control socket
    // (<socket>.ctl, mode 0600, peer-credential checked) — never on the
    // agent listener
    let ctl_socket = format!("{socket}.ctl");
    match cmd.as_str() {
        "serve" => serve(&socket, &manifest, &agentd, cgroups),
        "ps" => ps(&ctl_socket),
        "qos" => ctl_qos(&ctl_socket),
        "grant" => ctl_caps(&ctl_socket, "ctl_grant", &name, &caps),
        "revoke" => ctl_caps(&ctl_socket, "ctl_revoke", &name, &caps),
        "jail" => {
            // Tool Execution Jail: run a command inside the seccomp filter
            // (--strict upgrades to the allowlist profile: default-DENY,
            // socket() only for AF_UNIX — the kernel is the only channel)
            if rest.is_empty() {
                eprintln!("jail requires: ama jail [--strict] -- <cmd> [args...]");
                exit(2);
            }
            if userns {
                ama_core::seccomp::request_userns();
            }
            let profile = if strict {
                ama_core::seccomp::Profile::Allowlist
            } else {
                ama_core::seccomp::Profile::Denylist
            };
            if let Err(e) = ama_core::seccomp::jail_exec(&rest, profile) {
                eprintln!("{e}");
                exit(126);
            }
        }
        _ => {
            eprintln!("usage: ama serve|ps|qos|grant|revoke|jail");
            exit(2);
        }
    }
}

fn ctl_qos(socket: &str) {
    let msg = format!("{}\n", serde_json::json!({"kind": "ctl_qos"}));
    let mut s = UnixStream::connect(socket).expect("connect");
    s.write_all(msg.as_bytes()).expect("ctl");
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).expect("reply");
    println!("{}", line.trim());
}

fn ctl_caps(socket: &str, verb: &str, name: &str, caps: &str) {
    let list: Vec<&str> = caps
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let msg = format!(
        "{}\n",
        serde_json::json!({"kind": verb, "name": name, "caps": list})
    );
    let mut s = UnixStream::connect(socket).expect("connect");
    s.write_all(msg.as_bytes()).expect("ctl");
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).expect("reply");
    println!("{}", line.trim());
}

fn serve(socket: &str, manifest: &str, agentd: &str, cgroups: bool) {
    if manifest.is_empty() || agentd.is_empty() {
        eprintln!("serve requires --manifest <file> --agentd <path>");
        exit(2);
    }
    let m: ama_core::Manifest = serde_json::from_slice(&std::fs::read(manifest).expect("manifest"))
        .expect("manifest schema");
    let socket = if socket.is_empty() {
        m.kernel.socket.clone()
    } else {
        socket.to_string()
    };
    let kernel = ama_core::Kernel::new(
        std::path::Path::new(&socket),
        std::path::Path::new(&m.kernel.ledger),
        agentd,
        m.kernel.hb_interval_ms,
        m.kernel.hb_timeout_ms,
        m.kernel.max_respawns,
    )
    .expect("kernel");
    let mut kernel = kernel; // shadow for mutation
    kernel.apply_cgroups = cgroups; // opt-in, best-effort (see sandbox.rs)
    kernel.tcp_addr = m.kernel.tcp_port.map(|p| {
        format!(
            "{}:{p}",
            m.kernel.tcp_bind.as_deref().unwrap_or("127.0.0.1")
        )
    });
    kernel.vm_boot = m.kernel.vm_boot.clone();
    kernel.configure_delivery(
        m.kernel.admission_max_bytes_per_sec,
        m.kernel.admission_max_queue_bytes,
        m.kernel.wfq_capacity,
        m.kernel.link_bytes_per_tick,
    );
    kernel.configure_routing(
        &m.kernel.routes,
        m.kernel.max_hops,
        m.kernel.max_bundle_bytes,
    );
    let agents: Vec<AgentSpecTuple> = m
        .agents
        .iter()
        .map(|a| {
            (
                a.name.clone(),
                a.task.clone(),
                a.transport
                    .clone()
                    .map(|_| format!("127.0.0.1:{}", m.kernel.tcp_port.unwrap_or(0))),
                a.wire.as_deref().and_then(|w| match w {
                    "json" => Some(ama_core::Wire::Json),
                    "msgpack" => Some(ama_core::Wire::Msgpack),
                    "proto" => Some(ama_core::Wire::Proto),
                    _ => None,
                }),
                a.isolation.clone(),
                a.qos,
                a.dtn,
                a.caps.clone(),
            )
        })
        .collect();
    // BIND FIRST, spawn after: agent processes connect at startup — spawning
    // before the socket exists kills them (this exact failure appeared in
    // experiment 001 and is now part of the router's contract)
    let handle = ama_core::Router::serve_full(kernel, &agents).expect("router");
    eprintln!("[ama] kernel up on {socket}");
    handle.join().ok();
}

fn ps(socket: &str) {
    let mut s = UnixStream::connect(socket).expect("connect");
    s.write_all(b"{\"kind\": \"ctl_ps\"}\n").expect("ctl");
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).expect("reply");
    println!("{}", line.trim());
}
