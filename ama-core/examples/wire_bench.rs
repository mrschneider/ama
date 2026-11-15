//! END-TO-END wire benchmark: agent -> kernel -> agent over a real UDS.
//!
//! `perf_bench` measures `route_send` in isolation (the kernel's own API).
//! This one measures the REAL path a message takes:
//!
//!   socket read -> JSON parse -> envelope validation -> capability check
//!   -> admission/QoS -> ledger append -> outbound queue -> socket write
//!
//! The client speaks the actual envelope protocol (register, then send),
//! so the numbers include everything the kernel does per message — not
//! just the routing call.
//!
//! It also reports the LATENCY the client observes per message: the ack
//! arrives on the same connection, so this is the real agent-visible
//! round trip.
//!
//! Run: cargo run --release -p ama-core --example wire_bench

use ama_core::{Kernel, ProcEntry, ProcState, Wire};
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn plant_entry(k: &Kernel, uin: u64, name: &str, token: &str, caps: &[&str]) {
    let process = ProcEntry {
        uin,
        name: name.into(),
        pid: 0,
        caps: caps.iter().map(|c| c.to_string()).collect(),
        manifest_caps: None,
        auth_token: Some(token.into()),
        tcp_addr: None,
        spawned_at: Instant::now(),
        granted: vec![],
        revoked: vec![],
        state: ProcState::Starting,
        last_hb: Instant::now(),
        last_step: String::new(),
        last_phase: "executing".into(),
        stuck_sweeps: 0,
        respawns: 0,
        last_checkpoint: None,
        task_path: "/dev/null".into(),
        out: None,
        wire: Wire::Json,
        isolation: None,
        priority: 5,
        dtn: false,
    };
    k.agents
        .lock()
        .unwrap()
        .insert(uin, Arc::new(Mutex::new(process)));
    k.bind_name(name, uin);
}

fn main() {
    let tmp = std::env::temp_dir().join(format!("ama-wire-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let sock = tmp.join("k.sock");
    let ledger = tmp.join("ledger.jsonl");
    let k = Kernel::new(&sock, &ledger, "/nonexistent", 10_000_000, 5000, 3).unwrap();
    // the sender and the destination both live in the table, with a token
    // the client knows (the client registers with it)
    plant_entry(&k, 1, "sender", "tok-sender", &["send:dest"]);
    plant_entry(&k, 2, "dest", "tok-dest", &[]);
    let _handle = ama_core::Router::serve_full(k, &[]).expect("router");

    // wait for the listener
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(100));

    let mut client = UnixStream::connect(&sock).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut reader = BufReader::new(client.try_clone().unwrap());

    // register: the kernel answers with a welcome
    client
        .write_all(
            json!({"kind": "register", "name": "sender", "caps": ["send:dest"],
                   "pid": 4242, "token": "tok-sender"})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    client.write_all(b"\n").unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("welcome"), "register reply: {line}");

    // the destination: a raw reader that swallows the deliveries
    let stop = Arc::new(AtomicBool::new(false));
    {
        let mut dest = UnixStream::connect(&sock).expect("connect dest");
        dest.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        dest.write_all(
            json!({"kind": "register", "name": "dest", "caps": [], "pid": 4243,
                   "token": "tok-dest"})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        dest.write_all(b"\n").unwrap();
        let mut r = BufReader::new(dest.try_clone().unwrap());
        let mut l = String::new();
        let _ = r.read_line(&mut l); // welcome
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 1 << 16];
            while !stop.load(Ordering::Relaxed) {
                match dest.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => continue,
                }
            }
        });
    }

    for payload in [64usize, 256, 1024] {
        let body = json!({"op": "work", "payload": "y".repeat(payload)});
        let env = json!({"kind": "send", "uin": 1, "to": "dest", "body": body});
        let bytes = env.to_string();
        let n = 2_000usize;
        // warm the path (socket buffers, page cache, the writer thread)
        for _ in 0..50 {
            client.write_all(bytes.as_bytes()).unwrap();
            client.write_all(b"\n").unwrap();
            let mut l = String::new();
            let _ = reader.read_line(&mut l);
        }
        let t0 = Instant::now();
        let mut lat = Duration::ZERO;
        for _ in 0..n {
            let s = Instant::now();
            client.write_all(bytes.as_bytes()).unwrap();
            client.write_all(b"\n").unwrap();
            let mut l = String::new();
            reader.read_line(&mut l).unwrap();
            lat += s.elapsed();
        }
        let dt = t0.elapsed();
        println!(
            "wire payload={payload:>4}B: {n} msgs in {:.1?} => {:.0} msgs/s | ack latency {:.1} us/msg",
            dt,
            n as f64 / dt.as_secs_f64(),
            lat.as_micros() as f64 / n as f64
        );
    }
    stop.store(true, Ordering::Relaxed);
    std::process::exit(0);
}
