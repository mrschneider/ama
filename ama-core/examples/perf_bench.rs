//! Performance benchmark for the AMA kernel hot paths.
//!
//! Measures the real thing with real I/O and prints explicit numbers:
//!   1. route_send fast path — end-to-end through the kernel into a real
//!      Unix socket, at three payload sizes
//!   2. Ledger::append alone — the journal's share of the send-path cost
//!   3. Ledger::last_checkpoint — cost as the ledger grows (O(file)?)
//!
//! Run: cargo run --release -p ama-core --example perf_bench
//!
//! Harness note (both traps caught while writing this): the drainer must
//! read the end of the pair the kernel ACTUALLY writes to, and it must
//! retry on WouldBlock instead of breaking — otherwise the socket buffer
//! (~212 KB) fills, the kernel blocks in write, and the benchmark hangs.

use ama_core::{Kernel, Ledger, Peer, ProcEntry, ProcState, Wire};
use serde_json::json;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Instant;

fn fake_entry(uin: u64, name: &str, out: UnixStream) -> Arc<Mutex<ProcEntry>> {
    Arc::new(Mutex::new(ProcEntry {
        uin,
        name: name.into(),
        pid: 0,
        caps: vec![],
        manifest_caps: None,
        auth_token: None,
        granted: vec![],
        revoked: vec![],
        state: ProcState::Running,
        last_hb: std::time::Instant::now(),
        last_step: String::new(),
        last_phase: "executing".into(),
        stuck_sweeps: 0,
        respawns: 0,
        last_checkpoint: None,
        task_path: "/dev/null".into(),
        out: Some(Arc::new(Mutex::new(Peer::Unix(out)))),
        wire: Wire::Json,
        isolation: None,
        priority: 5,
        dtn: false,
    }))
}

fn main() {
    let tmp = std::env::temp_dir().join(format!("ama-perf-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    // ---- 1. route_send fast path through a real kernel -------------------
    let k = Arc::new(
        Kernel::new(
            &tmp.join("s.sock"),
            &tmp.join("kernel-ledger.jsonl"),
            "/nonexistent", // no real agents spawn; entries are registered by hand
            10_000_000,     // hb timeout ms (long: no watchdog interference)
            5000,           // hb interval ms
            3,              // max respawns
        )
        .expect("kernel"),
    );
    // pair 1 carries a's writer; pair 2 is what route_send writes into —
    // the drainer MUST hold the end of pair 2
    let (a_tx, _a_rx) = UnixStream::pair().unwrap();
    let (b_tx, mut b_rx) = UnixStream::pair().unwrap();
    k.agents
        .lock()
        .unwrap()
        .insert(1, fake_entry(1, "perf-a", a_tx));
    k.agents
        .lock()
        .unwrap()
        .insert(2, fake_entry(2, "perf-b", b_tx));
    k.bind_name("perf-a", 1);
    k.bind_name("perf-b", 2);

    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drainer_done = done.clone();
    let drainer = std::thread::spawn(move || {
        b_rx.set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        let mut total = 0usize;
        let mut buf = vec![0u8; 1 << 16];
        loop {
            if drainer_done.load(std::sync::atomic::Ordering::Relaxed) {
                // final drain of whatever is still in flight, then stop
                while let Ok(n) = b_rx.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                break;
            }
            match b_rx.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }
        total
    });

    for payload in [64usize, 256, 1024] {
        let body = json!({"op": "work", "payload": "y".repeat(payload)});
        let n = 5000;
        let t0 = Instant::now();
        let mut ok = 0usize;
        let mut err = String::new();
        for i in 0..n {
            if let Err(e) = k.route_send(1, "perf-b", &body) {
                err = format!("at {i}: {e}");
                break;
            }
            ok += 1;
        }
        let dt = t0.elapsed();
        println!(
            "route_send payload={payload:>4}B: {ok}/{n} in {:.1?} => {:.0} msgs/s ({:.1} us/msg)  err={}",
            dt,
            ok as f64 / dt.as_secs_f64(),
            dt.as_micros() as f64 / ok.max(1) as f64,
            err
        );
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let drained = drainer.join().unwrap_or(0);
    println!("delivered to peer: {drained} bytes");

    // ---- 2. Ledger::append alone -----------------------------------------
    let ledger = Ledger::open(&tmp.join("l.jsonl")).unwrap();
    for payload in [64usize, 256, 1024] {
        let body = json!({"op": "work", "payload": "y".repeat(payload)});
        let n = 5000;
        let t0 = Instant::now();
        for i in 0..n {
            ledger
                .append(
                    "delivered",
                    json!({"from": 1, "to": 2, "bytes": payload, "body": &body, "i": i}),
                )
                .unwrap();
        }
        let dt = t0.elapsed();
        println!(
            "ledger.append payload={payload:>4}B: {n} in {:.1?} => {:.0} appends/s ({:.1} us/append)",
            dt,
            n as f64 / dt.as_secs_f64(),
            dt.as_micros() as f64 / n as f64
        );
    }

    // ---- 3. last_checkpoint scaling ---------------------------------------
    for size in [2000usize, 8000, 32000] {
        let l2 = Ledger::open(&tmp.join(format!("l{size}.jsonl"))).unwrap();
        for i in 0..size {
            l2.append("noise", json!({"i": i})).unwrap();
        }
        l2.append("checkpoint", json!({"uin": 1, "state": json!({"x": 1})}))
            .unwrap();
        let t0 = Instant::now();
        let _ = l2.last_checkpoint(1);
        println!(
            "last_checkpoint over {size} events: {:.2} ms",
            t0.elapsed().as_micros() as f64 / 1000.0
        );
    }

    std::process::exit(0); // the kernel's threads are non-daemon: exit explicitly
}
