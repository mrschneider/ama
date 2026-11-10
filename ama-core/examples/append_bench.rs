//! Measure real append throughput before/after the metadata optimization.
use ama_core::Ledger;
use std::time::Instant;

fn main() {
    let dir = std::env::temp_dir().join("ama-append-bench");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.jsonl");

    let ledger = Ledger::open(&path).unwrap();
    ledger.set_segment_bytes(0); // no rotation

    let events = ["transfer", "ack", "checkpoint", "notify", "status"];
    let n = 500_000;

    let t0 = Instant::now();
    for i in 0..n {
        let ev = events[i % events.len()];
        ledger.append(ev, serde_json::json!({"i": i})).unwrap();
    }
    let dt = t0.elapsed();
    println!(
        "append x{}: {:.4} us/call, {:.2} M/s",
        n,
        dt.as_micros() as f64 / n as f64,
        n as f64 / dt.as_secs_f64() / 1e6
    );

    let _ = std::fs::remove_dir_all(&dir);
}
