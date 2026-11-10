//! Concurrent contention benchmark for the ledger hot path.
//!
//! The single-threaded perf_bench hides lock contention: append() holds the
//! writer Mutex while doing 2 metadata() syscalls + a clock read + full JSON
//! serialization, so under N concurrent threads the mutex serializes ALL of
//! that CPU work, not just the write.
//!
//! Run: cargo run --release -p ama-core --example contend_bench

use ama_core::Ledger;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn main() {
    let tmp = std::env::temp_dir().join(format!("ama-contend-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let path = tmp.join("l.jsonl");

    for threads in [1usize, 2, 4, 8, 16] {
        let _ = std::fs::remove_file(&path);
        let ledger = Arc::new(Ledger::open(&path).unwrap());

        let per_thread = 20_000u64;
        let total = per_thread * threads as u64;
        let done = Arc::new(AtomicU64::new(0));

        let t0 = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..threads {
            let ledger = Arc::clone(&ledger);
            let done = Arc::clone(&done);
            handles.push(thread::spawn(move || {
                for i in 0..per_thread {
                    ledger
                        .append("delivered", json!({"i": i, "bytes": 128}))
                        .unwrap();
                }
                done.fetch_add(per_thread, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let dt = t0.elapsed();
        let rate = total as f64 / dt.as_secs_f64();
        let us = dt.as_micros() as f64 / total as f64;
        let rate_str = format!("{rate:.0}");
        println!(
            "threads={:>2}: {} appends in {:?} => {}/s ({:.2} us/append)",
            threads, total, dt, rate_str, us
        );
    }

    // Durable variant: append_durable fsyncs every event — measure the cost.
    println!("--- durable (fsync each) ---");
    let _ = std::fs::remove_file(&path);
    let ledger = Arc::new(Ledger::open(&path).unwrap());
    for threads in [1usize, 2, 4] {
        let per_thread = 500u64;
        let total = per_thread * threads as u64;
        let t0 = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..threads {
            let ledger = Arc::clone(&ledger);
            handles.push(thread::spawn(move || {
                for i in 0..per_thread {
                    ledger.append_durable("delivered", json!({"i": i})).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let dt = t0.elapsed();
        let rate = total as f64 / dt.as_secs_f64();
        println!(
            "threads={:>2} durable: {} in {:?} => {:.0}/s",
            threads, total, dt, rate
        );
    }

    std::process::exit(0);
}
