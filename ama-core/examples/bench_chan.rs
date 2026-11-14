//! Compares three writer strategies under sustained heartbeat + task-loop
//! contention, using LARGE payloads (8 KB) where serialization dominates.
//!
//!   * `single` — lock the Mutex, ENCODE inside it, then write+flush (the OLD
//!     agentd pattern). The heartbeat thread must wait for the full encode of
//!     every concurrently-running task step.
//!   * `two`    — encode off the lock, then lock only for write+flush (the
//!     current agentd two-phase refactor).
//!   * `chan`   — producers push pre-encoded bytes to an mpsc channel; a single
//!     writer thread drains and writes. The socket Mutex is gone; the
//!     only lock is the brief channel push.
//!
//! Metric: heartbeat tail latency (the watchdog liveness signal) and task
//! throughput. Larger payloads make the encode the dominant cost so the
//! difference between "single" (encode under lock) and "two" (encode off lock)
//! is visible.

use ama_core::encode_envelope;
use serde_json::json;
use std::io::{Read, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn main() {
    let mode = std::env::var("MODE").unwrap_or_else(|_| "two".to_string());
    let window = Duration::from_secs(1);
    let hb_interval = Duration::from_millis(
        std::env::var("HB_INTERVAL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100),
    );

    let (a, b) = UnixStream::pair().unwrap();
    let mut drainer = b;
    drainer
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let drainer_stop = stop.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 1 << 16];
        while !drainer_stop.load(Ordering::Relaxed) {
            match drainer.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        let _ = drainer.read(&mut buf);
    });

    let writer = Arc::new(Mutex::new(a));

    // Channel mode: one writer thread drains pre-encoded bytes.
    let w_tx = match mode.as_str() {
        "chan" => {
            let (tx, rx) = mpsc::channel::<Vec<u8>>();
            let w = writer.clone();
            std::thread::spawn(move || {
                for buf in rx {
                    let mut w = w.lock().unwrap();
                    if w.write_all(&buf).is_err() {
                        break;
                    }
                }
            });
            tx
        }
        _ => {
            let (tx, _rx) = mpsc::channel::<Vec<u8>>();
            tx
        }
    };

    // Heartbeat thread.
    let hb_stop = stop.clone();
    let hb_mode = mode.clone();
    let hb_writer = writer.clone();
    let hb_tx = w_tx.clone();
    let hb = std::thread::spawn(move || {
        let mut last = Instant::now();
        let mut samples: Vec<u64> = Vec::new();
        let mut count: u64 = 0;
        let mut delayed: u64 = 0;
        let threshold = (hb_interval.as_micros() * 3) as u64;
        while !hb_stop.load(Ordering::Relaxed) {
            std::thread::sleep(hb_interval);
            let now = Instant::now();
            let gap = (now - last).as_micros() as u64;
            samples.push(gap);
            last = now;
            count += 1;
            if gap > threshold {
                delayed += 1;
            }
            let v = json!({"kind": "heartbeat", "uin": 1, "phase": "executing"});
            match hb_mode.as_str() {
                "single" => {
                    let mut w = hb_writer.lock().unwrap();
                    let buf = encode_envelope(ama_core::Wire::Json, &v).unwrap();
                    w.write_all(&buf).ok();
                    w.flush().ok();
                }
                "two" => {
                    let buf = encode_envelope(ama_core::Wire::Json, &v).unwrap();
                    let mut w = hb_writer.lock().unwrap();
                    w.write_all(&buf).ok();
                    w.flush().ok();
                }
                "chan" => {
                    let buf = encode_envelope(ama_core::Wire::Json, &v).unwrap();
                    let _ = hb_tx.send(buf);
                }
                _ => unreachable!(),
            }
        }
        (count, samples, delayed)
    });

    // Task loop.
    let t0 = Instant::now();
    let mut n_tasks: u64 = 0;
    while t0.elapsed() < window {
        let v = json!({"kind": "msg", "from": 1, "body": {"i": n_tasks, "s": "x".repeat(8192)}});
        match mode.as_str() {
            "single" => {
                let mut w = writer.lock().unwrap();
                let buf = encode_envelope(ama_core::Wire::Json, &v).unwrap();
                w.write_all(&buf).ok();
                w.flush().ok();
            }
            "two" => {
                let buf = encode_envelope(ama_core::Wire::Json, &v).unwrap();
                let mut w = writer.lock().unwrap();
                w.write_all(&buf).ok();
                w.flush().ok();
            }
            "chan" => {
                let buf = encode_envelope(ama_core::Wire::Json, &v).unwrap();
                let _ = w_tx.clone().send(buf);
            }
            _ => unreachable!(),
        }
        n_tasks += 1;
        std::thread::yield_now();
    }
    let dt = t0.elapsed();
    let task_rate = n_tasks as f64 / dt.as_secs_f64();

    stop.store(true, Ordering::Relaxed);
    let (count, mut samples, delayed) = hb.join().unwrap();
    samples.sort_unstable();

    let p = |f: f64| {
        if samples.is_empty() {
            0
        } else {
            let idx = (((samples.len() as f64) * f) as usize).min(samples.len() - 1);
            samples[idx]
        }
    };
    let min = samples.first().copied().unwrap_or(0);
    let med = p(0.5);
    let max = samples.last().copied().unwrap_or(0);
    println!(
        "MODE={} | tasks={} ({:.0}/s in {:.2?}) | heartbeats={} | hb latency us: min={} med={} p99.9={} max={} | beats>3x={}",
        mode,
        n_tasks,
        task_rate,
        dt,
        count,
        min,
        med,
        p(0.999),
        max,
        delayed,
    );
    std::process::exit(0);
}
