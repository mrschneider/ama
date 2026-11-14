//! Measures the contention the agentd `send` refactor removes.
//!
//! A single socket writer is shared by TWO producers:
//!   * a heartbeat thread that must send every 100 ms (the watchdog's only
//!     view of the process — its LATENCY JITTER is the metric that matters
//!     for liveness), and
//!   * a task loop that sends small envelopes back to back for a fixed
//!     wall-clock window, so the two producers overlap on purpose.
//!
//! Two send strategies are compared via the `MODE` env var:
//!   * `single` — lock the writer, serialize with `write_envelope`, write,
//!     flush (the OLD pattern). The task loop's serialization holds the
//!     lock, so a heartbeat that fires mid-loop BLOCKS until the loop
//!     finishes serializing that frame.
//!   * `two` — serialize OFF the lock, then lock only for the write+flush
//!     (the NEW pattern). The two producers serialize in parallel; the
//!     heartbeat only ever waits for the (cheap) write.
//!
//! Metric: the 99.9th-percentile heartbeat latency while the task loop is
//! running. Lower = better liveness predictability. We also report the
//! number of heartbeats that were delayed past 3x their interval, which is
//! the liveness-relevant tail.
//!
//! Run: MODE=single cargo run --release -p ama-core --example send_contention_bench
//!      MODE=two   cargo run --release -p ama-core --example send_contention_bench

use ama_core::{encode_envelope, write_envelope};
use serde_json::json;
use std::io::{Read, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn main() {
    let mode = std::env::var("MODE").unwrap_or_else(|_| "two".to_string());
    let single = mode == "single";
    let window = Duration::from_secs(
        std::env::var("WINDOW")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5),
    );
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

    // Heartbeat thread: send every `hb_interval`, record the gap since the
    // last heartbeat. Report min/max/median/p99.9 latency plus the count of
    // beats delayed past 3x the interval (the liveness-relevant tail).
    let hb_writer = writer.clone();
    let hb_stop = stop.clone();
    let hb = std::thread::spawn(move || {
        let mut last = Instant::now();
        let mut samples: Vec<u64> = Vec::new(); // microseconds between beats
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
            if single {
                let mut w = hb_writer.lock().unwrap();
                write_envelope(&mut *w, ama_core::Wire::Json, &v).ok();
            } else {
                let buf = encode_envelope(ama_core::Wire::Json, &v).unwrap();
                let mut w = hb_writer.lock().unwrap();
                w.write_all(&buf).ok();
                w.flush().ok();
            }
        }
        (count, samples, delayed)
    });

    // Task loop: keep sending for a fixed wall-clock window so it overlaps
    // many heartbeats. A tiny sleep keeps it from exhausting the lock in
    // microseconds (which happened in the previous version and made the
    // contention window too short to measure).
    let t0 = Instant::now();
    let mut n_tasks: u64 = 0;
    while t0.elapsed() < window {
        let v = json!({"kind": "msg", "from": 1, "body": {"i": n_tasks, "s": "x".repeat(32)}});
        if single {
            let mut w = writer.lock().unwrap();
            write_envelope(&mut *w, ama_core::Wire::Json, &v).ok();
        } else {
            let buf = encode_envelope(ama_core::Wire::Json, &v).unwrap();
            let mut w = writer.lock().unwrap();
            w.write_all(&buf).ok();
            w.flush().ok();
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
