//! Cost breakdown of a single append() — isolate clock, metadata syscalls,
//! serialization, and the write itself.

use ama_core::Ledger;
use serde_json::json;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

fn main() {
    let tmp = std::env::temp_dir().join(format!("ama-breakdown-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let path = tmp.join("l.jsonl");
    let ledger = Ledger::open(&path).unwrap();

    let detail = json!({"op": "work", "payload": "y".repeat(128), "i": 12345});

    // (a) clock only
    let n = 200_000;
    let t0 = Instant::now();
    for _ in 0..n {
        let _ = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
    }
    let dt = t0.elapsed();
    println!(
        "SystemTime::now() x{}: {:.3} us/call",
        n,
        dt.as_micros() as f64 / n as f64
    );

    // (b) std::fs::metadata (path statx)
    let p = path.clone();
    let t0 = Instant::now();
    for _ in 0..n {
        let _ = std::fs::metadata(&p).map(|m| (m.dev(), m.ino()));
    }
    let dt = t0.elapsed();
    println!(
        "std::fs::metadata(path) x{}: {:.3} us/call",
        n,
        dt.as_micros() as f64 / n as f64
    );

    // (c) serde_json::to_vec
    let t0 = Instant::now();
    for _ in 0..n {
        let _ = serde_json::to_vec(&detail).unwrap();
    }
    let dt = t0.elapsed();
    println!(
        "serde_json::to_vec x{}: {:.3} us/call",
        n,
        dt.as_micros() as f64 / n as f64
    );

    // (d) full append
    let t0 = Instant::now();
    for i in 0..n {
        ledger
            .append("delivered", json!({"i": i, "bytes": 128}))
            .unwrap();
    }
    let dt = t0.elapsed();
    println!(
        "full append x{}: {:.3} us/call",
        n,
        dt.as_micros() as f64 / n as f64
    );

    // (e) write_all to an already-open buffered file (lower bound for I/O)
    let _ = std::fs::remove_file(&path);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap();
    let mut bytes = serde_json::to_vec(&detail).unwrap();
    bytes.push(b'\n');
    let t0 = Instant::now();
    for _ in 0..n {
        f.write_all(&bytes).unwrap();
    }
    f.flush().unwrap();
    let dt = t0.elapsed();
    println!(
        "write_all (open fd) x{}: {:.3} us/call",
        n,
        dt.as_micros() as f64 / n as f64
    );

    std::process::exit(0);
}
