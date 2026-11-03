use std::hash::Hash;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// Feed `payload` (a string of repeated JSON lines) to a reader on a
/// UnixStream pair, from a background thread.
fn feed(payload: String) -> (UnixStream, std::thread::JoinHandle<()>) {
    let (tx, rx) = UnixStream::pair().unwrap();
    let h = std::thread::spawn(move || {
        let mut tx = tx;
        let _ = tx.write_all(payload.as_bytes());
        drop(tx);
    });
    (rx, h)
}

fn main() {
    let tmp = std::env::temp_dir().join(format!("ama-micro-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();

    // ---- 1. kernel-side JSON line reading: byte-at-a-time vs read_line ----
    let body = serde_json::json!({"op":"work","payload":"y".repeat(1024)});
    let one = format!("{}\n", serde_json::to_string(&body).unwrap());
    let n = 5000;
    let payload = one.repeat(n);

    // a) byte-at-a-time from a BufReader (the kernel's JsonPeer::read_line_after shape)
    let (rx, _h) = feed(payload.clone());
    let mut br = BufReader::with_capacity(1 << 16, rx);
    let t0 = Instant::now();
    let mut count = 0usize;
    let mut buf: Vec<u8> = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match br.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {
                if b[0] == b'\n' {
                    count += 1;
                    buf.clear();
                } else {
                    buf.push(b[0]);
                }
            }
            Err(_) => break,
        }
    }
    let dt = t0.elapsed();
    println!(
        "byte-at-a-time line read:  {} lines in {:.1?} => {:.2} us/line",
        count,
        dt,
        dt.as_micros() as f64 / count as f64
    );

    // b) BufReader::read_line (what the agent side uses)
    let (rx, _h) = feed(payload.clone());
    let mut br = BufReader::with_capacity(1 << 16, rx);
    let t0 = Instant::now();
    let mut count = 0usize;
    let mut line = String::new();
    while br.read_line(&mut line).unwrap_or(0) > 0 {
        count += 1;
        line.clear();
    }
    let dt = t0.elapsed();
    println!(
        "BufReader::read_line:      {} lines in {:.1?} => {:.2} us/line",
        count,
        dt,
        dt.as_micros() as f64 / count as f64
    );

    // b2) the NEW kernel reader shape: read_until + strip '\n'
    //     (JsonPeer::read_line_after now uses this)
    let (rx, _h) = feed(payload.clone());
    let mut br = BufReader::with_capacity(1 << 16, rx);
    let t0 = Instant::now();
    let mut count = 0usize;
    let mut line = String::new();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let n = br.read_until(b'\n', &mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        line.clear();
        line.push_str(&String::from_utf8_lossy(&buf));
        line.pop();
        count += 1;
    }
    let dt = t0.elapsed();
    println!(
        "read_until (new kernel):   {} lines in {:.1?} => {:.2} us/line",
        count,
        dt,
        dt.as_micros() as f64 / count as f64
    );

    // ---- 2. serde_json::Value clone vs to_vec at payload sizes ----
    for p in [64usize, 256, 1024, 4096] {
        let v = serde_json::json!({"op":"work","payload":"y".repeat(p)});
        let n = 10000;
        let t0 = Instant::now();
        let mut acc = std::hash::DefaultHasher::new();
        for _ in 0..n {
            let c = v.clone();
            c.hash(&mut acc);
        }
        let dt = t0.elapsed();
        let t1 = Instant::now();
        for _ in 0..n {
            let _ = serde_json::to_vec(&v);
        }
        let dt2 = t1.elapsed();
        println!(
            "payload={p:>5}B: Value::clone {:.2} us | serde_json::to_vec {:.2} us",
            dt.as_micros() as f64 / n as f64,
            dt2.as_micros() as f64 / n as f64
        );
    }

    // ---- 3. ledger.append WITH vs WITHOUT the full body in the detail ----
    let l = ama_core::Ledger::open(&tmp.join("l.jsonl")).unwrap();
    for p in [64usize, 1024] {
        let body = serde_json::json!({"op":"work","payload":"y".repeat(p)});
        let n = 5000;
        let t0 = Instant::now();
        for _ in 0..n {
            l.append(
                "delivered",
                serde_json::json!({"from":1,"to":2,"bytes":p,"body":&body}),
            )
            .unwrap();
        }
        let dt = t0.elapsed();
        let t1 = Instant::now();
        for _ in 0..n {
            l.append("delivered", serde_json::json!({"from":1,"to":2,"bytes":p}))
                .unwrap();
        }
        let dt2 = t1.elapsed();
        println!(
            "ledger.append payload={p:>5}B: with body {:.2} us | without body {:.2} us",
            dt.as_micros() as f64 / n as f64,
            dt2.as_micros() as f64 / n as f64
        );
    }

    // ---- 4. last_checkpoint warm (index) vs cold (full scan) ----
    for size in [2000usize, 8000, 32000] {
        let l2 = ama_core::Ledger::open(&tmp.join(format!("l{size}.jsonl"))).unwrap();
        for i in 0..size {
            l2.append("noise", serde_json::json!({"i": i})).unwrap();
        }
        l2.append(
            "checkpoint",
            serde_json::json!({"uin": 1, "state": serde_json::json!({"x": 1})}),
        )
        .unwrap();
        let t0 = Instant::now();
        let _ = l2.last_checkpoint(1);
        let warm = t0.elapsed();
        // cold: a FRESH Ledger over the same file => empty cp_index => full scan
        let l3 = ama_core::Ledger::open(&tmp.join(format!("l{size}.jsonl"))).unwrap();
        let t1 = Instant::now();
        let _ = l3.last_checkpoint(1);
        let cold = t1.elapsed();
        println!(
            "last_checkpoint {size:>6} events: warm(index) {:.2} ms | cold(scan) {:.2} ms",
            warm.as_micros() as f64 / 1000.0,
            cold.as_micros() as f64 / 1000.0
        );
    }

    // ---- 5. proto encode path (3 JSON passes) vs json to_vec ----
    for p in [64usize, 1024] {
        let v = serde_json::json!({"kind":"send","uin":1,"to":"b","body":{"op":"work","payload":"y".repeat(p)}});
        let n = 5000;
        let t0 = Instant::now();
        for _ in 0..n {
            let _ = ama_core::proto::encode_value(&v).unwrap();
        }
        let dt = t0.elapsed();
        println!(
            "proto encode_value payload={p:>5}B: {:.2} us",
            dt.as_micros() as f64 / n as f64
        );
    }

    std::process::exit(0);
}
