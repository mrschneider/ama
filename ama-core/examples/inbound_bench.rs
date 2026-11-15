//! Cost breakdown of the INBOUND path — what the kernel pays for ONE
//! message that arrives over the wire.
//!
//! The chain an inbound `send` envelope walks:
//!
//! 1. read the line            (buffered scan + memcpy)
//! 2. parse the line -> Value  (serde_json: a tree of allocations)
//! 3. Envelope::from_value     (schema validation + a DEEP CLONE of the body)
//! 4. serde_json::to_vec(body) (the body is serialized AGAIN, to count its bytes)
//! 5. json!({"from","to","bytes"}) + to_writer (the ledger record)
//!
//! Step 3 is a clone of the body and step 4 is a second serialization of
//! the same body: the payload is touched THREE times per message before
//! it even reaches the socket.
//!
//! Run: cargo run --release -p ama-core --example inbound_bench

use ama_core::Envelope;
use serde_json::{json, Value};
use std::time::Instant;

fn bench<F: FnMut()>(label: &str, n: usize, mut f: F) {
    // warm
    for _ in 0..(n / 10).max(1) {
        f();
    }
    let t0 = Instant::now();
    for _ in 0..n {
        f();
    }
    let dt = t0.elapsed();
    println!(
        "{label:<44} {:>8.3} us/op",
        dt.as_nanos() as f64 / n as f64 / 1000.0
    );
}

fn main() {
    for payload in [64usize, 256, 1024] {
        println!("\n== body payload {payload} bytes ==");
        let line = json!({
            "kind": "send",
            "uin": 1,
            "to": "dest",
            "body": {"op": "work", "payload": "y".repeat(payload)}
        })
        .to_string();
        let n = 200_000;

        bench("1. parse the line -> Value", n, || {
            let v: Value = serde_json::from_str(&line).unwrap();
            std::hint::black_box(&v);
        });

        let v: Value = serde_json::from_str(&line).unwrap();
        bench("2. Envelope::from_value (deep clone)", n, || {
            let e = Envelope::from_value(&v).unwrap();
            std::hint::black_box(&e);
        });

        let e = Envelope::from_value(&v).unwrap();
        let body = match &e {
            Envelope::Send { body, .. } => body.clone(),
            _ => unreachable!(),
        };
        bench("3. serde_json::to_vec(body)", n, || {
            let b = serde_json::to_vec(&body).unwrap();
            std::hint::black_box(&b);
        });

        bench("4. json!(3 keys) [the ledger detail]", n, || {
            let d = json!({"from": 1, "to": 2, "bytes": 100});
            std::hint::black_box(&d);
        });

        bench("5. json!(3 keys) + to_writer", n, || {
            let d = json!({"from": 1, "to": 2, "bytes": 100});
            let mut buf: Vec<u8> = Vec::with_capacity(256);
            serde_json::to_writer(&mut buf, &d).unwrap();
            std::hint::black_box(&buf);
        });
    }
    std::process::exit(0);
}
