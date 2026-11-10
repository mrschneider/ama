//! Compare statx-on-path (std::fs::metadata) vs fstat-on-fd cost.

use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

fn main() {
    let tmp = std::env::temp_dir().join("ama-fstat-bench");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let path = tmp.join("f.bin");
    let mut f = std::fs::OpenOptions::new().create(true).write(true).open(&path).unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    let n = 1_000_000;

    // statx on path
    let t0 = Instant::now();
    for _ in 0..n {
        let _ = std::fs::metadata(&path).map(|m| (m.dev(), m.ino()));
    }
    let dt = t0.elapsed();
    println!("statx path (metadata) x{}: {:.4} us/call", n, dt.as_micros() as f64 / n as f64);

    // fstat on fd
    let t0 = Instant::now();
    for _ in 0..n {
        let _ = f.metadata().map(|m| (m.dev(), m.ino()));
    }
    let dt = t0.elapsed();
    println!("fstat fd x{}: {:.4} us/call", n, dt.as_micros() as f64 / n as f64);

    // fstat on fd, ignoring result (still a syscall)
    let t0 = Instant::now();
    for _ in 0..n {
        let _ = f.metadata();
    }
    let dt = t0.elapsed();
    println!("fstat fd (noop map) x{}: {:.4} us/call", n, dt.as_micros() as f64 / n as f64);

    std::process::exit(0);
}
