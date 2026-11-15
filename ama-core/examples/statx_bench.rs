//! statx variants for the ledger's per-append path check.
//!
//! The kernel needs, per append: the ledger file's (dev, ino) to detect an
//! EXTERNAL rename, and its size to decide the rotation. `std::fs::metadata`
//! asks for the whole statx mask; a targeted mask may be cheaper — and
//! AT_STATX_DONT_SYNC skips the network-filesystem sync path.
//!
//! Run: cargo run --release -p ama-core --example statx_bench

use std::os::unix::fs::MetadataExt;
use std::time::Instant;

fn main() {
    let dir = std::env::temp_dir().join(format!("ama-statx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("l.jsonl");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"{}\n").unwrap();
    }
    let n = 500_000;

    // (a) std::fs::metadata — the full mask
    let t0 = Instant::now();
    for _ in 0..n {
        let m = std::fs::metadata(&path).unwrap();
        std::hint::black_box((m.dev(), m.ino(), m.len()));
    }
    println!(
        "std::fs::metadata(path)          {:.4} us/call",
        t0.elapsed().as_nanos() as f64 / n as f64 / 1000.0
    );

    // (b) raw statx with a targeted mask
    let c = path.as_os_str().as_encoded_bytes();
    let t0 = Instant::now();
    for _ in 0..n {
        let mut st: libc::statx = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::statx(
                libc::AT_FDCWD,
                c.as_ptr() as *const libc::c_char,
                0,
                libc::STATX_INO | libc::STATX_SIZE,
                &mut st,
            )
        };
        assert_eq!(r, 0);
        std::hint::black_box((st.stx_dev_major, st.stx_dev_minor, st.stx_ino, st.stx_size));
    }
    println!(
        "libc::statx (INO|SIZE)            {:.4} us/call",
        t0.elapsed().as_nanos() as f64 / n as f64 / 1000.0
    );

    // (c) raw statx with DONT_SYNC
    let t0 = Instant::now();
    for _ in 0..n {
        let mut st: libc::statx = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::statx(
                libc::AT_FDCWD,
                c.as_ptr() as *const libc::c_char,
                libc::AT_STATX_DONT_SYNC,
                libc::STATX_INO | libc::STATX_SIZE,
                &mut st,
            )
        };
        assert_eq!(r, 0);
        std::hint::black_box((st.stx_dev_major, st.stx_dev_minor, st.stx_ino, st.stx_size));
    }
    println!(
        "libc::statx (INO|SIZE|DONT_SYNC)  {:.4} us/call",
        t0.elapsed().as_nanos() as f64 / n as f64 / 1000.0
    );

    let _ = std::fs::remove_dir_all(&dir);
    std::process::exit(0);
}
