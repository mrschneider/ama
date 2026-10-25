//! Best-effort resource isolation (cgroup v2). The process boundary is the
//! v0.1 isolation unit; cgroup memory/CPU limits are applied when the
//! system allows (root / delegated cgroup dir), skipped with a warning
//! otherwise. MicroVM tool-jails are roadmap — see docs/research.

use std::fs;
use std::path::Path;

pub fn apply_cgroup(pid: u32, name: &str) -> Result<(), String> {
    let base = Path::new("/sys/fs/cgroup/ama");
    if !base.exists() && fs::create_dir_all(base).is_err() {
        return Err("cgroup v2 dir /sys/fs/cgroup/ama not available (not root?)".into());
    }
    let dir = base.join(name);
    fs::create_dir_all(&dir).map_err(|e| format!("cgroup mkdir: {e}"))?;
    // 512 MB memory cap, 50% of one CPU — severe by design
    fs::write(dir.join("memory.max"), "536870912").map_err(|e| format!("memory.max: {e}"))?;
    fs::write(dir.join("cpu.max"), "50000 100000").map_err(|e| format!("cpu.max: {e}"))?;
    fs::write(dir.join("cgroup.procs"), pid.to_string())
        .map_err(|e| format!("cgroup.procs: {e}"))?;
    Ok(())
}
