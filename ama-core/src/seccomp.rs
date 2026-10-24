//! seccomp-bpf jail (§2 of the brief): a denylist of host-dangerous
//! syscalls (mount, ptrace, module loading, BPF, …) applied with
//! PR_SET_SECCOMP over raw BPF — no libseccomp dependency. Denials
//! return EPERM (SECCOMP_RET_ERRNO), so a jailed agent can OBSERVE the
//! refusal instead of dying. Applied by `ama-agentd` to its own process
//! and by `ama jail -- <cmd>` (the Tool Execution Jail).

use std::ffi::CString;

const BPF_JEQ_K: u16 = BPF_JMP | BPF_JEQ | (BPF_K as u16);
const BPF_RET_K: u16 = BPF_RET | (BPF_K as u16);
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x15;
const BPF_RET: u16 = 0x06;
const BPF_K: u32 = 0x00;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000; // | errno
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFProg {
    len: u16,
    filter: *const SockFilter,
}

extern "C" {
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    fn syscall(num: i64, ...) -> i64;
}

/// Denylist for x86_64 — the jail surface. Everything NOT here is
/// allowed; the filter closes the capabilities an escaped prompt could
/// abuse. ptrace is the headline: a jailed agent cannot attach to its
/// host or to sibling agents.
const DENYLIST: &[u32] = &[
    101, // ptrace
    165, // mount
    166, // umount2
    167, // swapon
    168, // swapoff
    169, // reboot
    246, // kexec_load
    320, // kexec_file_load
    128, // init_module
    313, // finit_module
    129, // delete_module
    321, // bpf
    323, // userfaultfd
    298, // perf_event_open
    304, // open_by_handle_at
    303, // name_to_handle_at
    308, // setns
    272, // unshare
];

struct Filter {
    prog: Vec<SockFilter>,
    /// instruction index of each pending JEQ's deny target (resolved by
    /// the DENY block appended later)
    deny_jumps: Vec<usize>,
}

impl Filter {
    fn new() -> Filter {
        Filter { prog: Vec::new(), deny_jumps: Vec::new() }
    }
    fn push(&mut self, code: u16, jt: u8, jf: u8, k: u32) {
        self.prog.push(SockFilter { code, jt, jf, k });
    }
    fn push_jeq_deny(&mut self, nr: u32) {
        self.push(BPF_JEQ_K, 0, 0, nr as u32);
        self.deny_jumps.push(self.prog.len() - 1);
    }
    /// resolve all recorded deny jumps to the final RET ERRNO at `at`
    fn resolve_deny(&mut self, at: usize) {
        for pos in &self.deny_jumps {
            self.prog[*pos].jt = (at - pos - 1) as u8;
        }
    }
}

/// Apply the seccomp denylist to the CALLING process (no-unpriv: this
/// process can never regain privileges — `no_new_privs` is set first).
pub fn apply_seccomp_self() -> Result<(), String> {
    let mut f = Filter::new();
    // foreign architecture → deny everything (injection-defense trip)
    f.push(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_ARCH);
    f.push(BPF_JEQ_K, 0, 0, AUDIT_ARCH_X86_64);
    let arch_ok = f.prog.len() - 1;
    // nr = seccomp_data.nr
    f.push(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_NR);
    for &nr in DENYLIST {
        f.push_jeq_deny(nr);
    }
    f.push(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW);
    // the foreign-arch tripwire: everything on a non-x86_64 arch is EPERM
    f.push(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 1);
    // the deny block: one RET ERRNO(EPERM) reached by every denylist JEQ
    f.push(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 1);
    let deny_at = f.prog.len() - 1;
    // patch: the arch check jumps to the deny RET when NOT x86_64
    f.prog[arch_ok].jf = (deny_at - arch_ok - 1) as u8;
    f.resolve_deny(deny_at);

    let fprog = SockFProg {
        len: f.prog.len() as u16,
        filter: f.prog.as_ptr(),
    };
    let rc = unsafe { prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("PR_SET_NO_NEW_PRIVS failed: {rc} ({err})"));
    }
    let rc = unsafe {
        prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as u64,
            &fprog as *const SockFProg as u64,
            0,
            0,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!(
            "PR_SET_SECCOMP failed: {rc} ({err})"
        ));
    }
    Ok(())
}

/// The jail: apply the filter, then exec the command. Never returns on
/// success — the exec'd program runs INSIDE the filter.
pub fn jail_exec(argv: &[String]) -> Result<(), String> {
    apply_seccomp_self().map_err(|e| format!("jail: {e}"))?;
    // execve does NOT PATH-lookup (execvp does) — resolve relative names
    // against PATH ourselves; absolute paths pass through
    let path_dirs: Vec<String> = if argv[0].contains('/') {
        vec![argv[0].clone()]
    } else {
        let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
        path.split(':')
            .filter(|d| !d.is_empty())
            .map(|d| format!("{}/{}", d, argv[0]))
            .collect()
    };
    let mut last_err: Option<std::io::Error> = None;
    for cand in &path_dirs {
        let c = match CString::new(cand.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut cargs: Vec<CString> = vec![c.clone()];
        for a in argv.iter().skip(1) {
            cargs.push(CString::new(a.as_str()).map_err(|e| e.to_string())?);
        }
        cargs.push(CString::new("").unwrap());
        let mut argp: Vec<*const std::ffi::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
        argp.push(std::ptr::null());
        let rc = unsafe {
            syscall(
                libc::SYS_execve,
                argp[0],
                argp.as_ptr(),
                std::ptr::null::<std::ffi::c_char>(),
            )
        };
        if rc >= 0 {
            unreachable!("execve never returns on success");
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(2) | Some(13) => { last_err = Some(err); continue; } // ENOENT/EACCES: next PATH dir
            Some(e) => return Err(format!("jail: exec refused: errno {e}")),
            None => { last_err = Some(err); continue; }
        }
    }
    Err(format!("jail: exec failed: {:?}", last_err.map(|e| e.to_string())))
}
