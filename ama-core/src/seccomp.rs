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
    /// (instruction pos, is_conditional) — conditionals get jf->DENY,
    /// plain allow entries get jf=0 (fall through to the next comparison)
    allow_jumps: Vec<(usize, bool)>,
}

impl Filter {
    fn new() -> Filter {
        Filter {
            prog: Vec::new(),
            deny_jumps: Vec::new(),
            allow_jumps: Vec::new(),
        }
    }
    fn push(&mut self, code: u16, jt: u8, jf: u8, k: u32) {
        self.prog.push(SockFilter { code, jt, jf, k });
    }
    fn push_jeq_deny(&mut self, nr: u32) {
        self.push(BPF_JEQ_K, 0, 0, nr);
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
        return Err(format!("PR_SET_SECCOMP failed: {rc} ({err})"));
    }
    Ok(())
}

/// Which filter the jail installs
#[derive(Clone, Copy, PartialEq)]
pub enum Profile {
    /// host-dangerous syscalls return EPERM (default for agents)
    Denylist,
    /// default-DENY with an explicit allow set; socket() only AF_UNIX
    Allowlist,
}

/// Unprivileged USER-NAMESPACE isolation (the MicroVM frontier's first
/// step): the jailed tool runs in a fresh user+mount namespace with a
/// private root view — even if it escapes the seccomp filter, it owns
/// nothing on the host. Unprivileged unshare(CLONE_NEWUSER|CLONE_NEWNS)
/// works on stock kernels; returns Err when the host forbids it.
pub fn enter_userns() -> Result<(), String> {
    use std::fs;
    let rc = unsafe { unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("unshare(CLONE_NEWUSER|NEWNS): {err}"));
    }
    // map uid/gid 0 (inside) -> current uid/gid (outside)
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let _ = fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"));
    let _ = fs::write("/proc/self/setgroups", "deny\n");
    let _ = fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"));
    Ok(())
}

thread_local! {
    static USERNS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Request the user-namespace tier for the NEXT jail_exec in this thread.
pub fn request_userns() {
    USERNS.with(|f| f.set(true));
}

fn userns_requested() -> bool {
    USERNS.with(|f| f.get())
}

extern "C" {
    fn unshare(flags: i32) -> i32;
}

/// The jail: apply the chosen filter, then exec the command. Never
/// returns on success — the exec'd program runs INSIDE the filter.
pub fn jail_exec(argv: &[String], profile: Profile) -> Result<(), String> {
    if userns_requested() {
        enter_userns().map_err(|e| format!("jail: {e}"))?;
    }
    match profile {
        Profile::Denylist => apply_seccomp_self().map_err(|e| format!("jail: {e}"))?,
        Profile::Allowlist => apply_seccomp_allowlist().map_err(|e| format!("jail: {e}"))?,
    }
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
            Some(2) | Some(13) => {
                last_err = Some(err);
                continue;
            } // ENOENT/EACCES: next PATH dir
            Some(e) => return Err(format!("jail: exec refused: errno {e}")),
            None => {
                last_err = Some(err);
                continue;
            }
        }
    }
    Err(format!(
        "jail: exec failed: {:?}",
        last_err.map(|e| e.to_string())
    ))
}

// ---------------------------------------------------------------------------
// STRICT ALLOWLIST PROFILE (the next security tier): default-DENY with an
// explicit allow set, and `socket()` allowed ONLY for AF_UNIX (an agent has
// no business opening network sockets — the kernel is its only channel).
// Used by `ama jail --strict -- <cmd>` and by agents that opt in
// (`--allowlist`); the denylist profile stays the default for agents whose
// toolchains need broader syscalls.
// ---------------------------------------------------------------------------

const AF_UNIX: u32 = 1;
const NR_SOCKET: u32 = 41;
const SECCOMP_DATA_ARG0: u32 = 16;

pub fn apply_seccomp_allowlist() -> Result<(), String> {
    // curated x86_64 allowlist — everything ama-agentd + shell/python
    // tooling actually need; everything else is EPERM
    const OK: &[u32] = &[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 22, 23, 24, 25,
        26, 27, 28, 32, 33, 34, 35, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
        55, 56, 57, 58, 59, 60, 61, 62, 63, 72, 73, 79, 80, 87, 88, 89, 90, 96, 97, 99, 104, 105,
        106, 107, 108, 109, 110, 111, 127, 128, 129, 131, 137, 138, 157, 158, 160, 186, 202, 204,
        213, 217, 218, 226, 228, 231, 232, 233, 257, 259, 260, 262, 265, 266, 267, 269, 270, 273,
        291, 293, 294, 297, 302, 309, 318, 334, 435,
    ];
    let mut f = Filter::new();
    // foreign arch → deny everything
    f.push(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_ARCH);
    f.push(BPF_JEQ_K, 0, 0, AUDIT_ARCH_X86_64);
    let arch_ok = f.prog.len() - 1;
    f.push(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_NR);
    // ALLOWLIST semantics: JEQ nr -> ALLOW (recorded, resolved at the
    // end); everything that falls through the whole chain hits DENY
    for &nr in OK {
        if nr == NR_SOCKET {
            // socket() is conditional: allowed ONLY for AF_UNIX (arg0==1)
            f.push(BPF_JEQ_K, 0, 0, nr); // JEQ socket -> jt argcheck
            let j = f.prog.len() - 1;
            f.push(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_ARG0);
            f.push(BPF_JEQ_K, 0, 0, AF_UNIX); // JEQ AF_UNIX -> ALLOW / else DENY
            f.allow_jumps.push((f.prog.len() - 1, true));
            f.prog[j].jt = 0; // matched -> the ARG0 load is the NEXT instruction
                              // reload nr (the ARG0 load clobbered the accumulator)
            f.push(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_NR);
            // CRITICAL: the socket JEQ's FALSE branch must SKIP the whole
            // conditional block (LD arg0 clobbers the accumulator — without
            // the jump, every non-socket syscall falls into the AF_UNIX
            // check with garbage in A and gets denied)
            f.prog[j].jf = (f.prog.len() - j - 2) as u8; // -> nr reload
        } else {
            f.push(BPF_JEQ_K, 0, 0, nr);
            f.allow_jumps.push((f.prog.len() - 1, false));
        }
    }
    f.push(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | 1); // default DENY
    f.push(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW);
    let deny_at = f.prog.len() - 2;
    let allow_at = f.prog.len() - 1;
    f.prog[arch_ok].jf = (deny_at - arch_ok - 1) as u8;
    // resolve allow jumps: matched -> ALLOW; conditionals' jf -> DENY,
    // plain entries' jf = 0 (fall through to the NEXT comparison)
    for (pos, conditional) in &f.allow_jumps {
        f.prog[*pos].jt = (allow_at - pos - 1) as u8;
        f.prog[*pos].jf = if *conditional {
            (deny_at - pos - 1) as u8
        } else {
            0
        };
    }
    if std::env::var("AMA_DUMP_FILTER").is_ok() {
        eprintln!("=== BPF filter ({} instructions) ===", f.prog.len());
        for (i, ins) in f.prog.iter().enumerate() {
            eprintln!(
                "{i:3}: code=0x{:04x} jt={} jf={} k=0x{:x}",
                ins.code, ins.jt, ins.jf, ins.k
            );
        }
        eprintln!("deny_at={deny_at} allow_at={allow_at}");
    }
    let fprog = SockFProg {
        len: f.prog.len() as u16,
        filter: f.prog.as_ptr(),
    };
    let rc = unsafe { prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(format!("PR_SET_NO_NEW_PRIVS failed: {rc}"));
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
        return Err(format!("PR_SET_SECCOMP (allowlist) failed: {rc} ({err})"));
    }
    Ok(())
}
