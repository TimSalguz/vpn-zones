//! The seccomp-bpf filter for the bwrap sandbox ([`crate::fs_sandbox`]).
//!
//! Modelled on flatpak's base blocklist. The point is not "block everything
//! dangerous" — a default-deny list cannot be written for arbitrary nixpkgs
//! programs — but to close the handful of syscalls that let a sandboxed process
//! reach out of its box or poke at the kernel:
//!
//! * `ioctl(TIOCSTI)` pushes characters into the terminal's input queue: a
//!   program started from a shell could type a command into that shell and run
//!   it outside the sandbox. `TIOCLINUX` is the same trick on the VT.
//! * `ptrace` attaches to other processes of the same uid — the sandbox shares
//!   the uid with the rest of the session.
//! * key management (`add_key`, `keyctl`, `request_key`), `syslog`,
//!   `perf_event_open`, `acct`, `quotactl`, `uselib` and the NUMA calls are
//!   kernel attack surface with no use inside a desktop sandbox.
//! * `personality` is restricted to `PER_LINUX`: the other personalities
//!   (`READ_IMPLIES_EXEC` in particular) weaken userspace hardening.
//! * the new mount API (`open_tree`, `move_mount`, `fsopen`, …) and `clone3`
//!   answer `ENOSYS`, not `EPERM`, so that libc and applications fall back to
//!   the old code path instead of failing. glibc ≥ 2.34 does exactly that with
//!   `clone3`.
//!
//! Nested user namespaces are **not** blocked by default, and that is a
//! deliberate decision, not an oversight — see [`FilterOptions::deny_userns`].
//!
//! The filter is handed to bwrap as a raw compiled cBPF program on a file
//! descriptor (`bwrap --seccomp FD`), which is the only format bwrap accepts.
//! Filter attributes (NO_NEW_PRIVS, TSYNC) are *not* part of that program:
//! bwrap sets `PR_SET_NO_NEW_PRIVS` itself before loading it.
//!
//! Two callers, and they want different things. [`crate::fs_sandbox`] is the
//! real one and takes the program as an open, rewound file
//! ([`Filter::export_to_file`]) it can hand straight to bwrap; the
//! `vpn-zone-seccomp` binary exists for `selftest` and for exporting the
//! program to stdout by hand.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek};
use std::os::unix::io::{AsRawFd, FromRawFd};

use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

/// Denied outright: the program gets `EPERM` and has to cope.
const DENY_EPERM: [&str; 14] = [
    "syslog",
    "uselib",
    "acct",
    "quotactl",
    "add_key",
    "keyctl",
    "request_key",
    "move_pages",
    "mbind",
    "get_mempolicy",
    "set_mempolicy",
    "migrate_pages",
    "perf_event_open",
    "ptrace",
];

/// Answered with `ENOSYS` so that callers take their "this kernel is older"
/// path instead of treating the call as a hard failure.
const DENY_ENOSYS: [&str; 8] = [
    "clone3",
    "open_tree",
    "move_mount",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "mount_setattr",
];

/// `TIOCSTI` / `TIOCLINUX` from `asm-generic/ioctls.h` — the values used by
/// x86, arm, arm64, riscv and s390. (mips and alpha number them differently;
/// they are not targets of this project.)
const TIOCSTI: u64 = 0x5412;
const TIOCLINUX: u64 = 0x541c;

/// Low 32 bits of the ioctl request. The argument register is 64 bits wide and
/// the upper half is not part of the command, so the comparison is masked —
/// otherwise the rule is trivially bypassed by setting a high bit.
const IOCTL_CMD_MASK: u64 = 0xffff_ffff;

/// `PER_LINUX` from `linux/personality.h`.
const PER_LINUX: u64 = 0x0;

/// What to put in the filter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilterOptions {
    /// Block nested user namespaces (`clone`/`unshare` with `CLONE_NEWUSER`).
    ///
    /// **Off by default, on purpose.** flatpak can afford this rule because it
    /// ships zypak, which turns Chromium's namespace sandbox into calls to the
    /// flatpak portal. On NixOS there is neither zypak nor a setuid
    /// `chrome-sandbox`, so Chromium and every Electron app build their *own*
    /// nested user namespace; block it and they die on startup with
    /// "No usable sandbox! Update your kernel". A nested userns is also not a
    /// way out of the sandbox: it gives the process capabilities over its new,
    /// empty namespaces only, never over ours.
    ///
    /// Worth enabling for programs that are known not to sandbox themselves.
    pub deny_userns: bool,
}

/// A compiled-on-demand seccomp filter.
pub struct Filter {
    ctx: ScmpFilterContext,
    unknown: Vec<&'static str>,
}

/// Errors from building, exporting or loading the filter.
#[derive(Debug)]
pub enum Error {
    Seccomp(libseccomp::error::SeccompError),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seccomp(e) => write!(f, "seccomp: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Seccomp(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}

impl From<libseccomp::error::SeccompError> for Error {
    fn from(e: libseccomp::error::SeccompError) -> Self {
        Self::Seccomp(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl Filter {
    /// Build the filter. Default action is `ALLOW`: this is a blocklist.
    pub fn build(options: FilterOptions) -> Result<Self, Error> {
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
        let mut unknown = Vec::new();

        // NO_NEW_PRIVS is libseccomp's default, but it is the property that
        // makes an unprivileged `load()` legal at all — say it out loud.
        ctx.set_ctl_nnp(true)?;

        // The 32-bit x86 syscall table is a separate one, and a filter that
        // does not know the architecture lets every call through it: that is
        // Wine and every multilib binary. libseccomp translates the rules
        // below to each architecture in the filter by itself.
        #[cfg(target_arch = "x86_64")]
        ctx.add_arch(libseccomp::ScmpArch::X86)?;

        let eperm = ScmpAction::Errno(libc::EPERM);
        let enosys = ScmpAction::Errno(libc::ENOSYS);

        for name in DENY_EPERM {
            if let Some(syscall) = resolve(name, &mut unknown) {
                ctx.add_rule(eperm, syscall)?;
            }
        }

        for name in DENY_ENOSYS {
            if let Some(syscall) = resolve(name, &mut unknown) {
                ctx.add_rule(enosys, syscall)?;
            }
        }

        // Everything except PER_LINUX is refused.
        if let Some(syscall) = resolve("personality", &mut unknown) {
            ctx.add_rule_conditional(
                eperm,
                syscall,
                &[ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, PER_LINUX)],
            )?;
        }

        // Terminal injection: one rule per command, because a seccomp rule can
        // compare a given argument only once.
        if let Some(syscall) = resolve("ioctl", &mut unknown) {
            for cmd in [TIOCSTI, TIOCLINUX] {
                ctx.add_rule_conditional(
                    eperm,
                    syscall,
                    &[ScmpArgCompare::new(
                        1,
                        ScmpCompareOp::MaskedEqual(IOCTL_CMD_MASK),
                        cmd,
                    )],
                )?;
            }
        }

        if options.deny_userns {
            // Flags live in arg0 of both calls on the architectures we target
            // (s390 swaps clone's first two arguments — not a target).
            let newuser = libc::CLONE_NEWUSER as u64;
            let has_newuser = ScmpArgCompare::new(0, ScmpCompareOp::MaskedEqual(newuser), newuser);
            for name in ["clone", "unshare"] {
                if let Some(syscall) = resolve(name, &mut unknown) {
                    ctx.add_rule_conditional(eperm, syscall, &[has_newuser])?;
                }
            }
        }

        Ok(Self { ctx, unknown })
    }

    /// Syscall names the installed libseccomp did not recognise, i.e. rules
    /// that are missing from the filter. Empty on a current libseccomp; worth
    /// reporting, never worth failing on — a partial filter beats no filter.
    pub fn unknown_syscalls(&self) -> &[&'static str] {
        &self.unknown
    }

    /// The compiled cBPF program on an open, unnamed file, rewound to the
    /// start — the shape `bwrap --seccomp FD` wants, because bwrap reads the
    /// descriptor from its current offset.
    ///
    /// This is what [`crate::fs_sandbox`] hands to bwrap. Keeping it a file and
    /// not a path is the whole point: `--seccomp` takes a NUMBER, never a name.
    pub fn export_to_file(&self) -> Result<File, Error> {
        // libseccomp only exports to a file descriptor (the in-memory export
        // is a libseccomp 2.6 feature and would make this crate refuse to
        // build against older ones), so the program takes a detour through an
        // anonymous file.
        let mut scratch = scratch_file()?;
        self.ctx.export_bpf(&scratch)?;
        scratch.rewind()?;
        Ok(scratch)
    }

    /// The compiled cBPF program as bytes, for `vpn-zone-seccomp export`.
    pub fn export_bpf(&self) -> Result<Vec<u8>, Error> {
        let mut scratch = self.export_to_file()?;
        let mut bpf = Vec::new();
        scratch.read_to_end(&mut bpf)?;
        Ok(bpf)
    }

    /// Load the filter into the **current process**. Irreversible.
    pub fn load(&self) -> Result<(), Error> {
        self.ctx.load()?;
        Ok(())
    }
}

/// One selftest check.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// Load the filter into this process and verify that it does what it claims.
///
/// Irreversible for the calling process, which is why it lives behind a
/// separate CLI verb: run it in a process of its own.
pub fn selftest(options: FilterOptions) -> Result<Vec<Check>, Error> {
    let filter = Filter::build(options)?;
    filter.load()?;

    let mut checks = Vec::new();

    // Blocked with EPERM. Arguments are typed on purpose: they are passed
    // through a variadic C function, where an untyped literal would be handed
    // over as a 32-bit int.
    let zero: libc::c_long = 0;
    checks.push(expect_errno("keyctl is EPERM", libc::EPERM, || unsafe {
        libc::syscall(libc::SYS_keyctl, zero, zero, zero, zero, zero)
    }));

    // Answered with ENOSYS so that glibc falls back to clone(). Null arguments:
    // even without the filter this cannot fork anything.
    checks.push(expect_errno("clone3 is ENOSYS", libc::ENOSYS, || unsafe {
        libc::syscall(libc::SYS_clone3, std::ptr::null_mut::<libc::c_void>(), zero)
    }));

    // Personality: PER_LINUX still works, everything else does not.
    checks.push(expect_errno(
        "personality(!= PER_LINUX) is EPERM",
        libc::EPERM,
        || libc::c_long::from(unsafe { libc::personality(0xffff_ffff) }),
    ));
    // PER_LINUX, the one personality the filter lets through.
    let persona = unsafe { libc::personality(0) };
    checks.push(Check {
        name: "personality(PER_LINUX) is allowed",
        ok: persona >= 0,
        detail: format!("returned {persona}"),
    });

    // Terminal injection. /dev/null is not a terminal, so without the filter
    // this returns ENOTTY — and nothing is ever injected anywhere.
    match File::open("/dev/null") {
        Ok(devnull) => {
            let mut byte: libc::c_char = 0;
            let byte_ptr: *mut libc::c_char = &mut byte;
            checks.push(expect_errno("ioctl(TIOCSTI) is EPERM", libc::EPERM, || {
                // 0x5412 is TIOCSTI, written out because the request argument
                // is a different integer type in different libcs, and an
                // untyped literal is the only spelling that fits them all.
                let rc = unsafe { libc::ioctl(devnull.as_raw_fd(), 0x5412, byte_ptr) };
                libc::c_long::from(rc)
            }));
            checks.push(Check {
                name: "ordinary syscalls still work",
                ok: true,
                detail: "opened /dev/null".to_string(),
            });
        }
        Err(e) => checks.push(Check {
            name: "ordinary syscalls still work",
            ok: false,
            detail: format!("could not open /dev/null: {e}"),
        }),
    }

    if options.deny_userns {
        checks.push(expect_errno(
            "unshare(CLONE_NEWUSER) is EPERM",
            libc::EPERM,
            || libc::c_long::from(unsafe { libc::unshare(libc::CLONE_NEWUSER) }),
        ));
    }

    Ok(checks)
}

fn resolve(name: &'static str, unknown: &mut Vec<&'static str>) -> Option<ScmpSyscall> {
    match ScmpSyscall::from_name(name) {
        Ok(syscall) => Some(syscall),
        Err(_) => {
            unknown.push(name);
            None
        }
    }
}

fn expect_errno<F>(name: &'static str, want: libc::c_int, call: F) -> Check
where
    F: FnOnce() -> libc::c_long,
{
    let rc = call();
    if rc != -1 {
        return Check {
            name,
            ok: false,
            detail: format!("call succeeded (returned {rc}), the filter is not in effect"),
        };
    }
    let got = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    Check {
        name,
        ok: got == want,
        detail: format!("errno {got}, wanted {want}"),
    }
}

/// An unnamed, unlinked file to export the program into.
fn scratch_file() -> io::Result<File> {
    // SAFETY: memfd_create(2) only ever returns a fresh descriptor or -1, and
    // a C-string literal is NUL-terminated by construction.
    let fd = unsafe { libc::memfd_create(c"vpn-zone-seccomp".as_ptr(), 0) };
    if fd >= 0 {
        // SAFETY: the descriptor is fresh and owned by nobody else.
        return Ok(unsafe { File::from_raw_fd(fd) });
    }

    // Kernels and sandboxes without memfd_create: an ordinary file, unlinked
    // right away so that only our descriptor keeps it alive.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let mut path = std::env::temp_dir();
    path.push(format!(
        "vpn-zone-seccomp-{}-{nanos}.bpf",
        std::process::id()
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    std::fs::remove_file(&path)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `struct sock_filter` is 8 bytes: u16 code, u8 jt, u8 jf, u32 k.
    const INSN_LEN: usize = 8;

    fn insn_code(insn: &[u8]) -> u16 {
        u16::from_ne_bytes([insn[0], insn[1]])
    }

    #[test]
    fn export_produces_a_valid_bpf_program() {
        let bpf = Filter::build(FilterOptions::default())
            .unwrap()
            .export_bpf()
            .unwrap();

        assert!(!bpf.is_empty(), "empty filter would silently disable bwrap");
        assert_eq!(
            bpf.len() % INSN_LEN,
            0,
            "not a whole number of instructions"
        );

        // libseccomp always starts by loading the architecture out of
        // seccomp_data: BPF_LD | BPF_W | BPF_ABS, k = 4.
        assert_eq!(insn_code(&bpf[..INSN_LEN]), 0x20);
        assert_eq!(u32::from_ne_bytes([bpf[4], bpf[5], bpf[6], bpf[7]]), 4);

        // …and ends with a return.
        let last = &bpf[bpf.len() - INSN_LEN..];
        assert_eq!(
            insn_code(last) & 0x07,
            0x06,
            "last instruction is not BPF_RET"
        );
    }

    #[test]
    fn deny_userns_is_an_addition_to_the_default_filter() {
        let default = Filter::build(FilterOptions::default())
            .unwrap()
            .export_bpf()
            .unwrap();
        let strict = Filter::build(FilterOptions { deny_userns: true })
            .unwrap()
            .export_bpf()
            .unwrap();
        assert!(
            strict.len() > default.len(),
            "--deny-userns produced no extra instructions"
        );
    }

    #[test]
    fn every_syscall_in_the_list_is_known_to_libseccomp() {
        let filter = Filter::build(FilterOptions { deny_userns: true }).unwrap();
        let unknown = filter.unknown_syscalls();
        assert!(unknown.is_empty(), "libseccomp does not know: {unknown:?}");
    }
}
