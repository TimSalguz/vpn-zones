//! Data containers ("profiles"): an overlayfs layer over the XDG directories,
//! put in place for one program run.
//!
//! This is `vpn-zone run --profile` seen from the inside. The bash side has
//! already entered the zone's user+net namespace (`nsenter --preserve-credentials
//! --keep-caps`) and a private mount namespace of its own (`unshare --mount`);
//! everything that happens here happens in that namespace and is invisible to
//! the rest of the system. Three steps:
//!
//!  1. stack the profile over the XDG directories: the lower layer is the real
//!     `~/.config` and friends (read-only in effect), the upper layer lives in
//!     the profile directory. The program sees its settings, but everything it
//!     writes lands in the profile;
//!  2. drop the capabilities that were needed for step 1;
//!  3. start the program — and, for a throwaway container, outlive it and take
//!     the directory away afterwards.
//!
//! **Why mount(2) and not `mount(8)`.** The util-linux tool, started by a
//! non-root user, tries to drop privileges and dies with "drop permissions
//! failed" — even when the mount would be allowed (CAP_SYS_ADMIN came from
//! `nsenter --keep-caps`). The raw syscall makes no such check.
//! (`docs/GOTCHAS.md` §1)
//!
//! **Why the ambient capability set is cleared.** The capabilities are needed
//! for mounting and for nothing else. The ambient set survives `execve`, so
//! without an explicit clear Chrome would inherit CAP_SYS_ADMIN inside the
//! namespace. It cannot reach the host from there, but there is no reason to
//! hand it over either. (`docs/GOTCHAS.md` §1)

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// The XDG directories that make up a "profile".
///
/// Documents, Downloads and the rest of `$HOME` are shared on purpose: this
/// separates profiles, it is not a sandbox — that is what
/// [`crate::fs_sandbox`] is for. (`docs/GOTCHAS.md` §5)
pub const SUBDIRS: [&str; 5] = [".config", ".local/share", ".cache", ".mozilla", ".pki"];

/// `PR_CAP_AMBIENT` / `PR_CAP_AMBIENT_CLEAR_ALL` from `linux/prctl.h`.
///
/// Spelled out rather than taken from `libc`: the numbers are kernel ABI and
/// will never change, and this way the binary that has to clear the ambient set
/// cannot fail to build because some libc release moved the constant.
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_int = 4;

/// The program could not be started at all — the code a shell uses for it.
pub const EXIT_NOT_STARTED: u8 = 127;

/// What `profile-run` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Where the upper layers live. **Empty means the "main" profile**: no
    /// layers are stacked at all and the program works with the real `~/`.
    /// Being able to say "through the VPN, but without a container" is the
    /// point of that case.
    pub profile_dir: PathBuf,
    /// The zone this run belongs to. Accepted and not used: the "who runs
    /// where" registry is kept by `vpn-zone` itself (it is shared by profiles
    /// and by the main environment), and duplicating it here would only give
    /// the two copies a chance to disagree. Part of the CLI contract, so it
    /// stays in the signature.
    pub zone: OsString,
    /// Throwaway container: the directory is removed once the last program
    /// living in it is gone.
    pub ephemeral: bool,
    /// Directory of the launch registry for this container, or empty. Used
    /// only to answer "is anybody else still in here?".
    pub regdir: PathBuf,
    /// The program and its arguments.
    pub cmd: Vec<OsString>,
}

/// Everything that can be wrong with the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgError {
    /// No `--` separator, so where the command starts is anybody's guess.
    NoSeparator,
    /// Fewer positional arguments than the four this takes.
    MissingArguments,
    /// `--` was there, but nothing followed it.
    EmptyCommand,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSeparator => write!(f, "no `--` before the command"),
            Self::MissingArguments => {
                write!(f, "need <profiledir> <zone> <ephemeral 0|1> <regdir>")
            }
            Self::EmptyCommand => write!(f, "nothing to run after `--`"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parse `<profiledir> <zone> <ephemeral 0|1> <regdir> -- cmd...`.
    ///
    /// `OsString` and not `String` all the way through: an argument can be a
    /// file name handed over by the launcher through a `%U` field code, and
    /// those are bytes, not necessarily UTF-8. Refusing to start a program
    /// because its argument is not valid Unicode would be a regression against
    /// every other launcher on the system.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let split = argv
            .iter()
            .position(|a| a == "--")
            .ok_or(ArgError::NoSeparator)?;
        let positional = &argv[..split];
        let cmd = argv[split + 1..].to_vec();
        if cmd.is_empty() {
            return Err(ArgError::EmptyCommand);
        }
        if positional.len() < 2 {
            return Err(ArgError::MissingArguments);
        }
        Ok(Self {
            profile_dir: PathBuf::from(positional[0].clone()),
            zone: positional[1].clone(),
            // Anything other than "1" means "keep the container", which is the
            // safe way round: a typo must not delete somebody's data.
            ephemeral: positional.get(2).is_some_and(|e| e == "1"),
            regdir: PathBuf::from(positional.get(3).cloned().unwrap_or_default()),
            cmd,
        })
    }
}

/// Directory name of the upper/work pair for one XDG subdirectory:
/// `.local/share` → `.local_share`, so that the whole thing stays one level
/// deep inside the profile.
pub fn slot_name(sub: &str) -> String {
    sub.replace('/', "_")
}

/// `$HOME`, or the passwd entry if the environment does not say — the same
/// order Python's `os.path.expanduser("~")` used.
pub fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return Some(PathBuf::from(home));
    }
    // SAFETY: getpwuid returns a pointer into a static buffer; it is read
    // before anything else can call into the passwd machinery again.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() || (*pw).pw_dir.is_null() {
            return None;
        }
        let bytes = CStr::from_ptr((*pw).pw_dir).to_bytes().to_vec();
        Some(PathBuf::from(OsString::from_vec(bytes)))
    }
}

/// `mount -t overlay overlay -o lowerdir=…,upperdir=…,workdir=…,userxattr`,
/// as a syscall.
///
/// `userxattr` is what makes this work without root: the kernel then keeps its
/// overlay metadata in the `user.*` xattr namespace, which an unprivileged
/// mount inside a user namespace is allowed to write.
fn mount_overlay(lower: &Path, upper: &Path, work: &Path, target: &Path) -> io::Result<()> {
    let opts = format!(
        "lowerdir={},upperdir={},workdir={},userxattr",
        lower.display(),
        upper.display(),
        work.display()
    );
    // Source and filesystem type are both the literal "overlay" — the source
    // of an overlay mount is a name, not a device.
    crate::sys::mount(OsStr::new("overlay"), target, "overlay", 0, &opts)
}

/// Stack the profile over every XDG directory that exists.
///
/// A single failing layer is a warning, never fatal: losing `.pki` must not
/// stop the browser from starting, and the ones that did mount still separate
/// the data they cover.
fn mount_profile(profile_dir: &Path) {
    let Some(home) = home_dir() else {
        eprintln!("profile: no $HOME — running without the container layer");
        return;
    };
    for sub in SUBDIRS {
        let lower = home.join(sub);
        if !lower.is_dir() {
            continue;
        }
        let slot = profile_dir.join(slot_name(sub));
        let upper = slot.join("upper");
        let work = slot.join("work");
        if let Err(e) = fs::create_dir_all(&upper).and_then(|()| fs::create_dir_all(&work)) {
            eprintln!("profile: cannot prepare {}: {e}", slot.display());
            continue;
        }
        // The mount target is the lower directory itself: the program keeps
        // using the paths it always used.
        if let Err(e) = mount_overlay(&lower, &upper, &work, &lower) {
            eprintln!("profile: overlay on {}: {e}", lower.display());
        }
    }
}

/// Drop the ambient capability set before handing control to the program.
///
/// Errors are ignored deliberately: on a kernel without ambient capabilities
/// (< 4.3) `prctl` answers EINVAL, and there is nothing to clear there anyway.
fn clear_ambient_capabilities() {
    // SAFETY: prctl with these two constants takes no pointers.
    unsafe {
        libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
    }
}

/// Is there a live process with this pid? The real liveness test, the one
/// [`others_alive`] is given in production.
pub fn proc_is_alive(pid: i32) -> bool {
    Path::new("/proc").join(pid.to_string()).is_dir()
}

/// Is anybody else still living in this container?
///
/// The registry is the one `vpn-zone run` writes: one file per program, one
/// line per launch, `pid zone selector`. Liveness is a parameter so that the
/// tests can answer it without spawning processes.
pub fn others_alive<F>(regdir: &Path, myself: i32, is_alive: F) -> bool
where
    F: Fn(i32) -> bool,
{
    if regdir.as_os_str().is_empty() || !regdir.is_dir() {
        return false;
    }
    let Ok(entries) = fs::read_dir(regdir) else {
        return false;
    };
    for entry in entries.flatten() {
        // The lock file and any directory read as an error — skip, as the
        // Python version did.
        let Ok(text) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for line in text.lines() {
            let field = line.split(' ').next().unwrap_or("");
            if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = field.parse::<i32>() else {
                continue;
            };
            if pid != myself && is_alive(pid) {
                return true;
            }
        }
    }
    false
}

/// `execvp`, which only ever returns when the program could not be started.
///
/// Public because [`crate::wl_sandbox`] starts programs the same way; the
/// NUL-byte handling and the `OsString` argv are not worth having twice.
pub fn exec_command(cmd: &[OsString]) -> io::Error {
    let mut owned = Vec::with_capacity(cmd.len());
    for arg in cmd {
        match CString::new(arg.as_bytes()) {
            Ok(c) => owned.push(c),
            Err(_) => {
                return io::Error::new(io::ErrorKind::InvalidInput, "argument contains a NUL byte")
            }
        }
    }
    let mut argv: Vec<*const libc::c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());
    // SAFETY: argv is NULL-terminated and every pointer in it is a valid C
    // string owned by `owned`, which outlives the call.
    unsafe { libc::execvp(argv[0], argv.as_ptr()) };
    io::Error::last_os_error()
}

/// Exit code to report for a child that has been waited for.
///
/// A child killed by a signal gives `128 + signal`, the shell convention
/// (`vpn-zone run` is started from shells and `.desktop` files, so that is the
/// number a caller will recognise). Anything else — a stopped child that
/// somehow got reported — is a plain failure.
///
/// Public because [`crate::wl_sandbox`] waits for a child too, and both layers
/// of one launch should report the same number.
pub fn exit_code_of(status: libc::c_int) -> u8 {
    if libc::WIFEXITED(status) {
        // WEXITSTATUS is already 0..=255.
        libc::WEXITSTATUS(status) as u8
    } else if libc::WIFSIGNALED(status) {
        128u8.saturating_add(libc::WTERMSIG(status) as u8)
    } else {
        1
    }
}

/// `rm -rf`, errors ignored — the caller has nothing useful to do about them
/// and the next `vpn-zone gc` sweeps up whatever is left.
fn remove_tree(path: &Path) {
    if path.as_os_str().is_empty() {
        return;
    }
    let _ = crate::sys::remove_tree(path);
}

/// For messages only: an argument may be any byte string, and a message is
/// worth more than an exact round-trip.
fn lossy(name: &OsStr) -> std::borrow::Cow<'_, str> {
    name.to_string_lossy()
}

/// Mount the profile, drop the capabilities, run the program.
///
/// Returns only when the program could not be started or when this was a
/// throwaway container (which has to be outlived and cleaned up).
pub fn run(args: Args) -> u8 {
    if !args.profile_dir.as_os_str().is_empty() {
        mount_profile(&args.profile_dir);
    }

    // Nothing below this line needs privileges.
    clear_ambient_capabilities();

    if !args.ephemeral {
        let e = exec_command(&args.cmd);
        eprintln!("cannot start {}: {e}", lossy(&args.cmd[0]));
        return EXIT_NOT_STARTED;
    }

    // --- THROWAWAY CONTAINER ---
    // `exec` is not an option here: somebody has to outlive the program and
    // take the directory away afterwards, so it is started as a child instead.
    // The mount points need no cleaning — the mount namespace dies with its
    // last process.
    //
    // Caveat: a program that daemonises itself and lets its first process exit
    // will have the directory pulled out from under it, because the wait ends
    // too early. Browsers and Electron applications do not behave that way (in
    // their own profile they stay in the foreground), but it is worth knowing.
    // SAFETY: single-threaded at this point, so the child may allocate and
    // print before it execs.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let e = exec_command(&args.cmd);
        eprintln!("cannot start {}: {e}", lossy(&args.cmd[0]));
        // _exit, not exit: the parent's atexit handlers and buffers are not
        // ours to run twice.
        unsafe { libc::_exit(EXIT_NOT_STARTED as libc::c_int) };
    }
    if pid < 0 {
        eprintln!("cannot fork: {}", io::Error::last_os_error());
        return EXIT_NOT_STARTED;
    }

    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }

    // The layer is erased for the LAST tenant only. Several programs can be
    // put into one throwaway container (`--tmp-profile --join`), and removing
    // it when the first one exits would pull the filesystem out from under the
    // others. The count comes from the shared launch registry; our own pid —
    // which survived the `exec` into this binary — is excluded.
    if others_alive(&args.regdir, std::process::id() as i32, proc_is_alive) {
        let name = args
            .profile_dir
            .file_name()
            .unwrap_or(args.profile_dir.as_os_str());
        println!(
            "throwaway container {} kept: programs are still running in it",
            lossy(name)
        );
    } else {
        remove_tree(&args.profile_dir);
        remove_tree(&args.regdir);
    }
    exit_code_of(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn slot_names_stay_one_level_deep() {
        assert_eq!(slot_name(".config"), ".config");
        assert_eq!(slot_name(".local/share"), ".local_share");
        assert_eq!(
            SUBDIRS.map(slot_name),
            [".config", ".local_share", ".cache", ".mozilla", ".pki"].map(String::from)
        );
    }

    #[test]
    fn arguments_are_split_on_the_first_separator() {
        let a = Args::parse(&argv(&[
            "/state/prof",
            "nl",
            "0",
            "/state/.running/prof",
            "--",
            "sh",
            "-c",
            "echo -- hi",
        ]))
        .unwrap();
        assert_eq!(a.profile_dir, PathBuf::from("/state/prof"));
        assert_eq!(a.zone, OsString::from("nl"));
        assert!(!a.ephemeral);
        assert_eq!(a.regdir, PathBuf::from("/state/.running/prof"));
        assert_eq!(a.cmd, argv(&["sh", "-c", "echo -- hi"]));
    }

    #[test]
    fn the_main_profile_is_an_empty_directory_argument() {
        let a = Args::parse(&argv(&["", "direct", "0", "", "--", "firefox"])).unwrap();
        assert_eq!(a.profile_dir, PathBuf::from(""));
        assert!(a.profile_dir.as_os_str().is_empty());
        assert_eq!(a.regdir, PathBuf::from(""));
        assert!(!a.ephemeral);
    }

    #[test]
    fn only_a_literal_one_means_throwaway() {
        assert!(
            Args::parse(&argv(&["/tmp/p", "nl", "1", "/r", "--", "x"]))
                .unwrap()
                .ephemeral
        );
        for not_one in ["0", "", "true", "yes"] {
            assert!(
                !Args::parse(&argv(&["/tmp/p", "nl", not_one, "/r", "--", "x"]))
                    .unwrap()
                    .ephemeral,
                "{not_one:?} must not be taken for a throwaway container"
            );
        }
    }

    #[test]
    fn trailing_arguments_may_be_omitted() {
        let a = Args::parse(&argv(&["/tmp/p", "nl", "--", "x"])).unwrap();
        assert!(!a.ephemeral);
        assert_eq!(a.regdir, PathBuf::from(""));
    }

    #[test]
    fn broken_command_lines_are_rejected() {
        assert_eq!(
            Args::parse(&argv(&["/tmp/p", "nl", "0", "/r", "firefox"])),
            Err(ArgError::NoSeparator)
        );
        assert_eq!(
            Args::parse(&argv(&["/tmp/p", "nl", "0", "/r", "--"])),
            Err(ArgError::EmptyCommand)
        );
        assert_eq!(
            Args::parse(&argv(&["/tmp/p", "--", "firefox"])),
            Err(ArgError::MissingArguments)
        );
    }

    #[test]
    fn exit_codes_follow_the_shell_convention() {
        // Hand-built wait(2) statuses: low byte 0 means "exited", and the
        // signal number lives in the low seven bits otherwise.
        assert_eq!(exit_code_of(0), 0);
        assert_eq!(exit_code_of(3 << 8), 3);
        assert_eq!(exit_code_of(libc::SIGKILL), 128 + 9);
    }

    /// A directory of the shape `vpn-zone run` writes, removed on drop.
    struct Reg {
        dir: PathBuf,
    }

    impl Reg {
        fn new(tag: &str, files: &[(&str, &str)]) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("vpn-zone-core-test-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            for (name, body) in files {
                fs::write(dir.join(name), body).unwrap();
            }
            Self { dir }
        }
    }

    impl Drop for Reg {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_live_stranger_keeps_the_container() {
        let reg = Reg::new(
            "alive",
            &[
                ("firefox", "100 nl prof\n"),
                ("telegram", "200 nl prof\n"),
                (".lock", ""),
            ],
        );
        let alive: HashSet<i32> = [200].into_iter().collect();
        assert!(others_alive(&reg.dir, 100, |pid| alive.contains(&pid)));
        // 200 is the only live one, and if it is us there is nobody else.
        assert!(!others_alive(&reg.dir, 200, |pid| alive.contains(&pid)));
    }

    #[test]
    fn dead_records_and_junk_lines_do_not_keep_the_container() {
        let reg = Reg::new(
            "dead",
            &[
                ("firefox", "100 nl prof\n101 nl prof\n"),
                // Everything that is not a decimal pid in the first field is
                // ignored, including a stray blank line.
                ("junk", "\nnot-a-pid nl prof\n1x2 nl\n  \n"),
            ],
        );
        assert!(!others_alive(&reg.dir, 999, |_| false));
        assert!(!others_alive(&reg.dir, 999, |pid| pid == 42));
    }

    #[test]
    fn a_missing_or_unnamed_registry_means_nobody_else() {
        assert!(!others_alive(Path::new(""), 1, |_| true));
        assert!(!others_alive(
            Path::new("/nonexistent/vpn-zone-core/registry"),
            1,
            |_| true
        ));
    }
}
