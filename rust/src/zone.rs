//! Zone life cycle: everything `vpn-zone@<name>.service` starts.
//!
//! A zone is a network namespace with a tunnel of its own, created and torn
//! down entirely from the user's session — no root anywhere, not to create one
//! and not to run a program in one. This module is what used to be the two
//! shell scripts of `module/default.nix` (`zoneHolder` and `zoneInit`); the
//! architecture is unchanged and every quirk their comments carried is repeated
//! here.
//!
//! ```text
//! vpn-zone-core zone-holder <name>          (systemd main process, host user)
//!  └─ fork ─ user namespace, uid 0 inside              [holder]
//!      ├─ fork ─ net + mount namespace                 [the zone itself]
//!      │           awg0, routes, its own resolv.conf, then parks forever
//!      └─ pasta --netns /proc/<zone>/ns/net            [the way out]
//! ```
//!
//! **Why this is possible without root at all** (verified on niri and KWin):
//! unprivileged user namespaces are allowed by the kernel; `/etc/subuid` hands
//! the user a range of extra uids, which is where the zone's "root" comes from
//! (`newuidmap` has `cap_setuid` for exactly this); the amneziawg kernel module
//! lets an interface be created inside such a namespace, so the tunnel is a
//! real one and not a userspace emulation; and the way out is pasta (passt),
//! the same userspace network stack rootless podman runs on.
//!
//! **The double mapping.** Inside the zone we must be uid 0: capabilities are
//! lost on `execve` when the uid is not zero (measured: with an identity
//! mapping `CapEff=0`), and then the kernel refuses to create the interface —
//! and `ip`, `awg` and `wg` are all `execve`d from here. But the user's real uid
//! is mapped a SECOND time, onto itself, so that a program entering the zone
//! through `nsenter --preserve-credentials` runs under the real uid and sees
//! `$HOME` as usual. Podman does exactly this in its keep-id mode.
//! (`docs/GOTCHAS.md` §1)
//!
//! **Why the zone is a separate process.** pasta stays in the host's network
//! and attaches to the zone from the outside through
//! `--netns /proc/<pid>/ns/net`, so the net+mount namespace has to belong to
//! another process than the one running pasta. (`docs/GOTCHAS.md` §2)
//!
//! **Kill switch.** The namespace lives exactly as long as the zone process
//! parked at the end of [`zone_main`]: when it dies the zone is gone and
//! everything that was running inside loses the network. On the systemd side
//! `KillMode=control-group` (the default) takes pasta and every program in the
//! zone down together with it.
//!
//! **No PID namespace anywhere**, and that is deliberate: `zone.pid` has to
//! name the zone process the way the HOST sees it — `vpn-zone run`/`status`
//! `nsenter` into it by that number — so `getpid()` inside the zone must be the
//! host's pid, which it is only as long as no pid namespace is created.

use std::borrow::Cow;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

use crate::config::{Endpoint, EndpointHost, Family, WgConfig};
use crate::profile::{exit_code_of, home_dir};
use crate::sys;

/// Where the zones live, below `$HOME`. The bash CLI computes the same path.
const STATE_SUBDIR: &str = ".local/state/vpn-zones";

/// Files of one zone. This set is a contract: `vpn-zone` (bash), the desktop
/// picker and the smoke test all read them by these names.
const CONFIG: &str = "config.conf";
const OFFLINE: &str = "offline";
const PID: &str = "zone.pid";
const READY: &str = "ready";
const STATUS: &str = "status";
const STATUS_TMP: &str = "status.tmp";
const RESOLV: &str = "resolv.conf";
/// The config with the wg-quick directives taken out, i.e. what `setconf` gets.
const STRIPPED: &str = ".stripped.conf";

/// The tunnel is always called `awg0`, whichever kernel module carries it:
/// `vpn-zone status`, `vpn-zone check` and the smoke test look for that name.
const TUN_IFACE: &str = "awg0";
/// Name of pasta's interface inside the zone. Given explicitly because pasta
/// otherwise copies the name of the host's outbound interface — and if the host
/// is itself under a VPN and that interface is called `awg0`, the name would
/// collide with the zone's own tunnel. (`docs/GOTCHAS.md` §2)
const PASTA_IFACE: &str = "hostif";
/// wg-quick's default, used when the config carries no `MTU`.
const DEFAULT_MTU: u32 = 1420;
/// Resolvers for a config without `DNS=`: public ones, reached through the
/// tunnel. (`docs/GOTCHAS.md` §3)
const DEFAULT_RESOLVERS: [&str; 2] = ["1.1.1.1", "9.9.9.9"];

/// Waiting is done in 0.1 s steps, 50 of them — five seconds, as in bash.
const WAIT_STEPS: u32 = 50;
const WAIT_STEP: Duration = Duration::from_millis(100);
/// How often the tunnel state is mirrored into the `status` file. Five seconds
/// is the compromise the bash version settled on: the handshake shows up almost
/// at once and the load is nil.
const STATUS_PERIOD: Duration = Duration::from_secs(5);
/// When to report the first handshake to the journal.
const HANDSHAKE_AFTER: Duration = Duration::from_secs(4);

/// Handshake bytes between the holder and its user-namespace child.
const SYNC_OK: u8 = b'1';
const SYNC_FAIL: u8 = b'0';

/// Absolute paths of the tools the zone drives. Absolute because part of this
/// code runs inside a namespace where `PATH` can be anything; Nix substitutes
/// them into the unit's `ExecStart`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    pub ip: PathBuf,
    pub awg: PathBuf,
    pub wg: PathBuf,
    pub pasta: PathBuf,
}

impl Default for Tools {
    /// Bare names, i.e. "find them on `PATH`". Only used when a flag was left
    /// out — running the holder by hand, out of a `nix-shell`.
    fn default() -> Self {
        Self {
            ip: PathBuf::from("ip"),
            awg: PathBuf::from("awg"),
            wg: PathBuf::from("wg"),
            pasta: PathBuf::from("pasta"),
        }
    }
}

/// What `zone-holder` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Name of the zone, i.e. the directory below the state directory. An
    /// `OsString` because it is part of a path.
    pub name: OsString,
    pub tools: Tools,
}

/// Everything that can be wrong with the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// No zone name, or an empty one.
    MissingName,
    /// A `--tool` flag without its path.
    MissingValue(String),
    UnknownFlag(String),
    /// More than one zone name. Almost always a quoting accident.
    ExtraArguments,
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingName => write!(f, "need a zone name"),
            Self::MissingValue(flag) => write!(f, "{flag} needs a path"),
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
            Self::ExtraArguments => write!(f, "only one zone name is accepted"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parse `[--ip P] [--awg P] [--wg P] [--pasta P] <name>`.
    ///
    /// Only `--`-prefixed words are flags, so a zone name is free to start with
    /// a single dash. The order does not matter, but the unit puts the tool
    /// paths first and `%i` last.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let mut tools = Tools::default();
        let mut name: Option<OsString> = None;
        let mut rest = argv.iter();

        while let Some(arg) = rest.next() {
            if !arg.as_bytes().starts_with(b"--") {
                if name.is_some() {
                    return Err(ArgError::ExtraArguments);
                }
                name = Some(arg.clone());
                continue;
            }
            let flag = arg.to_string_lossy().into_owned();
            let slot = match flag.as_str() {
                "--ip" => &mut tools.ip,
                "--awg" => &mut tools.awg,
                "--wg" => &mut tools.wg,
                "--pasta" => &mut tools.pasta,
                _ => return Err(ArgError::UnknownFlag(flag)),
            };
            let value = rest
                .next()
                .ok_or_else(|| ArgError::MissingValue(flag.clone()))?;
            *slot = PathBuf::from(value);
        }

        let name = name
            .filter(|n| !n.is_empty())
            .ok_or(ArgError::MissingName)?;
        Ok(Self { name, tools })
    }
}

/// One zone: its name, its directory and the tools it drives.
struct Zone {
    name: OsString,
    dir: PathBuf,
    tools: Tools,
}

impl Zone {
    /// For messages only — a directory name may be any byte string.
    fn name(&self) -> Cow<'_, str> {
        self.name.to_string_lossy()
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    /// A zone with this marker has no network at all: no tunnel, no pasta, just
    /// loopback. That is what makes "no internet until it is explicitly given"
    /// possible — the program runs, but a route out does not physically exist.
    /// (`docs/GOTCHAS.md` §2)
    fn is_offline(&self) -> bool {
        self.path(OFFLINE).exists()
    }

    /// `ip …`, with the tool's own diagnostics passed through to the journal.
    fn ip(&self, args: &[&str]) -> Result<(), String> {
        run_tool(&self.tools.ip, args, false)
    }

    /// `ip … 2>/dev/null`: for the calls whose failure is expected and handled.
    fn ip_quiet(&self, args: &[&str]) -> Result<(), String> {
        run_tool(&self.tools.ip, args, true)
    }

    /// First line of `ip …` output, empty if the call failed.
    fn ip_line(&self, args: &[&str]) -> String {
        tool_output(&self.tools.ip, args)
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }
}

/// Run the holder. Returns the exit code for the process.
pub fn run(args: Args) -> u8 {
    let Some(home) = home_dir() else {
        eprintln!("zone-holder: no $HOME and no passwd entry — cannot find the zone directory");
        return 1;
    };
    let zone = Zone {
        dir: home.join(STATE_SUBDIR).join(&args.name),
        name: args.name,
        tools: args.tools,
    };

    // A directory is a zone if it has a config or the offline marker; anything
    // else is a typo, and starting a namespace for it would only confuse.
    if !zone.path(CONFIG).exists() && !zone.is_offline() {
        eprintln!(
            "zone {}: neither {} nor an offline marker",
            zone.name(),
            zone.path(CONFIG).display()
        );
        return 1;
    }
    // Leftovers of a previous run would make `vpn-zone up` and the picker
    // believe this zone is already up.
    let _ = fs::remove_file(zone.path(PID));
    let _ = fs::remove_file(zone.path(READY));

    let ids = match Ids::current() {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("zone {}: {e}", zone.name());
            return 1;
        }
    };

    match hold(&zone, &ids) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zone {}: {e}", zone.name());
            1
        }
    }
}

// --- THE DOUBLE MAPPING ------------------------------------------------------

/// The ids the mapping is built from.
struct Ids {
    uid: u32,
    gid: u32,
    /// First range of `/etc/subuid` for this user: the zone's uid 0 comes from
    /// its beginning.
    subuid: u64,
    subgid: u64,
}

impl Ids {
    fn current() -> Result<Self, String> {
        // SAFETY: getuid/getgid take no arguments and cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let user =
            user_name(uid).ok_or_else(|| "no passwd entry for the current uid".to_string())?;
        Ok(Self {
            uid,
            gid,
            subuid: first_subid("/etc/subuid", &user, uid)?,
            subgid: first_subid("/etc/subgid", &user, gid)?,
        })
    }
}

fn user_name(uid: libc::uid_t) -> Option<String> {
    // SAFETY: getpwuid returns a pointer into a static buffer, read here before
    // anything else can call into the passwd machinery again.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_name.is_null() {
            return None;
        }
        Some(CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

/// Start of the first range belonging to this user.
///
/// Without a range a rootless zone is impossible in principle, so this is
/// checked explicitly and said out loud rather than left to a confusing
/// `newuidmap` failure. (`docs/GOTCHAS.md` §1)
fn first_subid(file: &str, user: &str, id: u32) -> Result<u64, String> {
    let text = fs::read_to_string(file).map_err(|e| format!("cannot read {file}: {e}"))?;
    for line in text.lines() {
        let mut fields = line.split(':');
        let (Some(owner), Some(start)) = (fields.next(), fields.next()) else {
            continue;
        };
        // shadow accepts the login name or the numeric id in the first field.
        let owner = owner.trim();
        if owner != user && !owner.parse::<u32>().is_ok_and(|o| o == id) {
            continue;
        }
        return start
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{file}: the range of {user} does not start with a number"));
    }
    Err(format!(
        "no range for {user} in {file} — a rootless zone is impossible without one"
    ))
}

/// Write the two ranges into the child's namespace.
///
/// `newuidmap`/`newgidmap` are looked up on `PATH` on purpose: on NixOS the
/// setuid wrappers live in `/run/wrappers/bin`, on a Debian-ish CI runner in
/// `/usr/bin` — hardcoding either would break the other. util-linux's `unshare`
/// (what this replaces) did the same `execvp`.
fn map_ids(pid: libc::pid_t, ids: &Ids) -> Result<(), String> {
    map_range("newuidmap", pid, ids.subuid, ids.uid)?;
    map_range("newgidmap", pid, ids.subgid, ids.gid)
}

fn map_range(tool: &str, pid: libc::pid_t, sub: u64, id: u32) -> Result<(), String> {
    // <pid> <inside> <outside> <count> …: uid 0 inside comes from the subuid
    // range, and the real uid is mapped onto itself.
    let status = Command::new(tool)
        .args([
            pid.to_string(),
            "0".to_string(),
            sub.to_string(),
            "1".to_string(),
            id.to_string(),
            id.to_string(),
            "1".to_string(),
        ])
        .status()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                format!("{tool} is not on PATH (package uidmap) — a rootless zone needs it")
            } else {
                format!("cannot run {tool}: {e}")
            }
        })?;
    if !status.success() {
        return Err(format!(
            "{tool} failed ({status}) — check your ranges in /etc/subuid and /etc/subgid"
        ));
    }
    Ok(())
}

// --- PROCESS 1: THE HOLDER ---------------------------------------------------

/// The user-namespace child, so that a signal can be passed on to it.
static USERNS_CHILD: AtomicI32 = AtomicI32::new(0);
/// The zone process and pasta, from the point of view of the holder.
static ZONE_CHILD: AtomicI32 = AtomicI32::new(0);
static PASTA_CHILD: AtomicI32 = AtomicI32::new(0);
/// Did the shutdown start with a TERM/INT of our own?
static ASKED_TO_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn forward_signal(sig: libc::c_int) {
    ASKED_TO_STOP.store(true, Ordering::SeqCst);
    let pid = USERNS_CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe and takes no pointers.
        unsafe { libc::kill(pid, sig) };
    }
}

extern "C" fn stop_zone(_sig: libc::c_int) {
    ASKED_TO_STOP.store(true, Ordering::SeqCst);
    for slot in [&PASTA_CHILD, &ZONE_CHILD] {
        let pid = slot.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: as above.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }
}

/// A zone taken down on request exited cleanly, whatever the signal did to the
/// exit status.
///
/// Without this `systemctl --user stop vpn-zone@x` would leave the unit in the
/// `failed` state: the zone process dies of SIGTERM, which turns into the exit
/// code 143, and systemd counts only a *signalled* main process as a clean
/// stop. A zone that died on its own still reports its real code — that is the
/// difference worth keeping.
fn stopped_cleanly(code: u8) -> u8 {
    if ASKED_TO_STOP.load(Ordering::SeqCst) {
        0
    } else {
        code
    }
}

fn on_term_and_int(handler: extern "C" fn(libc::c_int)) {
    let handler = handler as libc::sighandler_t;
    // SAFETY: signal(2) with a plain function pointer; the handlers only touch
    // atomics and call kill(2).
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

fn default_signals() {
    // SAFETY: as above; SIG_DFL is the disposition every child starts from.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
}

/// Fork off the user namespace, map the ids into it from the outside, wait.
///
/// The mapping has to be written by a process that is still in the PARENT
/// namespace and can execute the setuid helpers, which is why this dance exists
/// at all: the child unshares and blocks, we map, the child carries on.
fn hold(zone: &Zone, ids: &Ids) -> Result<u8, String> {
    let (unshared_r, unshared_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;
    let (mapped_r, mapped_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;

    // SAFETY: single-threaded at this point, so the child may allocate and
    // print before it goes its own way.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("cannot fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(unshared_r);
        drop(mapped_w);
        let code = holder(zone, unshared_w, mapped_r);
        // _exit, not exit: the parent's atexit handlers and buffers are not
        // ours to run twice.
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(code)) };
    }
    drop(unshared_w);
    drop(mapped_r);
    USERNS_CHILD.store(pid, Ordering::SeqCst);
    // systemd stops the unit by signalling THIS process; without passing it on,
    // the zone would survive its own holder.
    on_term_and_int(forward_signal);

    let mut byte = [0u8; 1];
    let mut unshared = File::from(unshared_r);
    if unshared.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
        let _ = reap(pid);
        return Err("the zone could not get a user namespace of its own".to_string());
    }

    if let Err(e) = map_ids(pid, ids) {
        // Dropping the write end is the child's signal to give up.
        drop(mapped_w);
        let _ = reap(pid);
        return Err(e);
    }
    let mut mapped = File::from(mapped_w);
    if mapped.write_all(&[SYNC_OK]).is_err() {
        let _ = reap(pid);
        return Err("the zone stopped listening before the mapping was done".to_string());
    }
    drop(mapped);

    Ok(stopped_cleanly(reap(pid)))
}

/// Wait for a child, retrying on `EINTR` (our own signal handlers cause it).
fn reap(pid: libc::pid_t) -> u8 {
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    exit_code_of(status)
}

// --- PROCESS 2: INSIDE THE USER NAMESPACE ------------------------------------

/// Create the user namespace, wait for the mapping, become uid 0, supervise.
fn holder(zone: &Zone, unshared_w: OwnedFd, mapped_r: OwnedFd) -> u8 {
    // The parent's handlers are meaningless here (they name the parent's
    // child), and the zone process forked below inherits whatever we have.
    default_signals();

    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        eprintln!(
            "zone {}: cannot create a user namespace ({}) — unprivileged user namespaces \
             are probably disabled in the kernel",
            zone.name(),
            io::Error::last_os_error()
        );
        let mut unshared = File::from(unshared_w);
        let _ = unshared.write_all(&[SYNC_FAIL]);
        return 1;
    }
    let mut unshared = File::from(unshared_w);
    if unshared.write_all(&[SYNC_OK]).is_err() {
        return 1;
    }
    drop(unshared);

    let mut byte = [0u8; 1];
    let mut mapped = File::from(mapped_r);
    if mapped.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
        // The parent has already said what went wrong.
        return 1;
    }
    drop(mapped);

    // uid 0 inside: without it `ip`/`awg` lose their capabilities on execve and
    // the kernel refuses to create the interface. Group first, as always.
    // SAFETY: both take no pointers; we hold every capability in the namespace
    // we have just created.
    if unsafe { libc::setgid(0) } != 0 || unsafe { libc::setuid(0) } != 0 {
        eprintln!(
            "zone {}: cannot become uid 0 inside the namespace ({})",
            zone.name(),
            io::Error::last_os_error()
        );
        return 1;
    }

    match supervise(zone) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zone {}: {e}", zone.name());
            1
        }
    }
}

/// Start the zone process and pasta, then live exactly as long as the zone.
fn supervise(zone: &Zone) -> Result<u8, String> {
    // SAFETY: single-threaded at this point (the status mirror thread is
    // started by the child, after the fork).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("cannot fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        let code = zone_main(zone);
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(code)) };
    }
    ZONE_CHILD.store(pid, Ordering::SeqCst);

    // The pid file appears right after the zone has its namespaces, so waiting
    // for it is also the barrier pasta needs: there is nothing to attach to
    // before that. The number in it is this very pid — no pid namespace is
    // created anywhere — and pasta is given the one we know first-hand.
    if !wait_for_file(&zone.path(PID)) {
        // SAFETY: kill(2) takes no pointers.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let _ = reap(pid);
        return Err("the zone process did not start".to_string());
    }

    // A zone without a network needs no pasta — that is the whole point of it.
    let mut pasta: Option<Child> = None;
    if !zone.is_offline() {
        let netns = format!("/proc/{pid}/ns/net");
        match Command::new(&zone.tools.pasta)
            .arg("--netns")
            .arg(&netns)
            .args(["--config-net", "-I", PASTA_IFACE, "-f"])
            .spawn()
        {
            Ok(child) => {
                println!("zone {}: pasta started (pid {})", zone.name(), child.id());
                // Diagnostics: two seconds in, is pasta alive and in OUR zone's
                // netns? passt logs to syslog off a terminal, so this is the
                // only way to hear it.
                let (zone_pid, pasta_pid) = (pid, child.id() as i32);
                thread::sleep(Duration::from_secs(2));
                let ns = |p: i32| match fs::read_link(format!("/proc/{p}/ns/net")) {
                    Ok(l) => l.to_string_lossy().into_owned(),
                    Err(e) => format!("<{e}>"),
                };
                eprintln!(
                    "diag: zone pid {zone_pid} netns {}; pasta pid {pasta_pid} netns {}; pasta alive: {}",
                    ns(zone_pid),
                    ns(pasta_pid),
                    Path::new(&format!("/proc/{pasta_pid}")).exists()
                );
                PASTA_CHILD.store(child.id() as i32, Ordering::SeqCst);
                pasta = Some(child);
            }
            Err(e) => eprintln!(
                "zone {}: cannot start pasta ({e}) — the zone will have no way out",
                zone.name()
            ),
        }
    }

    // From here on TERM/INT means "tear the zone down", the trap the bash
    // holder had.
    on_term_and_int(stop_zone);
    let code = reap(pid);

    // pasta must not outlive the zone it serves: a stray one would keep an
    // interface on a dead namespace and `vpn-zone gc` would have to clean up
    // after us.
    if let Some(mut child) = pasta {
        // SAFETY: kill(2) takes no pointers; the pid is still ours to signal
        // because the child has not been waited for yet.
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        let _ = child.wait();
    }
    Ok(stopped_cleanly(code))
}

// --- PROCESS 3: THE ZONE ITSELF ----------------------------------------------

/// The zone process: its namespaces, its tunnel, and then forever.
fn zone_main(zone: &Zone) -> u8 {
    default_signals();
    if let Err(e) = zone_setup(zone) {
        eprintln!("zone {}: {e}", zone.name());
        return 1;
    }
    park()
}

/// Hold the namespaces until somebody kills us. The zone dies with this
/// process, which is exactly what makes it a kill switch.
fn park() -> ! {
    loop {
        // SAFETY: pause(2) takes no arguments; TERM and INT are left at their
        // default action, so this really is "until killed".
        unsafe { libc::pause() };
    }
}

fn zone_setup(zone: &Zone) -> Result<(), String> {
    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "cannot create the net+mount namespace: {}",
            io::Error::last_os_error()
        ));
    }
    // Private propagation, or every mount below (resolv.conf, the tmpfs over
    // nscd) would travel back to the host.
    sys::mount(
        OsStr::new("none"),
        Path::new("/"),
        "",
        libc::MS_REC | libc::MS_PRIVATE,
        "",
    )
    .map_err(|e| format!("cannot make the mount tree private: {e}"))?;

    // Only now: the file's appearance means "the namespaces exist".
    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let pid = unsafe { libc::getpid() };
    fs::write(zone.path(PID), format!("{pid}\n"))
        .map_err(|e| format!("cannot write {PID}: {e}"))?;

    if zone.is_offline() {
        zone.ip(&["link", "set", "lo", "up"])?;
        touch(&zone.path(READY)).map_err(|e| format!("cannot create {READY}: {e}"))?;
        println!("zone {}: no network (loopback only)", zone.name());
        return Ok(());
    }

    // Wait for pasta to configure the way out: until it has, there is no route
    // at all and nowhere to hang the route to the endpoint on.
    wait_for_default_route(zone);
    let out = default_route(zone, Family::V4);
    let Some(outif) = out.dev else {
        // The dump tells apart "pasta never attached" (lo only) from "attached
        // but configured differently" (a tap exists, the routes do not).
        for what in [
            ["-o", "link", "show"],
            ["-4", "addr", "show"],
            ["-4", "route", "show"],
        ] {
            eprintln!(
                "zone {}: ip {}:\n{}",
                zone.name(),
                what.join(" "),
                zone.ip_line(&what)
            );
        }
        return Err("pasta gave us no route out".to_string());
    };

    let raw = fs::read(zone.path(CONFIG)).map_err(|e| format!("cannot read {CONFIG}: {e}"))?;
    let cfg = WgConfig::parse(&raw).map_err(|e| format!("{CONFIG}: {e}"))?;
    if !cfg.dropped_empty.is_empty() {
        // Recent Amnezia writes junk-packet parameters and fills only some of
        // them; `setconf` rejects the whole file on such a line. Dropping them
        // is what keeps the zone coming up at all, so say which ones went.
        let keys: Vec<&str> = cfg.dropped_empty.iter().map(|d| d.key.as_str()).collect();
        println!(
            "zone {}: dropped empty config lines: {}",
            zone.name(),
            keys.join(", ")
        );
    }
    // `setconf` understands protocol keys only, so it gets a stripped copy.
    // 0600: it carries the private key.
    let stripped = zone.path(STRIPPED);
    write_private(&stripped, cfg.to_setconf().as_bytes())
        .map_err(|e| format!("cannot write {STRIPPED}: {e}"))?;

    // --- THE ROUTE TO THE VPN SERVER ITSELF ---
    // It has to go AROUND the tunnel, or the tunnel's own packets would be
    // wrapped into the tunnel. The name is resolved here, while the zone still
    // uses the host's resolver. The error is never swallowed: without this
    // route the zone simply does not work.
    let mut endpoint_v6 = false;
    match cfg.endpoint() {
        None => eprintln!(
            "zone {}: no Endpoint in the config — no route to the server",
            zone.name()
        ),
        Some(ep) => match resolve_endpoint(&ep) {
            None => eprintln!(
                "zone {}: cannot resolve the endpoint {} — no route to the server",
                zone.name(),
                ep.raw
            ),
            Some(IpAddr::V6(addr)) => {
                endpoint_v6 = true;
                route_to_endpoint_v6(zone, addr);
            }
            Some(IpAddr::V4(addr)) => {
                let dest = format!("{addr}/32");
                let (dest, outif) = (dest.as_str(), outif.as_str());
                let added = match out.via.as_deref() {
                    Some(gw) => zone.ip(&["route", "add", dest, "via", gw, "dev", outif]),
                    None => zone.ip(&["route", "add", dest, "dev", outif, "scope", "link"]),
                };
                if added.is_err() {
                    eprintln!(
                        "zone {}: could not add the route to {addr} through {outif}",
                        zone.name()
                    );
                }
            }
        },
    }

    // --- THE TUNNEL ---
    // The ordinary path is the kernel amneziawg module (it understands plain
    // WireGuard configs too). No module (a system without Amnezia, CI): a
    // config WITHOUT obfuscation parameters is carried by the in-tree wireguard
    // module and `wg`; with them we fail loudly — such a tunnel cannot be built
    // without the module, and degrading silently would be a lie.
    let wgtool: &Path = if zone
        .ip_quiet(&["link", "add", TUN_IFACE, "type", "amneziawg"])
        .is_ok()
    {
        zone.tools.awg.as_path()
    } else {
        if cfg.is_obfuscated() {
            return Err(
                "the amneziawg module is unavailable and an obfuscated config cannot be \
                 carried without it"
                    .to_string(),
            );
        }
        zone.ip(&["link", "add", TUN_IFACE, "type", "wireguard"])?;
        println!(
            "zone {}: no amneziawg module — using the in-tree wireguard",
            zone.name()
        );
        zone.tools.wg.as_path()
    };
    // Not through `run_tool`: the path of the stripped config is a path, and
    // squeezing it through a `&str` would mangle a `$HOME` that is not UTF-8.
    let setconf = Command::new(wgtool)
        .arg("setconf")
        .arg(TUN_IFACE)
        .arg(&stripped)
        .status()
        .map_err(|e| format!("cannot run {}: {e}", wgtool.display()))?;
    if !setconf.success() {
        return Err(format!("{} setconf failed ({setconf})", wgtool.display()));
    }

    // Every address, both families: a v6-only `Address` used to kill the zone
    // on `ip -4 addr add`, and a v6 address in a mixed list used to be dropped
    // silently — which is an IPv6 leak.
    let mut tunnel_v6 = false;
    for addr in cfg.addresses() {
        let raw = addr.raw.as_str();
        match addr.family {
            Family::V6 => {
                if zone
                    .ip_quiet(&["-6", "addr", "add", raw, "dev", TUN_IFACE])
                    .is_ok()
                {
                    tunnel_v6 = true;
                } else {
                    eprintln!(
                        "zone {}: the v6 address {} did not apply — IPv6 will be closed here",
                        zone.name(),
                        addr.raw
                    );
                }
            }
            Family::V4 => zone.ip(&["-4", "addr", "add", raw, "dev", TUN_IFACE])?,
        }
    }
    let mtu = cfg.mtu().unwrap_or(DEFAULT_MTU).to_string();
    zone.ip(&["link", "set", TUN_IFACE, "mtu", mtu.as_str(), "up"])?;
    zone.ip(&["route", "replace", "default", "dev", TUN_IFACE])?;

    // --- IPv6: EITHER THROUGH THE TUNNEL OR OFF ---
    // The principle is that a packet of ANY family must have no path around the
    // tunnel (docs/LEAK-MODEL.md). pasta gives the zone v6 connectivity to the
    // host as well, and only the v4 default used to be redirected — so all IPv6
    // traffic of the zone's programs went around the VPN. Fail-closed in every
    // branch; the programs cannot bring it back, they enter the zone without
    // capabilities.
    match v6_plan(
        Path::new("/proc/net/if_inet6").exists(),
        tunnel_v6,
        endpoint_v6,
    ) {
        V6Plan::NoKernel => {}
        V6Plan::IntoTunnel => zone.ip(&["-6", "route", "replace", "default", "dev", TUN_IFACE])?,
        V6Plan::CloseDefault => {
            // The tunnel's own transport runs over v6, so the family cannot be
            // switched off. Only the default goes: the /128 to the server is
            // more specific and stays, everything else has nowhere to go.
            if zone
                .ip(&["-6", "route", "replace", "default", "unreachable"])
                .is_err()
            {
                eprintln!(
                    "zone {}: could not close the v6 default — a v6 leak is possible",
                    zone.name()
                );
            }
        }
        V6Plan::Disable => {
            // Per-netns sysctl, the host is untouched; if even that fails, an
            // unreachable default is the fallback.
            if fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1").is_err()
                && zone
                    .ip_quiet(&["-6", "route", "replace", "default", "unreachable"])
                    .is_err()
            {
                eprintln!(
                    "zone {}: could not switch IPv6 off — a leak around the tunnel is possible",
                    zone.name()
                );
            }
        }
    }

    hide_nscd(zone);

    // --- THE ZONE'S DNS ---
    // Without this the queries would go to the host's resolver around the
    // tunnel — the most common leak of all. The bind mount is visible inside
    // the zone only: the rest of the system keeps its own /etc/resolv.conf.
    let (text, defaulted) = resolv_conf(&cfg.dns());
    if defaulted {
        println!(
            "zone {}: no DNS= in the config — taking {} (through the tunnel)",
            zone.name(),
            DEFAULT_RESOLVERS.join(" and ")
        );
    }
    let resolv = zone.path(RESOLV);
    fs::write(&resolv, &text).map_err(|e| format!("cannot write {RESOLV}: {e}"))?;
    sys::mount(
        resolv.as_os_str(),
        Path::new("/etc/resolv.conf"),
        "",
        libc::MS_BIND,
        "",
    )
    .map_err(|e| format!("cannot bind-mount {RESOLV} over /etc/resolv.conf: {e}"))?;

    // THE PROFILE IS NOT MOUNTED HERE, AND THAT MATTERS. The first version
    // stacked the data layer right here, over the whole zone — and the profile
    // ended up welded to the VPN: set a browser up in zone "nl", have the
    // server blocked, and the environment goes away with it. The profile is now
    // a separate thing, mounted when the program starts (`crate::profile`), so
    // the same one can be used in another zone or with no VPN at all.
    touch(&zone.path(READY)).map_err(|e| format!("cannot create {READY}: {e}"))?;
    println!(
        "zone {} is up: {}",
        zone.name(),
        zone.ip_line(&["-br", "-4", "addr", "show", TUN_IFACE])
    );

    start_status_mirror(zone, wgtool);

    // The first handshake is the sign that a config is alive — printing it to
    // the journal answers "is this .conf still worth anything?" straight away.
    thread::sleep(HANDSHAKE_AFTER);
    let handshakes =
        tool_output(wgtool, &["show", TUN_IFACE, "latest-handshakes"]).unwrap_or_default();
    if handshake_seen(&handshakes) {
        println!("zone {}: handshake done — the tunnel is alive", zone.name());
    } else {
        eprintln!(
            "zone {}: no handshake. Either the config is dead or the server is unreachable",
            zone.name()
        );
    }
    Ok(())
}

/// Mirror `awg show` / `wg show` into the zone's `status` file.
///
/// `show` needs netlink privileges, and programs (and `vpn-zone status`) enter
/// the zone under the ordinary uid and see nothing at all — so the state is
/// written from in here, where the privileges are. The rename is what makes a
/// reader see either the old file or the new one, never half of one.
/// (`docs/GOTCHAS.md` §4)
fn start_status_mirror(zone: &Zone, wgtool: &Path) {
    let tool = wgtool.to_path_buf();
    let status = zone.path(STATUS);
    let tmp = zone.path(STATUS_TMP);
    thread::spawn(move || loop {
        if let Ok(text) = tool_output(&tool, &["show", TUN_IFACE]) {
            if fs::write(&tmp, text).is_ok() {
                let _ = fs::rename(&tmp, &status);
            }
        }
        thread::sleep(STATUS_PERIOD);
    });
}

/// Close the host's caching resolver off from the zone.
///
/// This is not theory: NixOS runs nsncd (socket `/run/nscd/socket`) and glibc
/// asks it for names instead of the servers in resolv.conf. The daemon lives in
/// the HOST's network, so names inside the zone used to be resolved around the
/// tunnel — verified on a live zone, where `getent` answered while awg0 still
/// had RX=0. A classic DNS leak, and swapping resolv.conf does not cure it.
///
/// A tmpfs over the directory hides the socket inside the zone only: glibc does
/// not find it and goes straight to the servers in resolv.conf, i.e. through
/// the tunnel. For the rest of the system nsncd keeps working as before.
/// (`docs/GOTCHAS.md` §3)
fn hide_nscd(zone: &Zone) {
    for dir in ["/run/nscd", "/var/run/nscd"] {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        if let Err(e) = sys::mount(OsStr::new("tmpfs"), path, "tmpfs", 0, "mode=0755,size=64k") {
            eprintln!(
                "zone {}: could not hide {dir} ({e}) — a DNS leak is possible",
                zone.name()
            );
        }
        break;
    }
}

fn route_to_endpoint_v6(zone: &Zone, addr: std::net::Ipv6Addr) {
    // The v6 default from pasta exists only if the host itself has v6.
    let out = default_route(zone, Family::V6);
    let Some(dev) = out.dev else {
        eprintln!(
            "zone {}: the endpoint is IPv6 but there is no v6 route out — the tunnel will \
             not work",
            zone.name()
        );
        return;
    };
    let dest = format!("{addr}/128");
    let (dest, dev) = (dest.as_str(), dev.as_str());
    let added = match out.via.as_deref() {
        Some(gw) => zone.ip(&["-6", "route", "add", dest, "via", gw, "dev", dev]),
        None => zone.ip(&["-6", "route", "add", dest, "dev", dev]),
    };
    if added.is_err() {
        eprintln!("zone {}: could not add the v6 route to {addr}", zone.name());
    }
}

// --- PURE HELPERS (the testable half) ----------------------------------------

/// The `dev`/`via` of a default route.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultRoute {
    pub dev: Option<String>,
    pub via: Option<String>,
}

/// Read a route line BY KEYWORD, never by field number.
///
/// pasta's default route looks like `default dev hostif scope link` (no via),
/// an ordinary network's like `default via 192.168.1.1 dev enp4s0 …`. Positional
/// parsing picked up the word "link" instead of the interface name in the second
/// case — verified, and the route to the VPN server was then never added at all.
/// (`docs/GOTCHAS.md` §2)
pub fn parse_default_route(line: &str) -> DefaultRoute {
    let mut route = DefaultRoute::default();
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == "dev" && route.dev.is_none() {
            route.dev = words.next().map(str::to_string);
        } else if word == "via" && route.via.is_none() {
            route.via = words.next().map(str::to_string);
        }
    }
    route
}

/// What to do about IPv6, as a pure decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V6Plan {
    /// A kernel without IPv6 at all: nothing to close.
    NoKernel,
    /// The tunnel carries v6, so the v6 default goes into it.
    IntoTunnel,
    /// The tunnel's transport is itself IPv6: the family has to stay, only the
    /// default route is closed.
    CloseDefault,
    /// No v6 in the tunnel and none needed for the transport: IPv6 goes.
    Disable,
}

pub fn v6_plan(kernel_has_v6: bool, tunnel_has_v6: bool, endpoint_is_v6: bool) -> V6Plan {
    if !kernel_has_v6 {
        V6Plan::NoKernel
    } else if tunnel_has_v6 {
        V6Plan::IntoTunnel
    } else if endpoint_is_v6 {
        V6Plan::CloseDefault
    } else {
        V6Plan::Disable
    }
}

/// The zone's `/etc/resolv.conf` and whether the default had to be used.
///
/// A config without `DNS=` used to leave the zone with the host's resolv.conf,
/// where the resolver is a local one (192.168.1.1, or the 127.0.0.53 stub) that
/// cannot be reached from inside: names simply stopped resolving, and it looked
/// like "there is internet but nothing opens". (`docs/GOTCHAS.md` §3)
pub fn resolv_conf(dns: &[String]) -> (String, bool) {
    let mut servers: Vec<&str> = dns
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    let defaulted = servers.is_empty();
    if defaulted {
        servers = DEFAULT_RESOLVERS.to_vec();
    }
    let mut text = String::new();
    for server in servers {
        text.push_str("nameserver ");
        text.push_str(server);
        text.push('\n');
    }
    (text, defaulted)
}

/// Host of an endpoint: an address we already have, or a name to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHostKind {
    Literal(IpAddr),
    Name(String),
}

/// Tell a literal from a name.
///
/// The distinction is the parser's ([`crate::config::Endpoint`]), which makes it
/// by counting colons and never by "does it contain letters" — hex digits are
/// letters too, and that test used to send v6 endpoints down the hostname path.
pub fn endpoint_host_kind(endpoint: &Endpoint) -> EndpointHostKind {
    match &endpoint.host {
        EndpointHost::V4(addr) => EndpointHostKind::Literal(IpAddr::V4(*addr)),
        EndpointHost::V6(addr) => EndpointHostKind::Literal(IpAddr::V6(*addr)),
        EndpointHost::Name(name) => EndpointHostKind::Name(name.clone()),
    }
}

/// Address of the endpoint, resolving the name if there is one.
///
/// v4 first and v6 only if there is no v4 — the order `getent ahostsv4` then
/// `ahostsv6` gave. This has to happen before the tunnel exists, while the
/// resolver is still the host's.
fn resolve_endpoint(endpoint: &Endpoint) -> Option<IpAddr> {
    match endpoint_host_kind(endpoint) {
        EndpointHostKind::Literal(addr) => Some(addr),
        EndpointHostKind::Name(name) => {
            let port = endpoint.port.unwrap_or(0);
            let addrs: Vec<IpAddr> = (name.as_str(), port)
                .to_socket_addrs()
                .ok()?
                .map(|a| a.ip())
                .collect();
            addrs
                .iter()
                .copied()
                .find(IpAddr::is_ipv4)
                .or_else(|| addrs.first().copied())
        }
    }
}

/// Has the peer ever answered? `wg show <if> latest-handshakes` prints
/// `<peer>\t<unix seconds>`, and a zero means "never".
///
/// Deliberately different from the bash version, which piped this into
/// `awk '{exit ($2>0)?0:1}'`: on EMPTY input awk exits 0, so a failing `show`
/// was reported as a successful handshake. Nothing reads this but a human
/// looking at the journal, and a human should not be told a dead tunnel is
/// alive.
pub fn handshake_seen(text: &str) -> bool {
    text.lines().filter(|l| !l.trim().is_empty()).any(|line| {
        line.split_whitespace()
            .nth(1)
            .and_then(|f| f.parse::<u64>().ok())
            .is_some_and(|seconds| seconds > 0)
    })
}

// --- SMALL PLUMBING ----------------------------------------------------------

fn run_tool(tool: &Path, args: &[&str], quiet: bool) -> Result<(), String> {
    let status = Command::new(tool)
        .args(args)
        .stderr(if quiet {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .status()
        .map_err(|e| format!("cannot run {}: {e}", tool.display()))?;
    if !status.success() {
        return Err(format!(
            "{} {} failed ({status})",
            tool.display(),
            args.join(" ")
        ));
    }
    Ok(())
}

fn tool_output(tool: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(tool)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run {}: {e}", tool.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} {} failed ({})",
            tool.display(),
            args.join(" "),
            out.status
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn wait_for_default_route(zone: &Zone) {
    for _ in 0..WAIT_STEPS {
        if !zone.ip_line(&["-4", "route", "show", "default"]).is_empty() {
            return;
        }
        thread::sleep(WAIT_STEP);
    }
}

fn default_route(zone: &Zone, family: Family) -> DefaultRoute {
    let family = match family {
        Family::V4 => "-4",
        Family::V6 => "-6",
    };
    parse_default_route(&zone.ip_line(&["-o", family, "route", "show", "default"]))
}

fn wait_for_file(path: &Path) -> bool {
    for _ in 0..WAIT_STEPS {
        if path.exists() {
            return true;
        }
        thread::sleep(WAIT_STEP);
    }
    false
}

fn touch(path: &Path) -> io::Result<()> {
    File::create(path)?;
    Ok(())
}

/// Create (or replace) a file only its owner may read.
///
/// Replaced and not truncated: the mode is only applied when the file is
/// created, and a leftover from an older version would keep its old, wider
/// permissions while holding the private key.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn tool_paths_are_flags_and_the_zone_name_is_positional() {
        let parsed = Args::parse(&argv(&[
            "--ip", "/n/ip", "--awg", "/n/awg", "--wg", "/n/wg", "--pasta", "/n/pasta", "nl",
        ]))
        .unwrap();
        assert_eq!(parsed.name, OsString::from("nl"));
        assert_eq!(parsed.tools.ip, PathBuf::from("/n/ip"));
        assert_eq!(parsed.tools.awg, PathBuf::from("/n/awg"));
        assert_eq!(parsed.tools.wg, PathBuf::from("/n/wg"));
        assert_eq!(parsed.tools.pasta, PathBuf::from("/n/pasta"));
    }

    #[test]
    fn missing_flags_fall_back_to_the_path() {
        let parsed = Args::parse(&argv(&["nl"])).unwrap();
        assert_eq!(parsed.tools, Tools::default());
        assert_eq!(parsed.tools.ip, PathBuf::from("ip"));

        // Order is free, and a name may start with a single dash.
        let parsed = Args::parse(&argv(&["-nl", "--pasta", "/n/pasta"])).unwrap();
        assert_eq!(parsed.name, OsString::from("-nl"));
        assert_eq!(parsed.tools.pasta, PathBuf::from("/n/pasta"));
    }

    #[test]
    fn broken_command_lines_are_rejected() {
        assert_eq!(Args::parse(&argv(&[])), Err(ArgError::MissingName));
        assert_eq!(Args::parse(&argv(&[""])), Err(ArgError::MissingName));
        assert_eq!(
            Args::parse(&argv(&["--ip", "/n/ip"])),
            Err(ArgError::MissingName)
        );
        assert_eq!(
            Args::parse(&argv(&["--ip"])),
            Err(ArgError::MissingValue("--ip".to_string()))
        );
        assert_eq!(
            Args::parse(&argv(&["--wat", "x", "nl"])),
            Err(ArgError::UnknownFlag("--wat".to_string()))
        );
        assert_eq!(
            Args::parse(&argv(&["nl", "de"])),
            Err(ArgError::ExtraArguments)
        );
    }

    #[test]
    fn both_shapes_of_default_route_are_read_by_keyword() {
        // pasta: no gateway, and "link" sits where a positional parser used to
        // look for the interface name.
        let pasta = parse_default_route("default dev hostif scope link");
        assert_eq!(pasta.dev.as_deref(), Some("hostif"));
        assert_eq!(pasta.via, None);

        let lan = parse_default_route(
            "default via 192.168.1.1 dev enp4s0 proto dhcp src 192.168.1.42 metric 100",
        );
        assert_eq!(lan.dev.as_deref(), Some("enp4s0"));
        assert_eq!(lan.via.as_deref(), Some("192.168.1.1"));

        let v6 = parse_default_route("default via fe80::1 dev hostif metric 1024 pref medium");
        assert_eq!(v6.dev.as_deref(), Some("hostif"));
        assert_eq!(v6.via.as_deref(), Some("fe80::1"));

        // No route at all: both fields empty, and the caller fails loudly.
        assert_eq!(parse_default_route(""), DefaultRoute::default());
    }

    #[test]
    fn ipv6_is_either_tunnelled_or_closed() {
        // A kernel without v6: nothing to do.
        assert_eq!(v6_plan(false, false, false), V6Plan::NoKernel);
        assert_eq!(v6_plan(false, true, true), V6Plan::NoKernel);
        // The tunnel carries v6 — it wins over everything else.
        assert_eq!(v6_plan(true, true, false), V6Plan::IntoTunnel);
        assert_eq!(v6_plan(true, true, true), V6Plan::IntoTunnel);
        // A v6 endpoint means the family must stay up for the transport.
        assert_eq!(v6_plan(true, false, true), V6Plan::CloseDefault);
        // Nothing needs v6: it goes away entirely. Fail-closed.
        assert_eq!(v6_plan(true, false, false), V6Plan::Disable);
    }

    #[test]
    fn resolv_conf_falls_back_to_public_resolvers() {
        let (text, defaulted) = resolv_conf(&[]);
        assert!(defaulted);
        assert_eq!(text, "nameserver 1.1.1.1\nnameserver 9.9.9.9\n");

        let (text, defaulted) = resolv_conf(&["10.8.1.1".to_string(), "fd00::1".to_string()]);
        assert!(!defaulted);
        assert_eq!(text, "nameserver 10.8.1.1\nnameserver fd00::1\n");

        // A DNS= line of nothing but separators is the same as no line at all.
        let (_, defaulted) = resolv_conf(&[String::new()]);
        assert!(defaulted);
    }

    #[test]
    fn endpoint_literals_are_told_from_names() {
        let literal = endpoint_host_kind(&Endpoint::parse("198.51.100.7:51820").unwrap());
        assert_eq!(
            literal,
            EndpointHostKind::Literal("198.51.100.7".parse::<IpAddr>().unwrap())
        );

        // Bracketed and bare v6 literals: neither must end up as a hostname,
        // hex digits or not.
        let bracketed = endpoint_host_kind(&Endpoint::parse("[fd00::1]:51820").unwrap());
        assert_eq!(
            bracketed,
            EndpointHostKind::Literal("fd00::1".parse::<IpAddr>().unwrap())
        );
        let bare = endpoint_host_kind(&Endpoint::parse("fd00:dead:beef::1").unwrap());
        assert_eq!(
            bare,
            EndpointHostKind::Literal("fd00:dead:beef::1".parse::<IpAddr>().unwrap())
        );

        let name = endpoint_host_kind(&Endpoint::parse("vpn.example.org:51820").unwrap());
        assert_eq!(name, EndpointHostKind::Name("vpn.example.org".to_string()));
    }

    #[test]
    fn a_handshake_needs_a_nonzero_timestamp() {
        assert!(handshake_seen("peerkey\t1758000000\n"));
        assert!(!handshake_seen("peerkey\t0\n"));
        // Several peers, one of them alive.
        assert!(handshake_seen("a\t0\nb\t1758000000\n"));
        // Empty output is "no handshake", not "success" — the bash pipeline
        // used to report the opposite.
        assert!(!handshake_seen(""));
        assert!(!handshake_seen("\n \n"));
        assert!(!handshake_seen("nonsense\n"));
    }
}
