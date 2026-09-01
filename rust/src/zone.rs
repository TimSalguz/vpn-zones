//! Zone life cycle: everything `vpn-zone@<name>.service` starts.
//!
//! A zone is a pair of network namespaces with a tunnel strung between them,
//! created and torn down entirely from the user's session — no root anywhere,
//! not to create one and not to run a program in one.
//!
//! ```text
//! vpn-zone-core zone-holder <name>        (systemd main process, host user)
//!  └─ fork ─ user namespace, uid 0 inside                    [holder]
//!      ├─ fork ─ net + mount namespace: THE UPLINK      [uplink.pid]
//!      │           pasta's tap, the only route to the world, and the UDP
//!      │           socket of the tunnel; awg0 is CREATED here and moves ↓
//!      ├─ pasta --netns /proc/<uplink>/ns/net                [the way out]
//!      └─ fork ─ net + mount namespace: THE APP NAMESPACE    [zone.pid]
//!                  lo and awg0 and NOTHING ELSE: the default routes into
//!                  the tunnel, its own resolv.conf, then parks forever
//! ```
//!
//! **Why two namespaces** (`docs/LEAK-MODEL.md`). A leak is impossible not
//! because a rule forbids it but because the path does not exist: the namespace
//! the programs run in has exactly two interfaces, loopback and the tunnel. No
//! LAN, no host, no route to the VPN server, and nothing for a future protocol
//! family to escape through either — there is simply nowhere to send a packet.
//! Everything that talks to the outside world lives one namespace up, where no
//! program of the user's ever runs.
//!
//! **How the tunnel can be in one namespace and its socket in another.** This
//! is a documented property of WireGuard (and of AmneziaWG, which is WireGuard
//! plus obfuscation): the UDP socket of an interface stays in the namespace the
//! interface was **created** in and does not travel with it. So awg0 is created
//! in the uplink, moved into the app namespace with `ip link set … netns …` and
//! configured there — the encrypted packets are born in the uplink and leave
//! through pasta, while the app namespace never sees the endpoint at all.
//!
//! **Two kinds of tunnel, one contour.** A zone is either a kernel
//! WireGuard/AmneziaWG one (its config has an `[Interface]` section) or an
//! OpenConnect one (`[OpenConnect]`, [`crate::openconnect`]). The wall stands in
//! the same place either way — what changes is only what stays behind it. With
//! WireGuard it is a UDP socket; with OpenConnect it is a whole client process:
//! the TLS session, the gateway's address and every packet still wrapped in it
//! live one namespace up, and what arrives in the app namespace is a bare tun
//! device with an address on it. Who creates and moves that device is the other
//! difference: the uplink itself for WireGuard, the client's `--script` — which
//! is us, `vpn-zone-core oc-script` — for OpenConnect. A tun device and the
//! descriptor attached to it are separate things, so the client goes on reading
//! and writing packets from the uplink after the interface has left it.
//!
//! **The endpoint is resolved before either namespace exists.** `wg setconf`
//! resolves `Endpoint` itself, through `getaddrinfo`, and retries for a minute
//! and a half before giving up — in the app namespace, where there is no
//! network until the tunnel is up, a hostname would hang the zone. The holder
//! therefore resolves every endpoint while it is still in the host's network
//! and writes literal addresses into the text `setconf` gets.
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
//! Both namespaces belong to that one user namespace, which is what lets the
//! uplink move an interface into the app namespace: moving a link needs
//! CAP_NET_ADMIN in both, and uid 0 of the owning user namespace has it in
//! every namespace that user namespace owns.
//!
//! **Why the namespaces are separate processes.** pasta stays in the host's
//! network and attaches from the outside through `--netns /proc/<pid>/ns/net`,
//! so the namespace it serves has to belong to another process than the one
//! running pasta. (`docs/GOTCHAS.md` §2)
//!
//! **Kill switch.** Each namespace lives exactly as long as the process parked
//! at the end of its setup; the holder supervises both and takes the whole zone
//! down (pasta included) as soon as either dies. On the systemd side
//! `KillMode=control-group` (the default) does the same to everything that was
//! running inside.
//!
//! And when the holder is gone while programs are still running, the app
//! namespace survives — the programs hold it — but the uplink does not: nothing
//! is left inside it, so the kernel destroys it, and WireGuard's own reaction to
//! its creating namespace going away is to turn the carrier off and close the
//! sockets. awg0 stays where it is and drops every packet. Fail-closed by
//! construction, with nothing to fall back to.
//!
//! **The second echelon.** Both namespaces also get an nftables ruleset, and it
//! is insurance, not the load-bearing wall (`docs/LEAK-MODEL.md`): the app
//! namespace may send nothing except through the tunnel, the uplink nothing
//! except the tunnel's own packets to the endpoint we resolved. Neither rule has
//! anything to do today — there is no other interface in the app namespace, and
//! nothing but the tunnel runs in the uplink — which is exactly the point: the
//! day a mistake puts an interface or a process where none belongs, the packets
//! stop instead of leaving quietly. nftables missing or refused by the kernel is
//! a loud warning and a zone that comes up anyway.
//!
//! **No PID namespace anywhere**, and that is deliberate: `zone.pid` has to
//! name the app-namespace process the way the HOST sees it — `vpn-zone
//! run`/`status` `nsenter` into it by that number — and the uplink hands the
//! interface over by that same host pid, while pasta is given the uplink's.
//! All three are host pids only as long as no pid namespace is created.

use std::borrow::Cow;
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

use crate::config::{Endpoint, EndpointHost, Family, WgConfig};
use crate::openconnect::{self, OcConfig};
use crate::profile::{exit_code_of, home_dir};
use crate::sys;

/// Where the zones live, below `$HOME`. The bash CLI computes the same path.
const STATE_SUBDIR: &str = ".local/state/vpn-zones";

/// Files of one zone. This set is a contract: `vpn-zone` (bash), the desktop
/// picker and the smoke test all read them by these names.
const CONFIG: &str = "config.conf";
const OFFLINE: &str = "offline";
/// The APP namespace, the one `nsenter` targets. Programs run here.
const PID: &str = "zone.pid";
/// The uplink namespace: pasta attaches to it and `vpn-zone gc` recognises a
/// stray pasta by the number in its command line.
const UPLINK_PID: &str = "uplink.pid";
const READY: &str = "ready";
const STATUS: &str = "status";
const STATUS_TMP: &str = "status.tmp";
const RESOLV: &str = "resolv.conf";
/// What the zone's own resolv.conf is bound over. A path and not a file name:
/// on NixOS it is a chain of symlinks and the mount lands at the end of it
/// (`sys::link_target`).
const ETC_RESOLV: &str = "/etc/resolv.conf";
/// Directories holding a unix socket through which a daemon in the HOST's
/// network answers name lookups. Every one of them is covered by a tmpfs inside
/// the zone — see `hide_host_resolvers`, where the reason is written down.
///
/// Grouped, because the first entry is a pair: `/var/run` is a symlink to
/// `/run` on any modern system, so hiding either name hides the one directory
/// and there is nothing left to do in that group. The groups themselves are
/// independent and each is hidden on its own.
const RESOLVER_DIRS: [&[&str]; 3] = [
    // nscd, or the nsncd NixOS runs in its place.
    &["/run/nscd", "/var/run/nscd"],
    // systemd-resolved: `io.systemd.Resolve`, the varlink socket nss-resolve
    // talks to, and `io.systemd.Resolve.Monitor` next to it.
    &["/run/systemd/resolve"],
    // avahi, i.e. nss-mdns — it would put the name onto the host's LAN.
    &["/run/avahi-daemon"],
];
/// The config with the wg-quick directives taken out and every `Endpoint`
/// turned into a literal address, i.e. what `setconf` gets.
const STRIPPED: &str = ".stripped.conf";

/// The tunnel is always called `awg0`, whatever carries it — either kernel
/// module, or the OpenConnect client, which is told the name with
/// `--interface`. `vpn-zone status`, `vpn-zone check`, the smoke test and, more
/// importantly, the app namespace's own `oifname "awg0" accept` rule all look
/// for that one name; the rule is loaded BEFORE the tunnel arrives, so a
/// backend that brought its own name would have its packets dropped by the
/// second echelon. One name for every kind of zone is the invariant, and the
/// name is historical rather than descriptive.
const TUN_IFACE: &str = "awg0";
/// Name of pasta's interface inside the uplink namespace. Given explicitly
/// because pasta otherwise copies the name of the host's outbound interface —
/// and if the host is itself under a VPN and that interface is called `awg0`,
/// the name would collide with the zone's own tunnel. (`docs/GOTCHAS.md` §2)
const PASTA_IFACE: &str = "hostif";
/// wg-quick's default, used when the config carries no `MTU`.
const DEFAULT_MTU: u32 = 1420;
/// Resolvers for a config without `DNS=`: public ones, reached through the
/// tunnel. (`docs/GOTCHAS.md` §3)
const DEFAULT_RESOLVERS: [&str; 2] = ["1.1.1.1", "9.9.9.9"];

/// Name of the table both namespaces get, so that `nft list ruleset` inside a
/// zone says whose rules these are.
const NFT_TABLE: &str = "vpnzone";

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

/// Which tool speaks to the interface the uplink built. The app namespace does
/// not try the kernel modules itself — the interface is already there by the
/// time it hears about it — so the uplink says which of the two it got.
const TOOL_AWG: u8 = b'a';
const TOOL_WG: u8 = b'w';
/// The tunnel came from the OpenConnect client: the interface is already in the
/// app namespace and the facts about it are in the plan file the client's
/// script wrote. (`crate::openconnect`)
const TOOL_OC: u8 = b'o';

/// How long the uplink waits for the OpenConnect client to authenticate and
/// hand the tunnel over: two minutes in 0.1 s steps. Long, and deliberately so
/// — a corporate gateway with a slow authentication step is ordinary, and
/// giving up on a connection that was about to succeed costs the user the zone.
/// The wait ends early the moment the client exits.
const OC_CONNECT_STEPS: u32 = 1200;

/// Absolute paths of the tools the zone drives. Absolute because part of this
/// code runs inside a namespace where `PATH` can be anything; Nix substitutes
/// them into the unit's `ExecStart`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    pub ip: PathBuf,
    pub awg: PathBuf,
    pub wg: PathBuf,
    pub pasta: PathBuf,
    /// The second echelon (`docs/LEAK-MODEL.md`). Optional in the sense that a
    /// zone without it still comes up — loudly, and on its topology alone.
    pub nft: PathBuf,
    /// The userspace client of an `[OpenConnect]` zone. Only such a zone runs
    /// it; a WireGuard one never looks at this path.
    pub openconnect: PathBuf,
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
            nft: PathBuf::from("nft"),
            openconnect: PathBuf::from("openconnect"),
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
    /// Parse `[--ip P] [--awg P] [--wg P] [--pasta P] [--nft P]
    /// [--openconnect P] <name>`.
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
                "--nft" => &mut tools.nft,
                "--openconnect" => &mut tools.openconnect,
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

    /// A zone with this marker has no network at all: no tunnel, no uplink, no
    /// pasta, just loopback. That is what makes "no internet until it is
    /// explicitly given" possible — the program runs, but a route out does not
    /// physically exist. (`docs/GOTCHAS.md` §2)
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

    /// Load the second echelon into the CURRENT network namespace.
    ///
    /// Never fatal, and that is a decision rather than laziness
    /// (`docs/LEAK-MODEL.md`): the filter insures the topology, the topology
    /// does not lean on the filter. An old kernel, a kernel without the
    /// `nf_tables` module loaded (it cannot be autoloaded from inside an
    /// unprivileged user namespace) or no `nft` at all must not cost the user
    /// the zone — but it must be impossible to miss in the journal, because a
    /// zone whose second echelon is off is a zone one mistake away from a leak.
    fn seal(&self, side: &str, ruleset: &str) {
        if let Err(e) = feed_nft(&self.tools.nft, ruleset) {
            eprintln!(
                "zone {}: {side}: nftables second echelon is OFF ({e}) — the zone is up and \
                 still hermetic by construction, but nothing insures it against a mistake",
                self.name()
            );
        }
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
    let _ = fs::remove_file(zone.path(UPLINK_PID));
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
/// The two namespaces and pasta, from the point of view of the holder.
static ZONE_CHILD: AtomicI32 = AtomicI32::new(0);
static UPLINK_CHILD: AtomicI32 = AtomicI32::new(0);
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
    for slot in [&PASTA_CHILD, &UPLINK_CHILD, &ZONE_CHILD] {
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

/// Wait for the FIRST of our children to die: pid and its exit code. `-1` means
/// there is nothing left to wait for, which can only happen if everything
/// managed to die before we got here.
fn wait_any() -> (libc::pid_t, u8) {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return (-1, 1);
        }
        return (pid, exit_code_of(status));
    }
}

/// TERM a child and collect it, tolerating one that is already gone.
fn kill_and_reap(pid: libc::pid_t) {
    if pid <= 0 {
        return;
    }
    // SAFETY: kill(2) takes no pointers; the pid is still ours to signal
    // because it has not been waited for yet.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let _ = reap(pid);
}

// --- PROCESS 2: INSIDE THE USER NAMESPACE ------------------------------------

/// Create the user namespace, wait for the mapping, become uid 0, supervise.
fn holder(zone: &Zone, unshared_w: OwnedFd, mapped_r: OwnedFd) -> u8 {
    // The parent's handlers are meaningless here (they name the parent's
    // child), and the processes forked below inherit whatever we have.
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
    // setuid() cleared the dumpable flag, and both namespace processes forked
    // below inherit it. A non-dumpable process hides its /proc/<pid>/ns/* behind
    // a CAP_SYS_PTRACE check that pasta then fails: it has to open the uplink's
    // netns through /proc, gets EACCES and dies on the spot — silently, since
    // passt logs to syslog when stderr is not a terminal. The same check would
    // stop `nsenter` from entering the zone. util-linux's `unshare --setuid`
    // (what this dance replaces) sets dumpable back for exactly this reason, so
    // parity requires it. The exposure is unchanged from the bash version:
    // same-user processes may ptrace the zone.
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };

    match supervise(zone) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zone {}: {e}", zone.name());
            1
        }
    }
}

/// Which kind of tunnel this zone carries, decided once by [`prepare`] and read
/// by both namespaces afterwards.
///
/// The decision itself is one question asked of the config file: is there an
/// `[OpenConnect]` section? The two shapes cannot be confused — a WireGuard
/// config has no such section, and a file that has one but does not parse is
/// refused by `vpn-zone add` before a zone exists at all.
pub enum Backend {
    /// Kernel WireGuard or AmneziaWG. The uplink creates the interface itself
    /// and hands it down; the transport socket stays where it was created.
    Wg(WgConfig),
    /// A userspace OpenConnect client running in the uplink. It creates the
    /// interface and its own `--script` hands it down; the TLS session stays
    /// with the process, which never leaves the uplink.
    Oc(Box<OcZone>),
}

/// An OpenConnect zone, ready to be started.
pub struct OcZone {
    pub cfg: OcConfig,
    /// The gateway's address, resolved in the HOST's network before either
    /// namespace exists — the same rule the WireGuard endpoint follows, and for
    /// the same two reasons: the uplink has no resolver of its own, and its
    /// filter would not let a lookup out even if it had one. The client is then
    /// told the answer with `--resolve`, so it never asks either.
    pub addr: IpAddr,
}

impl Backend {
    /// What the uplink's filter may talk to.
    ///
    /// For WireGuard this is every endpoint of the config, with its port. For
    /// OpenConnect it is the gateway's address and NO port, which is one
    /// dimension wider on purpose: the transport is TLS on the configured port
    /// but the client also tries DTLS on whatever UDP port the server
    /// advertises, and that number is not known until the session exists. The
    /// rule that matters is unchanged — this namespace may talk to the VPN
    /// gateway and to nothing else in the world.
    fn sockets(&self) -> Vec<EndpointSocket> {
        match self {
            Self::Wg(cfg) => endpoint_sockets(cfg),
            Self::Oc(oc) => vec![EndpointSocket {
                addr: oc.addr,
                port: None,
            }],
        }
    }
}

/// What the app namespace is handed: the backend, the pipe it reports its own
/// existence on, and the pipe the tunnel arrives through.
struct ZoneLinks<'a> {
    backend: &'a Backend,
    ready_w: OwnedFd,
    moved_r: OwnedFd,
}

/// What the uplink is handed: the backend, the host pid of the app namespace to
/// hand the interface to, and its three pipe ends.
struct UplinkLinks<'a> {
    backend: &'a Backend,
    zone_pid: libc::pid_t,
    ready_w: OwnedFd,
    zone_up_r: OwnedFd,
    moved_w: OwnedFd,
}

/// Start both namespaces and pasta, then live exactly as long as all of them.
///
/// The order is forced by what each step needs from the one before it: the app
/// namespace goes first because the uplink has to know its pid; the uplink then
/// reports its own namespace so pasta can attach to it from out here; and the
/// uplink waits for the app namespace to say it exists before handing the
/// interface over. Everything else is barriers on pipes, so a failure anywhere
/// shows up as an EOF on the other side instead of a timeout.
fn supervise(zone: &Zone) -> Result<u8, String> {
    // Read the config and resolve its endpoints HERE: this is the last place
    // with the host's network and the host's resolver. An offline zone has no
    // config at all — and no uplink, and no pasta.
    let cfg = if zone.is_offline() {
        None
    } else {
        Some(prepare(zone)?)
    };

    let (uplink_up_r, uplink_up_w) =
        sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;
    let (zone_up_r, zone_up_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;
    let (moved_r, moved_w) = sys::pipe().map_err(|e| format!("cannot create a pipe: {e}"))?;

    // SAFETY: single-threaded at this point (the status mirror thread is
    // started by the app namespace, after the fork).
    let zone_pid = unsafe { libc::fork() };
    if zone_pid < 0 {
        return Err(format!("cannot fork: {}", io::Error::last_os_error()));
    }
    if zone_pid == 0 {
        drop(uplink_up_r);
        drop(uplink_up_w);
        drop(zone_up_r);
        drop(moved_w);
        let links = cfg.as_ref().map(|backend| ZoneLinks {
            backend,
            ready_w: zone_up_w,
            moved_r,
        });
        let code = zone_main(zone, links);
        // SAFETY: _exit never returns and touches nothing of ours.
        unsafe { libc::_exit(libc::c_int::from(code)) };
    }
    ZONE_CHILD.store(zone_pid, Ordering::SeqCst);
    // From here on TERM/INT means "tear the zone down", the trap the bash holder
    // had. Installed as soon as there is anything to tear down, and not after
    // the last child is up: a stop arriving during the setup below would
    // otherwise kill this process and leave the namespaces orphaned. The
    // children reset it to the default disposition first thing.
    on_term_and_int(stop_zone);
    // The app namespace has its two ends now; a copy left open here would keep
    // a pipe from ever reaching EOF, and EOF is how the other side learns that
    // this one has died.
    drop(zone_up_w);
    drop(moved_r);

    let mut uplink_pid = 0;
    let mut pasta: Option<Child> = None;
    if let Some(backend) = cfg.as_ref() {
        // SAFETY: as above.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let e = io::Error::last_os_error();
            kill_and_reap(zone_pid);
            return Err(format!("cannot fork: {e}"));
        }
        if pid == 0 {
            // The app namespace's ends are already closed here: the holder let
            // go of them before this fork.
            drop(uplink_up_r);
            let code = uplink_main(
                zone,
                UplinkLinks {
                    backend,
                    zone_pid,
                    ready_w: uplink_up_w,
                    zone_up_r,
                    moved_w,
                },
            );
            // SAFETY: as above.
            unsafe { libc::_exit(libc::c_int::from(code)) };
        }
        uplink_pid = pid;
        UPLINK_CHILD.store(pid, Ordering::SeqCst);
        drop(uplink_up_w);
        drop(zone_up_r);
        drop(moved_w);

        // The uplink's namespace exists once it says so, and there is nothing
        // for pasta to attach to before that. The pid is the one we know
        // first-hand — no pid namespace is created anywhere.
        let mut byte = [0u8; 1];
        let mut ready = File::from(uplink_up_r);
        if ready.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
            kill_and_reap(pid);
            kill_and_reap(zone_pid);
            return Err("the uplink namespace did not come up".to_string());
        }
        drop(ready);

        let netns = format!("/proc/{pid}/ns/net");
        match Command::new(&zone.tools.pasta)
            .arg("--netns")
            .arg(&netns)
            .args(["--config-net", "-q", "-I", PASTA_IFACE, "-f"])
            .spawn()
        {
            Ok(child) => {
                PASTA_CHILD.store(child.id() as i32, Ordering::SeqCst);
                pasta = Some(child);
            }
            Err(e) => eprintln!(
                "zone {}: cannot start pasta ({e}) — the zone will have no way out",
                zone.name()
            ),
        }
    } else {
        // An offline zone: nobody is on the other end of any of these.
        drop(uplink_up_r);
        drop(uplink_up_w);
        drop(zone_up_r);
        drop(moved_w);
    }

    // Either namespace dying is the end of the zone: without the uplink the
    // tunnel has no transport, and without the app namespace there is nothing
    // left to serve. pasta counts too — a zone whose way out is gone is a zone
    // that only pretends to work.
    let pasta_pid = pasta.as_ref().map_or(0, |c| c.id() as i32);
    let (dead, code) = wait_any();
    if !ASKED_TO_STOP.load(Ordering::SeqCst) {
        let what = if dead == zone_pid {
            "the zone"
        } else if dead == uplink_pid {
            "the uplink"
        } else if dead == pasta_pid {
            "pasta"
        } else {
            "a child"
        };
        eprintln!("zone {}: {what} died — taking the zone down", zone.name());
    }

    // Nothing may outlive the zone: a stray pasta would keep an interface on a
    // dead namespace and `vpn-zone gc` would have to clean up after us, and a
    // surviving uplink would keep a namespace nobody can reach any more.
    for pid in [pasta_pid, uplink_pid, zone_pid] {
        if pid != dead {
            kill_and_reap(pid);
        }
    }
    // pasta is signalled and collected by pid like the other two, because
    // `wait_any` above may already have collected it — `Child::wait` would then
    // fail on a pid that is no longer ours. Dropping the `Child` does nothing to
    // the process (std has no `Drop` for it), which is exactly what we want.
    drop(pasta);

    Ok(stopped_cleanly(code))
}

/// Read the config, resolve every `Endpoint` and write the text `setconf` gets.
///
/// All of it happens in the HOST's network, before any namespace exists: see
/// the note on `getaddrinfo` in the module docs. A name that does not resolve
/// is fatal on purpose — the alternative is `wg setconf` retrying DNS for a
/// minute and a half inside a namespace that has none, and then failing anyway.
fn prepare(zone: &Zone) -> Result<Backend, String> {
    let raw = fs::read(zone.path(CONFIG)).map_err(|e| format!("cannot read {CONFIG}: {e}"))?;
    let mut cfg = WgConfig::parse(&raw).map_err(|e| format!("{CONFIG}: {e}"))?;
    if openconnect::is_openconnect(&cfg) {
        return prepare_openconnect(zone, &cfg);
    }
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

    let endpoints = cfg.resolve_endpoints(resolve_endpoint);
    if endpoints.is_empty() {
        eprintln!(
            "zone {}: no Endpoint in the config — the tunnel has nowhere to go",
            zone.name()
        );
    }
    for endpoint in &endpoints {
        if endpoint.addr.is_none() {
            return Err(format!(
                "cannot resolve the endpoint {} (line {}) — it has to be an address by the \
                 time the tunnel is configured, because the zone has no DNS of its own until \
                 the tunnel is up",
                endpoint.raw, endpoint.line
            ));
        }
    }

    // `setconf` understands protocol keys only, so it gets a stripped copy.
    // 0600: it carries the private key.
    write_private(&zone.path(STRIPPED), cfg.to_setconf().as_bytes())
        .map_err(|e| format!("cannot write {STRIPPED}: {e}"))?;
    Ok(Backend::Wg(cfg))
}

/// The same work for an `[OpenConnect]` zone: check the config, check the
/// password file, resolve the gateway — all of it here, in the host's network,
/// before a namespace exists.
///
/// **Why the gateway is resolved here and not by the client.** The uplink has
/// the host's `/etc/resolv.conf` but not the host's network: its filter lets
/// out packets to the gateway and nothing else, so a lookup from in there would
/// be dropped, and a lookup that somehow got through a host resolver's socket
/// would be a leak of exactly the kind this project measures. The client is
/// therefore told the answer with `--resolve` and never asks — the same trick,
/// with the same reasoning, as writing literal addresses into the text
/// `wg setconf` gets.
fn prepare_openconnect(zone: &Zone, ini: &WgConfig) -> Result<Backend, String> {
    let cfg = OcConfig::from_ini(ini).map_err(|e| format!("{CONFIG}: {e}"))?;
    // Checked, not read: the password itself is read once, in the uplink, right
    // before it is handed to the client (`spawn_openconnect`).
    cfg.check_password_file()
        .map_err(|e| format!("{CONFIG}: {e}"))?;

    let addr = match cfg.server_literal() {
        Some(addr) => addr,
        None => {
            let port = cfg.port.unwrap_or(443);
            let addrs: Vec<IpAddr> = (cfg.server.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| {
                    format!(
                        "cannot resolve the gateway {} ({e}) — it has to be an address by the \
                         time the zone starts, because the uplink has no resolver of its own",
                        cfg.server
                    )
                })?
                .map(|a| a.ip())
                .collect();
            // v4 first, as everywhere else in this file. A name that resolves
            // ONLY to IPv6 is refused rather than half-supported: `--resolve`
            // takes `HOST:IP` and cannot express a v6 address unambiguously, so
            // the client would be handed a mangled one. Writing the literal
            // into `Server =` works and is what the message asks for.
            match addrs.iter().copied().find(IpAddr::is_ipv4) {
                Some(addr) => addr,
                None if addrs.is_empty() => {
                    return Err(format!("the gateway {} resolved to nothing", cfg.server))
                }
                None => {
                    return Err(format!(
                        "the gateway {} resolves only to IPv6; write that address into Server = \
                         instead — `--resolve` cannot carry one unambiguously",
                        cfg.server
                    ))
                }
            }
        }
    };

    // A plan left over from a previous run would make the uplink believe the
    // tunnel is already up the moment it looks.
    let _ = fs::remove_file(zone.path(openconnect::PLAN_FILE));
    Ok(Backend::Oc(Box::new(OcZone { cfg, addr })))
}

// --- PROCESS 3: THE UPLINK ---------------------------------------------------

/// The uplink: pasta's namespace, and the namespace the tunnel is born in.
///
/// A WireGuard zone parks here forever, because the tunnel is a kernel object
/// and there is nothing left to supervise. An OpenConnect zone waits on the
/// client instead: the client's exit becomes this process's exit, the holder
/// sees the uplink die and takes the whole zone down with it. No retry, no
/// fallback, nothing to fall back TO — the app namespace has one interface and
/// it is about to disappear.
fn uplink_main(zone: &Zone, links: UplinkLinks<'_>) -> u8 {
    default_signals();
    match uplink_setup(zone, links) {
        Ok(None) => park(),
        Ok(Some(mut client)) => {
            let code = match client.wait() {
                Ok(status) => {
                    eprintln!(
                        "zone {}: the openconnect client exited ({status}) — the tunnel is gone",
                        zone.name()
                    );
                    status.code().map_or(1, |c| c as u8)
                }
                Err(e) => {
                    eprintln!("zone {}: cannot wait for openconnect: {e}", zone.name());
                    1
                }
            };
            // A client that quit on its own leaves a zone that cannot work,
            // whatever it thought of its own exit — this path is never reached
            // on a `systemctl stop`, which signals us straight to death.
            if code == 0 {
                1
            } else {
                code
            }
        }
        Err(e) => {
            eprintln!("zone {}: uplink: {e}", zone.name());
            1
        }
    }
}

/// Bring the uplink up; the answer is the process this namespace now lives as
/// long as, if there is one.
fn uplink_setup(zone: &Zone, links: UplinkLinks<'_>) -> Result<Option<Child>, String> {
    let UplinkLinks {
        backend,
        zone_pid,
        ready_w,
        zone_up_r,
        moved_w,
    } = links;

    // SAFETY: unshare(2) takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "cannot create the net+mount namespace: {}",
            io::Error::last_os_error()
        ));
    }
    // Private propagation: nothing the uplink side ever mounts (a resolver of
    // its own, a userspace client's state — ROADMAP M4) may travel to the host.
    sys::mount(
        OsStr::new("none"),
        Path::new("/"),
        "",
        libc::MS_REC | libc::MS_PRIVATE,
        "",
    )
    .map_err(|e| format!("cannot make the mount tree private: {e}"))?;

    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let pid = unsafe { libc::getpid() };
    fs::write(zone.path(UPLINK_PID), format!("{pid}\n"))
        .map_err(|e| format!("cannot write {UPLINK_PID}: {e}"))?;
    zone.ip(&["link", "set", "lo", "up"])?;

    // --- THE SECOND ECHELON, BEFORE THERE IS ANYTHING TO FILTER ---
    // Loaded before pasta is even told about this namespace, so that connectivity
    // never exists here unfiltered. The rules cost the setup nothing: everything
    // below (waiting for a route, creating the interface, handing it over) is
    // netlink, which no filter hook of the `inet` family ever sees.
    //
    // What it buys: this namespace may send exactly the tunnel's own packets to
    // the endpoint, and nothing else. That mattered in theory while only the
    // kernel ran here; with an OpenConnect zone a whole third-party client runs
    // in this namespace, and the rule is what says it may talk to its gateway
    // and to nowhere else — no DNS, no update check, no second server.
    zone.seal("uplink", &uplink_ruleset(&backend.sockets()));

    // The holder is waiting for this to attach pasta to us.
    let mut ready = File::from(ready_w);
    ready
        .write_all(&[SYNC_OK])
        .map_err(|e| format!("cannot report the namespace to the holder: {e}"))?;
    drop(ready);

    // Wait for pasta to configure the way out: until it has, there is no route
    // at all and the tunnel would have nothing to send through.
    wait_for_default_route(zone);
    let out = default_route(zone, Family::V4);
    let Some(dev) = out.dev else {
        // The dump tells apart "pasta never attached" (lo only) from "attached
        // but configured differently" (a tap exists, the routes do not).
        for what in [
            ["-o", "link", "show"],
            ["-4", "addr", "show"],
            ["-4", "route", "show"],
        ] {
            eprintln!(
                "zone {}: uplink: ip {}:\n{}",
                zone.name(),
                what.join(" "),
                zone.ip_line(&what)
            );
        }
        return Err("pasta gave us no route out".to_string());
    };

    // --- THE TUNNEL IS BORN HERE, AND THAT IS THE WHOLE POINT ---
    // Whichever backend builds it. A WireGuard interface keeps its UDP socket
    // in the namespace it was CREATED in, whatever namespace it is moved to
    // afterwards; an OpenConnect tun keeps its whole client. Either way the app
    // namespace gets an interface whose packets leave through pasta, and needs
    // neither a route to the gateway nor any interface besides the tunnel.
    match backend {
        Backend::Wg(cfg) => {
            let tool = create_tunnel(zone, cfg)?;
            println!(
                "zone {}: uplink is up (default dev {dev}), tunnel created",
                zone.name()
            );

            // The interface can only be handed to a namespace that exists.
            wait_for_app_namespace(zone_up_r)?;

            // A host pid, because no pid namespace is created anywhere; `ip`
            // opens /proc/<pid>/ns/net behind it. Both namespaces belong to our
            // user namespace, where we are uid 0 — which is what makes the move
            // allowed.
            let target = zone_pid.to_string();
            zone.ip(&["link", "set", TUN_IFACE, "netns", target.as_str()])?;

            // Now the app namespace may configure it — and it has to be told
            // which of the two tools speaks to what we built.
            tell_the_zone(moved_w, tool)?;
            Ok(None)
        }
        Backend::Oc(oc) => {
            // Same barrier, read EARLIER than on the WireGuard path: there the
            // interface exists before the app namespace does, here the client's
            // script moves it the moment the client connects, so the target has
            // to be waiting before the client is even started.
            wait_for_app_namespace(zone_up_r)?;
            println!(
                "zone {}: uplink is up (default dev {dev}), starting openconnect to {}",
                zone.name(),
                oc.cfg.server
            );

            let mut client = spawn_openconnect(zone, oc, zone_pid)?;
            if let Err(e) = wait_for_plan(zone, &mut client) {
                // Nothing may outlive a failed setup: an orphaned client would
                // hold this namespace open with a live session in it.
                let _ = client.kill();
                let _ = client.wait();
                return Err(e);
            }
            tell_the_zone(moved_w, TOOL_OC)?;
            Ok(Some(client))
        }
    }
}

/// Wait for the app namespace to say it exists.
fn wait_for_app_namespace(zone_up_r: OwnedFd) -> Result<(), String> {
    let mut zone_up = File::from(zone_up_r);
    let mut byte = [0u8; 1];
    if zone_up.read_exact(&mut byte).is_err() || byte[0] != SYNC_OK {
        return Err("the app namespace never came up".to_string());
    }
    Ok(())
}

/// Hand the app namespace the one byte that says which backend built the
/// tunnel it is now looking at.
fn tell_the_zone(moved_w: OwnedFd, tool: u8) -> Result<(), String> {
    let mut moved = File::from(moved_w);
    moved
        .write_all(&[tool])
        .map_err(|e| format!("cannot tell the zone about the tunnel: {e}"))
}

/// Start the OpenConnect client in the uplink namespace.
///
/// Every argument here is either forced or checked, and that is the point: the
/// user's config can add flags only from an allowlist
/// ([`crate::openconnect`]), and the ones that decide where the tunnel ends up
/// are ours.
///
/// * `--script` is this very binary. Replacing it would replace the only thing
///   that puts the interface behind the wall, which is why `Args =` cannot
///   name it.
/// * `--interface awg0` gives every zone one interface name, so that the app
///   namespace's `oifname "awg0" accept` — loaded long before the tunnel
///   arrives — keeps meaning what it says.
/// * `--non-inter` because a zone is started by a systemd unit and there is no
///   terminal to ask anything on; a prompt would hang the zone instead of
///   failing it.
/// * `--no-external-auth` so that authentication never tries to open a browser
///   OUTSIDE the zone — the exact move `docs/LEAK-MODEL.md` spends a section on.
/// * `--disable-ipv6` because this backend does not carry IPv6 yet, and a
///   gateway that thinks we do would route a family into a black hole. Not
///   asking is honest; the app namespace closes the family either way.
/// * `--resolve` hands over the address resolved in the host's network, so the
///   client never needs a resolver in a namespace that has none.
/// * `--passwd-on-stdin` with the password written on one line and the pipe
///   closed. Not a command-line argument: `/proc/<pid>/cmdline` is world
///   readable, and not an environment variable either, for the same reason.
fn spawn_openconnect(zone: &Zone, oc: &OcZone, zone_pid: libc::pid_t) -> Result<Child, String> {
    let cfg = &oc.cfg;
    let password = cfg.read_password().map_err(|e| format!("{CONFIG}: {e}"))?;

    // `openconnect` runs its `--script` through `/bin/sh -c`, so the string is
    // shell-parsed. Store paths never contain anything a shell would look at,
    // but a hand-run holder might, and a mangled script is a tunnel nobody
    // moves anywhere.
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot find my own path for --script: {e}"))?;
    let exe = exe.to_str().ok_or_else(|| {
        "my own path is not UTF-8, and openconnect's --script goes through a shell".to_string()
    })?;
    if exe.contains(|c: char| c.is_whitespace() || "'\"\\$`;&|<>()*?[]{}#~!".contains(c)) {
        return Err(format!(
            "my own path ({exe}) has shell characters in it, and openconnect's --script is \
             shell-parsed"
        ));
    }

    let mut cmd = Command::new(&zone.tools.openconnect);
    cmd.arg(format!("--protocol={}", cfg.protocol))
        .arg("--interface")
        .arg(TUN_IFACE)
        .arg("--script")
        .arg(format!("{exe} oc-script"))
        .arg("--non-inter")
        .arg("--no-external-auth")
        .arg("--disable-ipv6");
    if cfg.server_literal().is_none() {
        cmd.arg(format!("--resolve={}:{}", cfg.server, oc.addr));
    }
    if let Some(pin) = &cfg.server_cert {
        cmd.arg(format!("--servercert={pin}"));
    }
    if let Some(user) = &cfg.user {
        cmd.arg(format!("--user={user}"));
    }
    if let Some(group) = &cfg.authgroup {
        cmd.arg(format!("--authgroup={group}"));
    }
    if password.is_some() {
        cmd.arg("--passwd-on-stdin");
    }
    for extra in &cfg.extra {
        cmd.arg(extra);
    }
    cmd.arg(cfg.server_arg());

    // What the script needs and openconnect knows nothing about. Inherited
    // through openconnect into the script, which is where they are read.
    cmd.env(openconnect::ENV_DIR, &zone.dir)
        .env(openconnect::ENV_NETNS_PID, zone_pid.to_string())
        .env(openconnect::ENV_IP, &zone.tools.ip);
    if let Some(mtu) = cfg.mtu {
        cmd.env(openconnect::ENV_MTU, mtu.to_string());
    }
    cmd.stdin(if password.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });

    // THE CLIENT MUST NOT OUTLIVE THIS PROCESS. The uplink is killed with a
    // plain signal and its default disposition, so no handler of ours runs on
    // the way out; without this the client would go on holding the uplink
    // namespace open, with a live VPN session in it, after the zone is gone.
    // SAFETY: pre_exec runs between fork and execve in the child; prctl with
    // these arguments takes no pointers, allocates nothing and is
    // async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            format!(
                "{} is not there — an [OpenConnect] zone needs the openconnect client",
                zone.tools.openconnect.display()
            )
        } else {
            format!("cannot run {}: {e}", zone.tools.openconnect.display())
        }
    })?;
    if let Some(password) = password {
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("openconnect was given no stdin to read the password from".to_string());
        };
        // One line, then EOF: `--non-inter` means nothing else will be asked.
        let written = stdin.write_all(password.as_bytes()).and_then(|()| stdin.write_all(b"\n"));
        drop(stdin);
        if let Err(e) = written {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("cannot hand the password to openconnect: {e}"));
        }
    }
    Ok(child)
}

/// Wait for the client's script to report that the tunnel is in the app
/// namespace.
///
/// The plan file appearing IS the report — the script writes it by rename after
/// the move, so its existence means the interface is already down there. The
/// wait ends early if the client dies, which is the ordinary failure: a wrong
/// password, a refused certificate, an unreachable gateway.
fn wait_for_plan(zone: &Zone, client: &mut Child) -> Result<(), String> {
    let plan = zone.path(openconnect::PLAN_FILE);
    for _ in 0..OC_CONNECT_STEPS {
        if plan.exists() {
            return Ok(());
        }
        match client.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "openconnect exited ({status}) before the tunnel was up — the messages above \
                     are its own"
                ))
            }
            Ok(None) => {}
            Err(e) => return Err(format!("cannot check on openconnect: {e}")),
        }
        thread::sleep(WAIT_STEP);
    }
    Err(format!(
        "openconnect did not hand the tunnel over in time ({OC_CONNECT_STEPS} tries of {} ms)",
        WAIT_STEP.as_millis()
    ))
}

/// Create the tunnel interface; the answer says which tool configures it.
///
/// The ordinary path is the kernel amneziawg module (it understands plain
/// WireGuard configs too). No module (a system without Amnezia, CI): a config
/// WITHOUT obfuscation parameters is carried by the in-tree wireguard module and
/// `wg`; with them we fail loudly — such a tunnel cannot be built without the
/// module, and degrading silently would be a lie.
fn create_tunnel(zone: &Zone, cfg: &WgConfig) -> Result<u8, String> {
    if zone
        .ip_quiet(&["link", "add", TUN_IFACE, "type", "amneziawg"])
        .is_ok()
    {
        return Ok(TOOL_AWG);
    }
    if cfg.is_obfuscated() {
        return Err(
            "the amneziawg module is unavailable and an obfuscated config cannot be carried \
             without it"
                .to_string(),
        );
    }
    zone.ip(&["link", "add", TUN_IFACE, "type", "wireguard"])?;
    println!(
        "zone {}: no amneziawg module — using the in-tree wireguard",
        zone.name()
    );
    Ok(TOOL_WG)
}

// --- PROCESS 4: THE APP NAMESPACE --------------------------------------------

/// The namespace programs run in: lo, the tunnel, and nothing else ever.
fn zone_main(zone: &Zone, links: Option<ZoneLinks<'_>>) -> u8 {
    default_signals();
    if let Err(e) = zone_setup(zone, links) {
        eprintln!("zone {}: {e}", zone.name());
        return 1;
    }
    park()
}

/// Hold the namespace until somebody kills us. The zone dies with this process,
/// which is exactly what makes it a kill switch.
fn park() -> ! {
    loop {
        // SAFETY: pause(2) takes no arguments; TERM and INT are left at their
        // default action, so this really is "until killed".
        unsafe { libc::pause() };
    }
}

fn zone_setup(zone: &Zone, links: Option<ZoneLinks<'_>>) -> Result<(), String> {
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

    // Only now: the file's appearance means "the namespaces exist", and this is
    // the number `vpn-zone run`/`status` enter by.
    // SAFETY: getpid(2) takes no arguments and cannot fail.
    let pid = unsafe { libc::getpid() };
    fs::write(zone.path(PID), format!("{pid}\n"))
        .map_err(|e| format!("cannot write {PID}: {e}"))?;
    zone.ip(&["link", "set", "lo", "up"])?;

    // BEFORE the offline branch, and deliberately so: an "offline" zone that
    // still sees the host's resolver sockets is not offline at all. A program
    // in it cannot open a connection, but it can have any name looked up by a
    // daemon in the HOST's network — which tells the outside world what it is
    // looking for and carries out with it anything that can be spelled into a
    // hostname. The policy "an unknown program gets no network" is only true
    // once these are gone.
    hide_host_resolvers(zone)?;

    let Some(ZoneLinks {
        backend,
        ready_w,
        moved_r,
    }) = links
    else {
        // An offline zone gets no rules, and needs none: loopback is the only
        // interface there will ever be, and `oifname "lo" accept` over an empty
        // namespace would say nothing that the empty namespace does not.
        //
        // Nor does it get a resolv.conf of its own: with the sockets above
        // hidden, whatever the host's file names is unreachable from a
        // namespace that has only loopback, and a name here simply does not
        // resolve. Which is what offline has to mean.
        touch(&zone.path(READY)).map_err(|e| format!("cannot create {READY}: {e}"))?;
        println!("zone {}: no network (loopback only)", zone.name());
        return Ok(());
    };

    // --- THE SECOND ECHELON, BEFORE THE TUNNEL EVEN ARRIVES ---
    // The rule names the interface (`oifname`) and not its index, so it does not
    // need awg0 to exist yet — which is why this can go first, and why it keeps
    // working if the interface is ever recreated. Everything below is netlink
    // (setconf, addresses, routes) and runs regardless: no filter hook of the
    // `inet` family sees a netlink message.
    //
    // Today this rule has nothing to stop: the namespace has lo and the tunnel
    // and no third interface can appear in it (the programs inside hold no
    // capabilities over it). That is precisely what makes it worth having — the
    // day a change of ours puts an interface here by mistake, the packets stop
    // instead of quietly leaving through it.
    zone.seal("zone", &app_ruleset());

    // The uplink is waiting for this before it hands the interface over.
    let mut ready = File::from(ready_w);
    ready
        .write_all(&[SYNC_OK])
        .map_err(|e| format!("cannot report the namespace to the uplink: {e}"))?;
    drop(ready);

    // --- THE TUNNEL ARRIVES ---
    // Created in the uplink and moved in here, so its transport socket stays
    // over there. Everything below runs over netlink in the CURRENT namespace,
    // which is why it has to happen after the move and not before it.
    let mut moved = File::from(moved_r);
    let mut byte = [0u8; 1];
    if moved.read_exact(&mut byte).is_err() {
        return Err("the uplink died before it could hand the tunnel over".to_string());
    }
    drop(moved);
    // Both backends end here with the same two answers: what the zone's
    // resolv.conf should say, and what its status mirror should watch. What
    // differs is only who put the address on the interface.
    let (dns, search, mirror) = match byte[0] {
        TOOL_AWG | TOOL_WG => {
            let Backend::Wg(cfg) = backend else {
                return Err(
                    "the uplink built a WireGuard tunnel for a zone that is not one".to_string(),
                );
            };
            let wgtool: &Path = if byte[0] == TOOL_AWG {
                zone.tools.awg.as_path()
            } else {
                zone.tools.wg.as_path()
            };
            configure_wg(zone, cfg, wgtool)?;
            (cfg.dns(), None, Mirror::Wg(wgtool.to_path_buf()))
        }
        TOOL_OC => {
            // The facts come from the file the client's script wrote, and its
            // existence is what the uplink waited for — so by the time this
            // byte arrives, the interface is already down here.
            let path = zone.path(openconnect::PLAN_FILE);
            let plan = fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))
                .and_then(|text| openconnect::Plan::parse(&text))?;
            configure_oc(zone, &plan)?;
            let dns: Vec<String> = plan.dns.iter().map(ToString::to_string).collect();
            (dns, plan.search.clone(), Mirror::Oc)
        }
        _ => return Err("the uplink could not build the tunnel".to_string()),
    };

    // --- THE ZONE'S DNS ---
    // The other half of `hide_host_resolvers`: with no daemon left to ask,
    // glibc goes to the servers named here — and they are reachable only
    // through the tunnel. The bind mount is visible inside the zone only: the
    // rest of the system keeps its own /etc/resolv.conf.
    let (text, defaulted) = resolv_conf_with_search(&dns, search.as_deref());
    if defaulted {
        println!(
            "zone {}: nobody named a resolver — taking {} (through the tunnel)",
            zone.name(),
            DEFAULT_RESOLVERS.join(" and ")
        );
    }
    let resolv = zone.path(RESOLV);
    fs::write(&resolv, &text).map_err(|e| format!("cannot write {RESOLV}: {e}"))?;
    // WHERE the mount lands is not /etc/resolv.conf. `mount(2)` follows the
    // symlinks in its target, and on NixOS that path is a chain ending in
    // /run/systemd/resolve/stub-resolv.conf — inside the tmpfs that has just
    // hidden the host's resolved. The last link then dangles, so the file has
    // to be created before anything can be mounted over it; the old code
    // mounted onto whatever the chain happened to point at and would have
    // failed here with a bare ENOENT.
    let target = sys::link_target(Path::new(ETC_RESOLV));
    if !target.exists() {
        if let Some(dir) = target.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        touch(&target).map_err(|e| format!("cannot create {}: {e}", target.display()))?;
    }
    sys::mount(resolv.as_os_str(), &target, "", libc::MS_BIND, "").map_err(|e| {
        format!(
            "cannot bind-mount {RESOLV} over {ETC_RESOLV} ({}): {e}",
            target.display()
        )
    })?;

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

    start_status_mirror(zone, mirror.clone());

    match mirror {
        Mirror::Wg(wgtool) => {
            // The first handshake is the sign that a config is alive — printing
            // it to the journal answers "is this .conf still worth anything?"
            // straight away.
            thread::sleep(HANDSHAKE_AFTER);
            let handshakes = tool_output(&wgtool, &["show", TUN_IFACE, "latest-handshakes"])
                .unwrap_or_default();
            if handshake_seen(&handshakes) {
                println!("zone {}: handshake done — the tunnel is alive", zone.name());
            } else {
                eprintln!(
                    "zone {}: no handshake. Either the config is dead or the server is \
                     unreachable",
                    zone.name()
                );
            }
        }
        Mirror::Oc => {
            // The same question, already answered: an OpenConnect zone only
            // gets this far because the client authenticated and handed the
            // tunnel over, and it takes the zone down with it the moment it
            // stops.
            println!(
                "zone {}: the openconnect client is connected — the tunnel is alive",
                zone.name()
            );
        }
    }
    Ok(())
}

/// Put the WireGuard config onto the interface the uplink handed down.
fn configure_wg(zone: &Zone, cfg: &WgConfig, wgtool: &Path) -> Result<(), String> {
    // Not through `run_tool`: the path of the stripped config is a path, and
    // squeezing it through a `&str` would mangle a `$HOME` that is not UTF-8.
    let setconf = Command::new(wgtool)
        .arg("setconf")
        .arg(TUN_IFACE)
        .arg(zone.path(STRIPPED))
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
    default_into_tunnel(zone)?;
    close_or_tunnel_v6(zone, tunnel_v6)
}

/// Put the gateway's answer onto the tun the OpenConnect client handed down.
///
/// A `/32` and nothing else, which is what the upstream `vpnc-script` does with
/// a point-to-point device too. The netmask the gateway may also have sent is
/// deliberately unused: it would only add an on-link route for a network the
/// default route below already covers, and the split-include list it belongs to
/// is ignored on purpose (`crate::openconnect`).
fn configure_oc(zone: &Zone, plan: &openconnect::Plan) -> Result<(), String> {
    // The name is an invariant, not a detail: the app namespace's filter was
    // loaded minutes ago and names `awg0`. A client that produced anything else
    // would have its packets dropped by our own second echelon, silently.
    if plan.iface != TUN_IFACE {
        return Err(format!(
            "the client built {} instead of {TUN_IFACE} — the app namespace's filter names \
             {TUN_IFACE} and was loaded before the tunnel arrived",
            plan.iface
        ));
    }
    let addr = format!("{}/32", plan.address);
    let mtu = plan.mtu.to_string();
    zone.ip(&["-4", "addr", "replace", addr.as_str(), "dev", TUN_IFACE])?;
    zone.ip(&["link", "set", TUN_IFACE, "mtu", mtu.as_str(), "up"])?;
    default_into_tunnel(zone)?;
    // This backend does not carry IPv6 yet and asks the gateway not to offer
    // it (`--disable-ipv6`), so the family ends here — the same way it does for
    // a WireGuard config without a v6 address.
    close_or_tunnel_v6(zone, false)
}

/// THERE IS NO ROUTE AROUND THE TUNNEL, AND THERE MUST NOT BE.
///
/// The old one-namespace layout needed a /32 to the VPN server through pasta's
/// interface, or the tunnel's own packets would have been wrapped into the
/// tunnel — and that route was visible to the programs, together with pasta's
/// interface and everything else reachable through it. Here the encrypted
/// packets are born in the uplink and leave by ITS default route; this namespace
/// has one interface besides loopback and one route, and both lead into the
/// tunnel. For OpenConnect that is also where the gateway's split-include list
/// goes: a zone routes everything, or it is not a zone.
fn default_into_tunnel(zone: &Zone) -> Result<(), String> {
    zone.ip(&["route", "replace", "default", "dev", TUN_IFACE])
}

/// --- IPv6: INTO THE TUNNEL OR NOWHERE AT ALL ---
///
/// A packet of ANY family must have no path around the tunnel
/// (`docs/LEAK-MODEL.md`). Here that is the topology's doing rather than a
/// rule's: with no other interface there is nothing to leak through even
/// without a single route. The unreachable default is belt and braces — it
/// turns "no route to host" into an immediate error instead of a timeout, and
/// it costs nothing. No sysctl is touched any more: switching the family off was
/// a way to plug a hole that no longer exists.
fn close_or_tunnel_v6(zone: &Zone, tunnel_v6: bool) -> Result<(), String> {
    match v6_plan(Path::new("/proc/net/if_inet6").exists(), tunnel_v6) {
        V6Plan::NoKernel => {}
        V6Plan::IntoTunnel => zone.ip(&["-6", "route", "replace", "default", "dev", TUN_IFACE])?,
        V6Plan::CloseDefault => {
            // THE TYPE COMES BEFORE THE PREFIX. `ip -6 route replace default
            // unreachable` is not a route at all: iproute2 parses "default" as
            // the prefix, then finds a route type with nothing behind it and
            // exits with "Command line is not complete" — measured. The old
            // one-namespace code had the words in that order, so its v6
            // fallback had never once worked; it went unnoticed because the
            // sysctl branch above it usually won. Errors stay quiet: this is
            // belt and braces over a namespace that has no second interface to
            // leak through anyway.
            let _ = zone.ip_quiet(&["-6", "route", "replace", "unreachable", "default"]);
        }
    }
    Ok(())
}

/// What the status mirror watches, which is the one thing the two backends do
/// not have in common.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mirror {
    /// `awg show` / `wg show`, by the path of the tool that speaks to the
    /// interface.
    Wg(PathBuf),
    /// There is no `show` for an OpenConnect tunnel: liveness is the interface
    /// being there and up, and the client — which the uplink is waiting on —
    /// still running.
    Oc,
}

/// Mirror the tunnel's state into the zone's `status` file.
///
/// `wg show` needs netlink privileges, and programs (and `vpn-zone status`)
/// enter the zone under the ordinary uid and see nothing at all — so the state
/// is written from in here, where the privileges are. It has to be this
/// namespace and not the uplink: `show` reads the interface over netlink in the
/// CURRENT namespace, and the interface lives here — and for an OpenConnect zone
/// the interface is the only thing there is to read. The rename is what makes a
/// reader see either the old file or the new one, never half of one.
/// (`docs/GOTCHAS.md` §4)
fn start_status_mirror(zone: &Zone, mirror: Mirror) {
    let status = zone.path(STATUS);
    let tmp = zone.path(STATUS_TMP);
    let ip = zone.tools.ip.clone();
    thread::spawn(move || loop {
        let text = match &mirror {
            Mirror::Wg(tool) => tool_output(tool, &["show", TUN_IFACE]).ok(),
            Mirror::Oc => Some(oc_mirror(
                &tool_output(&ip, &["-o", "link", "show", TUN_IFACE]).unwrap_or_default(),
                &tool_output(&ip, &["-br", "-4", "addr", "show", TUN_IFACE]).unwrap_or_default(),
            )),
        };
        if let Some(text) = text {
            if fs::write(&tmp, text).is_ok() {
                let _ = fs::rename(&tmp, &status);
            }
        }
        thread::sleep(STATUS_PERIOD);
    });
}

/// The status file of an OpenConnect zone, as a pure function of two `ip`
/// dumps.
///
/// `vpn-zone check` reads this file and answers "is the tunnel alive". For
/// WireGuard the answer is the handshake line; here it is the `connected:` line
/// below, and it is written only when the interface is BOTH present and up —
/// which for this backend really is the whole question, because the client
/// dying takes the interface and then the zone with it.
pub fn oc_mirror(link: &str, addr: &str) -> String {
    // The flags, and only the flags. `ip -o link show` prints them between
    // angle brackets — `<POINTOPOINT,NOARP,UP,LOWER_UP>` — and a substring
    // search for "UP" would find LOWER_UP, NO-CARRIER and half the operstates
    // as well.
    let up = link
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|flag| flag == "UP"));
    let mut text = format!("interface: {TUN_IFACE}\n  backend: openconnect\n");
    if link.trim().is_empty() {
        text.push_str("  disconnected: the tunnel interface is gone\n");
        return text;
    }
    if !up {
        text.push_str("  disconnected: the tunnel interface is down\n");
        return text;
    }
    // The word `check` greps for. Deliberately not "latest handshake": there is
    // no handshake here and pretending otherwise would be a lie in a file a
    // human reads.
    text.push_str("  connected: yes\n");
    let addr = addr.split_whitespace().nth(2).unwrap_or("").trim();
    if !addr.is_empty() {
        text.push_str("  address: ");
        text.push_str(addr);
        text.push('\n');
    }
    text
}

/// Close every resolver of the HOST off from the zone.
///
/// The topology cannot do this one. A name is resolved by asking a daemon over
/// a UNIX SOCKET, and a socket is not an interface: it has no route to remove,
/// no interface to leave by and no packet for a filter to see. The daemon on
/// the other end sits in the host's network and answers from there — so with
/// the socket in reach, `getaddrinfo` inside a zone goes around the tunnel no
/// matter how hermetic the namespace is, and swapping resolv.conf does not cure
/// it either.
///
/// Both known leaks are real, both were measured on a live zone:
///
/// * **nsncd** (`/run/nscd/socket`), which NixOS runs: `getent` answered while
///   awg0 still had RX=0 — the query had never touched the tunnel.
/// * **systemd-resolved** (`/run/systemd/resolve/io.systemd.Resolve`), which
///   nss-resolve talks varlink to. NixOS puts `resolve` FIRST in
///   `/etc/nsswitch.conf`, ahead of `dns`, so with resolved enabled EVERY
///   lookup in the zone went to the host's resolver: a leak test run in a
///   browser inside a zone named the user's real ISP as the resolver, while
///   `curl ifconfig.me` in the same zone correctly showed the VPN's address.
///   `resolvectl status` from inside the zone answering at all is the tell.
///
/// avahi (nss-mdns) is here for the same reason before anyone measures it: it
/// would put the name onto the host's LAN.
///
/// A tmpfs over the directory hides the socket inside the zone only, and the
/// zone's mount tree is private — the daemons keep serving the rest of the
/// system exactly as before. glibc then finds nothing to ask, nss-resolve
/// answers UNAVAIL (which is precisely the case `[!UNAVAIL=return]` in
/// nsswitch.conf falls through) and the `dns` module goes to the servers in the
/// zone's own resolv.conf — through the tunnel.
///
/// A failure here is fatal to the zone, and that is the fail-closed rule: a
/// zone that comes up while its programs resolve names in the host's network is
/// worse than no zone, because it looks exactly like a working one.
/// (`docs/GOTCHAS.md` §3, `docs/LEAK-MODEL.md`)
fn hide_host_resolvers(zone: &Zone) -> Result<(), String> {
    let mut hidden: Vec<&str> = Vec::new();
    for group in RESOLVER_DIRS {
        if let Some(dir) = hide_first(group)? {
            hidden.push(dir);
        }
    }
    // One line, and it is worth its place in the journal: this is where the
    // question "could a name have gone around the tunnel?" is answered.
    println!(
        "zone {}: host resolvers hidden ({})",
        zone.name(),
        if hidden.is_empty() {
            "none running".to_string()
        } else {
            hidden.join(", ")
        }
    );
    Ok(())
}

/// Cover the first of `dirs` that exists with an empty tmpfs, and say which.
fn hide_first<'a>(dirs: &[&'a str]) -> Result<Option<&'a str>, String> {
    for &dir in dirs {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        sys::mount(OsStr::new("tmpfs"), path, "tmpfs", 0, "mode=0755,size=64k").map_err(|e| {
            format!("cannot hide the host's resolver at {dir}: {e} — the zone would leak DNS")
        })?;
        return Ok(Some(dir));
    }
    Ok(None)
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
/// case — verified, and the zone was then declared routeless while it was not.
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

/// What to do about IPv6 in the app namespace, as a pure decision.
///
/// Shorter than it used to be, and that is the point: there is no "switch the
/// family off" case any more. IPv6 could leak while the zone had pasta's
/// interface in it; now the only interface besides loopback is the tunnel, so
/// the choice is between routing v6 into it and leaving it with no default at
/// all. The endpoint plays no part either — its family is the uplink's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V6Plan {
    /// A kernel without IPv6 at all: nothing to do.
    NoKernel,
    /// The tunnel carries v6, so the v6 default goes into it.
    IntoTunnel,
    /// No v6 in the tunnel: close the default and let the family end here.
    CloseDefault,
}

pub fn v6_plan(kernel_has_v6: bool, tunnel_has_v6: bool) -> V6Plan {
    if !kernel_has_v6 {
        V6Plan::NoKernel
    } else if tunnel_has_v6 {
        V6Plan::IntoTunnel
    } else {
        V6Plan::CloseDefault
    }
}

// --- THE SECOND ECHELON: THE TWO RULESETS ------------------------------------

/// One endpoint as the uplink's filter sees it: an address the tunnel may talk
/// to and, when the config bothered to say so, the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointSocket {
    pub addr: IpAddr,
    pub port: Option<u16>,
}

/// Every endpoint of a config that has already been through
/// [`WgConfig::resolve_endpoints`] — in file order, without duplicates.
///
/// An endpoint that is still a NAME cannot get this far (`prepare` refuses to
/// start a zone whose endpoint did not resolve) and is skipped rather than
/// guessed at: a filter built out of an address nobody has would be a filter
/// that lies.
pub fn endpoint_sockets(cfg: &WgConfig) -> Vec<EndpointSocket> {
    let mut out: Vec<EndpointSocket> = Vec::new();
    for section in &cfg.sections {
        for entry in &section.entries {
            if !entry.key.eq_ignore_ascii_case("Endpoint") {
                continue;
            }
            let Some(endpoint) = Endpoint::parse(&entry.value) else {
                continue;
            };
            let EndpointHostKind::Literal(addr) = endpoint_host_kind(&endpoint) else {
                continue;
            };
            let socket = EndpointSocket {
                addr,
                port: endpoint.port,
            };
            // Several peers of one server are one rule, not three.
            if !out.contains(&socket) {
                out.push(socket);
            }
        }
    }
    out
}

/// Neighbour discovery, without which a v6 endpoint is simply unreachable.
///
/// pasta hands the namespace a v6 default `via fe80::1`, and the kernel cannot
/// send a single packet there before it has resolved that address — with an
/// ICMPv6 neighbour solicitation, which the output hook sees like any other
/// packet. Drop it and the tunnel never gets off the ground. IPv4 needs no such
/// exception: ARP is not in the `inet` family at all (it has a family of its
/// own), so an `inet` filter never touches it.
///
/// Nothing can be smuggled out this way: these three types are link-local
/// multicast, and the only thing on that link is pasta.
const NDP_RULE: &str =
    "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept";

/// The app namespace's ruleset: out through the tunnel, or nowhere.
///
/// `oifname` and not `oif` on purpose. `oif` is resolved to an interface INDEX
/// when the rule is loaded, which would mean the rule has to be loaded after the
/// tunnel has arrived and would silently stop matching if the interface were
/// ever recreated; `oifname` compares the name every time, so the ruleset can go
/// in before the tunnel does and keeps meaning what it says afterwards.
pub fn app_ruleset() -> String {
    output_table(&[
        "oifname \"lo\" accept".to_string(),
        format!("oifname \"{TUN_IFACE}\" accept"),
    ])
}

/// The uplink's ruleset: the tunnel's own packets to the endpoint, and nothing
/// else.
///
/// The addresses are literals we resolved ourselves in the host's network
/// before any namespace existed, so there is nothing here to escape or to look
/// up. No DNS rule and no ICMP rule either, for the same reason: by the time
/// this namespace exists, every name in the config is already an address.
///
/// A config whose endpoints are all unusable ends up with a loopback-only
/// ruleset, which is the fail-closed answer to a tunnel that has nowhere to go —
/// and the holder has already said so out loud.
pub fn uplink_ruleset(endpoints: &[EndpointSocket]) -> String {
    let mut rules = vec!["oifname \"lo\" accept".to_string()];
    let mut needs_ndp = false;
    for endpoint in endpoints {
        let (family, addr) = match endpoint.addr {
            IpAddr::V4(addr) => ("ip", addr.to_string()),
            IpAddr::V6(addr) => {
                needs_ndp = true;
                ("ip6", addr.to_string())
            }
        };
        // A port is what the config wrote; without one `setconf` would have
        // rejected the endpoint anyway, so the rule stays as wide as the
        // address and no wider.
        rules.push(match endpoint.port {
            Some(port) => format!("{family} daddr {addr} udp dport {port} accept"),
            None => format!("{family} daddr {addr} accept"),
        });
    }
    if needs_ndp {
        rules.push(NDP_RULE.to_string());
    }
    output_table(&rules)
}

/// Wrap accept rules into the one table and chain both namespaces get.
///
/// Only `output` is filtered. There is no point in an input chain: the app
/// namespace can be reached from the tunnel alone, the uplink from pasta alone,
/// and neither of those becomes safer for being filtered here — what this is
/// about is packets LEAVING somewhere they should not.
fn output_table(rules: &[String]) -> String {
    let mut text = String::new();
    text.push_str("table inet ");
    text.push_str(NFT_TABLE);
    text.push_str(" {\n");
    text.push_str("\tchain output {\n");
    text.push_str("\t\ttype filter hook output priority filter; policy drop;\n");
    for rule in rules {
        text.push_str("\t\t");
        text.push_str(rule);
        text.push('\n');
    }
    text.push_str("\t}\n");
    text.push_str("}\n");
    text
}

/// The zone's `/etc/resolv.conf` and whether the default had to be used.
///
/// A config without `DNS=` used to leave the zone with the host's resolv.conf,
/// where the resolver is a local one (192.168.1.1, or the 127.0.0.53 stub) that
/// cannot be reached from inside: names simply stopped resolving, and it looked
/// like "there is internet but nothing opens". (`docs/GOTCHAS.md` §3)
pub fn resolv_conf(dns: &[String]) -> (String, bool) {
    resolv_conf_with_search(dns, None)
}

/// The same, plus the `search` line an OpenConnect gateway asks for.
///
/// A search domain is what makes a corporate zone usable at all (`wiki` has to
/// mean `wiki.corp.example.org`), and it opens no channel: the extra query goes
/// to the same resolvers, which are reachable only through the tunnel. What
/// the gateway may NOT do is write a line of its own — the domain is checked
/// for being a domain long before it gets here (`crate::openconnect`), and the
/// resolvers are checked for being addresses.
pub fn resolv_conf_with_search(dns: &[String], search: Option<&str>) -> (String, bool) {
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
    if let Some(search) = search.filter(|s| !s.is_empty()) {
        text.push_str("search ");
        text.push_str(search);
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
/// `ahostsv6` gave. This has to happen before either namespace exists, while
/// the resolver is still the host's.
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

/// Hand a ruleset to `nft -f -` on stdin.
///
/// On stdin and not in a file: the ruleset is generated, it has no business
/// existing on disk, and a file would need a directory that both namespaces can
/// write to. nft's own diagnostics go to the journal untouched — when a ruleset
/// is refused, the line and the reason are the only things worth having.
fn feed_nft(nft: &Path, ruleset: &str) -> Result<(), String> {
    let mut child = Command::new(nft)
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                format!("{} is not there", nft.display())
            } else {
                format!("cannot run {}: {e}", nft.display())
            }
        })?;
    // Taken out of the child so the pipe closes at the end of this statement:
    // `nft -f -` reads to EOF and would wait for one forever.
    let fed = match child.stdin.take() {
        Some(mut pipe) => pipe
            .write_all(ruleset.as_bytes())
            .map_err(|e| format!("cannot hand the ruleset to nft: {e}")),
        None => Err("nft was given no stdin".to_string()),
    };
    // Reap first, report second: a child that died on its own must not be left
    // behind just because the write end noticed it first.
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for {}: {e}", nft.display()))?;
    fed?;
    if !status.success() {
        return Err(format!("{} -f - failed ({status})", nft.display()));
    }
    Ok(())
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
            "--ip",
            "/n/ip",
            "--awg",
            "/n/awg",
            "--wg",
            "/n/wg",
            "--pasta",
            "/n/pasta",
            "--nft",
            "/n/nft",
            "--openconnect",
            "/n/openconnect",
            "nl",
        ]))
        .unwrap();
        assert_eq!(parsed.name, OsString::from("nl"));
        assert_eq!(parsed.tools.ip, PathBuf::from("/n/ip"));
        assert_eq!(parsed.tools.awg, PathBuf::from("/n/awg"));
        assert_eq!(parsed.tools.wg, PathBuf::from("/n/wg"));
        assert_eq!(parsed.tools.pasta, PathBuf::from("/n/pasta"));
        assert_eq!(parsed.tools.nft, PathBuf::from("/n/nft"));
        assert_eq!(parsed.tools.openconnect, PathBuf::from("/n/openconnect"));
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

        // No route at all: both fields empty, and the uplink fails loudly.
        assert_eq!(parse_default_route(""), DefaultRoute::default());
    }

    #[test]
    fn ipv6_is_either_tunnelled_or_left_without_a_default() {
        // A kernel without v6: nothing to do.
        assert_eq!(v6_plan(false, false), V6Plan::NoKernel);
        assert_eq!(v6_plan(false, true), V6Plan::NoKernel);
        // The tunnel carries v6 — the default goes into it.
        assert_eq!(v6_plan(true, true), V6Plan::IntoTunnel);
        // It does not: no default at all. There is nothing else in this
        // namespace for the family to leak through, so no sysctl is needed.
        assert_eq!(v6_plan(true, false), V6Plan::CloseDefault);
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
    fn a_gateways_search_domain_becomes_one_more_line_and_no_more() {
        let (text, _) = resolv_conf_with_search(
            &["10.5.0.1".to_string()],
            Some("corp.example.org"),
        );
        assert_eq!(text, "nameserver 10.5.0.1\nsearch corp.example.org\n");

        // No domain, no line — and an empty one is no domain.
        let (text, _) = resolv_conf_with_search(&["10.5.0.1".to_string()], None);
        assert_eq!(text, "nameserver 10.5.0.1\n");
        let (text, _) = resolv_conf_with_search(&["10.5.0.1".to_string()], Some(""));
        assert_eq!(text, "nameserver 10.5.0.1\n");

        // A gateway that names no resolver at all still gets the project's
        // default ones — reachable through the tunnel and nowhere else.
        let (text, defaulted) = resolv_conf_with_search(&[], Some("corp.example.org"));
        assert!(defaulted);
        assert_eq!(
            text,
            "nameserver 1.1.1.1\nnameserver 9.9.9.9\nsearch corp.example.org\n"
        );
    }

    #[test]
    fn the_openconnect_mirror_says_connected_only_while_the_interface_is_up() {
        let up = "5: awg0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1412 qdisc fq_codel \
                  state UNKNOWN mode DEFAULT group default qlen 500\\    link/none";
        let addr = "awg0             UNKNOWN        10.5.0.7/32";
        assert_eq!(
            oc_mirror(up, addr),
            "interface: awg0\n  backend: openconnect\n  connected: yes\n  address: 10.5.0.7/32\n"
        );

        // Down, and gone, are different answers and neither of them says
        // "connected" — which is the word `vpn-zone check` looks for.
        let down = "5: awg0: <POINTOPOINT,MULTICAST,NOARP> mtu 1412 qdisc noop state DOWN mode \
                    DEFAULT group default qlen 500\\    link/none";
        assert!(oc_mirror(down, "").contains("disconnected: the tunnel interface is down"));
        assert!(!oc_mirror(down, "").contains("connected: yes"));
        assert!(oc_mirror("", "").contains("disconnected: the tunnel interface is gone"));

        // LOWER_UP without UP is not up: a substring search for "UP" would have
        // said otherwise.
        let carrier_only = "5: awg0: <POINTOPOINT,NOARP,LOWER_UP> mtu 1412 state DOWN";
        assert!(oc_mirror(carrier_only, "").contains("disconnected"));

        // An interface that is up but has no address yet is still connected;
        // the address line is simply absent.
        assert_eq!(
            oc_mirror(up, "awg0             UNKNOWN"),
            "interface: awg0\n  backend: openconnect\n  connected: yes\n"
        );
    }

    #[test]
    fn an_openconnect_uplink_may_talk_to_its_gateway_and_to_nothing_else() {
        let backend = Backend::Oc(Box::new(OcZone {
            cfg: OcConfig::parse(b"[OpenConnect]\nServer = vpn.example.org:4443\n").unwrap(),
            addr: "198.51.100.7".parse().unwrap(),
        }));
        // No port in the rule, and that is the one place this backend is wider
        // than WireGuard's: DTLS goes to a UDP port the server picks, and the
        // number is not known before the session exists. What the rule says is
        // still "this gateway and nothing else in the world".
        assert_eq!(
            uplink_ruleset(&backend.sockets()),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\tip daddr 198.51.100.7 accept\n",
                "\t}\n",
                "}\n",
            )
        );

        // And a WireGuard zone's rules are unchanged by any of this.
        let wg = Backend::Wg(
            WgConfig::parse_str(
                "[Interface]\nPrivateKey = k\n[Peer]\nEndpoint = 198.51.100.7:51820\n",
            )
            .unwrap(),
        );
        assert!(uplink_ruleset(&wg.sockets()).contains("ip daddr 198.51.100.7 udp dport 51820"));
    }

    /// A guard over a security invariant rather than over an algorithm: every
    /// entry in this table is a measured DNS leak (`docs/GOTCHAS.md` §3), and
    /// dropping one gives every program in every zone a resolver in the host's
    /// network back. The behaviour itself is asserted where it can be — inside
    /// a VM with systemd-resolved running (`tests/vm.nix`).
    #[test]
    fn every_known_host_resolver_socket_is_in_the_table() {
        let all: Vec<&str> = RESOLVER_DIRS
            .iter()
            .flat_map(|g| g.iter().copied())
            .collect();
        for must in [
            // nsncd, what NixOS runs.
            "/run/nscd",
            // systemd-resolved's varlink socket: nss-resolve, and `resolve`
            // comes BEFORE `dns` in nsswitch.conf.
            "/run/systemd/resolve",
            // nss-mdns.
            "/run/avahi-daemon",
        ] {
            assert!(all.contains(&must), "{must} is no longer hidden from zones");
        }
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
    fn a_literal_endpoint_survives_the_resolver_unchanged() {
        // What `prepare` does to a config that needs no DNS at all: the text
        // handed to `setconf` must still carry the very same endpoint.
        let text = "[Interface]\n\
                    PrivateKey = U1lOVEhFVElDLUtFWS1BLURPLU5PVC1VU0UtMDAwMDAwMDA9\n\
                    [Peer]\n\
                    Endpoint = 198.51.100.7:51820\n";
        let mut cfg = WgConfig::parse_str(text).unwrap();
        let resolved = cfg.resolve_endpoints(resolve_endpoint);
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].addr,
            Some("198.51.100.7".parse::<IpAddr>().unwrap())
        );
        assert!(cfg.to_setconf().contains("Endpoint = 198.51.100.7:51820"));
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

    #[test]
    fn the_app_ruleset_lets_nothing_out_but_the_tunnel() {
        // `oifname`, not `oif`: the rule must not depend on an interface index
        // that does not exist yet when the ruleset is loaded.
        assert_eq!(
            app_ruleset(),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\toifname \"awg0\" accept\n",
                "\t}\n",
                "}\n",
            )
        );
    }

    #[test]
    fn the_uplink_ruleset_opens_the_tunnel_transport_and_nothing_else() {
        let v4 = [EndpointSocket {
            addr: "198.51.100.7".parse().unwrap(),
            port: Some(51820),
        }];
        assert_eq!(
            uplink_ruleset(&v4),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\tip daddr 198.51.100.7 udp dport 51820 accept\n",
                "\t}\n",
                "}\n",
            )
        );

        // No endpoint at all: loopback only. A tunnel with nowhere to go is
        // already fatal-ish (the holder says so), and the answer to "which
        // packets may leave" is "none" rather than "all of them".
        let empty = uplink_ruleset(&[]);
        assert!(empty.contains("policy drop;"));
        assert!(empty.contains("oifname \"lo\" accept"));
        assert!(!empty.contains("daddr"));
    }

    #[test]
    fn a_v6_endpoint_brings_neighbour_discovery_with_it() {
        // Without the ND exception the kernel cannot even resolve pasta's
        // fe80::1, and a v6 tunnel never sends its first packet. v4 needs no
        // counterpart: ARP is not in the `inet` family.
        let v6 = [EndpointSocket {
            addr: "2001:db8::1".parse().unwrap(),
            port: Some(443),
        }];
        assert_eq!(
            uplink_ruleset(&v6),
            concat!(
                "table inet vpnzone {\n",
                "\tchain output {\n",
                "\t\ttype filter hook output priority filter; policy drop;\n",
                "\t\toifname \"lo\" accept\n",
                "\t\tip6 daddr 2001:db8::1 udp dport 443 accept\n",
                "\t\ticmpv6 type { nd-router-solicit, nd-neighbor-solicit, \
                 nd-neighbor-advert } accept\n",
                "\t}\n",
                "}\n",
            )
        );

        // Two families, one ND rule.
        let both = uplink_ruleset(&[
            EndpointSocket {
                addr: "198.51.100.7".parse().unwrap(),
                port: Some(51820),
            },
            EndpointSocket {
                addr: "2001:db8::1".parse().unwrap(),
                port: Some(51820),
            },
        ]);
        assert_eq!(both.matches("icmpv6 type").count(), 1);
        assert!(both.contains("ip daddr 198.51.100.7 udp dport 51820 accept"));
        assert!(both.contains("ip6 daddr 2001:db8::1 udp dport 51820 accept"));

        // An endpoint written without a port: the rule is as wide as the
        // address and no wider.
        let portless = uplink_ruleset(&[EndpointSocket {
            addr: "198.51.100.7".parse().unwrap(),
            port: None,
        }]);
        assert!(portless.contains("\t\tip daddr 198.51.100.7 accept\n"));
        assert!(!portless.contains("dport"));
    }

    #[test]
    fn endpoints_of_the_config_become_the_uplinks_rules() {
        let text = "[Interface]\n\
                    PrivateKey = U1lOVEhFVElDLUtFWS1BLURPLU5PVC1VU0UtMDAwMDAwMDA9\n\
                    [Peer]\n\
                    Endpoint = 198.51.100.7:51820\n\
                    [Peer]\n\
                    Endpoint = 198.51.100.7:51820\n\
                    [Peer]\n\
                    Endpoint = [2001:db8::1]:51820\n\
                    [Peer]\n\
                    Endpoint = vpn.example.org:51820\n";
        let cfg = WgConfig::parse_str(text).unwrap();
        // Two peers behind one server are one rule; a name that never got
        // resolved is left out rather than guessed at.
        assert_eq!(
            endpoint_sockets(&cfg),
            vec![
                EndpointSocket {
                    addr: "198.51.100.7".parse().unwrap(),
                    port: Some(51820),
                },
                EndpointSocket {
                    addr: "2001:db8::1".parse().unwrap(),
                    port: Some(51820),
                },
            ]
        );

        // And a config that has no peers at all yields no rules.
        let bare = WgConfig::parse_str("[Interface]\nListenPort = 51820\n").unwrap();
        assert!(endpoint_sockets(&bare).is_empty());
    }
}
