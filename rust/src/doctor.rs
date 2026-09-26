//! `vpn-zone doctor` (ROADMAP M5): what is really in place, checked from where
//! a program would see it.
//!
//! The rule this command exists for is in `docs/LEAK-MODEL.md`: a channel is
//! closed when something shows it closed, not when reasoning says there is
//! nowhere to go. The DNS leak through nss-resolve was found by a browser leak
//! test on a live machine while every document said "closed". So the zone
//! checks run INSIDE the zone — `nsenter` into its namespaces and a probe
//! (`vpn-zone-core doctor-probe`) that reads what a program there would read —
//! and the host only compares.
//!
//! Four levels, and the difference between the middle two is the point:
//!
//! * `ok` — the property holds;
//! * `warn` — a channel the project KNOWS is open and names in
//!   `docs/LEAK-MODEL.md` ("open channels"): the session bus, `systemd --user`,
//!   the system bus, X11. Reported every time, so that nobody reads the absence
//!   of a failure as the absence of a way out;
//! * `fail` — a property the project promises does not hold: a second way out
//!   of the zone, a host resolver in reach, the host's `nsswitch.conf`;
//! * `skip` — could not be checked, and says why.
//!
//! The unix sockets a program of the zone can connect to are listed one by one
//! (`crate::sockets`): a `sockets` summary with the zone's own, and a `socket`
//! line for every other one — `warn`, or `fail` where the project promises it
//! out of reach.
//!
//! The probe prints one line per check, `id<TAB>level<TAB>detail`: a stable,
//! trivial format across a namespace boundary, where the two sides may even be
//! different builds for a moment after an update.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::cli::{visible_entries, zone_pid};
use crate::status::string as json_string;
use crate::tools::Tools;

/// The one link a zone's app namespace may have besides loopback: every
/// backend brings its tunnel up under this name (`crate::zone`).
pub const TUNNEL: &str = "awg0";

/// How a check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Skip,
    Warn,
    Fail,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Skip => "skip",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "ok" => Some(Self::Ok),
            "skip" => Some(Self::Skip),
            "warn" => Some(Self::Warn),
            "fail" => Some(Self::Fail),
            _ => None,
        }
    }

    fn mark(self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Skip => "·",
            Self::Warn => "⚠",
            Self::Fail => "✗",
        }
    }
}

/// One check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: String,
    pub level: Level,
    pub detail: String,
}

impl Check {
    pub fn new(id: &str, level: Level, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_owned(),
            level,
            detail: detail.into(),
        }
    }

    /// The probe's line: tabs and newlines in the detail become spaces.
    pub fn line(&self) -> String {
        let detail: String = self
            .detail
            .chars()
            .map(|c| if c == '\t' || c == '\n' { ' ' } else { c })
            .collect();
        format!("{}\t{}\t{detail}", self.id, self.level.as_str())
    }

    pub fn parse_line(line: &str) -> Option<Self> {
        let mut parts = line.splitn(3, '\t');
        let id = parts.next()?;
        let level = Level::parse(parts.next()?)?;
        Some(Self::new(id, level, parts.next().unwrap_or("")))
    }

    fn json(&self) -> String {
        format!(
            "{{\"id\":{},\"level\":{},\"detail\":{}}}",
            json_string(&self.id),
            json_string(self.level.as_str()),
            json_string(&self.detail)
        )
    }
}

// --- PURE EVALUATORS -----------------------------------------------------------

/// The interface names of a `/proc/net/dev`.
pub fn interfaces(net_dev: &str) -> Vec<String> {
    net_dev
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .collect()
}

/// A zone has loopback and at most its tunnel: anything else is a second way
/// out, around the tunnel.
pub fn links_check(links: &[String]) -> Check {
    let others: Vec<&str> = links
        .iter()
        .map(String::as_str)
        .filter(|l| *l != "lo" && *l != TUNNEL)
        .collect();
    if !others.is_empty() {
        return Check::new(
            "links",
            Level::Fail,
            format!("в зоне есть выход мимо туннеля: {}", others.join(", ")),
        );
    }
    if links.iter().any(|l| l == TUNNEL) {
        Check::new("links", Level::Ok, format!("lo и {TUNNEL}, больше ничего"))
    } else {
        Check::new("links", Level::Ok, "только lo: сети нет вовсе")
    }
}

/// The interfaces of the IPv4 default routes in a `/proc/net/route`.
pub fn default_routes4(route: &str) -> Vec<String> {
    route
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            (f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000").then(|| f[0].to_owned())
        })
        .collect()
}

/// The interfaces of the IPv6 default routes in a `/proc/net/ipv6_route`,
/// without the kernel's own unreachable ones (`RTF_REJECT` on `lo`).
pub fn default_routes6(route: &str) -> Vec<String> {
    const RTF_REJECT: u32 = 0x0200;
    route
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 || f[0].bytes().any(|b| b != b'0') || f[1] != "00" {
                return None;
            }
            let flags = u32::from_str_radix(f[8], 16).unwrap_or(0);
            (flags & RTF_REJECT == 0).then(|| f[9].to_owned())
        })
        .collect()
}

/// Every default route goes into the tunnel, or there is none.
pub fn routes_check(id: &str, family: &str, routes: &[String]) -> Check {
    let around: Vec<&str> = routes
        .iter()
        .map(String::as_str)
        .filter(|r| *r != TUNNEL)
        .collect();
    if !around.is_empty() {
        Check::new(
            id,
            Level::Fail,
            format!(
                "маршрут {family} по умолчанию мимо туннеля: {}",
                around.join(", ")
            ),
        )
    } else if routes.is_empty() {
        Check::new(id, Level::Ok, format!("маршрута {family} наружу нет"))
    } else {
        Check::new(id, Level::Ok, format!("{family} по умолчанию — в {TUNNEL}"))
    }
}

/// The zone's own `nsswitch.conf` says `hosts: files dns`, and nothing else
/// that could ask a daemon of the host.
pub fn nsswitch_check(text: Option<&str>) -> Check {
    let Some(text) = text else {
        return Check::new(
            "nsswitch",
            Level::Ok,
            "nsswitch.conf нет: встроенный порядок glibc без демонов",
        );
    };
    let hosts = text.lines().find_map(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        line.strip_prefix("hosts:").map(|rest| {
            rest.split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<String>>()
        })
    });
    match hosts {
        Some(words) if words == ["files", "dns"] => {
            Check::new("nsswitch", Level::Ok, "hosts: files dns")
        }
        Some(words) => Check::new(
            "nsswitch",
            Level::Fail,
            format!(
                "hosts: {} — модули кроме files и dns могут спросить демона хоста; \
                 зона поднята без своего nsswitch.conf (перезапусти её)",
                words.join(" ")
            ),
        ),
        None => Check::new("nsswitch", Level::Ok, "строки hosts: нет — files dns"),
    }
}

/// The nameservers of a `resolv.conf`.
pub fn nameservers(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                (Some("nameserver"), Some(address)) => Some(address.to_owned()),
                _ => None,
            }
        })
        .collect()
}

pub fn resolv_check(text: Option<&str>) -> Check {
    match text.map(nameservers) {
        None => Check::new(
            "resolv",
            Level::Warn,
            "resolv.conf не читается: имена не резолвятся",
        ),
        Some(servers) if servers.is_empty() => Check::new(
            "resolv",
            Level::Warn,
            "в resolv.conf нет серверов: имена не резолвятся",
        ),
        Some(servers) => Check::new(
            "resolv",
            Level::Ok,
            format!("серверы имён: {}", servers.join(", ")),
        ),
    }
}

/// Sockets of the host's resolvers: must not be visible in a zone.
pub const RESOLVER_SOCKETS: [&str; 5] = [
    "/run/nscd/socket",
    "/var/run/nscd/socket",
    "/run/systemd/resolve/io.systemd.Resolve",
    "/run/systemd/resolve/io.systemd.Resolve.Monitor",
    "/run/avahi-daemon/socket",
];

pub fn resolver_sockets_check(present: &[&str]) -> Check {
    if present.is_empty() {
        Check::new(
            "resolvers",
            Level::Ok,
            "сокетов резолверов хоста (nscd, systemd-resolved, avahi) не видно",
        )
    } else {
        Check::new(
            "resolvers",
            Level::Fail,
            format!(
                "виден резолвер хоста — имена уйдут мимо туннеля: {}",
                present.join(", ")
            ),
        )
    }
}

/// The channels `docs/LEAK-MODEL.md` lists as open, as they are seen in this
/// namespace: `(id, path, what it is)`.
pub fn open_channels(uid: u32) -> Vec<(&'static str, PathBuf, &'static str)> {
    vec![
        (
            "session-bus",
            PathBuf::from(format!("/run/user/{uid}/bus")),
            "сессионная шина: порталы и systemd --user — запуск процесса вне зоны \
             (LEAK-MODEL, открытые каналы §1–2)",
        ),
        (
            "systemd-user",
            PathBuf::from(format!("/run/user/{uid}/systemd/private")),
            "сокет systemd --user: запуск процесса вне зоны (§1)",
        ),
        (
            "system-bus",
            PathBuf::from("/run/dbus/system_bus_socket"),
            "системная шина: NetworkManager, hostname1, resolve1 (§3)",
        ),
        (
            "x11",
            PathBuf::from("/tmp/.X11-unix"),
            "сокеты X-сервера хоста: окна, ввод и буфер обмена всей машины (§7)",
        ),
    ]
}

/// A known open channel: `warn` while it is there.
pub fn open_channel_check(id: &str, what: &str, open: bool) -> Check {
    if open {
        Check::new(id, Level::Warn, format!("открыт — {what}"))
    } else {
        Check::new(id, Level::Ok, "не виден")
    }
}

/// Is there a socket or anything else at this path (an X11 directory counts
/// only with an entry in it)? Reached one component at a time, never through
/// a link a program may have made and never into a network or FUSE
/// filesystem (`crate::sockets::present_at`): in a hermetic zone
/// `systemd/` is absent and a program may put a link there — into the
/// document portal's FUSE mount, whose server it has stopped.
fn reachable(path: &Path, slow: &crate::sockets::Slow) -> bool {
    crate::sockets::present_at(path.as_os_str().as_bytes(), slow)
}

// --- THE PROBE (inside a zone) -------------------------------------------------

/// What the doctor tells the probe about the zone, after the uid:
/// `--zone=<name>`, `--hermetic`, `--nix-daemon`, `--audio-manager` (what the
/// zone is to be — its
/// setting, read the way the holder reads it), `--host-devs=<maj:min>,…` (the
/// host's own mounts, so that the probe can tell a filesystem only the zone
/// has, `crate::sockets::own_devs`) and `--closed=<kind:maj:min:ino>,…` (the
/// host's sockets promised out of the zone's reach, by identity,
/// `crate::sockets::parse_closed`). Anything else is ignored: the two sides
/// may be different builds for a moment after an update.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeArgs {
    pub uid: u32,
    pub zone: Option<String>,
    pub hermetic: bool,
    pub nix_daemon: bool,
    pub audio_manager: bool,
    /// `None` when the doctor did not say (an older one, or the probe run by
    /// hand): then nothing is the zone's own by its device.
    pub host_devs: Option<HashSet<crate::sockets::Dev>>,
    pub closed: HashMap<(crate::sockets::Dev, u64), crate::sockets::HostSocket>,
}

impl ProbeArgs {
    pub fn parse(args: &[OsString]) -> Option<Self> {
        let uid = args.first()?.to_str()?.parse::<u32>().ok()?;
        let mut parsed = Self {
            uid,
            ..Self::default()
        };
        for arg in &args[1..] {
            let Some(arg) = arg.to_str() else {
                continue;
            };
            match arg {
                "--hermetic" => parsed.hermetic = true,
                "--nix-daemon" => parsed.nix_daemon = true,
                "--audio-manager" => parsed.audio_manager = true,
                _ => {
                    if let Some(name) = arg.strip_prefix("--zone=") {
                        // A name, never a path: compared with one component.
                        parsed.zone = Some(name.to_owned())
                            .filter(|n| !n.is_empty() && !n.contains('/') && n != "." && n != "..");
                    }
                    if let Some(list) = arg.strip_prefix("--closed=") {
                        parsed.closed = crate::sockets::parse_closed(list);
                    }
                    if let Some(list) = arg.strip_prefix("--host-devs=") {
                        // One unreadable entry and the list is not the
                        // host's: better none than a wrong one.
                        let devs: Option<HashSet<_>> =
                            list.split(',').map(crate::sockets::parse_dev).collect();
                        parsed.host_devs = devs.filter(|d| !d.is_empty());
                    }
                }
            }
        }
        Some(parsed)
    }
}

/// Every check a program in this namespace can answer.
pub fn probe(args: &ProbeArgs, groups_shed: bool) -> Vec<Check> {
    let uid = args.uid;
    let read = |path: &str| fs::read_to_string(path).ok();
    let mut checks = Vec::new();
    match read("/proc/net/dev") {
        Some(dev) => checks.push(links_check(&interfaces(&dev))),
        None => checks.push(Check::new(
            "links",
            Level::Skip,
            "/proc/net/dev не читается",
        )),
    }
    match read("/proc/net/route") {
        Some(route) => checks.push(routes_check("route4", "IPv4", &default_routes4(&route))),
        None => checks.push(Check::new(
            "route4",
            Level::Skip,
            "/proc/net/route не читается",
        )),
    }
    match read("/proc/net/ipv6_route") {
        Some(route) => checks.push(routes_check("route6", "IPv6", &default_routes6(&route))),
        // IPv6 switched off in the zone: nothing to route.
        None => checks.push(Check::new("route6", Level::Ok, "IPv6 в зоне нет")),
    }
    checks.push(nsswitch_check(read("/etc/nsswitch.conf").as_deref()));
    checks.push(resolv_check(read("/etc/resolv.conf").as_deref()));
    let mountinfo = read("/proc/self/mountinfo").unwrap_or_default();
    let slow = crate::sockets::Slow::new(&mountinfo);
    let present: Vec<&str> = RESOLVER_SOCKETS
        .iter()
        .copied()
        .filter(|p| reachable(Path::new(p), &slow))
        .collect();
    checks.push(resolver_sockets_check(&present));
    for (id, path, what) in open_channels(uid) {
        if id == "system-bus" {
            checks.push(system_bus_check(&mountinfo, reachable(&path, &slow), what));
            continue;
        }
        // A bus bound into a zone is the filtered one only when what is bound
        // is the zone's filter: an ordinary zone's sealed runtime binds the
        // host's own bus back, and that is as open as ever. The proxy alone,
        // from a zone brought up before the filter, hands the portal's links
        // to the host (§2).
        if id == "session-bus" && crate::zone::bus_is_zones_bus_filter(&mountinfo, &path) {
            checks.push(Check::new(
                "session-bus",
                Level::Ok,
                "фильтруется (герметичная зона): порталы, уведомления, трей, MPRIS, методы ввода",
            ));
            continue;
        }
        if id == "session-bus" && crate::zone::bus_is_zones_filter(&mountinfo, &path) {
            checks.push(Check::new(
                "session-bus",
                Level::Warn,
                "прокси без фильтра (зона поднята старой версией): ссылки портала уходят хосту \
                 (§2) — перезапусти зону",
            ));
            continue;
        }
        if id == "x11" && mounted_at(&mountinfo, crate::x11::X11_DIR) {
            checks.push(Check::new(
                "x11",
                Level::Ok,
                "X-сервер хоста скрыт; видны только свои X-серверы контейнеров",
            ));
            continue;
        }
        checks.push(open_channel_check(id, what, reachable(&path, &slow)));
    }
    // Every unix socket a program here may connect to (`crate::sockets`):
    // the zone's own named in the summary, anything else line by line.
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let home = crate::profile::home_dir();
    let walk = crate::sockets::walk(
        &crate::sockets::places(&runtime, home.as_deref()),
        &crate::sockets::known(&runtime),
        &slow,
        crate::sockets::LIMITS,
    );
    let context = crate::sockets::Context {
        own_devs: crate::sockets::own_devs(&mountinfo, &runtime, args.host_devs.as_ref()),
        runtime: runtime.clone(),
        zone: args.zone.clone(),
        hermetic: args.hermetic,
        nix_daemon: args.nix_daemon,
        audio_manager: args.audio_manager,
        mountinfo: mountinfo.clone(),
        closed: args.closed.clone(),
    };
    checks.extend(crate::sockets::checks(&walk, &context, groups_shed));
    let (raw, ipc) = compositor_entries(&runtime);
    checks.push(listed_channel_check(
        "wayland-raw",
        &raw,
        "сокет композитора без ограничений: захват экрана, буфер обмена, \
         виртуальная клавиатура — команда в терминал хоста (§13)",
    ));
    checks.push(listed_channel_check(
        "compositor-ipc",
        &ipc,
        "IPC композитора: запуск процесса на хосте (`niri msg action spawn`) (§13)",
    ));
    checks
}

/// The temporary directories a zone may share with the host
/// (`docs/LEAK-MODEL.md` §15).
pub const TMP_DIRS: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

/// The compositor's own sockets and its IPC in a runtime directory, as
/// `(raw, ipc)` names, shown as `crate::sockets::shown` shows a path: the
/// zone's runtime directory is the zone's, and a program names what it makes
/// there — an escape sequence for the owner's terminal included.
pub fn compositor_entries(runtime: &Path) -> (Vec<String>, Vec<String>) {
    let mut raw = Vec::new();
    let mut ipc = Vec::new();
    for entry in fs::read_dir(runtime).into_iter().flatten().flatten() {
        let bytes = entry.file_name().as_bytes().to_vec();
        let name = String::from_utf8_lossy(&bytes);
        if name.ends_with(".lock") || !crate::zone::compositor_private(&name) {
            continue;
        }
        if name.starts_with("wayland-") {
            raw.push(crate::sockets::shown(&bytes));
        } else {
            ipc.push(crate::sockets::shown(&bytes));
        }
    }
    raw.sort();
    ipc.sort();
    (raw, ipc)
}

/// How many names a listed channel names; the rest are counted.
const LISTED_MAX: usize = 20;

/// A channel found by name: `warn` naming what is there, `ok` when nothing is.
pub fn listed_channel_check(id: &str, found: &[String], what: &str) -> Check {
    if found.is_empty() {
        Check::new(id, Level::Ok, "не виден")
    } else {
        let mut names = found
            .iter()
            .take(LISTED_MAX)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if found.len() > LISTED_MAX {
            names.push_str(&format!(" и ещё {}", found.len() - LISTED_MAX));
        }
        Check::new(id, Level::Warn, format!("открыт ({names}) — {what}"))
    }
}

/// The root (field 4 of `mountinfo`) of the last mount at `point`: what of its
/// filesystem is bound there.
pub fn mount_root_at<'a>(mountinfo: &'a str, point: &str) -> Option<&'a str> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let root = fields.nth(3)?;
            (fields.next()? == point).then_some(root)
        })
        .next_back()
}

/// The system bus in a zone: filtered (the zone's proxy bound over the socket)
/// or closed (a tmpfs over `/run/dbus`) is what the zone promises; the host's
/// bus as it is, a warning.
/// Is something mounted at this point, per `/proc/self/mountinfo`?
pub fn mounted_at(mountinfo: &str, point: &str) -> bool {
    mountinfo
        .lines()
        .any(|line| line.split_whitespace().nth(4) == Some(point))
}

pub fn system_bus_check(mountinfo: &str, reachable: bool, what: &str) -> Check {
    let mounted_at = |point: &str| mounted_at(mountinfo, point);
    if mounted_at("/run/dbus/system_bus_socket") {
        Check::new(
            "system-bus",
            Level::Ok,
            "фильтруется: UPower, login1 только Inhibit и чтение",
        )
    } else if mounted_at("/run/dbus") || !reachable {
        Check::new("system-bus", Level::Ok, "закрыта")
    } else {
        Check::new("system-bus", Level::Warn, format!("открыта — {what}"))
    }
}

/// `vpn-zone-core doctor-probe <uid> [--hermetic] [--nix-daemon]
/// [--audio-manager] [--host-devs=…]` ([`ProbeArgs`]).
pub fn probe_main(args: &[OsString]) -> u8 {
    let Some(args) = ProbeArgs::parse(args) else {
        eprintln!("vpn-zone-core doctor-probe: need <uid>");
        return 2;
    };
    // A stop is taken for a program of the zone holding the probe
    // (`run_bounded`): the terminal's own stops (Ctrl-Z stops the doctor's
    // whole group) do not stop it — only `SIGSTOP`, which nobody sends by
    // accident.
    for signal in [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
        // SAFETY: setting a standard signal's disposition to "ignore".
        unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
    let groups_shed = match as_a_program() {
        Ok(shed) => shed,
        Err(e) => {
            // A probe with more rights than a program would call reachable
            // what is not: it does not answer at all (the doctor fails).
            eprintln!("vpn-zone-core doctor-probe: {e}");
            return 1;
        }
    };
    for check in probe(&args, groups_shed) {
        println!("{}", check.line());
    }
    0
}

/// Become what a program of the zone is before looking: the user's own group
/// and no other, as `profile-run` leaves a launch (the session's groups open
/// doors — docker's, libvirt's — that a zone's programs do not have), and no
/// capability at all. The doctor enters with `nsenter --keep-caps`, as a
/// launch does, so that the groups can go here; entered without (an older
/// doctor, or by hand on the host) they cannot, and the answer is whether the
/// groups are the program's anyway. Capabilities are dropped either way, and a
/// probe that cannot drop them does not run.
///
/// And first of all, not dumpable. Without capabilities the probe is, to the
/// kernel, an ordinary process of the zone — the same user in the same user
/// namespace, dumpable after an exec with `euid == uid` — which every program
/// there may read by the ptrace rules (`PTRACE_MODE_READ`, which Yama leaves
/// alone): `/proc/<probe>/environ` with the terminal's environment of whoever
/// ran `vpn-zone doctor`, and `/proc/<probe>/fd/1`, the pipe to the doctor,
/// opened for writing to put lines of its own ahead of the probe's. Not
/// dumpable, its `/proc` is the zone's root's and reading it takes
/// `CAP_SYS_PTRACE` in the zone's namespace, which no program there has (as
/// `bus_filter::run`). Set while the probe still holds its capabilities, so
/// that there is no moment it is readable; lowering capabilities does not
/// make a process dumpable again.
fn as_a_program() -> Result<bool, String> {
    // SAFETY: prctl with these arguments takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!(
            "cannot stop being dumpable: {}",
            std::io::Error::last_os_error()
        ));
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const VERSION_3: u32 = 0x2008_0522;
    // SAFETY: getgid(2) takes no arguments and cannot fail.
    let gid = unsafe { libc::getgid() };
    // SAFETY: a list of one gid and its length. Failing is an answer, read
    // back below.
    let _ = unsafe { libc::setgroups(1, &gid) };
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let data = [
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: capset(2) with a version-3 header and its two data structs;
    // lowering every set is always allowed.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut Header, data.as_ptr()) } != 0 {
        return Err(format!(
            "cannot drop capabilities: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: prctl with constants. Nothing ambient survives the capset; this
    // says so to a kernel that keeps the set apart.
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
    }
    // SAFETY: with a zero size getgroups(2) only counts.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups: Vec<libc::gid_t> = vec![0; usize::try_from(count).unwrap_or(0)];
    // SAFETY: a buffer of exactly `count` gids.
    let count = unsafe { libc::getgroups(count.max(0), groups.as_mut_ptr()) };
    groups.truncate(usize::try_from(count).unwrap_or(0));
    // Read back: a credential change that reset it would leave the probe
    // readable, and then it does not look at all.
    // SAFETY: prctl with these arguments takes no pointers.
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err("still dumpable after dropping rights".to_owned());
    }
    Ok(groups.iter().all(|g| *g == gid))
}

/// The devices of the mounts in this (the host's) namespace, for the probe
/// (`--host-devs`). `None` when the table cannot be read: a wrong list would
/// make the host's own filesystems look like the zone's.
fn host_devs() -> Option<String> {
    let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut devs: Vec<crate::sockets::Dev> = crate::sockets::mounts(&text)
        .into_iter()
        .map(|m| m.dev)
        .collect();
    devs.sort_unstable();
    devs.dedup();
    (!devs.is_empty()).then(|| {
        devs.iter()
            .map(|(major, minor)| format!("{major}:{minor}"))
            .collect::<Vec<_>>()
            .join(",")
    })
}

/// The host's sockets the zone is promised out of reach of, by identity, for
/// the probe (`--closed=`, `crate::sockets::parse_closed`): the same socket
/// under another name — a hard link into a directory the zone reaches — is
/// still that socket. What is closed depends on what the zone is to be, as the
/// probe's own reading by path does.
fn closed_identities(uid: u32, hermetic: bool, nix_daemon: bool, audio_manager: bool) -> String {
    use crate::sockets::HostSocket as Host;
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let mut named: Vec<(Host, PathBuf)> = RESOLVER_SOCKETS
        .iter()
        .map(|p| (Host::Resolver, PathBuf::from(p)))
        .collect();
    named.push((Host::SystemTier, PathBuf::from(crate::sysrun::SOCKET)));
    if !nix_daemon {
        named.push((
            Host::NixDaemon,
            Path::new(crate::zone::NIX_DAEMON_DIR).join("socket"),
        ));
    }
    named.push((Host::Pulse, runtime.join("pulse/native")));
    if hermetic {
        named.push((Host::SessionBus, runtime.join("bus")));
        named.push((Host::SystemdUser, runtime.join("systemd/private")));
        if !audio_manager {
            named.push((Host::Pipewire, runtime.join("pipewire-0")));
        }
    }
    for entry in fs::read_dir(&runtime).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if crate::zone::compositor_private(&name) {
            named.push((Host::Compositor, entry.path()));
        } else if name.starts_with("pipewire-") && name.ends_with("-manager") {
            named.push((Host::PipewireManager, entry.path()));
        }
    }
    for entry in fs::read_dir(crate::x11::X11_DIR)
        .into_iter()
        .flatten()
        .flatten()
    {
        named.push((Host::X11, entry.path()));
    }
    named
        .iter()
        .filter_map(|(kind, path)| {
            let meta = fs::symlink_metadata(path).ok()?;
            meta.file_type().is_socket().then(|| {
                format!(
                    "{}:{}:{}:{}",
                    kind.tag(),
                    libc::major(meta.dev()),
                    libc::minor(meta.dev()),
                    meta.ino()
                )
            })
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// How much of the probe's answer the doctor reads. A report of the zone's
/// sockets is a few kilobytes; a program that makes sockets by the hundred
/// thousand must not make the doctor hold a gigabyte.
pub const PROBE_OUTPUT_MAX: usize = 4 * 1024 * 1024;
/// And of its errors.
const PROBE_STDERR_MAX: usize = 64 * 1024;

/// What [`run_bounded`] got.
#[derive(Debug, Default)]
pub struct Bounded {
    pub success: bool,
    /// Killed for having been stopped.
    pub stopped: bool,
    /// Killed for answering more than it may.
    pub overflow: bool,
    /// Given up on by the person (Ctrl-C).
    pub interrupted: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// The write end of the pipe a Ctrl-C is told through while [`run_bounded`]
/// waits; -1 when nobody waits.
static INTERRUPT_W: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

extern "C" fn interrupted(_: libc::c_int) {
    let fd = INTERRUPT_W.load(Ordering::SeqCst);
    if fd >= 0 {
        // SAFETY: write(2) is async-signal-safe; one byte from a static.
        unsafe { libc::write(fd, [1u8].as_ptr().cast(), 1) };
    }
    // A second Ctrl-C ends the doctor, as it would have.
    // SAFETY: signal(2) is async-signal-safe.
    unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
}

/// When the doctor says what it is waiting for. Only that: it waits either
/// way.
const SAY_WAITING_AFTER: libc::c_int = 3000;

/// Run `command` to its end, reading at most `max` bytes of its standard
/// output; past that it is killed, and says so.
///
/// Waited for as long as it takes — no clock: the walk is bounded by what it
/// may read (`sockets::LIMITS`), a loaded machine only makes it later, and a
/// guess at "too long" would fail the check on exactly such a machine. A
/// program of the zone can hold the probe (LEAK-MODEL §16, and §19 for the
/// user's cgroups): stop it — seen as it happens (`waitid(WSTOPPED)`), the
/// probe killed and the check failed —, freeze or starve it through a cgroup
/// it may write, or stop the doctor itself; a tracer it cannot be, the probe
/// is not dumpable ([`as_a_program`]). So the doctor never says "fine" for a
/// probe that did not answer: it waits, says after a while what for
/// (`waiting`, on standard error), and a Ctrl-C gives up on the probe — the
/// check failed ([`Bounded::interrupted`]); a second one ends the doctor.
/// The probe is a process group of its own: the terminal's Ctrl-C and Ctrl-Z
/// are the doctor's, never the probe's. The end is the process's own (its
/// pidfd), not its pipes': a pipe held open by someone else ends the reading
/// once the probe is gone and what it wrote is read.
pub fn run_bounded(
    command: &mut Command,
    max: usize,
    waiting: Option<&str>,
) -> io::Result<Bounded> {
    use std::os::unix::process::CommandExt;
    // Inherited as "ignore", SIGCHLD would have the kernel reap the probe
    // unseen — and no stop of it could be seen either.
    // SAFETY: signal(2) with a standard disposition.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pidfd = match crate::sys::pidfd_open(child.id() as i32) {
        Some(fd) => fd,
        None => {
            let e = io::Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    let stopped = Arc::new(AtomicBool::new(false));
    {
        let watch = match pidfd.try_clone() {
            Ok(fd) => fd,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let stopped = Arc::clone(&stopped);
        std::thread::spawn(move || {
            if crate::sys::pidfd_stopped_or_gone(&watch) == crate::sys::ChildState::Stopped {
                stopped.store(true, Ordering::SeqCst);
                crate::sys::pidfd_signal(&watch, libc::SIGKILL);
            }
        });
    }
    let mut out = Bounded::default();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut buf = vec![0u8; 64 * 1024];
    let mut ended = false;
    // A Ctrl-C while the probe is waited for is told through a pipe.
    let interrupt = crate::sys::pipe().ok();
    let previous = interrupt.as_ref().map(|(_, w)| {
        INTERRUPT_W.store(w.as_raw_fd(), Ordering::SeqCst);
        // SAFETY: a handler that only writes a byte and resets itself.
        unsafe {
            libc::signal(
                libc::SIGINT,
                interrupted as extern "C" fn(libc::c_int) as libc::sighandler_t,
            )
        }
    });
    let interrupt_r = interrupt.as_ref().map(|(r, _)| r.as_raw_fd());
    let mut said = waiting.is_none();
    'read: while stdout.is_some() || stderr.is_some() {
        let pollin = |fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let mut fds: Vec<libc::pollfd> = [
            stdout.as_ref().map(AsRawFd::as_raw_fd),
            stderr.as_ref().map(AsRawFd::as_raw_fd),
            (!ended).then(|| pidfd.as_raw_fd()),
            interrupt_r.filter(|_| !ended),
        ]
        .into_iter()
        .flatten()
        .map(pollin)
        .collect();
        // Once it has ended, only what is in the pipes already: everything it
        // wrote is there by then. Before, no clock but the one for saying
        // what the doctor waits for.
        let ms = if ended {
            0
        } else if !said {
            SAY_WAITING_AFTER
        } else {
            -1
        };
        // SAFETY: a valid array of pollfd and its length.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if ready < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            let _ = child.kill();
            let _ = child.wait();
            restore_interrupt(previous);
            return Err(e);
        }
        if ready == 0 {
            if ended {
                break;
            }
            if let Some(waiting) = waiting.filter(|_| !said) {
                eprintln!("{waiting}");
            }
            said = true;
            continue;
        }
        for pfd in fds.iter().filter(|p| p.revents != 0) {
            if pfd.fd == pidfd.as_raw_fd() {
                ended = true;
                continue;
            }
            if Some(pfd.fd) == interrupt_r {
                out.interrupted = true;
                break 'read;
            }
            let is_out = stdout.as_ref().map(AsRawFd::as_raw_fd) == Some(pfd.fd);
            let n = if is_out {
                stdout.as_mut().map(|s| s.read(&mut buf))
            } else {
                stderr.as_mut().map(|s| s.read(&mut buf))
            };
            match n {
                Some(Ok(0)) | Some(Err(_)) | None => {
                    if is_out {
                        stdout = None;
                    } else {
                        stderr = None;
                    }
                }
                Some(Ok(n)) if is_out => {
                    out.stdout.extend_from_slice(&buf[..n]);
                    if out.stdout.len() > max {
                        out.overflow = true;
                        break 'read;
                    }
                }
                Some(Ok(n)) => {
                    // Read on past the cap, so that the child never blocks on
                    // a full pipe; kept only up to it.
                    let room = PROBE_STDERR_MAX.saturating_sub(out.stderr.len());
                    out.stderr.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
    }
    if out.overflow || out.interrupted {
        let _ = child.kill();
    }
    // Both pipes closed or the child gone: it is done, or about to be — and a
    // stop on the way is still seen, and ends it. A Ctrl-C now is the
    // doctor's again: a second one would have been anyway.
    let status = child.wait();
    restore_interrupt(previous);
    let status = status?;
    out.stopped = stopped.load(Ordering::SeqCst);
    out.success = status.success() && !out.stopped && !out.overflow && !out.interrupted;
    Ok(out)
}

/// SIGINT as it was before [`run_bounded`], and nobody told of it.
fn restore_interrupt(previous: Option<libc::sighandler_t>) {
    INTERRUPT_W.store(-1, Ordering::SeqCst);
    if let Some(previous) = previous.filter(|p| *p != libc::SIG_ERR) {
        // SAFETY: signal(2) with the disposition it returned before.
        unsafe { libc::signal(libc::SIGINT, previous) };
    }
}

/// A check the probe prints once, printed more than once: somebody else
/// wrote into its answer, or it is broken. Either way the answer is not
/// taken at its word (`socket` lines are many by design).
fn repeated_check(parsed: &[Check]) -> Option<Check> {
    let mut seen = HashSet::new();
    let mut repeated: Vec<&str> = parsed
        .iter()
        .filter(|c| c.id != "socket" && !seen.insert(c.id.as_str()))
        .map(|c| c.id.as_str())
        .collect();
    repeated.sort_unstable();
    repeated.dedup();
    (!repeated.is_empty()).then(|| {
        Check::new(
            "probe",
            Level::Fail,
            format!(
                "в ответе пробы не один раз: {} — ответ подделан или испорчен",
                repeated.join(", ")
            ),
        )
    })
}

/// `fs.protected_hardlinks`: with it on, a hard link to a socket (not a
/// regular file) takes being its owner, so a promised-closed socket of root's
/// cannot reappear under a name of the zone's choosing — the Nix daemon's in
/// `/nix/var/nix/profiles/per-user/<user>`, the user's own and not covered in
/// any zone. The same holds `zone::hide_nix_daemon`, which covers only the
/// daemon's directory.
pub fn hardlinks_check(value: Option<&str>) -> Check {
    match value.map(str::trim) {
        Some("1") => Check::new("hardlinks", Level::Ok, "fs.protected_hardlinks = 1"),
        Some(other) => Check::new(
            "hardlinks",
            Level::Warn,
            format!(
                "fs.protected_hardlinks = {other}: программа зоны может сделать жёсткую ссылку \
                 на закрытый ей сокет root (Nix-демон) в каталог, который она видит; доктор \
                 ищет такие по идентичности, но только там, куда доходит обход — \
                 sysctl fs.protected_hardlinks=1"
            ),
        ),
        None => Check::new(
            "hardlinks",
            Level::Skip,
            "/proc/sys/fs/protected_hardlinks не читается",
        ),
    }
}

/// A text for the owner's terminal: every control character written out.
/// What the probe says, and even the ids it says it for, come from inside a
/// zone — a name a program chose included —, and an escape sequence must not
/// reach the terminal to hide the lines before it or set the clipboard.
pub fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if crate::sockets::unseen_char(c) {
            out.push_str(&c.escape_unicode().to_string());
        } else {
            out.push(c);
        }
    }
    out
}

// --- THE HOST SIDE -------------------------------------------------------------

/// Where this command itself runs: a terminal started in a zone or a sandbox
/// breaks system operations in ways that do not say why (ROADMAP M5).
pub fn context_check(current_zone: Option<&str>, in_sandbox: bool) -> Check {
    match (current_zone, in_sandbox) {
        (Some(zone), true) => Check::new(
            "context",
            Level::Warn,
            format!("эта команда запущена в зоне «{zone}» и в песочнице: сеть и файлы — не хоста"),
        ),
        (Some(zone), false) => Check::new(
            "context",
            Level::Warn,
            format!("эта команда запущена в зоне «{zone}»: её сеть — не сеть хоста"),
        ),
        (None, true) => Check::new(
            "context",
            Level::Warn,
            "эта команда запущена в песочнице: файлы хоста ей не видны",
        ),
        (None, false) => Check::new("context", Level::Ok, "запущено на хосте"),
    }
}

/// The user namespace switches of the kernel, from their `/proc/sys` values.
pub fn userns_check(
    max_user_namespaces: Option<&str>,
    unprivileged_clone: Option<&str>,
    apparmor_restrict: Option<&str>,
) -> Check {
    let value = |v: Option<&str>| v.and_then(|t| t.trim().parse::<i64>().ok());
    if value(max_user_namespaces) == Some(0) {
        return Check::new(
            "userns",
            Level::Fail,
            "user.max_user_namespaces = 0: зоны без root невозможны",
        );
    }
    if value(unprivileged_clone) == Some(0) {
        return Check::new(
            "userns",
            Level::Fail,
            "kernel.unprivileged_userns_clone = 0: непривилегированные userns запрещены",
        );
    }
    if value(apparmor_restrict) == Some(1) {
        return Check::new(
            "userns",
            Level::Fail,
            "kernel.apparmor_restrict_unprivileged_userns = 1: AppArmor запрещает userns \
             (sysctl kernel.apparmor_restrict_unprivileged_userns=0)",
        );
    }
    Check::new(
        "userns",
        Level::Ok,
        "непривилегированные user namespaces разрешены",
    )
}

/// A line of `/etc/subuid` (or `subgid`) for this user, by name or by uid.
pub fn has_subid_range(text: &str, user: &str, uid: u32) -> bool {
    let uid = uid.to_string();
    text.lines().any(|line| {
        let mut fields = line.split(':');
        let owner = fields.next().unwrap_or("");
        (owner == user || owner == uid)
            && fields.nth(1).and_then(|n| n.trim().parse::<u64>().ok()) >= Some(65536)
    })
}

fn file_check(id: &str, path: &Path, what: &str) -> Check {
    let executable = fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if executable {
        Check::new(id, Level::Ok, format!("{what}: {}", path.display()))
    } else {
        Check::new(
            id,
            Level::Fail,
            format!("{what} не найден или не исполняемый: {}", path.display()),
        )
    }
}

/// `newuidmap` with the setuid bit, where NixOS and the distributions put it.
fn newuidmap_check() -> Check {
    for dir in ["/run/wrappers/bin", "/usr/bin", "/bin"] {
        let path = Path::new(dir).join("newuidmap");
        if let Ok(meta) = fs::metadata(&path) {
            return if meta.mode() & 0o4000 != 0 {
                Check::new(
                    "newuidmap",
                    Level::Ok,
                    format!("{} (setuid)", path.display()),
                )
            } else {
                Check::new(
                    "newuidmap",
                    Level::Warn,
                    format!(
                        "{} без setuid-бита: второй диапазон uid в зоне не отобразится \
                         (file capabilities этой проверкой не видны)",
                        path.display()
                    ),
                )
            };
        }
    }
    Check::new(
        "newuidmap",
        Level::Fail,
        "newuidmap не найден (shadow / uidmap): зоне нечем отобразить uid",
    )
}

pub fn system_checks(tools: &Tools, uid: u32) -> Vec<Check> {
    let read = |path: &str| fs::read_to_string(path).ok();
    let mut checks = vec![context_check(
        std::env::var(crate::launch::ENV_CURRENT)
            .ok()
            .filter(|z| !z.is_empty())
            .as_deref(),
        Path::new("/.flatpak-info").exists(),
    )];
    checks.push(userns_check(
        read("/proc/sys/user/max_user_namespaces").as_deref(),
        read("/proc/sys/kernel/unprivileged_userns_clone").as_deref(),
        read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref(),
    ));
    checks.push(newuidmap_check());
    checks.push(hardlinks_check(
        read("/proc/sys/fs/protected_hardlinks").as_deref(),
    ));
    let user = std::env::var("USER").unwrap_or_default();
    for (id, file) in [("subuid", "/etc/subuid"), ("subgid", "/etc/subgid")] {
        checks.push(match read(file) {
            Some(text) if has_subid_range(&text, &user, uid) => {
                Check::new(id, Level::Ok, format!("диапазон для {user} есть в {file}"))
            }
            Some(_) => Check::new(
                id,
                Level::Fail,
                format!("в {file} нет диапазона на 65536 для {user}"),
            ),
            None => Check::new(id, Level::Fail, format!("{file} не читается")),
        });
    }
    // A zone that kept the name `unconfined` from before it meant the host's
    // network: no longer offered, and refused when named.
    if tools.state.join(crate::launch::UNCONFINED).is_dir() {
        checks.push(Check::new(
            "zone-name-unconfined",
            Level::Fail,
            format!(
                "есть зона с именем «{}» — теперь это имя сети хоста без ограничений; \
                 запуск в неё отказывается, переименуй её каталог в {}",
                crate::launch::UNCONFINED,
                tools.state.display()
            ),
        ));
    }
    checks.push(if Path::new("/dev/net/tun").exists() {
        Check::new("tun", Level::Ok, "/dev/net/tun есть")
    } else {
        Check::new(
            "tun",
            Level::Fail,
            "/dev/net/tun нет: pasta не поднимет аплинк",
        )
    });
    for (id, path, what) in [
        ("tool-nsenter", &tools.nsenter, "nsenter"),
        ("tool-ip", &tools.ip, "ip"),
        ("tool-systemctl", &tools.systemctl, "systemctl"),
        ("tool-bwrap", &tools.bwrap, "bwrap"),
        ("tool-dbus-proxy", &tools.dbus_proxy, "xdg-dbus-proxy"),
        ("tool-core", &tools.core, "vpn-zone-core"),
    ] {
        checks.push(file_check(id, path, what));
    }
    checks
}

/// The zone's own checks: the probe inside it, and the tunnel from outside.
/// A running zone on the build installed now, or left on a previous one by
/// an update (`crate::build`): not a leak, but the holder's newer fixes do
/// not apply to it until it is restarted.
pub fn build_check(age: crate::build::Age) -> Check {
    match age {
        crate::build::Age::Current => {
            Check::new("build", Level::Ok, "зона на текущей сборке cellward")
        }
        crate::build::Age::Previous => Check::new(
            "build",
            Level::Warn,
            "зона на прошлой сборке cellward: обновление её не перезапустило; исправления \
             новой сборки придут после cellward down/up",
        ),
    }
}

pub fn zone_checks(tools: &Tools, name: &str, uid: u32) -> (bool, Vec<Check>) {
    let Some(pid) = zone_pid(&tools.state, name.as_ref()) else {
        return (
            false,
            vec![Check::new(
                "up",
                Level::Skip,
                "зона не поднята — проверяется только поднятая",
            )],
        );
    };
    let dir = tools.state.join(name);
    let offline = dir.join("offline").exists();
    let mut checks = vec![build_check(crate::build::age(
        &dir,
        &crate::build::installed(tools),
    ))];
    // What the zone is to be, read as its holder reads it: the probe judges
    // the host's bus and the Nix daemon by it.
    let (hermetic, _) = crate::hermetic::zone_setting(&dir, &tools.config, name);
    let (nix_daemon, _) = crate::hermetic::nix_daemon(&dir, &tools.config, name);
    let (audio_manager, _) = crate::hermetic::audio_manager(&dir, &tools.config, name);
    let mut probe_args = vec![uid.to_string(), format!("--zone={name}")];
    if hermetic {
        probe_args.push("--hermetic".to_owned());
    }
    if nix_daemon {
        probe_args.push("--nix-daemon".to_owned());
    }
    if audio_manager {
        probe_args.push("--audio-manager".to_owned());
    }
    if let Some(devs) = host_devs() {
        probe_args.push(format!("--host-devs={devs}"));
    }
    let closed = closed_identities(uid, hermetic, nix_daemon, audio_manager);
    if !closed.is_empty() {
        probe_args.push(format!("--closed={closed}"));
    }
    // `--keep-caps`, as a launch enters: the probe sheds the session's groups
    // in the zone's user namespace, as `profile-run` does, and then every
    // capability (`as_a_program`). The environment is not passed: the probe
    // runs among the zone's programs, and the terminal this command was
    // started from may hold anything — the home is all it needs.
    let mut command = Command::new(&tools.nsenter);
    command
        .env_clear()
        .env("HOME", &tools.home)
        .args([
            "--preserve-credentials",
            "--keep-caps",
            "-U",
            "-n",
            "-m",
            "-t",
        ])
        .arg(pid.to_string())
        .arg("--")
        .arg(&tools.core)
        .arg("doctor-probe")
        .args(&probe_args);
    let waiting =
        format!("doctor: жду пробу в зоне {name} — Ctrl-C: не ждать (проверка не пройдена)");
    match run_bounded(&mut command, PROBE_OUTPUT_MAX, Some(&waiting)) {
        Ok(out) if out.stopped => checks.push(Check::new(
            "probe",
            Level::Fail,
            "пробу в зоне остановили сигналом — она снята (программа зоны может так \
             сделать; проверка не пройдена)",
        )),
        Ok(out) if out.interrupted => checks.push(Check::new(
            "probe",
            Level::Fail,
            "пробу в зоне не дождались (Ctrl-C) — проверка не пройдена: программа зоны \
             может заморозить или замедлить её",
        )),
        Ok(out) if out.overflow => checks.push(Check::new(
            "probe",
            Level::Fail,
            format!(
                "проба в зоне ответила больше {} МБ — остановлена, ответ не принят",
                PROBE_OUTPUT_MAX / (1024 * 1024)
            ),
        )),
        Ok(out) if out.success => {
            let text = String::from_utf8_lossy(&out.stdout);
            let parsed: Vec<Check> = text.lines().filter_map(Check::parse_line).collect();
            if parsed.is_empty() {
                checks.push(Check::new(
                    "probe",
                    Level::Fail,
                    "проба в зоне ничего не ответила",
                ));
            }
            checks.extend(repeated_check(&parsed));
            checks.extend(parsed);
        }
        Ok(out) => checks.push(Check::new(
            "probe",
            Level::Fail,
            format!(
                "проба в зоне не запустилась: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        )),
        Err(e) => checks.push(Check::new(
            "probe",
            Level::Fail,
            format!("не запустить {}: {e}", tools.nsenter.display()),
        )),
    }
    if let Some(check) =
        pipewire_check(hermetic, audio_manager, crate::pw_context::read_state(&dir))
    {
        checks.push(check);
    }
    if !offline {
        checks.push(match fs::read_to_string(dir.join("status")) {
            Ok(mirror) => match crate::cli::alive_line(&dir, &mirror) {
                Some(line) => Check::new("tunnel", Level::Ok, format!("туннель живой ({line})")),
                None => Check::new(
                    "tunnel",
                    Level::Warn,
                    "рукопожатия нет: программы зоны без сети (утечки нет — выход закрыт)",
                ),
            },
            Err(_) => Check::new(
                "tunnel",
                Level::Skip,
                "состояние туннеля неизвестно: зона поднята старой версией",
            ),
        });
    }
    (true, checks)
}

/// A hermetic zone's PipeWire (`crate::pw_context`): restricted through
/// WirePlumber's policy, closed without it, or — an audio manager — the
/// host's raw socket, said loudly. `None` for an ordinary zone: its raw
/// socket is named among the sockets, beside its `systemd --user`.
pub fn pipewire_check(
    hermetic: bool,
    audio_manager: bool,
    state: Option<crate::pw_context::State>,
) -> Option<Check> {
    use crate::pw_context::State;
    if !hermetic {
        return None;
    }
    Some(if audio_manager {
        Check::new(
            "pipewire",
            Level::Warn,
            "МЕНЕДЖЕР ЗВУКА: зоне отдан PipeWire хоста без ограничений — всё, что играет \
             хост, микрофон мимо настройки microphone, чужие потоки и связи \
             (cellward audio-manager <зона> off)",
        )
    } else {
        match state {
            Some(State::Active) => Check::new(
                "pipewire",
                Level::Ok,
                "ограниченный: политика WirePlumber cellward действует",
            ),
            Some(State::NoPolicy) => Check::new(
                "pipewire",
                Level::Warn,
                "политики WirePlumber cellward нет — PipeWire зоне закрыт, звук только \
                 через pulse (services.cellward.pipewirePolicy или \
                 programs.cellward.pipewirePolicy)",
            ),
            Some(State::NoPipewire) => Check::new(
                "pipewire",
                Level::Warn,
                "PipeWire хоста недоступен — зоне закрыт, звук только через pulse",
            ),
            None => Check::new(
                "pipewire",
                Level::Warn,
                "помощника PipeWire нет (зона поднята старой версией или он умер) — \
                 перезапусти зону",
            ),
        }
    })
}

/// The names of every zone on disk, `offline` included.
fn all_zones(tools: &Tools) -> Vec<String> {
    let mut names: Vec<String> = visible_entries(&tools.state)
        .into_iter()
        .filter(|d| d.join("config.conf").is_file() || d.join("offline").exists())
        .filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    names.sort();
    names
}

/// `vpn-zone doctor [<zone>…] [--json]`. Exit code 1 when anything failed.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let json = args.iter().any(|a| a == "--json");
    let asked: Vec<String> = args
        .iter()
        .filter(|a| *a != "--json")
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let system = system_checks(tools, uid);
    let names = if asked.is_empty() {
        all_zones(tools)
    } else {
        asked
    };
    let zones: Vec<(String, bool, Vec<Check>)> = names
        .into_iter()
        .map(|name| {
            if !tools.state.join(&name).is_dir() {
                let missing = Check::new("exists", Level::Fail, "такой зоны нет");
                return (name, false, vec![missing]);
            }
            let (up, checks) = zone_checks(tools, &name, uid);
            (name, up, checks)
        })
        .collect();

    let worst = system
        .iter()
        .chain(zones.iter().flat_map(|(_, _, c)| c.iter()))
        .map(|c| c.level)
        .max()
        .unwrap_or(Level::Ok);

    if json {
        let list = |checks: &[Check]| {
            format!(
                "[{}]",
                checks.iter().map(Check::json).collect::<Vec<_>>().join(",")
            )
        };
        let zones_json: Vec<String> = zones
            .iter()
            .map(|(name, up, checks)| {
                format!(
                    "{{\"name\":{},\"up\":{up},\"checks\":{}}}",
                    json_string(name),
                    list(checks)
                )
            })
            .collect();
        println!(
            "{{\"schema_version\":{},\"worst\":{},\"system\":{},\"zones\":[{}]}}",
            crate::status::SCHEMA_VERSION,
            json_string(worst.as_str()),
            list(&system),
            zones_json.join(",")
        );
    } else {
        // Nothing that came from a zone reaches the terminal as it is.
        let print = |checks: &[Check]| {
            for check in checks {
                println!(
                    "  {} {:<14} {}",
                    check.level.mark(),
                    printable(&check.id),
                    printable(&check.detail)
                );
            }
        };
        println!("система:");
        print(&system);
        for (name, _, checks) in &zones {
            println!("зона {}:", printable(name));
            print(checks);
        }
        match worst {
            Level::Fail => println!("\n✗ есть нарушения — см. строки с ✗"),
            Level::Warn => println!(
                "\n⚠ нарушений нет; ⚠ — известные открытые каналы и предупреждения \
                 (docs/LEAK-MODEL.md, «Открытые каналы»)"
            ),
            _ => println!("\n✓ всё в порядке"),
        }
    }
    u8::from(worst == Level::Fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn a_zone_has_loopback_and_its_tunnel_and_nothing_else() {
        let dev = "Inter-|   Receive\n face |bytes\n    lo: 1 2 3\n  awg0: 4 5 6\n";
        assert_eq!(interfaces(dev), ["lo", "awg0"]);
        assert_eq!(links_check(&interfaces(dev)).level, Level::Ok);
        assert_eq!(links_check(&["lo".to_owned()]).level, Level::Ok);
        let host = ["lo".to_owned(), "eth0".to_owned(), "awg0".to_owned()];
        let check = links_check(&host);
        assert_eq!(check.level, Level::Fail);
        assert!(check.detail.contains("eth0"), "{}", check.detail);
    }

    #[test]
    fn default_routes_are_read_from_proc() {
        let v4 =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                  awg0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
                  eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(default_routes4(v4), ["awg0"]);
        assert_eq!(
            routes_check("route4", "IPv4", &default_routes4(v4)).level,
            Level::Ok
        );
        let leak =
            "Iface\tDestination\n eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert_eq!(
            routes_check("route4", "IPv4", &default_routes4(leak)).level,
            Level::Fail
        );

        let zero = "00000000000000000000000000000000";
        let v6 = format!(
            "{zero} 00 {zero} 00 {zero} 00000400 00000001 00000000 00000001     awg0\n\
             {zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200       lo\n\
             fe800000000000000000000000000000 40 {zero} 00 {zero} 00000100 00000001 00000000 00000001     eth0\n"
        );
        assert_eq!(default_routes6(&v6), ["awg0"]);
        let unreachable_only =
            format!("{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200       lo\n");
        assert!(default_routes6(&unreachable_only).is_empty());
    }

    #[test]
    fn only_files_and_dns_resolve_hosts() {
        let own = "passwd: files systemd\nhosts: files dns # zone\n";
        assert_eq!(nsswitch_check(Some(own)).level, Level::Ok);
        let host = "hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n";
        let check = nsswitch_check(Some(host));
        assert_eq!(check.level, Level::Fail);
        assert!(check.detail.contains("mymachines"), "{}", check.detail);
        assert_eq!(nsswitch_check(None).level, Level::Ok);
    }

    #[test]
    fn resolvers_fail_and_open_channels_warn() {
        assert_eq!(resolver_sockets_check(&[]).level, Level::Ok);
        assert_eq!(
            resolver_sockets_check(&["/run/systemd/resolve/io.systemd.Resolve"]).level,
            Level::Fail
        );
        assert_eq!(open_channel_check("x11", "X", true).level, Level::Warn);
        assert_eq!(open_channel_check("x11", "X", false).level, Level::Ok);
        assert_eq!(
            listed_channel_check("wayland-raw", &[], "w").level,
            Level::Ok
        );
        let found = ["wayland-1".to_owned()];
        let check = listed_channel_check("wayland-raw", &found, "w");
        assert_eq!(check.level, Level::Warn);
        assert!(check.detail.contains("wayland-1"), "{}", check.detail);
        let info = "30 29 0:40 /bus /run/user/1000/bus rw - tmpfs tmpfs rw\n\
                    31 29 8:2 /u/.local/state/vpn-zones/nl/session-bus /run/user/1000/bus rw - ext4 /dev/x rw\n";
        assert_eq!(
            mount_root_at(info, "/run/user/1000/bus"),
            Some("/u/.local/state/vpn-zones/nl/session-bus")
        );
        assert_eq!(
            mount_root_at(info.lines().next().unwrap(), "/run/user/1000/bus"),
            Some("/bus")
        );
        assert_eq!(mount_root_at(info, "/run/user/1000/pulse"), None);
        assert_eq!(
            nameservers("# c\nnameserver 10.0.0.1\nnameserver  ::1\nsearch x\n"),
            ["10.0.0.1", "::1"]
        );
        assert_eq!(resolv_check(Some("search x\n")).level, Level::Warn);
    }

    #[test]
    fn the_system_bus_is_ok_when_filtered_or_closed() {
        let bound = "36 25 0:5 /x /run/dbus/system_bus_socket rw - tmpfs x rw\n";
        let closed = "36 25 0:5 / /run/dbus rw - tmpfs tmpfs rw\n";
        assert_eq!(system_bus_check(bound, true, "w").level, Level::Ok);
        assert_eq!(system_bus_check(closed, false, "w").level, Level::Ok);
        assert_eq!(system_bus_check("", true, "w").level, Level::Warn);
    }

    /// A hermetic zone's PipeWire in the doctor: ok only with the policy in
    /// force; an audio manager said loudly; nothing for an ordinary zone
    /// (its raw socket is among the sockets).
    #[test]
    fn a_hermetic_zones_pipewire_is_ok_only_through_the_policy() {
        use crate::pw_context::State;
        assert!(pipewire_check(false, false, None).is_none());
        assert!(pipewire_check(false, true, Some(State::Active)).is_none());
        let level = |c: Option<Check>| c.map(|c| c.level);
        assert_eq!(
            level(pipewire_check(true, false, Some(State::Active))),
            Some(Level::Ok)
        );
        for state in [None, Some(State::NoPolicy), Some(State::NoPipewire)] {
            assert_eq!(level(pipewire_check(true, false, state)), Some(Level::Warn));
        }
        let loud = pipewire_check(true, true, Some(State::Active)).unwrap();
        assert_eq!(loud.level, Level::Warn);
        assert!(loud.detail.contains("МЕНЕДЖЕР ЗВУКА"), "{}", loud.detail);
    }

    #[test]
    fn the_probe_takes_what_the_doctor_says_and_ignores_the_rest() {
        let args = |list: &[&str]| -> Vec<OsString> { list.iter().map(OsString::from).collect() };
        assert_eq!(ProbeArgs::parse(&args(&[])), None);
        assert_eq!(ProbeArgs::parse(&args(&["x"])), None);
        let plain = ProbeArgs::parse(&args(&["1000"])).unwrap();
        assert_eq!(plain.uid, 1000);
        assert!(
            !plain.hermetic
                && !plain.nix_daemon
                && !plain.audio_manager
                && plain.host_devs.is_none()
        );
        let full = ProbeArgs::parse(&args(&[
            "1000",
            "--hermetic",
            "--nix-daemon",
            "--audio-manager",
            "--from-a-newer-doctor",
            "--host-devs=0:25,259:2",
        ]))
        .unwrap();
        assert!(full.hermetic && full.nix_daemon && full.audio_manager);
        assert_eq!(full.host_devs, Some([(0, 25), (259, 2)].into()));
        // A list that does not read is no list.
        let broken = ProbeArgs::parse(&args(&["1000", "--host-devs=0:25,junk"])).unwrap();
        assert_eq!(broken.host_devs, None);
        let empty = ProbeArgs::parse(&args(&["1000", "--host-devs="])).unwrap();
        assert_eq!(empty.host_devs, None);
        let named = ProbeArgs::parse(&args(&[
            "1000",
            "--zone=nl",
            "--closed=nix-daemon:0:25:7,from-a-newer-doctor:0:1:2",
        ]))
        .unwrap();
        assert_eq!(named.zone.as_deref(), Some("nl"));
        assert_eq!(named.closed.len(), 1);
        // A zone's name is one component, never a path.
        for bad in ["--zone=", "--zone=a/b", "--zone=.."] {
            assert_eq!(ProbeArgs::parse(&args(&["1000", bad])).unwrap().zone, None);
        }
    }

    #[test]
    fn the_probe_is_not_readable_by_the_zones_programs() {
        // In a child: the test harness is one process for every test.
        // SAFETY: fork(2); the child only makes system calls and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = match as_a_program() {
                // SAFETY: prctl with these arguments takes no pointers.
                Ok(_) => unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) },
                Err(_) => 7,
            };
            // SAFETY: _exit(2) in the forked child, nothing to unwind.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: waitpid(2) on our own child with a status to fill.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "still dumpable (1) or failed (7)"
        );
    }

    #[test]
    fn the_doctor_sees_a_stopped_probe_and_reads_no_more_than_it_may() {
        let quick = run_bounded(
            Command::new("sh").args(["-c", "echo out; echo err >&2"]),
            1024,
            None,
        )
        .unwrap();
        assert!(quick.success && !quick.stopped && !quick.overflow);
        assert_eq!(quick.stdout, b"out\n");
        assert_eq!(quick.stderr, b"err\n");
        // Stopped — as a program of the zone would stop it: seen, not waited
        // out.
        let stopped = run_bounded(
            Command::new("sh").args(["-c", "kill -STOP $$; echo never"]),
            1024,
            None,
        )
        .unwrap();
        assert!(stopped.stopped && !stopped.success, "{stopped:?}");
        assert!(stopped.stdout.is_empty());
        // Its pipe held by someone else: the probe's end is the end.
        let started = Instant::now();
        let held = run_bounded(
            Command::new("sh").args(["-c", "sleep 60 & echo out"]),
            1024,
            None,
        )
        .unwrap();
        assert!(held.success && !held.stopped, "{held:?}");
        assert_eq!(held.stdout, b"out\n");
        assert!(started.elapsed() < Duration::from_secs(30));
        let flood = run_bounded(
            Command::new("sh").args(["-c", "while :; do echo xxxxxxxxxxxxxxxx; done"]),
            4096,
            None,
        )
        .unwrap();
        assert!(flood.overflow && !flood.success);
        assert!(flood.stdout.len() <= 4096 + 64 * 1024);
    }

    #[test]
    fn an_answer_that_says_a_check_twice_is_not_taken() {
        let once = [
            Check::new("sockets", Level::Ok, "x"),
            Check::new("socket", Level::Warn, "a"),
            Check::new("socket", Level::Warn, "b"),
        ];
        assert_eq!(repeated_check(&once), None);
        let forged = [
            Check::new("sockets", Level::Ok, "чужих сокетов в досягаемости нет"),
            Check::new("links", Level::Ok, "x"),
            Check::new("sockets", Level::Fail, "y"),
        ];
        let check = repeated_check(&forged).unwrap();
        assert_eq!(check.level, Level::Fail);
        assert!(check.detail.contains("sockets"), "{}", check.detail);
    }

    #[test]
    fn nothing_from_a_zone_reaches_the_terminal_as_it_is() {
        let dir = std::env::temp_dir().join(format!("vz-doctor-esc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("wayland-\u{1b}[3A\u{1b}[J\u{7}"), "").unwrap();
        fs::write(dir.join("niri.\u{1b}]52;c;ZWNobwo=\u{7}.sock"), "").unwrap();
        let (raw, ipc) = compositor_entries(&dir);
        assert_eq!((raw.len(), ipc.len()), (1, 1));
        for name in raw.iter().chain(&ipc) {
            assert!(!name.chars().any(char::is_control), "{name:?}");
        }
        let check = listed_channel_check("wayland-raw", &raw, "w");
        assert!(!check.line().chars().any(|c| c.is_control() && c != '\t'));
        // And at the terminal, whatever the probe said.
        let shown = printable("ok \u{1b}]52;c;x\u{7} \u{9b}2J \u{202e}txt");
        assert!(!shown.chars().any(crate::sockets::unseen_char), "{shown}");
        assert!(shown.starts_with("ok \\u{1b}]52;c;x\\u{7}"), "{shown}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hard_links_to_root_sockets_are_warned_of() {
        assert_eq!(hardlinks_check(Some("1\n")).level, Level::Ok);
        assert_eq!(hardlinks_check(Some("0\n")).level, Level::Warn);
        assert_eq!(hardlinks_check(None).level, Level::Skip);
    }

    #[test]
    fn the_probe_line_survives_the_namespace_boundary() {
        let check = Check::new("links", Level::Fail, "a\tb\nc");
        assert_eq!(check.line(), "links\tfail\ta b c");
        assert_eq!(
            Check::parse_line(&check.line()),
            Some(Check::new("links", Level::Fail, "a b c"))
        );
        assert_eq!(Check::parse_line("junk"), None);
        assert_eq!(Check::parse_line("id\tweird\tx"), None);
        assert!(Level::Fail > Level::Warn && Level::Warn > Level::Skip && Level::Skip > Level::Ok);
    }

    #[test]
    fn system_readiness_is_read_from_proc_and_etc() {
        assert_eq!(userns_check(Some("63000\n"), None, None).level, Level::Ok);
        assert_eq!(userns_check(Some("0\n"), None, None).level, Level::Fail);
        assert_eq!(userns_check(Some("1"), Some("0"), None).level, Level::Fail);
        assert_eq!(
            userns_check(Some("1"), Some("1"), Some("1\n")).level,
            Level::Fail
        );
        assert_eq!(userns_check(Some("1"), None, Some("0")).level, Level::Ok);

        let subuid = "root:100000:65536\nalice:165536:65536\n1001:231072:1000\n";
        assert!(has_subid_range(subuid, "alice", 1000));
        assert!(!has_subid_range(subuid, "bob", 1001), "too small a range");
        assert!(has_subid_range("1000:100000:65536\n", "alice", 1000));

        assert_eq!(context_check(None, false).level, Level::Ok);
        assert_eq!(context_check(Some("nl"), false).level, Level::Warn);
        assert_eq!(context_check(None, true).level, Level::Warn);
    }
}
