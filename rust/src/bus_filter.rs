//! `vpn-zone-core bus-filter` — the session bus of a sandbox, with the door
//! for links (`docs/LEAK-MODEL.md` §2).
//!
//! **Why.** A program in a sandbox sees `/.flatpak-info`, and GTK, Qt, Firefox
//! and `xdg-open` itself then open a link through the portal: `OpenURI` on the
//! session bus. The portal lives on the host and hands the link to the default
//! browser there — in the host's network, or in whatever network that browser
//! already runs in, with nobody asked. A link sent to a program in a zone is
//! then a beacon that ties that zone to the home address.
//!
//! Refusing the call is no answer: GLib does not fall back to `xdg-open` when
//! the portal says no, the link simply does not open. So the call is answered
//! HERE, the way the portal would answer it, and the link goes to the broker
//! on the host (`crate::links`, `docs/PERMISSIONS.md` §11.13): the program
//! chosen there — the container's rule, the distribution's window of choice
//! —, then the network and the container in the launch window. The filter
//! tells the broker whose program's connection asked; with no broker, a
//! sandbox's filter on the host opens the link with `xdg-open` as before.
//!
//! ```text
//! program in bwrap ──► bus-filter (this) ──► xdg-dbus-proxy ──► session bus
//!                         │ OpenURI/OpenFile/OpenDirectory, ComposeEmail:
//!                         │ answered here; a link → the broker, on the host
//! ```
//!
//! Everything else passes byte for byte, file descriptors with the message
//! that carries them; the policy — which names the program may see and talk
//! to — stays `xdg-dbus-proxy`'s. The calls are recognised by member and
//! interface, NOT by destination: the portal's unique name reaches it just as
//! well as its well-known one, and a call without an interface field is
//! delivered by member alone.
//!
//! **What is refused, for now.** A `file:` link, `OpenFile`, `OpenDirectory`
//! (a file of the sandbox, opened on the host by the host's program) and
//! `ComposeEmail` (the host's mail client) are answered "cancelled": opening
//! them in the zone needs the file brought along, which is the next step.
//! Better nothing than the host.
//!
//! **Who the program is to the portal** (LEAK-MODEL §23): with
//! `--portal-app`, each connection is registered with the portal as the zone
//! before anything of the program's passes (`register`). **The screen cast
//! switch** (`crate::screencast`): with `--zone`, each call of the ScreenCast
//! portal is judged by the switch of the connection's container as it is at
//! that call (`screencast_verdict`) — whose program connected is looked at
//! once, when it connects (`crate::origin`).
//!
//! Every byte comes from the sandboxed program, so the parsing is
//! `crate::dbus_wire`'s, bounds-checked throughout; a message that does not
//! parse ends the connection. The filter dies with the sandbox launcher
//! (`PR_SET_PDEATHSIG`); a link it opened lives on in its own unit.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::dbus_wire::{self as wire, body, Field, Header};
use crate::sys;

/// The portal's well-known name.
const PORTAL: &str = "org.freedesktop.portal.Desktop";
const OPEN_URI: &str = "org.freedesktop.portal.OpenURI";
const EMAIL: &str = "org.freedesktop.portal.Email";
const BACKGROUND: &str = "org.freedesktop.portal.Background";
const NETWORK_MONITOR: &str = "org.freedesktop.portal.NetworkMonitor";
const PROXY_RESOLVER: &str = "org.freedesktop.portal.ProxyResolver";
const REQUEST: &str = "org.freedesktop.portal.Request";
/// The portal's registry of host programs, and where it lives: the portal's
/// own object.
const REGISTRY: &str = "org.freedesktop.host.portal.Registry";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
/// The serial of the filter's own `Register` on a program's connection.
/// Serials are per connection and a program counts its own from 1: this one
/// it would have to pick on purpose — and a message of the program's with
/// this serial waits while ours is unanswered (`Conn::holds`), so that no
/// answer to it can pass for the portal's. Not higher: xdg-dbus-proxy keeps the
/// serials above [`MAX_CLIENT_SERIAL`] for messages of its own and closes a
/// connection whose client uses one.
pub const REGISTER_SERIAL: u32 = 0xFFFE_FF00;
/// xdg-dbus-proxy's `MAX_CLIENT_SERIAL` (flatpak-proxy.c): 2^32 − 1 − 65 536.
pub const MAX_CLIENT_SERIAL: u32 = u32::MAX - 65_536;
/// `Response` codes: done, and "the interaction ended some other way".
const RESPONSE_OK: u32 = 0;
const RESPONSE_OTHER: u32 = 2;
/// Bounds on what one connection may make the filter hold.
const READ_CHUNK: usize = 64 * 1024;
const MAX_FDS_PER_READ: usize = 64;
const MAX_QUEUED_FDS: usize = 256;
const MAX_AUTH_BYTES: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 64;
/// Links the filter opens: at most this many in a minute.
const MAX_OPENS_PER_MINUTE: usize = 10;
/// The longest link it opens.
const MAX_URI: usize = 8 * 1024;
/// How often a notice about a refusal may be shown.
const NOTICE_EVERY: Duration = Duration::from_secs(30);
/// What a refused file says.
const FILE_NOTICE: &str = "Программа из контейнера попросила открыть файл другой программой. \
     Сейчас это сделала бы программа хоста, в сети хоста, — поэтому файл не открыт. Откройте \
     его из файлового менеджера или из самой программы.";

/// `vpn-zone-core bus-filter --listen <socket> --upstream <socket> --opener <program>
/// [--via-broker <zone>] [--portal-app <app-id>]
/// [--zone <zone> --zone-dir <dir> --config <dir>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub listen: PathBuf,
    pub upstream: PathBuf,
    pub opener: PathBuf,
    /// A hermetic zone's own bus: the filter runs in the zone, but not in a
    /// launch with an environment a link could be opened from — so the link
    /// goes to the broker as "run the opener in this very zone", which the
    /// broker starts without a question (it knows the zone by the network
    /// namespace of the one asking), and from there the usual door.
    pub via_broker: Option<String>,
    /// `--portal-app`: the application id each connection is registered with
    /// at the portal's host registry before anything of the program's passes
    /// (`desktop::zone_app_id`, LEAK-MODEL §23). Only the filter right in
    /// front of the bus proxy is given one: the `Register` of a sandbox's
    /// filter in front of a hermetic zone's own would be refused by that one,
    /// as the program's is (`refused`) — and that one has already registered
    /// the connection.
    pub portal_app: Option<String>,
    /// `--zone`, `--zone-dir`, `--config`, all three or none: the zone whose
    /// screen cast switch the filter reads for every call of the portal's
    /// ScreenCast (`crate::screencast`), its state directory and
    /// `~/.config/vpn-zones`. None: every cast asks, as before the switch.
    /// With it, `--profiles`: the containers' data, by which a container is
    /// known to be one (`crate::origin`).
    pub zone: Option<ZoneArgs>,
}

/// The zone a filter reads the screen cast switch of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneArgs {
    pub name: String,
    pub dir: PathBuf,
    pub config: PathBuf,
    pub profiles: Option<PathBuf>,
}

impl Args {
    pub fn parse(argv: &[OsString]) -> Result<Self, String> {
        let (mut listen, mut upstream, mut opener, mut via_broker) = (None, None, None, None);
        let mut portal_app = None;
        let (mut zone, mut zone_dir, mut config, mut profiles) = (None, None, None, None);
        let mut it = argv.iter();
        while let Some(flag) = it.next() {
            let value = it
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| format!("{} needs a value", flag.to_string_lossy()))?;
            match flag.to_str() {
                Some("--listen") => listen = Some(value),
                Some("--upstream") => upstream = Some(value),
                Some("--opener") => opener = Some(value),
                Some("--via-broker") => via_broker = Some(value.to_string_lossy().into_owned()),
                Some("--portal-app") => {
                    let id = value
                        .to_str()
                        .filter(|id| is_app_id(id))
                        .ok_or("--portal-app is not an application id")?;
                    portal_app = Some(id.to_owned());
                }
                Some("--zone") => {
                    zone = Some(
                        value
                            .to_str()
                            .filter(|z| !z.is_empty())
                            .ok_or("--zone is not a zone's name")?
                            .to_owned(),
                    )
                }
                Some("--zone-dir") => zone_dir = Some(value),
                Some("--config") => config = Some(value),
                Some("--profiles") => profiles = Some(value),
                _ => return Err(format!("unknown argument {}", flag.to_string_lossy())),
            }
        }
        let zone = match (zone, zone_dir, config) {
            (Some(name), Some(dir), Some(config)) => Some(ZoneArgs {
                name,
                dir,
                config,
                profiles,
            }),
            (None, None, None) if profiles.is_none() => None,
            _ => {
                return Err(
                    "--zone, --zone-dir and --config go together (and --profiles with them)"
                        .to_owned(),
                )
            }
        };
        Ok(Self {
            listen: listen.ok_or("--listen is required")?,
            upstream: upstream.ok_or("--upstream is required")?,
            opener: opener.ok_or("--opener is required")?,
            via_broker,
            portal_app,
            zone,
        })
    }
}

/// An application id as GLib takes one (`g_application_id_is_valid`): at
/// most 255 bytes, two elements or more, each of `[A-Za-z0-9_-]`, none empty
/// or starting with a digit.
pub fn is_app_id(id: &str) -> bool {
    id.len() <= 255
        && id.split('.').count() >= 2
        && id.split('.').all(|e| {
            !e.is_empty()
                && !e.starts_with(|c: char| c.is_ascii_digit())
                && e.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// What the filter answers itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Door {
    /// `OpenURI.OpenURI`: a link.
    Uri,
    /// `OpenURI.OpenFile`, `OpenURI.OpenDirectory`: a file of the sandbox.
    File,
    /// `Email.ComposeEmail`.
    Email,
    /// `Background.RequestBackground`: with `autostart` the portal writes an
    /// autostart entry ON THE HOST, run at the next login outside every zone.
    Background,
    /// `NetworkMonitor.*`: the HOST's network, as the portal sees it — and
    /// `CanReach` has the host resolve and try any name, in the host's
    /// network (review 2026-09-25). Answered here: the zone's network is up,
    /// not metered, full; any name "reachable" without a packet sent.
    Network,
    /// `ProxyResolver.Lookup`: the host's proxy settings. Answered here: a
    /// zone goes out directly, through its own tunnel.
    Proxy,
}

/// Is this call one the filter answers? By member and interface only: the
/// destination does not matter (see the module's notes).
pub fn door(h: &Header) -> Option<Door> {
    if h.kind != wire::METHOD_CALL {
        return None;
    }
    let iface_is = |want: &str| h.interface.as_deref().is_none_or(|i| i == want);
    match h.member.as_deref()? {
        "OpenURI" if iface_is(OPEN_URI) => Some(Door::Uri),
        "OpenFile" | "OpenDirectory" if iface_is(OPEN_URI) => Some(Door::File),
        "ComposeEmail" if iface_is(EMAIL) => Some(Door::Email),
        "RequestBackground" if iface_is(BACKGROUND) => Some(Door::Background),
        "GetAvailable" | "GetMetered" | "GetConnectivity" | "GetStatus" | "CanReach"
            if iface_is(NETWORK_MONITOR) =>
        {
            Some(Door::Network)
        }
        "Lookup" if iface_is(PROXY_RESOLVER) => Some(Door::Proxy),
        _ => None,
    }
}

/// The portal interfaces a program of a zone or a sandbox may call.
///
/// **The portal takes it for a host application.** xdg-desktop-portal knows a
/// caller by the process on the other end of ITS connection — the proxy, which
/// runs outside the sandbox and outside the zone's mount namespace — and finds
/// no `/.flatpak-info` there (review 2026-09-25). A host application is
/// granted without a dialog what a Flatpak would be asked about: the
/// dynamic launcher installs a `.desktop` entry of the caller's making and
/// starts it ON THE HOST; location, camera, a non-interactive screenshot, the
/// Secret portal's key (one for every "host" caller) come the same way. So
/// the interfaces are named here, and everything else under
/// `org.freedesktop.portal.` is refused — a portal added later included.
pub const PORTAL_ALLOWED: &[&str] = &[
    "org.freedesktop.portal.Request",
    "org.freedesktop.portal.Session",
    "org.freedesktop.portal.FileChooser",
    "org.freedesktop.portal.FileTransfer",
    // Answered by the filter itself (`door`).
    "org.freedesktop.portal.OpenURI",
    "org.freedesktop.portal.Email",
    "org.freedesktop.portal.Background",
    // Read-only, or with a dialog of the portal's own every time.
    // Answered by the filter as well (`Door::Network`, `Door::Proxy`): no
    // call of theirs reaches the host.
    "org.freedesktop.portal.NetworkMonitor",
    "org.freedesktop.portal.ProxyResolver",
    "org.freedesktop.portal.Settings",
    "org.freedesktop.portal.Notification",
    "org.freedesktop.portal.Inhibit",
    "org.freedesktop.portal.MemoryMonitor",
    "org.freedesktop.portal.PowerProfileMonitor",
    "org.freedesktop.portal.Print",
    "org.freedesktop.portal.ScreenCast",
    "org.freedesktop.portal.Account",
];

/// Why a call is not passed on, if it is not: a portal interface not in
/// [`PORTAL_ALLOWED`], or a call that names no interface at all — dispatched
/// by its member alone, it could reach any of them. The bus itself is always
/// asked directly.
pub fn refused(h: &Header) -> Option<String> {
    if h.kind != wire::METHOD_CALL {
        return None;
    }
    match h.interface.as_deref() {
        None if h.destination.as_deref() != Some("org.freedesktop.DBus") => Some(format!(
            "{} without an interface",
            h.member.as_deref().unwrap_or("?")
        )),
        Some(i) if i.starts_with("org.freedesktop.portal.") && !PORTAL_ALLOWED.contains(&i) => {
            Some(format!("{i} is not for programs of a zone"))
        }
        // The portal's host registry (`org.freedesktop.host.portal.Registry`,
        // xdg-desktop-portal 1.19+): an unsandboxed caller names itself with
        // any application id, once, before its first portal call. The portal
        // takes a zone's program for such a caller, so it could name itself
        // after a host program — its dialogs and notifications would say that
        // program asked, and the permissions the portal keeps for that id would
        // be its. By interface, not by destination: a unique name reaches the
        // same object. Anything else of the host's `org.freedesktop.host.`
        // tree goes the same way.
        Some(i) if i.starts_with("org.freedesktop.host.") => {
            Some(format!("{i} is not for programs of a zone"))
        }
        _ => None,
    }
}

/// Answer a call with a value, as its service would, from where it was sent to.
fn reply(conn: &Conn, ctx: &Ctx, h: &Header, signature: &str, body: &[u8]) -> io::Result<()> {
    if h.flags & wire::NO_REPLY_EXPECTED != 0 {
        return Ok(());
    }
    let unique = conn
        .unique
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let from = h.destination.clone().unwrap_or_else(|| PORTAL.to_owned());
    let mut fields = vec![Field::ReplySerial(h.serial), Field::Sender(&from)];
    if let Some(d) = unique.as_deref() {
        fields.push(Field::Destination(d));
    }
    fields.push(Field::Signature(signature));
    let msg = wire::message(
        wire::METHOD_RETURN,
        wire::NO_REPLY_EXPECTED,
        ctx.serial(),
        &fields,
        body,
    );
    conn.send(&msg, &[])
}

/// The answers of `Door::Network` and `Door::Proxy`.
fn answer_value(conn: &Conn, ctx: &Ctx, h: &Header, which: Door) -> io::Result<()> {
    match (which, h.member.as_deref().unwrap_or("")) {
        (Door::Network, "GetStatus") => {
            reply(conn, ctx, h, "a{sv}", &body::network_status(true, false, 4))
        }
        (Door::Network, "GetConnectivity") => reply(conn, ctx, h, "u", &body::uint(4)),
        (Door::Network, "GetMetered") => reply(conn, ctx, h, "b", &body::boolean(false)),
        (Door::Network, _) => reply(conn, ctx, h, "b", &body::boolean(true)),
        _ => reply(conn, ctx, h, "as", &body::strings(&["direct://"])),
    }
}

/// Say no to a call the way the bus would: `AccessDenied`, from where it was
/// sent to. Nothing when no reply is expected.
fn deny(conn: &Conn, ctx: &Ctx, h: &Header, why: &str) -> io::Result<()> {
    eprintln!("bus-filter: refused — {why}");
    error_reply(conn, ctx, h, "org.freedesktop.DBus.Error.AccessDenied", why)
}

/// The error `name` with the text `why` for a call, from where it was sent
/// to. Nothing when no reply is expected.
fn error_reply(conn: &Conn, ctx: &Ctx, h: &Header, name: &str, why: &str) -> io::Result<()> {
    if h.flags & wire::NO_REPLY_EXPECTED != 0 {
        return Ok(());
    }
    let unique = conn
        .unique
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let from = h.destination.clone().unwrap_or_else(|| PORTAL.to_owned());
    let mut fields = vec![
        Field::ErrorName(name),
        Field::ReplySerial(h.serial),
        Field::Sender(&from),
    ];
    if let Some(d) = unique.as_deref() {
        fields.push(Field::Destination(d));
    }
    fields.push(Field::Signature("s"));
    let reply = wire::message(
        wire::ERROR,
        wire::NO_REPLY_EXPECTED,
        ctx.serial(),
        &fields,
        &body::string(&format!("{}: {why}", crate::dialog::APP)),
    );
    conn.send(&reply, &[])
}

/// The portal's own error for "not allowed".
const NOT_ALLOWED: &str = "org.freedesktop.portal.Error.NotAllowed";

/// What becomes of a call as the zone's screen cast switch has it
/// (`crate::screencast`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cast {
    /// As before the switch: `SelectSources` without a remembered choice,
    /// everything else as it is.
    Pass,
    /// `SelectSources` with the choice it may remember (`yes`, on a
    /// connection the portal knows as the zone).
    Remember,
    /// Refused (`no`), and the text for the program.
    Refuse(String),
}

/// The switch for one call, read now: a change applies to the next call.
/// Only calls on the ScreenCast interface — one without an interface is
/// refused already (`refused`) — and only with a zone to read the switch of.
fn screencast_verdict(conn: &Conn, ctx: &Ctx, h: &Header) -> Cast {
    use crate::screencast::{Setting, INTERFACE};
    if h.kind != wire::METHOD_CALL || h.interface.as_deref() != Some(INTERFACE) {
        return Cast::Pass;
    }
    let Some(policy) = &ctx.screencast else {
        return Cast::Pass;
    };
    let (setting, source) = policy.setting_for(&conn.who);
    match setting {
        Setting::No => Cast::Refuse(policy.refused(&conn.who, source)),
        Setting::Ask => Cast::Pass,
        // Only the selection carries a choice to remember.
        Setting::Yes if h.member.as_deref() != Some("SelectSources") => Cast::Pass,
        // The portal knows the connection as the zone: a choice kept there
        // would be every container's of the zone. A container's `yes` keeps
        // none until it has a name of its own with the portal.
        Setting::Yes if conn.who != crate::origin::Who::Main => Cast::Pass,
        Setting::Yes if identified(conn, ctx, h) => Cast::Remember,
        Setting::Yes => {
            if !ctx.told_unremembered.swap(true, Ordering::SeqCst) {
                eprintln!(
                    "bus-filter: zone {}: screen cast yes is ask on a connection the portal does \
                     not know as the zone — no choice is kept for a nameless host application; \
                     said once",
                    policy.zone()
                );
            }
            Cast::Pass
        }
    }
}

/// Whether a call goes to the portal that knows this connection as the zone
/// (`register`): by that portal's unique name, or by the well-known one while
/// that portal still owns it — one started since knows the connection by no
/// name, and would keep the choice for the nameless host application.
fn identified(conn: &Conn, ctx: &Ctx, h: &Header) -> bool {
    let Some(portal) = conn.portal() else {
        return false;
    };
    match h.destination.as_deref() {
        Some(to) if to == portal => true,
        Some(PORTAL) => portal_owner(&ctx.upstream).is_some_and(|owner| owner == portal),
        _ => false,
    }
}

/// Whether a link may be handed to the opener, and why not.
pub fn acceptable(uri: &str) -> Result<(), &'static str> {
    if uri.len() > MAX_URI {
        return Err("too long");
    }
    if uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("control characters or spaces");
    }
    let Some((scheme, _)) = uri.split_once(':') else {
        return Err("no scheme");
    };
    let mut chars = scheme.chars();
    let starts = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    if !starts || !chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) {
        return Err("not a scheme");
    }
    if scheme.eq_ignore_ascii_case("file") {
        return Err("a local file");
    }
    Ok(())
}

/// What of a link goes into the log: the scheme and the host, never the path
/// or the query, which carry tokens.
pub fn loggable(uri: &str) -> String {
    let Some((scheme, rest)) = uri.split_once(':') else {
        return "?".to_owned();
    };
    match rest.strip_prefix("//") {
        Some(rest) => {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            // Credentials in front of the host stay out too.
            let host = host.rsplit('@').next().unwrap_or(host);
            format!("{scheme}://{host}")
        }
        None => format!("{scheme}:…"),
    }
}

/// The object path a portal request lives at: `…/request/<sender>/<token>`,
/// where the sender is the caller's unique name without `:` and with `_` for
/// `.`. A token that is not an object path element is replaced.
pub fn handle_path(unique: Option<&str>, token: Option<&str>, fallback: u32) -> String {
    let sender = unique
        .map(|u| u.trim_start_matches(':').replace('.', "_"))
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .unwrap_or_else(|| "unknown".to_owned());
    let token = token
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("vpnzones{fallback}"));
    format!("/org/freedesktop/portal/desktop/request/{sender}/{token}")
}

/// Shared by every connection.
struct Ctx {
    upstream: PathBuf,
    opener: PathBuf,
    via_broker: Option<String>,
    /// `--portal-app`.
    portal_app: Option<String>,
    /// Why a connection has no id of the zone's has been said: once per
    /// filter, not once per connection — an old portal would say it for
    /// every program.
    told_register: AtomicBool,
    /// The zone's screen cast switch, its directories held (`--zone`).
    screencast: Option<crate::screencast::Policy>,
    /// That `yes` was `ask` for want of an id has been said, once.
    told_unremembered: AtomicBool,
    opens: Mutex<VecDeque<Instant>>,
    last_notice: Mutex<Option<Instant>>,
    serial: AtomicU32,
    connections: AtomicU32,
}

impl Ctx {
    fn new(upstream: PathBuf, args: &Args, screencast: Option<crate::screencast::Policy>) -> Self {
        Self {
            upstream,
            opener: args.opener.clone(),
            via_broker: args.via_broker.clone(),
            portal_app: args.portal_app.clone(),
            told_register: AtomicBool::new(false),
            screencast,
            told_unremembered: AtomicBool::new(false),
            opens: Mutex::new(VecDeque::new()),
            last_notice: Mutex::new(None),
            serial: AtomicU32::new(1),
            connections: AtomicU32::new(0),
        }
    }

    /// A connection goes on with no id of the zone's: said on stderr (the
    /// zone's unit journal), the first time only.
    fn unregistered(&self, why: &str) {
        if !self.told_register.swap(true, Ordering::SeqCst) {
            eprintln!(
                "bus-filter: the portal does not know a connection as {} ({why}) — its program \
                 is a nameless host application to the portal, as before its registry; said once",
                self.portal_app.as_deref().unwrap_or("?")
            );
        }
    }

    fn serial(&self) -> u32 {
        // Our own serials, far from where a bus starts counting; never 0.
        self.serial.fetch_add(1, Ordering::Relaxed) | 0x4000_0000
    }

    fn may_open(&self) -> bool {
        let mut opens = self.opens.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while opens
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            opens.pop_front();
        }
        if opens.len() >= MAX_OPENS_PER_MINUTE {
            return false;
        }
        opens.push_back(now);
        true
    }
}

/// One connection of the program: the client end, written to only under the
/// lock and only in whole messages, and what was learned about it.
struct Conn {
    client: UnixStream,
    write: Mutex<()>,
    unique: Mutex<Option<String>>,
    began: AtomicBool,
    /// Who the connection is to the portal, and how far that got: the two
    /// directions meet here — one sends and waits, the other sees the
    /// answers go by.
    registry: Mutex<Registration>,
    settled: Condvar,
    /// Whose program is on the other end (`crate::origin`), looked at when
    /// it connected: the screen cast is decided by its container. The zone's
    /// own for a filter with no zone to read (a sandbox's).
    who: crate::origin::Who,
}

impl Conn {
    fn new(client: UnixStream, who: crate::origin::Who) -> Self {
        Self {
            who,
            client,
            write: Mutex::new(()),
            unique: Mutex::new(None),
            began: AtomicBool::new(false),
            registry: Mutex::new(Registration::default()),
            settled: Condvar::new(),
        }
    }

    fn send(&self, bytes: &[u8], fds: &[RawFd]) -> io::Result<()> {
        let _guard = self.write.lock().unwrap_or_else(|e| e.into_inner());
        send_all(self.client.as_raw_fd(), bytes, fds)
    }

    fn registration(&self) -> MutexGuard<'_, Registration> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait while the registration is at `waiting` — as long as it takes,
    /// no clock of ours: a portal activated cold on a loaded machine answers
    /// late, and a guess at "too late" would make the connection nameless
    /// on exactly such a machine. The bus answers the Hello itself; for the
    /// `Register` it answers in the portal's stead when the portal cannot:
    /// an error when the activation fails, `NoReply` when the portal goes
    /// without answering. The bus side going settles it too
    /// ([`Conn::bus_gone`]), and the program's side going ends the wait for a
    /// call ([`Conn::settle`]). A portal alive and stuck (or stopped: a
    /// program of any zone can `kill -STOP` it, LEAK-MODEL §16) holds only
    /// what would reach it — a program's calls to the portal and what the
    /// program sends after them — until it is restarted, as it holds GTK's
    /// own wait for its settings at start.
    fn wait_while(&self, waiting: impl Fn(&Stage) -> bool) {
        let mut reg = self.registration();
        while waiting(&reg.stage) {
            reg = match self.settled.wait(reg) {
                Ok(guard) => guard,
                Err(e) => e.into_inner(),
            };
        }
    }

    /// A reply from the bus as the registration sees it: the answer to the
    /// program's Hello moves it on; the answer to our `Register` settles it
    /// and is the filter's — `true`: swallowed, never the program's, however
    /// late it comes.
    fn answered(&self, ctx: &Ctx, msg: &[u8], h: &Header) -> bool {
        if !matches!(h.kind, wire::METHOD_RETURN | wire::ERROR) {
            return false;
        }
        let Some(serial) = h.reply_serial else {
            return false;
        };
        let mut reg = self.registration();
        if reg.outstanding == Some(serial) {
            reg.outstanding = None;
            // Only while ours is the one waited for: once the bus side went
            // (`bus_gone`), nothing is the zone's any more.
            if reg.stage != Stage::Register(serial) {
                return true;
            }
            reg.stage = Stage::Done;
            let refusal = match (h.kind, h.sender.as_deref()) {
                (wire::METHOD_RETURN, Some(portal)) => {
                    reg.portal = Some(portal.to_owned());
                    None
                }
                (wire::METHOD_RETURN, None) => Some("an answer from nobody".to_owned()),
                _ => Some(format!(
                    "{}: {}",
                    h.error_name.as_deref().unwrap_or("an error"),
                    wire::body_string(msg, h).unwrap_or_default()
                )),
            };
            // Said before the held calls go on — under the lock the waiting
            // side reads the stage with: once they are on the bus, the
            // refusal is on record (the flag was set after the wake-up, and
            // a caller could see the calls before it).
            if let Some(why) = refusal {
                ctx.unregistered(&format!("the portal said {why}"));
            }
            self.settled.notify_all();
            drop(reg);
            return true;
        }
        if reg.stage == Stage::Hello(serial) {
            reg.stage = Stage::Welcomed(h.kind == wire::METHOD_RETURN);
            self.settled.notify_all();
        }
        false
    }

    /// The bus side is gone: nobody is to wait for its answers — whatever
    /// the stage, short of settled: a `Register` about to be sent after this
    /// would otherwise be waited for with nobody left to answer it.
    fn bus_gone(&self) {
        let mut reg = self.registration();
        if reg.stage != Stage::Done {
            reg.stage = Stage::Closed;
        }
        self.settled.notify_all();
    }

    /// The program's side went while its call waited for our `Register`:
    /// nobody is left to hold it for.
    fn program_gone(&self) {
        let mut reg = self.registration();
        if matches!(reg.stage, Stage::Register(_)) {
            reg.stage = Stage::Closed;
        }
        self.settled.notify_all();
    }

    /// Whether a message of the program's waits for our `Register` to be
    /// settled: a call the portal may see ([`may_reach_portal`]) — and one
    /// with our `Register`'s serial, whatever it is and wherever it goes: an
    /// answer to it would pass for the portal's (`Conn::answered`), and the
    /// program cannot answer for us.
    fn holds(&self, h: &Header) -> bool {
        let reg = self.registration();
        matches!(reg.stage, Stage::Register(_))
            && (may_reach_portal(h) || reg.outstanding == Some(h.serial))
    }

    /// Wait while our `Register` is unanswered, as long as it takes — see
    /// [`Conn::wait_while`] for who ends it. And while it waits, the
    /// program's side is watched: a program that went (or shut its writing
    /// side) is held for no longer — what it sent still goes up, without an
    /// id, and its connection (one of the filter's few) is not kept.
    fn settle(&self, client: RawFd) {
        if !matches!(self.registration().stage, Stage::Register(_)) {
            return;
        }
        let Ok((wake_r, wake_w)) = sys::pipe() else {
            self.wait_while(|s| matches!(s, Stage::Register(_)));
            return;
        };
        thread::scope(|scope| {
            scope.spawn(|| {
                let mut fds = [
                    libc::pollfd {
                        fd: client,
                        events: libc::POLLRDHUP,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: wake_r.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];
                loop {
                    // SAFETY: two valid pollfds for the duration of the call.
                    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
                    if rc < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if fds[1].revents == 0 && fds[0].revents != 0 {
                    self.program_gone();
                }
            });
            self.wait_while(|s| matches!(s, Stage::Register(_)));
            // SAFETY: a valid descriptor and one byte.
            let _ = unsafe { libc::write(wake_w.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
        });
    }

    /// The portal that took the zone's id for this connection, if one did.
    fn portal(&self) -> Option<String> {
        self.registration().portal.clone()
    }
}

/// How far a connection's registration got.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum Stage {
    /// Nothing asked: no `--portal-app`, or before the program's Hello.
    #[default]
    Idle,
    /// The program's Hello is on its way up; its serial.
    Hello(u32),
    /// The bus answered it — with a name (`true`) or an error.
    Welcomed(bool),
    /// Our `Register` is on its way; its serial.
    Register(u32),
    /// Settled, whichever way.
    Done,
    /// The bus side went away.
    Closed,
}

#[derive(Debug, Default)]
struct Registration {
    stage: Stage,
    /// Our `Register` whose answer is still to come — swallowed whenever it
    /// does.
    outstanding: Option<u32>,
    /// The portal (its unique name) that took the zone's id for this
    /// connection; `None`: the connection has no id of the zone's.
    portal: Option<String>,
}

/// The serial of our `Register` on a connection whose Hello had `hello`: the
/// reserved one, or next to it should the program have picked that for its
/// Hello — the only call of the program's that is up while ours is.
fn register_serial(hello: u32) -> u32 {
    if hello == REGISTER_SERIAL {
        REGISTER_SERIAL - 1
    } else {
        REGISTER_SERIAL
    }
}

/// The program's first call, if the bus takes it for Hello: to the bus
/// itself, on its interface or on none.
fn is_hello(h: &Header) -> bool {
    h.kind == wire::METHOD_CALL
        && h.member.as_deref() == Some("Hello")
        && h.destination.as_deref() == Some("org.freedesktop.DBus")
        && h.interface
            .as_deref()
            .is_none_or(|i| i == "org.freedesktop.DBus")
}

/// Who the connection is to the portal (LEAK-MODEL §23): with the program's
/// Hello gone up, our own `Register(<portal_app>, {})` — once the bus has
/// answered the Hello, so that the connection has its name — on the
/// program's connection. From the program's first call the portal may see
/// ([`may_reach_portal`]) on, its messages are held, in order and with their
/// descriptors, until the portal answers; what it sends the bus and other
/// names before that goes on. They are held simply by not being read: this
/// is the only reader of the program's side.
///
/// The portal takes an id only before the first call it sees from a
/// connection ("Registered too late") and only once, so ours goes first, and
/// nothing the portal may see passes until the portal has settled it: a call
/// handled beside a `Register` still in the portal's hands could make the
/// connection a nameless one after all. The program cannot answer for us
/// either: its own `Register` is refused (`refused`), and the answer to ours
/// never reaches it (`Conn::answered`).
///
/// An error for an answer (an older portal, no entry for the id, the bus's
/// `NoReply` for a portal that never answers): the connection goes on
/// without an id of the zone's — what it had before —
/// said once. Refusing its portal calls instead would break every program on
/// an older portal, and the id only ever narrows what the portal does
/// (`screencast yes` needs it; nothing is let because of it).
fn register(conn: &Conn, ctx: &Ctx, up: RawFd, hello: &Header) -> io::Result<()> {
    let Some(app) = ctx.portal_app.as_deref() else {
        return Ok(());
    };
    conn.wait_while(|s| matches!(s, Stage::Hello(_)));
    let serial = register_serial(hello.serial);
    // Looked at and moved on under one lock: the bus side going in between
    // (`bus_gone`) would leave a `Register` waited for with nobody to
    // answer it.
    let welcomed = {
        let mut reg = conn.registration();
        let stage = reg.stage.clone();
        match stage {
            Stage::Welcomed(true) => {
                reg.stage = Stage::Register(serial);
                reg.outstanding = Some(serial);
            }
            Stage::Closed => {}
            _ => reg.stage = Stage::Done,
        }
        stage
    };
    match welcomed {
        Stage::Welcomed(true) => {}
        // Going anyway.
        Stage::Closed => return Ok(()),
        Stage::Welcomed(false) => {
            ctx.unregistered("the bus refused the program's Hello");
            return Ok(());
        }
        _ => {
            ctx.unregistered("no answer to the program's Hello");
            return Ok(());
        }
    }
    let call = wire::message(
        wire::METHOD_CALL,
        0,
        serial,
        &[
            Field::Path(PORTAL_PATH),
            Field::Interface(REGISTRY),
            Field::Member("Register"),
            Field::Destination(PORTAL),
            Field::Signature("sa{sv}"),
        ],
        &body::register(app),
    );
    // Not waited for here: the program's calls that may reach the portal
    // wait for the answer (`Conn::settle`); what goes elsewhere before them
    // goes on.
    send_all(up, &call, &[])
}

/// A call the portal may see: to its name, or to a unique name — which may
/// be the portal's (GDBus calls a name's owner by its unique name once it
/// knows it). Such a call waits for our `Register` to be settled; calls to
/// the bus and to other names, signals and replies do not.
fn may_reach_portal(h: &Header) -> bool {
    h.kind == wire::METHOD_CALL
        && h.destination
            .as_deref()
            .is_some_and(|d| d == PORTAL || d.starts_with(':'))
}

/// All of `data`, the descriptors with its first byte.
fn send_all(sock: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let first = data.len().min(READ_CHUNK);
    sys::send_with_fds(sock, &data[..first], fds)?;
    let mut rest = &data[first..];
    while !rest.is_empty() {
        let chunk = rest.len().min(READ_CHUNK);
        sys::send_with_fds(sock, &rest[..chunk], &[])?;
        rest = &rest[chunk..];
    }
    Ok(())
}

/// Serve until the launcher that started us goes.
pub fn run(args: &Args) -> u8 {
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    // The proxy behind is reached through its directory, held from here on:
    // in a zone that directory is about to be covered (`zone::hide_project_state`),
    // so that no program there can connect past this filter. And nobody of
    // the same uid here may borrow the descriptor through `/proc/<pid>/fd`:
    // not dumpable — its /proc is root's, and reading it takes CAP_SYS_PTRACE
    // over the namespace, which the zone's programs do not have.
    // SAFETY: prctl with these arguments takes no pointers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let upstream = match held_upstream(&args.upstream) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("bus-filter: cannot open {}: {e}", args.upstream.display());
            return 1;
        }
    };
    // The zone's directories for its screen cast switch, held before the
    // socket appears: the holder waits for the socket and then covers the
    // project's state in this very mount namespace.
    let screencast = args.zone.as_ref().map(|z| {
        crate::screencast::Policy::hold(&z.name, &z.dir, &z.config, z.profiles.as_deref())
    });
    let _ = fs::remove_file(&args.listen);
    let listener = match UnixListener::bind(&args.listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "bus-filter: cannot listen on {}: {e}",
                args.listen.display()
            );
            return 1;
        }
    };
    let _ = fs::set_permissions(&args.listen, fs::Permissions::from_mode(0o600));
    let ctx = Arc::new(Ctx::new(upstream, args, screencast));
    for client in listener.incoming() {
        let Ok(client) = client else {
            continue;
        };
        if ctx.connections.load(Ordering::SeqCst) as usize >= MAX_CONNECTIONS {
            eprintln!("bus-filter: too many connections — refused");
            continue;
        }
        let ctx = Arc::clone(&ctx);
        ctx.connections.fetch_add(1, Ordering::SeqCst);
        thread::spawn(move || {
            // A client that goes as soon as it has its answer is the usual
            // end, not news.
            match serve(client, &ctx) {
                Err(e)
                    if !matches!(
                        e.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    eprintln!("bus-filter: connection closed: {e}");
                }
                _ => {}
            }
            ctx.connections.fetch_sub(1, Ordering::SeqCst);
        });
    }
    0
}

fn serve(client: UnixStream, ctx: &Arc<Ctx>) -> io::Result<()> {
    // Whose program connected, while it is certainly the one: only where
    // there is a zone's switch to read by it.
    let who = match &ctx.screencast {
        Some(policy) => crate::origin::Peer::of(client.as_raw_fd())
            .map_or(crate::origin::Who::Unknown, |peer| policy.who(&peer)),
        None => crate::origin::Who::Main,
    };
    let conn = Arc::new(Conn::new(client.try_clone()?, who));
    serve_conn(client, &conn, ctx)
}

fn serve_conn(client: UnixStream, conn: &Arc<Conn>, ctx: &Arc<Ctx>) -> io::Result<()> {
    let upstream = UnixStream::connect(&ctx.upstream)?;
    let down = {
        let conn = Arc::clone(conn);
        let ctx = Arc::clone(ctx);
        let upstream = upstream.try_clone()?;
        thread::spawn(move || {
            let _ = bus_to_client(&upstream, &conn, &ctx);
            conn.bus_gone();
            let _ = conn.client.shutdown(std::net::Shutdown::Both);
            let _ = upstream.shutdown(std::net::Shutdown::Both);
        })
    };
    let result = client_to_bus(&client, &upstream, conn, ctx);
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = upstream.shutdown(std::net::Shutdown::Both);
    let _ = down.join();
    result
}

/// Read the next chunk: bytes and descriptors, `None` at the end.
fn read_chunk(
    sock: RawFd,
    buf: &mut [u8],
    fds: &mut VecDeque<OwnedFd>,
) -> io::Result<Option<usize>> {
    let (n, got, truncated) = sys::recv_into_with_fds(sock, buf, MAX_FDS_PER_READ)?;
    if truncated {
        return Err(io::Error::other("descriptors were cut off"));
    }
    fds.extend(got);
    if fds.len() > MAX_QUEUED_FDS {
        return Err(io::Error::other("too many descriptors"));
    }
    Ok((n > 0).then_some(n))
}

/// The complete messages at the front of `pending`, each with its header.
fn next_message(pending: &mut Vec<u8>) -> io::Result<Option<(Vec<u8>, Header)>> {
    let Some(len) = wire::message_len(pending).map_err(io::Error::other)? else {
        return Ok(None);
    };
    if pending.len() < len {
        return Ok(None);
    }
    let msg: Vec<u8> = pending.drain(..len).collect();
    let h = wire::parse_header(&msg).map_err(io::Error::other)?;
    Ok(Some((msg, h)))
}

fn take_fds(fds: &mut VecDeque<OwnedFd>, n: u32) -> io::Result<Vec<OwnedFd>> {
    let n = n as usize;
    if n > fds.len() {
        return Err(io::Error::other(
            "a message names descriptors that did not come",
        ));
    }
    Ok(fds.drain(..n).collect())
}

/// The client's side of the authentication, as the proxy behind reads it.
///
/// Where the authentication ends is where this filter starts reading
/// messages — and where xdg-dbus-proxy starts applying its rules. The two
/// must agree to the byte: a client that ends it in a way the proxy takes
/// and this filter does not (`BEGIN` followed by a blank and anything, as
/// dbus-daemon allows; or a first line glued to the credentials byte) would
/// have its calls go past the filter unread, OpenURI among them (review
/// 2026-09-25, third round). So the rules are the proxy's own
/// (`auth_line_is_valid`, `auth_line_is_begin` in flatpak-proxy.c): the first
/// byte apart, whole lines, ASCII without control characters beginning with
/// a capital, and a line the proxy would refuse ends the connection here. The
/// end is passed on as the plain `BEGIN` — then neither side can read it
/// differently.
#[derive(Default)]
struct Auth {
    first: bool,
    line: Vec<u8>,
    bytes: usize,
}

impl Auth {
    /// Take `data`: the lines to pass on, and where the messages start if the
    /// authentication ended in it.
    fn feed(&mut self, data: &[u8]) -> io::Result<(Vec<u8>, Option<usize>)> {
        let mut out = Vec::new();
        for (i, &b) in data.iter().enumerate() {
            self.bytes += 1;
            if self.bytes > MAX_AUTH_BYTES {
                return Err(io::Error::other("authentication too long"));
            }
            if !self.first {
                // The credentials byte, on its own as the proxy reads it.
                self.first = true;
                out.push(b);
                continue;
            }
            self.line.push(b);
            if !self.line.ends_with(b"\r\n") {
                continue;
            }
            let text = &self.line[..self.line.len() - 2];
            if !auth_line_is_valid(text) {
                return Err(io::Error::other(
                    "an authentication line the bus proxy would refuse",
                ));
            }
            if auth_line_is_begin(text) {
                out.extend_from_slice(b"BEGIN\r\n");
                self.line.clear();
                return Ok((out, Some(i + 1)));
            }
            out.extend_from_slice(&self.line);
            self.line.clear();
        }
        Ok((out, None))
    }
}

/// xdg-dbus-proxy's `auth_line_is_valid`: ASCII, no control characters, a
/// capital letter first.
fn auth_line_is_valid(line: &[u8]) -> bool {
    line.first().is_some_and(u8::is_ascii_uppercase)
        && line.iter().all(|&b| b.is_ascii() && b >= b' ')
}

/// xdg-dbus-proxy's `auth_line_is_begin`: `BEGIN`, alone or followed by a
/// blank and anything.
fn auth_line_is_begin(line: &[u8]) -> bool {
    line.strip_prefix(b"BEGIN")
        .is_some_and(|rest| matches!(rest.first(), None | Some(b' ' | b'\t')))
}

/// A call the host may have from a zone only rewritten: a notification
/// (`dbus_wire::sanitized_notify`, `sanitized_portal_notification`) and a
/// screen cast's choice of sources, which is not remembered unless
/// `remember` (`sanitized_screencast_sources`, `screencast_verdict`). The
/// message rewritten, an error for one the filter cannot read (refused, not
/// passed on unread), `None` for anything else.
fn rewritten(msg: &[u8], h: &Header, remember: bool) -> Option<Result<Vec<u8>, wire::WireError>> {
    if h.kind != wire::METHOD_CALL {
        return None;
    }
    let body = match (h.interface.as_deref(), h.member.as_deref()) {
        (Some("org.freedesktop.Notifications"), Some("Notify")) => {
            if h.unix_fds != 0 {
                return Some(Err(wire::WireError("a notification with descriptors")));
            }
            wire::sanitized_notify(msg, h)
        }
        (Some("org.freedesktop.portal.Notification"), Some("AddNotification")) => {
            wire::sanitized_portal_notification(msg, h)
        }
        (Some("org.freedesktop.portal.ScreenCast"), Some("SelectSources")) => {
            wire::sanitized_screencast_sources(msg, h, remember)
        }
        _ => return None,
    };
    Some(body.map(|body| {
        let mut fields = Vec::new();
        if let Some(path) = h.path.as_deref() {
            fields.push(Field::Path(path));
        }
        if let Some(interface) = h.interface.as_deref() {
            fields.push(Field::Interface(interface));
        }
        if let Some(member) = h.member.as_deref() {
            fields.push(Field::Member(member));
        }
        if let Some(destination) = h.destination.as_deref() {
            fields.push(Field::Destination(destination));
        }
        if let Some(signature) = h.signature.as_deref() {
            fields.push(Field::Signature(signature));
        }
        if h.unix_fds != 0 {
            fields.push(Field::UnixFds(h.unix_fds));
        }
        wire::message(h.kind, h.flags, h.serial, &fields, &body)
    }))
}

/// `upstream` as `/proc/self/fd/N/<name>`, N a descriptor of its directory
/// kept for the life of the process.
fn held_upstream(upstream: &Path) -> io::Result<PathBuf> {
    let (Some(dir), Some(name)) = (upstream.parent(), upstream.file_name()) else {
        return Err(io::Error::other("not a path to a socket"));
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let fd = sys::open_dir(dir)?.into_raw_fd();
    Ok(Path::new(&format!("/proc/self/fd/{fd}")).join(name))
}

fn client_to_bus(
    client: &UnixStream,
    upstream: &UnixStream,
    conn: &Conn,
    ctx: &Ctx,
) -> io::Result<()> {
    let mut buf = vec![0u8; READ_CHUNK];
    let mut fds: VecDeque<OwnedFd> = VecDeque::new();
    let mut auth = Auth::default();
    let mut pending: Vec<u8> = Vec::new();
    let up = upstream.as_raw_fd();
    let mut first = true;
    while let Some(n) = read_chunk(client.as_raw_fd(), &mut buf, &mut fds)? {
        let mut data = &buf[..n];
        if !conn.began.load(Ordering::SeqCst) {
            // The authentication, whole lines at a time, up to BEGIN; what
            // follows BEGIN is messages.
            let (lines, split) = auth.feed(data)?;
            if split.is_some() {
                // Before the bus can answer it, so that the other direction
                // knows to expect messages.
                conn.began.store(true, Ordering::SeqCst);
            }
            send_all(up, &lines, &[])?;
            let Some(split) = split else {
                continue;
            };
            data = &data[split..];
        }
        pending.extend_from_slice(data);
        while let Some((msg, h)) = next_message(&mut pending)? {
            let carried = take_fds(&mut fds, h.unix_fds)?;
            // The program's Hello, as it is — and the connection is the
            // zone's before anything else of the program's goes up
            // (`register`). Only the first message: the bus takes no other
            // for a Hello. One that wants no answer gives nothing to wait for.
            if std::mem::take(&mut first)
                && ctx.portal_app.is_some()
                && is_hello(&h)
                && h.flags & wire::NO_REPLY_EXPECTED == 0
            {
                conn.registration().stage = Stage::Hello(h.serial);
                let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
                send_all(up, &msg, &raw)?;
                register(conn, ctx, up, &h)?;
                continue;
            }
            // The first call that may reach the portal waits for our
            // `Register` to be settled — and everything after it with it,
            // unread, in order; what went before it is up already.
            if conn.holds(&h) {
                conn.settle(client.as_raw_fd());
            }
            match door(&h) {
                // The descriptors of an answered call are dropped — closed.
                Some(which @ (Door::Network | Door::Proxy)) => answer_value(conn, ctx, &h, which)?,
                Some(which) => answer(conn, ctx, &msg, &h, which)?,
                // So are those of a refused one.
                None if refused(&h).is_some() => {
                    deny(conn, ctx, &h, &refused(&h).unwrap_or_default())?
                }
                // The zone's screen cast switch (`crate::screencast`): `no`
                // refuses the call — and closes its descriptors.
                None => match screencast_verdict(conn, ctx, &h) {
                    Cast::Refuse(why) => error_reply(conn, ctx, &h, NOT_ALLOWED, &why)?,
                    cast => {
                        let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
                        match rewritten(&msg, &h, cast == Cast::Remember) {
                            // Passed on without what would point the host's
                            // daemon at the network or at an application, or
                            // have the screen shown again without a question
                            // where the switch does not say so.
                            Some(Ok(message)) => send_all(up, &message, &raw)?,
                            Some(Err(e)) => deny(conn, ctx, &h, &format!("call refused: {e}"))?,
                            None => send_all(up, &msg, &raw)?,
                        }
                    }
                },
            }
        }
    }
    Ok(())
}

fn bus_to_client(upstream: &UnixStream, conn: &Conn, ctx: &Ctx) -> io::Result<()> {
    let mut buf = vec![0u8; READ_CHUNK];
    let mut fds: VecDeque<OwnedFd> = VecDeque::new();
    let mut text: Vec<u8> = Vec::new();
    let mut binary = false;
    let mut pending: Vec<u8> = Vec::new();
    while let Some(n) = read_chunk(upstream.as_raw_fd(), &mut buf, &mut fds)? {
        if binary {
            pending.extend_from_slice(&buf[..n]);
        } else {
            text.extend_from_slice(&buf[..n]);
            // The bus's lines (OK, AGREE_UNIX_FD, REJECTED…) go through as
            // they are. Its first message can only follow the client's BEGIN,
            // and a message starts with its endianness byte, which no line
            // does.
            loop {
                let begins_message =
                    conn.began.load(Ordering::SeqCst) && matches!(text.first(), Some(b'l' | b'B'));
                if begins_message {
                    binary = true;
                    pending = std::mem::take(&mut text);
                    break;
                }
                let Some(end) = text.windows(2).position(|w| w == b"\r\n") else {
                    break;
                };
                let line: Vec<u8> = text.drain(..end + 2).collect();
                conn.send(&line, &[])?;
            }
            if text.len() > MAX_AUTH_BYTES {
                return Err(io::Error::other("authentication too long"));
            }
        }
        while let Some((msg, h)) = next_message(&mut pending)? {
            // The bus addresses the connection by its unique name, first in
            // the reply to Hello: what a portal request's path is made of.
            if let Some(dest) = h.destination.as_deref().filter(|d| d.starts_with(':')) {
                let mut unique = conn.unique.lock().unwrap_or_else(|e| e.into_inner());
                if unique.is_none() {
                    *unique = Some(dest.to_owned());
                }
            }
            let carried = take_fds(&mut fds, h.unix_fds)?;
            // The answer to our own `Register` is ours: the program never
            // sees it (and its descriptors, if any, are closed).
            if conn.answered(ctx, &msg, &h) {
                continue;
            }
            let raw: Vec<RawFd> = carried.iter().map(AsRawFd::as_raw_fd).collect();
            conn.send(&msg, &raw)?;
        }
    }
    Ok(())
}

/// Answer a call the way the portal would: the request's handle, then its
/// `Response` — done, or cancelled.
fn answer(conn: &Conn, ctx: &Ctx, msg: &[u8], h: &Header, which: Door) -> io::Result<()> {
    let parsed = wire::portal_call(msg, h)
        .map_err(|e| {
            eprintln!(
                "bus-filter: {} does not parse: {e}",
                h.member.as_deref().unwrap_or("?")
            )
        })
        .ok();
    let token = parsed.as_ref().and_then(|(_, t)| t.clone());
    let unique = conn
        .unique
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let handle = handle_path(unique.as_deref(), token.as_deref(), ctx.serial());
    // A client checks that a portal signal comes from the portal's current
    // owner (GLib since 2.80.1): the unique name, asked on a connection of
    // our own. With no portal running, the well-known name is all there is.
    let portal = portal_owner(&ctx.upstream).unwrap_or_else(|| PORTAL.to_owned());
    let dest = unique.as_deref();

    if h.flags & wire::NO_REPLY_EXPECTED == 0 {
        let mut fields = vec![Field::ReplySerial(h.serial), Field::Sender(&portal)];
        if let Some(d) = dest {
            fields.push(Field::Destination(d));
        }
        fields.push(Field::Signature("o"));
        let reply = wire::message(
            wire::METHOD_RETURN,
            wire::NO_REPLY_EXPECTED,
            ctx.serial(),
            &fields,
            &body::string(&handle),
        );
        conn.send(&reply, &[])?;
    }

    let code = match which {
        Door::Uri => match parsed.as_ref().and_then(|(s, _)| s.get(1)) {
            Some(uri) => open_link(ctx, uri, &conn.who),
            None => {
                eprintln!("bus-filter: OpenURI that does not parse — refused");
                RESPONSE_OTHER
            }
        },
        Door::File => {
            eprintln!(
                "bus-filter: {} refused — a file of the sandbox is not opened on the host",
                h.member.as_deref().unwrap_or("?")
            );
            notify(ctx, "Файл не открыт", FILE_NOTICE);
            RESPONSE_OTHER
        }
        Door::Email => {
            eprintln!(
                "bus-filter: ComposeEmail refused — the host's mail client is outside the zone"
            );
            notify(
                ctx,
                "Письмо не создано",
                "Программа из контейнера попросила почтовый клиент хоста — он вне её зоны, \
                 поэтому не открыт.",
            );
            RESPONSE_OTHER
        }
        Door::Background => {
            // No note to the user: programs ask this at every start, and the
            // answer changes nothing they can do while running.
            eprintln!(
                "bus-filter: RequestBackground refused — autostart would be the host's, outside the zone"
            );
            RESPONSE_OTHER
        }
        // Answered with a value, never a Request (`answer_value`): here only
        // if called wrongly, and then refused.
        Door::Network | Door::Proxy => RESPONSE_OTHER,
    };

    let mut fields = vec![
        Field::Path(&handle),
        Field::Interface(REQUEST),
        Field::Member("Response"),
        Field::Sender(&portal),
    ];
    if let Some(d) = dest {
        fields.push(Field::Destination(d));
    }
    fields.push(Field::Signature("ua{sv}"));
    let signal = wire::message(
        wire::SIGNAL,
        wire::NO_REPLY_EXPECTED,
        ctx.serial(),
        &fields,
        &body::response(code),
    );
    conn.send(&signal, &[])
}

/// Hand a link to the broker on the host (`crate::links`): the program is
/// chosen there — the container's rule, the distribution's window of choice
/// —, then the network and the container. `who`: whose program's connection
/// asks, which the broker believes from the zone's own filter alone. The
/// person may take their time over the windows, and the program's bus goes
/// on meanwhile: handed over in a thread of its own, and the portal's answer
/// is "done" at once — a link they then decide not to open is one the
/// program need not hear of. With no broker to hand it to, a sandbox's
/// filter on the host opens it as it did, with the opener; a zone's does not.
/// The response code for the portal answer.
fn open_link(ctx: &Ctx, uri: &str, who: &crate::origin::Who) -> u32 {
    let shown = loggable(uri);
    if let Err(why) = acceptable(uri) {
        eprintln!("bus-filter: link {shown} refused: {why}");
        if why == "a local file" {
            notify(ctx, "Файл не открыт", FILE_NOTICE);
        }
        return RESPONSE_OTHER;
    }
    if !ctx.may_open() {
        eprintln!("bus-filter: link {shown} refused: more than {MAX_OPENS_PER_MINUTE} a minute");
        return RESPONSE_OTHER;
    }
    let claim = match who {
        crate::origin::Who::Main => crate::broker::LINK_MAIN.to_owned(),
        crate::origin::Who::Container(name) => name.clone(),
        crate::origin::Who::Unknown => String::new(),
    };
    let (uri, opener, in_zone) = (uri.to_owned(), ctx.opener.clone(), ctx.via_broker.is_some());
    thread::spawn(move || match crate::broker::link(&uri, &claim) {
        crate::broker::Linked::Opened => eprintln!("bus-filter: link {shown} → the broker"),
        crate::broker::Linked::Refused => {
            eprintln!("bus-filter: link {shown}: the broker did not open it")
        }
        // A sandbox on the host: its links open as before.
        crate::broker::Linked::NotAZone | crate::broker::Linked::NoBroker if !in_zone => {
            run_opener(&opener, &uri, &shown)
        }
        _ => eprintln!("bus-filter: link {shown}: no broker to hand it to — not opened"),
    });
    RESPONSE_OK
}

/// The opener, in this process's context: a sandbox's filter on the host —
/// the broker opens zones' links only — or with no broker to ask.
fn run_opener(opener: &Path, uri: &str, shown: &str) {
    match Command::new(opener)
        .arg(uri)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            eprintln!("bus-filter: link {shown} → {}", opener.display());
            let _ = child.wait();
        }
        Err(e) => eprintln!(
            "bus-filter: link {shown}: cannot run {}: {e}",
            opener.display()
        ),
    }
}

/// A short connection of the filter's own through the same filtered bus: the
/// same rules as the program's, nothing the program could not ask itself.
struct OwnConn {
    stream: UnixStream,
    pending: Vec<u8>,
    serial: u32,
}

impl OwnConn {
    fn open(upstream: &Path) -> Option<Self> {
        // No clock of ours: what is asked on it is the bus's own (the
        // portal's owner, answered at once) or asked from a thread of its own
        // (a notice, `notify`) — a callee that never answers holds only that.
        let mut stream = UnixStream::connect(upstream).ok()?;
        // SAFETY: getuid(2) cannot fail and takes no pointers.
        let uid = unsafe { libc::getuid() }.to_string();
        let hex: String = uid.bytes().map(|b| format!("{b:02x}")).collect();
        stream
            .write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())
            .ok()?;
        let mut pending = Vec::new();
        let mut chunk = [0u8; 512];
        let line_end = loop {
            if let Some(end) = pending.windows(2).position(|w| w == b"\r\n") {
                break end;
            }
            let n = io::Read::read(&mut stream, &mut chunk).ok()?;
            if n == 0 || pending.len() > MAX_AUTH_BYTES {
                return None;
            }
            pending.extend_from_slice(&chunk[..n]);
        };
        if !pending.starts_with(b"OK ") {
            return None;
        }
        pending.drain(..line_end + 2);
        stream.write_all(b"BEGIN\r\n").ok()?;
        let mut conn = Self {
            stream,
            pending,
            serial: 0,
        };
        conn.call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
            None,
            &[],
        )?;
        Some(conn)
    }

    /// A method call and its reply (or error), or `None` when the connection
    /// ends first.
    fn call(
        &mut self,
        dest: &str,
        path: &str,
        iface: &str,
        member: &str,
        sig: Option<&str>,
        body: &[u8],
    ) -> Option<(Vec<u8>, Header)> {
        self.serial += 1;
        let serial = self.serial;
        let mut fields = vec![
            Field::Path(path),
            Field::Interface(iface),
            Field::Member(member),
            Field::Destination(dest),
        ];
        if let Some(sig) = sig {
            fields.push(Field::Signature(sig));
        }
        self.stream
            .write_all(&wire::message(wire::METHOD_CALL, 0, serial, &fields, body))
            .ok()?;
        let mut chunk = [0u8; 4096];
        loop {
            while let Ok(Some((msg, h))) = next_message(&mut self.pending) {
                if h.reply_serial == Some(serial) {
                    return Some((msg, h));
                }
            }
            let n = io::Read::read(&mut self.stream, &mut chunk).ok()?;
            if n == 0 || self.pending.len() > 1 << 20 {
                return None;
            }
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }
}

/// The portal's unique name, asked on a connection of our own.
fn portal_owner(upstream: &Path) -> Option<String> {
    let mut conn = OwnConn::open(upstream)?;
    let (msg, h) = conn.call(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetNameOwner",
        Some("s"),
        &body::string(PORTAL),
    )?;
    (h.kind == wire::METHOD_RETURN)
        .then(|| wire::body_string(&msg, &h).ok())
        .flatten()
}

/// Say why nothing opened: a refusal nobody sees looks like a broken program.
/// At most one notice in [`NOTICE_EVERY`], so that a program cannot flood the
/// desktop with them.
fn notify(ctx: &Ctx, summary: &str, text: &str) {
    {
        let mut last = ctx.last_notice.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|t| t.elapsed() < NOTICE_EVERY) {
            return;
        }
        *last = Some(Instant::now());
    }
    // In a thread of its own: a notification daemon slow to answer holds
    // nothing of the program's. One at a time: a daemon that never answers
    // holds one thread, not one per notice.
    static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
    if IN_FLIGHT.swap(true, Ordering::SeqCst) {
        return;
    }
    let (upstream, summary, text) = (ctx.upstream.clone(), summary.to_owned(), text.to_owned());
    thread::spawn(move || {
        struct Landed;
        impl Drop for Landed {
            fn drop(&mut self) {
                IN_FLIGHT.store(false, Ordering::SeqCst);
            }
        }
        let _landed = Landed;
        let Some(mut conn) = OwnConn::open(&upstream) else {
            return;
        };
        let _ = conn.call(
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "Notify",
            Some(body::NOTIFY_SIGNATURE),
            &body::notification(crate::dialog::APP, &summary, &text),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the authentication ends, the proxy's way: whatever follows a
    /// blank after BEGIN, a first line glued to the credentials byte, a line
    /// cut between two reads. The end goes on as the plain BEGIN.
    #[test]
    fn the_authentication_ends_where_the_proxy_says() {
        let mut auth = Auth::default();
        let (out, split) = auth
            .feed(b"\0AUTH EXTERNAL 31303030\r\nBEGIN now\r\nl\x01")
            .unwrap();
        assert_eq!(out, b"\0AUTH EXTERNAL 31303030\r\nBEGIN\r\n");
        assert_eq!(split, Some(36));

        let mut auth = Auth::default();
        let (out, split) = auth.feed(b"\0BEGIN\r\n").unwrap();
        assert_eq!((out.as_slice(), split), (&b"\0BEGIN\r\n"[..], Some(8)));

        let mut auth = Auth::default();
        assert_eq!(
            auth.feed(b"\0NEGOTIATE_UNIX_FD\r\nBEG").unwrap(),
            (b"\0NEGOTIATE_UNIX_FD\r\n".to_vec(), None)
        );
        assert_eq!(
            auth.feed(b"IN\r\nl").unwrap(),
            (b"BEGIN\r\n".to_vec(), Some(4))
        );
    }

    /// A line the proxy would refuse ends the connection here as well, rather
    /// than being read one way here and another there.
    #[test]
    fn a_line_the_proxy_refuses_is_refused() {
        for line in [
            &b"\0BEGIN\tx\r\n"[..],
            b"\0BEGIN\0x\r\n",
            b"\0begin\r\n",
            b"\0 BEGIN\r\n",
            b"\0\r\n",
            b"\0AUTH \xd0\x96\r\n",
        ] {
            assert!(Auth::default().feed(line).is_err(), "{line:?}");
        }
        // Not the end, and passed on: BEGINNING is another word.
        let mut auth = Auth::default();
        assert_eq!(
            auth.feed(b"\0BEGINNING\r\n").unwrap(),
            (b"\0BEGINNING\r\n".to_vec(), None)
        );
    }

    fn call(member: &str, interface: Option<&str>, dest: &str) -> Header {
        Header {
            kind: wire::METHOD_CALL,
            member: Some(member.to_owned()),
            interface: interface.map(str::to_owned),
            destination: Some(dest.to_owned()),
            ..Header::default()
        }
    }

    /// Recognised by what is called, not by whom: the portal's unique name and
    /// a call with no interface field reach it just the same.
    #[test]
    fn the_doors_are_known_by_member_and_interface() {
        assert_eq!(
            door(&call("OpenURI", Some(OPEN_URI), PORTAL)),
            Some(Door::Uri)
        );
        assert_eq!(
            door(&call("OpenURI", Some(OPEN_URI), ":1.7")),
            Some(Door::Uri)
        );
        assert_eq!(door(&call("OpenURI", None, ":1.7")), Some(Door::Uri));
        assert_eq!(door(&call("OpenFile", None, PORTAL)), Some(Door::File));
        assert_eq!(
            door(&call("OpenDirectory", Some(OPEN_URI), PORTAL)),
            Some(Door::File)
        );
        assert_eq!(
            door(&call("ComposeEmail", Some(EMAIL), PORTAL)),
            Some(Door::Email)
        );
        assert_eq!(
            door(&call("RequestBackground", Some(BACKGROUND), PORTAL)),
            Some(Door::Background)
        );
        assert_eq!(
            door(&call("RequestBackground", None, ":1.7")),
            Some(Door::Background)
        );
        // The same member on another interface, a query, a signal: passed on.
        assert_eq!(
            door(&call("OpenURI", Some("org.example.Other"), PORTAL)),
            None
        );
        assert_eq!(door(&call("SchemeSupported", Some(OPEN_URI), PORTAL)), None);
        let mut signal = call("OpenURI", Some(OPEN_URI), PORTAL);
        signal.kind = wire::SIGNAL;
        assert_eq!(door(&signal), None);
    }

    #[test]
    fn links_are_checked_and_logged_without_their_secrets() {
        assert!(acceptable("https://example.org/a?b=c").is_ok());
        assert!(acceptable("mailto:someone@example.org").is_ok());
        assert!(acceptable("tg://resolve?domain=x").is_ok());
        assert_eq!(acceptable("file:///etc/passwd"), Err("a local file"));
        assert_eq!(acceptable("FILE:///x"), Err("a local file"));
        assert_eq!(
            acceptable("https://a b"),
            Err("control characters or spaces")
        );
        assert_eq!(
            acceptable("https://a\nb"),
            Err("control characters or spaces")
        );
        assert_eq!(acceptable("-x:y"), Err("not a scheme"));
        assert_eq!(acceptable("no-colon"), Err("no scheme"));
        assert_eq!(
            acceptable(&format!("https://{}", "a".repeat(MAX_URI))),
            Err("too long")
        );
        assert_eq!(
            loggable("https://user:pw@example.org/path?token=secret#x"),
            "https://example.org"
        );
        assert_eq!(loggable("mailto:someone@example.org"), "mailto:…");
    }

    #[test]
    fn a_request_path_is_made_of_the_sender_and_the_token() {
        assert_eq!(
            handle_path(Some(":1.42"), Some("gtk3"), 5),
            "/org/freedesktop/portal/desktop/request/1_42/gtk3"
        );
        assert_eq!(
            handle_path(Some(":1.42"), Some("bad/token"), 5),
            "/org/freedesktop/portal/desktop/request/1_42/vpnzones5"
        );
        assert_eq!(
            handle_path(None, None, 9),
            "/org/freedesktop/portal/desktop/request/unknown/vpnzones9"
        );
    }

    #[test]
    fn at_most_so_many_links_a_minute() {
        let ctx = Ctx::for_test(PathBuf::new(), None);
        for _ in 0..MAX_OPENS_PER_MINUTE {
            assert!(ctx.may_open());
        }
        assert!(!ctx.may_open());
        assert_ne!(ctx.serial(), 0);
    }

    /// The portal takes a zone's program for a host application: only the
    /// named portal interfaces get through, and no call without an interface.
    #[test]
    fn only_the_named_portal_interfaces_get_through() {
        let on = |iface: Option<&str>, dest: &str| {
            let mut h = call("Anything", iface, dest);
            h.destination = Some(dest.to_owned());
            refused(&h)
        };
        for bad in [
            "org.freedesktop.portal.DynamicLauncher",
            "org.freedesktop.portal.Location",
            "org.freedesktop.portal.Camera",
            "org.freedesktop.portal.Screenshot",
            "org.freedesktop.portal.Secret",
            "org.freedesktop.portal.Realtime",
            "org.freedesktop.portal.Documents",
            "org.freedesktop.portal.SomethingNew",
            "org.freedesktop.host.portal.Registry",
            "org.freedesktop.host.SomethingNew",
        ] {
            assert!(on(Some(bad), PORTAL).is_some(), "{bad}");
            // Not by the portal's well-known name either.
            assert!(on(Some(bad), ":1.42").is_some(), "{bad} by a unique name");
        }
        for good in [
            "org.freedesktop.portal.FileChooser",
            "org.freedesktop.portal.Settings",
            "org.freedesktop.portal.Request",
            "org.freedesktop.DBus.Properties",
            "org.freedesktop.Notifications",
            "org.kde.StatusNotifierWatcher",
        ] {
            assert!(on(Some(good), PORTAL).is_none(), "{good}");
        }
        assert!(on(None, PORTAL).is_some());
        assert!(on(None, "org.freedesktop.DBus").is_none());
        let mut signal = call("Anything", Some("org.freedesktop.portal.Location"), PORTAL);
        signal.kind = wire::SIGNAL;
        assert!(refused(&signal).is_none());
    }

    /// The host's network state is not asked for: the filter answers.
    #[test]
    fn network_and_proxy_questions_are_answered_here() {
        for member in [
            "GetAvailable",
            "GetMetered",
            "GetConnectivity",
            "GetStatus",
            "CanReach",
        ] {
            assert_eq!(
                door(&call(member, Some(NETWORK_MONITOR), PORTAL)),
                Some(Door::Network),
                "{member}"
            );
        }
        assert_eq!(
            door(&call("Lookup", Some(PROXY_RESOLVER), PORTAL)),
            Some(Door::Proxy)
        );
        // The trash is not among what passes any more.
        let mut h = call("TrashFile", Some("org.freedesktop.portal.Trash"), PORTAL);
        h.destination = Some(PORTAL.to_owned());
        assert!(refused(&h).is_some());
        // `as` with one string: length 14, then the string.
        let b = body::strings(&["direct://"]);
        assert_eq!(&b[..4], &14u32.to_le_bytes());
        assert_eq!(&b[4..8], &9u32.to_le_bytes());
        assert_eq!(&b[8..17], b"direct://");
        // `a{sv}` of three entries parses back as one array of the stated length.
        let st = body::network_status(true, false, 4);
        let len = u32::from_le_bytes(st[..4].try_into().unwrap()) as usize;
        assert_eq!(st.len(), 8 + len);
    }

    // --- WHO THE CONNECTION IS TO THE PORTAL --------------------------------

    impl Ctx {
        fn for_test(upstream: PathBuf, portal_app: Option<&str>) -> Self {
            let args = Args {
                listen: PathBuf::new(),
                upstream: upstream.clone(),
                opener: PathBuf::new(),
                via_broker: None,
                portal_app: portal_app.map(str::to_owned),
                zone: None,
            };
            Self::new(upstream, &args, None)
        }
    }

    /// A stand-in for what is behind the filter — xdg-dbus-proxy and the bus
    /// in the real chain: a socket the filter connects to, read and answered
    /// by the test.
    struct Stand {
        dir: PathBuf,
        listener: UnixListener,
    }

    impl Stand {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("vpn-zone-bus-filter-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let listener = UnixListener::bind(dir.join("bus")).unwrap();
            Self { dir, listener }
        }

        fn socket(&self) -> PathBuf {
            self.dir.join("bus")
        }

        /// The filter's connection upstream.
        fn accept(&self) -> End {
            End::new(self.listener.accept().unwrap().0)
        }
    }

    impl Drop for Stand {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// One end of a connection, read line by line or message by message,
    /// with the descriptors that came along.
    struct End {
        stream: UnixStream,
        pending: Vec<u8>,
        fds: VecDeque<OwnedFd>,
    }

    impl End {
        const PATIENCE: Duration = Duration::from_secs(10);

        fn new(stream: UnixStream) -> Self {
            stream.set_read_timeout(Some(Self::PATIENCE)).unwrap();
            Self {
                stream,
                pending: Vec::new(),
                fds: VecDeque::new(),
            }
        }

        fn send(&self, bytes: &[u8], fds: &[RawFd]) {
            sys::send_with_fds(self.stream.as_raw_fd(), bytes, fds).unwrap();
        }

        /// More bytes; `false` when none came in time (or at the end).
        fn more(&mut self) -> bool {
            let mut buf = [0u8; 4096];
            match sys::recv_into_with_fds(self.stream.as_raw_fd(), &mut buf, 16) {
                Ok((0, _, _)) => false,
                Ok((n, fds, _)) => {
                    self.pending.extend_from_slice(&buf[..n]);
                    self.fds.extend(fds);
                    true
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
                Err(e) => panic!("{e}"),
            }
        }

        /// The next line, `\r\n` included.
        fn line(&mut self) -> Vec<u8> {
            loop {
                if let Some(end) = self.pending.windows(2).position(|w| w == b"\r\n") {
                    return self.pending.drain(..end + 2).collect();
                }
                assert!(self.more(), "no line came");
            }
        }

        /// The next message, and the descriptors it carries.
        fn message(&mut self) -> (Vec<u8>, Header, Vec<OwnedFd>) {
            loop {
                if let Some(len) = wire::message_len(&self.pending).unwrap() {
                    if self.pending.len() >= len {
                        let msg: Vec<u8> = self.pending.drain(..len).collect();
                        let h = wire::parse_header(&msg).unwrap();
                        let fds = self.fds.drain(..h.unix_fds as usize).collect();
                        return (msg, h, fds);
                    }
                }
                assert!(self.more(), "no message came");
            }
        }

        /// Nothing comes for `quiet`.
        fn quiet(&mut self, quiet: Duration) -> bool {
            if !self.pending.is_empty() {
                return false;
            }
            self.stream.set_read_timeout(Some(quiet)).unwrap();
            let came = self.more() && !self.pending.is_empty();
            self.stream.set_read_timeout(Some(Self::PATIENCE)).unwrap();
            !came
        }
    }

    /// A method call from the program.
    fn method(serial: u32, dest: &str, iface: &str, member: &str, fds: u32) -> Vec<u8> {
        let mut fields = vec![
            Field::Path("/org/freedesktop/portal/desktop"),
            Field::Interface(iface),
            Field::Member(member),
            Field::Destination(dest),
        ];
        if fds != 0 {
            fields.push(Field::Signature("h"));
            fields.push(Field::UnixFds(fds));
        }
        let body = if fds != 0 { body::uint(0) } else { Vec::new() };
        wire::message(wire::METHOD_CALL, 0, serial, &fields, &body)
    }

    fn hello(serial: u32) -> Vec<u8> {
        wire::message(
            wire::METHOD_CALL,
            0,
            serial,
            &[
                Field::Path("/org/freedesktop/DBus"),
                Field::Interface("org.freedesktop.DBus"),
                Field::Member("Hello"),
                Field::Destination("org.freedesktop.DBus"),
            ],
            &[],
        )
    }

    /// A reply from the bus side to the program's connection, `:1.42`.
    fn reply_to(serial: u32, from: &str) -> Vec<u8> {
        wire::message(
            wire::METHOD_RETURN,
            wire::NO_REPLY_EXPECTED,
            7000 + serial % 1000,
            &[
                Field::ReplySerial(serial),
                Field::Destination(":1.42"),
                Field::Sender(from),
                Field::Signature("s"),
            ],
            &body::string(":1.42"),
        )
    }

    fn error_to(serial: u32, name: &str, text: &str) -> Vec<u8> {
        wire::message(
            wire::ERROR,
            wire::NO_REPLY_EXPECTED,
            8000,
            &[
                Field::ErrorName(name),
                Field::ReplySerial(serial),
                Field::Destination(":1.42"),
                Field::Sender(":1.7"),
                Field::Signature("s"),
            ],
            &body::string(text),
        )
    }

    /// What a program writes first, the way sd-bus pipelines it: the
    /// authentication, its Hello and `calls` in one go.
    const AUTH: &[u8] = b"\0AUTH EXTERNAL 31303030\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";

    /// A filter serving one program's connection to the stand-in bus: the
    /// program's end, the bus's end, and the connection's own state.
    struct Served {
        program: End,
        bus: End,
        conn: Arc<Conn>,
        ctx: Arc<Ctx>,
        serving: Option<thread::JoinHandle<()>>,
        stand: Stand,
    }

    impl Served {
        fn start(tag: &str, portal_app: Option<&str>, ctx: impl FnOnce(Ctx) -> Ctx) -> Self {
            Self::start_as(tag, portal_app, crate::origin::Who::Main, ctx)
        }

        /// [`Served::start`] for a program of `who`.
        fn start_as(
            tag: &str,
            portal_app: Option<&str>,
            who: crate::origin::Who,
            ctx: impl FnOnce(Ctx) -> Ctx,
        ) -> Self {
            let stand = Stand::new(tag);
            let ctx = Arc::new(ctx(Ctx::for_test(stand.socket(), portal_app)));
            let (program, filter) = UnixStream::pair().unwrap();
            let conn = Arc::new(Conn::new(filter.try_clone().unwrap(), who));
            let serving = {
                let (conn, ctx) = (Arc::clone(&conn), Arc::clone(&ctx));
                thread::spawn(move || {
                    let _ = serve_conn(filter, &conn, &ctx);
                })
            };
            let bus = stand.accept();
            Self {
                program: End::new(program),
                bus,
                conn,
                ctx,
                serving: Some(serving),
                stand,
            }
        }

        /// The authentication through, both ways.
        fn authenticated(&mut self) {
            assert_eq!(self.bus.line(), b"\0AUTH EXTERNAL 31303030\r\n");
            assert_eq!(self.bus.line(), b"NEGOTIATE_UNIX_FD\r\n");
            assert_eq!(self.bus.line(), b"BEGIN\r\n");
            self.bus
                .send(b"OK 0123456789abcdef\r\nAGREE_UNIX_FD\r\n", &[]);
            assert_eq!(self.program.line(), b"OK 0123456789abcdef\r\n");
            assert_eq!(self.program.line(), b"AGREE_UNIX_FD\r\n");
        }

        fn portal(&self) -> Option<String> {
            self.conn.registration().portal.clone()
        }
    }

    impl Drop for Served {
        fn drop(&mut self) {
            let _ = self.program.stream.shutdown(std::net::Shutdown::Both);
            let _ = self.bus.stream.shutdown(std::net::Shutdown::Both);
            if let Some(serving) = self.serving.take() {
                let _ = serving.join();
            }
        }
    }

    const SETTINGS: &str = "org.freedesktop.portal.Settings";
    const HELD: Duration = Duration::from_millis(300);

    /// Our `Register` as the bus side sees it: the zone's id, to the portal,
    /// on the program's own connection under the reserved serial.
    fn assert_register(msg: &[u8], h: &Header, serial: u32) {
        assert_eq!(h.kind, wire::METHOD_CALL);
        assert_eq!(h.serial, serial);
        assert_eq!(h.flags & wire::NO_REPLY_EXPECTED, 0);
        assert_eq!(h.interface.as_deref(), Some(REGISTRY));
        assert_eq!(h.member.as_deref(), Some("Register"));
        assert_eq!(h.destination.as_deref(), Some(PORTAL));
        assert_eq!(h.path.as_deref(), Some(PORTAL_PATH));
        assert_eq!(h.signature.as_deref(), Some("sa{sv}"));
        assert_eq!(h.unix_fds, 0);
        assert_eq!(&msg[h.body_offset..], body::register("cellward.zone.nl"));
    }

    /// The connection is the zone's before its first call: the program's
    /// Hello goes up at once, its pipelined calls wait — in order, with
    /// their descriptors — while ours asks the portal, and the portal's
    /// answer to ours never reaches the program.
    #[test]
    fn the_connection_is_the_zones_before_its_first_call() {
        let mut s = Served::start("register", Some("cellward.zone.nl"), |c| c);
        // A descriptor with the first call: a socket, checked to be the same
        // one at the other end.
        let (kept, passed) = UnixStream::pair().unwrap();
        let mut first = AUTH.to_vec();
        first.extend(hello(1));
        first.extend(method(2, PORTAL, SETTINGS, "ReadAll", 1));
        first.extend(method(3, PORTAL, SETTINGS, "Read", 0));
        s.program.send(&first, &[passed.as_raw_fd()]);
        drop(passed);
        s.authenticated();

        let (_, h, _) = s.bus.message();
        assert_eq!((h.member.as_deref(), h.serial), (Some("Hello"), 1));
        // Held until the bus has named the connection.
        assert!(
            s.bus.quiet(HELD),
            "a call went up before the Hello's answer"
        );
        s.bus.send(&reply_to(1, "org.freedesktop.DBus"), &[]);

        let (msg, h, _) = s.bus.message();
        assert_register(&msg, &h, REGISTER_SERIAL);
        // And held until the portal answers ours.
        assert!(
            s.bus.quiet(HELD),
            "a call went up before the portal's answer"
        );
        s.bus.send(&reply_to(REGISTER_SERIAL, ":1.7"), &[]);

        let (_, h, fds) = s.bus.message();
        assert_eq!((h.member.as_deref(), h.serial), (Some("ReadAll"), 2));
        assert_eq!(fds.len(), 1);
        let mut through = UnixStream::from(fds.into_iter().next().unwrap());
        (&kept).write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        io::Read::read_exact(&mut through, &mut byte).unwrap();
        assert_eq!(&byte, b"x");
        let (_, h, _) = s.bus.message();
        assert_eq!((h.member.as_deref(), h.serial), (Some("Read"), 3));
        assert_eq!(s.portal().as_deref(), Some(":1.7"));

        // The program: its Hello answered, and the next thing it gets is the
        // answer to its own call — ours was swallowed.
        s.bus.send(&reply_to(2, ":1.7"), &[]);
        let (_, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(1));
        let (_, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(2));
        assert!(s.program.quiet(HELD));
        assert!(!s.ctx.told_register.load(Ordering::SeqCst));
    }

    /// Refused by the portal (no entry for the id, an older portal): said
    /// once, swallowed, and the connection goes on as it did before — no id
    /// of the zone's, nothing of the program's lost.
    #[test]
    fn a_refused_registration_leaves_the_connection_as_it_was() {
        let mut s = Served::start("refused", Some("cellward.zone.nl"), |c| c);
        let mut first = AUTH.to_vec();
        first.extend(hello(1));
        first.extend(method(2, PORTAL, SETTINGS, "Read", 0));
        s.program.send(&first, &[]);
        s.authenticated();
        let _ = s.bus.message();
        s.bus.send(&reply_to(1, "org.freedesktop.DBus"), &[]);
        let (msg, h, _) = s.bus.message();
        assert_register(&msg, &h, REGISTER_SERIAL);
        s.bus.send(
            &error_to(
                REGISTER_SERIAL,
                "org.freedesktop.portal.Error.Failed",
                "Could not register app ID: App info not found for 'cellward.zone.nl'",
            ),
            &[],
        );
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, 2);
        assert_eq!(s.portal(), None);
        assert!(s.ctx.told_register.load(Ordering::SeqCst));
        s.bus.send(&reply_to(2, ":1.7"), &[]);
        let (_, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(1));
        let (_, h, _) = s.program.message();
        assert_eq!((h.kind, h.reply_serial), (wire::METHOD_RETURN, Some(2)));
    }

    /// A portal that never answers: the calls are held until the bus says
    /// so itself (`NoReply`), then go on without an id — the bus's error is
    /// the filter's, never the program's.
    #[test]
    fn a_portal_that_never_answers_is_the_buss_to_say() {
        let mut s = Served::start("late", Some("cellward.zone.nl"), |c| c);
        let mut first = AUTH.to_vec();
        first.extend(hello(1));
        first.extend(method(2, PORTAL, SETTINGS, "Read", 0));
        s.program.send(&first, &[]);
        s.authenticated();
        let _ = s.bus.message();
        s.bus.send(&reply_to(1, "org.freedesktop.DBus"), &[]);
        let (msg, h, _) = s.bus.message();
        assert_register(&msg, &h, REGISTER_SERIAL);
        // Nothing from the portal: the program's call waits — no clock.
        assert!(s.bus.quiet(HELD));
        // The bus says it will not come: the call goes on, without an id.
        s.bus.send(
            &error_to(
                REGISTER_SERIAL,
                "org.freedesktop.DBus.Error.NoReply",
                "no reply",
            ),
            &[],
        );
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, 2);
        assert!(s.ctx.told_register.load(Ordering::SeqCst));
        s.bus.send(&reply_to(2, ":1.7"), &[]);
        let (_, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(1));
        let (_, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(2));
        assert!(s.program.quiet(HELD));
        assert_eq!(s.portal(), None);
    }

    /// The program cannot name itself or answer for us: its own `Register`,
    /// pipelined right behind its Hello, waits behind ours and is refused;
    /// a Hello under our serial moves ours aside.
    /// Only what the portal may see waits for it: a call to another name
    /// goes up at once — a portal that is stuck (or stopped by a program of
    /// any zone) holds nothing else of the program's.
    #[test]
    fn only_a_call_the_portal_may_see_waits_for_it() {
        let mut s = Served::start("other", Some("cellward.zone.nl"), |c| c);
        let mut first = AUTH.to_vec();
        first.extend(hello(1));
        first.extend(method(
            2,
            "org.freedesktop.Notifications",
            "org.freedesktop.Notifications",
            "GetServerInformation",
            0,
        ));
        first.extend(method(3, PORTAL, SETTINGS, "Read", 0));
        first.extend(method(4, "org.freedesktop.Notifications", "x.y", "Z", 0));
        s.program.send(&first, &[]);
        s.authenticated();
        let (_, h, _) = s.bus.message();
        assert_eq!(h.member.as_deref(), Some("Hello"));
        s.bus.send(&reply_to(1, "org.freedesktop.DBus"), &[]);
        let (msg, h, _) = s.bus.message();
        assert_register(&msg, &h, REGISTER_SERIAL);
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, 2, "a call to another name waited for the portal");
        // The portal's call waits, and what came after it waits behind it.
        assert!(s.bus.quiet(HELD));
        s.bus.send(&reply_to(REGISTER_SERIAL, ":1.7"), &[]);
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, 3);
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, 4);
        assert_eq!(s.portal().as_deref(), Some(":1.7"));
    }

    /// A program's call with our `Register`'s serial, to any name, waits for
    /// the portal's answer: an answer to it cannot pass for the portal's.
    #[test]
    fn a_call_with_our_serial_waits_for_the_portals_answer() {
        let mut s = Served::start("serial", Some("cellward.zone.nl"), |c| c);
        let mut first = AUTH.to_vec();
        first.extend(hello(1));
        first.extend(method(
            REGISTER_SERIAL,
            "org.freedesktop.Notifications",
            "org.freedesktop.Notifications",
            "GetServerInformation",
            0,
        ));
        s.program.send(&first, &[]);
        s.authenticated();
        let (_, h, _) = s.bus.message();
        assert_eq!(h.member.as_deref(), Some("Hello"));
        s.bus.send(&reply_to(1, "org.freedesktop.DBus"), &[]);
        let (msg, h, _) = s.bus.message();
        assert_register(&msg, &h, REGISTER_SERIAL);
        assert!(
            s.bus.quiet(HELD),
            "a call with our serial went up before the answer"
        );
        s.bus.send(&reply_to(REGISTER_SERIAL, ":1.7"), &[]);
        let (_, h, _) = s.bus.message();
        assert_eq!(
            (h.member.as_deref(), h.serial),
            (Some("GetServerInformation"), REGISTER_SERIAL)
        );
        assert_eq!(s.portal().as_deref(), Some(":1.7"));
        // Its own answer now is the program's.
        s.bus.send(&reply_to(REGISTER_SERIAL, ":1.9"), &[]);
        let (_, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(1));
        let (_, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(REGISTER_SERIAL));
    }

    /// A program gone while its call waits for the portal is let go: its
    /// connection — one of the filter's few — does not stay held.
    #[test]
    fn a_program_gone_while_it_waits_is_let_go() {
        let mut s = Served::start("gone", Some("cellward.zone.nl"), |c| c);
        let mut first = AUTH.to_vec();
        first.extend(hello(1));
        first.extend(method(2, PORTAL, SETTINGS, "Read", 0));
        s.program.send(&first, &[]);
        s.authenticated();
        let (_, h, _) = s.bus.message();
        assert_eq!(h.member.as_deref(), Some("Hello"));
        s.bus.send(&reply_to(1, "org.freedesktop.DBus"), &[]);
        let (msg, h, _) = s.bus.message();
        assert_register(&msg, &h, REGISTER_SERIAL);
        assert!(s.bus.quiet(HELD));
        // The program goes; the portal still says nothing.
        let _ = s.program.stream.shutdown(std::net::Shutdown::Both);
        // What it sent still goes up — as a message on the bus can outlive
        // its sender —, and then the filter hangs up its end of the bus: the
        // end of the stream, not the test's patience running out.
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, 2);
        let mut buf = [0u8; 64];
        let got = sys::recv_into_with_fds(s.bus.stream.as_raw_fd(), &mut buf, 1).map(|r| r.0);
        assert_eq!(
            got.ok(),
            Some(0),
            "the connection stayed held after its program went"
        );
    }

    #[test]
    fn the_programs_own_register_is_refused_after_ours() {
        let mut s = Served::start("theirs", Some("cellward.zone.nl"), |c| c);
        let mut first = AUTH.to_vec();
        first.extend(hello(REGISTER_SERIAL));
        // No body needed: refused by its interface.
        first.extend(method(5, PORTAL, REGISTRY, "Register", 0));
        first.extend(method(6, PORTAL, SETTINGS, "Read", 0));
        s.program.send(&first, &[]);
        s.authenticated();
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, REGISTER_SERIAL);
        s.bus
            .send(&reply_to(REGISTER_SERIAL, "org.freedesktop.DBus"), &[]);
        let (msg, h, _) = s.bus.message();
        assert_register(&msg, &h, REGISTER_SERIAL - 1);
        assert!(s.bus.quiet(HELD));
        s.bus.send(&reply_to(REGISTER_SERIAL - 1, ":1.7"), &[]);
        // Only the program's harmless call went up; its Register was
        // answered by the filter.
        let (_, h, _) = s.bus.message();
        assert_eq!((h.member.as_deref(), h.serial), (Some("Read"), 6));
        assert!(s.bus.quiet(HELD));
        let (_, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(REGISTER_SERIAL));
        let (_, h, _) = s.program.message();
        assert_eq!((h.kind, h.reply_serial), (wire::ERROR, Some(5)));
        assert_eq!(
            h.error_name.as_deref(),
            Some("org.freedesktop.DBus.Error.AccessDenied")
        );
        assert_eq!(s.portal().as_deref(), Some(":1.7"));
    }

    /// Without `--portal-app` nothing is held and nothing added: the calls
    /// go up behind the Hello at once, as they always did.
    #[test]
    fn without_an_id_nothing_is_held() {
        let mut s = Served::start("none", None, |c| c);
        let mut first = AUTH.to_vec();
        first.extend(hello(1));
        first.extend(method(2, PORTAL, SETTINGS, "Read", 0));
        s.program.send(&first, &[]);
        s.authenticated();
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, 1);
        let (_, h, _) = s.bus.message();
        assert_eq!(h.serial, 2);
        assert!(s.bus.quiet(HELD));
        assert_eq!(s.portal(), None);
    }

    /// The serial of ours passes xdg-dbus-proxy, which closes a connection
    /// whose client uses one of its own, and is never the Hello's.
    #[test]
    fn the_reserved_serial_is_one_the_proxy_takes() {
        assert_eq!(MAX_CLIENT_SERIAL, 0xFFFE_FFFF);
        for hello in [
            1,
            2,
            REGISTER_SERIAL - 1,
            REGISTER_SERIAL,
            MAX_CLIENT_SERIAL,
        ] {
            let ours = register_serial(hello);
            assert_ne!(ours, hello);
            assert_ne!(ours, 0);
            assert!(ours <= MAX_CLIENT_SERIAL, "{ours:#x}");
        }
    }

    #[test]
    fn an_app_id_is_checked_and_passed() {
        for good in [
            "cellward.zone.nl",
            "cellward.zone._1x_0a1b2c3d",
            "org.example.App-1",
        ] {
            assert!(is_app_id(good), "{good}");
        }
        for bad in [
            "",
            "nl",
            "cellward..nl",
            "cellward.zone.1x",
            "cellward.zone.a b",
            "cellward.zone.зона",
            &format!("cellward.zone.{}", "a".repeat(250)),
        ] {
            assert!(!is_app_id(bad), "{bad}");
        }
        let args = |extra: &[&str]| {
            let mut argv: Vec<OsString> = ["--listen", "/l", "--upstream", "/u", "--opener", "/o"]
                .iter()
                .map(OsString::from)
                .collect();
            argv.extend(extra.iter().map(OsString::from));
            Args::parse(&argv)
        };
        assert_eq!(args(&[]).unwrap().portal_app, None);
        assert_eq!(
            args(&["--portal-app", "cellward.zone.nl"])
                .unwrap()
                .portal_app
                .as_deref(),
            Some("cellward.zone.nl")
        );
        assert!(args(&["--portal-app", "not an id"]).is_err());
        assert!(args(&["--portal-app"]).is_err());
        // The zone of the screen cast switch: all three, or none.
        let zone = args(&["--zone", "nl", "--zone-dir", "/s/nl", "--config", "/c"]).unwrap();
        assert_eq!(
            zone.zone,
            Some(ZoneArgs {
                name: "nl".to_owned(),
                dir: PathBuf::from("/s/nl"),
                config: PathBuf::from("/c"),
                profiles: None,
            })
        );
        assert!(args(&["--zone", "nl"]).is_err());
        assert!(args(&["--zone-dir", "/s/nl", "--config", "/c"]).is_err());
        assert!(args(&["--zone", "", "--zone-dir", "/s/nl", "--config", "/c"]).is_err());
    }

    // --- THE SCREEN CAST SWITCH ----------------------------------------------

    const SCREENCAST: &str = crate::screencast::INTERFACE;

    /// A zone's state and config directories, and its switch held on them.
    struct ZoneDirs {
        base: PathBuf,
    }

    impl ZoneDirs {
        fn new(tag: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "vpn-zone-bus-filter-cast-{tag}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(base.join("state/nl")).unwrap();
            fs::create_dir_all(base.join("config/declared")).unwrap();
            Self { base }
        }

        fn policy(&self) -> crate::screencast::Policy {
            crate::screencast::Policy::hold(
                "nl",
                &self.base.join("state/nl"),
                &self.base.join("config"),
                None,
            )
        }

        fn write(&self, path: &str, text: &str) {
            fs::write(self.base.join(path), text).unwrap();
        }

        fn journal(&self) -> String {
            fs::read_to_string(self.base.join("state").join(crate::journal::FILE))
                .unwrap_or_default()
        }
    }

    impl Drop for ZoneDirs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    /// `SelectSources(o, a{sv})` the way a program asking to be remembered
    /// sends it: a token, a remembered choice, a restore token, the types.
    fn select_sources(serial: u32, dest: &str) -> Vec<u8> {
        fn pad(b: &mut Vec<u8>, n: usize) {
            b.resize(b.len().next_multiple_of(n), 0);
        }
        fn string(b: &mut Vec<u8>, s: &str) {
            pad(b, 4);
            b.extend((s.len() as u32).to_le_bytes());
            b.extend(s.as_bytes());
            b.push(0);
        }
        fn entry(b: &mut Vec<u8>, key: &str, sig: &str) {
            pad(b, 8);
            string(b, key);
            b.push(sig.len() as u8);
            b.extend(sig.as_bytes());
            b.push(0);
        }
        let mut b = Vec::new();
        string(&mut b, "/org/freedesktop/portal/desktop/session/1_42/s");
        pad(&mut b, 4);
        let len_at = b.len();
        b.extend([0; 4]);
        pad(&mut b, 8);
        let start = b.len();
        entry(&mut b, "handle_token", "s");
        string(&mut b, "t1");
        entry(&mut b, "persist_mode", "u");
        pad(&mut b, 4);
        b.extend(2u32.to_le_bytes());
        entry(&mut b, "restore_token", "s");
        string(&mut b, "remembered");
        entry(&mut b, "types", "u");
        pad(&mut b, 4);
        b.extend(1u32.to_le_bytes());
        let len = (b.len() - start) as u32;
        b[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
        wire::message(
            wire::METHOD_CALL,
            0,
            serial,
            &[
                Field::Path(PORTAL_PATH),
                Field::Interface(SCREENCAST),
                Field::Member("SelectSources"),
                Field::Destination(dest),
                Field::Signature("oa{sv}"),
            ],
            &b,
        )
    }

    /// Whether a message the bus got asks for the choice to be remembered.
    fn remembers(msg: &[u8]) -> (bool, bool) {
        let has = |word: &[u8]| msg.windows(word.len()).any(|w| w == word);
        (has(b"persist_mode"), has(b"restore_token"))
    }

    impl Served {
        /// The program's connection up and — with an id — registered, the
        /// portal `:1.7` answering; the program has its Hello's answer.
        fn registered(&mut self) {
            let mut first = AUTH.to_vec();
            first.extend(hello(1));
            self.program.send(&first, &[]);
            self.authenticated();
            let _ = self.bus.message();
            self.bus.send(&reply_to(1, "org.freedesktop.DBus"), &[]);
            if self.ctx.portal_app.is_some() {
                let (msg, h, _) = self.bus.message();
                assert_register(&msg, &h, REGISTER_SERIAL);
                self.bus.send(&reply_to(REGISTER_SERIAL, ":1.7"), &[]);
            }
            let (_, h, _) = self.program.message();
            assert_eq!(h.reply_serial, Some(1));
        }

        /// A call of the program's, and what the bus got of it.
        fn through(&mut self, msg: &[u8]) -> Vec<u8> {
            self.program.send(msg, &[]);
            self.bus.message().0
        }
    }

    /// The filter's own short connection (`portal_owner`), answered by the
    /// stand-in: the portal's name is owned by `owner`.
    fn answer_owner(stand: &Stand, owner: &str) {
        let mut own = stand.accept();
        assert!(own.line().starts_with(b"\0AUTH EXTERNAL "));
        own.send(b"OK 0123456789abcdef\r\n", &[]);
        assert_eq!(own.line(), b"BEGIN\r\n");
        let (_, h, _) = own.message();
        assert_eq!(h.member.as_deref(), Some("Hello"));
        own.send(&reply_to(h.serial, "org.freedesktop.DBus"), &[]);
        let (msg, h, _) = own.message();
        assert_eq!(h.member.as_deref(), Some("GetNameOwner"));
        assert_eq!(wire::body_string(&msg, &h).unwrap(), PORTAL);
        own.send(
            &wire::message(
                wire::METHOD_RETURN,
                wire::NO_REPLY_EXPECTED,
                9,
                &[Field::ReplySerial(h.serial), Field::Signature("s")],
                &body::string(owner),
            ),
            &[],
        );
    }

    /// The switch as it is at each call: `ask` strips the remembered
    /// choice, `yes` on the zone's own connection keeps it, `no` refuses
    /// every call of the interface with the portal's own error — the
    /// program told why, the journal told, the bus told nothing — and Nix
    /// over the zone's own word, at once.
    #[test]
    fn the_screen_cast_switch_is_read_for_every_call() {
        let d = ZoneDirs::new("switch");
        let policy = d.policy();
        let mut s = Served::start("cast", Some("cellward.zone.nl"), |c| Ctx {
            screencast: Some(policy),
            ..c
        });
        s.registered();
        // ask, the default.
        let got = s.through(&select_sources(10, ":1.7"));
        assert_eq!(remembers(&got), (false, false));
        // yes: remembered, the token passed.
        d.write("state/nl/screencast", "yes");
        let got = s.through(&select_sources(11, ":1.7"));
        assert_eq!(remembers(&got), (true, true));
        // Other calls of the interface pass as they are.
        let got = s.through(&method(12, ":1.7", SCREENCAST, "CreateSession", 0));
        assert_eq!(wire::parse_header(&got).unwrap().serial, 12);
        // no: refused, whatever the call.
        d.write("state/nl/screencast", "no");
        for (serial, member) in [(13, "CreateSession"), (14, "Start")] {
            s.program
                .send(&method(serial, PORTAL, SCREENCAST, member, 0), &[]);
            let (msg, h, _) = s.program.message();
            assert_eq!((h.kind, h.reply_serial), (wire::ERROR, Some(serial)));
            assert_eq!(h.error_name.as_deref(), Some(NOT_ALLOWED));
            let text = wire::body_string(&msg, &h).unwrap();
            assert!(
                text.contains("трансляция экрана выключена для зоны «nl»"),
                "{text}"
            );
        }
        s.program.send(&select_sources(15, ":1.7"), &[]);
        let (_, h, _) = s.program.message();
        assert_eq!((h.kind, h.reply_serial), (wire::ERROR, Some(15)));
        assert!(s.bus.quiet(HELD), "a refused call went up");
        // Once in the journal for the three: at most a line per ten seconds.
        assert_eq!(d.journal().matches("\"event\":\"screencast\"").count(), 1);
        // Nix over the zone's own word, at once.
        d.write("config/declared/screencast", "nl ask\n");
        let got = s.through(&select_sources(16, ":1.7"));
        assert_eq!(remembers(&got), (false, false));
        d.write("config/declared/screencast", "nl no\n");
        s.program.send(&select_sources(17, ":1.7"), &[]);
        let (msg, h, _) = s.program.message();
        assert_eq!(h.reply_serial, Some(17));
        assert!(wire::body_string(&msg, &h)
            .unwrap()
            .ends_with("(задано в Nix)"));
    }

    /// `yes` remembers only for the zone: not on a connection the portal
    /// does not know as it, not for another name, not for a portal started
    /// since the one that took the id — and for the one that did, by its
    /// well-known name.
    #[test]
    fn yes_is_ask_where_the_portal_does_not_know_the_zone() {
        let d = ZoneDirs::new("unknown");
        d.write("state/nl/screencast", "yes");
        // No id at all.
        let policy = d.policy();
        let mut s = Served::start("cast-anon", None, |c| Ctx {
            screencast: Some(policy),
            ..c
        });
        s.registered();
        let got = s.through(&select_sources(10, PORTAL));
        assert_eq!(remembers(&got), (false, false));
        drop(s);

        let policy = d.policy();
        let mut s = Served::start("cast-known", Some("cellward.zone.nl"), |c| Ctx {
            screencast: Some(policy),
            ..c
        });
        s.registered();
        // Another name than the portal that took the id.
        let got = s.through(&select_sources(10, ":1.99"));
        assert_eq!(remembers(&got), (false, false));
        // By the well-known name: the portal that took it still owns it.
        s.program.send(&select_sources(11, PORTAL), &[]);
        answer_owner(&s.stand, ":1.7");
        assert_eq!(remembers(&s.bus.message().0), (true, true));
        // A portal started since: it knows the connection by no name.
        s.program.send(&select_sources(12, PORTAL), &[]);
        answer_owner(&s.stand, ":1.8");
        assert_eq!(remembers(&s.bus.message().0), (false, false));
        assert!(s.ctx.told_unremembered.load(Ordering::SeqCst));
    }

    /// Without a zone to read (a sandbox's own filter, an unconfined one),
    /// every cast asks, as before the switch.
    #[test]
    fn without_a_zone_every_cast_asks() {
        let mut s = Served::start("cast-none", Some("cellward.zone.nl"), |c| c);
        s.registered();
        let got = s.through(&select_sources(10, ":1.7"));
        assert_eq!(remembers(&got), (false, false));
    }

    /// A program of a container casts as the container's switch says: its
    /// `no` stands against the zone's `yes`, the refusal names it, and its
    /// `yes` keeps no choice — the portal knows the connection as the zone.
    #[test]
    fn a_container_casts_as_its_own_switch_says() {
        let d = ZoneDirs::new("container");
        d.write("state/nl/screencast", "yes");
        fs::create_dir_all(d.base.join("config/containers/work")).unwrap();
        d.write("config/containers/work/container.conf", "screencast = no\n");
        let policy = d.policy();
        let work = crate::origin::Who::Container("work".into());
        let mut s = Served::start_as("cast-work", Some("cellward.zone.nl"), work, |c| Ctx {
            screencast: Some(policy),
            ..c
        });
        s.registered();
        s.program.send(&select_sources(10, ":1.7"), &[]);
        let (msg, h, _) = s.program.message();
        assert_eq!((h.kind, h.reply_serial), (wire::ERROR, Some(10)));
        let text = wire::body_string(&msg, &h).unwrap();
        assert!(text.contains("контейнера «work» (зона «nl»)"), "{text}");
        assert!(
            d.journal().contains("\"container\":\"work\""),
            "{}",
            d.journal()
        );
        // Its own yes: the cast goes on, but no choice is kept.
        d.write(
            "config/containers/work/container.conf",
            "screencast = yes\n",
        );
        let got = s.through(&select_sources(11, ":1.7"));
        assert_eq!(remembers(&got), (false, false));
    }
}
