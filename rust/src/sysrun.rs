//! A user's program in a system zone (ROADMAP M10 stage 4, `docs/SYSTEM.md`
//! §7): `vpn-zone-sys <zone> -- <command>`.
//!
//! ```text
//! vpn-zone-sys (the user)                  vpn-zone-sysrun@N (root, one per launch)
//!  connect /run/vpn-zones/sysrun.sock ───►  who: SO_PEERCRED, from the kernel
//!  a pty of its own; the request           may this user use this zone?
//!    + the pty's slave (or 0, 1, 2)        fork ─ the zone's network
//!  relay: terminal ⇄ pty master                   own mount namespace: the zone's
//!                                                 resolv.conf and nsswitch, the
//!                                                 host's resolvers, system bus and
//!                                                 session sockets hidden
//!                                                 drop to the user, NO_NEW_PRIVS
//!                                                 a user namespace of its own
//!                                                 exec the command
//!  ◄── EXIT <code>                         wait, answer
//! ```
//!
//! **Why a service at all.** A system zone's namespace belongs to the host's
//! user namespace; entering it takes `CAP_SYS_ADMIN` there, which no program of
//! a user has. Something privileged has to do the entering — and then get out
//! of the way before the user's command runs.
//!
//! **What root does, and what it does not.** Root reads who is asking from the
//! kernel, checks the zone's list of users, enters the zone and prepares the
//! mounts: the paths are fixed, and the only part that comes from the request is
//! the zone's name, which is checked like any zone name before it becomes a
//! path. Everything else in the request — the command, its directory, its
//! environment — is applied only after the privileges are gone, as the user,
//! and could not do anything the user cannot do anyway. `NO_NEW_PRIVS` makes
//! that stick: `sudo` inside would be root in the zone's namespace, which can
//! add a route around the tunnel.
//!
//! **The terminal stays the user's business.** The client makes the pty and
//! relays it; the service only gets the slave end, which becomes the command's
//! controlling terminal. Ctrl-C, job control and the window size then work the
//! way they do in any terminal, without a signal ever passing through root.
//! Without a terminal (a pipe, a script) the client's own 0, 1 and 2 are passed.
//!
//! **One unit per launch** (`Accept=yes`): the command lives in the cgroup of
//! its own `vpn-zone-sysrun@…` instance — listed by `systemctl`, stopped with
//! it, and nothing it leaves behind outlives it.
//!
//! **Console programs here.** The session's sockets — its bus, the compositor,
//! pipewire — are hidden: a program that could ask the host's session to open a
//! link would have a way out around the zone. Graphical programs get the
//! system zone's network another way: a user zone through it (`VZP1` below,
//! `docs/SYSTEM.md` §7b), where the sealing user zones do (LEAK-MODEL §13) is
//! already there — this service only starts that zone's pasta.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use crate::system::{self, check_name};
use crate::{sys, zone};

/// The socket; the NixOS module makes it `0660 root:vpn-zones`.
pub const SOCKET: &str = "/run/vpn-zones/sysrun.sock";
/// Per zone: `users` (one name per line) and, if present, `system-bus`.
pub const ZONES_DIR: &str = "/etc/vpn-zones/system-zones.d";

const MAGIC: &[u8] = b"VZS1\0";
/// A request is one datagram of a SOCK_SEQPACKET socket, so it has a size.
pub const MAX_REQUEST: usize = 64 * 1024;
const MAX_ITEMS: usize = 4096;
/// Variables that point at the session, which a program here has no access to
/// — or at vpn-zones' own idea of where the program runs.
const DROPPED_ENV: [&[u8]; 6] = [
    b"DBUS_SESSION_BUS_ADDRESS",
    b"WAYLAND_DISPLAY",
    b"DISPLAY",
    b"XDG_RUNTIME_DIR",
    b"SSH_AUTH_SOCK",
    b"VPN_ZONE_CURRENT",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The client's pty: one descriptor, the slave.
    Pty,
    /// No terminal: the client's 0, 1 and 2.
    Pipes,
}

impl Mode {
    fn word(self) -> &'static str {
        match self {
            Self::Pty => "pty",
            Self::Pipes => "pipes",
        }
    }

    fn parse(word: &[u8]) -> Option<Self> {
        match word {
            b"pty" => Some(Self::Pty),
            b"pipes" => Some(Self::Pipes),
            _ => None,
        }
    }

    /// How many descriptors come with the request.
    pub fn fds(self) -> usize {
        match self {
            Self::Pty => 1,
            Self::Pipes => 3,
        }
    }
}

/// What the client asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub zone: String,
    pub mode: Mode,
    pub cwd: OsString,
    pub argv: Vec<OsString>,
    /// `KEY=value`, as the client has them.
    pub env: Vec<OsString>,
}

impl Request {
    /// `VZS1\0`, then zone, mode, cwd, argc, argv…, envc, env…, each ended by a
    /// NUL.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        let mut field = |bytes: &[u8]| {
            out.extend_from_slice(bytes);
            out.push(0);
        };
        field(self.zone.as_bytes());
        field(self.mode.word().as_bytes());
        field(self.cwd.as_bytes());
        field(self.argv.len().to_string().as_bytes());
        for arg in &self.argv {
            field(arg.as_bytes());
        }
        field(self.env.len().to_string().as_bytes());
        for item in &self.env {
            field(item.as_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let body = bytes
            .strip_prefix(MAGIC)
            .ok_or("not a request of vpn-zone-sys")?
            .strip_suffix(&[0])
            .ok_or("the request is cut short")?;
        let mut fields = body.split(|&b| b == 0);
        let mut next = || fields.next().ok_or("the request is cut short");

        let zone = std::str::from_utf8(next()?)
            .map_err(|_| "the zone's name is not UTF-8")?
            .to_owned();
        let mode = Mode::parse(next()?).ok_or("unknown mode")?;
        let cwd = OsString::from_vec(next()?.to_vec());
        let argv = list(&mut next)?;
        if argv.first().is_none_or(|a| a.is_empty()) {
            return Err("no command".to_owned());
        }
        let env = list(&mut next)?;
        if fields.next().is_some() {
            return Err("something follows the request".to_owned());
        }
        Ok(Self {
            zone,
            mode,
            cwd,
            argv,
            env,
        })
    }
}

/// A count, then that many fields.
fn list<'a>(
    next: &mut impl FnMut() -> Result<&'a [u8], &'static str>,
) -> Result<Vec<OsString>, String> {
    let count: usize = std::str::from_utf8(next()?)
        .ok()
        .and_then(|n| n.parse().ok())
        .filter(|&n| n <= MAX_ITEMS)
        .ok_or("a bad count in the request")?;
    (0..count)
        .map(|_| Ok(OsString::from_vec(next()?.to_vec())))
        .collect()
}

/// The service's answer.
pub fn answer_exit(code: u8) -> Vec<u8> {
    format!("EXIT {code}").into_bytes()
}

pub fn answer_refusal(why: &str) -> Vec<u8> {
    format!("ERR {why}").into_bytes()
}

pub fn parse_answer(bytes: &[u8]) -> Result<u8, String> {
    let text = String::from_utf8_lossy(bytes);
    if let Some(code) = text.strip_prefix("EXIT ") {
        return code
            .trim()
            .parse()
            .map_err(|_| format!("a strange answer: {text}"));
    }
    match text.strip_prefix("ERR ") {
        Some(why) => Err(why.to_owned()),
        None => Err(format!("a strange answer: {text}")),
    }
}

/// Adding a zone: `VZA1\0`, the zone, `tunnel` or `plain`, a NUL, then the
/// config's bytes (none for a plain zone).
const ADD_MAGIC: &[u8] = b"VZA1\0";
/// Bringing a zone up: `VZU1\0`, the zone, a NUL.
const UP_MAGIC: &[u8] = b"VZU1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddRequest {
    pub zone: String,
    pub plain: bool,
    pub config: Vec<u8>,
}

impl AddRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = ADD_MAGIC.to_vec();
        out.extend_from_slice(self.zone.as_bytes());
        out.push(0);
        out.extend_from_slice(if self.plain { b"plain" } else { b"tunnel" });
        out.push(0);
        out.extend_from_slice(&self.config);
        out
    }

    pub fn decode(body: &[u8]) -> Result<Self, String> {
        let mut parts = body.splitn(3, |&b| b == 0);
        let zone = std::str::from_utf8(parts.next().unwrap_or_default())
            .map_err(|_| "the zone's name is not UTF-8")?
            .to_owned();
        let plain = match parts.next() {
            Some(b"plain") => true,
            Some(b"tunnel") => false,
            _ => return Err("unknown kind of zone".to_owned()),
        };
        let config = parts.next().ok_or("the request is cut short")?.to_vec();
        check_name(&zone)?;
        Ok(Self {
            zone,
            plain,
            config,
        })
    }
}

pub fn encode_up(zone: &str) -> Vec<u8> {
    let mut out = UP_MAGIC.to_vec();
    out.extend_from_slice(zone.as_bytes());
    out.push(0);
    out
}

pub fn decode_up(body: &[u8]) -> Result<String, String> {
    let zone = body.strip_suffix(&[0]).ok_or("the request is cut short")?;
    let zone = std::str::from_utf8(zone)
        .map_err(|_| "the zone's name is not UTF-8")?
        .to_owned();
    check_name(&zone)?;
    Ok(zone)
}

/// What adding or bringing up a zone came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    /// Done, in words.
    Ok(String),
    /// This VPN is already that zone: one config, one tunnel — use it.
    Same(String),
}

pub fn answer_done(done: &Done) -> Vec<u8> {
    match done {
        Done::Ok(what) => format!("OK {what}").into_bytes(),
        Done::Same(zone) => format!("SAME {zone}").into_bytes(),
    }
}

pub fn parse_done(bytes: &[u8]) -> Result<Done, String> {
    let text = String::from_utf8_lossy(bytes);
    if let Some(what) = text.strip_prefix("OK ") {
        return Ok(Done::Ok(what.to_owned()));
    }
    if let Some(zone) = text.strip_prefix("SAME ") {
        return Ok(Done::Same(zone.trim().to_owned()));
    }
    match text.strip_prefix("ERR ") {
        Some(why) => Err(why.to_owned()),
        None => Err(format!("a strange answer: {text}")),
    }
}

/// Who may run programs in a zone: the module's list for a declared zone, the
/// one who added it for a zone made on the spot.
pub fn allowed_users(zone: &str) -> Vec<String> {
    system::settings(zone).map(|s| s.users).unwrap_or_default()
}

pub fn parse_users(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|name| {
            name.bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.".contains(&b))
        })
        .map(str::to_owned)
        .collect()
}

/// Does the zone leave the host's system bus reachable?
fn system_bus_allowed(zone: &str) -> bool {
    system::settings(zone).is_some_and(|s| s.system_bus)
}

/// The user the command runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
    pub groups: Vec<u32>,
}

/// The command's environment: the client's, minus what points at the session,
/// with the account's own `HOME`, `USER`, `LOGNAME` and `SHELL`.
pub fn child_env(
    requested: &[OsString],
    user: &User,
    zone: &str,
    runtime: Option<&Path>,
) -> Vec<(OsString, OsString)> {
    let mut forced: Vec<(OsString, OsString)> = vec![
        ("HOME".into(), user.home.clone().into_os_string()),
        ("USER".into(), user.name.clone().into()),
        ("LOGNAME".into(), user.name.clone().into()),
        ("SHELL".into(), user.shell.clone().into_os_string()),
        ("VPN_ZONE_CURRENT".into(), format!("sys:{zone}").into()),
    ];
    if let Some(dir) = runtime {
        forced.push(("XDG_RUNTIME_DIR".into(), dir.as_os_str().to_owned()));
    }
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    for item in requested {
        let bytes = item.as_bytes();
        let Some(eq) = bytes.iter().position(|&b| b == b'=') else {
            continue;
        };
        let (key, value) = (&bytes[..eq], &bytes[eq + 1..]);
        let taken = DROPPED_ENV.contains(&key)
            || forced.iter().any(|(k, _)| k.as_bytes() == key)
            || out.iter().any(|(k, _)| k.as_bytes() == key);
        if key.is_empty() || taken {
            continue;
        }
        out.push((
            OsString::from_vec(key.to_vec()),
            OsString::from_vec(value.to_vec()),
        ));
    }
    out.extend(forced);
    out
}

/// `vpn-zone-sys <zone> [--] <command> [args…]`.
pub fn parse_client_args(args: &[OsString]) -> Result<(String, Vec<OsString>), String> {
    let mut rest = args.iter();
    let zone = rest
        .next()
        .ok_or("need a zone")?
        .to_str()
        .ok_or("the zone's name is not UTF-8")?
        .to_owned();
    check_name(&zone)?;
    let mut cmd: Vec<OsString> = rest.cloned().collect();
    if cmd.first().is_some_and(|first| first == "--") {
        cmd.remove(0);
    }
    if cmd.is_empty() {
        return Err("need a command".to_owned());
    }
    Ok((zone, cmd))
}

// --- THE CLIENT --------------------------------------------------------------

const USAGE: &str = "usage: vpn-zone-sys <zone> [--] <command> [args…]
       vpn-zone-sys --add <zone> <config.conf | ->
       vpn-zone-sys --add <zone> --plain
       vpn-zone-sys --up <zone>";

/// The client. Returns the command's exit code.
pub fn client(args: &[OsString]) -> u8 {
    match args.first().and_then(|a| a.to_str()) {
        Some("--add") => return manage(add_request(&args[1..])),
        Some("--up") => return manage(up_request(&args[1..])),
        _ => {}
    }
    let (zone, cmd) = match parse_client_args(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("vpn-zone-sys: {e}\n{USAGE}");
            return 2;
        }
    };
    match run_client(&zone, cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("vpn-zone-sys: {e}");
            1
        }
    }
}

/// `--add <zone> <file | - | --plain>`.
fn add_request(args: &[OsString]) -> Result<Vec<u8>, String> {
    let zone = args
        .first()
        .and_then(|a| a.to_str())
        .ok_or("need a zone")?
        .to_owned();
    check_name(&zone)?;
    let source = args.get(1).ok_or("need a config file, `-` or --plain")?;
    if args.len() > 2 {
        return Err("too many arguments".to_owned());
    }
    let (plain, config) = if source == "--plain" {
        (true, Vec::new())
    } else if source == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read the config: {e}"))?;
        (false, bytes)
    } else {
        let bytes = fs::read(source)
            .map_err(|e| format!("cannot read {}: {e}", source.to_string_lossy()))?;
        (false, bytes)
    };
    let request = AddRequest {
        zone,
        plain,
        config,
    }
    .encode();
    if request.len() > MAX_REQUEST {
        return Err("the config is too large".to_owned());
    }
    Ok(request)
}

fn up_request(args: &[OsString]) -> Result<Vec<u8>, String> {
    match args {
        [zone] => {
            let zone = zone.to_str().ok_or("the zone's name is not UTF-8")?;
            check_name(zone)?;
            Ok(encode_up(zone))
        }
        _ => Err("need exactly one zone".to_owned()),
    }
}

/// Send an add or up request and say what came of it.
fn manage(request: Result<Vec<u8>, String>) -> u8 {
    let request = match request {
        Ok(r) => r,
        Err(e) => {
            eprintln!("vpn-zone-sys: {e}\n{USAGE}");
            return 2;
        }
    };
    match exchange(&request) {
        Ok(Done::Ok(what)) => {
            println!("{what}");
            0
        }
        Ok(Done::Same(zone)) => {
            println!(
                "Этот VPN уже есть: системная зона {zone}. Второе подключение не нужно — \
                 программы запускаются в ней: vpn-zone-sys {zone} -- <команда>"
            );
            0
        }
        Err(e) => {
            eprintln!("vpn-zone-sys: {e}");
            1
        }
    }
}

/// Bring a system zone up through the service, as its user: what the TTY
/// console does when the zone is down.
pub fn request_up(zone: &str) -> Result<Done, String> {
    exchange(&encode_up(zone))
}

fn exchange(request: &[u8]) -> Result<Done, String> {
    let sock = connect(SOCKET).map_err(|e| {
        format!(
            "cannot reach {SOCKET}: {e} — is the system tier on, and are you in the group \
             vpn-zones?"
        )
    })?;
    sys::send_with_fds(sock.as_raw_fd(), request, &[])
        .map_err(|e| format!("cannot send the request: {e}"))?;
    let mut buf = [0u8; 4096];
    // SAFETY: a valid descriptor and a buffer of the length given.
    let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n <= 0 {
        return Err("the system-zone service went away without an answer".to_owned());
    }
    parse_done(&buf[..n.unsigned_abs()])
}

fn run_client(zone: &str, argv: Vec<OsString>) -> Result<u8, String> {
    let sock = connect(SOCKET).map_err(|e| {
        format!(
            "cannot reach {SOCKET}: {e} — is the system tier on, and are you in the group \
             vpn-zones?"
        )
    })?;
    let cwd = std::env::current_dir()
        .map(PathBuf::into_os_string)
        .unwrap_or_else(|_| OsString::from("/"));
    let env = std::env::vars_os()
        .map(|(key, value)| {
            let mut item = key;
            item.push("=");
            item.push(value);
            item
        })
        .collect();
    // SAFETY: isatty takes a descriptor number and nothing else.
    let tty = unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 };
    let mode = if tty { Mode::Pty } else { Mode::Pipes };
    let request = Request {
        zone: zone.to_owned(),
        mode,
        cwd,
        argv,
        env,
    }
    .encode();
    if request.len() > MAX_REQUEST {
        return Err("the command and its environment are too large".to_owned());
    }
    match mode {
        Mode::Pipes => {
            sys::send_with_fds(sock.as_raw_fd(), &request, &[0, 1, 2])
                .map_err(|e| format!("cannot send the request: {e}"))?;
            wait_answer(sock.as_raw_fd())
        }
        Mode::Pty => pty_session(&sock, &request),
    }
}

/// Relay the terminal to a pty whose slave the command gets.
fn pty_session(sock: &OwnedFd, request: &[u8]) -> Result<u8, String> {
    let (master, slave) = openpty().map_err(|e| format!("cannot make a terminal: {e}"))?;
    let size = window_size(0);
    if let Some(size) = size {
        set_window_size(master.as_raw_fd(), size);
    }
    sys::send_with_fds(sock.as_raw_fd(), request, &[slave.as_raw_fd()])
        .map_err(|e| format!("cannot send the request: {e}"))?;
    drop(slave);

    let raw = RawMode::enable(0);
    let to_master = master
        .try_clone()
        .map_err(|e| format!("cannot relay: {e}"))?;
    let from_master = master
        .try_clone()
        .map_err(|e| format!("cannot relay: {e}"))?;
    thread::spawn(move || {
        let _ = copy(&mut io::stdin().lock(), &mut File::from(to_master));
    });
    let (done_w, done_r) = mpsc::channel();
    thread::spawn(move || {
        let _ = copy(&mut File::from(from_master), &mut io::stdout());
        let _ = done_w.send(());
    });
    let stop = Arc::new(AtomicBool::new(false));
    let watching = Arc::clone(&stop);
    let master_fd = master.as_raw_fd();
    thread::spawn(move || {
        let mut last = size;
        while !watching.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(200));
            let now = window_size(0);
            if now != last {
                if let Some(now) = now {
                    set_window_size(master_fd, now);
                }
                last = now;
            }
        }
    });

    let answer = wait_answer(sock.as_raw_fd());
    // The command's last output is still on its way through the pty: the master
    // reads until every slave is closed, which is when the unit is gone —
    // systemd ends whatever the command left behind with it. Waited for as
    // long as that takes, no clock of ours: on a loaded machine a guess would
    // cut the tail of the output off.
    let _ = done_r.recv();
    stop.store(true, Ordering::Relaxed);
    drop(raw);
    drop(master);
    answer
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n])?;
        to.flush()?;
    }
}

fn wait_answer(sock: RawFd) -> Result<u8, String> {
    let mut buf = [0u8; 4096];
    // SAFETY: a valid descriptor and a buffer of the length given.
    let n = unsafe { libc::recv(sock, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n <= 0 {
        return Err("the system-zone service went away without an answer".to_owned());
    }
    parse_answer(&buf[..n.unsigned_abs()])
}

/// The client's terminal in raw mode while the relay runs; restored on drop.
struct RawMode {
    fd: RawFd,
    saved: libc::termios,
}

impl RawMode {
    fn enable(fd: RawFd) -> Option<Self> {
        // SAFETY: termios is plain data; tcgetattr fills it or fails.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: a descriptor and a termios to fill.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return None;
        }
        let mut raw = saved;
        // SAFETY: cfmakeraw only edits the struct it is given.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: a descriptor and a filled termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: the same descriptor and the termios read from it.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
    }
}

fn window_size(fd: RawFd) -> Option<(u16, u16)> {
    // SAFETY: winsize is plain data; the ioctl fills it or fails.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one winsize.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) };
    (rc == 0).then_some((size.ws_row, size.ws_col))
}

fn set_window_size(fd: RawFd, (rows, cols): (u16, u16)) {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads one winsize.
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &size) };
}

fn openpty() -> io::Result<(OwnedFd, OwnedFd)> {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: two out-parameters; no name, no termios, no window size.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty succeeded, so both are fresh descriptors of ours.
    Ok(unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) })
}

// --- THE SERVICE -------------------------------------------------------------

/// The service: one connection on descriptor 0 (`Accept=yes`), one launch.
pub fn broker() -> u8 {
    let sock: RawFd = 0;
    let answer = match serve_any(sock) {
        Ok(answer) => answer,
        Err(e) => {
            eprintln!("sysrun: refused: {e}");
            answer_refusal(&e)
        }
    };
    // SAFETY: a valid descriptor and a buffer of the length given.
    unsafe {
        libc::send(
            sock,
            answer.as_ptr().cast(),
            answer.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    0
}

/// Everything the child needs, prepared by the parent: after `fork` the child
/// only does syscalls and one `exec`.
struct Launch {
    request: Request,
    fds: Vec<OwnedFd>,
    netns: File,
    user: User,
    runtime: Option<PathBuf>,
    env: Vec<(OsString, OsString)>,
    system_bus: bool,
}

/// Who asks, from the kernel; then what they ask for.
fn serve_any(sock: RawFd) -> Result<Vec<u8>, String> {
    let uid = peer_uid(sock)?;
    // A client that connects and says nothing must not hold the unit — and
    // one of the few connections the socket allows — for ever (review).
    set_recv_timeout(sock, REQUEST_WAIT);
    let (data, fds) = sys::recv_with_fds(sock, MAX_REQUEST, 3)
        .map_err(|e| format!("cannot read the request: {e}"))?;
    // The request is in: from here the connection is the command's life, and
    // a wait on it must not end after five seconds (review: every command was
    // hung up then — the watcher took the timeout for the client leaving).
    set_recv_timeout(sock, Duration::ZERO);
    if system::is_off() {
        // The zones are down and stay down (their units check the same
        // flag): say so, rather than "the zone did not come up".
        return Err("cellward is off; `vpn-zones-on` turns it on".to_owned());
    }
    if let Some(body) = data.strip_prefix(ADD_MAGIC) {
        return serve_add(uid, &AddRequest::decode(body)?).map(|d| answer_done(&d));
    }
    if let Some(body) = data.strip_prefix(UP_MAGIC) {
        return serve_up(uid, &decode_up(body)?).map(|d| answer_done(&d));
    }
    if let Some(body) = data.strip_prefix(UPLINK_MAGIC) {
        let (zone, pid) = decode_uplink(body)?;
        return serve_uplink(sock, uid, &zone, pid, fds);
    }
    if let Some(body) = data.strip_prefix(KEY_MAGIC) {
        let key = std::str::from_utf8(body).map_err(|_| "the key is not UTF-8")?;
        return serve_key(uid, key.trim()).map(|d| answer_done(&d));
    }
    serve(sock, uid, &data, fds).map(answer_exit)
}

// --- A USER ZONE'S WAY OUT THROUGH A SYSTEM ZONE (docs/SYSTEM.md §7b) ---
//
// The user zone's own process asks, with its user and network namespaces as
// descriptors; the service starts pasta in the SYSTEM zone's network, as the
// user, attached to those namespaces. The connection is the uplink's life:
// the zone letting go of it takes pasta down, and pasta ending is said on it.

/// `VZP1\0`, the system zone, a NUL, the pid of the zone's app namespace, a
/// NUL; two descriptors: that process's user and network namespaces. Answered
/// `OK <resolvers>` once pasta runs, and `EXIT <code>` when it has ended.
const UPLINK_MAGIC: &[u8] = b"VZP1\0";
/// `VZK1\0` and a private key: which system zone holds it.
const KEY_MAGIC: &[u8] = b"VZK1\0";
/// How the module names pasta for the service.
pub const ENV_PASTA: &str = "VPN_ZONE_PASTA";
/// The group user zones' pasta runs with in a system zone (`BRIDGE_GROUP`
/// rule in `system::ns_up`).
pub const BRIDGE_GROUP: &str = "vpn-zones-bridge";
/// How long a client has to say what it wants.
const REQUEST_WAIT: Duration = Duration::from_secs(5);
/// ioctl_ns(2): `_IO(0xb7, 0x1)` and `_IO(0xb7, 0x4)`.
const NS_GET_USERNS: libc::c_ulong = 0xb701;
const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
const NS_GET_OWNER_UID: libc::c_ulong = 0xb704;
/// pasta failing at once — no such namespace, no way in — is said as a
/// refusal rather than as an uplink that ends a moment later.
const UPLINK_SETTLE: Duration = Duration::from_millis(300);

pub fn encode_uplink(zone: &str, pid: i32) -> Vec<u8> {
    let mut out = UPLINK_MAGIC.to_vec();
    out.extend_from_slice(zone.as_bytes());
    out.push(0);
    out.extend_from_slice(pid.to_string().as_bytes());
    out.push(0);
    out
}

pub fn decode_uplink(body: &[u8]) -> Result<(String, i32), String> {
    let mut parts = body.split(|&b| b == 0);
    let zone = std::str::from_utf8(parts.next().unwrap_or_default())
        .map_err(|_| "the zone's name is not UTF-8")?
        .to_owned();
    check_name(&zone)?;
    let pid = parts
        .next()
        .and_then(|p| std::str::from_utf8(p).ok())
        .and_then(|p| p.parse::<i32>().ok())
        .filter(|&p| p > 1)
        .ok_or("a bad pid in the request")?;
    Ok((zone, pid))
}

pub fn encode_key(key: &str) -> Vec<u8> {
    let mut out = KEY_MAGIC.to_vec();
    out.extend_from_slice(key.as_bytes());
    out
}

/// Which system zone this private key already is, if any — asked by
/// `vpn-zone add` before it makes a second tunnel on the same key.
pub fn request_key_owner(key: &str) -> Result<Option<String>, String> {
    match exchange(&encode_key(key))? {
        Done::Same(zone) => Ok(Some(zone)),
        Done::Ok(_) => Ok(None),
    }
}

/// Ask for a user zone's way out through `zone`, for the namespaces of the
/// process `pid` (the zone's app namespace). Returns the connection — keep it
/// open for as long as the zone wants its way out, and read the end from it
/// with [`wait_uplink`] — and the system zone's resolvers.
pub fn request_uplink(zone: &str, pid: i32) -> Result<(OwnedFd, Vec<String>), String> {
    let userns = File::open(format!("/proc/{pid}/ns/user"))
        .map_err(|e| format!("cannot open the zone's user namespace: {e}"))?;
    let netns = File::open(format!("/proc/{pid}/ns/net"))
        .map_err(|e| format!("cannot open the zone's network namespace: {e}"))?;
    let sock = connect(SOCKET).map_err(|e| {
        format!(
            "cannot reach {SOCKET}: {e} — is the system tier on, and are you in the group \
             vpn-zones?"
        )
    })?;
    sys::send_with_fds(
        sock.as_raw_fd(),
        &encode_uplink(zone, pid),
        &[userns.as_raw_fd(), netns.as_raw_fd()],
    )
    .map_err(|e| format!("cannot send the request: {e}"))?;
    let mut buf = [0u8; 4096];
    // SAFETY: a valid descriptor and a buffer of the length given.
    let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n <= 0 {
        return Err("the system-zone service went away without an answer".to_owned());
    }
    match parse_done(&buf[..n.unsigned_abs()])? {
        Done::Ok(resolvers) => Ok((
            sock,
            resolvers.split_whitespace().map(str::to_owned).collect(),
        )),
        Done::Same(_) => Err("a strange answer to an uplink".to_owned()),
    }
}

/// `vpn-zone-core system-uplink <system zone> <pid>`: what a user zone's holder
/// runs as its way out through a system zone. Says `OK <resolvers>` or
/// `ERR <why>` on its first line, then holds the uplink and exits with its
/// end — the holder watches it the way it watches pasta, and stopping it lets
/// go of the uplink.
pub fn uplink_main(args: &[OsString]) -> u8 {
    let (Some(zone), Some(pid)) = (
        args.first().and_then(|a| a.to_str()),
        args.get(1)
            .and_then(|a| a.to_str())
            .and_then(|p| p.parse::<i32>().ok()),
    ) else {
        eprintln!("usage: vpn-zone-core system-uplink <system zone> <pid>");
        return 2;
    };
    let mut out = io::stdout();
    match request_uplink(zone, pid) {
        Ok((sock, resolvers)) => {
            let _ = writeln!(out, "OK {}", resolvers.join(" "));
            let _ = out.flush();
            wait_uplink(&sock)
        }
        Err(e) => {
            let _ = writeln!(out, "ERR {e}");
            let _ = out.flush();
            1
        }
    }
}

/// Block until the uplink ends: pasta's exit code, or 1 when the service is
/// gone without saying.
pub fn wait_uplink(sock: &OwnedFd) -> u8 {
    let mut buf = [0u8; 256];
    // SAFETY: a valid descriptor and a buffer of the length given.
    let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n <= 0 {
        return 1;
    }
    parse_answer(&buf[..n.unsigned_abs()]).unwrap_or(1)
}

/// Whose zone asks for an uplink. Only a zone asks, from inside its own user
/// namespace as that namespace's uid 0 — on the host the first uid of the
/// user's `/etc/subuid` range (`zone::uplink_owner`, the owner the egress
/// policy knows zones' ways out by). An account's own uid is refused: a
/// program the user runs — in a zone, where it cannot become that uid, or
/// anywhere — has no business attaching a system zone's way out to namespaces
/// of its own making (found by review).
fn zone_owner(uid: u32) -> Result<User, String> {
    if user_of(uid).is_ok() {
        return Err(
            "a way out through a system zone is asked for by a zone, not by a program".to_owned(),
        );
    }
    let text = fs::read_to_string("/etc/subuid").unwrap_or_default();
    for line in text.lines() {
        let mut fields = line.trim().split(':');
        let (Some(who), Some(start)) = (fields.next(), fields.next()) else {
            continue;
        };
        if start.parse::<u32>().ok() != Some(uid) {
            continue;
        }
        // An owner that does not resolve is not the answer; a later line may be.
        if let Some(owner) = who
            .parse::<u32>()
            .ok()
            .or_else(|| crate::egress::user_id(who))
        {
            return user_of(owner);
        }
    }
    Err(format!("uid {uid} starts no user's subordinate range"))
}

fn ns_ioctl(fd: RawFd, request: libc::c_ulong, arg: *mut libc::c_void) -> libc::c_int {
    // SAFETY: the requests used here take either nothing or a pointer to a
    // uid_t the caller owns.
    unsafe { libc::ioctl(fd, request as _, arg) }
}

/// The uid owning a user namespace.
fn ns_owner_uid(userns: &OwnedFd) -> Result<u32, String> {
    let mut uid: libc::uid_t = 0;
    if ns_ioctl(userns.as_raw_fd(), NS_GET_OWNER_UID, (&raw mut uid).cast()) != 0 {
        return Err(format!(
            "not a user namespace: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(uid)
}

/// Whether two descriptors are the same namespace.
fn same_ns(a: &OwnedFd, b: &OwnedFd) -> bool {
    matches!((ns_id(a), ns_id(b)), (Some(x), Some(y)) if x == y)
}

fn set_recv_timeout(sock: RawFd, wait: Duration) {
    let tv = libc::timeval {
        tv_sec: libc::time_t::try_from(wait.as_secs()).unwrap_or(5),
        tv_usec: 0,
    };
    // SAFETY: a valid descriptor and a timeval of the size given.
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
}

fn send_on(sock: RawFd, answer: &[u8]) {
    // SAFETY: a valid descriptor and a buffer of the length given.
    unsafe {
        libc::send(
            sock,
            answer.as_ptr().cast(),
            answer.len(),
            libc::MSG_NOSIGNAL,
        )
    };
}

/// `(st_dev, st_ino)` of a descriptor: a namespace's identity.
fn ns_id(fd: &OwnedFd) -> Option<(u64, u64)> {
    // SAFETY: fstat fills the struct it is given.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0).then_some((st.st_dev, st.st_ino))
}

/// pasta in the system zone's network, as the user, attached to the zone's
/// namespaces by `/proc/<pid>/ns/*`.
///
/// Paths, not the descriptors the zone sent: pasta closes every descriptor it
/// inherits before it does anything (found by the VM test). The descriptors
/// are what was checked; so the child, once it is the user — who may open a
/// process of their own zone's, as its owner, where root without
/// `CAP_SYS_PTRACE` may not —, checks that the paths lead to the very same
/// namespaces before pasta starts. And pasta, running as the user, could
/// enter nothing but the user's own namespaces in any case.
fn spawn_uplink_pasta(
    sysnet: &File,
    userns: &OwnedFd,
    netns: &OwnedFd,
    pid: i32,
    user: &User,
) -> Result<std::process::Child, String> {
    use std::os::unix::process::CommandExt;
    let sysnet_fd = sysnet.as_raw_fd();
    let want = [
        ns_id(userns).ok_or("cannot stat the zone's user namespace")?,
        ns_id(netns).ok_or("cannot stat the zone's network namespace")?,
    ];
    let user_path = format!("/proc/{pid}/ns/user");
    let net_path = format!("/proc/{pid}/ns/net");
    let paths = [
        CString::new(user_path.clone()).map_err(|_| "a bad path")?,
        CString::new(net_path.clone()).map_err(|_| "a bad path")?,
    ];
    // The user's uid, and a group of its own rather than the user's: the
    // system zone refuses this group's packets to its own addresses, so a user
    // zone gets through the system zone and not INTO it (review: a service
    // listening in the system zone was reachable from the user zone).
    let (uid, gid) = (
        user.uid,
        // Without that group the system zone's refusal of it never applies:
        // no uplink, rather than one into the system zone (review).
        crate::egress::group_id(BRIDGE_GROUP)
            .ok_or_else(|| format!("the group {BRIDGE_GROUP} is missing — no uplink without it"))?,
    );
    let pasta = std::env::var_os(ENV_PASTA).unwrap_or_else(|| "pasta".into());
    let mut cmd = Command::new(pasta);
    cmd.arg("--userns")
        .arg(&user_path)
        .arg("--netns")
        .arg(&net_path)
        .args(["--config-net", "-q", "-I", zone::TUN_IFACE, "-f", "-4"])
        // pasta would watch the namespace's /proc directory to quit with it,
        // and that directory is the zone's uid 0's, not the user's: EACCES.
        // Its life is this service's to end anyway, on the zone letting go.
        .arg("--no-netns-quit")
        .args([
            "-a",
            zone::HOSTIF_GUEST4,
            "-n",
            zone::HOSTIF_PREFIX4,
            "-g",
            zone::HOSTIF_GATEWAY4,
        ])
        .args(zone::PASTA_CLOSED)
        .stdin(std::process::Stdio::null());
    // SAFETY: only async-signal-safe syscalls between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            // Into the system zone's network while still root…
            if libc::setns(sysnet_fd, libc::CLONE_NEWNET) != 0 {
                return Err(io::Error::last_os_error());
            }
            // …then the user and nothing more: no group of root's, and no way
            // back up — pasta's own sockets are made here, in the system zone.
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // As the user now: the paths are the namespaces that were checked.
            for (path, (dev, ino)) in paths.iter().zip(want) {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::stat(path.as_ptr(), &mut st) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if st.st_dev != dev || st.st_ino != ino {
                    return Err(io::Error::from_raw_os_error(libc::ESTALE));
                }
            }
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| format!("cannot start pasta: {e}"))
}

/// A user zone's way out through the system zone `zone` (§7b).
fn serve_uplink(
    sock: RawFd,
    uid: u32,
    zone: &str,
    pid: i32,
    mut fds: Vec<OwnedFd>,
) -> Result<Vec<u8>, String> {
    let user = zone_owner(uid)?;
    if user.uid == 0 {
        return Err("root's services go into a system zone directly".to_owned());
    }
    if !allowed_users(zone).contains(&user.name) {
        return Err(format!("{} may not use the system zone {zone}", user.name));
    }
    // What the zone is now: a re-attach later has to find it the same kind.
    // The rule that keeps user zones out of this one, for the group their
    // pasta runs as: without it the way through is a way in.
    let bridge = crate::egress::group_id(BRIDGE_GROUP);
    let ruled = fs::read_to_string(system::run_dir(zone).join(system::BRIDGE_RULE))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok());
    if bridge.is_none() || ruled != bridge {
        return Err(format!(
            "the system zone {zone} has no rule keeping user zones out of it — restart \
             vpn-zone-system-ns-{zone}"
        ));
    }
    let plain = system::settings(zone).is_some_and(|s| s.plain);
    if fds.len() != 2 {
        return Err("an uplink comes with the zone's two namespaces".to_owned());
    }
    let netns = fds.pop().expect("two");
    let userns = fds.pop().expect("two");
    // Each descriptor the kind of namespace its slot says (review): a user
    // namespace in the network slot would pass the ownership check below by
    // its parent.
    for (fd, kind, what) in [
        (&userns, libc::CLONE_NEWUSER, "user"),
        (&netns, libc::CLONE_NEWNET, "network"),
    ] {
        if ns_ioctl(fd.as_raw_fd(), NS_GET_NSTYPE, std::ptr::null_mut()) != kind {
            return Err(format!("that is not a {what} namespace"));
        }
    }
    // The zone's namespaces are the user's own: the network one belongs to
    // the user namespace, and that one to the user. The host's network and a
    // system zone's belong to the host's user namespace, owned by root, so
    // neither can be passed off as a zone.
    if ns_owner_uid(&userns)? != user.uid {
        return Err(format!("that namespace is not {}'s", user.name));
    }
    let owning = ns_ioctl(netns.as_raw_fd(), NS_GET_USERNS, std::ptr::null_mut());
    if owning < 0 {
        return Err(format!(
            "not a network namespace: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: NS_GET_USERNS returned a new descriptor that is ours.
    let owning = unsafe { OwnedFd::from_raw_fd(owning) };
    if !same_ns(&owning, &userns) {
        return Err("the network namespace is not the zone's".to_owned());
    }
    drop(owning);

    systemctl(&["start", &format!("vpn-zone-system@{zone}.service")])
        .map_err(|e| format!("{zone} did not come up: {e}"))?;
    let sysnet = File::open(system::netns_path(zone))
        .map_err(|e| format!("cannot open the zone's namespace: {e}"))?;
    let resolvers: Vec<String> = crate::dnsfwd::nameservers(
        &fs::read_to_string(system::resolv_path(zone)).unwrap_or_default(),
    )
    .iter()
    .map(|a| a.ip().to_string())
    .collect();

    let mut pasta = spawn_uplink_pasta(&sysnet, &userns, &netns, pid, &user)?;
    // The namespace pasta was started in: the one to follow if it changes.
    let mut serving = file_ns_id(&sysnet);
    drop(sysnet);
    thread::sleep(UPLINK_SETTLE);
    if let Ok(Some(status)) = pasta.try_wait() {
        return Err(format!("pasta could not attach ({status})"));
    }
    println!(
        "sysrun: a zone of {} goes out through the system zone {zone}",
        user.name
    );
    send_on(sock, &answer_done(&Done::Ok(resolvers.join(" "))));

    // Until the zone lets go. The zone's namespaces stay open here (`userns`,
    // `netns`), so pasta can be started again without asking the zone: the
    // system zone's namespace made anew — its unit restarted, vpn-zones off
    // and on — leaves pasta in the old one, which has no tunnel. Between the
    // old pasta going and the new one coming the zone has no way out at all:
    // closed, never open.
    let mut pasta = Some(pasta);
    loop {
        let now = File::open(system::netns_path(zone))
            .ok()
            .and_then(|f| file_ns_id(&f).map(|id| (f, id)));
        match (pasta.as_mut(), now) {
            // Serving the zone's current namespace: pasta ending here is the
            // end of the way out, as for any zone.
            (Some(child), Some((_, id))) if Some(id) == serving => {
                if let Ok(Some(status)) = child.try_wait() {
                    eprintln!(
                        "sysrun: the way out of {}'s zone through {zone} ended ({status})",
                        user.name
                    );
                    let code = status
                        .code()
                        .and_then(|c| u8::try_from(c).ok())
                        .unwrap_or(1);
                    return Ok(answer_exit(code.max(1)));
                }
            }
            // The system zone's namespace is gone or another one: pasta is
            // left in a dead end.
            (Some(child), _) => {
                let _ = child.kill();
                let _ = child.wait();
                pasta = None;
                serving = None;
                println!(
                    "sysrun: the system zone {zone} was made anew — {}'s zone waits for it",
                    user.name
                );
            }
            // A namespace again, and its way out up: follow it.
            (None, Some((file, id))) if system::is_ready(zone) => {
                // Asked again, as the first time (review): the user may have
                // been taken off the zone's list, or the zone may have become
                // another kind — a way out "through VPN nl" must not come back
                // as a plain one.
                let still = system::settings(zone)
                    .filter(|s| s.users.contains(&user.name) && s.plain == plain);
                if still.is_none() {
                    eprintln!(
                        "sysrun: {}'s way out through {zone} is not given again: the zone \
                         changed",
                        user.name
                    );
                    return Ok(answer_exit(1));
                }
                match spawn_uplink_pasta(&file, &userns, &netns, pid, &user) {
                    Ok(child) => {
                        pasta = Some(child);
                        serving = Some(id);
                        println!(
                            "sysrun: {}'s zone goes out through the system zone {zone} again",
                            user.name
                        );
                    }
                    Err(e) => eprintln!("sysrun: {e} — trying again"),
                }
            }
            (None, _) => {}
        }
        let mut pfd = libc::pollfd {
            fd: sock,
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        if unsafe { libc::poll(&mut pfd, 1, 1000) } > 0 && pfd.revents != 0 {
            if let Some(mut child) = pasta.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Ok(answer_exit(0));
        }
    }
}

/// [`ns_id`] of an opened namespace file.
fn file_ns_id(file: &File) -> Option<(u64, u64)> {
    // SAFETY: fstat fills the struct it is given.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(file.as_raw_fd(), &mut st) } == 0).then_some((st.st_dev, st.st_ino))
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let tool = std::env::var_os("VPN_ZONE_SYSTEMCTL").unwrap_or_else(|| "systemctl".into());
    let status = Command::new(&tool)
        .args(args)
        .status()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl {} failed ({status})", args.join(" ")))
    }
}

fn private_key(cfg: &crate::config::WgConfig) -> Option<String> {
    cfg.interface()?.get("PrivateKey").map(str::to_owned)
}

/// The system zone whose config holds this private key, and its users — other
/// than `except`, the zone being (re)added.
fn key_owner(key: &str, except: Option<&str>) -> Option<(String, Vec<String>)> {
    system::all_zones().into_iter().find_map(|other| {
        let s = system::settings(&other).filter(|s| !s.plain && Some(other.as_str()) != except)?;
        let held = fs::read(&s.config)
            .ok()
            .and_then(|raw| crate::config::WgConfig::parse(&raw).ok())
            .and_then(|o| private_key(&o))?;
        (held == key).then_some((other, s.users))
    })
}

/// Which system zone a VPN already is, for `vpn-zone add`: a user zone on the
/// same key would be a second tunnel, and two tunnels on one key knock each
/// other off. `SAME <zone>` for a zone the asker may use — the user zone then
/// goes out through it (§7b) —, a refusal for one they may not.
fn serve_key(uid: u32, key: &str) -> Result<Done, String> {
    let user = user_of(uid)?;
    match key_owner(key, None) {
        Some((zone, users)) if users.contains(&user.name) => Ok(Done::Same(zone)),
        Some((zone, _)) => Err(format!(
            "this VPN is already the system zone {zone}, which is not {}'s",
            user.name
        )),
        None => Ok(Done::Ok(String::new())),
    }
}

/// Add a VPN as a system zone — or say which zone it already is. One config
/// is one tunnel: the same private key in two tunnels makes the server see
/// two devices with one key, and they knock each other off.
fn serve_add(uid: u32, request: &AddRequest) -> Result<Done, String> {
    let zone = request.zone.as_str();
    if uid == 0 {
        return Err("root adds a zone by declaring it".to_owned());
    }
    let user = user_of(uid)?;
    // `services.cellward.system.users`, and nobody else: a zone's own users
    // may use it, not add zones (review — a program in a user zone, where the
    // group reaches, could have added a plain zone and gone out by it).
    if !system::adders().contains(&user.name) {
        return Err(format!(
            "{} may not add system zones (services.cellward.system.users)",
            user.name
        ));
    }
    let existing = system::settings(zone);
    if let Some(s) = &existing {
        if !s.users.contains(&user.name) {
            return Err(format!(
                "the system zone {zone} exists and is not {}'s",
                user.name
            ));
        }
        if s.declared && s.plain != request.plain {
            return Err(format!(
                "{zone} is declared in Nix as {}",
                if s.plain { "plain" } else { "a tunnel" }
            ));
        }
        if s.declared
            && !s.plain
            && s.config != system::local_dir(zone).join("config.conf")
            && !system::is_foreign_config(zone, &s.config)
        {
            return Err(format!(
                "the config of {zone} comes from Nix ({})",
                s.config.display()
            ));
        }
        // The host's own names, clock or services go through it: whoever sets
        // its tunnel answers for all of them. Root sets it, not a request.
        if s.declared && s.carries {
            return Err(format!(
                "{zone} carries the host's own services — its config is root's to change"
            ));
        }
    }
    if !request.plain {
        let cfg = crate::config::WgConfig::parse(&request.config)
            .map_err(|e| format!("the config: {e}"))?;
        if let Some(why) = system::refusal(&cfg) {
            return Err(why.to_owned());
        }
        let key = private_key(&cfg).ok_or("the config has no PrivateKey")?;
        if let Some((other, users)) = key_owner(&key, Some(zone)) {
            if users.contains(&user.name) {
                return Ok(Done::Same(other));
            }
            return Err(format!(
                "this VPN is already the system zone {other}, which is not {}'s",
                user.name
            ));
        }
    }

    let local = system::local_dir(zone);
    fs::create_dir_all(&local).map_err(|e| format!("cannot create {}: {e}", local.display()))?;
    if !request.plain {
        crate::zone::write_private(
            &local.join("config.conf"),
            system::without_listen_port(&String::from_utf8_lossy(&request.config)).as_bytes(),
        )
        .map_err(|e| format!("cannot write the config: {e}"))?;
    }
    if existing.as_ref().is_some_and(|s| s.declared) {
        // A declared user wrote this config: it is the declared zone's now,
        // whoever added one of that name on the spot before (`system::settings`).
        let _ = fs::remove_file(local.join("users"));
    }
    if !existing.as_ref().is_some_and(|s| s.declared) {
        let kind = if request.plain { "plain\n" } else { "tunnel\n" };
        fs::write(local.join("kind"), kind).map_err(|e| format!("cannot write: {e}"))?;
        fs::write(local.join("users"), format!("{}\n", user.name))
            .map_err(|e| format!("cannot write: {e}"))?;
    }
    println!("sysrun: {} added the system zone {zone}", user.name);
    systemctl(&["restart", &format!("vpn-zone-system@{zone}.service")])
        .map_err(|e| format!("{zone} is added, but did not come up: {e}"))?;
    Ok(Done::Ok(format!("зона {zone} добавлена и поднята")))
}

/// Bring a zone up for one of its users.
fn serve_up(uid: u32, zone: &str) -> Result<Done, String> {
    let settings =
        system::settings(zone).ok_or_else(|| format!("there is no system zone {zone}"))?;
    let user = user_of(uid)?;
    if uid != 0 && !settings.users.contains(&user.name) {
        return Err(format!("{} may not use the system zone {zone}", user.name));
    }
    systemctl(&["start", &format!("vpn-zone-system@{zone}.service")])
        .map_err(|e| format!("{zone} did not come up: {e}"))?;
    Ok(Done::Ok(format!("зона {zone} поднята")))
}

fn serve(sock: RawFd, uid: u32, data: &[u8], fds: Vec<OwnedFd>) -> Result<u8, String> {
    let request = Request::decode(data)?;
    let zone = request.zone.clone();
    check_name(&zone)?;
    if system::settings(&zone).is_none() {
        return Err(format!("there is no system zone {zone}"));
    }
    if uid == 0 {
        // Root is root in the zone's namespace, and could route around the
        // tunnel; root has `ip netns exec` anyway.
        return Err("root does not go through here — `ip netns exec` is root's".to_owned());
    }
    let mut user = user_of(uid)?;
    if !allowed_users(&zone).contains(&user.name) {
        return Err(format!(
            "{} may not run programs in the system zone {zone}",
            user.name
        ));
    }
    // The account's own group and no other (review 2026-09-25, third round:
    // a list of groups to drop was a list of doors not yet thought of). Not
    // the group that opens this service's socket — from inside a zone the
    // command must not ask for another one; nor one that opens a daemon
    // running things for it on the host, in the host's network (docker,
    // libvirt: a way out of any zone); nor `input`, every key pressed.
    user.groups = vec![user.gid];
    if fds.len() != request.mode.fds() {
        return Err("the descriptors do not match the mode".to_owned());
    }
    let netns = File::open(system::netns_path(&zone))
        .map_err(|e| format!("the system zone {zone} is not up ({e})"))?;
    let runtime = Path::new("/run/user").join(uid.to_string());
    let runtime = runtime.is_dir().then_some(runtime);
    let env = child_env(&request.env, &user, &zone, runtime.as_deref());
    // Debug-quoted: a program name with a line break in it would forge a
    // line of root's journal.
    println!(
        "sysrun: {} runs {:?} in the system zone {zone}",
        user.name,
        request.argv[0].to_string_lossy()
    );
    let launch = Launch {
        system_bus: system_bus_allowed(&zone),
        request,
        fds,
        netns,
        user,
        runtime,
        env,
    };

    // SAFETY: the service is single-threaded here, so the child may allocate.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        let why = become_the_command(&launch);
        eprintln!("vpn-zone-sys: {why}");
        // SAFETY: the child ends here, without running the parent's cleanup.
        unsafe { libc::_exit(127) };
    }
    drop(launch);

    // The client gone means nobody wants the command any more: the end of the
    // stream or a reset — not an interrupted or timed-out wait, and not a byte
    // it sent after the request.
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        loop {
            // SAFETY: a valid descriptor and a buffer of the length given.
            let n = unsafe { libc::recv(sock, byte.as_mut_ptr().cast(), 1, 0) };
            if n > 0 {
                continue;
            }
            if n < 0 {
                let err = io::Error::last_os_error().raw_os_error();
                if matches!(err, Some(libc::EINTR | libc::EAGAIN)) {
                    continue;
                }
            }
            break;
        }
        // SAFETY: the child's process group — it made itself a session.
        unsafe {
            libc::kill(-pid, libc::SIGHUP);
            libc::kill(-pid, libc::SIGTERM);
        }
        // A command that ignores both would outlive its client for good. The
        // group is ours while its leader lives — held by a pidfd, so a number
        // reused is never signalled.
        if let Some(leader) = sys::pidfd_open(pid) {
            if !sys::pidfd_wait(&leader, Duration::from_secs(5)) {
                // SAFETY: as above; the leader still runs, so the group is ours.
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
        }
    });
    let mut status = 0;
    loop {
        // SAFETY: our own child and an out-parameter.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(crate::profile::exit_code_of(status));
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(format!("waitpid: {err}"));
        }
    }
}

/// In the child: the caller's terminal, the zone, the mounts, the user, exec.
/// Returns only why it failed.
fn become_the_command(launch: &Launch) -> String {
    // SAFETY: setsid takes no arguments; a new session so the pty can become
    // the controlling terminal.
    unsafe { libc::setsid() };
    match launch.request.mode {
        Mode::Pty => {
            let tty = launch.fds[0].as_raw_fd();
            // SAFETY: a fresh pty slave, controlling no other session.
            if unsafe { libc::ioctl(tty, libc::TIOCSCTTY, 0) } != 0 {
                return format!("cannot take the terminal: {}", io::Error::last_os_error());
            }
            for target in 0..3 {
                // SAFETY: two valid descriptor numbers.
                unsafe { libc::dup2(tty, target) };
            }
        }
        Mode::Pipes => {
            for (target, fd) in (0..3).zip(&launch.fds) {
                // SAFETY: two valid descriptor numbers.
                unsafe { libc::dup2(fd.as_raw_fd(), target) };
            }
        }
    }

    // SAFETY: a descriptor of /run/netns/vz-<zone>.
    if unsafe { libc::setns(launch.netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return format!("cannot enter the zone: {}", io::Error::last_os_error());
    }
    // Nothing but the three standard descriptors goes into the command: the
    // connection systemd passed is fd 3, and with it the command could answer
    // its own client in the service's name (review). Marked close-on-exec,
    // so the ones still needed until the exec stay usable.
    // SAFETY: close_range(2) takes numbers and flags only.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } != 0
    {
        // Before Linux 5.11: one by one, from what /proc says is open.
        let open: Vec<i32> = fs::read_dir("/proc/self/fd")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse().ok())
            .filter(|fd| *fd >= 3)
            .collect();
        for fd in open {
            // SAFETY: fcntl on a descriptor number; a closed one just fails.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
    }
    if let Err(e) = seal_mounts(launch) {
        return e;
    }
    if let Err(e) = drop_to(&launch.user) {
        return e;
    }
    if let Err(e) = own_user_namespace(&launch.user) {
        return e;
    }
    if std::env::set_current_dir(&launch.request.cwd).is_err()
        && std::env::set_current_dir(&launch.user.home).is_err()
    {
        let _ = std::env::set_current_dir("/");
    }
    // SAFETY: the child is single-threaded; nothing else reads the environment.
    unsafe { libc::clearenv() };
    for (key, value) in &launch.env {
        std::env::set_var(key, value);
    }
    let e = crate::profile::exec_command(&launch.request.argv);
    format!(
        "cannot run {}: {e}",
        launch.request.argv[0].to_string_lossy()
    )
}

/// A mount namespace of the command's own: what a service in the zone gets
/// from its unit, done by hand.
fn seal_mounts(launch: &Launch) -> Result<(), String> {
    // SAFETY: unshare takes flags only.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "cannot make a mount namespace: {}",
            io::Error::last_os_error()
        ));
    }
    sys::mount(
        OsStr::new("none"),
        Path::new("/"),
        "",
        libc::MS_REC | libc::MS_PRIVATE,
        "",
    )
    .map_err(|e| format!("cannot make the mount tree private: {e}"))?;

    // The system's own services under /run, as in a user zone
    // (`zone::seal_run`) — before the resolvers, which are below it.
    zone::seal_run()?;
    // The host's resolvers first: on NixOS /etc/resolv.conf is a chain of links
    // ending INSIDE one of them (see zone.rs, where it bit first).
    for group in zone::RESOLVER_DIRS {
        zone::hide_first(group)?;
    }
    let zone = launch.request.zone.as_str();
    bind_over(
        &system::resolv_path(zone),
        Path::new("/etc/resolv.conf"),
        true,
    )?;
    let nsswitch = system::nsswitch_path(zone);
    if nsswitch.exists() {
        bind_over(&nsswitch, Path::new("/etc/nsswitch.conf"), false)?;
    }
    if !launch.system_bus && Path::new("/run/dbus").is_dir() {
        sys::mount(
            OsStr::new("tmpfs"),
            Path::new("/run/dbus"),
            "tmpfs",
            0,
            "mode=0755,size=64k",
        )
        .map_err(|e| format!("cannot hide the system bus: {e}"))?;
    }
    if let Some(dir) = &launch.runtime {
        let options = format!(
            "mode=0700,uid={},gid={},size=16m",
            launch.user.uid, launch.user.gid
        );
        sys::mount(OsStr::new("tmpfs"), dir, "tmpfs", 0, &options)
            .map_err(|e| format!("cannot hide the session's sockets: {e}"))?;
    }
    // This service's own socket: a command in one zone asking for another
    // (review) — the same cover a user zone gets.
    let tier = Path::new("/run/vpn-zones");
    if tier.is_dir() {
        sys::mount(OsStr::new("tmpfs"), tier, "tmpfs", 0, "mode=0755,size=16k")
            .map_err(|e| format!("cannot hide the system tier's socket: {e}"))?;
    }
    // Temporary directories of its own: the host's /tmp holds the session's
    // listening sockets — X11, tmux, singletons —, and the user's uid gets
    // through their peer checks (review).
    for dir in ["/tmp", "/var/tmp", "/dev/shm"] {
        let dir = Path::new(dir);
        if dir.is_dir() {
            sys::mount(
                OsStr::new("tmpfs"),
                dir,
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV,
                "mode=1777,size=512m",
            )
            .map_err(|e| format!("cannot give {} of its own: {e}", dir.display()))?;
        }
    }
    // The Nix daemon builds and fetches in the host's network.
    let daemon = Path::new("/nix/var/nix/daemon-socket");
    if daemon.is_dir() {
        sys::mount(
            OsStr::new("tmpfs"),
            daemon,
            "tmpfs",
            0,
            "mode=0755,size=16k",
        )
        .map_err(|e| format!("cannot hide the Nix daemon: {e}"))?;
    }
    // The user zones' state and the project's settings, as in a user zone
    // (`zone::hide_project_state`): the command has the user's home, and from
    // there could rewrite which namespace the host takes for which zone.
    let home = &launch.user.home;
    zone::seal_project_state(&home.join(".local/state/vpn-zones"), home, &[])?;
    Ok(())
}

/// Bind `source` over wherever `link`'s chain of symlinks ends, creating the
/// end when it is missing and `create` says so.
fn bind_over(source: &Path, link: &Path, create: bool) -> Result<(), String> {
    let target = sys::link_target(link);
    if !target.exists() {
        if !create {
            return Ok(());
        }
        if let Some(dir) = target.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        File::create(&target).map_err(|e| format!("cannot create {}: {e}", target.display()))?;
    }
    sys::mount(source.as_os_str(), &target, "", libc::MS_BIND, "").map_err(|e| {
        format!(
            "cannot bind {} over {}: {e}",
            source.display(),
            target.display()
        )
    })
}

/// The user's groups, gid and uid, and no way back.
fn drop_to(user: &User) -> Result<(), String> {
    let fail = |what: &str| format!("cannot {what}: {}", io::Error::last_os_error());
    // SAFETY: a list of gids and its length.
    if unsafe { libc::setgroups(user.groups.len(), user.groups.as_ptr()) } != 0 {
        return Err(fail("set the groups"));
    }
    // SAFETY: plain ids.
    if unsafe { libc::setgid(user.gid) } != 0 {
        return Err(fail("set the gid"));
    }
    // SAFETY: plain ids.
    if unsafe { libc::setuid(user.uid) } != 0 {
        return Err(fail("set the uid"));
    }
    // SAFETY: no arguments.
    let still_root = unsafe { libc::getuid() != user.uid || libc::geteuid() != user.uid };
    if still_root {
        return Err("the uid did not change".to_owned());
    }
    // SAFETY: a documented prctl with constant arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(fail("set no_new_privs"));
    }
    Ok(())
}

/// A user namespace of the command's own, the user mapped onto itself
/// (`docs/LEAK-MODEL.md` §16).
///
/// The tmpfs of [`seal_mounts`] hides the session's sockets where they lie, but
/// in the host's user namespace the command could still walk into any process
/// of the session through `/proc/<pid>/root` — the compositor's IPC, the
/// session bus — because the kernel lets the same user read another process's
/// view of the file system. From a namespace of its own it cannot: reading a
/// process of another user namespace takes `CAP_SYS_PTRACE` in that one. The
/// same wall user zones stand behind. Files of other users, root included, are
/// seen as `nobody` inside, exactly as in a user zone.
///
/// Fatal when it cannot be made: a command that sees into the session is worse
/// than no command. Done as the user, after `NO_NEW_PRIVS` — the capabilities
/// the new namespace hands out are over nothing that already exists, and the
/// `execve` that follows drops them (the uid inside is not 0).
fn own_user_namespace(user: &User) -> Result<(), String> {
    // setuid() from root cleared the dumpable flag, and a process that is not
    // dumpable has its /proc/self owned by root: the maps below would be
    // refused (measured: EACCES on setgroups). The execve that follows sets it
    // back anyway — the command is the user's, with the user's ids — so this
    // only brings that moment forward; `unshare --map-current-user` does the
    // same, as does the zone holder (zone.rs).
    // SAFETY: prctl with these arguments takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "cannot make the command dumpable: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: unshare takes flags only; the child is single-threaded.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(format!(
            "cannot make a user namespace for the command ({}) — it would see into the session's processes",
            io::Error::last_os_error()
        ));
    }
    // `deny` first: without it an unprivileged process may not write gid_map.
    // The groups already set stay in force.
    for (file, text) in [
        ("/proc/self/setgroups", "deny".to_owned()),
        ("/proc/self/uid_map", format!("{0} {0} 1\n", user.uid)),
        ("/proc/self/gid_map", format!("{0} {0} 1\n", user.gid)),
    ] {
        fs::write(file, text).map_err(|e| format!("cannot write {file}: {e}"))?;
    }
    Ok(())
}

/// The account behind a uid, with its groups.
fn user_of(uid: u32) -> Result<User, String> {
    // SAFETY: passwd is plain data; getpwuid_r fills it or leaves `found` null.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf: Vec<libc::c_char> = vec![0; 16 * 1024];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is to a local that outlives the call.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() {
        return Err(format!("uid {uid} has no account"));
    }
    // SAFETY: getpwuid_r succeeded, so these point into `buf`.
    let (name, home, shell) = unsafe {
        (
            CStr::from_ptr(pwd.pw_name).to_owned(),
            CStr::from_ptr(pwd.pw_dir).to_owned(),
            CStr::from_ptr(pwd.pw_shell).to_owned(),
        )
    };
    let groups = groups_of(&name, pwd.pw_gid)?;
    Ok(User {
        name: name
            .into_string()
            .map_err(|_| format!("the name of uid {uid} is not UTF-8"))?,
        uid,
        gid: pwd.pw_gid,
        home: PathBuf::from(OsString::from_vec(home.into_bytes())),
        shell: PathBuf::from(OsString::from_vec(shell.into_bytes())),
        groups,
    })
}

fn groups_of(name: &CString, gid: u32) -> Result<Vec<u32>, String> {
    let mut size: libc::c_int = 64;
    loop {
        let mut list: Vec<libc::gid_t> = vec![0; usize::try_from(size).unwrap_or(64)];
        let mut count = size;
        // SAFETY: a name, a buffer and its length in `count`.
        let rc = unsafe { libc::getgrouplist(name.as_ptr(), gid, list.as_mut_ptr(), &mut count) };
        if rc >= 0 {
            list.truncate(usize::try_from(count).unwrap_or(0));
            return Ok(list);
        }
        if count <= size || count > 65_536 {
            return Err("cannot list the user's groups".to_owned());
        }
        size = count;
    }
}

// --- SOCKETS -------------------------------------------------------------------

/// Who is on the other end, by the kernel's word.
fn peer_uid(sock: RawFd) -> Result<u32, String> {
    peer_cred(sock).map(|(uid, _)| uid)
}

/// The asker's uid and pid, from the kernel.
fn peer_cred(sock: RawFd) -> Result<(u32, i32), String> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid descriptor, a correctly sized buffer and its length.
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || cred.pid <= 0 {
        return Err("cannot tell who is asking".to_owned());
    }
    Ok((cred.uid, cred.pid))
}

fn connect(path: &str) -> io::Result<OwnedFd> {
    // SAFETY: plain constants.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor of ours.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: sockaddr_un is plain data.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }
    for (slot, byte) in addr.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: a valid descriptor and an address of the length given.
    let rc = unsafe {
        libc::connect(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_un).cast(),
            len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    fn request() -> Request {
        Request {
            zone: "nl".to_owned(),
            mode: Mode::Pty,
            cwd: OsString::from("/home/alice/проект"),
            argv: os(&["socat", "-", "TCP:10.99.0.1:8080"]),
            env: os(&["PATH=/run/current-system/sw/bin", "TERM=xterm-256color"]),
        }
    }

    #[test]
    fn a_request_survives_the_wire() {
        let r = request();
        assert_eq!(Request::decode(&r.encode()), Ok(r.clone()));
        let pipes = Request {
            mode: Mode::Pipes,
            env: Vec::new(),
            ..r
        };
        assert_eq!(Request::decode(&pipes.encode()), Ok(pipes));
    }

    #[test]
    fn a_broken_request_is_refused() {
        let good = request().encode();
        assert!(Request::decode(b"").is_err());
        assert!(Request::decode(&good[1..]).is_err(), "no magic");
        assert!(
            Request::decode(&good[..good.len() - 1]).is_err(),
            "no final NUL"
        );
        let mut extra = good.clone();
        extra.extend_from_slice(b"more\0");
        assert!(Request::decode(&extra).is_err(), "trailing field");

        let empty_cmd = Request {
            argv: os(&[""]),
            ..request()
        };
        assert!(Request::decode(&empty_cmd.encode()).is_err());
        let no_cmd = Request {
            argv: Vec::new(),
            ..request()
        };
        assert!(Request::decode(&no_cmd.encode()).is_err());

        // Built field by field: a NUL next to a digit would read as an octal
        // escape in a literal.
        let raw = |fields: &[&str]| {
            let mut out = MAGIC.to_vec();
            for field in fields {
                out.extend_from_slice(field.as_bytes());
                out.push(0);
            }
            out
        };
        let huge = raw(&["nl", "pty", "/", "999999"]);
        assert!(Request::decode(&huge).is_err(), "a count past the limit");
        let short = raw(&["nl", "pty", "/", "3", "a", "b"]);
        assert!(
            Request::decode(&short).is_err(),
            "fewer arguments than said"
        );
        let mode = raw(&["nl", "tty", "/", "1", "sh", "0"]);
        assert!(Request::decode(&mode).is_err(), "unknown mode");
        let fine = raw(&["nl", "pipes", "/", "1", "sh", "0"]);
        assert!(Request::decode(&fine).is_ok(), "the same, well-formed");
    }

    #[test]
    fn the_answer_carries_the_exit_code_or_the_reason() {
        assert_eq!(parse_answer(&answer_exit(7)), Ok(7));
        assert_eq!(parse_answer(&answer_exit(0)), Ok(0));
        assert_eq!(
            parse_answer(&answer_refusal("bob may not")),
            Err("bob may not".to_owned())
        );
        assert!(parse_answer(b"garbage").is_err());
        assert!(parse_answer(b"EXIT x").is_err());
    }

    #[test]
    fn the_environment_loses_the_session_and_gets_the_account() {
        let user = User {
            name: "alice".to_owned(),
            uid: 1000,
            gid: 100,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/run/current-system/sw/bin/zsh"),
            groups: vec![100],
        };
        let env = child_env(
            &os(&[
                "PATH=/bin",
                "TERM=xterm",
                "HOME=/tmp/elsewhere",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                "WAYLAND_DISPLAY=wayland-1",
                "XDG_RUNTIME_DIR=/run/user/1000",
                "PATH=/second",
                "not a variable",
                "=value",
            ]),
            &user,
            "nl",
            Some(Path::new("/run/user/1000")),
        );
        let get = |k: &str| {
            env.iter()
                .filter(|(key, _)| key == k)
                .map(|(_, v)| v.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(get("PATH"), ["/bin"]);
        assert_eq!(get("TERM"), ["xterm"]);
        assert_eq!(get("HOME"), ["/home/alice"]);
        assert_eq!(get("USER"), ["alice"]);
        assert_eq!(get("SHELL"), ["/run/current-system/sw/bin/zsh"]);
        assert_eq!(get("VPN_ZONE_CURRENT"), ["sys:nl"]);
        assert_eq!(get("XDG_RUNTIME_DIR"), ["/run/user/1000"]);
        assert!(get("DBUS_SESSION_BUS_ADDRESS").is_empty());
        assert!(get("WAYLAND_DISPLAY").is_empty());
        assert!(env.iter().all(|(k, _)| !k.is_empty()));

        let without_runtime = child_env(&os(&["XDG_RUNTIME_DIR=/x"]), &user, "nl", None);
        assert!(without_runtime.iter().all(|(k, _)| k != "XDG_RUNTIME_DIR"));
    }

    #[test]
    fn adding_a_zone_survives_the_wire() {
        let add = AddRequest {
            zone: "nl".to_owned(),
            plain: false,
            config: b"[Interface]\nPrivateKey = x\n".to_vec(),
        };
        let bytes = add.encode();
        assert_eq!(
            AddRequest::decode(bytes.strip_prefix(ADD_MAGIC).unwrap()),
            Ok(add)
        );
        let plain = AddRequest {
            zone: "direct2".to_owned(),
            plain: true,
            config: Vec::new(),
        };
        assert_eq!(
            AddRequest::decode(plain.encode().strip_prefix(ADD_MAGIC).unwrap()),
            Ok(plain)
        );
        assert!(AddRequest::decode(b"Bad_Zone\0tunnel\0").is_err());
        assert!(AddRequest::decode(b"nl\0vpn\0").is_err());
        assert!(AddRequest::decode(b"nl\0tunnel").is_err());

        assert_eq!(
            decode_up(encode_up("nl").strip_prefix(UP_MAGIC).unwrap()),
            Ok("nl".to_owned())
        );
        assert!(decode_up(b"nl").is_err());

        assert_eq!(
            parse_done(&answer_done(&Done::Same("nl".to_owned()))),
            Ok(Done::Same("nl".to_owned()))
        );
        assert_eq!(
            parse_done(&answer_done(&Done::Ok("зона nl поднята".to_owned()))),
            Ok(Done::Ok("зона nl поднята".to_owned()))
        );
        assert_eq!(parse_done(&answer_refusal("no")), Err("no".to_owned()));
    }

    #[test]
    fn the_users_of_a_zone_are_names_and_nothing_else() {
        assert_eq!(
            parse_users("alice\n\n bob \nroot\nBad\n../x\n_svc\nw.x-y\n"),
            ["alice", "bob", "root", "_svc", "w.x-y"]
        );
    }

    #[test]
    fn the_command_line_of_the_client() {
        assert_eq!(
            parse_client_args(&os(&["nl", "--", "bash", "-l"])),
            Ok(("nl".to_owned(), os(&["bash", "-l"])))
        );
        assert_eq!(
            parse_client_args(&os(&["nl", "curl", "--", "x"])),
            Ok(("nl".to_owned(), os(&["curl", "--", "x"])))
        );
        assert!(parse_client_args(&os(&[])).is_err());
        assert!(parse_client_args(&os(&["nl"])).is_err());
        assert!(parse_client_args(&os(&["nl", "--"])).is_err());
        assert!(parse_client_args(&os(&["Bad_Zone", "sh"])).is_err());
    }

    #[test]
    fn descriptors_travel_with_a_request() {
        let mut pair = [0; 2];
        // SAFETY: an out-parameter for two descriptors.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: both are fresh descriptors of ours.
        let (a, b) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
        let (r, w) = sys::pipe().unwrap();
        sys::send_with_fds(a.as_raw_fd(), b"hello", &[w.as_raw_fd()]).unwrap();
        drop(w);
        let (data, fds) = sys::recv_with_fds(b.as_raw_fd(), 64, 3).unwrap();
        assert_eq!(data, b"hello");
        assert_eq!(fds.len(), 1);
        File::from(fds.into_iter().next().unwrap())
            .write_all(b"through")
            .unwrap();
        let mut got = String::new();
        File::from(r).read_to_string(&mut got).unwrap();
        assert_eq!(got, "through");
    }
}
