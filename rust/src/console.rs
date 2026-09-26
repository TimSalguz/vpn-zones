//! The TTY console (ROADMAP M10, `docs/ARCHITECTURE.md` §4, `docs/SYSTEM.md`
//! §7a): fell into a text console, logged in — and there is a network already,
//! with nothing to type and nothing to know.
//!
//! ```text
//!  cellward — console · alice
//!    network: sz — tunnel alive
//!    [Enter] a terminal with the network (zone sz)
//!    [n]     the admin tool, if one is configured
//!    [p]     directly, without the VPN (zone pl)   ← when sz has no tunnel
//!    [k]     the emergency key: the host's network for 15 minutes
//!    [q]     the plain console (no network)
//! ```
//!
//! The login shell calls this on every login (`environment.loginShellInit`);
//! it decides for itself whether to show up: only on a virtual terminal, only
//! outside any zone, only for a user of the console's zone. It never locks
//! anybody out — every failure ends in the ordinary shell of the host, which
//! under the egress policy has no network but has everything to repair with.
//!
//! The words on the screen are Russian like the rest of the interface; the
//! parts a test or a person can grep for — the zone names and the keys — are
//! ASCII.

use std::ffi::{CStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::system::{self, RunState};
use crate::watch;

/// The module's settings: `key=value` lines.
pub const CONFIG: &str = "/etc/vpn-zones/console";

/// How long to wait for a tunnel that was just started, or is starting.
const WAIT_ALIVE: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub zone: String,
    pub fallback: Option<String>,
    pub admin: Option<String>,
    pub admin_label: Option<String>,
}

pub fn parse_config(text: &str) -> Option<Config> {
    let mut config = Config::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_owned();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "zone" => config.zone = value,
            "fallback" => config.fallback = Some(value),
            "admin" => config.admin = Some(value),
            "admin-label" => config.admin_label = Some(value),
            _ => {}
        }
    }
    system::check_name(&config.zone).ok()?;
    if let Some(fallback) = &config.fallback {
        system::check_name(fallback).ok()?;
    }
    Some(config)
}

/// Is this device a virtual terminal — `/dev/tty1`, not a pty, not a serial
/// line?
pub fn is_virtual_terminal(device: &str) -> bool {
    device
        .strip_prefix("/dev/tty")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// What the network of a zone looks like to its user right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Net {
    Alive,
    /// Up, no live tunnel (yet).
    Waiting,
    Down,
    /// The reader is not in the group `vpn-zones`.
    Unknown,
}

/// A tunnel is alive when it shook hands within WireGuard's session limit; a
/// plain zone when pasta's interface is there and up.
pub fn net_of(state: &RunState) -> Net {
    match state {
        RunState::Closed => Net::Unknown,
        RunState::Down => Net::Down,
        RunState::Up(None) => Net::Waiting,
        RunState::Up(Some(mirror)) => {
            let reading = watch::parse_mirror(mirror);
            let alive = reading.connected == Some(true)
                || reading
                    .handshake_age_s
                    .is_some_and(|age| age <= watch::SESSION_LIMIT_S);
            if alive {
                Net::Alive
            } else {
                Net::Waiting
            }
        }
    }
}

/// `vpn-zone-console [--login]`. Always 0: a console that fails must still
/// leave the login going.
pub fn run(args: &[OsString]) -> u8 {
    let login = args.iter().any(|a| a == "--login");
    if login && (!should_show() || crate::system::is_off()) {
        return 0;
    }
    let Some(config) = fs::read_to_string(CONFIG)
        .ok()
        .and_then(|t| parse_config(&t))
    else {
        if !login {
            eprintln!("vpn-zone-console: не настроен ({CONFIG})");
        }
        return 0;
    };
    let user = user_name().unwrap_or_default();
    if !crate::sysrun::allowed_users(&config.zone).contains(&user) {
        if !login {
            eprintln!("vpn-zone-console: {user} не в зоне {}", config.zone);
        }
        return 0;
    }
    menu(&config, &user);
    0
}

/// A virtual terminal, outside any zone.
fn should_show() -> bool {
    if std::env::var_os("VPN_ZONE_CURRENT").is_some() {
        return false;
    }
    let mut buf: [libc::c_char; 128] = [0; 128];
    // SAFETY: descriptor 0 and a buffer of the length given.
    let rc = unsafe { libc::ttyname_r(0, buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: ttyname_r succeeded, so the buffer holds a C string.
    let name = unsafe { CStr::from_ptr(buf.as_ptr()) };
    is_virtual_terminal(&name.to_string_lossy())
}

fn user_name() -> Option<String> {
    // SAFETY: getpwuid returns a pointer into a static buffer, read at once.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() {
            return None;
        }
        Some(CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

fn menu(config: &Config, user: &str) {
    let zone = config.zone.as_str();
    let mut started = false;
    let mut waited = false;
    loop {
        // A zone that is down is started — through the system-zone service,
        // which lets the zone's users — and waited for, once per console; a
        // tunnel that was already up but has not shaken hands is waited for
        // too. Once: back from a shell, the menu says how things are now.
        let mut net = net_of(&system::run_state(zone));
        if net == Net::Down && !started {
            started = true;
            println!("Поднимаю зону {zone}…");
            if let Err(e) = crate::sysrun::request_up(zone) {
                println!("{e}");
            }
            net = net_of(&system::run_state(zone));
        }
        if net == Net::Waiting && !waited {
            waited = true;
            net = wait_alive(zone);
        }
        // Mouse reports off — a program of a zone may have turned them on:
        // a click is not a choice (`next_key` skips them all the same).
        print!("\x1b[?1000l\x1b[?9l");
        drop_typeahead();

        let fallback = config.fallback.as_deref().filter(|_| net != Net::Alive);
        println!();
        println!("  cellward — консоль · {user}");
        println!(
            "    сеть: {zone} — {}",
            match net {
                Net::Alive => "туннель жив (tunnel alive)",
                Net::Waiting => "туннель не отвечает (no tunnel)",
                Net::Down => "зона не поднялась (down)",
                Net::Unknown => "состояние не видно (not in vpn-zones)",
            }
        );
        if net == Net::Alive {
            println!("    [Enter] терминал с интернетом (zone {zone})");
        } else {
            println!("    [Enter] терминал в зоне {zone} — пока без сети");
        }
        if let Some(admin) = &config.admin {
            println!(
                "    [n]     {}",
                config.admin_label.as_deref().unwrap_or(admin)
            );
        }
        if let Some(plain) = fallback {
            println!("    [p]     напрямую, без VPN (zone {plain})");
        }
        println!("    [k]     аварийный ключ: сеть на хосте на время (emergency key)");
        println!(
            "    [x]     выключить cellward целиком — сеть хоста, пока не включишь (cellward off)"
        );
        println!("    [q]     обычная консоль, без сети (plain console)");
        print!("  > ");
        let _ = io::stdout().flush();

        let Some(key) = read_key() else {
            return;
        };
        println!();
        match key {
            b'\n' | b'\r' => shell_in(zone),
            b'n' | b'N' => {
                if let Some(admin) = &config.admin {
                    let _ = Command::new("sh").args(["-c", admin]).status();
                }
            }
            b'p' | b'P' => {
                if let Some(plain) = fallback {
                    if let Err(e) = crate::sysrun::request_up(plain) {
                        println!("{e}");
                    }
                    shell_in(plain);
                }
            }
            b'k' | b'K' if !confirmed(b'k', "аварийный ключ: у хоста будет сеть") =>
                {}
            b'x' | b'X' if !confirmed(b'x', "выключить cellward целиком") => {}
            b'k' | b'K' => {
                let ok = Command::new("systemctl")
                    .args(["start", "vpn-zones-egress-open.service"])
                    .status()
                    .is_ok_and(|s| s.success());
                println!(
                    "{}",
                    if ok {
                        "Ключ повёрнут: у хоста сеть на время, потом закроется сама. (key turned)"
                    } else {
                        "Ключ не повернулся — нужна группа ключа или root. (key refused)"
                    }
                );
            }
            b'x' | b'X' => {
                let ok = Command::new("systemctl")
                    .args(["start", "vpn-zones-off.service"])
                    .status()
                    .is_ok_and(|s| s.success());
                if ok {
                    println!(
                        "cellward выключен: у хоста своя сеть. Включить обратно — vpn-zones-on. \
                         (cellward off)"
                    );
                    return;
                }
                println!("Не выключилось — нужна группа выключателя или root. (refused)");
            }
            b'q' | b'Q' | 0x1b | 0x04 => return,
            _ => {}
        }
    }
}

/// The same key once more, pressed after the question is on the screen: the
/// two choices that open the host take two keys, so that one stray byte —
/// a terminal's answer, a key held down — does not (review 2026-09-25).
fn confirmed(key: u8, what: &str) -> bool {
    print!(
        "  {what} — нажми «{}» ещё раз, любая другая клавиша — отмена: ",
        key as char
    );
    let _ = io::stdout().flush();
    drop_typeahead();
    let again = read_key();
    println!();
    again.is_some_and(|k| k.to_ascii_lowercase() == key)
}

/// Keys pressed before the menu is on the screen are not choices: typed while
/// the console waited for the tunnel, left over from the shell that just
/// ended, or a terminal's answer to something a program there printed. They
/// are dropped, so nothing reaches `x` or `k` that was not pressed for them.
fn drop_typeahead() {
    // SAFETY: descriptor 0 and a constant; on anything but a terminal it fails
    // and changes nothing.
    unsafe { libc::tcflush(0, libc::TCIFLUSH) };
}

/// Poll the zone's state until its tunnel is alive or the wait is over.
fn wait_alive(zone: &str) -> Net {
    let mut net = net_of(&system::run_state(zone));
    let steps = WAIT_ALIVE.as_millis() / 500;
    for i in 0..steps {
        if net == Net::Alive || net == Net::Down || net == Net::Unknown {
            break;
        }
        if i == 0 {
            println!("Жду туннель зоны {zone}…");
        }
        thread::sleep(Duration::from_millis(500));
        net = net_of(&system::run_state(zone));
    }
    net
}

/// A login shell in a system zone, through the system-zone service; back to
/// the menu when it ends. A process of its own and not `sysrun::client` in
/// this one: the client's relay leaves a thread blocked on the terminal, which
/// would take the next key meant for the menu.
///
/// A terminal answers what a program printed last (a query) a moment after
/// it is gone — sooner or later, as loaded as the machine is: the answer is
/// never a key, however late it lands ([`next_key`]).
fn shell_in(zone: &str) {
    shell_in_zone(zone);
}

fn shell_in_zone(zone: &str) {
    let shell = std::env::var_os("SHELL").unwrap_or_else(|| OsString::from("/bin/sh"));
    let core = std::env::current_exe().unwrap_or_else(|_| "vpn-zone-core".into());
    let status = Command::new(core)
        .arg("system-run")
        .arg(zone)
        .arg("--")
        .arg(shell)
        .arg("-l")
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => println!("({s})"),
        Err(e) => println!("не запустилось: {e}"),
    }
}

/// One key, without echo and without waiting for Enter. `None` at the end of
/// input — the console is gone, and so is the menu.
fn read_key() -> Option<u8> {
    // SAFETY: termios is plain data; tcgetattr fills it or fails.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: descriptor 0 and a termios to fill.
    let is_tty = unsafe { libc::tcgetattr(0, &mut saved) } == 0;
    if is_tty {
        let mut raw = saved;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: descriptor 0 and a filled termios.
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) };
    }
    // Straight from the descriptor, not through `io::stdin()`'s buffer: what
    // a buffer took in ahead would be out of `drop_typeahead`'s reach.
    let key = next_key(|buf| loop {
        // SAFETY: descriptor 0 and a buffer of the length given.
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Some(n as usize);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return None;
        }
    });
    if is_tty {
        // SAFETY: descriptor 0 and the termios read from it.
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
    }
    key
}

/// The next key, from `read` — a chunk at a time, what the terminal has as
/// it has it. A key is the first byte of a chunk with no ESC in it; a chunk
/// of ESC alone is the Esc key. Any other chunk with an ESC in it is a
/// sequence and chooses nothing, whenever it arrives: a terminal's answer to
/// a query a program printed (the console's `ESC [ ? 6 c` for its kind,
/// `ESC [ 0 n` for its status — an `n` in it, the admin tool's key —,
/// `ESC [ <row> ; <col> R` for the cursor), a key that sends one (arrows,
/// F-keys: the console's F1 is `ESC [ [ A`), a mouse report. The kernel
/// hands such a sequence over whole, in one piece, where a person's keys
/// come one by one — so no clock decides what was typed. Esc pressed
/// together with a key reads as one piece too, and is pressed again.
/// `None` at the end of input.
fn next_key(mut read: impl FnMut(&mut [u8]) -> Option<usize>) -> Option<u8> {
    let mut buf = [0u8; 256];
    loop {
        let n = read(&mut buf)?;
        let chunk = &buf[..n.min(buf.len())];
        match chunk {
            [] => return None,
            [0x1b] => return Some(0x1b),
            _ if chunk.contains(&0x1b) => continue,
            [first, ..] => return Some(*first),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_config_names_valid_zones_or_is_nothing() {
        let config = parse_config(
            "zone=sz\nfallback=pl\nadmin=nix_cm --tui\nadmin-label=Настройки и откат\n",
        )
        .unwrap();
        assert_eq!(config.zone, "sz");
        assert_eq!(config.fallback.as_deref(), Some("pl"));
        assert_eq!(config.admin.as_deref(), Some("nix_cm --tui"));
        assert_eq!(config.admin_label.as_deref(), Some("Настройки и откат"));
        assert_eq!(parse_config("zone=sz\n").unwrap().fallback, None);
        assert!(parse_config("").is_none());
        assert!(parse_config("zone=Bad_Zone\n").is_none());
        assert!(parse_config("zone=sz\nfallback=../x\n").is_none());
    }

    #[test]
    fn a_terminals_answer_is_never_a_key() {
        let key = |chunks: &[&[u8]]| {
            let mut chunks = chunks.iter();
            next_key(|buf| {
                let chunk = chunks.next()?;
                buf[..chunk.len()].copy_from_slice(chunk);
                Some(chunk.len())
            })
        };
        assert_eq!(key(&[b"q"]), Some(b'q'));
        // The console's answers, whole: never a key.
        assert_eq!(key(&[b"\x1b[?6c", b"\x1b[0n", b"q"]), Some(b'q'));
        assert_eq!(key(&[b"\x1b[12;40R", b"k"]), Some(b'k'));
        // Two answers in one piece, and an answer with a key typed with it.
        assert_eq!(key(&[b"\x1b[?6c\x1b[0n", b"\x1b[0nk", b"p"]), Some(b'p'));
        // F1 on the console, and a mouse report (`ESC [ M b x y`: a click
        // at column 78 makes an `n`).
        assert_eq!(key(&[b"\x1b[[A", b"\x1b[M n+", b"\r"]), Some(b'\r'));
        // Esc alone is a key: the menu's way out.
        assert_eq!(key(&[b"\x1b"]), Some(0x1b));
        // The end of input.
        assert_eq!(key(&[]), None);
        assert_eq!(key(&[b""]), None);
    }

    #[test]
    fn only_a_virtual_terminal_gets_the_console() {
        assert!(is_virtual_terminal("/dev/tty1"));
        assert!(is_virtual_terminal("/dev/tty12"));
        assert!(!is_virtual_terminal("/dev/tty"));
        assert!(!is_virtual_terminal("/dev/ttyS0"));
        assert!(!is_virtual_terminal("/dev/pts/3"));
    }

    #[test]
    fn alive_means_a_fresh_handshake_or_a_plain_link() {
        let fresh = "peer: x\n  latest handshake: 5 seconds ago\n";
        assert_eq!(net_of(&RunState::Up(Some(fresh.to_owned()))), Net::Alive);
        let stale = "peer: x\n  latest handshake: 1 hour, 2 minutes ago\n";
        assert_eq!(net_of(&RunState::Up(Some(stale.to_owned()))), Net::Waiting);
        let never = "interface: awg0\npeer: x\n";
        assert_eq!(net_of(&RunState::Up(Some(never.to_owned()))), Net::Waiting);
        let plain = "interface: awg0\n  backend: plain\n  connected: yes\n";
        assert_eq!(net_of(&RunState::Up(Some(plain.to_owned()))), Net::Alive);
        assert_eq!(net_of(&RunState::Up(None)), Net::Waiting);
        assert_eq!(net_of(&RunState::Down), Net::Down);
        assert_eq!(net_of(&RunState::Closed), Net::Unknown);
    }
}
