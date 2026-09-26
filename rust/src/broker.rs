//! The broker (`docs/HERMETICITY.md` §3, §7 C): the one door out of a hermetic
//! zone.
//!
//! A program in a zone that opens something — a link in a messenger, a file in
//! a mail client — ends in `vpn-zone run`, and a zone cannot enter another
//! network itself (`docs/GOTCHAS.md` §1), so the launch has to happen outside.
//! It used to go through `systemd-run --user`, which is a door with no guard:
//! any program in any zone can start any process on the host with it. A
//! hermetic zone has no `systemd --user` to reach, and this socket instead.
//!
//! The broker is a user service on the host. It learns WHICH zone asks from the
//! kernel — the network namespace of the process that connected — never from
//! the request, and it answers:
//!
//! * the host's own namespace: started — a host program could run `vpn-zone`
//!   itself;
//! * a launch into the very zone that asks: started, no dialog — the program
//!   is in that zone already;
//! * a locked zone asking for another network: refused;
//! * another zone asking — for another zone, for `unconfined`: a person is
//!   asked, with the asking zone and the command in the question; with nobody
//!   to ask (no graphical session), refused;
//! * a namespace that is none of these, or a process that can no longer be
//!   told: refused. It used to be "not a zone, so the host", and started:
//!   a program that asked and exited before the broker looked had its request
//!   run on the host with the host's network, no question asked.
//!
//! **The process is held, not its number.** The peer is pinned when the
//! connection is taken — the kernel's pidfd of the very process that connected
//! (`SO_PEERPIDFD`, Linux 6.5; before that, one opened by its pid at once;
//! a peer the kernel says has exited is not opened by its number at all) —
//! and its namespace is read only while that process is still alive, before
//! and after the read. A pid that went to somebody else is never looked at.
//!
//! The request is `VZB1\0`, the app-id, then the arguments of `vpn-zone run`,
//! each terminated by a NUL; the client closes its writing half, the broker
//! answers one line: `ok` or `refused: <why>`.
//!
//! **A choice to make** (`VZP1\0`, the app-id, then the command): the picker
//! in a zone sees none of the zones, and a window the zone draws is one its
//! programs could draw too — so the broker shows the launch window on the
//! host instead ([`handle_pick`], `picker::pick_for_zone`), with the asking
//! zone and the command in it. What the person chose comes back as the
//! arguments of `run`; the broker checks them against the request and starts
//! them. No question after that one: the window was the question.
//!
//! **A link to open** (`VZL1\0`, the app-id, the link, the container the
//! asking program is of — `crate::links`, [`handle_link`]): the program
//! chosen by the container's rule, else in the distribution's window of
//! choice; then the launch window as for a choice to make. The container
//! is the zone's bus filter's word for its program's connection, believed
//! from that filter alone — a child of the zone's process, which a program
//! of the zone cannot be ([`is_zones_filter`]); anyone else's is the
//! container the kernel says the asking process is of.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::{visible_entries, zone_pid};
use crate::origin::Peer;
use crate::tools::Tools;

/// The magic that starts a request.
const MAGIC: &[u8] = b"VZB1\0";
/// The magic of a choice to make ([`handle_pick`]).
const PICK_MAGIC: &[u8] = b"VZP1\0";
/// The magic of a link to open ([`handle_link`]).
const LINK_MAGIC: &[u8] = b"VZL1\0";
/// A link request's word for the zone's own programs (no container is
/// named `main`).
pub const LINK_MAIN: &str = "main";
/// The socket, below the runtime directory.
pub const SOCKET: &str = "vpn-zones/broker";
/// The largest request the broker reads: a command line, not a file.
const MAX_REQUEST: u64 = 64 * 1024;

/// The runtime directory of this user.
pub fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        // SAFETY: getuid(2) cannot fail.
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })))
}

/// A request as bytes.
pub fn encode(app_id: &[u8], argv: &[OsString]) -> Vec<u8> {
    encode_with(MAGIC, app_id, argv)
}

/// A choice to make, as bytes: the app-id and the command.
pub fn encode_pick(app_id: &[u8], cmd: &[OsString]) -> Vec<u8> {
    encode_with(PICK_MAGIC, app_id, cmd)
}

fn encode_with(magic: &[u8], app_id: &[u8], argv: &[OsString]) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(app_id);
    out.push(0);
    for arg in argv {
        out.extend_from_slice(arg.as_bytes());
        out.push(0);
    }
    out
}

/// A request from bytes: `(app_id, argv)`.
pub fn decode(bytes: &[u8]) -> Option<(OsString, Vec<OsString>)> {
    decode_with(MAGIC, bytes)
}

/// A choice to make from bytes: `(app_id, cmd)`.
pub fn decode_pick(bytes: &[u8]) -> Option<(OsString, Vec<OsString>)> {
    decode_with(PICK_MAGIC, bytes)
}

/// A link to open, as bytes: the app-id, the link, and the container the
/// asking program is of (empty: none said).
pub fn encode_link(app_id: &[u8], uri: &str, container: &str) -> Vec<u8> {
    encode_with(LINK_MAGIC, app_id, &[uri.into(), container.into()])
}

/// A link to open from bytes: `(app_id, [uri, container])`.
pub fn decode_link(bytes: &[u8]) -> Option<(OsString, Vec<OsString>)> {
    decode_with(LINK_MAGIC, bytes)
}

fn decode_with(magic: &[u8], bytes: &[u8]) -> Option<(OsString, Vec<OsString>)> {
    let rest = bytes.strip_prefix(magic)?;
    let mut parts = rest.split(|b| *b == 0);
    let app_id = OsString::from_vec(parts.next()?.to_vec());
    let mut argv: Vec<OsString> = parts.map(|p| OsString::from_vec(p.to_vec())).collect();
    // The request ends with a NUL, which leaves one empty piece behind it.
    if argv.last().is_some_and(|a| a.is_empty()) {
        argv.pop();
    }
    Some((app_id, argv))
}

/// Where a request comes from, by the kernel's word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The host's own network namespace, the broker's.
    Host,
    /// A zone of this user.
    Zone(String),
    /// A system zone (`/run/netns/vz-<name>`, root's).
    SystemZone(String),
    /// Anything else: a namespace that is none of ours, or a process gone
    /// before it could be looked at.
    Unknown,
}

impl Origin {
    /// How the journal and "always" name it; a system zone apart from a user
    /// zone of the same name.
    pub fn name(&self) -> String {
        match self {
            Origin::Host => String::new(),
            Origin::Zone(zone) => zone.clone(),
            Origin::SystemZone(zone) => format!("system:{zone}"),
            Origin::Unknown => "?".to_owned(),
        }
    }
}

/// What the broker decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Start,
    /// A person has to say yes.
    Ask,
    Refuse(String),
}

/// The policy, from where the request comes from, the network it asks for,
/// and whether the launch keeps the asker's identity — a program of a
/// container asking for that very container, or of the zone's own with no
/// container asking for none (`same_identity`, [`container_of`]).
pub fn decide(origin: &Origin, origin_locked: bool, target: &str, same_identity: bool) -> Decision {
    match origin {
        // The host never needs the broker — a launch outside a zone, or from
        // a zone with `systemd --user`, goes without it — so a request that
        // looks like the host's is refused rather than trusted (review
        // 2026-09-25: on a kernel without SO_PEERPIDFD the peer is found by
        // its number, and a number can change hands).
        Origin::Host => Decision::Refuse(
            "запрос с хоста: брокер — дверь из герметичной зоны, хосту она не нужна".to_owned(),
        ),
        // The same zone — never the host's network under that name, whatever
        // took itself for a zone called so (review 2026-09-25, third round).
        Origin::Zone(zone)
            if zone == target && !crate::launch::is_unconfined_name(target) && same_identity =>
        {
            Decision::Start
        }
        // The same zone, another identity: a person says yes — also in a
        // locked zone, which bars other networks, not other containers.
        Origin::Zone(zone) if zone == target && !crate::launch::is_unconfined_name(target) => {
            Decision::Ask
        }
        Origin::Zone(zone) if origin_locked => Decision::Refuse(format!(
            "зона «{zone}» заперта: запуск в другой сети ({target}) запрещён"
        )),
        Origin::Zone(_) | Origin::SystemZone(_) => Decision::Ask,
        Origin::Unknown => Decision::Refuse(
            "не понять, откуда запрос: не хост и не зона (или процесс уже вышел)".to_owned(),
        ),
    }
}

/// The zone whose app namespace is `netns` (`net:[…]`), if any.
fn zone_of_netns(state: &Path, netns: &Path) -> Option<String> {
    visible_entries(state).into_iter().find_map(|dir| {
        let name = dir.file_name()?.to_os_string();
        let pid = zone_pid(state, &name)?;
        (std::fs::read_link(format!("/proc/{pid}/ns/net"))
            .ok()?
            .as_path()
            == netns)
            .then(|| name.to_string_lossy().into_owned())
    })
}

/// Which of our networks the namespaces `netns` and `userns` (`net:[…]`,
/// `user:[…]`) are. The host is both of the broker's own: a process in the
/// host's network but a user namespace of its own is somebody's sandbox, not
/// the host.
fn classify(state: &Path, netns: &Path, userns: &Path) -> Origin {
    let own = |ns: &str| std::fs::read_link(format!("/proc/self/ns/{ns}")).ok();
    if own("net").as_deref() == Some(netns) {
        return if own("user").as_deref() == Some(userns) {
            Origin::Host
        } else {
            Origin::Unknown
        };
    }
    if let Some(zone) = zone_of_netns(state, netns) {
        return Origin::Zone(zone);
    }
    if let Some(zone) = crate::system::zone_of_netns(&netns.to_string_lossy()) {
        return Origin::SystemZone(zone);
    }
    Origin::Unknown
}

/// Where the peer of `stream` is, looked at while it is certainly the process
/// that connected.
fn origin_of(state: &Path, stream: &UnixStream) -> (Origin, Option<Peer>) {
    let unknown = (Origin::Unknown, None);
    let Some(peer) = Peer::of(stream.as_raw_fd()) else {
        return unknown;
    };
    // Read while it lives (`Peer::ns`): the namespaces are the peer's own.
    let (Some(netns), Some(userns)) = (peer.ns("net"), peer.ns("user")) else {
        return unknown;
    };
    (classify(state, &netns, &userns), Some(peer))
}

/// The container of `zone` the peer is a program of (`docs/PERMISSIONS.md`
/// §11.9, `crate::origin`): `Some(name)` for a program of a named container,
/// `Some("")` for one of the zone's own or of the main profile, `None` when
/// nothing is known (a throwaway or temporary container, a daemon that left
/// its launch's tree into a namespace of its own).
fn container_of(tools: &Tools, zone: &str, peer: Option<&Peer>) -> Option<String> {
    match crate::origin::of_peer(crate::origin::Places::of(tools), zone, peer?) {
        crate::origin::Who::Main => Some(String::new()),
        crate::origin::Who::Container(name) => Some(name),
        crate::origin::Who::Unknown => None,
    }
}

/// How the journal and "always" name where a request came from: the zone,
/// and the container in it when there is one (`nl/work`); `nl/?` for a
/// program of the zone whose container is not known — a throwaway one, a
/// daemon that left its launch —, which must not pass for the zone's own.
fn origin_label(origin: &Origin, container: Option<&str>) -> String {
    match (origin, container) {
        (Origin::Zone(zone), Some(c)) if !c.is_empty() => format!("{zone}/{c}"),
        (Origin::Zone(_), Some(_)) => origin.name(),
        (Origin::Zone(zone), None) => format!("{zone}/?"),
        _ => origin.name(),
    }
}

/// Is this origin known well enough for "always": a zone's own programs,
/// a container's — not a program whose container is not known.
fn may_always(label: &str) -> bool {
    !label.ends_with("/?")
}

/// The longest app-id a request may carry: a launcher's id, not a text —
/// it goes into the journal, which a flood of long ones would rotate away.
const MAX_APP_ID: usize = 255;

/// At most this many requests of one origin handled at once: a zone that
/// holds connections open must not lock the others out of the door.
const MAX_PER_ORIGIN: usize = 4;

/// Requests being handled, by origin.
static HANDLING: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// A request of `origin` being handled, for as long as this lives.
struct OriginSlot(String);

impl OriginSlot {
    fn take(origin: &str) -> Option<Self> {
        let mut handling = HANDLING.lock().ok()?;
        if handling.iter().filter(|o| *o == origin).count() >= MAX_PER_ORIGIN {
            return None;
        }
        handling.push(origin.to_owned());
        Some(Self(origin.to_owned()))
    }
}

impl Drop for OriginSlot {
    fn drop(&mut self) {
        if let Ok(mut handling) = HANDLING.lock() {
            if let Some(at) = handling.iter().position(|o| *o == self.0) {
                handling.swap_remove(at);
            }
        }
    }
}

/// The request, read whole — as long as that takes, no clock: a peer writes
/// its request as it connects, and on a loaded machine that is later, not
/// never. One that sends nothing, or a byte now and then, holds a thread and
/// one of its origin's few slots ([`MAX_PER_ORIGIN`], taken before this):
/// its own zone's requests wait behind it, nobody else's — a count bounds
/// it, where five seconds used to. `None`: it broke off. One byte past
/// `MAX_REQUEST` is read, so that a request too long is told from one
/// exactly as long.
fn read_request(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Some(bytes),
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if bytes.len() as u64 > MAX_REQUEST {
                    return Some(bytes);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
}

fn handle(tools: &Tools, mut stream: UnixStream) {
    // First, before the request is read: the peer may leave while it is.
    let (origin, peer) = origin_of(&tools.state, &stream);
    let Some(_slot) = OriginSlot::take(&origin.name()) else {
        let _ = stream.write_all(b"refused: too many requests of this zone at once\n");
        return;
    };
    let Some(bytes) = read_request(&mut stream) else {
        return;
    };
    // Longer than a request is: refused whole, never read in part.
    let oversized = if bytes.len() as u64 > MAX_REQUEST {
        Some("запрос длиннее 64 КиБ")
    } else if decode_pick(&bytes)
        .or_else(|| decode_link(&bytes))
        .or_else(|| decode(&bytes))
        .is_some_and(|(app_id, _)| app_id.len() > MAX_APP_ID)
    {
        Some("app-id длиннее 255 байт")
    } else {
        None
    };
    if let Some(why) = oversized {
        eprintln!("broker: refused: {why}");
        let _ = stream.write_all(format!("refused: {why}\n").as_bytes());
        return;
    }
    if let Some((app_id, cmd)) = decode_pick(&bytes) {
        let answer = handle_pick(tools, &origin, &app_id, &cmd);
        eprintln!("broker: {answer}");
        let _ = stream.write_all(format!("{answer}\n").as_bytes());
        return;
    }
    if let Some((_, args)) = decode_link(&bytes) {
        let answer = handle_link(tools, &origin, peer.as_ref(), &args);
        eprintln!("broker: {answer}");
        let _ = stream.write_all(format!("{answer}\n").as_bytes());
        return;
    }
    let answer = match decode(&bytes) {
        None => "refused: не запрос брокера".to_owned(),
        Some((app_id, argv)) => {
            match crate::launch::Selection::parse(&argv) {
                Err(e) => format!("refused: {e}"),
                Ok(selection) => {
                    let target = selection.zone.to_string_lossy().into_owned();
                    let locked = match &origin {
                        Origin::Zone(zone) => tools
                            .state
                            .join(zone)
                            .join(crate::launch::NO_ESCAPE)
                            .exists(),
                        _ => false,
                    };
                    // Without a question only where nothing is crossed: a
                    // program of a container asking for a launch in that very
                    // container, in the same zone — or, with no container, one
                    // with none. Into another container, or out of one into
                    // the real home, is a crossing (docs/PERMISSIONS.md
                    // §11.9). The container asked for as `run` will resolve
                    // it, making nothing; the origin's as the kernel says.
                    let origin_container = match &origin {
                        Origin::Zone(zone) => container_of(tools, zone, peer.as_ref()),
                        _ => None,
                    };
                    // The container asked for as `run` will resolve it,
                    // making nothing — only where it can make a difference:
                    // a known container of a zone asking in that zone.
                    let resolved = match &origin {
                        Origin::Zone(zone) if *zone == target => {
                            Some(crate::launch::resolve_selection(tools, selection.clone()))
                        }
                        _ => None,
                    };
                    let asked_container = match &resolved {
                        Some(Ok(resolved)) => match crate::launch::container_name(resolved) {
                            Some(name) => Some(name),
                            None if selection_selector(resolved).is_empty() => Some(String::new()),
                            None => None,
                        },
                        _ => None,
                    };
                    let same_identity =
                        origin_container.is_some() && origin_container == asked_container;
                    let label = origin_label(&origin, origin_container.as_deref());
                    let allowed = match decide(&origin, locked, &target, same_identity) {
                        Decision::Start => Ok(()),
                        Decision::Refuse(why) => Err(why),
                        // Asked about the container the launch will really
                        // be in — `--sandbox work` is `work-sb` when a layer
                        // has the name —, and "always" kept for that one and
                        // its kind of home: resolved here the way `run` will,
                        // making nothing (`launch::resolve_selection`).
                        Decision::Ask => {
                            let resolved = match resolved {
                                Some(resolved) => resolved,
                                None => crate::launch::resolve_selection(tools, selection.clone()),
                            };
                            match resolved {
                                Err(why) => Err(why),
                                Ok(resolved) => ask(
                                    tools,
                                    &origin,
                                    &label,
                                    &target,
                                    &resolved_selector(tools, &resolved),
                                    &selection.cmd,
                                ),
                            }
                        }
                    };
                    // A launch that goes on without a question takes no word of
                    // the requester's about what it is: the policies kept by a
                    // program's id (the proxy, the frame) are the command's.
                    let started_id = if same_identity {
                        OsString::new()
                    } else {
                        app_id.clone()
                    };
                    let answer = match &allowed {
                        Ok(()) => start(&started_id, &argv, same_identity),
                        Err(why) => format!("refused: {why}"),
                    };
                    // Every crossing the broker decides, either way, on the
                    // record: which zone asked, for what, and what came of it.
                    let why = answer.strip_prefix("refused: ").unwrap_or("");
                    let decision = if answer == "ok" { "started" } else { "refused" };
                    if !may_journal(&origin.name()) {
                        eprintln!("broker: journal: too many lines of this zone — {decision}");
                    } else if let Err(e) = crate::journal::append(
                        &tools.state,
                        "broker",
                        &[
                            ("origin", label.as_str()),
                            ("target", target.as_str()),
                            ("app", &*app_id.to_string_lossy()),
                            ("decision", decision),
                            ("why", why),
                        ],
                    ) {
                        eprintln!("broker: journal: {e}");
                    }
                    answer
                }
            }
        }
    };
    eprintln!("broker: {answer}");
    let _ = stream.write_all(format!("{answer}\n").as_bytes());
}

/// What "always" is remembered in: one `origin\ttarget\tprogram` per line,
/// below the config directory.
pub const ALWAYS: &str = "broker-always";

/// The program a launch runs, as the host resolves it: the first word of the
/// command, looked up in `PATH` if it is a bare name, its directory's links
/// followed and its own name kept — `touch` and `cat` are links to one
/// coreutils binary, and "always" for one must not be "always" for all.
pub fn program_of(cmd: &[OsString]) -> Option<PathBuf> {
    let first = Path::new(cmd.first()?);
    let path = if first.components().count() > 1 {
        first.to_path_buf()
    } else {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .map(|dir| dir.join(first))
            .find(|p| p.is_file())?
    };
    let dir = std::fs::canonicalize(path.parent()?).ok()?;
    Some(dir.join(path.file_name()?))
}

/// Whether "always" may be offered for this program: only for one in the
/// store — the name and the file it finally is — where nothing in a zone can
/// write. A program named by a path the user, or a program in a zone with the
/// home in reach, could replace (`~/.local/bin/…`) would make "always" a
/// standing door for whatever is put there next.
///
/// Nor for a program that runs whatever it is told: "always" for `sh`, `env`
/// or `python3` would be "always" for any command at all behind them.
pub fn may_remember(program: &Path) -> bool {
    program.starts_with("/nix/store/")
        && std::fs::canonicalize(program).is_ok_and(|real| real.starts_with("/nix/store/"))
        && !program
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(runs_anything)
}

/// Shells, interpreters and wrappers that run a command given to them.
pub fn runs_anything(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "sh",
        "bash",
        "dash",
        "zsh",
        "fish",
        "ksh",
        "mksh",
        "tcsh",
        "csh",
        "nu",
        "xonsh",
        "env",
        "busybox",
        "toybox",
        "xargs",
        "nohup",
        "setsid",
        "timeout",
        "nice",
        "ionice",
        "chrt",
        "taskset",
        "stdbuf",
        "time",
        "script",
        "expect",
        "sudo",
        "doas",
        "pkexec",
        "su",
        "runuser",
        "systemd-run",
        "flatpak-spawn",
        "dbus-send",
        "gdbus",
        "busctl",
        "awk",
        "gawk",
        "mawk",
        "sed",
        "find",
        "make",
        "vim",
        "nvim",
        "emacs",
        // Our own command under every name it has: `run` takes any command.
        "cellward",
        "cw",
        "vpn-zone",
        "vpn-zone-pick",
        "nix",
        "nix-shell",
        "nix-env",
        "nix-build",
    ];
    const PREFIXES: &[&str] = &[
        "python", "perl", "ruby", "node", "lua", "php", "tclsh", "wish",
    ];
    EXACT.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p))
}

/// How many words a command in a question may have: every one is shown.
const SHOWN_WORDS: usize = 24;
/// How much of one word is shown — its beginning, which says what it is: an
/// option is a word of its own, and a word cut short says how much is left.
const SHOWN_WORD: usize = 300;

/// A command as it may be shown in a question: one word a line, so that none
/// hides in another; no control characters, no angle brackets for the dialog
/// to take for markup, none of the invisible ones that reorder text. `None`
/// for a command too long to show whole — it is not asked about (review
/// 2026-09-25, third round: a cut at 600 characters could leave an option
/// behind the "…").
pub fn shown_command(cmd: &[OsString]) -> Option<String> {
    shown_words(cmd).map(|words| words.join("\n"))
}

/// [`shown_command`] a word each — an empty word too, said so, since it is
/// an argument all the same.
pub fn shown_words(cmd: &[OsString]) -> Option<Vec<String>> {
    if cmd.len() > SHOWN_WORDS {
        return None;
    }
    Some(
        cmd.iter()
            .map(|word| {
                let clean = shown_word(&word.to_string_lossy());
                let n = clean.chars().count();
                if n == 0 {
                    "(пустой аргумент)".to_owned()
                } else if n > SHOWN_WORD {
                    let head: String = clean.chars().take(SHOWN_WORD).collect();
                    format!("{head}… (ещё {} симв.)", n - SHOWN_WORD)
                } else {
                    clean
                }
            })
            .collect(),
    )
}

/// One word a program chose, fit for a dialog's text: no control characters
/// (a line break would start a line of its own), no angle brackets for the
/// dialog to take for markup (kdialog shows text that looks like HTML as
/// HTML), none of the invisible ones that reorder or hide text. Not cut: the
/// caller decides how much of it is shown.
pub fn shown_word(word: &str) -> String {
    word.chars()
        .filter(|c| !crate::focus::reorders(*c))
        .map(|c| match c {
            '<' => '‹',
            '>' => '›',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

/// No option among the words after the program: "always" is for a program,
/// and an option can make it run something else (a browser's helper, a
/// player's script, git's `-c`).
fn plain_arguments(cmd: &[OsString]) -> bool {
    cmd.iter()
        .skip(1)
        .all(|a| !a.to_string_lossy().starts_with('-'))
}

/// The line "always" writes, and looks for.
pub fn always_line(origin: &str, target: &str, program: &Path) -> String {
    format!("{origin}\t{target}\t{}", program.display())
}

fn remembered(tools: &Tools, line: &str) -> bool {
    std::fs::read_to_string(tools.config.join(ALWAYS))
        .is_ok_and(|text| text.lines().any(|l| l == line))
}

fn remember(tools: &Tools, line: &str) {
    let path = tools.config.join(ALWAYS);
    let _ = std::fs::create_dir_all(&tools.config);
    let appended = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| writeln!(f, "{line}"));
    if let Err(e) = appended {
        eprintln!("broker: cannot remember in {}: {e}", path.display());
    }
}

/// The container a request asks for, as a selector (a container's name,
/// `__fs__`, `__tmp__`, empty for the main one), as it was asked: what the
/// no-question path looks at — empty is the main profile and nothing else.
pub fn selection_selector(selection: &crate::launch::Selection) -> String {
    use crate::launch::{Container, Sandbox};
    match (&selection.sandbox, &selection.container) {
        (Sandbox::Named(name), _) => name.to_string_lossy().into_owned(),
        (Sandbox::Throwaway, _) => "__fs__".to_owned(),
        (Sandbox::None, Container::Named(name) | Container::MainNamed(name)) => {
            name.to_string_lossy().into_owned()
        }
        (Sandbox::None, Container::TmpNew | Container::TmpJoin(_)) => "__tmp__".to_owned(),
        (Sandbox::None, Container::Main) => String::new(),
    }
}

/// A resolved request's container for the question and for "always": its
/// name and its kind of home (`work@private`) — a change of kind is not the
/// container "always" was said for. The rest as [`selection_selector`].
fn resolved_selector(tools: &Tools, selection: &crate::launch::Selection) -> String {
    match crate::launch::container_name(selection) {
        Some(name) => {
            let home = crate::container::load(tools, &name)
                .map_or(crate::container::Home::Private, |c| c.home);
            format!("{name}@{}", home.setting())
        }
        None => selection_selector(selection),
    }
}

fn ask(
    tools: &Tools,
    origin: &Origin,
    label: &str,
    target: &str,
    selector: &str,
    cmd: &[OsString],
) -> Result<(), String> {
    // Asked before, and "always" said: the same zone, the same network, the
    // same container, the very same program from the store.
    let program = program_of(cmd)
        .filter(|p| may_remember(p))
        .filter(|_| plain_arguments(cmd))
        .filter(|_| may_always(label));
    let target_and_container = if selector.is_empty() {
        target.to_owned()
    } else {
        format!("{target}\t{selector}")
    };
    let line = program
        .as_ref()
        .map(|p| always_line(label, &target_and_container, p));
    if line.as_ref().is_some_and(|l| remembered(tools, l)) {
        return Ok(());
    }
    if !crate::launch::has_display() {
        return Err("спросить некого (нет графической сессии)".to_owned());
    }
    // One question at a time: a stream of them is how a "yes" is got by
    // accident. The next request while one is open is refused, not queued.
    let Ok(_asking) = ASKING.try_lock() else {
        return Err("уже открыт другой вопрос о запуске".to_owned());
    };
    begin_asking(&origin.name())?;
    let network = if target == crate::launch::UNCONFINED {
        "без ограничений (сеть хоста, без VPN и без изоляции зоны)".to_owned()
    } else {
        format!("сети «{target}»")
    };
    let asker = match origin {
        Origin::SystemZone(zone) => format!("системной зоны «{zone}»"),
        Origin::Zone(zone) => match label.split_once('/') {
            Some((_, "?")) => format!("зоны «{zone}», контейнер не опознан"),
            Some((_, container)) => format!(
                "контейнера «{}» (сеть «{zone}»)",
                crate::picker::container_label_in(tools, container)
            ),
            None => format!("зоны «{zone}»"),
        },
        other => format!("зоны «{}»", other.name()),
    };
    // The kind is after the LAST `@`: a name may have one of its own.
    let container = match selector.rsplit_once('@') {
        Some((name, _)) => crate::picker::container_label_in(tools, name),
        None => crate::picker::container_label_in(tools, selector),
    };
    let Some(shown) = shown_command(cmd) else {
        return Err(format!(
            "команда длиннее {SHOWN_WORDS} слов — целиком её не показать, а не целиком не спрашивают"
        ));
    };
    let question = format!(
        "Программа из {asker} просит запустить в {network}, контейнер: {container}:\n\n{shown}\n\nРазрешить?"
    );
    // A "yes" sooner than the question can be read is a key meant for
    // something else: the dialog takes the focus, and its default allows
    // (`dialog::TOO_FAST`).
    let asked = std::time::Instant::now();
    // "Always" only where it can be kept safely (`may_remember`).
    let Some(line) = line else {
        return if crate::dialog::choose_within(
            &tools.kdialog,
            [
                "--title",
                "Запуск из зоны",
                "--warningcontinuecancel",
                question.as_str(),
            ],
            question_timeout(tools),
        ) == Some(0)
        {
            crate::dialog::not_too_soon(asked)
        } else {
            answered_no(&origin.name());
            Err("человек отказал".to_owned())
        };
    };
    match crate::dialog::choose_within(
        &tools.kdialog,
        [
            "--title",
            "Запуск из зоны",
            "--yes-label",
            "Разрешить",
            "--no-label",
            "Всегда",
            "--cancel-label",
            "Отказать",
            "--warningyesnocancel",
            question.as_str(),
        ],
        question_timeout(tools),
    ) {
        Some(0) => crate::dialog::not_too_soon(asked),
        Some(1) => {
            crate::dialog::not_too_soon(asked)?;
            remember(tools, &line);
            Ok(())
        }
        _ => {
            answered_no(&origin.name());
            Err("человек отказал".to_owned())
        }
    }
}

/// How long a question waits for its answer: past it the window or dialog
/// is closed, and the request refused. The person's setting
/// (`cellward question-timeout`, `crate::timings::QUESTION`; 2 minutes
/// unless set); `None`, never: the question waits for its answer, and the
/// next ones are refused meanwhile ([`ASKING`]).
fn question_timeout(tools: &Tools) -> Option<std::time::Duration> {
    crate::timings::QUESTION.read(&tools.config).0.duration()
}

/// One question at a time, a window or a dialog: a stream of them is how a
/// "yes" is got by accident. The next request while one is open is refused,
/// not queued.
static ASKING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Lines each origin put into the journal lately.
static JOURNALED: std::sync::Mutex<Vec<(String, std::time::Instant)>> =
    std::sync::Mutex::new(Vec::new());

/// At most this many journal lines of one origin a minute: the journal is
/// the record of crossings, and a zone's stream of cheap requests must not
/// rotate it away. What is over is said on stderr only.
const JOURNAL_PER_MINUTE: usize = 30;

/// Whether `origin` may write one more journal line now.
fn may_journal(origin: &str) -> bool {
    let Ok(mut lines) = JOURNALED.lock() else {
        return false;
    };
    let now = std::time::Instant::now();
    lines.retain(|(_, at)| now.duration_since(*at) < ASK_WINDOW);
    if lines.iter().filter(|(o, _)| o == origin).count() >= JOURNAL_PER_MINUTE {
        return false;
    }
    lines.push((origin.to_owned(), now));
    true
}

/// The questions put to the person lately: `(origin, when, refused)`.
static ASKED: std::sync::Mutex<Vec<(String, std::time::Instant, bool)>> =
    std::sync::Mutex::new(Vec::new());

/// At most this many questions for one origin within [`ASK_WINDOW`]: a zone
/// that asks again the moment it is answered takes the keyboard away from
/// the session and makes a "yes" by accident likelier with every question.
const ASKS_PER_WINDOW: usize = 4;
const ASK_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// After the person said no (or closed the window), that origin is not asked
/// again for this long.
const AFTER_NO: std::time::Duration = std::time::Duration::from_secs(15);

/// Whether `origin` may be asked now ([`ASKS_PER_WINDOW`], [`AFTER_NO`]).
pub fn may_ask_now(
    asked: &[(String, std::time::Instant, bool)],
    origin: &str,
    now: std::time::Instant,
) -> Result<(), String> {
    let recent: Vec<_> = asked
        .iter()
        .filter(|(o, at, _)| o == origin && now.duration_since(*at) < ASK_WINDOW)
        .collect();
    if recent.len() >= ASKS_PER_WINDOW {
        return Err(format!(
            "зона спрашивает слишком часто: не больше {ASKS_PER_WINDOW} вопросов в минуту"
        ));
    }
    if recent
        .iter()
        .any(|(_, at, refused)| *refused && now.duration_since(*at) < AFTER_NO)
    {
        return Err("человек только что отказал этой зоне".to_owned());
    }
    Ok(())
}

/// [`may_ask_now`] against the record, and the question put on it.
fn begin_asking(origin: &str) -> Result<(), String> {
    let mut asked = ASKED
        .lock()
        .map_err(|_| "учёт вопросов сломан".to_owned())?;
    let now = std::time::Instant::now();
    asked.retain(|(_, at, _)| now.duration_since(*at) < ASK_WINDOW);
    may_ask_now(&asked, origin, now)?;
    asked.push((origin.to_owned(), now, false));
    Ok(())
}

/// [`ASKING`] held and a question to `origin` begun: one at a time, and
/// counted ([`begin_asking`]).
fn start_asking(origin: &str) -> Result<std::sync::MutexGuard<'static, ()>, String> {
    let guard = ASKING
        .try_lock()
        .map_err(|_| "уже открыт другой вопрос о запуске".to_owned())?;
    begin_asking(origin)?;
    Ok(guard)
}

/// The last question put to `origin` was answered no.
fn answered_no(origin: &str) {
    if let Ok(mut asked) = ASKED.lock() {
        if let Some(last) = asked.iter_mut().rev().find(|(o, _, _)| o == origin) {
            last.1 = std::time::Instant::now();
            last.2 = true;
        }
    }
}

/// Our own binary, from the store — never the manifest's runner, a link in
/// the profile a program with the home could point elsewhere (review
/// 2026-09-25).
fn own_binary() -> Result<PathBuf, String> {
    match std::env::current_exe() {
        Ok(exe) if exe.starts_with("/nix/store/") => Ok(exe),
        Ok(exe) => Err(format!("{} is not in the store", exe.display())),
        Err(e) => Err(format!("cannot find our own binary: {e}")),
    }
}

/// A choice to make for a program in a zone: the launch window on the host
/// (`picker::pick_for_zone`), then what the person chose, checked and
/// started. From the host or from nowhere known: refused, as a request is.
/// A locked zone is offered only itself, and anything else coming back is
/// refused here again. The answer must be the request's own command, word
/// for word — the window chooses where, never what — and it must not come
/// sooner than a person could have read the window (`dialog::TOO_FAST`).
fn handle_pick(tools: &Tools, origin: &Origin, app_id: &OsString, cmd: &[OsString]) -> String {
    let (zone, locked) = match origin {
        Origin::Zone(zone) => (
            zone.clone(),
            tools
                .state
                .join(zone)
                .join(crate::launch::NO_ESCAPE)
                .exists(),
        ),
        Origin::SystemZone(_) => (origin.name(), false),
        Origin::Host => {
            return "refused: запрос с хоста: брокер — дверь из зоны, хосту она не нужна".to_owned()
        }
        Origin::Unknown => {
            return "refused: не понять, откуда запрос: не хост и не зона (или процесс уже вышел)"
                .to_owned()
        }
    };
    let result = pick_and_check(
        &zone,
        locked,
        app_id,
        cmd,
        &origin.name(),
        question_timeout(tools),
    );
    let (answer, target) = match result {
        Ok(argv) => {
            let target = argv
                .first()
                .map(|z| z.to_string_lossy().into_owned())
                .unwrap_or_default();
            (start(app_id, &argv, false), target)
        }
        Err(why) => (format!("refused: {why}"), String::new()),
    };
    let why = answer.strip_prefix("refused: ").unwrap_or("");
    let decision = if answer == "ok" { "started" } else { "refused" };
    if !may_journal(&origin.name()) {
        eprintln!("broker: journal: too many lines of this zone — {decision}");
    } else if let Err(e) = crate::journal::append(
        &tools.state,
        "broker",
        &[
            ("origin", origin.name().as_str()),
            ("target", target.as_str()),
            ("app", &*app_id.to_string_lossy()),
            ("decision", decision),
            ("why", why),
        ],
    ) {
        eprintln!("broker: journal: {e}");
    }
    answer
}

/// The window, and its answer as the arguments of `run`, checked.
fn pick_and_check(
    zone: &str,
    locked: bool,
    app_id: &OsString,
    cmd: &[OsString],
    origin: &str,
    timeout: Option<std::time::Duration>,
) -> Result<Vec<OsString>, String> {
    let cmd = host_command(cmd)?;
    let Ok(_asking) = ASKING.try_lock() else {
        return Err("уже открыт другой вопрос о запуске".to_owned());
    };
    begin_asking(origin)?;
    ask_window(zone, locked, app_id, &cmd, origin, None, timeout).map(|(argv, _)| argv)
}

/// The command a zone asks for as the host runs it: shown whole, someone to
/// ask, and its program as the host finds it, once — what the window shows
/// is what runs: `run` finds nothing again by PATH, where a link in the
/// home could have been pointed elsewhere while the window was open.
fn host_command(cmd: &[OsString]) -> Result<Vec<OsString>, String> {
    if cmd.is_empty() {
        return Err("нечего запускать".to_owned());
    }
    if shown_command(cmd).is_none() {
        return Err(format!(
            "команда длиннее {SHOWN_WORDS} слов — целиком её не показать, а не целиком не спрашивают"
        ));
    }
    if !crate::launch::has_display() {
        return Err("спросить некого (нет графической сессии)".to_owned());
    }
    // The program as the host finds it, once: what the window shows is what
    // runs — `run` finds nothing again by PATH, where a link in the home
    // could have been pointed elsewhere while the window was open.
    let program = program_of(cmd).ok_or_else(|| {
        format!(
            "программы «{}» на хосте нет",
            shown_word(&cmd[0].to_string_lossy())
        )
    })?;
    Ok(std::iter::once(program.into_os_string())
        .chain(cmd[1..].iter().cloned())
        .collect())
}

/// The launch window for a zone's `cmd` ([`host_command`]'s), and its answer
/// checked: the arguments of `run`, and whether the offered rule was
/// ticked. The caller holds [`ASKING`] and has begun asking.
fn ask_window(
    zone: &str,
    locked: bool,
    app_id: &OsString,
    cmd: &[OsString],
    origin: &str,
    offer_rule: Option<&str>,
    timeout: Option<std::time::Duration>,
) -> Result<(Vec<OsString>, bool), String> {
    let exe = own_binary()?;
    let picker = exe.with_file_name("vpn-zone-pick");
    let mut command = Command::new(&picker);
    command.arg("--from-zone").arg(zone);
    if locked {
        command.arg("--locked");
    }
    if let Some(rule) = offer_rule {
        command.arg("--offer-rule").arg(rule);
    }
    command
        .arg("--id")
        .arg(app_id)
        .arg("--")
        .args(cmd)
        .env_remove(crate::launch::ENV_CURRENT)
        .env_remove(crate::launch::ENV_DELEGATED)
        .env_remove("VPN_ZONE_ASK")
        .env_remove("VPN_ZONE_PROFILE")
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_FDNAMES")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let asked = std::time::Instant::now();
    let mut child = command
        .spawn()
        .map_err(|e| format!("не открыть окно запуска ({}): {e}", picker.display()))?;
    // An answer by the person's deadline (`question_timeout`): a window left
    // open keeps every other zone's question out. None set: as long as it
    // takes.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if timeout.is_none_or(|t| asked.elapsed() < t) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                answered_no(origin);
                return Err("на окно не ответили".to_owned());
            }
        }
    };
    if !status.success() {
        answered_no(origin);
        return Err("человек отказал".to_owned());
    }
    crate::dialog::not_too_soon(asked)?;
    let mut stdout = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_end(&mut stdout);
    }
    let mut argv: Vec<OsString> = stdout
        .split(|b| *b == 0)
        .map(|w| OsString::from_vec(w.to_vec()))
        .collect();
    // Every word ends with a NUL, which leaves one empty piece behind.
    if argv.last().is_some_and(|a| a.is_empty()) {
        argv.pop();
    }
    // The rule offered and ticked: said first.
    let rule = offer_rule.is_some() && argv.first().is_some_and(|w| w == "--rule");
    if rule {
        argv.remove(0);
    }
    check_pick(&argv, zone, locked, cmd)?;
    Ok((argv, rule))
}

/// Whether the asking process is the zone's own bus filter: a child of the
/// zone's process (`zone.pid`) — which a program of the zone cannot be: it
/// comes in from the host (`nsenter`), and an orphan goes to the host's
/// reaper, never to the zone's process. Read while the process is held.
fn is_zones_filter(tools: &Tools, zone: &str, peer: Option<&Peer>) -> bool {
    let (Some(peer), Some(zone_pid)) = (peer, zone_pid(&tools.state, std::ffi::OsStr::new(zone)))
    else {
        return false;
    };
    crate::sys::ancestors(peer.pid, &peer.pidfd).get(1) == Some(&zone_pid) && peer.alive()
}

/// A link a program of a zone opens (`crate::links`): the program — the
/// container's rule, else the distribution's window of choice —, then the
/// launch window, as for [`handle_pick`], with the rule offered where the
/// container is known and has none for this scheme.
fn handle_link(tools: &Tools, origin: &Origin, peer: Option<&Peer>, args: &[OsString]) -> String {
    let answer = link_answer(tools, origin, peer, args);
    let decision = if answer.0 == "ok" {
        "started"
    } else {
        "refused"
    };
    let why = answer.0.strip_prefix("refused: ").unwrap_or("");
    if !may_journal(&origin.name()) {
        eprintln!("broker: journal: too many lines of this zone — {decision}");
    } else if let Err(e) = crate::journal::append(
        &tools.state,
        "broker",
        &[
            ("origin", origin.name().as_str()),
            ("target", answer.1.as_str()),
            ("app", answer.2.as_str()),
            ("link", answer.3.as_str()),
            ("container", answer.4.as_str()),
            ("decision", decision),
            ("why", why),
        ],
    ) {
        eprintln!("broker: journal: {e}");
    }
    answer.0
}

/// Who asked for a link to be opened.
enum Asker {
    /// A program of the zone's own, with no container.
    Main,
    /// A program of this container.
    Container(Box<crate::container::Container>),
    /// Not known: no rule, and never started without the window.
    Unknown,
}

/// The answer a link from outside a zone gets: the asking filter opens it
/// itself, as before (a sandbox on the host).
pub const NOT_A_ZONE: &str = "refused: not a zone";

/// [`handle_link`]'s work: the answer, the network it went to, the program,
/// the link as the log may show it, and whose program asked (`main`, a
/// container, `?`).
fn link_answer(
    tools: &Tools,
    origin: &Origin,
    peer: Option<&Peer>,
    args: &[OsString],
) -> (String, String, String, String, String) {
    let refused = |why: String, shown: &str| {
        (
            format!("refused: {why}"),
            String::new(),
            String::new(),
            shown.to_owned(),
            String::new(),
        )
    };
    // A zone's program only: a sandbox on the host opens its links itself.
    let Origin::Zone(zone) = origin else {
        let nothing = String::new;
        return (
            NOT_A_ZONE.to_owned(),
            nothing(),
            nothing(),
            nothing(),
            nothing(),
        );
    };
    let zone = zone.as_str();
    let Some(uri) = args.first().and_then(|u| u.to_str()) else {
        return refused("нет ссылки".to_owned(), "");
    };
    let shown = crate::bus_filter::loggable(uri);
    if let Err(why) = crate::bus_filter::acceptable(uri) {
        return refused(format!("ссылка не принята: {why}"), &shown);
    }
    let Some(scheme) = crate::links::scheme_of(uri) else {
        return refused("у ссылки нет схемы".to_owned(), &shown);
    };
    // Whose program asks: the zone's filter's word from that filter alone
    // (`main`: the zone's own; a container's name; nothing: not known),
    // anyone else's container as the kernel says.
    let word = match args.get(1).and_then(|c| c.to_str()) {
        Some(c) if is_zones_filter(tools, zone, peer) => Some(c.to_owned()),
        _ => container_of(tools, zone, peer).map(|c| {
            if c.is_empty() {
                LINK_MAIN.to_owned()
            } else {
                c
            }
        }),
    };
    let asker = match word.as_deref() {
        Some(LINK_MAIN) => Asker::Main,
        Some(name) if !name.is_empty() => crate::container::load(tools, name)
            .map_or(Asker::Unknown, |c| Asker::Container(Box::new(c))),
        _ => Asker::Unknown,
    };
    let who = match &asker {
        Asker::Main => LINK_MAIN.to_owned(),
        Asker::Container(c) => c.name.clone(),
        Asker::Unknown => "?".to_owned(),
    };
    let refused = |why: String, shown: &str| {
        let (a, t, p, l, _) = refused(why, shown);
        (a, t, p, l, who.clone())
    };
    // One question at a time, and counted — taken where the person is
    // asked, once for both windows: the choice of a program is a question
    // as the launch window is; a zone that asks without end is not asked,
    // and a no holds it off for a while.
    let mut asking: Option<std::sync::MutexGuard<'static, ()>> = None;
    let dirs = crate::desktop::source_dirs(&tools.home);
    let entry_of = |id: &str| {
        crate::desktop::find_entry(&dirs, &tools.home, &tools.state, id)
            .filter(|(_, groups)| crate::desktop::desktop_entry(groups).is_some())
    };
    // The container's rule, where its program is still there.
    let ruled = match &asker {
        Asker::Container(c) => crate::links::rule(c, &scheme).filter(|id| entry_of(id).is_some()),
        _ => None,
    };
    let id = match &ruled {
        Some(id) => id.clone(),
        None => {
            let default =
                crate::links::distro_default(&crate::links::mimeapps_files(&tools.home), &scheme);
            let programs = crate::links::programs_for(
                &dirs,
                &tools.home,
                &tools.state,
                &scheme,
                default.as_deref(),
            );
            // One program for such links: nothing to choose, as on a phone.
            if let [only] = programs.as_slice() {
                only.id.clone()
            } else {
                if !crate::launch::has_display() {
                    return refused(
                        "спросить некого (нет графической сессии)".to_owned(),
                        &shown,
                    );
                }
                match start_asking(&origin.name()) {
                    Ok(guard) => asking = Some(guard),
                    Err(why) => return refused(why, &shown),
                }
                match crate::links::choose(&tools.busctl, &tools.kdialog, &scheme, uri, &programs) {
                    crate::links::Choice::Chosen(id) => id,
                    crate::links::Choice::Cancelled => {
                        answered_no(&origin.name());
                        return refused("программу не выбрали".to_owned(), &shown);
                    }
                    crate::links::Choice::Unavailable(why) => return refused(why, &shown),
                }
            }
        }
    };
    let Some((file, groups)) = entry_of(&id) else {
        return refused(format!("ярлыка {id} нет"), &shown);
    };
    let Some(entry) = crate::desktop::desktop_entry(&groups) else {
        return refused(format!("{id} — не ярлык программы"), &shown);
    };
    let (cmd, used) = crate::desktop::expand_exec(entry, &file, &[OsString::from(uri)]);
    if cmd.is_empty() || !used {
        return refused(format!("{id} не принимает ссылок"), &shown);
    }
    let name = entry
        .get("Name")
        .filter(|n| !n.is_empty())
        .unwrap_or(&id)
        .to_owned();
    let app_id = OsString::from(crate::desktop::stable_key(&id));
    // An entry CellWard does not take over (a symlink of the user's, of
    // home-manager's, any entry where sync takes none over): run where the
    // link was asked for — in the zone, in the asking program's own
    // container —, as `xdg-open` there would run it; no network is crossed.
    // A program of no container known (a throwaway sandbox's) gets the
    // zone's own, where `xdg-open` in the zone ran it before.
    if !crate::desktop::intercepted(&tools.home, &id) {
        let mut argv: Vec<OsString> = vec![zone.into()];
        if let Asker::Container(c) = &asker {
            argv.push("--container".into());
            argv.push(c.name.clone().into());
        }
        argv.push("--".into());
        argv.extend(cmd);
        return (start(&app_id, &argv, true), zone.to_owned(), id, shown, who);
    }
    let locked = tools
        .state
        .join(zone)
        .join(crate::launch::NO_ESCAPE)
        .exists();
    // "Always", per container and only where it is known: the program kept
    // for this scheme — the choice of it skipped next time, the window not.
    let offer = match (&asker, &ruled) {
        (Asker::Container(c), None) => Some(format!(
            "Всегда открывать ссылки {scheme}: из контейнера {} в {name}",
            c.name
        )),
        _ => None,
    };
    // Held to the end: the window's answer is started under it.
    let _asking = match asking {
        Some(guard) => guard,
        None => match start_asking(&origin.name()) {
            Ok(guard) => guard,
            Err(why) => return refused(why, &shown),
        },
    };
    let chosen = host_command(&cmd).and_then(|cmd| {
        ask_window(
            zone,
            locked,
            &app_id,
            &cmd,
            &origin.name(),
            offer.as_deref(),
            question_timeout(tools),
        )
    });
    let (argv, keep) = match chosen {
        Ok(chosen) => chosen,
        Err(why) => return refused(why, &shown),
    };
    let target = argv
        .first()
        .map(|z| z.to_string_lossy().into_owned())
        .unwrap_or_default();
    if keep {
        if let Asker::Container(c) = &asker {
            if let Err(e) = crate::container::set_link(tools, &c.name, &scheme, Some(&id)) {
                eprintln!(
                    "broker: the rule for {scheme} links of {} not kept: {e}",
                    c.name
                );
            }
        }
    }
    (start(&app_id, &argv, false), target, id, shown, who)
}

/// What the window chose, against the request: the arguments of `run`, with
/// the very command asked for and, from a locked zone, that zone.
pub fn check_pick(
    argv: &[OsString],
    zone: &str,
    locked: bool,
    cmd: &[OsString],
) -> Result<(), String> {
    let selection =
        crate::launch::Selection::parse(argv).map_err(|e| format!("окно ответило не так: {e}"))?;
    if selection.cmd != cmd {
        return Err("окно ответило другой командой".to_owned());
    }
    if locked && selection.zone.as_os_str() != std::ffi::OsStr::new(zone) {
        return Err(format!(
            "зона «{zone}» заперта: запуск в другой сети запрещён"
        ));
    }
    Ok(())
}

/// `unasked`: started without a question — the program's name relaxes
/// nothing (`launch::ENV_UNASKED`).
fn start(app_id: &OsString, argv: &[OsString], unasked: bool) -> String {
    // Our own binary, from the store — not the manifest's runner, a profile
    // path: in a standalone home-manager that is `~/.nix-profile`, a link a
    // program with the home could point elsewhere, and the broker would run
    // its binary on the host at once (review 2026-09-25). The manifest is the
    // one this process runs with (VPN_ZONE_TOOLS, set by the wrapper).
    let exe = match own_binary() {
        Ok(exe) => exe,
        Err(why) => return format!("refused: {why}"),
    };
    let mut command = Command::new(exe);
    command
        .arg("run")
        .args(argv)
        .env(crate::launch::ENV_DELEGATED, "1")
        .env_remove(crate::launch::ENV_CURRENT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !app_id.is_empty() {
        command.env(crate::launch::ENV_APPID, app_id);
    }
    if unasked {
        command.env(crate::launch::ENV_UNASKED, "1");
    } else {
        command.env_remove(crate::launch::ENV_UNASKED);
    }
    match command.spawn() {
        Ok(mut child) => {
            // Reaped in the background: the program may run for days.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            "ok".to_owned()
        }
        Err(e) => format!("refused: не запустить vpn-zone: {e}"),
    }
}

/// `vpn-zone _broker`: listen and answer, forever. Normally the socket is
/// systemd's (`vpn-zone-broker.socket`) and handed over at fd 3 — it exists
/// from the moment the user manager or a zone wants it, whether or not this
/// has been started (red in CI: the service, wanted by `default.target`, was
/// never started when home-manager put its unit in place after the manager
/// had reached that target). Run by hand, it listens by itself.
pub fn serve(tools: &Tools) -> u8 {
    let passed = crate::dnsfwd::listen_fds(
        &std::env::var("LISTEN_PID").unwrap_or_default(),
        &std::env::var("LISTEN_FDS").unwrap_or_default(),
        std::process::id(),
    );
    // What systemd passed is ours, and no program the broker starts may
    // inherit it: holding the listening socket, a program started into its own
    // zone (no question for that) would take every other zone's requests —
    // their commands and links — and answer them itself (review 2026-09-25).
    for var in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        std::env::remove_var(var);
    }
    if passed >= 1 {
        use std::os::fd::FromRawFd;
        // SAFETY: fcntl on a descriptor number; harmless if it is not open.
        unsafe { libc::fcntl(3, libc::F_SETFD, libc::FD_CLOEXEC) };
        // SAFETY: systemd passed this descriptor to us to own.
        let listener = unsafe { UnixListener::from_raw_fd(3) };
        eprintln!("broker: listening on the socket systemd passed");
        return accept_forever(tools, &listener);
    }
    let socket = runtime_dir().join(SOCKET);
    if let Some(dir) = socket.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("broker: cannot create {}: {e}", dir.display());
            return 1;
        }
    }
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("broker: cannot listen on {}: {e}", socket.display());
            return 1;
        }
    };
    eprintln!("broker: listening on {}", socket.display());
    accept_forever(tools, &listener)
}

/// At most this many requests handled at once; the next is refused. A
/// question holds its request for as long as it is open, so more than one is
/// normal, but not a flood of connections that each hold a thread.
const MAX_HANDLED: usize = 64;

fn accept_forever(tools: &Tools, listener: &UnixListener) -> u8 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static HANDLED: AtomicUsize = AtomicUsize::new(0);
    for mut stream in listener.incoming().flatten() {
        if HANDLED.fetch_add(1, Ordering::SeqCst) >= MAX_HANDLED {
            HANDLED.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.write_all(b"refused: too many requests at once\n");
            continue;
        }
        /// Gives the slot back however the handler ends.
        struct Handled;
        impl Drop for Handled {
            fn drop(&mut self) {
                HANDLED.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let slot = Handled;
        let tools = tools.clone();
        // The slot moves into the thread; a thread that could not start
        // drops it with the closure.
        let _ = std::thread::Builder::new().spawn(move || {
            let _slot = slot;
            handle(&tools, stream);
        });
    }
    0
}

/// The client half, for `delegate`: `Some(code)` when a broker answered,
/// `None` when there is none to ask.
pub fn request(app_id: &[u8], argv: &[OsString]) -> Option<u8> {
    exchange(&encode(app_id, argv))
}

/// What came of a link handed to the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Linked {
    /// Opened.
    Opened,
    /// Not opened: refused, or nobody chose.
    Refused,
    /// The broker takes the asker for no zone's program: its own to open.
    NotAZone,
    /// No broker to ask.
    NoBroker,
}

/// The client half of a link to open, for a bus filter (after the windows
/// were answered or closed). `container`: whose program's connection asked
/// — [`LINK_MAIN`] for the zone's own, empty where not known.
pub fn link(uri: &str, container: &str) -> Linked {
    let Some(answer) = exchange_text(&encode_link(b"", uri, container)) else {
        return Linked::NoBroker;
    };
    if answer == "ok" {
        Linked::Opened
    } else if answer == NOT_A_ZONE {
        Linked::NotAZone
    } else {
        eprintln!(
            "брокер: {}",
            answer.strip_prefix("refused: ").unwrap_or(&answer)
        );
        Linked::Refused
    }
}

/// The client half of a choice to make, for the picker in a zone: `Some(code)`
/// when a broker answered (after the window was answered or closed), `None`
/// when there is none to ask.
pub fn pick(app_id: &[u8], cmd: &[OsString]) -> Option<u8> {
    exchange(&encode_pick(app_id, cmd))
}

fn exchange(request: &[u8]) -> Option<u8> {
    let answer = exchange_text(request)?;
    if answer == "ok" {
        Some(0)
    } else {
        eprintln!(
            "брокер: {}",
            answer.strip_prefix("refused: ").unwrap_or(&answer)
        );
        Some(1)
    }
}

/// The broker's one line of answer to `request`; `None` with no broker.
fn exchange_text(request: &[u8]) -> Option<String> {
    let socket = runtime_dir().join(SOCKET);
    let mut stream = UnixStream::connect(&socket).ok()?;
    if stream.write_all(request).is_err() {
        return Some("refused: запрос не отправлен".to_owned());
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    Some(answer.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every word on a line of its own, whole up to a length and marked when
    /// cut; nothing that reorders text; a command too long to show is not
    /// asked about. "Always" is not for a command with options.
    #[test]
    fn a_question_shows_every_word() {
        let cmd: Vec<OsString> = ["firefox", "--x\u{202E}y", "a<b>"]
            .map(OsString::from)
            .to_vec();
        assert_eq!(shown_command(&cmd).unwrap(), "firefox\n--xy\na‹b›");
        assert!(shown_command(&vec![OsString::from("x"); SHOWN_WORDS + 1]).is_none());
        let word = OsString::from("a".repeat(SHOWN_WORD + 5));
        assert!(shown_command(&[word]).unwrap().ends_with("(ещё 5 симв.)"));
        assert!(plain_arguments(&[
            "firefox".into(),
            "https://x.test".into()
        ]));
        assert!(!plain_arguments(&[
            "chromium".into(),
            "https://x.test".into(),
            "--renderer-cmd-prefix=sh".into()
        ]));
    }

    #[test]
    fn always_is_kept_for_programs_of_the_store_only() {
        // A program of the store: `ls`, as the test's own PATH has it — and
        // `sh` next to it, which runs anything and is never remembered.
        let ls = program_of(&["ls".into()]).unwrap();
        assert!(
            ls.starts_with("/nix/store/") && ls.ends_with("ls"),
            "{}",
            ls.display()
        );
        assert!(may_remember(&ls));
        assert!(!may_remember(&program_of(&["sh".into()]).unwrap()));
        assert!(!may_remember(Path::new(
            "/nix/store/does-not-exist/bin/zen"
        )));
        assert!(!may_remember(Path::new("/home/u/.local/bin/zen")));
        assert!(!may_remember(Path::new("/tmp/zen")));
        assert_eq!(
            always_line("nl", "unconfined", Path::new("/nix/store/abc-zen/bin/zen")),
            "nl\tunconfined\t/nix/store/abc-zen/bin/zen"
        );
        // The program as the host resolves it: the directory's links followed,
        // the name kept.
        let dir = std::env::temp_dir().join(format!("vpn-zone-broker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real");
        std::fs::write(&real, "").unwrap();
        let link = dir.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            program_of(&[link.clone().into_os_string()]),
            Some(std::fs::canonicalize(&dir).unwrap().join("link"))
        );
        // …and a file outside the store is never "always".
        assert!(!may_remember(
            &program_of(&[real.clone().into_os_string()]).unwrap()
        ));
        assert_eq!(program_of(&[]), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_request_survives_the_socket() {
        let argv: Vec<OsString> = ["nl", "--", "firefox", "https://a b"]
            .iter()
            .map(OsString::from)
            .collect();
        let bytes = encode(b"org.mozilla.firefox", &argv);
        let (app_id, back) = decode(&bytes).unwrap();
        assert_eq!(app_id, OsString::from("org.mozilla.firefox"));
        assert_eq!(back, argv);
        assert!(decode(b"junk").is_none());
        let (app_id, back) = decode(&encode(b"", &[])).unwrap();
        assert!(app_id.is_empty() && back.is_empty());
    }

    /// A choice to make is not a request, nor the other way round: one kind
    /// is never read as the other.
    #[test]
    fn a_choice_to_make_survives_the_socket_and_is_no_request() {
        let cmd: Vec<OsString> = ["firefox", "https://a b", ""]
            .iter()
            .map(OsString::from)
            .collect();
        let bytes = encode_pick(b"firefox", &cmd);
        let (app_id, back) = decode_pick(&bytes).unwrap();
        assert_eq!(app_id, OsString::from("firefox"));
        assert_eq!(back, cmd);
        assert!(decode(&bytes).is_none());
        assert!(decode_pick(&encode(b"firefox", &cmd)).is_none());
    }

    /// An empty argument is shown as one: `["x", ""]` runs two words.
    #[test]
    fn every_word_is_shown_an_empty_one_too() {
        let cmd: Vec<OsString> = ["x", ""].iter().map(OsString::from).collect();
        assert_eq!(shown_words(&cmd).unwrap(), ["x", "(пустой аргумент)"]);
    }

    /// One zone holds at most a few requests at once, and the others are
    /// not held up by it; a slot is given back when its request ends.
    #[test]
    fn one_zone_cannot_hold_the_door_for_all() {
        let origin = "test-slots-zone";
        let slots: Vec<_> = (0..MAX_PER_ORIGIN)
            .map(|_| OriginSlot::take(origin).expect("a slot"))
            .collect();
        assert!(OriginSlot::take(origin).is_none());
        assert!(OriginSlot::take("test-slots-other").is_some());
        drop(slots);
        assert!(OriginSlot::take(origin).is_some());
    }

    /// The journal takes so many lines of one zone a minute, and no more.
    #[test]
    fn a_zone_cannot_rotate_the_journal_away() {
        let origin = "test-journal-zone";
        for _ in 0..JOURNAL_PER_MINUTE {
            assert!(may_journal(origin));
        }
        assert!(!may_journal(origin));
        assert!(may_journal("test-journal-other"));
    }

    /// A zone asking again and again is refused after a few, and right
    /// after a "no" it is not asked at all for a while.
    #[test]
    fn a_zone_that_keeps_asking_is_not_asked() {
        let now = std::time::Instant::now();
        let past = |secs: u64, refused: bool| {
            (
                "nl".to_owned(),
                now - std::time::Duration::from_secs(secs),
                refused,
            )
        };
        assert!(may_ask_now(&[], "nl", now).is_ok());
        let three = [past(50, false), past(40, false), past(30, false)];
        assert!(may_ask_now(&three, "nl", now).is_ok());
        let four = [
            past(50, false),
            past(40, false),
            past(30, false),
            past(20, false),
        ];
        assert!(may_ask_now(&four, "nl", now).is_err());
        assert!(
            may_ask_now(&four, "de", now).is_ok(),
            "another zone is its own"
        );
        let stale = [
            past(70, false),
            past(65, false),
            past(61, false),
            past(20, false),
        ];
        assert!(
            may_ask_now(&stale, "nl", now).is_ok(),
            "a minute ago is over"
        );
        assert!(may_ask_now(&[past(5, true)], "nl", now).is_err());
        assert!(may_ask_now(&[past(20, true)], "nl", now).is_ok());
    }

    /// What the window chose is started only as asked: the same command word
    /// for word, `run`'s own arguments, and from a locked zone that zone.
    #[test]
    fn the_window_chooses_where_and_never_what() {
        let os = |words: &[&str]| -> Vec<OsString> { words.iter().map(OsString::from).collect() };
        let cmd = os(&["firefox", "https://a"]);
        assert!(check_pick(
            &os(&["de", "--", "firefox", "https://a"]),
            "nl",
            false,
            &cmd
        )
        .is_ok());
        assert!(check_pick(
            &os(&["de", "--sandbox", "work", "--", "firefox", "https://a"]),
            "nl",
            false,
            &cmd
        )
        .is_ok());
        assert!(check_pick(
            &os(&["unconfined", "--", "firefox", "https://a"]),
            "nl",
            false,
            &cmd
        )
        .is_ok());
        // Another command, or more of it.
        assert!(check_pick(&os(&["de", "--", "sh", "-c", "x"]), "nl", false, &cmd).is_err());
        assert!(check_pick(
            &os(&["de", "--", "firefox", "https://a", "-P"]),
            "nl",
            false,
            &cmd
        )
        .is_err());
        // Not `run`'s arguments at all.
        assert!(check_pick(&os(&["--bogus"]), "nl", false, &cmd).is_err());
        assert!(check_pick(&[], "nl", false, &cmd).is_err());
        // A locked zone: only itself.
        assert!(check_pick(&os(&["nl", "--", "firefox", "https://a"]), "nl", true, &cmd).is_ok());
        assert!(check_pick(&os(&["de", "--", "firefox", "https://a"]), "nl", true, &cmd).is_err());
        assert!(check_pick(
            &os(&["unconfined", "--", "firefox", "https://a"]),
            "nl",
            true,
            &cmd
        )
        .is_err());
    }

    #[test]
    fn only_the_host_and_the_same_zone_start_without_a_person() {
        let nl = Origin::Zone("nl".to_owned());
        assert_eq!(decide(&nl, false, "nl", true), Decision::Start);
        // From a container, or into one: a crossing, asked about.
        assert_eq!(decide(&nl, false, "nl", false), Decision::Ask);
        assert_eq!(decide(&nl, true, "nl", false), Decision::Ask);
        // A zone that calls itself the host's network is not let through as
        // "the same zone".
        let fake = Origin::Zone("unconfined".to_owned());
        assert_eq!(decide(&fake, false, "unconfined", true), Decision::Ask);
        let fake = Origin::Zone("direct".to_owned());
        assert_eq!(decide(&fake, false, "direct", true), Decision::Ask);
        assert_eq!(decide(&nl, false, "de", true), Decision::Ask);
        assert_eq!(decide(&nl, false, "unconfined", true), Decision::Ask);
        assert!(matches!(
            decide(&nl, true, "unconfined", true),
            Decision::Refuse(_)
        ));
        assert_eq!(decide(&nl, true, "nl", true), Decision::Start);
        // The host never needs the broker: a request that looks like it is refused.
        assert!(matches!(
            decide(&Origin::Host, false, "unconfined", true),
            Decision::Refuse(_)
        ));
        // A system zone is never "the same zone" as a user zone of its name.
        let system = Origin::SystemZone("nl".to_owned());
        assert_eq!(decide(&system, false, "nl", true), Decision::Ask);
        assert_eq!(system.name(), "system:nl");
        // Not the host and not a zone — or gone before it was looked at: no.
        assert!(matches!(
            decide(&Origin::Unknown, false, "unconfined", true),
            Decision::Refuse(_)
        ));
        assert!(matches!(
            decide(&Origin::Unknown, false, "nl", true),
            Decision::Refuse(_)
        ));
    }

    /// The peer of a connection is found while it lives, and a peer that has
    /// left is nobody — not the host.
    #[test]
    fn a_peer_that_left_before_it_was_looked_at_is_unknown() {
        let state = std::env::temp_dir().join(format!("vz-broker-{}", std::process::id()));
        // Ourselves, alive, in our own namespace: the host.
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(origin_of(&state, &a).0, Origin::Host);
        drop((a, b));
        // A child that connects and exits before the broker looks.
        let dir = std::env::temp_dir().join(format!("vz-broker-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        // The address is made before the fork: the child only calls the kernel.
        // SAFETY: sockaddr_un is plain data.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (dst, src) in addr.sun_path.iter_mut().zip(socket.as_os_str().as_bytes()) {
            *dst = *src as libc::c_char;
        }
        // SAFETY: the child makes three system calls and leaves with _exit.
        let child = unsafe { libc::fork() };
        if child == 0 {
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                libc::connect(
                    fd,
                    (&addr as *const libc::sockaddr_un).cast(),
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                );
                libc::_exit(0);
            }
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        unsafe { libc::waitpid(child, &mut status, 0) };
        let (stream, _) = listener.accept().unwrap();
        assert_eq!(origin_of(&state, &stream).0, Origin::Unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn always_is_never_offered_for_what_runs_any_command() {
        for name in [
            "sh",
            "bash",
            "env",
            "python3",
            "python3.12",
            "perl",
            "node",
            "systemd-run",
            "cellward",
            "cw",
            "vpn-zone",
            "vpn-zone-pick",
        ] {
            assert!(runs_anything(name), "{name}");
        }
        for name in ["firefox", "telegram-desktop", "xdg-open", "mpv"] {
            assert!(!runs_anything(name), "{name}");
        }
        assert!(!may_remember(Path::new("/nix/store/x-bash/bin/bash")));
        assert!(!may_remember(Path::new("/nix/store/x-cellward/bin/cw")));
    }

    #[test]
    fn a_command_is_shown_a_word_a_line_and_without_markup() {
        let shown = shown_command(&["sh".into(), "-c".into(), "<b>ok</b>\n\nбезопасно".into()]);
        assert_eq!(shown.as_deref(), Some("sh\n-c\n‹b›ok‹/b›  безопасно"));
    }

    /// "Always" and the journal name the container a request came from with
    /// its zone: an answer for the zone's own programs is not one for a
    /// container's (docs/PERMISSIONS.md §11.9).
    #[test]
    fn the_origin_is_the_zone_and_its_container() {
        let nl = Origin::Zone("nl".into());
        assert_eq!(origin_label(&nl, Some("work")), "nl/work");
        assert_eq!(origin_label(&nl, Some("")), "nl");
        // Not known: never taken for the zone's own, and no "always" for it.
        assert_eq!(origin_label(&nl, None), "nl/?");
        assert!(!may_always("nl/?"));
        assert!(may_always("nl") && may_always("nl/work"));
        assert_eq!(
            origin_label(&Origin::SystemZone("nl".into()), Some("work")),
            "system:nl"
        );
    }
}
