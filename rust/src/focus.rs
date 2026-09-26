//! Which launch the focused window belongs to: the network and the container
//! of the program in front (`docs/WINDOW-FRAME.md` §7б, §7в) — what the hotkey
//! menu acts on and what a panel shows.
//!
//! The compositor knows the window and the pid that opened its connection
//! (niri: `niri msg --json focused-window`; sway: the focused node of
//! `swaymsg -t get_tree`). vpn-zones knows its launches: the registry
//! (`crate::registry`) records the pid of each, and that pid is an ANCESTOR of
//! the window's — the launch becomes the program through wl-sandbox and
//! profile-run, and a program opens its windows from its own children too. So:
//! up the parent chain from the window's pid to a pid of the registry.
//!
//! **The network is the kernel's word, and only the kernel's.** It is the
//! network namespace of the window's own process, held against the host's (the
//! one this command runs in: a zone has no compositor IPC) and the zones' — a
//! user zone by its holder, checked by its start time (`crate::cli::zone_pid`),
//! a system zone by `/run/netns/vz-<name>`, which only root writes. The
//! registry is on disk: a record outlives its process, its pid comes round to
//! somebody else, and a program with the whole `$HOME` can write it
//! (`docs/LEAK-MODEL.md` §9). So it only ever adds the container and the
//! program — a record of a launch that is certainly still this process
//! (`crate::registry::launched`), and in the network the kernel says. A window
//! in the host's namespace is the host's, whatever any file claims. A namespace
//! that is none of these is not guessed at.
//!
//! A program that detached from its parent (a double fork, reparented to init)
//! is not found in the registry either: its network is known, its container is
//! not, and it is said so.
//!
//! A window cannot lie about its pid (the kernel's `SO_PEERCRED`), but a program
//! can call itself anything in its title and app id: nothing here trusts the
//! title, and the app id is only shown — cut clean — when nothing else names
//! the program.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::json::{self, Value};
use crate::registry;
use crate::tools::Tools;

/// The focused window as the compositor tells it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Window {
    pub pid: i32,
    pub app_id: String,
    pub title: String,
}

/// The launch a window belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Launch {
    /// The network: a zone, `unconfined`, `offline`.
    pub zone: String,
    /// What was chosen for the container (`sb:<name>`, `__fs__`, a profile,
    /// empty for the main one); `None` when only the network is known.
    pub selector: Option<String>,
    /// The program's key — the registry file, the picker's `--id`.
    pub program: Option<String>,
}

/// The window of `niri msg --json focused-window`.
pub fn window_from_niri(v: &Value) -> Option<Window> {
    Some(Window {
        pid: i32::try_from(v.get("pid")?.as_i64()?).ok()?,
        app_id: v
            .get("app_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        title: v
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
    })
}

/// The focused window of `swaymsg -t get_tree`: the node with `focused`, where
/// a window is a node with a pid.
pub fn window_from_sway(v: &Value) -> Option<Window> {
    if v.get("focused").and_then(Value::as_bool) == Some(true) {
        if let Some(pid) = v.get("pid").and_then(Value::as_i64) {
            return Some(Window {
                pid: i32::try_from(pid).ok()?,
                app_id: v
                    .get("app_id")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        v.get("window_properties")
                            .and_then(|p| p.get("class"))
                            .and_then(Value::as_str)
                    })
                    .unwrap_or("")
                    .to_owned(),
                title: v
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            });
        }
    }
    ["nodes", "floating_nodes"]
        .iter()
        .filter_map(|k| v.get(k).and_then(Value::as_array))
        .flatten()
        .find_map(window_from_sway)
}

/// Which compositor answers here, by the variable its IPC socket is named in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compositor {
    Niri,
    Sway,
}

pub fn compositor() -> Option<Compositor> {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if set("NIRI_SOCKET") {
        Some(Compositor::Niri)
    } else if set("SWAYSOCK") {
        Some(Compositor::Sway)
    } else {
        None
    }
}

fn run_json(program: &str, args: &[&str]) -> Result<Value, String> {
    let out = Command::new(program)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{program} {} failed", args.join(" ")));
    }
    json::parse(String::from_utf8_lossy(&out.stdout).trim())
}

/// The focused window, or `None` when nothing has the focus.
pub fn focused_window() -> Result<Option<Window>, String> {
    match compositor() {
        Some(Compositor::Niri) => {
            run_json("niri", &["msg", "--json", "focused-window"]).map(|v| window_from_niri(&v))
        }
        Some(Compositor::Sway) => {
            run_json("swaymsg", &["-t", "get_tree", "-r"]).map(|v| window_from_sway(&v))
        }
        None => {
            Err("композитор не отвечает: нужен niri (NIRI_SOCKET) или sway (SWAYSOCK)".to_owned())
        }
    }
}

/// The parent of a process, from `/proc/<pid>/status`.
fn parent(pid: i32) -> Option<i32> {
    crate::sys::parent_of(pid)
}

fn netns(pid: &str) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/ns/net"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Every launch of the registry by its pid: `(container dir, program, record)`.
fn registry_index(running: &Path) -> HashMap<i32, (String, String, registry::Record)> {
    let mut index = HashMap::new();
    for dir in registry::dirs(running) {
        let container = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for file in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let program = file.file_name().to_string_lossy().into_owned();
            if program.starts_with('.') {
                continue;
            }
            let Ok(text) = fs::read_to_string(file.path()) else {
                continue;
            };
            for record in text.lines().filter_map(registry::parse_record) {
                index.insert(record.pid, (container.clone(), program.clone(), record));
            }
        }
    }
    index
}

/// Which of our networks the namespace `ns` (`net:[…]`) is: the host's, a user
/// zone's, a system zone's. `None` for any other.
fn network_of(state: &Path, ns: &str) -> Option<String> {
    if netns("self").as_deref() == Some(ns) {
        return Some(crate::launch::UNCONFINED.to_owned());
    }
    for entry in fs::read_dir(state).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(zone_pid) = crate::cli::zone_pid(state, &name) else {
            continue;
        };
        if netns(&zone_pid.to_string()).as_deref() == Some(ns) {
            return Some(name.to_string_lossy().into_owned());
        }
    }
    crate::system::zone_of_netns(ns)
}

/// Whether `pid` is the supervisor of a launch behind the Wayland proxy
/// (`crate::wl_proxy`), and if so, the launch's network.
enum Proxied {
    No,
    /// The supervisor's program is in this network.
    Yes(String),
    /// A supervisor whose program's network cannot be told.
    Unknown,
}

/// A window behind the proxy has the SUPERVISOR's pid: upstream, the
/// supervisor (`wl-sandbox`, the pid of the registry record) makes the
/// connection the compositor takes the pid from, for every window of its
/// launch. It runs on the host, so its own namespace says nothing of the
/// program's. The kernel still does: its children are the program and the
/// orphans it adopted — in the program's network — and the proxy (not
/// dumpable, its namespace unread; and not counted). That network, when they
/// all agree on one we know; a nested one (a browser's sandbox) is not
/// counted, and two is not guessed between.
///
/// Known by its name ([`crate::wl_proxy::SUPERVISOR_NAME`]) — and not by
/// that alone, since a name is anybody's (review 2026-09-25): a process in a
/// zone's own namespace is taken by that namespace, whatever it is called;
/// one on the host counts only when the kernel says it runs our own
/// `vpn-zone-core` (`core`) and it is a launch on record. A host process that
/// merely calls itself so — one an ordinary zone started through
/// `systemd --user`, with a child put into that zone — gets no network at all
/// instead of its children's: its windows are its own, and they must not wear
/// the zone's label. A real supervisor passes on only the connections of its
/// own launch (`crate::wl_proxy`), and no process below it in a zone can bring
/// a host process into its subtree — so its children's network is its
/// windows'. After an update of the package a supervisor started before it
/// runs the old file: its windows show no network until the program is
/// started again — the safe way round.
fn proxied(state: &Path, core: &Path, pid: i32) -> Proxied {
    if comm(pid) != crate::wl_proxy::SUPERVISOR_NAME {
        return Proxied::No;
    }
    let own = netns(&pid.to_string()).and_then(|ns| network_of(state, &ns));
    if own.is_some_and(|zone| zone != crate::launch::UNCONFINED) {
        return Proxied::No;
    }
    if !runs_core(pid, core) || !registry::launched(&state.join(".running"), pid) {
        return Proxied::Unknown;
    }
    let networks = children(pid)
        .into_iter()
        .filter(|&child| comm(child) != crate::wl_proxy::PROCESS_NAME)
        .filter_map(|child| network_of(state, &netns(&child.to_string())?));
    match one_network(networks) {
        Some(zone) => Proxied::Yes(zone),
        None => Proxied::Unknown,
    }
}

fn comm(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim_end().to_owned())
        .unwrap_or_default()
}

/// The one network all of these are in; `None` for none or several.
fn one_network(networks: impl IntoIterator<Item = String>) -> Option<String> {
    let mut networks = networks.into_iter();
    let first = networks.next()?;
    networks.all(|n| n == first).then_some(first)
}

fn children(pid: i32) -> Vec<i32> {
    crate::sys::children_of(pid)
}

/// Whether `pid` runs our own `vpn-zone-core` (`core`, as the tools manifest
/// names it): the file the kernel executed, which a process cannot rename.
/// Readable for a process of the same user that is dumpable, as the
/// supervisor is.
fn runs_core(pid: i32, core: &Path) -> bool {
    let (Ok(exe), Ok(core)) = (
        fs::read_link(format!("/proc/{pid}/exe")),
        fs::canonicalize(core),
    ) else {
        return false;
    };
    exe == core
}

/// The launch of the process `pid`: its network by its namespace, its
/// container and program by the nearest launch up its parent chain — when that
/// launch is certainly still running and in the same network. A window of a
/// program behind the Wayland proxy has its supervisor's pid, whose network is
/// its children's ([`proxied`]); `core` is our `vpn-zone-core`, the file a
/// supervisor runs.
pub fn launch_of(state: &Path, core: &Path, pid: i32) -> Option<Launch> {
    let zone = match proxied(state, core, pid) {
        Proxied::No => network_of(state, &netns(&pid.to_string())?)?,
        Proxied::Yes(zone) => zone,
        Proxied::Unknown => return None,
    };
    let running = state.join(".running");
    let index = registry_index(&running);
    let mut at = pid;
    for _ in 0..64 {
        if let Some((_, program, record)) = index.get(&at) {
            // The user's own launch: one a program in a zone asked for runs
            // under an id of that program's choosing, and would get the user's
            // label for it and the "pin" and "restart" entries.
            if registry::launched_here(&running, at) {
                if record.zone == zone {
                    return Some(Launch {
                        zone,
                        selector: Some(record.selector.clone()),
                        program: Some(program.clone()),
                    });
                }
                // The nearest launch is somewhere else than the kernel says —
                // a program entered by hand into another network: its network
                // is known, its container is not.
                break;
            }
        }
        match parent(at) {
            Some(p) if p > 1 => at = p,
            _ => break,
        }
    }
    Some(Launch {
        zone,
        ..Launch::default()
    })
}

/// A name a program gave itself, fit to be shown: no control characters (a
/// line break would start a line of its own in a dialog), not endless.
fn shown(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && !reorders(*c))
        .take(80)
        .collect()
}

/// Invisible characters that change the order text is shown in, or hide in
/// it: bidi marks, embeddings, isolates, zero-width joiners and spaces. With
/// them a name can make the network after it read as something else.
pub(crate) fn reorders(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// Text for a markup parser: waybar reads `text` and `tooltip` as Pango
/// markup, and a container or a program is named by people and programs.
fn markup(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The network as a person says it.
pub fn zone_words(zone: &str) -> String {
    match zone {
        crate::launch::UNCONFINED => "без ограничений".to_owned(),
        "offline" => "без сети".to_owned(),
        zone => zone.to_owned(),
    }
}

/// "сеть nl", "без сети", "без ограничений" — the network in a sentence.
fn net_phrase(zone: &str) -> String {
    match zone {
        crate::launch::UNCONFINED | "offline" => zone_words(zone),
        zone => format!("сеть {zone}"),
    }
}

/// "в сети nl", "без сети", "без ограничений" — where a program runs.
fn in_net(zone: &str) -> String {
    match zone {
        crate::launch::UNCONFINED | "offline" => zone_words(zone),
        zone => format!("в сети {zone}"),
    }
}

/// The program's name as the picker last showed it, or its key.
fn label(state: &Path, program: &str) -> String {
    crate::cli::read_setting(&state.join(".labels").join(program))
        .unwrap_or_else(|| program.to_owned())
}

/// The program of a window as a person knows it: its label, or else the app
/// id it gave itself, or else its pid.
fn window_name(state: &Path, window: &Window, launch: Option<&Launch>) -> String {
    launch
        .and_then(|l| l.program.as_deref())
        .map(|p| label(state, p))
        .map(|l| shown(&l))
        .unwrap_or_else(|| {
            // The window's own name, in quotes: nothing vouches for it.
            let app_id = shown(&window.app_id);
            if app_id.is_empty() {
                format!("pid {}", window.pid)
            } else {
                format!("«{app_id}»")
            }
        })
}

/// One line for a person.
pub fn describe(state: &Path, window: &Window, launch: Option<&Launch>) -> String {
    let name = window_name(state, window, launch);
    match launch {
        None => format!("{name}: сеть не известна — не хост и не зона cellward"),
        Some(l) => {
            let container = match &l.selector {
                Some(s) => crate::picker::container_label(s),
                None => "контейнер не известен".to_owned(),
            };
            format!("{name}: {}, контейнер: {container}", net_phrase(&l.zone))
        }
    }
}

/// `{"zone":…,"container":…,"program":…,"label":…,"pid":…,"app_id":…}`, or
/// `{"window":null}` with nothing focused.
pub fn to_json(state: &Path, window: Option<&Window>, launch: Option<&Launch>) -> String {
    let Some(w) = window else {
        return "{\"window\":null}".to_owned();
    };
    let opt = |v: Option<&str>| v.map_or("null".to_owned(), json::quote);
    let program = launch.and_then(|l| l.program.as_deref());
    format!(
        "{{\"pid\":{},\"app_id\":{},\"zone\":{},\"container\":{},\"program\":{},\"label\":{}}}",
        w.pid,
        json::quote(&w.app_id),
        opt(launch.map(|l| l.zone.as_str())),
        opt(launch.and_then(|l| l.selector.as_deref())),
        opt(program),
        opt(program.map(|p| label(state, p)).as_deref()),
    )
}

/// One line for a status bar (waybar's `return-type: json`): the text, a
/// tooltip, and a class a style sheet can colour by zone.
pub fn bar_line(state: &Path, window: Option<&Window>, launch: Option<&Launch>) -> String {
    let (text, class) = match launch {
        None if window.is_none() => (String::new(), "none".to_owned()),
        None => ("?".to_owned(), "unknown".to_owned()),
        Some(l) => {
            let container = l
                .selector
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!(" · {}", crate::picker::container_label(s)))
                .unwrap_or_default();
            (
                format!("{}{container}", zone_words(&l.zone)),
                format!("zone-{}", l.zone),
            )
        }
    };
    let tooltip = window
        .map(|w| describe(state, w, launch))
        .unwrap_or_default();
    format!(
        "{{\"text\":{},\"tooltip\":{},\"class\":{}}}",
        json::quote(&markup(&text)),
        json::quote(&markup(&tooltip)),
        json::quote(&class)
    )
}

/// `vpn-zone focused [--json | --bar | --watch]`.
pub fn run(tools: &Tools, args: &[OsString]) -> u8 {
    let flag = args.first().and_then(|a| a.to_str()).unwrap_or("");
    if flag == "--watch" {
        return watch(tools);
    }
    let window = match focused_window() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cellward focused: {e}");
            return 1;
        }
    };
    let launch = window
        .as_ref()
        .and_then(|w| launch_of(&tools.state, &tools.core, w.pid));
    match flag {
        "--json" => println!(
            "{}",
            to_json(&tools.state, window.as_ref(), launch.as_ref())
        ),
        "--bar" => println!(
            "{}",
            bar_line(&tools.state, window.as_ref(), launch.as_ref())
        ),
        "" => match &window {
            Some(w) => println!("{}", describe(&tools.state, w, launch.as_ref())),
            None => println!("нет окна в фокусе"),
        },
        other => {
            eprintln!("cellward focused [--json | --bar | --watch], не {other}");
            return 1;
        }
    }
    0
}

/// A bar line every time the focus moves: the compositor's event stream, and
/// a line printed only when it changed.
fn watch(tools: &Tools) -> u8 {
    let (program, args): (&str, &[&str]) = match compositor() {
        Some(Compositor::Niri) => ("niri", &["msg", "--json", "event-stream"]),
        Some(Compositor::Sway) => (
            "swaymsg",
            &["-t", "subscribe", "-m", "[\"window\",\"workspace\"]"],
        ),
        None => {
            eprintln!("cellward focused --watch: нужен niri или sway");
            return 1;
        }
    };
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cellward focused --watch: {program}: {e}");
            return 1;
        }
    };
    let Some(stdout) = child.stdout.take() else {
        return 1;
    };
    let mut last = String::new();
    let mut show = || {
        let window = focused_window().ok().flatten();
        let launch = window
            .as_ref()
            .and_then(|w| launch_of(&tools.state, &tools.core, w.pid));
        let line = bar_line(&tools.state, window.as_ref(), launch.as_ref());
        if line != last {
            println!("{line}");
            last = line;
        }
    };
    show();
    for _ in BufReader::new(stdout).lines().map_while(Result::ok) {
        show();
    }
    let _ = child.wait();
    0
}

/// What "always" is for the program of a window: the network is its
/// container's, never the program's (`docs/PERMISSIONS.md` §11.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// A container with no network yet: bind it to the one it runs in.
    Bind(String),
    /// A container bound here (not in Nix): unbind it, and its network is
    /// asked at its next launch.
    Unbind { container: String, network: String },
    /// The main home: the program moves to the container of the main home
    /// bound to the network it runs in (`main-<network>`).
    Main,
    /// Nothing to pin: a throwaway container, a network declared in Nix, a
    /// launch not known.
    Nothing,
}

/// [`Pin`] for a launch.
pub fn pin_of(tools: &Tools, launch: &Launch) -> Pin {
    use crate::container::{Network, Source};
    match launch.selector.as_deref() {
        Some("") => Pin::Main,
        Some(selector) => match crate::container::load(tools, selector) {
            Some(c) => match (&c.network.value, c.network.source) {
                (_, Source::Nix) => Pin::Nothing,
                (Network::Ask, _) => Pin::Bind(c.name),
                (Network::Named(network), _) => Pin::Unbind {
                    network: network.clone(),
                    container: c.name,
                },
            },
            None => Pin::Nothing,
        },
        None => Pin::Nothing,
    }
}

/// The entries of the hotkey menu for the program of a window: `(tag, label,
/// danger)`.
pub fn menu_entries(
    label: &str,
    launch: Option<&Launch>,
    pin: &Pin,
) -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    let entry = |tag: &str, text: String, danger: bool| (tag.to_owned(), text, danger);
    if let Some(l) = launch.filter(|l| l.program.is_some()) {
        match pin {
            Pin::Unbind { container, network } => out.push(entry(
                "unpin",
                format!(
                    "Спрашивать сеть контейнера «{container}» при запуске (сейчас всегда {})",
                    in_net(network)
                ),
                false,
            )),
            Pin::Bind(container) => out.push(entry(
                "pin",
                format!("Контейнер «{container}» — всегда {}", in_net(&l.zone)),
                false,
            )),
            Pin::Main => out.push(entry(
                "pin",
                format!(
                    "Всегда запускать «{label}» в основном доме {}",
                    in_net(&l.zone)
                ),
                false,
            )),
            Pin::Nothing => {}
        }
        out.push(entry(
            "restart",
            format!("Закрыть «{label}» и запустить снова — выбрать сеть и контейнер…"),
            true,
        ));
    }
    out.push(entry("close", format!("Закрыть «{label}»"), true));
    if let Some(l) = launch.filter(|l| l.zone != crate::launch::UNCONFINED && l.zone != "offline") {
        out.push(entry(
            "kill-zone",
            format!(
                "Оборвать сеть {}: все её программы останутся без сети",
                l.zone
            ),
            true,
        ));
    }
    out
}

/// Ask with the launch window in its menu mode, or with a kdialog menu where
/// the window is missing. The chosen tag.
fn ask_menu(tools: &Tools, menu: &crate::window::Menu) -> Option<String> {
    if !tools.window.as_os_str().is_empty() {
        if let Ok(mut child) = Command::new(&tools.window)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = std::io::Write::write_all(
                    &mut stdin,
                    crate::window::render_menu(menu).as_bytes(),
                );
            }
            let out = child.wait_with_output().ok()?;
            if !out.status.success() {
                return None;
            }
            return crate::window::parse_menu_reply(&String::from_utf8_lossy(&out.stdout));
        }
    }
    let mut argv: Vec<OsString> = vec![
        "--title".into(),
        menu.title.clone().into(),
        "--menu".into(),
        // kdialog shows it in a QLabel, which takes `<` for rich text: a
        // window's own name must not restyle, or hide, what follows it.
        menu.notes
            .join("\n")
            .replace('<', "‹")
            .replace('>', "›")
            .replace('&', "＆")
            .into(),
    ];
    for (tag, label, _) in &menu.actions {
        argv.push(tag.into());
        argv.push(label.into());
    }
    crate::dialog::ask(&tools.kdialog, &argv)
}

/// When a restart asks what to do about a program still closing. Only that:
/// no clock decides — the program closing does, or the person.
const SAY_CLOSING_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

/// A program asked to close for a restart that has not closed yet: the
/// person decides, while it goes on closing (it may be asking whether to
/// save). "Wait" is the default — Enter changes nothing; "close now" kills
/// it, and what is unsaved is lost — pressed sooner than
/// [`crate::dialog::TOO_FAST`] after the question it is taken for a key
/// meant for something else, and waits; Esc cancels the restart. The program
/// closing meanwhile answers the question: the dialog goes. `true`: it
/// closed, and the restart goes on — its launch window asks, and can be
/// closed.
fn closed_after_all(tools: &Tools, label: &str, program: &OwnedFd) -> bool {
    let shown = label.replace('<', "‹").replace('>', "›").replace('&', "＆");
    let text = format!(
        "«{shown}» ещё не закрылась — может быть, спрашивает, сохранить ли. \
         Перезапуск будет, когда она закроется."
    );
    let asked = std::time::Instant::now();
    let dialog = Command::new(&tools.kdialog)
        .args(["--title", crate::dialog::APP, "--warningyesnocancel"])
        .arg(&text)
        .args([
            "--yes-label",
            "Ждать",
            "--no-label",
            "Закрыть сразу",
            "--cancel-label",
            "Отменить перезапуск",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let (mut dialog, dialog_fd) = match dialog {
        Ok(child) => match crate::sys::pidfd_open(child.id() as i32) {
            Some(fd) => (child, fd),
            None => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                crate::sys::pidfd_wait_end(program);
                return true;
            }
        },
        // Nowhere to ask: waited for, as the restart asked.
        Err(_) => {
            crate::sys::pidfd_wait_end(program);
            return true;
        }
    };
    let pollin = |fd: &OwnedFd| libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let mut fds = [pollin(program), pollin(&dialog_fd)];
    loop {
        // SAFETY: two valid pollfds for the duration of the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    if fds[0].revents != 0 {
        let _ = dialog.kill();
        let _ = dialog.wait();
        return true;
    }
    match dialog.wait().ok().and_then(|s| s.code()) {
        Some(1) if crate::dialog::not_too_soon(asked).is_ok() => {
            crate::sys::pidfd_signal(program, libc::SIGKILL);
            crate::sys::pidfd_wait_end(program);
            true
        }
        Some(0 | 1) => {
            crate::sys::pidfd_wait_end(program);
            true
        }
        _ => false,
    }
}

/// `vpn-zone window-menu`: what can be done with the program of the focused
/// window — for a key binding of the compositor.
pub fn menu(tools: &Tools) -> u8 {
    let notify = |title: &str, body: &str| {
        crate::dialog::notify(&tools.notify_send, None, "5000", title, body);
    };
    let window = match focused_window() {
        Ok(Some(w)) => w,
        Ok(None) => {
            notify(crate::dialog::APP, "Нет окна в фокусе");
            return 0;
        }
        Err(e) => {
            eprintln!("cellward window-menu: {e}");
            notify(crate::dialog::APP, &e);
            return 1;
        }
    };
    // Held from here on: the menu may stay open a while, and a number can
    // change hands in that time — "close" reaches this process or nobody.
    let target = crate::sys::pidfd_open(window.pid);
    let launch = launch_of(&tools.state, &tools.core, window.pid);
    let program = launch.as_ref().and_then(|l| l.program.clone());
    let label = window_name(&tools.state, &window, launch.as_ref());
    let pin = launch.as_ref().map_or(Pin::Nothing, |l| pin_of(tools, l));
    let menu = crate::window::Menu {
        title: label.clone(),
        notes: vec![describe(&tools.state, &window, launch.as_ref())],
        actions: menu_entries(&label, launch.as_ref(), &pin),
    };
    let Some(choice) = ask_menu(tools, &menu) else {
        return 0;
    };
    let confirm = |text: String| {
        crate::dialog::confirm(
            &tools.kdialog,
            [
                "--title",
                crate::dialog::APP,
                "--warningcontinuecancel",
                text.as_str(),
            ],
        )
    };
    match choice.as_str() {
        "pin" => {
            let (Some(p), Some(l)) = (&program, &launch) else {
                return 0;
            };
            let network = crate::container::Network::Named(l.zone.clone());
            let done = match &pin {
                Pin::Bind(container) => crate::container::set_network(tools, container, &network)
                    .map(|()| format!("Контейнер «{container}» теперь всегда {}", in_net(&l.zone))),
                Pin::Main => crate::container::main_for_network(tools, &l.zone).and_then(|name| {
                    let dir = tools.state.join(".pinnedprofile");
                    fs::create_dir_all(&dir)
                        .and_then(|()| fs::write(dir.join(p), &name))
                        .map_err(|e| e.to_string())
                        .map(|()| {
                            format!(
                                "Теперь в контейнере «{name}»: основной дом, всегда {}",
                                in_net(&l.zone)
                            )
                        })
                }),
                _ => return 0,
            };
            match done {
                Ok(text) => notify(&label, &text),
                Err(e) => notify(&label, &e),
            }
        }
        "unpin" => {
            if let Pin::Unbind { container, .. } = &pin {
                match crate::container::set_network(
                    tools,
                    container,
                    &crate::container::Network::Ask,
                ) {
                    Ok(()) => notify(
                        &label,
                        &format!("Сеть контейнера «{container}» спросится при следующем запуске"),
                    ),
                    Err(e) => notify(&label, &e),
                }
            }
        }
        "close" => {
            if !target
                .as_ref()
                .is_some_and(|fd| crate::sys::pidfd_signal(fd, libc::SIGTERM))
            {
                notify(&label, "Программа уже закрылась");
            }
        }
        "restart" => {
            let Some(p) = &program else { return 0 };
            if !confirm(format!(
                "«{label}» закроется и запустится снова с выбором сети и контейнера. \
                 Несохранённое в ней может пропасть."
            )) {
                return 0;
            }
            // No descriptor: the process was gone before the menu came up.
            // Waited for as long as closing takes, no clock of ours: a program
            // asking whether to save, or slow on a loaded machine, is closing
            // all the same, and a deadline would cancel the restart exactly
            // then. When it is not quick, the person decides
            // (`closed_after_all`).
            if let Some(fd) = &target {
                crate::sys::pidfd_signal(fd, libc::SIGTERM);
                if !crate::sys::pidfd_wait(fd, SAY_CLOSING_AFTER)
                    && !closed_after_all(tools, &label, fd)
                {
                    return 0;
                }
            }
            // Through the picker, asked: the launch window with both questions.
            let started = Command::new(&tools.runner)
                .args(["launch", p.as_str()])
                .env(crate::picker::ENV_ASK, "1")
                .stdin(Stdio::null())
                .spawn();
            if let Err(e) = started {
                notify(&label, &format!("Не запустилась: {e}"));
                return 1;
            }
        }
        "kill-zone" => {
            let Some(l) = &launch else { return 0 };
            if !confirm(format!(
                "Оборвать сеть {}? Все её программы сразу останутся без сети, зона опустится.",
                l.zone
            )) {
                return 0;
            }
            let _ = Command::new(&tools.runner)
                .args(["kill", l.zone.as_str()])
                .status();
        }
        other => eprintln!("cellward window-menu: неизвестный выбор {other}"),
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_focused_window_is_found_in_what_niri_and_sway_say() {
        let niri =
            json::parse(r#"{"id":3,"title":"t","app_id":"firefox","pid":77,"is_focused":true}"#)
                .unwrap();
        assert_eq!(
            window_from_niri(&niri),
            Some(Window {
                pid: 77,
                app_id: "firefox".to_owned(),
                title: "t".to_owned()
            })
        );
        assert_eq!(window_from_niri(&Value::Null), None);
        let sway = json::parse(
            r#"{"type":"root","focused":false,"nodes":[{"type":"output","focused":false,"nodes":[
                {"type":"workspace","focused":false,"nodes":[
                   {"type":"con","focused":false,"pid":10,"app_id":"foot","name":"a"},
                   {"type":"con","focused":true,"pid":11,"app_id":null,"name":"b",
                    "window_properties":{"class":"Steam"}}]}]}],"floating_nodes":[]}"#,
        )
        .unwrap();
        let w = window_from_sway(&sway).unwrap();
        assert_eq!(
            (w.pid, w.app_id.as_str(), w.title.as_str()),
            (11, "Steam", "b")
        );
    }

    /// What the menu offers follows what is known: a program of the registry
    /// can be pinned or restarted; a real zone can be cut off; the host cannot.
    #[test]
    fn the_menu_offers_what_is_known_of_the_window() {
        let launch = Launch {
            zone: "nl".to_owned(),
            selector: Some(String::new()),
            program: Some("firefox".to_owned()),
        };
        let tags =
            |e: Vec<(String, String, bool)>| e.into_iter().map(|(t, _, _)| t).collect::<Vec<_>>();
        assert_eq!(
            tags(menu_entries("Лис", Some(&launch), &Pin::Main)),
            ["pin", "restart", "close", "kill-zone"]
        );
        assert_eq!(
            tags(menu_entries(
                "Лис",
                Some(&launch),
                &Pin::Bind("work".into())
            )),
            ["pin", "restart", "close", "kill-zone"]
        );
        let unbind = Pin::Unbind {
            container: "work".into(),
            network: "nl".into(),
        };
        let entries = menu_entries("Лис", Some(&launch), &unbind);
        assert_eq!(
            tags(entries.clone()),
            ["unpin", "restart", "close", "kill-zone"]
        );
        assert!(entries[0].1.contains("«work»"), "{entries:?}");
        // A throwaway container, a network from Nix: nothing to pin.
        assert_eq!(
            tags(menu_entries("Лис", Some(&launch), &Pin::Nothing)),
            ["restart", "close", "kill-zone"]
        );
        let host = Launch {
            zone: crate::launch::UNCONFINED.to_owned(),
            ..Launch::default()
        };
        assert_eq!(
            tags(menu_entries("x", Some(&host), &Pin::Nothing)),
            ["close"]
        );
        assert_eq!(tags(menu_entries("x", None, &Pin::Nothing)), ["close"]);
        let entries = menu_entries("Лис", Some(&launch), &Pin::Main);
        assert!(entries[3].2, "cutting a zone off is marked as dangerous");
        assert!(entries[3].1.contains("nl"));
    }

    #[test]
    fn one_network_is_all_of_them_agreeing() {
        let n = |v: &[&str]| one_network(v.iter().map(|s| s.to_string()));
        assert_eq!(n(&["nl", "nl"]).as_deref(), Some("nl"));
        assert_eq!(n(&["nl"]).as_deref(), Some("nl"));
        assert_eq!(n(&["nl", "de"]), None);
        assert_eq!(n(&[]), None);
    }

    /// A window behind the Wayland proxy has the supervisor's pid: its launch is
    /// that pid's record, its network the one of the supervisor's children.
    #[test]
    fn a_window_of_a_proxied_program_is_found_through_the_supervisor() {
        let state = std::env::temp_dir().join(format!("vz-focus-proxy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        let running = state.join(".running");
        let dir = running.join("sb:work");
        fs::create_dir_all(&dir).unwrap();
        let find = |name: &str| {
            std::env::var_os("PATH")
                .and_then(|p| {
                    std::env::split_paths(&p)
                        .map(|d| d.join(name))
                        .find(|p| p.is_file())
                })
                .unwrap()
        };
        // The supervisor: a shell under the supervisor's name (the kernel
        // takes the name of the file run), with a `sleep` for its program and
        // one more under the proxy's name.
        let supervisor_name = state.join(crate::wl_proxy::SUPERVISOR_NAME);
        let proxy_name = state.join(crate::wl_proxy::PROCESS_NAME);
        std::os::unix::fs::symlink(find("bash"), &supervisor_name).unwrap();
        std::os::unix::fs::symlink(find("sleep"), &proxy_name).unwrap();
        let mut supervisor = Command::new(&supervisor_name)
            .args(["-c", "(exec -a sleep \"$0\" 5) & sleep 5 & wait"])
            .arg(&proxy_name)
            .spawn()
            .unwrap();
        let sup = supervisor.id() as i32;
        for _ in 0..200 {
            if children(sup).len() == 2 && comm(sup) == crate::wl_proxy::SUPERVISOR_NAME {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        fs::write(
            dir.join("foot"),
            format!("{sup} {} sb:work\n", crate::launch::UNCONFINED),
        )
        .unwrap();
        // The file the kernel runs for it: "our vpn-zone-core" in this test.
        let core = find("bash");
        // The name alone is not a supervisor: no launch on record yet, and
        // then a file that is not ours — no network, not the children's.
        assert!(matches!(proxied(&state, &core, sup), Proxied::Unknown));
        registry::note_start(&running, sup, false).unwrap();
        assert!(matches!(
            proxied(&state, &find("sleep"), sup),
            Proxied::Unknown
        ));
        assert!(launch_of(&state, &find("sleep"), sup).is_none());
        // Taken for a supervisor, its network is its children's; a child is
        // taken for itself.
        assert!(
            matches!(proxied(&state, &core, sup), Proxied::Yes(ref z) if z == crate::launch::UNCONFINED)
        );
        assert!(matches!(
            proxied(&state, &core, children(sup)[0]),
            Proxied::No
        ));
        let launch = launch_of(&state, &core, sup).unwrap();
        assert_eq!(launch.zone, crate::launch::UNCONFINED);
        assert_eq!(launch.program.as_deref(), Some("foot"));
        assert_eq!(launch.selector.as_deref(), Some("sb:work"));
        for child in children(sup) {
            // SAFETY: a plain signal to a child of our child, still running.
            unsafe { libc::kill(child, libc::SIGKILL) };
        }
        let _ = supervisor.kill();
        let _ = supervisor.wait();
        let _ = fs::remove_dir_all(&state);
    }

    /// Up the parent chain to the registry: a child of the recorded launch is
    /// that launch — when the record is certainly still that process and in
    /// the network the kernel says.
    #[test]
    fn a_window_of_a_child_is_found_through_its_parents() {
        let state = std::env::temp_dir().join(format!("vz-focus-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        let running = state.join(".running");
        let dir = running.join("sb:work");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(state.join(".labels")).unwrap();
        fs::write(state.join(".labels").join("firefox"), "Огненный <лис>").unwrap();
        // This test process is "the launch"; a child of it is "the window".
        // Both are in our own namespace — the host's, to this command.
        let me = std::process::id() as i32;
        let record = |zone: &str| {
            fs::write(dir.join("firefox"), format!("{me} {zone} sb:work\n")).unwrap();
        };
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let window = child.id() as i32;

        // A record from before start times were kept: its pid may be anybody's
        // by now. The network is still the kernel's; the container is unknown.
        record(crate::launch::UNCONFINED);
        let bare = launch_of(&state, Path::new(""), window).unwrap();
        assert_eq!(bare.zone, crate::launch::UNCONFINED);
        assert_eq!((bare.selector, bare.program), (None, None));

        // With its start time on record: the launch.
        registry::note_start(&running, me, false).unwrap();
        let launch = launch_of(&state, Path::new(""), window).unwrap();
        assert_eq!(launch.zone, crate::launch::UNCONFINED);
        assert_eq!(launch.selector.as_deref(), Some("sb:work"));
        assert_eq!(launch.program.as_deref(), Some("firefox"));

        // A record that says "nl" of a process in the host's namespace does
        // not make the window a zone's: the kernel says host, and host it is.
        record("nl");
        let host = launch_of(&state, Path::new(""), window).unwrap();
        assert_eq!(host.zone, crate::launch::UNCONFINED);
        assert_eq!(host.program, None);

        // A start time of somebody else: the number was reused.
        record(crate::launch::UNCONFINED);
        fs::write(running.join(registry::STARTED).join(me.to_string()), "1\n").unwrap();
        assert_eq!(
            launch_of(&state, Path::new(""), window).unwrap().program,
            None
        );
        let _ = child.kill();
        let _ = child.wait();

        let w = Window {
            pid: 1,
            app_id: "fire\nfox".to_owned(),
            title: String::new(),
        };
        assert_eq!(
            describe(&state, &w, Some(&launch)),
            "Огненный <лис>: без ограничений, контейнер: песочница work"
        );
        // Markup is escaped for the bar: waybar parses it.
        assert_eq!(
            bar_line(&state, Some(&w), Some(&launch)),
            "{\"text\":\"без ограничений · песочница work\",\"tooltip\":\"Огненный &lt;лис&gt;: без ограничений, контейнер: песочница work\",\"class\":\"zone-unconfined\"}"
        );
        // Nothing but the app id: shown without its line break.
        assert!(describe(&state, &w, None).starts_with("«firefox»: "));
        // Bidi controls are cut: they could make the network read otherwise.
        assert_eq!(shown("a\u{202E}b\u{2066}c"), "abc");
        let _ = fs::remove_dir_all(&state);
    }
}
