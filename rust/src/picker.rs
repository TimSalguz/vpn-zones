//! `vpn-zone-pick` — the dialog that asks where a program is allowed to go.
//!
//! This is what an intercepted launcher entry starts instead of the program
//! (`crate::desktop`, picker mode): it asks which network and which container,
//! remembers the answer, and becomes `vpn-zone run`. It was the last shell
//! script of the project, and every branch of it is here because something went
//! wrong without it.
//!
//! **Three levels of memory, strongest first** (`docs/GOTCHAS.md` §11):
//!
//!  1. a PIN (`.pinned/<program>`) — no dialog at all, the program goes
//!     straight into the network it names. Set from the menu ("Всегда: …"),
//!     cleared from the same menu ("Спрашивать снова"), by the reset shortcut
//!     or by `vpn-zone forget`;
//!  2. the LAST CHOICE (`.last/<program>`) — the dialog is shown with that
//!     entry already selected;
//!  3. the GLOBAL DEFAULT (`~/.config/vpn-zones/default`, `offline` unless set).
//!     That is the "an unknown program gets no internet" policy: until a
//!     network is picked explicitly, the one without any is offered.
//!
//! The network and the container are pinned SEPARATELY (`.pinned` and
//! `.pinnedprofile`): they are independent axes, and the dialog is shown only
//! for the one that is not pinned. With the network pinned and the container
//! free there is no first dialog to reach "change container" from, so the
//! container gets a window of its own — that is what makes "always this
//! network, container chosen every time" possible.
//!
//! Two environment variables drive the second pass:
//!
//! * `VPN_ZONE_ASK=1` forces the dialog for a pinned program;
//! * `VPN_ZONE_PROFILE` is how the picker hands ITSELF the container that was
//!   just chosen in "⚙ Сменить контейнер" — it re-execs itself with both set.
//!   It is read once and removed from the environment immediately, or it would
//!   travel into the program, and a link opened from there would inherit
//!   somebody else's container.
//!
//! The decision itself is a pure function of a snapshot ([`Memory`]) so that
//! every branch of that machine is a test case and not a mouse click:
//! [`net_step`], [`container_without_dialog`], [`Container::from_selector`].

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::cli::{read_setting, visible_entries, EXIT_TOOLS};
use crate::desktop::sanitize;
use crate::dialog;
use crate::launch::{self, basename, is_assignment};
use crate::profile::{exec_command, proc_is_alive, EXIT_NOT_STARTED};
use crate::registry;
use crate::tools::Tools;

/// Force the dialog even for a pinned program.
pub const ENV_ASK: &str = "VPN_ZONE_ASK";
/// The container chosen in "⚙ Сменить контейнер", carried across the re-exec.
/// Internal: setting it by hand does nothing useful.
pub const ENV_PROFILE: &str = "VPN_ZONE_PROFILE";

/// Sentinel for "the main profile" where an empty string would not do: in
/// `.pinnedprofile` and in `VPN_ZONE_PROFILE` an empty value cannot be told
/// apart from "not set at all". (`docs/GOTCHAS.md` §11)
pub const MAIN: &str = "__main__";
/// Selector of a throwaway filesystem sandbox.
pub const THROWAWAY: &str = "__fs__";
/// Prefix of a named sandbox selector: `sb:<name>`.
pub const SANDBOX_PREFIX: &str = "sb:";
/// Selector of a fresh throwaway container.
pub const TMP: &str = "__tmp__";
/// Prefix of "join the throwaway container that is already open at <dir>".
pub const TMPJOIN_PREFIX: &str = "tmpjoin:";

/// The wrappers and shell built-ins the fallback key derivation walks past.
///
/// One more than [`crate::launch::app_word`] has (`systemd-run`), and the
/// difference is deliberate: this list is the picker's own, and a launch
/// delegated through `systemd-run` must be keyed by the program, not by the
/// tool that started it.
const WRAPPERS: [&[u8]; 6] = [b"env", b"sh", b"bash", b"setsid", b"nohup", b"systemd-run"];

// --- ARGUMENTS ---------------------------------------------------------------

/// `[<label>] [--id K] [--label L] [--] cmd…`
///
/// The program's DISPLAY NAME is no longer an argument: it contains spaces, and
/// Telegram (and it is not alone) splits `Exec` naively without removing
/// quotes, so "Zen Browser" fell apart into two arguments and the launch died.
/// The name is read from the label file the shortcut generator writes instead.
/// (`docs/GOTCHAS.md` §10)
///
/// A leading positional label is still ACCEPTED, because shortcuts and the
/// picker are not updated atomically: during one rebuild `sync` ran before the
/// profile was swapped, and the new picker was handed shortcuts in the old
/// format — AyuGram stopped starting at all. Parsing both shapes is cheaper
/// than depending on the order of an update. Such a label is only taken when a
/// `--` follows somewhere, or the command itself would be eaten.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    /// `--id`: the stable identifier of the launcher entry (its file name
    /// without the extension). Without it the memory key would have to be
    /// derived from the command, and those are full of wrappers: AyuGram's
    /// `Exec` starts with `env DESKTOPINTEGRATION=1 …`, and the key came out as
    /// "env". (`docs/GOTCHAS.md` §10)
    pub id: Option<OsString>,
    pub label: Option<OsString>,
    pub cmd: Vec<OsString>,
}

impl Args {
    pub fn parse(argv: &[OsString]) -> Self {
        let mut rest = argv;
        let mut label = None;

        let legacy = rest
            .first()
            .filter(|a| !a.is_empty() && !a.as_bytes().starts_with(b"-"))
            .is_some()
            && rest.iter().any(|a| a == "--");
        if legacy {
            label = Some(rest[0].clone());
            rest = &rest[1..];
        }

        let mut id = None;
        let mut at = 0;
        while at < rest.len() {
            match rest[at].as_bytes() {
                b"--id" => {
                    id = rest.get(at + 1).cloned();
                    at += 2;
                }
                b"--label" => {
                    label = rest.get(at + 1).cloned();
                    at += 2;
                }
                b"--" => {
                    at += 1;
                    break;
                }
                _ => break,
            }
        }

        Self {
            id: id.filter(|v| !v.is_empty()),
            label: label.filter(|v| !v.is_empty()),
            cmd: rest.get(at..).unwrap_or(&[]).to_vec(),
        }
    }
}

/// The memory key of a launch that did not come from a shortcut (a compositor
/// binding, a terminal): skip the wrappers and the variable assignments and
/// take the first real command.
///
/// The two traps are the ones [`crate::launch::app_word`] documents: only a
/// REAL assignment is skipped (`FOO=bar`, not `--url=https://x`), and an
/// argument with a space in it is the `sh -c '…'` case, where the whole word is
/// taken through `basename` rather than skipped.
pub fn fallback_key(cmd: &[OsString]) -> OsString {
    for word in cmd {
        let bytes = word.as_bytes();
        if WRAPPERS.contains(&bytes) || bytes.starts_with(b"-") {
            continue;
        }
        if bytes.contains(&b' ') {
            return basename(word).to_owned();
        }
        if is_assignment(bytes) {
            continue;
        }
        return basename(word).to_owned();
    }
    OsString::from("программа")
}

/// A name a person typed into a dialog, cleaned of exactly what would break —
/// path separators, quotes, spaces — and of the leading dash or dot kdialog
/// takes for an option. Cyrillic stays Cyrillic. (`docs/GOTCHAS.md` §11)
pub fn sanitize_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| match c {
            '/' | '"' | '\'' | '`' | '\\' | ' ' => '_',
            other => other,
        })
        .collect();
    cleaned.trim_start_matches(['-', '.']).to_owned()
}

// --- THE STATE THE DECISION IS MADE FROM -------------------------------------

/// One live record of the launch registry, as the picker cares about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    pub zone: String,
    /// The third registry field: what was CHOSEN (`sb:<name>`, `__fs__`, a
    /// container name, or empty). (`docs/GOTCHAS.md` §5)
    pub selector: String,
}

/// Everything the first decision depends on, read from disk and nothing else.
///
/// The pins are the VALIDATED ones: a pin naming a zone or a container that no
/// longer exists has already been dropped by the caller
/// ([`pin_is_valid`], [`profile_pin_is_valid`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Memory {
    /// A live registry record for this program, if it is running somewhere.
    pub running: Option<Running>,
    /// `.pinned/<key>`, empty when the network is not pinned.
    pub pinned: String,
    /// `.pinnedprofile/<key>`, empty when the container is not pinned.
    pub pinned_profile: String,
    /// `.last/<key>`.
    pub last: String,
    /// `.lastprofile/<key>`.
    pub last_profile: String,
    /// `~/.config/vpn-zones/default`, `offline` when the file is absent.
    pub fallback: String,
    /// `~/.config/vpn-zones/default-profile`, `ask` when the file is absent.
    pub default_profile: String,
    /// `VPN_ZONE_ASK` is set.
    pub ask: bool,
}

/// What the first (network) question resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetStep {
    /// The program is already running: a click on the shortcut of a running
    /// program means "raise the window", not "start another one". Asking about
    /// the network would be pointless — a program with one process per profile
    /// hands the command to the instance that is already up and it stays in ITS
    /// network — so it is started into the same place and no dialog is shown.
    /// (`docs/GOTCHAS.md` §11)
    Running { zone: String, selector: String },
    /// The network is pinned. `ask_container` is the case of a pinned network
    /// and a free container: the "change container" entry lives in the network
    /// dialog that is not being shown, so the container gets its own window.
    Pinned { zone: String, ask_container: bool },
    /// Show the network dialog, with this entry selected.
    Ask { default: String },
}

/// The first decision, without touching anything.
pub fn net_step(memory: &Memory) -> NetStep {
    if !memory.ask {
        if let Some(running) = &memory.running {
            return NetStep::Running {
                zone: running.zone.clone(),
                selector: running.selector.clone(),
            };
        }
        if !memory.pinned.is_empty() {
            return NetStep::Pinned {
                zone: memory.pinned.clone(),
                // A container pinned separately, or set globally, is an answer
                // already — only "ask" leaves a question to ask.
                ask_container: memory.pinned_profile.is_empty() && memory.default_profile == "ask",
            };
        }
    }
    NetStep::Ask {
        default: if memory.last.is_empty() {
            memory.fallback.clone()
        } else {
            memory.last.clone()
        },
    }
}

/// The container of a launch: exactly the three variables the shell carried
/// (`profile`, `fssand`, `sandbox`).
///
/// They are not one enum because they are not exclusive: a named sandbox is
/// also a filesystem sandbox, and a throwaway container can be combined with
/// one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Container {
    /// A container name, `__tmp__`, `tmpjoin:<dir>`, or empty for the main
    /// profile.
    pub profile: String,
    /// `--fs-sandbox`.
    pub fs_sandbox: bool,
    /// `--sandbox <name>`, empty when there is none.
    pub sandbox: String,
}

impl Container {
    /// A stored selector turned back into a choice.
    ///
    /// No existence check: this is the shape used for a selector that came from
    /// the launch registry, from a pin or from `VPN_ZONE_PROFILE`, all of which
    /// were validated when they were written. A container name that has been
    /// deleted since reaches `vpn-zone run`, which says so in words.
    pub fn from_selector(selector: &str) -> Self {
        Self::resolve(selector, |_| true)
    }

    /// The same, but a container name is only taken when it still exists —
    /// what `.lastprofile` gets, since nothing revalidates it on the way in.
    pub fn from_selector_checked(selector: &str, exists: impl Fn(&str) -> bool) -> Self {
        Self::resolve(selector, exists)
    }

    fn resolve(selector: &str, exists: impl Fn(&str) -> bool) -> Self {
        match selector {
            "" | MAIN => Self::default(),
            THROWAWAY => Self {
                fs_sandbox: true,
                ..Self::default()
            },
            other => match other.strip_prefix(SANDBOX_PREFIX) {
                Some(name) => Self {
                    fs_sandbox: true,
                    sandbox: name.to_owned(),
                    ..Self::default()
                },
                None if exists(other) => Self {
                    profile: other.to_owned(),
                    ..Self::default()
                },
                None => Self::default(),
            },
        }
    }

    /// What goes into `.lastprofile`: the CHOICE, not the `profile` variable.
    ///
    /// A sandbox leaves `profile` empty (it lives in a flag of its own), so
    /// writing the variable "as it is" turned it into "main" and the choice
    /// looked like it had not been saved. (`docs/GOTCHAS.md` §11)
    pub fn selector(&self) -> String {
        if !self.sandbox.is_empty() {
            return format!("{SANDBOX_PREFIX}{}", self.sandbox);
        }
        if self.fs_sandbox {
            return THROWAWAY.to_owned();
        }
        self.profile.clone()
    }

    /// Is this a one-off container that must not be remembered? Remembering it
    /// would make a throwaway permanent.
    pub fn is_throwaway_container(&self) -> bool {
        self.profile == TMP || self.profile.starts_with(TMPJOIN_PREFIX)
    }

    fn own_sandbox(key: &str) -> Self {
        Self {
            fs_sandbox: true,
            sandbox: format!("app-{key}"),
            ..Self::default()
        }
    }
}

/// The container when there is no dialog to ask it in, in priority order.
///
/// 1. `VPN_ZONE_PROFILE` — chosen in "⚙ Сменить контейнер" a second ago, so it
///    beats everything, the pin included;
/// 2. `.pinnedprofile` — and with no `VPN_ZONE_ASK` check in front of it: the
///    fresh choice arrives in the variable above, and testing for ASK here made
///    "↺ Спрашивать сеть снова" drop a pinned container into "main", because
///    `.lastprofile` is usually empty for somebody who pinned one;
/// 3. `.lastprofile`, overlaid with the global `default-profile` setting.
///
/// The overlay is deliberately partial, exactly as the shell was: `main` and a
/// named default clear `profile` only, so a sandbox remembered in
/// `.lastprofile` survives them.
pub fn container_without_dialog(
    memory: &Memory,
    key: &str,
    exists: impl Fn(&str) -> bool,
    reprofile: Option<&str>,
) -> Container {
    if let Some(selector) = reprofile.filter(|s| !s.is_empty()) {
        return Container::from_selector(selector);
    }
    if !memory.pinned_profile.is_empty() {
        return Container::from_selector(&memory.pinned_profile);
    }
    let mut container = Container::from_selector_checked(&memory.last_profile, &exists);
    match memory.default_profile.as_str() {
        "main" => container.profile.clear(),
        "ask" => {}
        "own" => container = Container::own_sandbox(key),
        name => {
            if exists(name) {
                container.profile = name.to_owned();
            }
        }
    }
    container
}

/// Is this network pin still worth honouring?
///
/// `direct` and `offline` are built-in choices rather than zones, so they are
/// always valid; anything else has to still have a config. A dead pin is
/// removed rather than ignored, or the program would stay bound to a network
/// that does not exist and fail silently on every launch.
/// (`docs/GOTCHAS.md` §11)
pub fn pin_is_valid(pinned: &str, zone_exists: impl Fn(&str) -> bool) -> bool {
    matches!(pinned, "" | "direct" | "offline") || zone_exists(pinned)
}

/// Is this container pin still worth honouring?
///
/// `sb:<name>` is a SANDBOX, not a container: its home lives in
/// `vpn-sandboxes` and is created on first use. It used to be checked as a
/// container, no directory named `sb:name` was ever found among the profiles,
/// and the pin was erased on the very next click — which meant "🔒 Своя
/// песочница — всегда" and "Песочница «X» — всегда" did not work at all.
/// (`docs/GOTCHAS.md` §11)
pub fn profile_pin_is_valid(pinned: &str, profile_exists: impl Fn(&str) -> bool) -> bool {
    match pinned {
        "" | MAIN | THROWAWAY => true,
        other => other.starts_with(SANDBOX_PREFIX) || profile_exists(other),
    }
}

// --- THE MENUS ---------------------------------------------------------------

/// One row of a kdialog `--menu`: the tag that comes back on stdout, and the
/// text shown next to it.
pub type Row = (String, String);

fn row(tag: &str, text: impl Into<String>) -> Row {
    (tag.to_owned(), text.into())
}

/// The network menu: every choice once "for this launch", then the same list
/// again as "Всегда: …".
///
/// One dialog rather than two steps, because pinning is worth exactly one
/// click. `current_container` is the label of the container that WOULD be used
/// — see [`container_label`].
pub fn net_menu(zones: &[String], pinned: &str, current_container: &str) -> Vec<Row> {
    let mut nets = vec![
        row("direct", "Прямой интернет (без VPN)"),
        row("offline", "Без сети"),
    ];
    for zone in zones {
        nets.push(row(zone, format!("VPN: {zone}")));
    }

    let mut menu = nets.clone();
    for (tag, text) in &nets {
        menu.push((format!("pin:{tag}"), format!("Всегда: {text}")));
    }
    menu.push(row(
        "__chooseprofile__",
        format!("⚙ Сменить контейнер (сейчас: {current_container})…"),
    ));
    if !pinned.is_empty() {
        menu.push(row(
            "unpin",
            format!("↺ Спрашивать сеть снова (закреплено: {pinned})"),
        ));
    }
    menu
}

/// How the container that is in force right now is described in that entry.
///
/// A PINNED container outranks the last choice here, and that is a fix: without
/// it the entry promised "сейчас: основной" while the program opened in the
/// pinned one — the menu disagreed with what actually happened.
pub fn container_label(selector: &str) -> String {
    match selector {
        "" | MAIN => "основной".to_owned(),
        THROWAWAY => "разовая песочница".to_owned(),
        other => match other.strip_prefix(SANDBOX_PREFIX) {
            Some(name) if name.starts_with("app-") => "своя песочница".to_owned(),
            Some(name) => format!("песочница {name}"),
            None => other.to_owned(),
        },
    }
}

/// A container directory as the menu shows it: its name, and the zone it is
/// open in (empty when it is free).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRow {
    pub name: String,
    pub busy_in: String,
}

/// A throwaway container that is already open: the directory to join, and the
/// programs living in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmpJoinRow {
    pub dir: String,
    /// The program names, each with the leading space the shell's
    /// `who="$who $(basename …)"` produced.
    pub who: String,
}

/// The container menu.
///
/// The filesystem sandbox is not a container but a separate property of a
/// launch — it is here because asking about it in a third dialog would be
/// tiring, and because "an isolated home" is what people are actually choosing
/// between when they think about containers.
///
/// The question is asked EVEN WHEN THERE ARE NO CONTAINERS YET. It used to be
/// shown only when one existed, and then there was no way to learn the feature
/// existed without reading the manual: the system quietly decided for you that
/// no container was needed. (`docs/GOTCHAS.md` §11)
pub fn profile_menu(
    sandboxes: &[String],
    profiles: &[ProfileRow],
    tmp_joins: &[TmpJoinRow],
    pinned_profile: &str,
    current_zone: &str,
) -> Vec<Row> {
    let mut menu = vec![
        row("", "Основной (общий с системой)"),
        row("pinmain", "Основной — всегда"),
        // A home of the program's own: permanent, but nobody else's. It differs
        // from a named sandbox only in that the name is picked automatically —
        // it is "an isolated profile by default", which can later be merged
        // with another program by choosing a shared named sandbox.
        row(
            "__ownsb__",
            "🔒 Своя песочница: постоянный дом только этой программы",
        ),
        row("pin:__ownsb__", "🔒 Своя песочница — всегда"),
        row(THROWAWAY, "🔒 Разовая песочница: стирается при выходе"),
        row("pin:__fs__", "🔒 Разовая песочница — всегда"),
    ];
    // Named sandboxes: the home is shared by everything started into the same
    // one, so two programs can work together without seeing your files.
    for name in sandboxes {
        menu.push((
            format!("{SANDBOX_PREFIX}{name}"),
            format!("🔒 Песочница «{name}»"),
        ));
        menu.push((
            format!("pin:{SANDBOX_PREFIX}{name}"),
            format!("🔒 Песочница «{name}» — всегда"),
        ));
    }
    menu.push(row("__newsb__", "🔒➕ Новая песочница…"));

    for profile in profiles {
        let name = &profile.name;
        if !profile.busy_in.is_empty() && profile.busy_in != current_zone {
            menu.push((
                name.clone(),
                format!("{name} — занят сетью {}", profile.busy_in),
            ));
        } else {
            menu.push((name.clone(), name.clone()));
        }
        menu.push((format!("pin:{name}"), format!("{name} — всегда")));
    }

    // Throwaway containers that are open right now — so a program can be put
    // into one that is already running (a shared one-off session) instead of
    // starting yet another.
    for join in tmp_joins {
        menu.push((
            format!("{TMPJOIN_PREFIX}{}", join.dir),
            format!("🗑 К открытому временному:{}", join.who),
        ));
    }
    menu.push(row(
        TMP,
        "🗑 Новый временный (сотрётся, когда выйдет последняя программа)",
    ));
    menu.push(row("__new__", "➕ Новый профиль…"));
    if !pinned_profile.is_empty() {
        menu.push(row("unpinprof", "↺ Спрашивать контейнер снова"));
    }
    menu
}

// --- WHAT CAME BACK ----------------------------------------------------------

/// The answer to the network dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetChoice {
    /// An empty answer. kdialog exits 0 with nothing on stdout when the menu
    /// was dismissed, and the shell checked for it separately.
    Nothing,
    ChooseContainer,
    Unpin,
    Pin(String),
    Zone(String),
}

pub fn parse_net_choice(tag: &str) -> NetChoice {
    match tag {
        "" => NetChoice::Nothing,
        "__chooseprofile__" => NetChoice::ChooseContainer,
        "unpin" => NetChoice::Unpin,
        other => match other.strip_prefix("pin:") {
            Some(zone) => NetChoice::Pin(zone.to_owned()),
            None => NetChoice::Zone(other.to_owned()),
        },
    }
}

/// The answer to the container dialog. `pin` means the choice is also written
/// to `.pinnedprofile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileChoice {
    Main { pin: bool },
    OwnSandbox { pin: bool },
    Throwaway { pin: bool },
    Sandbox { name: String, pin: bool },
    NewSandbox,
    Tmp,
    TmpJoin(String),
    NewProfile,
    Unpin,
    Profile { name: String, pin: bool },
}

/// Order matters and is the shell's `case` order: `pin:__ownsb__`,
/// `pin:sb:<name>` and `pin:__fs__` all have to be recognised before the plain
/// `pin:<container>` pattern would swallow them.
pub fn parse_profile_choice(tag: &str) -> ProfileChoice {
    match tag {
        "" => ProfileChoice::Main { pin: false },
        "pinmain" => ProfileChoice::Main { pin: true },
        "__ownsb__" => ProfileChoice::OwnSandbox { pin: false },
        "pin:__ownsb__" => ProfileChoice::OwnSandbox { pin: true },
        THROWAWAY => ProfileChoice::Throwaway { pin: false },
        "pin:__fs__" => ProfileChoice::Throwaway { pin: true },
        "__newsb__" => ProfileChoice::NewSandbox,
        TMP => ProfileChoice::Tmp,
        "__new__" => ProfileChoice::NewProfile,
        "unpinprof" => ProfileChoice::Unpin,
        other => {
            if let Some(name) = other.strip_prefix(SANDBOX_PREFIX) {
                return ProfileChoice::Sandbox {
                    name: name.to_owned(),
                    pin: false,
                };
            }
            if let Some(dir) = other.strip_prefix(TMPJOIN_PREFIX) {
                return ProfileChoice::TmpJoin(dir.to_owned());
            }
            match other.strip_prefix("pin:") {
                Some(rest) => match rest.strip_prefix(SANDBOX_PREFIX) {
                    Some(name) => ProfileChoice::Sandbox {
                        name: name.to_owned(),
                        pin: true,
                    },
                    None => ProfileChoice::Profile {
                        name: rest.to_owned(),
                        pin: true,
                    },
                },
                None => ProfileChoice::Profile {
                    name: other.to_owned(),
                    pin: false,
                },
            }
        }
    }
}

// --- THE COMMAND LINE THAT COMES OUT -----------------------------------------

/// `vpn-zone run <zone> [container flags] [sandbox flags] -- cmd…`
///
/// The order is the one [`crate::launch::Selection::parse`] expects: the
/// container flag first, the sandbox flag second, `--` and then the command.
pub fn run_argv(
    runner: &Path,
    zone: &str,
    container: &Container,
    cmd: &[OsString],
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![runner.into(), "run".into(), zone.into()];
    if let Some(dir) = container.profile.strip_prefix(TMPJOIN_PREFIX) {
        argv.push("--tmp-profile".into());
        argv.push("--join".into());
        argv.push(dir.into());
    } else if container.profile == TMP {
        argv.push("--tmp-profile".into());
    } else if !container.profile.is_empty() {
        argv.push("--profile".into());
        argv.push(container.profile.as_str().into());
    }
    if !container.sandbox.is_empty() {
        argv.push("--sandbox".into());
        argv.push(container.sandbox.as_str().into());
    } else if container.fs_sandbox {
        argv.push("--fs-sandbox".into());
    }
    argv.push("--".into());
    argv.extend(cmd.iter().cloned());
    argv
}

// --- THE PROGRAM -------------------------------------------------------------

/// Entry point of the `vpn-zone-pick` binary.
pub fn main() -> ExitCode {
    // `args_os`: a launcher hands file names through `%U` field codes, and file
    // names are bytes.
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args = Args::parse(&argv);
    if args.cmd.is_empty() {
        eprintln!("нечего запускать");
        return ExitCode::from(1);
    }

    let tools = match Tools::from_env() {
        Ok(tools) => tools,
        Err(e) => {
            eprintln!("vpn-zone-pick: {e}");
            return ExitCode::from(EXIT_TOOLS);
        }
    };
    for dir in [
        ".last",
        ".lastprofile",
        ".pinned",
        ".pinnedprofile",
        ".labels",
    ] {
        let _ = fs::create_dir_all(tools.state.join(dir));
    }
    let _ = fs::create_dir_all(&tools.config);

    let key = match &args.id {
        Some(id) => sanitize(&id.to_string_lossy()),
        None => sanitize(&fallback_key(&args.cmd).to_string_lossy()),
    };

    // The name for the dialogs: from the label the shortcut generator left, or
    // from `--label`, or the key itself.
    let label = match &args.label {
        Some(label) => {
            let text = label.to_string_lossy().into_owned();
            let _ = fs::write(tools.state.join(".labels").join(&key), &text);
            text
        }
        None => {
            read_setting(&tools.state.join(".labels").join(&key)).unwrap_or_else(|| key.clone())
        }
    };

    // Read the hand-over variable AT ONCE and take it out of the environment:
    // otherwise it would travel into the program itself, and a link opened from
    // there would inherit somebody else's container.
    let reprofile = std::env::var(ENV_PROFILE).ok().filter(|v| !v.is_empty());
    std::env::remove_var(ENV_PROFILE);

    let memory = read_memory(&tools, &key);
    let mut asksolo = false;
    let zone_choice: String;

    match net_step(&memory) {
        NetStep::Running { zone, selector } => {
            return launch(
                &tools,
                &key,
                &zone,
                &Container::from_selector(&selector),
                &args.cmd,
            );
        }
        NetStep::Pinned {
            zone,
            ask_container,
        } => {
            zone_choice = zone;
            asksolo = ask_container;
        }
        NetStep::Ask { default } => {
            let current = if memory.pinned_profile.is_empty() {
                &memory.last_profile
            } else {
                &memory.pinned_profile
            };
            let menu = net_menu(
                &zone_names(&tools.state),
                &memory.pinned,
                &container_label(current),
            );

            let answer = if launch::has_display() {
                let mut argv: Vec<OsString> = vec![
                    "--title".into(),
                    format!("Куда пустить «{label}»?").into(),
                    "--default".into(),
                    default.as_str().into(),
                    "--menu".into(),
                    "Выбери сеть для запуска".into(),
                ];
                push_rows(&mut argv, &menu);
                match dialog::ask(&tools.kdialog, &argv) {
                    Some(answer) => answer,
                    // Cancelled: the launch is over, and quietly.
                    None => return ExitCode::SUCCESS,
                }
            } else {
                // Nowhere to show a dialog: kdialog dies immediately, and
                // taking that for a cancel turned a click (or a launch from a
                // terminal) into silence. Take what WOULD have been selected —
                // the last choice, or the global default.
                // (`docs/GOTCHAS.md` §5)
                eprintln!("vpn-zone-pick: спросить негде (нет графики) — беру «{default}»");
                default.clone()
            };

            match parse_net_choice(&answer) {
                NetChoice::Nothing => return ExitCode::SUCCESS,
                NetChoice::ChooseContainer => {
                    // The container is asked here and the network question is
                    // then asked again by a second pass of this same binary.
                    let Some(container) =
                        ask_profile(&tools, &key, &label, "__chooseprofile__", &memory)
                    else {
                        return ExitCode::SUCCESS;
                    };
                    let selector = container.selector();
                    if !container.is_throwaway_container() {
                        remember(&tools.state, ".lastprofile", &key, &selector);
                    }
                    // The choice is handed over in a VARIABLE as well as in the
                    // file. A one-off container is not written to `.lastprofile`
                    // (that would make it permanent) and used to be lost
                    // completely across the re-exec: the user chose "🗑 Новый
                    // временный" and the program quietly opened in the previous,
                    // permanent container. For a sandbox that is a loss of
                    // isolation, not a detail. An empty choice ("Основной")
                    // travels as `__main__`: an empty string cannot be told
                    // apart from "not set".
                    let handover = if selector.is_empty() {
                        MAIN.to_owned()
                    } else {
                        selector
                    };
                    return reexec(&tools, &key, &args.cmd, Some(&handover));
                }
                NetChoice::Unpin => {
                    let _ = fs::remove_file(tools.state.join(".pinned").join(&key));
                    return reexec(&tools, &key, &args.cmd, None);
                }
                NetChoice::Pin(zone) => {
                    remember(&tools.state, ".pinned", &key, &zone);
                    zone_choice = zone;
                }
                NetChoice::Zone(zone) => zone_choice = zone,
            }
            remember(&tools.state, ".last", &key, &zone_choice);
        }
    }

    // The second question — the container. It is not asked when one is pinned
    // separately or set globally (`vpn-zone default-profile`).
    let container = if asksolo {
        let Some(container) = ask_profile(&tools, &key, &label, &zone_choice, &memory) else {
            return ExitCode::SUCCESS;
        };
        if !container.is_throwaway_container() {
            remember(&tools.state, ".lastprofile", &key, &container.selector());
        }
        container
    } else {
        let profiles = tools.profiles.clone();
        container_without_dialog(
            &memory,
            &key,
            |name| profiles.join(name).is_dir(),
            reprofile.as_deref(),
        )
    };

    launch(&tools, &key, &zone_choice, &container, &args.cmd)
}

/// Read the three levels of memory, dropping the pins that have gone stale.
fn read_memory(tools: &Tools, key: &str) -> Memory {
    let state = &tools.state;
    let pinned_path = state.join(".pinned").join(key);
    let mut pinned = read_setting(&pinned_path).unwrap_or_default();
    if !pin_is_valid(&pinned, |zone| {
        state.join(zone).join("config.conf").is_file()
    }) {
        let _ = fs::remove_file(&pinned_path);
        pinned.clear();
    }

    let profile_pin_path = state.join(".pinnedprofile").join(key);
    let mut pinned_profile = read_setting(&profile_pin_path).unwrap_or_default();
    if !profile_pin_is_valid(&pinned_profile, |name| tools.profiles.join(name).is_dir()) {
        let _ = fs::remove_file(&profile_pin_path);
        pinned_profile.clear();
    }

    Memory {
        running: running_record(state, key),
        pinned,
        pinned_profile,
        last: read_setting(&state.join(".last").join(key)).unwrap_or_default(),
        last_profile: read_setting(&state.join(".lastprofile").join(key)).unwrap_or_default(),
        fallback: read_setting(&tools.config.join("default"))
            .unwrap_or_else(|| "offline".to_owned()),
        default_profile: read_setting(&tools.config.join("default-profile"))
            .unwrap_or_else(|| "ask".to_owned()),
        ask: std::env::var_os(ENV_ASK).is_some_and(|v| !v.is_empty()),
    }
}

/// Where is this program running right now? The first live record found, over
/// every container's registry directory.
fn running_record(state: &Path, key: &str) -> Option<Running> {
    for dir in registry::dirs(&state.join(".running")) {
        let Ok(text) = fs::read_to_string(dir.join(key)) else {
            continue;
        };
        if let Some(record) = text
            .lines()
            .filter_map(registry::parse_record)
            .find(|r| proc_is_alive(r.pid))
        {
            return Some(Running {
                zone: record.zone,
                selector: record.selector,
            });
        }
    }
    None
}

/// The zones that can be started into: a directory with a config in it.
/// `offline` is skipped even though it has no config — it is a built-in choice
/// of the menu, listed above the zones. (`docs/GOTCHAS.md` §2)
fn zone_names(state: &Path) -> Vec<String> {
    visible_entries(state)
        .into_iter()
        .filter(|dir| dir.join("config.conf").is_file())
        .filter_map(|dir| dir.file_name().map(|n| n.to_string_lossy().into_owned()))
        .filter(|name| name != "offline")
        .collect()
}

/// Names of the directories a menu may show: sorted, dot-files skipped, and
/// nothing starting with a dash.
///
/// A name starting with `-` is taken by kdialog for an option and the dialog
/// closes without a single word. Such names cannot be created any more, but a
/// directory may have survived from an older version — it is simply not shown.
/// (`docs/GOTCHAS.md` §11)
fn menu_names(dir: &Path) -> Vec<String> {
    visible_entries(dir)
        .into_iter()
        .filter(|path| path.is_dir())
        .filter_map(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
        .filter(|name| !name.starts_with('-'))
        .collect()
}

/// The second dialog: which container (or sandbox) to open the program in.
///
/// `None` means the user cancelled and the launch is over. `current_zone` is
/// what a container being open in ANOTHER network is compared against.
fn ask_profile(
    tools: &Tools,
    key: &str,
    label: &str,
    current_zone: &str,
    memory: &Memory,
) -> Option<Container> {
    // The global "do not ask" setting: `main` is always the main profile, a
    // name is always that container. Set by the settings shortcut or by
    // `vpn-zone default-profile`.
    match memory.default_profile.as_str() {
        "ask" => {}
        "main" => return Some(Container::default()),
        "own" => return Some(Container::own_sandbox(key)),
        name => {
            if tools.profiles.join(name).is_dir() {
                return Some(Container {
                    profile: name.to_owned(),
                    ..Container::default()
                });
            }
        }
    }

    if !launch::has_display() {
        // Same reason as the network dialog above: without a graphical session
        // kdialog dies and `|| exit 0` took that for a cancel, so a launch from
        // a terminal or from a unit ended in nothing at all. Take the last
        // choice and let the program start.
        let profiles = tools.profiles.clone();
        return Some(Container::from_selector_checked(
            &memory.last_profile,
            |n| profiles.join(n).is_dir(),
        ));
    }

    let sandboxes = menu_names(&tools.sandboxes);
    let running = tools.state.join(".running");
    let profiles: Vec<ProfileRow> = menu_names(&tools.profiles)
        .into_iter()
        .map(|name| {
            let busy_in = live_tenant(&tools.profiles.join(&name).join("inuse"))
                .or_else(|| registry::live_zone(&running.join(&name), &proc_is_alive))
                .unwrap_or_default();
            ProfileRow { name, busy_in }
        })
        .collect();
    let tmp_joins = open_throwaways(&running);

    let mut argv: Vec<OsString> = vec![
        "--title".into(),
        format!("Профиль для «{label}»").into(),
        "--default".into(),
        memory.last_profile.as_str().into(),
        "--menu".into(),
        "В каком профиле открыть? Профиль хранит настройки, сессии и логины отдельно от системных"
            .into(),
    ];
    push_rows(
        &mut argv,
        &profile_menu(
            &sandboxes,
            &profiles,
            &tmp_joins,
            &memory.pinned_profile,
            current_zone,
        ),
    );
    let answer = dialog::ask(&tools.kdialog, &argv)?;

    let pin = |selector: &str| remember(&tools.state, ".pinnedprofile", key, selector);
    match parse_profile_choice(&answer) {
        ProfileChoice::Main { pin: false } => Some(Container::default()),
        ProfileChoice::Main { pin: true } => {
            // "Основной — всегда": pinned separately from the network.
            pin(MAIN);
            Some(Container::default())
        }
        ProfileChoice::OwnSandbox { pin: want } => {
            if want {
                pin(&format!("{SANDBOX_PREFIX}app-{key}"));
            }
            Some(Container::own_sandbox(key))
        }
        ProfileChoice::Throwaway { pin: want } => {
            if want {
                pin(THROWAWAY);
            }
            Some(Container {
                fs_sandbox: true,
                ..Container::default()
            })
        }
        ProfileChoice::Sandbox { name, pin: want } => {
            if want {
                pin(&format!("{SANDBOX_PREFIX}{name}"));
            }
            Some(Container {
                fs_sandbox: true,
                sandbox: name,
                ..Container::default()
            })
        }
        ProfileChoice::NewSandbox => {
            let name = dialog::ask(
                &tools.kdialog,
                [
                    "--title",
                    "Новая песочница",
                    "--inputbox",
                    "Название песочницы. У неё будет свой пустой дом, общий для всех программ, которые ты в ней запустишь.",
                    "",
                ],
            )?;
            let name = sanitize_name(&name);
            if name.is_empty() {
                return Some(Container::default());
            }
            // A creation that fails (no space, no permission) must not kill the
            // picker: that used to happen silently, AFTER every dialog had been
            // answered — the user answered the questions and the program did not
            // start. It did not work out: into the main profile, but GO.
            create(tools, "sandbox", &name);
            if !tools.sandboxes.join(&name).is_dir() {
                return Some(Container::default());
            }
            Some(Container {
                fs_sandbox: true,
                sandbox: name,
                ..Container::default()
            })
        }
        ProfileChoice::Tmp => Some(Container {
            profile: TMP.to_owned(),
            ..Container::default()
        }),
        ProfileChoice::TmpJoin(dir) => Some(Container {
            profile: format!("{TMPJOIN_PREFIX}{dir}"),
            ..Container::default()
        }),
        ProfileChoice::Unpin => {
            let _ = fs::remove_file(tools.state.join(".pinnedprofile").join(key));
            Some(Container::default())
        }
        ProfileChoice::NewProfile => {
            let name = dialog::ask(
                &tools.kdialog,
                [
                    "--title",
                    "Новый профиль",
                    "--inputbox",
                    "Название профиля (буквы, цифры, дефис):",
                    "",
                ],
            )?;
            // Only what actually gets in the way is cleaned (paths, spaces,
            // quotes) and a leading dash is cut off — Cyrillic stays Cyrillic.
            let name = sanitize_name(&name);
            if name.is_empty() {
                return Some(Container::default());
            }
            // The same trap as the sandbox above: without swallowing the error
            // the picker died after all the dialogs, and with a container that
            // does not exist `vpn-zone run` would honestly refuse to start.
            create(tools, "profile", &name);
            if !tools.profiles.join(&name).is_dir() {
                return Some(Container::default());
            }
            Some(Container {
                profile: name,
                ..Container::default()
            })
        }
        ProfileChoice::Profile { name, pin: want } => {
            if want {
                pin(&name);
            }
            Some(Container {
                profile: name,
                ..Container::default()
            })
        }
    }
}

/// `vpn-zone <kind> create <name>`, failures and all output swallowed: the
/// caller checks whether the directory appeared, which is the only answer that
/// matters here.
fn create(tools: &Tools, kind: &str, name: &str) {
    let _ = Command::new(&tools.runner)
        .arg(kind)
        .arg("create")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// The zone named by the first live line of a container's `inuse` file.
///
/// That file is a leftover of an older version and nothing writes it any more,
/// which is why "занят сетью …" never actually appeared in this menu. It is
/// still read (a container from that era may carry one), and the launch
/// registry — the same source `vpn-zone profile list` and the container removal
/// dialog use — answers the question for everything else.
fn live_tenant(inuse: &Path) -> Option<String> {
    let text = fs::read_to_string(inuse).ok()?;
    text.lines()
        .filter_map(registry::parse_record)
        .find(|record| proc_is_alive(record.pid))
        .map(|record| record.zone)
        .filter(|zone| !zone.is_empty())
}

/// The throwaway containers that are open right now: a registry directory named
/// `vpn-profile-*` whose `/tmp` directory still exists and which has at least
/// one live tenant.
fn open_throwaways(running: &Path) -> Vec<TmpJoinRow> {
    let mut out = Vec::new();
    for dir in registry::dirs(running) {
        let Some(name) = dir.file_name() else {
            continue;
        };
        if !name.as_bytes().starts_with(b"vpn-profile-") {
            continue;
        }
        let tmp = PathBuf::from("/tmp").join(name);
        if !tmp.is_dir() {
            continue;
        }
        let mut who = String::new();
        for file in visible_entries(&dir) {
            if !file.is_file() {
                continue;
            }
            // Only the FIRST line of each file is looked at, as the shell's
            // `while read … break` did: one program, one answer.
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            let alive = text
                .lines()
                .next()
                .and_then(registry::parse_record)
                .is_some_and(|record| proc_is_alive(record.pid));
            if alive {
                who.push(' ');
                who.push_str(&file.file_name().unwrap_or_default().to_string_lossy());
            }
        }
        if !who.is_empty() {
            out.push(TmpJoinRow {
                dir: tmp.to_string_lossy().into_owned(),
                who,
            });
        }
    }
    out
}

/// Append a menu to a kdialog command line: tag, text, tag, text…
fn push_rows(argv: &mut Vec<OsString>, rows: &[Row]) {
    for (tag, text) in rows {
        argv.push(tag.as_str().into());
        argv.push(text.as_str().into());
    }
}

/// Write one of the memory files (`printf '%s'`: no trailing newline).
///
/// A failure is reported and stepped over rather than fatal: the launch matters
/// more than the memory of it, and this runs after every dialog has been
/// answered.
fn remember(state: &Path, sub: &str, key: &str, value: &str) {
    let path = state.join(sub).join(key);
    if let Err(e) = fs::write(&path, value) {
        eprintln!("vpn-zone-pick: не записать {}: {e}", path.display());
    }
}

/// Start the second pass of the picker: the same binary, with the answer
/// already given carried in the environment.
///
/// `/proc/self/exe` rather than the profile path on purpose — this is the same
/// binary asking itself a second question, and during a home-manager switch the
/// profile path may already point at the next generation. The environment
/// (including `VPN_ZONE_TOOLS`) is inherited as it is.
fn reexec(tools: &Tools, key: &str, cmd: &[OsString], handover: Option<&str>) -> ExitCode {
    std::env::set_var(ENV_ASK, "1");
    match handover {
        Some(selector) => std::env::set_var(ENV_PROFILE, selector),
        // Already removed at startup; make sure a second pass cannot inherit a
        // stale one.
        None => std::env::remove_var(ENV_PROFILE),
    }
    let me = fs::read_link("/proc/self/exe")
        .ok()
        .filter(|path| path.is_file())
        .unwrap_or_else(|| tools.picker.clone());
    let mut argv: Vec<OsString> = vec![me.clone().into(), "--id".into(), key.into(), "--".into()];
    argv.extend(cmd.iter().cloned());
    let e = exec_command(&argv);
    eprintln!("не удалось запустить {}: {e}", me.display());
    ExitCode::from(EXIT_NOT_STARTED)
}

/// Become the launch. Returns only when the `execvp` failed.
fn launch(
    tools: &Tools,
    key: &str,
    zone_choice: &str,
    container: &Container,
    cmd: &[OsString],
) -> ExitCode {
    // The shortcut's key is also the app-id the compositor restriction and the
    // sandbox permissions are keyed by. (`docs/GOTCHAS.md` §6, §7)
    std::env::set_var(launch::ENV_APPID, key);

    let zone = match zone_choice {
        "direct" => {
            // From inside a zone "direct" would not be direct at all: the
            // process would inherit its network. Ask systemd to start it
            // outside, the way `vpn-zone run` delegates. (`docs/GOTCHAS.md` §13)
            let argv: Vec<OsString> =
                if std::env::var_os(launch::ENV_CURRENT).is_some_and(|v| !v.is_empty()) {
                    let mut argv: Vec<OsString> = vec![tools.systemd_run.clone().into()];
                    argv.extend([
                        "--user".into(),
                        "--quiet".into(),
                        "--collect".into(),
                        "--".into(),
                    ]);
                    argv.extend(cmd.iter().cloned());
                    argv
                } else {
                    cmd.to_vec()
                };
            let e = exec_command(&argv);
            eprintln!("не удалось запустить {}: {e}", argv[0].to_string_lossy());
            return ExitCode::from(EXIT_NOT_STARTED);
        }
        "offline" => {
            // A zone with no network is created on demand — there is nothing to
            // keep in a config, it is an empty namespace. (`docs/GOTCHAS.md` §2)
            let dir = tools.state.join("offline");
            if !dir.is_dir() {
                let _ = fs::create_dir_all(&dir);
                let _ = fs::write(dir.join("offline"), b"");
            }
            "offline"
        }
        other => other,
    };

    let argv = run_argv(&tools.runner, zone, container, cmd);
    let e = exec_command(&argv);
    eprintln!("не удалось запустить {}: {e}", tools.runner.display());
    ExitCode::from(EXIT_NOT_STARTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn tags(rows: &[Row]) -> Vec<&str> {
        rows.iter().map(|(tag, _)| tag.as_str()).collect()
    }

    fn text_of<'a>(rows: &'a [Row], tag: &str) -> &'a str {
        rows.iter()
            .find(|(t, _)| t == tag)
            .map(|(_, text)| text.as_str())
            .unwrap_or_else(|| panic!("нет пункта «{tag}»"))
    }

    fn nothing(_: &str) -> bool {
        false
    }

    fn anything(_: &str) -> bool {
        true
    }

    // --- ARGUMENTS -----------------------------------------------------------

    #[test]
    fn the_shortcut_form_is_id_then_command() {
        let a = Args::parse(&argv(&["--id", "org.kde.dolphin", "--", "dolphin", "%u"]));
        assert_eq!(a.id.as_deref(), Some(OsStr::new("org.kde.dolphin")));
        assert_eq!(a.label, None);
        assert_eq!(a.cmd, argv(&["dolphin", "%u"]));

        let a = Args::parse(&argv(&["--id", "x", "--label", "Зен", "--", "zen"]));
        assert_eq!(a.label.as_deref(), Some(OsStr::new("Зен")));
        assert_eq!(a.cmd, argv(&["zen"]));
    }

    #[test]
    fn a_leading_label_is_only_taken_when_a_separator_follows() {
        // The old shortcut format: shortcuts and the picker do not update
        // atomically, so both shapes have to parse.
        let a = Args::parse(&argv(&["AyuGram Desktop", "--", "env", "X=1", "AyuGram"]));
        assert_eq!(a.label.as_deref(), Some(OsStr::new("AyuGram Desktop")));
        assert_eq!(a.cmd, argv(&["env", "X=1", "AyuGram"]));

        // No `--` anywhere: the first word is the COMMAND and must not be eaten.
        let a = Args::parse(&argv(&["firefox", "--new-window"]));
        assert_eq!(a.label, None);
        assert_eq!(a.cmd, argv(&["firefox", "--new-window"]));

        // `--label` still wins over a positional one.
        let a = Args::parse(&argv(&["Старое", "--label", "Новое", "--", "x"]));
        assert_eq!(a.label.as_deref(), Some(OsStr::new("Новое")));
    }

    #[test]
    fn a_command_can_be_given_without_the_separator() {
        let a = Args::parse(&argv(&["--id", "x", "firefox"]));
        assert_eq!(a.cmd, argv(&["firefox"]));
        // Nothing at all is the "нечего запускать" case.
        assert!(Args::parse(&[]).cmd.is_empty());
        assert!(Args::parse(&argv(&["--id", "x", "--"])).cmd.is_empty());
        // A flag with no value is not a crash and not a key.
        assert_eq!(Args::parse(&argv(&["--id"])).id, None);
    }

    #[test]
    fn the_fallback_key_walks_past_wrappers_and_assignments() {
        assert_eq!(
            fallback_key(&argv(&["env", "DESKTOPINTEGRATION=1", "AyuGram"])),
            OsString::from("AyuGram")
        );
        assert_eq!(
            fallback_key(&argv(&["/nix/store/x/bin/firefox", "--new-window"])),
            OsString::from("firefox")
        );
        // One more wrapper than `launch::app_word` knows: a delegated launch is
        // keyed by the program, not by systemd-run.
        assert_eq!(
            fallback_key(&argv(&["systemd-run", "--user", "telegram-desktop"])),
            OsString::from("telegram-desktop")
        );
        // `sh -c '…'`: the whole word, not skipped, or the key would be empty.
        assert_eq!(
            fallback_key(&argv(&["sh", "-c", "exec foo --url=https://x"])),
            OsString::from("x")
        );
        // Nothing recognisable at all still yields a key.
        assert_eq!(fallback_key(&argv(&["env"])), OsString::from("программа"));
        assert_eq!(fallback_key(&[]), OsString::from("программа"));
    }

    #[test]
    fn a_typed_name_keeps_its_cyrillic_and_loses_what_breaks_a_dialog() {
        assert_eq!(sanitize_name("личное"), "личное");
        assert_eq!(sanitize_name("два слова"), "два_слова");
        assert_eq!(sanitize_name("a/b\"c'd`e\\f"), "a_b_c_d_e_f");
        // A leading dash makes kdialog take the argument for an option and
        // close without a word.
        assert_eq!(sanitize_name("-x"), "x");
        assert_eq!(sanitize_name("..-.-a"), "a");
        assert_eq!(sanitize_name("---"), "");
        assert_eq!(sanitize_name(""), "");
    }

    // --- THE DECISION MACHINE ------------------------------------------------

    fn memory() -> Memory {
        Memory {
            fallback: "offline".to_owned(),
            default_profile: "ask".to_owned(),
            ..Memory::default()
        }
    }

    #[test]
    fn a_running_program_is_started_where_it_already_runs() {
        let mut m = memory();
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: "sb:work".to_owned(),
        });
        // Even a pin does not get a say: the window is going to be raised by the
        // process that is already up.
        m.pinned = "de".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Running {
                zone: "nl".to_owned(),
                selector: "sb:work".to_owned()
            }
        );
        // VPN_ZONE_ASK is the way past it — that is what the re-exec sets.
        m.ask = true;
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "offline".to_owned()
            }
        );
    }

    #[test]
    fn a_pinned_network_asks_about_the_container_only_when_it_is_free() {
        let mut m = memory();
        m.pinned = "nl".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Pinned {
                zone: "nl".to_owned(),
                ask_container: true
            }
        );
        // Pinned separately: nothing left to ask.
        m.pinned_profile = "work".to_owned();
        assert!(matches!(
            net_step(&m),
            NetStep::Pinned {
                ask_container: false,
                ..
            }
        ));
        // Set globally: same.
        m.pinned_profile.clear();
        m.default_profile = "main".to_owned();
        assert!(matches!(
            net_step(&m),
            NetStep::Pinned {
                ask_container: false,
                ..
            }
        ));
    }

    #[test]
    fn without_a_pin_the_dialog_opens_on_the_last_choice_then_the_default() {
        let mut m = memory();
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "offline".to_owned()
            }
        );
        m.fallback = "direct".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "direct".to_owned()
            }
        );
        m.last = "nl".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "nl".to_owned()
            }
        );
    }

    #[test]
    fn a_selector_is_read_back_into_the_three_variables() {
        assert_eq!(Container::from_selector(""), Container::default());
        assert_eq!(Container::from_selector(MAIN), Container::default());
        assert_eq!(
            Container::from_selector("__fs__"),
            Container {
                fs_sandbox: true,
                ..Container::default()
            }
        );
        assert_eq!(
            Container::from_selector("sb:work"),
            Container {
                fs_sandbox: true,
                sandbox: "work".to_owned(),
                ..Container::default()
            }
        );
        // A per-app sandbox is an ordinary named one under the covers.
        assert_eq!(
            Container::from_selector("sb:app-firefox").sandbox,
            "app-firefox"
        );
        assert_eq!(
            Container::from_selector("work"),
            Container {
                profile: "work".to_owned(),
                ..Container::default()
            }
        );
        // Checked: a container that has been deleted falls back to the main
        // profile instead of a launch that cannot work.
        assert_eq!(
            Container::from_selector_checked("work", nothing),
            Container::default()
        );
        assert_eq!(
            Container::from_selector_checked("work", anything).profile,
            "work"
        );
    }

    #[test]
    fn the_selector_that_is_written_back_is_the_choice_not_the_variable() {
        let sandbox = Container {
            fs_sandbox: true,
            sandbox: "work".to_owned(),
            ..Container::default()
        };
        assert_eq!(sandbox.selector(), "sb:work");
        assert_eq!(
            Container {
                fs_sandbox: true,
                ..Container::default()
            }
            .selector(),
            "__fs__"
        );
        assert_eq!(Container::default().selector(), "");
        assert_eq!(
            Container {
                profile: "work".to_owned(),
                ..Container::default()
            }
            .selector(),
            "work"
        );
        // And it round-trips, which is what makes the re-exec faithful.
        assert_eq!(Container::from_selector(&sandbox.selector()), sandbox);
        // One-off containers are never remembered.
        for profile in [TMP, "tmpjoin:/tmp/vpn-profile-abc"] {
            let c = Container {
                profile: profile.to_owned(),
                ..Container::default()
            };
            assert!(c.is_throwaway_container(), "{profile}");
        }
        assert!(!Container::default().is_throwaway_container());
        assert!(!sandbox.is_throwaway_container());
    }

    #[test]
    fn the_fresh_choice_outranks_the_pin_and_the_pin_outranks_the_memory() {
        let mut m = memory();
        m.pinned_profile = "pinned".to_owned();
        m.last_profile = "last".to_owned();

        // 1. What "⚙ Сменить контейнер" just answered. Including a throwaway
        //    one, which is exactly what used to be lost across the re-exec.
        assert_eq!(
            container_without_dialog(&m, "k", anything, Some(TMP)).profile,
            TMP
        );
        assert_eq!(
            container_without_dialog(&m, "k", anything, Some(MAIN)),
            Container::default()
        );
        // An empty variable is "not set", not "main".
        assert_eq!(
            container_without_dialog(&m, "k", anything, Some("")).profile,
            "pinned"
        );

        // 2. The pin — and with ASK set, too: that is the fix for "↺ Спрашивать
        //    сеть снова" dropping a pinned container into the main profile.
        m.ask = true;
        assert_eq!(
            container_without_dialog(&m, "k", anything, None).profile,
            "pinned"
        );
        m.ask = false;

        // 3. The last choice, when nothing is pinned.
        m.pinned_profile.clear();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None).profile,
            "last"
        );
    }

    #[test]
    fn the_global_default_container_is_laid_over_the_last_choice() {
        let mut m = memory();
        m.last_profile = "last".to_owned();

        m.default_profile = "main".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None),
            Container::default()
        );

        m.default_profile = "own".to_owned();
        assert_eq!(
            container_without_dialog(&m, "firefox", anything, None),
            Container {
                fs_sandbox: true,
                sandbox: "app-firefox".to_owned(),
                ..Container::default()
            }
        );

        m.default_profile = "work".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None).profile,
            "work"
        );
        // A default naming a container that is gone leaves the last choice
        // alone, as the shell's `[ -d … ] && profile=$defp` did.
        m.default_profile = "gone".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", |name| name == "last", None).profile,
            "last"
        );
    }

    #[test]
    fn a_remembered_sandbox_survives_a_named_default_container() {
        // The overlay is partial on purpose: `main` and a named default clear
        // the container only, so the sandbox flags stay as they were.
        let mut m = memory();
        m.last_profile = "sb:work".to_owned();
        m.default_profile = "main".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None),
            Container {
                fs_sandbox: true,
                sandbox: "work".to_owned(),
                ..Container::default()
            }
        );
    }

    #[test]
    fn a_pin_is_dropped_only_when_what_it_names_is_gone() {
        assert!(pin_is_valid("", nothing));
        // Built-in choices are not zones and are always valid.
        assert!(pin_is_valid("direct", nothing));
        assert!(pin_is_valid("offline", nothing));
        assert!(pin_is_valid("nl", |z| z == "nl"));
        assert!(!pin_is_valid("nl", nothing));

        // A pinned SANDBOX is not a container and must not be looked for among
        // them: checking it as one erased the pin on the next click, and
        // "🔒 Своя песочница — всегда" never worked at all.
        assert!(profile_pin_is_valid("sb:work", nothing));
        assert!(profile_pin_is_valid("sb:app-firefox", nothing));
        assert!(profile_pin_is_valid(THROWAWAY, nothing));
        assert!(profile_pin_is_valid(MAIN, nothing));
        assert!(profile_pin_is_valid("", nothing));
        assert!(profile_pin_is_valid("work", |p| p == "work"));
        assert!(!profile_pin_is_valid("work", nothing));
    }

    // --- THE MENUS -----------------------------------------------------------

    #[test]
    fn the_network_menu_offers_every_choice_twice_once_as_a_pin() {
        let menu = net_menu(&["de".to_owned(), "nl".to_owned()], "", "основной");
        assert_eq!(
            tags(&menu),
            [
                "direct",
                "offline",
                "de",
                "nl",
                "pin:direct",
                "pin:offline",
                "pin:de",
                "pin:nl",
                "__chooseprofile__",
            ]
        );
        assert_eq!(text_of(&menu, "nl"), "VPN: nl");
        assert_eq!(text_of(&menu, "pin:nl"), "Всегда: VPN: nl");
        assert_eq!(
            text_of(&menu, "__chooseprofile__"),
            "⚙ Сменить контейнер (сейчас: основной)…"
        );
        // The way back out of a pin is only offered when there is one.
        let menu = net_menu(&[], "nl", "основной");
        assert_eq!(
            text_of(&menu, "unpin"),
            "↺ Спрашивать сеть снова (закреплено: nl)"
        );
    }

    #[test]
    fn the_container_in_force_is_named_the_way_the_user_chose_it() {
        assert_eq!(container_label(""), "основной");
        assert_eq!(container_label(MAIN), "основной");
        assert_eq!(container_label(THROWAWAY), "разовая песочница");
        assert_eq!(container_label("sb:app-firefox"), "своя песочница");
        assert_eq!(container_label("sb:work"), "песочница work");
        assert_eq!(container_label("work"), "work");
    }

    #[test]
    fn the_container_menu_lists_the_ways_to_split_data_and_the_ways_to_pin_them() {
        let profiles = vec![
            ProfileRow {
                name: "work".to_owned(),
                busy_in: "de".to_owned(),
            },
            ProfileRow {
                name: "личное".to_owned(),
                busy_in: String::new(),
            },
        ];
        let joins = vec![TmpJoinRow {
            dir: "/tmp/vpn-profile-abc".to_owned(),
            who: " firefox telegram".to_owned(),
        }];
        let menu = profile_menu(&["общая".to_owned()], &profiles, &joins, "", "nl");
        assert_eq!(
            tags(&menu),
            [
                "",
                "pinmain",
                "__ownsb__",
                "pin:__ownsb__",
                "__fs__",
                "pin:__fs__",
                "sb:общая",
                "pin:sb:общая",
                "__newsb__",
                "work",
                "pin:work",
                "личное",
                "pin:личное",
                "tmpjoin:/tmp/vpn-profile-abc",
                "__tmp__",
                "__new__",
            ]
        );
        assert_eq!(text_of(&menu, "sb:общая"), "🔒 Песочница «общая»");
        assert_eq!(text_of(&menu, "work"), "work — занят сетью de");
        assert_eq!(text_of(&menu, "личное"), "личное");
        assert_eq!(
            text_of(&menu, "tmpjoin:/tmp/vpn-profile-abc"),
            "🗑 К открытому временному: firefox telegram"
        );
        // Busy in the network we are about to use is not "busy" at all.
        let menu = profile_menu(&[], &profiles, &[], "", "de");
        assert_eq!(text_of(&menu, "work"), "work");
        // The way back out of a container pin, when there is one.
        let menu = profile_menu(&[], &[], &[], "sb:work", "nl");
        assert_eq!(text_of(&menu, "unpinprof"), "↺ Спрашивать контейнер снова");
    }

    // --- WHAT CAME BACK ------------------------------------------------------

    #[test]
    fn the_network_answers_are_told_apart() {
        assert_eq!(parse_net_choice(""), NetChoice::Nothing);
        assert_eq!(parse_net_choice("nl"), NetChoice::Zone("nl".to_owned()));
        assert_eq!(
            parse_net_choice("pin:offline"),
            NetChoice::Pin("offline".to_owned())
        );
        assert_eq!(parse_net_choice("unpin"), NetChoice::Unpin);
        assert_eq!(
            parse_net_choice("__chooseprofile__"),
            NetChoice::ChooseContainer
        );
    }

    #[test]
    fn the_container_answers_are_told_apart_pins_first() {
        use ProfileChoice as P;
        assert_eq!(parse_profile_choice(""), P::Main { pin: false });
        assert_eq!(parse_profile_choice("pinmain"), P::Main { pin: true });
        assert_eq!(
            parse_profile_choice("__ownsb__"),
            P::OwnSandbox { pin: false }
        );
        assert_eq!(
            parse_profile_choice("pin:__ownsb__"),
            P::OwnSandbox { pin: true }
        );
        assert_eq!(parse_profile_choice("__fs__"), P::Throwaway { pin: false });
        assert_eq!(
            parse_profile_choice("pin:__fs__"),
            P::Throwaway { pin: true }
        );
        assert_eq!(
            parse_profile_choice("sb:work"),
            P::Sandbox {
                name: "work".to_owned(),
                pin: false
            }
        );
        // The trap: `pin:sb:work` must not be read as a container called
        // `sb:work`.
        assert_eq!(
            parse_profile_choice("pin:sb:work"),
            P::Sandbox {
                name: "work".to_owned(),
                pin: true
            }
        );
        assert_eq!(parse_profile_choice("__newsb__"), P::NewSandbox);
        assert_eq!(parse_profile_choice("__new__"), P::NewProfile);
        assert_eq!(parse_profile_choice("__tmp__"), P::Tmp);
        assert_eq!(
            parse_profile_choice("tmpjoin:/tmp/vpn-profile-abc"),
            P::TmpJoin("/tmp/vpn-profile-abc".to_owned())
        );
        assert_eq!(parse_profile_choice("unpinprof"), P::Unpin);
        assert_eq!(
            parse_profile_choice("work"),
            P::Profile {
                name: "work".to_owned(),
                pin: false
            }
        );
        assert_eq!(
            parse_profile_choice("pin:work"),
            P::Profile {
                name: "work".to_owned(),
                pin: true
            }
        );
    }

    // --- THE COMMAND LINE ----------------------------------------------------

    #[test]
    fn the_launch_line_is_built_in_the_order_run_parses_it() {
        let runner = Path::new("/p/bin/vpn-zone");
        let cmd = argv(&["firefox", "%U"]);

        assert_eq!(
            run_argv(runner, "nl", &Container::default(), &cmd),
            argv(&["/p/bin/vpn-zone", "run", "nl", "--", "firefox", "%U"])
        );
        assert_eq!(
            run_argv(
                runner,
                "nl",
                &Container {
                    profile: "work".to_owned(),
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "nl",
                "--profile",
                "work",
                "--",
                "firefox",
                "%U"
            ])
        );
        assert_eq!(
            run_argv(
                runner,
                "offline",
                &Container {
                    fs_sandbox: true,
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "offline",
                "--fs-sandbox",
                "--",
                "firefox",
                "%U"
            ])
        );
        // A named sandbox replaces the throwaway flag rather than joining it.
        assert_eq!(
            run_argv(
                runner,
                "nl",
                &Container {
                    fs_sandbox: true,
                    sandbox: "work".to_owned(),
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "nl",
                "--sandbox",
                "work",
                "--",
                "firefox",
                "%U"
            ])
        );
        assert_eq!(
            run_argv(
                runner,
                "nl",
                &Container {
                    profile: TMP.to_owned(),
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "nl",
                "--tmp-profile",
                "--",
                "firefox",
                "%U"
            ])
        );
        assert_eq!(
            run_argv(
                runner,
                "nl",
                &Container {
                    profile: "tmpjoin:/tmp/vpn-profile-abc".to_owned(),
                    fs_sandbox: true,
                    ..Container::default()
                },
                &cmd
            ),
            argv(&[
                "/p/bin/vpn-zone",
                "run",
                "nl",
                "--tmp-profile",
                "--join",
                "/tmp/vpn-profile-abc",
                "--fs-sandbox",
                "--",
                "firefox",
                "%U"
            ])
        );
    }

    #[test]
    fn what_the_picker_writes_is_what_run_parses() {
        // The two halves of one contract: whatever menu row was chosen, the
        // line that comes out has to be understood by `vpn-zone run`.
        use crate::launch::{Sandbox, Selection};
        for tag in ["", "__fs__", "sb:work", "work", "__tmp__", "tmpjoin:/tmp/p"] {
            let container = match parse_profile_choice(tag) {
                ProfileChoice::Main { .. } => Container::default(),
                ProfileChoice::Throwaway { .. } => Container {
                    fs_sandbox: true,
                    ..Container::default()
                },
                ProfileChoice::Sandbox { name, .. } => Container {
                    fs_sandbox: true,
                    sandbox: name,
                    ..Container::default()
                },
                ProfileChoice::Tmp => Container {
                    profile: TMP.to_owned(),
                    ..Container::default()
                },
                ProfileChoice::TmpJoin(dir) => Container {
                    profile: format!("{TMPJOIN_PREFIX}{dir}"),
                    ..Container::default()
                },
                ProfileChoice::Profile { name, .. } => Container {
                    profile: name,
                    ..Container::default()
                },
                other => panic!("неожиданный разбор «{tag}»: {other:?}"),
            };
            let line = run_argv(Path::new("/p/vpn-zone"), "nl", &container, &argv(&["x"]));
            let parsed = Selection::parse(&line[2..]).unwrap_or_else(|e| panic!("«{tag}»: {e}"));
            assert_eq!(parsed.zone, OsString::from("nl"), "«{tag}»");
            assert_eq!(parsed.cmd, argv(&["x"]), "«{tag}»");
            if !container.sandbox.is_empty() {
                assert_eq!(
                    parsed.sandbox,
                    Sandbox::Named(container.sandbox.as_str().into()),
                    "«{tag}»"
                );
            } else if container.fs_sandbox {
                assert_eq!(parsed.sandbox, Sandbox::Throwaway, "«{tag}»");
            }
        }
    }
}
