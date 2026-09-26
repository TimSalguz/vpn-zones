//! `vpn-zone-pick` — the dialog that asks where a program is allowed to go.
//!
//! This is what an intercepted launcher entry starts instead of the program
//! (`crate::desktop`, picker mode): it asks which network and which container,
//! remembers the answer, and becomes `vpn-zone run`. It was the last shell
//! script of the project, and every branch of it is here because something went
//! wrong without it.
//!
//! **The network is the container's** (`docs/PERMISSIONS.md` §11.8): a
//! container bound to a network is started there with no question; one with
//! no network yet — and the main home, and a throwaway one — has it asked,
//! and the answer binds a named container. A program has no network of its
//! own any more: "always" in the main home moves it to the container of the
//! main home bound to that network (`main-<network>`), and the programs'
//! network pins of before (`.pinned/<program>`) became their containers'
//! networks at the first look (`container::migrate_pins`).
//!
//! **What the question starts on** (`docs/GOTCHAS.md` §11):
//!
//!  1. where the program runs, when it does;
//!  2. the LAST CHOICE (`.last/<program>`);
//!  3. the GLOBAL DEFAULT (`~/.config/vpn-zones/default`, `offline` unless set).
//!     That is the "an unknown program gets no internet" policy: until a
//!     network is picked explicitly, the one without any is offered.
//!
//! The container is the program's pin (`.pinnedprofile/<program>`), the
//! global default, or the last choice; "↺ Спрашивать снова" drops the pin.
//!
//! Two environment variables drive the second pass:
//!
//! * `VPN_ZONE_ASK=1` forces the dialog for a program whose container is
//!   bound;
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
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use crate::cli::{read_setting, visible_entries, EXIT_TOOLS};
use crate::desktop::sanitize;
use crate::dialog;
use crate::launch::{self, basename, is_assignment};
use crate::profile::{exec_command, EXIT_NOT_STARTED};
use crate::registry;
use crate::tools::Tools;
use crate::window;

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
    /// `--autostart`: started by XDG autostart at login, where nobody is
    /// looking at a dialog yet. Never asks (`docs/CONTAINERS.md` §5).
    pub autostart: bool,
    /// `--from-zone <zone>`: the broker asks on behalf of a program in that
    /// zone ([`pick_for_zone`]); `--locked`: that zone is locked.
    pub from_zone: Option<String>,
    pub locked: bool,
    /// `--offer-rule <text>`: with `--from-zone`, a checkbox of its own in
    /// the window — a container's rule for links (`crate::links`); ticked,
    /// the answer starts with the word `--rule`.
    pub offer_rule: Option<String>,
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
        let mut autostart = false;
        let mut from_zone = None;
        let mut locked = false;
        let mut offer_rule = None;
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
                b"--autostart" => {
                    autostart = true;
                    at += 1;
                }
                b"--from-zone" => {
                    from_zone = rest
                        .get(at + 1)
                        .map(|z| z.to_string_lossy().into_owned())
                        .filter(|z| !z.is_empty());
                    at += 2;
                }
                b"--locked" => {
                    locked = true;
                    at += 1;
                }
                b"--offer-rule" => {
                    offer_rule = rest
                        .get(at + 1)
                        .map(|r| r.to_string_lossy().into_owned())
                        .filter(|r| !r.is_empty());
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
            autostart,
            from_zone,
            locked,
            offer_rule,
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
/// path separators, quotes, spaces, line breaks and the invisible characters
/// that reorder text — and of the leading dash or dot kdialog takes for an
/// option. Cyrillic stays Cyrillic. (`docs/GOTCHAS.md` §11)
pub fn sanitize_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !crate::focus::reorders(*c))
        .map(|c| match c {
            '/' | '"' | '\'' | '`' | '\\' | ' ' | ':' => '_',
            other => other,
        })
        .collect();
    let name = cleaned.trim_start_matches(['-', '.']).to_owned();
    if reserved_name(&name) {
        String::new()
    } else {
        name
    }
}

/// A container name the menus use as a tag of their own: a profile called
/// `pinmain` or `__fs__` would be read as that command, not as itself. Never
/// created, by the picker or by `cellward container create`.
pub fn reserved_name(name: &str) -> bool {
    name.contains(':') || crate::container::reserved_name(name)
}

/// A selector from memory as it is now: a container's name after the move to
/// one name per container (`sb:work` → `work`, or `work-sb` when a layer had
/// the name); the words of the menus and the settings as they are.
///
/// `sb:<name>` keeps its prefix, with the name as it is now: what was a
/// sandbox is asked for as one ([`Container::from_selector`]). A temporary
/// container of a running program (its directory's name) is joined while it
/// is there, and a new one is made when it is gone — never a container of
/// that name.
fn canon(tools: &Tools, selector: &str) -> String {
    match selector {
        "" | MAIN | THROWAWAY | TMP | "ask" | "main" | "own" => selector.to_owned(),
        s if s.starts_with(TMPJOIN_PREFIX) => s.to_owned(),
        s if s.starts_with(crate::container::TEMPORARY_PREFIX) => {
            match launch::throwaway_path(&tools.state, std::ffi::OsStr::new(s)) {
                Some(dir) => format!("{TMPJOIN_PREFIX}{}", dir.display()),
                None => TMP.to_owned(),
            }
        }
        // Resolved here once; `run --sandbox` takes a home of its own of
        // that very name as it is, and renames nothing twice.
        s if s.starts_with(SANDBOX_PREFIX) => match crate::container::sandbox_name(tools, s) {
            Some(name) => format!("{SANDBOX_PREFIX}{name}"),
            None => s.to_owned(),
        },
        s => crate::container::canonical(tools, s).unwrap_or_else(|| s.to_owned()),
    }
}

/// Is there a container by this name — its data, its policy or its
/// declaration?
fn container_exists(tools: &Tools, name: &str) -> bool {
    crate::container::load(tools, name).is_some()
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
    /// `.handover/<key>`: the program was seen handing a launch over to the
    /// copy already running ([`HANDOVER`]) — a click on it while it runs
    /// raises that copy's window, with no question.
    pub hands_over: bool,
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
    /// The network the container this launch would use is bound to, empty
    /// when it is not bound (`ask`) or there is no container at all.
    pub bound: String,
}

/// What the first (network) question resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetStep {
    /// The program is already running AND is known to hand a launch over to
    /// the copy that is up ([`Memory::hands_over`]): a click on its shortcut
    /// means "raise the window", not "start another one". Asking about the
    /// network would be pointless — the command goes to the instance that is
    /// already up and it stays in ITS network — so it is started into the
    /// same place and no dialog is shown. A program not known to do that (a
    /// terminal: every window its own process) is asked, with the network it
    /// runs in chosen. (`docs/GOTCHAS.md` §11)
    Running { zone: String, selector: String },
    /// The container this launch uses without a question is bound to a
    /// network: that is where it goes (`docs/PERMISSIONS.md` §11.8).
    Bound { zone: String },
    /// Show the network dialog, with this entry selected.
    Ask { default: String },
}

/// The first decision, without touching anything.
pub fn net_step(memory: &Memory) -> NetStep {
    if !memory.ask {
        if let Some(running) = memory.running.as_ref().filter(|_| memory.hands_over) {
            return NetStep::Running {
                zone: running.zone.clone(),
                selector: running.selector.clone(),
            };
        }
        // A container bound to a network answers the network question itself:
        // the network is part of the container's identity, and asking would
        // only offer the way to break it (`docs/CONTAINERS.md` I1). The
        // container itself is the one the pin or the default chose, so there
        // is nothing left to ask. The network is the container's and never a
        // program's: a program's pin is gone (`docs/PERMISSIONS.md` §11.8).
        if !memory.bound.is_empty() {
            return NetStep::Bound {
                zone: memory.bound.clone(),
            };
        }
    }
    NetStep::Ask {
        // Running already: where it runs is what Enter keeps; then the
        // container's own network (asked anyway with VPN_ZONE_ASK).
        default: match &memory.running {
            Some(running) => crate::launch::network_name(&running.zone).to_owned(),
            None if !memory.bound.is_empty() => memory.bound.clone(),
            None if memory.last.is_empty() => memory.fallback.clone(),
            None => memory.last.clone(),
        },
    }
}

/// Where [`Memory::hands_over`] is kept, one empty file per program.
pub const HANDOVER: &str = ".handover";

/// Whether a launch is watched for a hand-over ([`launch_asked`]): the
/// program runs, it is not known to hand over yet, and it is started into
/// the network it runs in — the one case where the new process ending with
/// success without a window of its own can mean nothing else. Another network is not watched: there `run`
/// warns first, and a cancel there exits with success too. Not from inside
/// a zone either (`in_zone`): the launch is delegated to the host and the
/// launcher returns at once.
pub fn watch_handover(memory: &Memory, zone: &str, in_zone: bool) -> bool {
    !in_zone
        && !memory.hands_over
        && memory.running.as_ref().is_some_and(|running| {
            crate::launch::network_name(&running.zone) == crate::launch::network_name(zone)
        })
}

/// The container of a launch: exactly the three variables the shell carried
/// (`profile`, `fssand`, `sandbox`) — and now never two of them at once
/// (`docs/PERMISSIONS.md` §11.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Container {
    /// A container that exists, by name, whatever its home — `run
    /// --container`; `__tmp__` or `tmpjoin:<dir>`; empty for the main
    /// profile.
    pub profile: String,
    /// `--fs-sandbox`, or with `sandbox` set a home of its own.
    pub fs_sandbox: bool,
    /// `--sandbox <name>`: a container made with a home of its own at its
    /// first launch — the program's own, a new one, or one that is gone.
    pub sandbox: String,
}

impl Container {
    /// A stored selector turned back into a choice.
    ///
    /// For a selector from the launch registry, a pin or `VPN_ZONE_PROFILE`,
    /// all validated when they were written: a container that is not there
    /// (any more) is made again with a home of its own — the program's own
    /// home, never the whole real one.
    pub fn from_selector(selector: &str, exists: impl Fn(&str) -> bool) -> Self {
        Self::resolve(selector, &exists).unwrap_or_else(|| {
            let name = selector
                .strip_prefix(SANDBOX_PREFIX)
                .unwrap_or(selector)
                .to_owned();
            Self {
                fs_sandbox: true,
                sandbox: name,
                ..Self::default()
            }
        })
    }

    /// The same, for what nothing revalidates on the way in — `.lastprofile`:
    /// `None` for a container that is gone, and the caller decides.
    pub fn from_selector_checked(selector: &str, exists: impl Fn(&str) -> bool) -> Option<Self> {
        Self::resolve(selector, &exists)
    }

    fn resolve(selector: &str, exists: &impl Fn(&str) -> bool) -> Option<Self> {
        match selector {
            "" | MAIN => Some(Self::default()),
            THROWAWAY => Some(Self {
                fs_sandbox: true,
                ..Self::default()
            }),
            TMP => Some(Self {
                profile: TMP.to_owned(),
                ..Self::default()
            }),
            other if other.starts_with(TMPJOIN_PREFIX) => Some(Self {
                profile: other.to_owned(),
                ..Self::default()
            }),
            // `sb:<name>` — a stale pin, a default from Nix, a record of a
            // program started before one name per container — asked for a
            // home of its own and gets nothing else: `run --sandbox` refuses
            // a layer or the main home by that name, and makes a missing one.
            other => match other.strip_prefix(SANDBOX_PREFIX) {
                Some("") => None,
                Some(name) => Some(Self {
                    fs_sandbox: true,
                    sandbox: name.to_owned(),
                    ..Self::default()
                }),
                None if exists(other) => Some(Self {
                    profile: other.to_owned(),
                    ..Self::default()
                }),
                None => None,
            },
        }
    }

    /// What goes into `.lastprofile`: the CHOICE, a container's name
    /// whatever flag carries it. (`docs/GOTCHAS.md` §11)
    pub fn selector(&self) -> String {
        if !self.sandbox.is_empty() {
            return self.sandbox.clone();
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
            sandbox: own_name(key),
            ..Self::default()
        }
    }
}

/// The name of a program's own container, with a home of its own.
pub fn own_name(key: &str) -> String {
    format!("app-{key}")
}

/// The container when there is no dialog to ask it in, in priority order.
///
/// 1. `VPN_ZONE_PROFILE` — chosen in "⚙ Сменить контейнер" a second ago, so it
///    beats everything, the pin included;
/// 2. `.pinnedprofile` — and with no `VPN_ZONE_ASK` check in front of it: the
///    fresh choice arrives in the variable above, and testing for ASK here made
///    "↺ Спрашивать сеть снова" drop a pinned container into "main", because
///    `.lastprofile` is usually empty for somebody who pinned one;
/// 3. the global `default-profile` setting when it is an answer (`main`,
///    `own`, an existing container);
/// 4. `.lastprofile`; one that is gone is the program's own container, not
///    the whole real home.
///
/// Whole containers, never a part of one laid over another: the shell's
/// partial overlay (a default container with the sandbox remembered from
/// the last time) made one launch of two containers.
pub fn container_without_dialog(
    memory: &Memory,
    key: &str,
    exists: impl Fn(&str) -> bool,
    reprofile: Option<&str>,
) -> Container {
    if let Some(selector) = reprofile.filter(|s| !s.is_empty()) {
        return Container::from_selector(selector, &exists);
    }
    if !memory.pinned_profile.is_empty() {
        return Container::from_selector(&memory.pinned_profile, &exists);
    }
    match memory.default_profile.as_str() {
        "main" => return Container::default(),
        "own" => return Container::own_sandbox(key),
        "ask" => {}
        name if exists(name) => return Container::from_selector(name, &exists),
        _ => {}
    }
    Container::from_selector_checked(&memory.last_profile, &exists)
        .unwrap_or_else(|| Container::own_sandbox(key))
}

/// Where a program started by XDG autostart goes, and what had to be guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutostartPlan {
    pub zone: String,
    pub container: Container,
    /// No network was chosen for the program: it starts in `offline`.
    pub network_guessed: bool,
    /// No container was chosen and the default is `ask`: it starts in a home
    /// of its own.
    pub container_guessed: bool,
}

/// The decision for an autostart launch — never a dialog.
///
/// What was chosen for the program is honoured without a dialog. What was not
/// chosen is, with `autostart.unassigned = "ask"` (the default since
/// 2026-09-24, the owner's word), the picker's question — see
/// [`autostart_asks`]; with `offline` (2026-09-17 to 2026-09-24), or with no
/// screen to ask on, the closed variant below: a stray click on a dialog drawn
/// at login is a choice nobody made, and the old default started the program
/// uncontained in the host's network.
///
/// * running already — where it runs, like a click would;
/// * the container: the pinned or assigned one; otherwise the global default
///   when it is an answer (`main`, `own`, an existing container); otherwise —
///   `ask` — a home of its own;
/// * the network: the one that container is bound to; otherwise `offline`.
///   Not the last choice and not the global default: those
///   are what a dialog preselects, not a consent to go online unasked.
///
/// `bound_of` is the network a container is bound to, if any.
pub fn autostart_plan(
    memory: &Memory,
    key: &str,
    exists: impl Fn(&str) -> bool,
    bound_of: impl Fn(&Container) -> Option<String>,
) -> AutostartPlan {
    if let Some(running) = &memory.running {
        return AutostartPlan {
            zone: running.zone.clone(),
            container: Container::from_selector(&running.selector, &exists),
            network_guessed: false,
            container_guessed: false,
        };
    }
    let (container, container_guessed) = if !memory.pinned_profile.is_empty() {
        (
            Container::from_selector(&memory.pinned_profile, &exists),
            false,
        )
    } else {
        match memory.default_profile.as_str() {
            "main" => (Container::default(), false),
            "own" => (Container::own_sandbox(key), false),
            name if name != "ask" && exists(name) => {
                (Container::from_selector(name, &exists), false)
            }
            _ => (Container::own_sandbox(key), true),
        }
    };
    // The network of the global default container is not a choice for this
    // program: nobody made one.
    let via_default = memory.pinned_profile.is_empty() && is_default(memory, &container);
    let (zone, network_guessed) = match bound_of(&container).filter(|_| !via_default) {
        Some(network) => (network, false),
        None => ("offline".to_owned(), true),
    };
    AutostartPlan {
        zone,
        container,
        network_guessed,
        container_guessed,
    }
}

/// Is this network pin still worth honouring?
///
/// `unconfined` (and its old name `direct`) and `offline` are built-in choices
/// rather than zones, so they are always valid; anything else has to still
/// have a config. A dead pin is
/// removed rather than ignored, or the program would stay bound to a network
/// that does not exist and fail silently on every launch.
/// (`docs/GOTCHAS.md` §11)
pub fn pin_is_valid(pinned: &str, zone_exists: impl Fn(&str) -> bool) -> bool {
    matches!(pinned, "" | "offline")
        || crate::launch::is_unconfined_name(pinned)
        || zone_exists(pinned)
}

/// Is this container pin still worth honouring?
///
/// A container that exists; and the program's own one even before its first
/// launch, which makes it — it used to be checked as something that had to
/// exist, and the pin was erased on the very next click: "🔒 Своя песочница
/// — всегда" did not work at all. (`docs/GOTCHAS.md` §11)
/// A pinned sandbox (`sb:<name>`) likewise: a home of its own is made when it
/// is not there, as it always was.
pub fn profile_pin_is_valid(pinned: &str, profile_exists: impl Fn(&str) -> bool) -> bool {
    match pinned {
        "" | MAIN | THROWAWAY => true,
        other if other.starts_with(SANDBOX_PREFIX) => true,
        other => other.starts_with("app-") || profile_exists(other),
    }
}

// --- THE MENUS ---------------------------------------------------------------

/// One row of a kdialog `--menu`: the tag that comes back on stdout, and the
/// text shown next to it.
pub type Row = (String, String);

/// The unconfined choice, said the way it is: nothing of a zone stands
/// between the program and the host.
pub const UNCONFINED_ROW: (&str, &str) = (
    crate::launch::UNCONFINED,
    "Без ограничений — сеть хоста, без VPN и без изоляции зоны",
);

fn row(tag: &str, text: impl Into<String>) -> Row {
    (tag.to_owned(), text.into())
}

/// The network menu: every choice once "for this launch", then the same list
/// again as "Всегда: …".
///
/// One dialog rather than two steps, because pinning is worth exactly one
/// click. `current_container` is the label of the container that WOULD be used
/// — see [`container_label`].
pub fn net_menu(zones: &[MenuZone], pinned: &str, current_container: &str) -> Vec<Row> {
    let mut nets = vec![
        row(UNCONFINED_ROW.0, UNCONFINED_ROW.1),
        row("offline", "Без сети"),
    ];
    for zone in zones {
        let name = &zone.name;
        // A network through an interface of the host is not a VPN, and the
        // menu must not call it one: nothing about it is encrypted.
        let mut text = if zone.host_interface {
            format!("Через интерфейс: {name} (без шифрования)")
        } else if let Some(system) = &zone.system_zone {
            format!("VPN: {name} (через системную зону {system})")
        } else {
            format!("VPN: {name}")
        };
        // What `vpn-zone watch` last concluded: choosing a network whose
        // tunnel does not answer should not be a surprise.
        if zone.dead {
            text.push_str(" — туннель не отвечает");
        }
        nets.push(row(name, text));
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
            format!("↺ Спрашивать снова (программа закреплена за контейнером {pinned})"),
        ));
    }
    menu
}

/// A zone as the network menu shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MenuZone {
    pub name: String,
    /// `[HostInterface]`: no tunnel, no encryption.
    pub host_interface: bool,
    /// `[SystemZone]`: the tunnel is this system zone's (`docs/SYSTEM.md` §7b).
    pub system_zone: Option<String>,
    /// `vpn-zone watch` found the tunnel dead at its last look.
    pub dead: bool,
}

/// The zones of the state directory with what the menu says about them.
fn menu_zones(state: &Path) -> Vec<MenuZone> {
    zone_names(state)
        .into_iter()
        .map(|name| {
            let dir = state.join(&name);
            let ini = fs::read(dir.join("config.conf"))
                .ok()
                .and_then(|raw| crate::config::WgConfig::parse(&crate::cli::strip_cr(&raw)).ok());
            let host_interface = ini.as_ref().is_some_and(crate::hostif::is_host_interface);
            let system_zone = ini
                .as_ref()
                .and_then(|ini| crate::sysuplink::SysUplinkConfig::from_ini(ini).ok())
                .map(|s| s.zone);
            let dead = crate::cli::zone_pid(state, name.as_ref()).is_some()
                && fs::read_to_string(state.join(crate::watch::WATCH_DIR).join(&name))
                    .ok()
                    .and_then(|t| crate::watch::parse_memory(&t))
                    .is_some_and(|(_, v)| v == crate::watch::Verdict::Dead);
            MenuZone {
                name,
                host_interface,
                system_zone,
                dead,
            }
        })
        .collect()
}

/// How the container that is in force right now is described in that entry.
///
/// A PINNED container outranks the last choice here, and that is a fix: without
/// it the entry promised "сейчас: основной" while the program opened in the
/// pinned one — the menu disagreed with what actually happened.
///
/// By the selector alone; [`container_label_in`] knows the kind of its home.
pub fn container_label(selector: &str) -> String {
    label_of(selector, None)
}

/// [`container_label`], with the kind of the container's home read.
pub fn container_label_in(tools: &Tools, selector: &str) -> String {
    let home = crate::container::load(tools, selector).map(|c| c.home);
    label_of(selector, home)
}

fn label_of(selector: &str, home: Option<crate::container::Home>) -> String {
    use crate::container::Home;
    match selector {
        "" | MAIN => "основной".to_owned(),
        THROWAWAY => "разовая песочница".to_owned(),
        other => {
            let (name, home) = match other.strip_prefix(SANDBOX_PREFIX) {
                Some(name) => (name, Some(Home::Private)),
                None => (other, home),
            };
            match home {
                Some(Home::Private) | None if name.starts_with("app-") => {
                    "своя песочница".to_owned()
                }
                Some(Home::Private) => format!("песочница {name}"),
                Some(Home::Main) => format!("основной {name}"),
                Some(Home::Layer) | None => name.to_owned(),
            }
        }
    }
}

/// A container as the menu shows it: its name, and the zone it is open in
/// (empty when it is free). `main`: a container of the main home.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileRow {
    pub name: String,
    pub busy_in: String,
    pub main: bool,
    /// The network the container is bound to, empty when it has none yet:
    /// the window does not offer it with another.
    pub bound: String,
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
    // Containers with a home of their own: shared by everything started into
    // the same one, so two programs can work together without seeing your
    // files.
    for name in sandboxes {
        menu.push((name.clone(), format!("🔒 Песочница «{name}»")));
        menu.push((
            format!("pin:{name}"),
            format!("🔒 Песочница «{name}» — всегда"),
        ));
    }
    menu.push(row("__newsb__", "🔒➕ Новая песочница…"));

    for profile in profiles {
        let name = &profile.name;
        let shown = if profile.main {
            format!("⚠ Основной «{name}» (весь настоящий дом)")
        } else {
            name.clone()
        };
        if !profile.busy_in.is_empty() && profile.busy_in != current_zone && !profile.main {
            menu.push((
                name.clone(),
                format!("{shown} — занят сетью {}", profile.busy_in),
            ));
        } else {
            menu.push((name.clone(), shown.clone()));
        }
        menu.push((format!("pin:{name}"), format!("{shown} — всегда")));
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

// --- THE LAUNCH WINDOW (`crate::window`) -------------------------------------

/// The network column: the menu's choices, once — "always" is a checkbox now.
pub fn window_nets(zones: &[MenuZone], selected: &str) -> Vec<window::Item> {
    let mut items = net_menu(zones, "", "")
        .into_iter()
        .take_while(|(tag, _)| !tag.starts_with("pin:"))
        .map(|(tag, label)| {
            let dead = zones.iter().any(|z| z.name == tag && z.dead);
            let label = label
                .strip_suffix(" — туннель не отвечает")
                .map(str::to_owned)
                .unwrap_or(label);
            window::Item {
                selected: tag == selected,
                dead,
                tag,
                label,
                ..window::Item::default()
            }
        })
        .collect::<Vec<_>>();
    // Nothing remembered is offered: `offline`, not the first row.
    if !items.iter().any(|i| i.selected) {
        for it in &mut items {
            it.selected = it.tag == "offline";
        }
    }
    items
}

/// The container column: what the container menu offers, once each.
/// `current` is the selector in force (pinned, set, or the last one).
pub fn window_containers(
    key: &str,
    sandboxes: &[ProfileRow],
    profiles: &[ProfileRow],
    tmp_joins: &[TmpJoinRow],
    current: &str,
) -> Vec<window::Item> {
    let item = |tag: &str, label: &str| window::Item {
        tag: tag.to_owned(),
        label: label.to_owned(),
        ..window::Item::default()
    };
    let own = own_name(key);
    let mut items = vec![
        item("", "Основной (общий с системой)"),
        item(
            "__ownsb__",
            "Своя песочница — постоянный дом только этой программы",
        ),
        item(THROWAWAY, "Разовая песочница — стирается при выходе"),
    ];
    for row in sandboxes {
        if row.name == own {
            // The program's own: the row above — with its network, when it
            // has one.
            if let Some(it) = items.iter_mut().find(|i| i.tag == "__ownsb__") {
                it.bound = Some(row.bound.clone()).filter(|z| !z.is_empty());
            }
            continue;
        }
        let mut it = item(&row.name, &format!("Песочница «{}»", row.name));
        it.busy = Some(row.busy_in.clone()).filter(|z| !z.is_empty());
        it.bound = Some(row.bound.clone()).filter(|z| !z.is_empty());
        items.push(it);
    }
    for profile in profiles {
        let label = if profile.main {
            format!("Основной «{}» — весь настоящий дом", profile.name)
        } else {
            format!("Профиль {}", profile.name)
        };
        let mut it = item(&profile.name, &label);
        // The main home is one identity in every network: never "busy".
        it.busy = Some(profile.busy_in.clone()).filter(|z| !z.is_empty() && !profile.main);
        it.bound = Some(profile.bound.clone()).filter(|z| !z.is_empty());
        items.push(it);
    }
    for join in tmp_joins {
        items.push(item(
            &format!("{TMPJOIN_PREFIX}{}", join.dir),
            &format!("К открытому временному:{}", join.who),
        ));
    }
    items.push(item(
        TMP,
        "Новый временный — сотрётся, когда выйдет последняя программа",
    ));
    let mut new_sandbox = item("__newsb__", "Новая песочница…");
    new_sandbox.new = true;
    items.push(new_sandbox);
    let mut new_profile = item("__new__", "Новый профиль…");
    new_profile.new = true;
    items.push(new_profile);

    let current = current.strip_prefix(SANDBOX_PREFIX).unwrap_or(current);
    let selected = match current {
        "" | MAIN => "",
        c if c == own => "__ownsb__",
        c => c,
    };
    let mut found = false;
    for it in &mut items {
        it.selected = !found && it.tag == selected;
        found |= it.selected;
    }
    // What was remembered is gone (a sandbox removed, a profile renamed): the
    // program's own sandbox, not the main profile with the whole home.
    if !found {
        for it in &mut items {
            it.selected = it.tag == "__ownsb__";
        }
    }
    items
}

/// A container answer of the window as the menu would have said it, with its
/// pin: the menu had an "— всегда" row where the window has a checkbox.
pub fn window_container_choice(tag: &str, pin: bool) -> ProfileChoice {
    match tag {
        _ if !pin => parse_profile_choice(tag),
        "" => parse_profile_choice("pinmain"),
        TMP | "__newsb__" | "__new__" => parse_profile_choice(tag),
        t if t.starts_with(TMPJOIN_PREFIX) => parse_profile_choice(t),
        t => parse_profile_choice(&format!("pin:{t}")),
    }
}

/// The launch window instead of the two menus. `None`: there is no window to
/// show — none installed, or it would not start — and kdialog asks.
/// `Some(None)`: the window was closed, and the launch is over. Otherwise the
/// network and the container, with their pins already written.
fn ask_window(
    tools: &Tools,
    key: &str,
    label: &str,
    default_net: &str,
    memory: &Memory,
) -> Option<Option<(String, Container)>> {
    if tools.window.as_os_str().is_empty() {
        return None;
    }
    let req = window_request(tools, key, label, default_net, memory);
    let reply = match show_window(tools, &req)? {
        Some(reply) => reply,
        None => return Some(None),
    };

    remember(&tools.state, ".last", key, &reply.net);

    if !reply.pin_container && !memory.pinned_profile.is_empty() {
        let _ = fs::remove_file(tools.state.join(".pinnedprofile").join(key));
    }
    let is_new = matches!(reply.container.as_str(), "__newsb__" | "__new__");
    let choice = window_container_choice(&reply.container, reply.pin_container);
    let Some(container) = apply_profile_choice(tools, key, choice, reply.name.clone()) else {
        return Some(None);
    };
    let selector = container.selector();
    if is_new && reply.pin_container {
        remember(&tools.state, ".pinnedprofile", key, &selector);
    }
    if !container.is_throwaway_container() {
        remember(&tools.state, ".lastprofile", key, &selector);
    }
    let shared = !reply.pin_container && shared_default(memory, &container, None);
    let container = settle_network(tools, key, container, &reply.net, reply.pin_net, shared);
    Some(Some((reply.net, container)))
}

/// Is this container the program's by the global default alone — a named
/// container nobody pinned this program to? Its network is shared by every
/// program that goes there unasked, and is not bound from one of them.
fn shared_default(memory: &Memory, container: &Container, reprofile: Option<&str>) -> bool {
    reprofile.is_none() && memory.pinned_profile.is_empty() && is_default(memory, container)
}

/// Is this container the named global default (`sb:` or not)?
fn is_default(memory: &Memory, container: &Container) -> bool {
    let default = memory.default_profile.as_str();
    !matches!(default, "" | "ask" | "main" | "own")
        && container.selector() == default.strip_prefix(SANDBOX_PREFIX).unwrap_or(default)
}

/// "Always" for a network (`docs/PERMISSIONS.md` §11.8): the network is
/// made the container's — a named container with no network yet is bound to
/// it, the program's own one is made with it, and in the main home the
/// program moves to the container of the main home bound to it,
/// `main-<network>`. Without "always" nothing is bound: a binding is an
/// action of its own, never a side effect of one launch (I1). A throwaway
/// container keeps nothing, and a container that is the program's only by
/// the global default is not bound from it (`shared_default`). A sandbox
/// asked for by name is bound only when it is a home of its own. Returns the
/// container to launch.
fn settle_network(
    tools: &Tools,
    key: &str,
    container: Container,
    net: &str,
    always: bool,
    shared: bool,
) -> Container {
    use crate::container::{Home, Network, Source};
    if !always
        || container.is_throwaway_container()
        || (container.fs_sandbox && container.sandbox.is_empty())
    {
        return container;
    }
    let network = Network::Named(launch::network_name(net).to_owned());
    if container.profile.is_empty() && container.sandbox.is_empty() {
        return match crate::container::main_for_network(tools, net) {
            Ok(name) => {
                remember(&tools.state, ".pinnedprofile", key, &name);
                remember(&tools.state, ".lastprofile", key, &name);
                Container {
                    profile: name,
                    ..Container::default()
                }
            }
            Err(why) => {
                eprintln!("vpn-zone-pick: {why}");
                container
            }
        };
    }
    if shared {
        let name = container.selector();
        dialog::notify(
            &tools.notify_send,
            None,
            "8000",
            "Сеть не закреплена",
            &format!(
                "«{name}» — контейнер по умолчанию для всех программ: его сеть меняется в его \
                 настройках (cellward container set {name} network …), не одним запуском."
            ),
        );
        return container;
    }
    let (name, private_only) = if container.sandbox.is_empty() {
        (container.profile.clone(), false)
    } else {
        (
            crate::container::sandbox_name(tools, &container.sandbox)
                .unwrap_or_else(|| container.sandbox.clone()),
            true,
        )
    };
    let bound = match crate::container::load(tools, &name) {
        // `run --sandbox` refuses a layer or the main home by that name: its
        // network is not touched either.
        Some(c) if private_only && c.home != Home::Private => Ok(()),
        Some(c) if c.network.value == Network::Ask && c.network.source != Source::Nix => {
            crate::container::set_network(tools, &c.name, &network)
        }
        Some(_) => Ok(()),
        // The program's own, or a new one, made at its first launch: made now,
        // with its network.
        None if private_only => crate::container::create(tools, &name, Home::Private)
            .and_then(|c| crate::container::set_network(tools, &c.name, &network)),
        None => Ok(()),
    };
    if let Err(why) = bound {
        eprintln!("vpn-zone-pick: сеть контейнера {name}: {why}");
    }
    container
}

/// The containers the menus offer: those with a home of their own, and the
/// rest (a layer, the main home) with the network each is open in.
fn container_rows(tools: &Tools) -> (Vec<ProfileRow>, Vec<ProfileRow>) {
    use crate::container::{Home, Network};
    let running = tools.state.join(".running");
    let mut sandboxes = Vec::new();
    let mut profiles = Vec::new();
    for c in crate::container::load_all(tools) {
        // A name a menu takes for a command of its own is not shown.
        if reserved_name(&c.name) {
            continue;
        }
        let bound = match &c.network.value {
            Network::Named(net) => net.clone(),
            Network::Ask => String::new(),
        };
        let busy_in = live_tenant(&running, &c.dir.join("inuse"))
            .or_else(|| crate::container::running_network(tools, &c))
            .unwrap_or_default();
        let row = ProfileRow {
            main: c.home == Home::Main,
            name: c.name.clone(),
            busy_in,
            bound,
        };
        if c.home == Home::Private {
            sandboxes.push(row);
        } else {
            profiles.push(row);
        }
    }
    (sandboxes, profiles)
}

/// What the launch window is asked: both columns as the memory has them.
fn window_request(
    tools: &Tools,
    key: &str,
    label: &str,
    default_net: &str,
    memory: &Memory,
) -> window::Request {
    let running = tools.state.join(".running");
    let (sandboxes, profiles) = container_rows(tools);
    // In force: the pin, then the global setting, then the running copy's,
    // then the last choice.
    let current = if !memory.pinned_profile.is_empty() {
        memory.pinned_profile.clone()
    } else {
        match memory.default_profile.as_str() {
            "ask" => match &memory.running {
                Some(running) => running.selector.clone(),
                None => memory.last_profile.clone(),
            },
            "main" => String::new(),
            "own" => own_name(key),
            name => name.to_owned(),
        }
    };
    let mut req = window::Request {
        title: format!("Запуск: {label}"),
        notes: Vec::new(),
        nets: window_nets(&menu_zones(&tools.state), default_net),
        containers: window_containers(
            key,
            &sandboxes,
            &profiles,
            &open_throwaways(&running),
            &current,
        ),
        // "Always" for the network is for the main home only: a container's
        // network is its own once chosen.
        pin_net: false,
        pin_container: !memory.pinned_profile.is_empty(),
        ..window::Request::default()
    };
    if let Some(running) = &memory.running {
        let zone = launch::network_name(&running.zone);
        let shown = req
            .nets
            .iter()
            .find(|n| n.tag == zone)
            .map_or(zone, |n| n.label.as_str());
        req.notes.push(format!("Уже открыта: {shown}"));
    }
    req
}

/// Show the launch window. `None`: it would not start. `Some(None)`: closed,
/// or an answer that is none — the launch is over. Only what was offered
/// comes back: an answer from outside the lists starts nothing.
fn show_window(tools: &Tools, req: &window::Request) -> Option<Option<window::Reply>> {
    let mut child = Command::new(&tools.window)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = std::io::Write::write_all(&mut stdin, window::render(req).as_bytes());
    }
    // From here on a failure is a close, never the menus on top of a window
    // the person has already answered.
    let Ok(out) = child.wait_with_output() else {
        return Some(None);
    };
    if !out.status.success() {
        return Some(None);
    }
    let Some(reply) = window::parse_reply(&String::from_utf8_lossy(&out.stdout)) else {
        return Some(None);
    };
    // Only what was offered: an answer from outside the list starts nothing.
    let offered_net = req.nets.iter().any(|n| n.tag == reply.net);
    let offered_container = req.containers.iter().any(|c| c.tag == reply.container);
    if !offered_net || !offered_container {
        eprintln!("vpn-zone-pick: окно запуска ответило тем, чего не предлагали — не запускаю");
        return Some(None);
    }
    Some(Some(reply))
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
        argv.push("--container".into());
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
    for dir in [".last", ".lastprofile", ".pinnedprofile", ".labels"] {
        let _ = fs::create_dir_all(tools.state.join(dir));
    }
    let _ = fs::create_dir_all(&tools.config);

    let key = match &args.id {
        Some(id) => crate::desktop::stable_key(&id.to_string_lossy()),
        None => sanitize(&fallback_key(&args.cmd).to_string_lossy()),
    };

    // From inside a zone the question is the host's: the zone sees none of
    // the zones (`zone::hide_project_state`), and a window the zone draws is
    // one its programs could draw as well. The broker shows it
    // (`broker::pick`). No broker to ask — a zone from before it — and the
    // picker asks here, as before; `run` still goes through the broker.
    // Not for a container of the host's network (`unconfined` in the
    // variable): it sees the state, and the broker knows no zone of it.
    let in_zone = std::env::var(launch::ENV_CURRENT)
        .is_ok_and(|z| !z.is_empty() && !launch::is_unconfined_name(&z));
    if args.from_zone.is_none() && in_zone {
        if let Some(code) = crate::broker::pick(key.as_bytes(), &args.cmd) {
            return ExitCode::from(code);
        }
    }

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

    if let Some(zone) = &args.from_zone {
        let memory = read_memory_with(&tools, &key, false);
        return pick_for_zone(
            &tools,
            &key,
            &memory,
            &args.cmd,
            zone,
            args.locked,
            args.offer_rule.as_deref(),
        );
    }
    let memory = read_memory(&tools, &key);
    if args.autostart {
        if let Some(code) = autostart(&tools, &key, &label, &memory, &args.cmd) {
            return code;
        }
        // Nothing chosen for it, and the setting says ask (owner, 2026-09-24):
        // the same picker a click shows, with its "always".
        eprintln!("vpn-zone-pick: автозапуск «{label}»: для неё ничего не выбрано — спрашиваю");
    }
    let zone_choice: String;
    // The network was chosen here, "always" or not: made the container's
    // once the container is known (`settle_network`).
    let mut chosen: Option<bool> = None;

    match net_step(&memory) {
        NetStep::Running { zone, selector } => {
            return launch(
                &tools,
                &key,
                &zone,
                &Container::from_selector(&selector, |n| container_exists(&tools, n)),
                &args.cmd,
            );
        }
        NetStep::Bound { zone } => zone_choice = zone,
        NetStep::Ask { default } => {
            // The row the question starts on: the remembered one while it is
            // still offered, else `offline` — never whatever comes first, which
            // is the host's network. A zone removed after `vpn-zone default`
            // named it (or after it was last chosen) is not offered.
            let default = if default == "offline"
                || default == launch::UNCONFINED
                || menu_zones(&tools.state).iter().any(|z| z.name == default)
            {
                default
            } else {
                "offline".to_owned()
            };
            // One window for both questions, where there is one.
            if launch::has_display() {
                match ask_window(&tools, &key, &label, &default, &memory) {
                    Some(Some((zone, container))) => {
                        return launch_asked(&tools, &key, &zone, &container, &args.cmd, &memory)
                    }
                    Some(None) => return ExitCode::SUCCESS,
                    None => {}
                }
            }
            let current = if memory.pinned_profile.is_empty() {
                &memory.last_profile
            } else {
                &memory.pinned_profile
            };
            // "↺" only for a pin of the picker's own: one declared in Nix is
            // not undone here.
            let local_pin = tools.state.join(".pinnedprofile").join(&key).is_file();
            let menu = net_menu(
                &menu_zones(&tools.state),
                if local_pin {
                    &memory.pinned_profile
                } else {
                    ""
                },
                &container_label_in(&tools, current),
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

            let choice = parse_net_choice(&answer);
            // "↺ Спрашивать снова": the program's container pin goes — the
            // network is the container's — and the container is asked right
            // away, as "⚙ Сменить контейнер" does. Not a pass that falls back
            // to whatever the memory had, the main home with nothing.
            if choice == NetChoice::Unpin {
                let _ = fs::remove_file(tools.state.join(".pinnedprofile").join(&key));
            }
            match choice {
                NetChoice::Nothing => return ExitCode::SUCCESS,
                NetChoice::ChooseContainer | NetChoice::Unpin => {
                    // The container is asked here and the network question is
                    // then asked again by a second pass of this same binary.
                    let Some(container) = ask_profile(
                        &tools,
                        &key,
                        &label,
                        "__chooseprofile__",
                        // After "↺" the pin is gone: the menu does not
                        // offer to drop it again.
                        &Memory {
                            pinned_profile: if choice == NetChoice::Unpin {
                                String::new()
                            } else {
                                memory.pinned_profile.clone()
                            },
                            ..memory.clone()
                        },
                    ) else {
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
                NetChoice::Pin(zone) => {
                    chosen = Some(true);
                    zone_choice = zone;
                }
                NetChoice::Zone(zone) => {
                    chosen = Some(false);
                    zone_choice = zone;
                }
            }
            remember(&tools.state, ".last", &key, &zone_choice);
        }
    }

    // The container: the one pinned, set globally, or remembered — the
    // network question above was about it.
    let container = container_without_dialog(
        &memory,
        &key,
        |name| container_exists(&tools, name),
        reprofile.as_deref(),
    );
    let container = match chosen {
        Some(always) => {
            let shared = shared_default(&memory, &container, reprofile.as_deref());
            settle_network(&tools, &key, container, &zone_choice, always, shared)
        }
        None => container,
    };

    launch_asked(&tools, &key, &zone_choice, &container, &args.cmd, &memory)
}

/// How long the window a zone's program brought up starts nothing: the
/// question's own `dialog::TOO_FAST`.
const FROM_ZONE_GUARD: std::time::Duration = crate::dialog::TOO_FAST;

/// The picker for a program in a zone (`--from-zone`, run by the broker on
/// the host, `broker::pick`): the window, and the answer on stdout — the
/// arguments of `run`, each ended by a NUL — for the broker to check and
/// start. Nothing is started here and nothing is remembered.
///
/// Nothing is decided without the window either: a pin, a container's
/// network, a running copy only choose what the window starts on. The program
/// in the zone chose which launcher's name this is, and a pin of that name
/// must not start the zone's command anywhere unasked; for the same reason
/// the window has no "always" (a pin of that name would decide the menu's
/// next launch of the real program), and the title says who asks and the
/// notes what, word by word — not the launcher's name. Starting is off for
/// its first moments ([`FROM_ZONE_GUARD`], in the window and checked here
/// again): it takes the focus, and a key meant for something else must not
/// answer it. A locked zone is offered only itself. What the window shows is
/// [`zone_request`]; what it may answer is a container that exists, with no
/// pin.
fn pick_for_zone(
    tools: &Tools,
    key: &str,
    memory: &Memory,
    cmd: &[OsString],
    zone: &str,
    locked: bool,
    offer_rule: Option<&str>,
) -> ExitCode {
    let refuse = |why: &str| {
        eprintln!("vpn-zone-pick: {why}");
        ExitCode::from(1)
    };
    if cmd.is_empty() {
        return refuse("нечего запускать");
    }
    if tools.window.as_os_str().is_empty() {
        return refuse("окна запуска нет");
    }
    let Some(shown) = crate::broker::shown_words(cmd) else {
        return refuse("команда слишком длинная, чтобы показать её целиком");
    };
    let mut req = zone_request(tools, key, memory, cmd, &shown, zone, locked);
    req.rule = offer_rule.map(str::to_owned);

    let asked = std::time::Instant::now();
    let reply = match show_window(tools, &req) {
        Some(Some(reply)) => reply,
        Some(None) => return ExitCode::from(1),
        None => return refuse("окно запуска не открылось"),
    };
    if let Err(why) = crate::dialog::not_too_soon(asked) {
        return refuse(&why);
    }
    // Only a container that exists and no pin: the window offers nothing
    // else, and a row named like a command is refused all the same.
    let choice = window_container_choice(&reply.container, false);
    match &choice {
        ProfileChoice::Main { pin: false }
        | ProfileChoice::OwnSandbox { pin: false }
        | ProfileChoice::Throwaway { pin: false }
        | ProfileChoice::Sandbox { pin: false, .. }
        | ProfileChoice::Profile { pin: false, .. }
        | ProfileChoice::Tmp
        | ProfileChoice::TmpJoin(_) => {}
        _ => return refuse("окно ответило выбором, которого в запросе из зоны нет"),
    }
    let Some(container) = apply_profile_choice(tools, key, choice, None) else {
        return ExitCode::from(1);
    };
    let net = launch::network_name(&reply.net);
    if net == "offline" {
        launch::ensure_offline_zone(&tools.state);
    }
    let argv = run_argv(Path::new(""), net, &container, cmd);
    let mut out = Vec::new();
    // The rule ticked: said first, apart from the arguments of `run`.
    if offer_rule.is_some() && reply.rule {
        out.extend_from_slice(b"--rule\0");
    }
    for word in &argv[2..] {
        out.extend_from_slice(word.as_bytes());
        out.push(0);
    }
    if std::io::Write::write_all(&mut std::io::stdout(), &out).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// What the window of [`pick_for_zone`] is asked: the zone's command in a
/// block of its own and the program as the host finds it; the asking
/// network chosen, and the only one Enter starts in (`offline` for a
/// system zone's program); the host's network last, away from where a
/// habit would click; no new container (a name typed into a window that
/// came up by itself), no "always", no note of the memory of a name the
/// zone chose; a sandbox named by its name, not "its own".
fn zone_request(
    tools: &Tools,
    key: &str,
    memory: &Memory,
    cmd: &[OsString],
    shown: &[String],
    zone: &str,
    locked: bool,
) -> window::Request {
    let mut req = window_request(tools, key, "", zone, memory);
    req.title = match zone.strip_prefix("system:") {
        Some(system) => format!("Запрос из системной зоны «{system}»"),
        None => format!("Запрос из зоны «{zone}»"),
    };
    req.notes.clear();
    let asker = if req.nets.iter().any(|n| n.tag == zone) {
        zone
    } else {
        "offline"
    };
    for net in &mut req.nets {
        net.selected = net.tag == asker;
    }
    if locked {
        req.nets.retain(|n| n.tag == zone);
        req.notes
            .push("Зона заперта: запустить можно только в ней самой.".to_owned());
    }
    if let Some(at) = req
        .nets
        .iter()
        .position(|n| launch::is_unconfined_name(&n.tag))
    {
        let host = req.nets.remove(at);
        req.nets.push(host);
    }
    req.containers.retain(|c| !c.new);
    for c in &mut req.containers {
        if c.tag == "__ownsb__" {
            c.label = format!("🔒 Песочница «app-{key}»");
        }
    }
    req.asker = Some(asker.to_owned());
    req.command = shown.to_vec();
    // The broker hands the program over found already (an absolute path):
    // what is shown is what runs.
    let path = Path::new(&cmd[0]);
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let shown_path = crate::broker::shown_word(&path.display().to_string());
    req.program = if crate::broker::runs_anything(name) {
        format!("⚠ {shown_path} — запускает любую команду: смотри, что идёт следом")
    } else if crate::broker::may_remember(path) {
        shown_path
    } else {
        format!(
            "⚠ {shown_path} — не из системы: этот файл может подменить программа, у которой есть дом"
        )
    };
    req.pin_net = false;
    req.pin_container = false;
    req.no_pins = true;
    req.guard_ms = FROM_ZONE_GUARD.as_millis() as u64;
    req
}

/// `autostart.unassigned`: the declared setting, then the local one; `ask` by
/// default (owner, 2026-09-24 — `offline` before).
fn autostart_setting(tools: &Tools) -> String {
    read_setting(&tools.config.join("declared/autostart"))
        .or_else(|| read_setting(&tools.config.join("autostart")))
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|| "ask".to_owned())
}

/// Whether an autostart launch shows the picker instead of guessing: with
/// `ask`, when something had to be guessed, and when there is a screen to ask
/// on — a login on a text console gets the closed variant as before.
pub fn autostart_asks(setting: &str, plan: &AutostartPlan, screen: bool) -> bool {
    setting == "ask" && (plan.network_guessed || plan.container_guessed) && screen
}

/// A launch from XDG autostart: [`autostart_plan`], a notification for what
/// was guessed, and the launch itself. `None`: the picker asks instead
/// ([`autostart_asks`]).
fn autostart(
    tools: &Tools,
    key: &str,
    label: &str,
    memory: &Memory,
    cmd: &[OsString],
) -> Option<ExitCode> {
    let plan = autostart_plan(
        memory,
        key,
        |name| container_exists(tools, name),
        |container| {
            crate::container::load(tools, &container.selector()).and_then(|c| {
                match c.network.value {
                    crate::container::Network::Named(network) => Some(network),
                    crate::container::Network::Ask => None,
                }
            })
        },
    );
    let screen = std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty());
    if autostart_asks(&autostart_setting(tools), &plan, screen) {
        return None;
    }
    let mut lines = Vec::new();
    if plan.network_guessed {
        lines.push(
            "сеть для неё не выбрана — запущена без сети. Чтобы выбрать: закрой программу, \
             запусти из меню и закрепи сеть"
                .to_owned(),
        );
    }
    if plan.container_guessed {
        lines.push(format!(
            "контейнер не выбран — запущена в своём доме ({}). Назначить: cellward container \
             assign {key} <контейнер>",
            container_label_in(tools, &plan.container.selector())
        ));
    }
    // A home of its own that has never been started asks for file access in
    // a dialog — the one thing an autostart must not do. It gets the closed
    // answer instead, the one given when there is no screen to ask on.
    if !plan.container.sandbox.is_empty() {
        let dir = crate::container::policy_dir(tools, &plan.container.sandbox);
        let perms = dir.join("perms");
        if !perms.exists()
            && fs::create_dir_all(&dir)
                .and_then(|()| fs::write(&perms, crate::fs_sandbox::Perms::default().render()))
                .is_ok()
        {
            lines.push("доступа к файлам хоста у неё нет".to_owned());
        }
    }
    if !lines.is_empty() {
        eprintln!("vpn-zone-pick: автозапуск «{label}»: {}", lines.join("; "));
        dialog::notify(
            &tools.notify_send,
            None,
            "15000",
            &format!("Автозапуск: «{label}»"),
            &lines.join("\n"),
        );
    }
    Some(launch(tools, key, &plan.zone, &plan.container, cmd))
}

/// Read the three levels of memory, dropping the pins that have gone stale.
fn read_memory(tools: &Tools, key: &str) -> Memory {
    read_memory_with(tools, key, true)
}

/// [`read_memory`]; `tidy` false leaves every file as it is — for a window a
/// zone's program asks for, under a launcher's name the zone chose: a pin
/// is not dropped because the zone moved a container away for a moment.
fn read_memory_with(tools: &Tools, key: &str, tidy: bool) -> Memory {
    // The memory as the layout of one name per container has it: the move
    // rewrites the pins it renames, and makes the programs' network pins
    // their containers' networks (`container::migrate_pins`), before they
    // are read.
    crate::container::migrate(tools);
    let state = &tools.state;

    let profile_pin_path = state.join(".pinnedprofile").join(key);
    let mut pinned_profile = canon(tools, &read_setting(&profile_pin_path).unwrap_or_default());
    // An assignment declared in Nix outranks the picker's own pin: it is the
    // configuration, the pin only a memory. (`docs/CONTAINERS.md` §4)
    if let Some(declared) = crate::container::declared_owner(tools, key) {
        pinned_profile = declared;
    }
    if !profile_pin_is_valid(&pinned_profile, |name| container_exists(tools, name)) {
        if tidy {
            let _ = fs::remove_file(&profile_pin_path);
        }
        pinned_profile.clear();
    }

    let running: Vec<Running> = running_records(state, key)
        .into_iter()
        .map(|r| Running {
            selector: canon(tools, &r.selector),
            ..r
        })
        .collect();
    // Two copies alive at once: whatever handed over once, this program runs
    // side by side (two containers of one browser, or a wrong guess) — ask
    // again.
    let handover_path = state.join(HANDOVER).join(key);
    let mut hands_over = handover_path.is_file();
    if hands_over && running.len() > 1 {
        if tidy {
            let _ = fs::remove_file(&handover_path);
        }
        hands_over = false;
    }
    let mut memory = Memory {
        running: running.into_iter().next(),
        hands_over,
        pinned_profile,
        last: crate::launch::network_name(
            &read_setting(&state.join(".last").join(key)).unwrap_or_default(),
        )
        .to_owned(),
        last_profile: canon(
            tools,
            &read_setting(&state.join(".lastprofile").join(key)).unwrap_or_default(),
        ),
        fallback: crate::cli::setting(tools, "default").map_or_else(
            || "offline".to_owned(),
            |(value, _)| crate::launch::network_name(&value).to_owned(),
        ),
        default_profile: crate::cli::setting(tools, "default-profile")
            .map_or_else(|| "ask".to_owned(), |(value, _)| canon(tools, &value)),
        ask: std::env::var_os(ENV_ASK).is_some_and(|v| !v.is_empty()),
        bound: String::new(),
    };
    // The container this launch would use without a dialog, and its network.
    let would_use = container_without_dialog(&memory, key, |n| container_exists(tools, n), None);
    // A program that reaches the global default container with nothing
    // pinned is a program nobody chose a network for: its network is asked,
    // the container's own preselected — never taken unasked, or every new
    // program would go there (`docs/PERMISSIONS.md` §11.8).
    if !(memory.pinned_profile.is_empty() && is_default(&memory, &would_use)) {
        if let Some(container) = crate::container::load(tools, &would_use.selector()) {
            if let crate::container::Network::Named(network) = container.network.value {
                memory.bound = network;
            }
        }
    }
    memory
}

/// Where is this program running right now? Every live record, over every
/// container's registry directory; the first one is where a click goes.
fn running_records(state: &Path, key: &str) -> Vec<Running> {
    let running = state.join(".running");
    let mut out = Vec::new();
    for dir in registry::dirs(&running) {
        let Ok(text) = fs::read_to_string(dir.join(key)) else {
            continue;
        };
        out.extend(
            text.lines()
                .filter_map(registry::parse_record)
                // This one starts a click into that network without a
                // question: only a launch that is certainly still this
                // process counts (`registry::STARTED`), not whatever holds its
                // number now — and only one the user started, not one a
                // program in a zone asked for under an id of its choosing.
                .filter(|r| registry::launched_here(&running, r.pid))
                .map(|record| Running {
                    zone: record.zone,
                    selector: record.selector,
                }),
        );
    }
    out
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
        // A zone left with a name that now means the host's network is not
        // offered: choosing it would launch unconfined. (`vpn-zone doctor`
        // names it.)
        .filter(|name| !crate::launch::is_unconfined_name(name))
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
            if container_exists(tools, name) {
                return Some(Container::from_selector(name, |n| {
                    container_exists(tools, n)
                }));
            }
        }
    }

    if !launch::has_display() {
        // Same reason as the network dialog above: without a graphical session
        // kdialog dies and `|| exit 0` took that for a cancel, so a launch from
        // a terminal or from a unit ended in nothing at all. Take the last
        // choice and let the program start — its own home when that is gone.
        return Some(
            Container::from_selector_checked(&memory.last_profile, |n| container_exists(tools, n))
                .unwrap_or_else(|| Container::own_sandbox(key)),
        );
    }

    let (sandboxes, profiles) = container_rows(tools);
    let sandboxes: Vec<String> = sandboxes.into_iter().map(|r| r.name).collect();
    let running = tools.state.join(".running");
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
    apply_profile_choice(tools, key, parse_profile_choice(&answer), None)
}

/// A container choice made real: its pin written, a new sandbox or profile
/// created. `new_name` is the new one's name when the launch window already
/// asked for it; without it kdialog asks, as the menu always did.
fn apply_profile_choice(
    tools: &Tools,
    key: &str,
    choice: ProfileChoice,
    new_name: Option<String>,
) -> Option<Container> {
    let pin = |selector: &str| remember(&tools.state, ".pinnedprofile", key, selector);
    match choice {
        ProfileChoice::Main { pin: false } => Some(Container::default()),
        ProfileChoice::Main { pin: true } => {
            // "Основной — всегда": pinned separately from the network.
            pin(MAIN);
            Some(Container::default())
        }
        ProfileChoice::OwnSandbox { pin: want } => {
            if want {
                pin(&own_name(key));
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
        // `sb:<name>` of an older menu or window: the container by its name.
        ProfileChoice::Sandbox { name, pin: want } => {
            let name = canon(tools, &format!("{SANDBOX_PREFIX}{name}"));
            if want {
                pin(&name);
            }
            Some(Container::from_selector(&name, |n| {
                container_exists(tools, n)
            }))
        }
        ProfileChoice::NewSandbox => {
            let name = match new_name {
                Some(name) => name,
                None => dialog::ask(
                    &tools.kdialog,
                    [
                        "--title",
                        "Новая песочница",
                        "--inputbox",
                        "Название песочницы. У неё будет свой пустой дом, общий для всех программ, которые ты в ней запустишь.",
                        "",
                    ],
                )?,
            };
            // A creation that fails (a name that cleans down to nothing, no
            // space, no permission) must not kill the picker: that used to
            // happen silently, AFTER every dialog had been answered. But what
            // was asked for is a sandbox, so it is the program's own sandbox —
            // not the main profile with the whole home —, and said so.
            let name = sanitize_name(&name);
            let made = crate::container::create(tools, &name, crate::container::Home::Private);
            if let Err(why) = made {
                dialog::notify(
                    &tools.notify_send,
                    None,
                    "8000",
                    "Песочница не создана",
                    &format!("{why}. Программа запущена в своей песочнице — без дома системы."),
                );
                return apply_profile_choice(
                    tools,
                    key,
                    ProfileChoice::OwnSandbox { pin: false },
                    None,
                );
            }
            Some(Container {
                profile: name,
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
        // The pin goes, and the program's own container follows — not the
        // main home with the whole of it.
        ProfileChoice::Unpin => {
            let _ = fs::remove_file(tools.state.join(".pinnedprofile").join(key));
            Some(Container::own_sandbox(key))
        }
        ProfileChoice::NewProfile => {
            let name = match new_name {
                Some(name) => name,
                None => dialog::ask(
                    &tools.kdialog,
                    [
                        "--title",
                        "Новый профиль",
                        "--inputbox",
                        "Название профиля (буквы, цифры, дефис):",
                        "",
                    ],
                )?,
            };
            // Only what actually gets in the way is cleaned (paths, spaces,
            // quotes) and a leading dash is cut off — Cyrillic stays Cyrillic.
            let name = sanitize_name(&name);
            // The same trap as the sandbox above: without swallowing the error
            // the picker died after all the dialogs, and with a container that
            // does not exist `vpn-zone run` would honestly refuse to start.
            let made = crate::container::create(tools, &name, crate::container::Home::Layer);
            if let Err(why) = made {
                // A container was asked for: the program's own sandbox, not the
                // main profile with the whole home (review 2026-09-25).
                dialog::notify(
                    &tools.notify_send,
                    None,
                    "8000",
                    "Профиль не создан",
                    &format!("{why}. Программа запущена в своей песочнице — без дома системы."),
                );
                return apply_profile_choice(
                    tools,
                    key,
                    ProfileChoice::OwnSandbox { pin: false },
                    None,
                );
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

/// The zone named by the first live line of a container's `inuse` file.
///
/// That file is a leftover of an older version and nothing writes it any more,
/// which is why "занят сетью …" never actually appeared in this menu. It is
/// still read (a container from that era may carry one), and the launch
/// registry — the same source `vpn-zone profile list` and the container removal
/// dialog use — answers the question for everything else.
fn live_tenant(running: &Path, inuse: &Path) -> Option<String> {
    let text = fs::read_to_string(inuse).ok()?;
    text.lines()
        .filter_map(registry::parse_record)
        .find(|record| registry::alive(running, record.pid))
        .map(|record| record.zone)
        .filter(|zone| !zone.is_empty())
}

/// The throwaway containers that are open right now: a registry directory named
/// `vpn-profile-*` whose directory still exists (below the state directory, or
/// in `/tmp` from before the move) and which has at least one live tenant.
fn open_throwaways(running: &Path) -> Vec<TmpJoinRow> {
    let mut out = Vec::new();
    for dir in registry::dirs(running) {
        let Some(name) = dir.file_name() else {
            continue;
        };
        if !name.as_bytes().starts_with(b"vpn-profile-") {
            continue;
        }
        let state = running.parent().unwrap_or(running);
        let Some(tmp) = crate::launch::throwaway_path(state, name) else {
            continue;
        };
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
                .is_some_and(|record| registry::alive(running, record.pid));
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
    let argv = launch_argv(tools, key, zone_choice, container, cmd);
    let e = exec_command(&argv);
    eprintln!("не удалось запустить {}: {e}", tools.runner.display());
    ExitCode::from(EXIT_NOT_STARTED)
}

/// [`launch`] of an answer the person gave, watched for a hand-over when
/// [`watch_handover`] says so: the program is then started as a child
/// instead of in place. Gone with success without ever opening a window (the
/// Wayland proxy's word, [`opened_or_ended`]) — however long that took: it
/// handed the launch to the copy that runs, and [`HANDOVER`] remembers that —
/// the next click on it while it runs raises that copy with no question, as
/// every click on a running program did before. A window of its own: the
/// picker leaves, and the program goes on without it. No proxy on the way
/// (no word to come): the picker leaves, and learns nothing.
fn launch_asked(
    tools: &Tools,
    key: &str,
    zone_choice: &str,
    container: &Container,
    cmd: &[OsString],
    memory: &Memory,
) -> ExitCode {
    let in_zone = std::env::var_os(launch::ENV_CURRENT).is_some_and(|v| !v.is_empty());
    if !watch_handover(memory, zone_choice, in_zone) {
        return launch(tools, key, zone_choice, container, cmd);
    }
    let argv = launch_argv(tools, key, zone_choice, container, cmd);
    // The program's first window, told by the Wayland proxy through a pipe of
    // ours (`wl_proxy::window_opened`, taken by `wl-sandbox`). No pipe: the
    // launch goes on as any other, and nothing is learned.
    let Ok((heard, told)) = crate::sys::pipe() else {
        return launch(tools, key, zone_choice, container, cmd);
    };
    let told_raw = told.as_raw_fd();
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).env(
        crate::wl_sandbox::ENV_OPENED_FD,
        crate::wl_sandbox::OPENED_FD.to_string(),
    );
    // SAFETY: between fork and exec: dup2/fcntl on descriptors of ours.
    unsafe {
        command.pre_exec(move || {
            let fd = crate::wl_sandbox::OPENED_FD;
            let done = if told_raw == fd {
                libc::fcntl(fd, libc::F_SETFD, 0)
            } else {
                libc::dup2(told_raw, fd)
            };
            if done < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = command.spawn();
    drop(told);
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            eprintln!("не удалось запустить {}: {e}", tools.runner.display());
            return ExitCode::from(EXIT_NOT_STARTED);
        }
    };
    let status = match opened_or_ended(&heard, &mut child) {
        // A window of its own: no hand-over. The picker leaves, the program
        // goes on without it.
        Heard::Opened | Heard::Nothing => return ExitCode::SUCCESS,
        Heard::Ended(status) => status,
    };
    // Gone without ever opening a window, with success: it handed the launch
    // over to the copy that runs — remembered, however long that took.
    if status.success() {
        let dir = tools.state.join(HANDOVER);
        let _ = fs::create_dir_all(&dir).and_then(|()| fs::write(dir.join(key), ""));
    }
    ExitCode::from(status.code().map_or(1, |c| c as u8))
}

/// What [`opened_or_ended`] heard first.
enum Heard {
    /// The program opened a window.
    Opened,
    /// Nobody will say: the launch went without the Wayland proxy
    /// ([`crate::wl_sandbox::WORD_NONE`]).
    Nothing,
    /// The launch ended, no window opened.
    Ended(std::process::ExitStatus),
}

/// Whichever comes first, as long as it takes: the word that the program
/// opened a window, or the launch's end. No clock: a hand-over that takes
/// long on a loaded machine is a hand-over all the same, and a window that
/// comes late is a window.
fn opened_or_ended(heard: &OwnedFd, child: &mut std::process::Child) -> Heard {
    let pidfd = crate::sys::pidfd_open(child.id() as i32);
    loop {
        let mut fds = vec![libc::pollfd {
            fd: heard.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        if let Some(fd) = &pidfd {
            fds.push(libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // SAFETY: a valid array of pollfd and its length.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                std::thread::sleep(crate::sys::LOOK_AGAIN);
            }
            continue;
        }
        if fds[0].revents != 0 {
            let mut byte = [0u8; 1];
            // SAFETY: a valid descriptor and a buffer of one byte.
            let n = unsafe { libc::read(heard.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
            return match (n, byte[0]) {
                (1, crate::wl_sandbox::WORD_OPENED) => Heard::Opened,
                (1, _) => Heard::Nothing,
                // The end of the pipe with no word: nobody holds it any more
                // — the launch is ending (its descriptors close a moment
                // before it can be waited for; waited for, then).
                _ => match child.wait() {
                    Ok(status) => Heard::Ended(status),
                    Err(_) => Heard::Nothing,
                },
            };
        }
        // Ended, and nothing in the pipe (a word said on the way would have
        // been heard above, first).
        if fds.get(1).is_some_and(|f| f.revents != 0) {
            return match child.wait() {
                Ok(status) => Heard::Ended(status),
                Err(_) => Heard::Nothing,
            };
        }
    }
}

/// The `run` command line of a launch, with the environment it needs.
fn launch_argv(
    tools: &Tools,
    key: &str,
    zone_choice: &str,
    container: &Container,
    cmd: &[OsString],
) -> Vec<OsString> {
    // The shortcut's key is also the app-id the compositor restriction and the
    // sandbox permissions are keyed by. (`docs/GOTCHAS.md` §6, §7)
    std::env::set_var(launch::ENV_APPID, key);

    // "unconfined" (once "direct") is NOT special here any more, and must not
    // become special again.
    // The picker used to become the command itself for it, and everything
    // `vpn-zone run` adds on the way was lost without a word: the container or
    // sandbox that had just been chosen (or pinned, or set as the default), the
    // compositor restriction and the registry record. "🔒 Своя песочница" with
    // "Прямой интернет" started the program with the whole home in reach, and
    // from inside a LOCKED zone the systemd-run it used went straight past the
    // lock. `vpn-zone run unconfined` does all of it — delegation out of a zone
    // (§13) and the lock included. (`docs/GOTCHAS.md` §10)
    let zone = match crate::launch::network_name(zone_choice) {
        "offline" => {
            launch::ensure_offline_zone(&tools.state);
            "offline"
        }
        other => other,
    };

    run_argv(&tools.runner, zone, container, cmd)
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
    fn the_autostart_flag_is_taken_before_the_command() {
        let a = Args::parse(&argv(&[
            "--autostart",
            "--id",
            "tg",
            "--",
            "telegram",
            "-autostart",
        ]));
        assert!(a.autostart);
        assert_eq!(a.id.as_deref(), Some(OsStr::new("tg")));
        assert_eq!(a.cmd, argv(&["telegram", "-autostart"]));
        // After `--` it belongs to the program.
        let a = Args::parse(&argv(&["--id", "x", "--", "x", "--autostart"]));
        assert!(!a.autostart);
    }

    // --- AUTOSTART -----------------------------------------------------------

    fn unbound(_: &Container) -> Option<String> {
        None
    }

    #[test]
    fn an_unassigned_program_starts_offline_in_a_home_of_its_own() {
        let memory = Memory {
            // What a dialog would preselect is not a consent to go online.
            last: "nl".into(),
            last_profile: "work".into(),
            fallback: "unconfined".into(),
            default_profile: "ask".into(),
            ..Memory::default()
        };
        let plan = autostart_plan(&memory, "tg", anything, unbound);
        assert_eq!(plan.zone, "offline");
        assert_eq!(plan.container.selector(), "app-tg");
        assert!(plan.network_guessed && plan.container_guessed);
    }

    #[test]
    fn what_was_chosen_for_a_program_is_honoured_at_login() {
        let memory = Memory {
            pinned_profile: "work".into(),
            default_profile: "ask".into(),
            ..Memory::default()
        };
        // The container's network: the program's own is gone.
        let bound = |c: &Container| (c.selector() == "work").then(|| "de".to_owned());
        let plan = autostart_plan(&memory, "tg", anything, bound);
        assert_eq!(
            (plan.zone.as_str(), plan.container.selector()),
            ("de", "work".to_owned())
        );
        assert!(!plan.network_guessed && !plan.container_guessed);
        // A container with no network yet: offline, and said.
        let plan = autostart_plan(&memory, "tg", anything, unbound);
        assert_eq!(plan.zone, "offline");
        assert!(plan.network_guessed && !plan.container_guessed);
        // The global default container's network is nobody's choice for an
        // unassigned program: offline at login, bound or not.
        let by_default = Memory {
            default_profile: "work".into(),
            ..Memory::default()
        };
        let plan = autostart_plan(&by_default, "tg", anything, bound);
        assert_eq!(plan.zone, "offline");
        assert!(plan.network_guessed);

        // The global container default is an answer, `ask` is not.
        for (default, selector) in [("main", ""), ("own", "app-tg"), ("work", "work")] {
            let memory = Memory {
                default_profile: default.into(),
                ..Memory::default()
            };
            let plan = autostart_plan(&memory, "tg", anything, unbound);
            assert_eq!(plan.container.selector(), selector, "{default}");
            assert!(!plan.container_guessed, "{default}");
            assert!(plan.network_guessed, "{default}");
        }
        // A default naming a container that is gone is no answer either.
        let memory = Memory {
            default_profile: "gone".into(),
            ..Memory::default()
        };
        let plan = autostart_plan(&memory, "tg", nothing, unbound);
        assert_eq!(plan.container.selector(), "app-tg");
        assert!(plan.container_guessed);

        // Running already: where it runs.
        let memory = Memory {
            running: Some(Running {
                zone: "nl".into(),
                selector: "sb:x".into(),
            }),
            ..Memory::default()
        };
        let plan = autostart_plan(&memory, "tg", anything, unbound);
        assert_eq!(
            (plan.zone.as_str(), plan.container.selector()),
            ("nl", "x".to_owned())
        );
    }

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

    /// `ask` shows the picker at login only when something had to be guessed
    /// and there is a screen; what is chosen starts without a question, and
    /// `offline` or a text console keep the closed variant.
    #[test]
    fn autostart_asks_only_for_what_was_not_chosen_and_only_on_a_screen() {
        let plan = |network_guessed, container_guessed| AutostartPlan {
            zone: "offline".to_owned(),
            container: Container::default(),
            network_guessed,
            container_guessed,
        };
        assert!(autostart_asks("ask", &plan(true, true), true));
        assert!(autostart_asks("ask", &plan(true, false), true));
        assert!(autostart_asks("ask", &plan(false, true), true));
        assert!(
            !autostart_asks("ask", &plan(false, false), true),
            "all chosen: no question"
        );
        assert!(
            !autostart_asks("ask", &plan(true, true), false),
            "a text console: nobody to ask"
        );
        assert!(
            !autostart_asks("offline", &plan(true, true), true),
            "the closed variant, when set"
        );
    }

    #[test]
    fn a_running_program_that_hands_over_is_started_where_it_already_runs() {
        let mut m = memory();
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: "sb:work".to_owned(),
        });
        m.hands_over = true;
        // Even a bound container does not get a say: the window is going to be
        // raised by the process that is already up.
        m.bound = "de".to_owned();
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
                default: "nl".to_owned()
            }
        );
    }

    /// A terminal opened in a zone left every next one in that zone with no
    /// question (owner, 2026-09-25): a program not known to hand over is
    /// asked, with the network it runs in chosen — and a bound container's
    /// network still holds.
    #[test]
    fn a_running_program_not_known_to_hand_over_is_asked() {
        let mut m = memory();
        m.last = "de".to_owned();
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: String::new(),
        });
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "nl".to_owned()
            }
        );
        // The host's network under its old name is chosen as the new one.
        m.running = Some(Running {
            zone: "direct".to_owned(),
            selector: String::new(),
        });
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "unconfined".to_owned()
            }
        );
        m.bound = "de".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Bound {
                zone: "de".to_owned()
            }
        );
    }

    /// Only a launch into the network the program runs in is watched, only
    /// while it is not known to hand over, and never from inside a zone.
    #[test]
    fn a_hand_over_is_watched_for_only_where_it_can_be_told() {
        let mut m = memory();
        assert!(!watch_handover(&m, "nl", false), "not running");
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: String::new(),
        });
        assert!(watch_handover(&m, "nl", false));
        assert!(
            !watch_handover(&m, "de", false),
            "another network: run warns"
        );
        assert!(!watch_handover(&m, "nl", true), "delegated from a zone");
        m.running = Some(Running {
            zone: "direct".to_owned(),
            selector: String::new(),
        });
        assert!(watch_handover(&m, "unconfined", false));
        m.hands_over = true;
        assert!(!watch_handover(&m, "unconfined", false), "known already");
    }

    #[test]
    fn a_container_bound_to_a_network_answers_the_network_question() {
        let mut m = memory();
        m.bound = "nl".to_owned();
        // The last choice is only where a question would start.
        m.last = "de".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Bound {
                zone: "nl".to_owned()
            }
        );
        // A running instance that hands over still wins: its window is
        // raised where it is.
        m.running = Some(Running {
            zone: "nl".to_owned(),
            selector: "work".to_owned(),
        });
        m.hands_over = true;
        assert!(matches!(net_step(&m), NetStep::Running { .. }));
        // One that does not: the container's network, no question.
        m.hands_over = false;
        assert!(matches!(net_step(&m), NetStep::Bound { .. }));
        // And VPN_ZONE_ASK still opens the dialog.
        m.running = None;
        m.ask = true;
        assert!(matches!(net_step(&m), NetStep::Ask { .. }));
    }

    /// A container not bound to a network yet — and the main home, and a
    /// throwaway one — have it asked (`docs/PERMISSIONS.md` §11.8): a
    /// program has no network of its own to skip the question with.
    #[test]
    fn a_container_with_no_network_has_it_asked() {
        let mut m = memory();
        m.last = "nl".to_owned();
        for pinned in ["work", "", THROWAWAY] {
            m.pinned_profile = pinned.to_owned();
            assert_eq!(
                net_step(&m),
                NetStep::Ask {
                    default: "nl".to_owned()
                },
                "{pinned}"
            );
        }
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
        m.fallback = "unconfined".to_owned();
        assert_eq!(
            net_step(&m),
            NetStep::Ask {
                default: "unconfined".to_owned()
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
        assert_eq!(Container::from_selector("", nothing), Container::default());
        assert_eq!(
            Container::from_selector(MAIN, nothing),
            Container::default()
        );
        assert_eq!(
            Container::from_selector("__fs__", nothing),
            Container {
                fs_sandbox: true,
                ..Container::default()
            }
        );
        // A container that exists, by its name, whatever its home.
        assert_eq!(
            Container::from_selector("work", anything),
            Container {
                profile: "work".to_owned(),
                ..Container::default()
            }
        );
        // The old prefix asks for a home of its own and nothing else: `run
        // --sandbox` refuses a layer or the main home by that name.
        assert_eq!(
            Container::from_selector("sb:work", anything),
            Container {
                fs_sandbox: true,
                sandbox: "work".to_owned(),
                ..Container::default()
            }
        );
        // One that is gone is made again with a home of its own: the
        // program's own home, never the whole real one.
        assert_eq!(
            Container::from_selector("sb:app-firefox", nothing),
            Container {
                fs_sandbox: true,
                sandbox: "app-firefox".to_owned(),
                ..Container::default()
            }
        );
        // Checked: a container that has been deleted is no answer, and the
        // caller decides.
        assert_eq!(Container::from_selector_checked("work", nothing), None);
        assert_eq!(
            Container::from_selector_checked("work", anything).map(|c| c.profile),
            Some("work".to_owned())
        );
        assert_eq!(
            Container::from_selector_checked(TMP, nothing).map(|c| c.profile),
            Some(TMP.to_owned())
        );
    }

    #[test]
    fn the_selector_that_is_written_back_is_the_choice_not_the_variable() {
        let sandbox = Container {
            fs_sandbox: true,
            sandbox: "work".to_owned(),
            ..Container::default()
        };
        assert_eq!(sandbox.selector(), "work");
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
        // And it round-trips, which is what makes the re-exec faithful: once
        // made, the container is found by its name.
        assert_eq!(
            Container::from_selector(&sandbox.selector(), anything).selector(),
            "work"
        );
        assert_eq!(
            Container::from_selector(&sandbox.selector(), nothing),
            sandbox
        );
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
    fn the_global_default_container_outranks_the_last_choice() {
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
        // And a last choice that is gone is the program's own home, not the
        // whole real one.
        assert_eq!(
            container_without_dialog(&m, "k", nothing, None).selector(),
            "app-k"
        );
    }

    /// One launch, one container: a default is a whole container, never laid
    /// over a part of the last choice — the shell's partial overlay made one
    /// launch of a layer and a sandbox at once.
    #[test]
    fn a_default_container_is_whole() {
        let mut m = memory();
        m.last_profile = "work".to_owned();
        m.default_profile = "main".to_owned();
        assert_eq!(
            container_without_dialog(&m, "k", anything, None),
            Container::default()
        );
        m.default_profile = "other".to_owned();
        let c = container_without_dialog(&m, "k", anything, None);
        assert_eq!((c.profile.as_str(), c.sandbox.as_str()), ("other", ""));
    }

    #[test]
    fn a_pin_is_dropped_only_when_what_it_names_is_gone() {
        assert!(pin_is_valid("", nothing));
        // Built-in choices are not zones and are always valid.
        assert!(pin_is_valid("unconfined", nothing));
        assert!(pin_is_valid("direct", nothing));
        assert!(pin_is_valid("offline", nothing));
        assert!(pin_is_valid("nl", |z| z == "nl"));
        assert!(!pin_is_valid("nl", nothing));

        // The program's own container is valid before its first launch makes
        // it: checking it as one that must exist erased the pin on the next
        // click, and "🔒 Своя песочница — всегда" never worked at all.
        assert!(profile_pin_is_valid("app-firefox", nothing));
        assert!(profile_pin_is_valid("sb:app-firefox", nothing));
        // A pinned sandbox is made again when it is gone, as it always was.
        assert!(profile_pin_is_valid("sb:work", nothing));
        assert!(!profile_pin_is_valid("work", nothing));
        assert!(profile_pin_is_valid(THROWAWAY, nothing));
        assert!(profile_pin_is_valid(MAIN, nothing));
        assert!(profile_pin_is_valid("", nothing));
        assert!(profile_pin_is_valid("work", |p| p == "work"));
        assert!(!profile_pin_is_valid("work", nothing));
    }

    // --- THE MENUS -----------------------------------------------------------

    #[test]
    fn the_network_menu_offers_every_choice_twice_once_as_a_pin() {
        let zone = |name: &str| MenuZone {
            name: name.to_owned(),
            ..MenuZone::default()
        };
        let menu = net_menu(&[zone("de"), zone("nl")], "", "основной");
        assert_eq!(
            tags(&menu),
            [
                "unconfined",
                "offline",
                "de",
                "nl",
                "pin:unconfined",
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
        // The way back out of a pin is only offered when there is one — of
        // the program's container: the network is the container's.
        let menu = net_menu(&[], "work", "work");
        assert_eq!(
            text_of(&menu, "unpin"),
            "↺ Спрашивать снова (программа закреплена за контейнером work)"
        );
        // A host interface is not called a VPN, and a dead tunnel says so.
        let menu = net_menu(
            &[
                MenuZone {
                    name: "lan".to_owned(),
                    host_interface: true,
                    dead: false,
                    ..MenuZone::default()
                },
                MenuZone {
                    name: "nl".to_owned(),
                    host_interface: false,
                    dead: true,
                    ..MenuZone::default()
                },
                MenuZone {
                    name: "mz".to_owned(),
                    system_zone: Some("sz".to_owned()),
                    ..MenuZone::default()
                },
            ],
            "",
            "основной",
        );
        assert_eq!(
            text_of(&menu, "lan"),
            "Через интерфейс: lan (без шифрования)"
        );
        assert_eq!(text_of(&menu, "nl"), "VPN: nl — туннель не отвечает");
        // A zone through a system zone is a VPN, and says whose tunnel it is.
        assert_eq!(text_of(&menu, "mz"), "VPN: mz (через системную зону sz)");
    }

    #[test]
    fn the_container_in_force_is_named_the_way_the_user_chose_it() {
        assert_eq!(container_label(""), "основной");
        assert_eq!(container_label(MAIN), "основной");
        assert_eq!(container_label(THROWAWAY), "разовая песочница");
        assert_eq!(container_label("sb:app-firefox"), "своя песочница");
        assert_eq!(container_label("sb:work"), "песочница work");
        assert_eq!(container_label("work"), "work");
        // A program's own container is one by its name, whatever the prefix.
        assert_eq!(container_label("app-firefox"), "своя песочница");
        use crate::container::Home;
        assert_eq!(label_of("dev", Some(Home::Private)), "песочница dev");
        assert_eq!(label_of("files", Some(Home::Main)), "основной files");
        assert_eq!(label_of("work", Some(Home::Layer)), "work");
    }

    #[test]
    fn the_container_menu_lists_the_ways_to_split_data_and_the_ways_to_pin_them() {
        let profiles = vec![
            ProfileRow {
                name: "work".to_owned(),
                busy_in: "de".to_owned(),
                main: false,
                bound: String::new(),
            },
            ProfileRow {
                name: "личное".to_owned(),
                busy_in: String::new(),
                main: false,
                bound: String::new(),
            },
            ProfileRow {
                name: "files".to_owned(),
                busy_in: "de".to_owned(),
                main: true,
                bound: String::new(),
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
                "общая",
                "pin:общая",
                "__newsb__",
                "work",
                "pin:work",
                "личное",
                "pin:личное",
                "files",
                "pin:files",
                "tmpjoin:/tmp/vpn-profile-abc",
                "__tmp__",
                "__new__",
            ]
        );
        assert_eq!(text_of(&menu, "общая"), "🔒 Песочница «общая»");
        // The main home says what it is, and is never "busy": it is one
        // identity in every network.
        assert_eq!(
            text_of(&menu, "files"),
            "⚠ Основной «files» (весь настоящий дом)"
        );
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
        let menu = profile_menu(&[], &[], &[], "work", "nl");
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
                "--container",
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
            // `sb:work` of an older window: here, before anything resolves
            // it, the name as a sandbox.
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

    /// A remembered choice that is no longer offered starts the question on
    /// the safe rows — never the first one, which is the host's network, nor
    /// the main profile with the whole home.
    #[test]
    fn a_choice_that_is_gone_is_not_replaced_by_the_first_row() {
        let zones = vec![MenuZone {
            name: "de".to_owned(),
            host_interface: false,
            system_zone: None,
            dead: false,
        }];
        let nets = window_nets(&zones, "nl-removed");
        let chosen: Vec<&str> = nets
            .iter()
            .filter(|i| i.selected)
            .map(|i| i.tag.as_str())
            .collect();
        assert_eq!(chosen, ["offline"]);
        assert!(window_nets(&zones, "de")
            .iter()
            .any(|i| i.selected && i.tag == "de"));
        // A container's network goes with its row: the window does not
        // offer it with another.
        let row = |name: &str, bound: &str| ProfileRow {
            name: name.to_owned(),
            bound: bound.to_owned(),
            ..ProfileRow::default()
        };
        let items = window_containers(
            "firefox",
            &[row("app-firefox", "nl"), row("dev", "de")],
            &[row("work", "")],
            &[],
            "",
        );
        let bound_of = |tag: &str| items.iter().find(|i| i.tag == tag).unwrap().bound.clone();
        assert_eq!(bound_of("__ownsb__").as_deref(), Some("nl"));
        assert_eq!(bound_of("dev").as_deref(), Some("de"));
        assert_eq!(bound_of("work"), None);

        let containers = window_containers("firefox", &[], &[], &[], "sb:removed");
        let chosen: Vec<&str> = containers
            .iter()
            .filter(|i| i.selected)
            .map(|i| i.tag.as_str())
            .collect();
        assert_eq!(chosen, ["__ownsb__"]);
    }
}
