//! `vpn-zone run` — everything that happens between a click on a shortcut and
//! the program starting inside a zone.
//!
//! The order of the steps is the interesting part, and every one of them is
//! there because something went wrong without it:
//!
//!  1. **a launch coming FROM a zone is delegated outwards.** A process that is
//!     already in a user+net namespace cannot enter another one ("nsenter:
//!     reassociate to namespaces failed"), so a link clicked in a messenger
//!     inside a zone opened the picker and then no browser at all — and "direct
//!     internet" silently inherited the zone's network instead of being direct.
//!     `systemd --user` lives in the root namespace and its socket is visible
//!     from inside the zone, so the launch is handed to it and starts outside;
//!  2. **a locked zone keeps its launches**, because a quarantine zone must not
//!     be able to open a program in another network. Not by re-entering the zone
//!     (the kernel forbids that too) but by dropping the selection arguments and
//!     running the command where we already are;
//!  3. the container and sandbox flags are parsed, and a throwaway container is
//!     created;
//!  4. the command is wrapped in the compositor restriction (`wl-sandbox`) and,
//!     if asked for, the filesystem sandbox (`fs-sandbox`);
//!  5. the launch registry says whether this program is already running in
//!     ANOTHER network — the "I thought I was on the VPN" warning;
//!  6. the zone is started if it was down, we write ourselves into the registry
//!     and `execvp` into `nsenter`.
//!
//! **`direct` takes the same road**, minus the zone. It used to be a special
//! case of the picker, which simply became the command — and with that the
//! container or sandbox the user had chosen, the compositor restriction and the
//! registry record were all dropped without a word: "🔒 Своя песочница" plus
//! "Прямой интернет" started the program with the whole `$HOME` in reach.
//! Now only the NAMESPACE step differs: there is no zone to enter, so a
//! container gets a user+mount namespace of its own from `unshare` (see
//! [`entry_argv`]) and everything else is exactly what a zone launch gets.
//!
//! **The last step must be an `exec`.** The pid does not change, so the registry
//! record written just before it stays true for as long as the program runs —
//! the picker, the conflict warning and the throwaway-container cleanup all read
//! that pid. Anything that forked here instead would leave a record naming a
//! process that exits immediately. (`docs/GOTCHAS.md` §5)

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli;
use crate::profile::{exec_command, EXIT_NOT_STARTED};
use crate::registry;
use crate::tools::Tools;

/// Marks the descendants of a zone. Its presence is what step 1 keys on.
pub const ENV_CURRENT: &str = "VPN_ZONE_CURRENT";
/// Set on the delegated launch so that it does not delegate itself again.
pub const ENV_DELEGATED: &str = "VPN_ZONE_DELEGATED";
/// The launcher's stable key for the program, put there by the picker.
pub const ENV_APPID: &str = "VPN_ZONE_APPID";
/// On a delegated launch: the zone it was asked for from. A zone's lock is
/// out of its own sight (`zone::hide_project_state`), so the host looks it up.
const ENV_FROM: &str = "VPN_ZONE_FROM";
/// Print the resulting command and start nothing.
pub const ENV_DRYRUN: &str = "VPN_ZONE_DRYRUN";
/// On a launch the broker started without a question (the same container
/// asking for itself): what the program's name would relax — no Wayland
/// proxy, no compositor restriction — is not relaxed. The requester chose
/// the command's first word, and so the name the lists are read by.
pub const ENV_UNASKED: &str = "VPN_ZONE_UNASKED";

/// Environment variables that name a compositor's IPC socket — a way to have
/// the compositor spawn a process on the host. Dropped from launches into a
/// zone, where the sockets are not either (`docs/LEAK-MODEL.md` §13).
pub const COMPOSITOR_IPC_VARS: [&str; 4] = [
    "NIRI_SOCKET",
    "SWAYSOCK",
    "I3SOCK",
    "HYPRLAND_INSTANCE_SIGNATURE",
];

/// Marker file of a locked ("no escape") zone.
pub const NO_ESCAPE: &str = "no-escape";

/// The built-in "network" that is the host's own: no zone, no tunnel, and none
/// of a zone's containment — the host's resolver, its session bus, its
/// `systemd --user`, its X server. Named for exactly that, so that it is never
/// taken for a harmless default. Not a directory in the state dir and never
/// one: `vpn-zone add` refuses the name, and a launch refuses it while a zone
/// of that name survives from before the name was taken.
pub const UNCONFINED: &str = "unconfined";
/// Its name until 2026-09. Accepted wherever a network name comes in — the
/// command line, pins, settings, containers, Nix, the registry — and never
/// written again.
pub const UNCONFINED_ALIAS: &str = "direct";

/// A network name as the rest of the code knows it: the old name of
/// [`UNCONFINED`] becomes the new one, everything else stays.
pub fn network_name(name: &str) -> &str {
    if name == UNCONFINED_ALIAS {
        UNCONFINED
    } else {
        name
    }
}

/// Whether this process is a zone's: a program started into a zone carries
/// [`ENV_CURRENT`]. A program that drops the variable only loses what the
/// host would do for it; the zone's walls are the kernel's.
pub fn in_zone() -> bool {
    std::env::var_os(ENV_CURRENT).is_some_and(|v| !v.is_empty())
}

/// Names a zone directory cannot be entered by: they mean [`UNCONFINED`].
pub fn is_unconfined_name(name: &str) -> bool {
    matches!(name, UNCONFINED | UNCONFINED_ALIAS)
}
/// The other built-in choice: a zone with loopback only, created on demand.
pub const OFFLINE: &str = "offline";

/// Programs that keep the full set of compositor protocols.
///
/// They are the ones that live off exactly those protocols: screenshot tools,
/// the clipboard manager, screen recording, the compositor's own shell. The
/// sandboxes at the end (flatpak, bwrap, podman, distrobox) are here NOT by
/// oversight: they create a security context of their own, and a restricted
/// client has that protocol taken away — one sandbox cannot be nested in
/// another. Their own isolation is stricter than ours, so they get to use it.
/// (`docs/GOTCHAS.md` §7)
pub const WAYLAND_ALLOWED: [&str; 27] = [
    "grim",
    "slurp",
    "swappy",
    "wl-copy",
    "wl-paste",
    "copyq",
    "wf-recorder",
    "obs",
    "obs-studio",
    "spectacle",
    "ksnip",
    "wtype",
    "ydotool",
    "niri",
    "noctalia",
    "noctalia-shell",
    "waybar",
    "wayland-info",
    "wlr-randr",
    "kanshi",
    "gammastep",
    "wlsunset",
    "wdisplays",
    "flatpak",
    "bwrap",
    "podman",
    "distrobox",
];

/// The warning shown when the same program is already running somewhere else.
/// Verbatim from the shell version: it is the one message in the project a user
/// reads under time pressure.
const CONFLICT_MESSAGE: &str = "«{app}» уже запущена в сети «{busy}», а ты открываешь её в «{zone}».\n\nОсторожно: у программ с одним процессом на профиль (браузеры, Telegram, Discord) окно ОТКРОЕТСЯ и будет выглядеть обычно — но нарисует его старый процесс, и трафик в нём пойдёт через «{busy}», а не через «{zone}». Со стороны неотличимо, поэтому и предупреждаем.\n\nЕсли у программы каждое окно своё (терминалы, редакторы), всё в порядке — отметь «не спрашивать снова».";

/// The same warning when what is being handed over is a LINK (`steam://…`,
/// `tg://…`, `https://…`). A single-instance program hands it to the process
/// that is already up, so the link — or the game a Steam shortcut starts — is
/// opened in THAT process's network; "the window will open" is the wrong
/// picture for it. (`docs/GOTCHAS.md` §5)
const CONFLICT_URL_MESSAGE: &str = "«{app}» уже запущена в сети «{busy}», а ссылку ты открываешь в «{zone}».\n\nОсторожно: ссылку, скорее всего, примет уже запущенный процесс — и откроет её в сети «{busy}», а не «{zone}». Так ведут себя браузеры, мессенджеры и Steam: игра с ярлыка запускается в сети клиента. Со стороны неотличимо, поэтому и предупреждаем.\n\nЕсли программа на каждую ссылку запускает свой процесс, всё в порядке — отметь «не спрашивать снова».";

/// What the user asked for, before anything was created or checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub zone: OsString,
    pub container: Container,
    pub sandbox: Sandbox,
    /// The program and its arguments. May be empty: the shell version passed
    /// nothing to `nsenter` in that case, and `nsenter` with no command starts a
    /// shell inside the zone — which is a perfectly good thing to want.
    pub cmd: Vec<OsString>,
}

/// The data container of a launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Container {
    /// No layers: `~/` as it is.
    Main,
    /// A container with a layer over the home (`--profile`, `--container`).
    /// Before [`resolve_selection`], any named container: its kind is not
    /// known yet.
    Named(OsString),
    /// A named container of the main home: `~/` as it is, under the
    /// container's name, network and permissions.
    MainNamed(OsString),
    /// `--tmp-profile`: a fresh layer in `/tmp`, erased when the last program
    /// living in it exits.
    TmpNew,
    /// `--tmp-profile --join <dir>`: put this program into a throwaway
    /// container that is already open, so that two programs share one session.
    TmpJoin(PathBuf),
}

/// The filesystem sandbox of a launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sandbox {
    None,
    /// `--fs-sandbox`: an empty home that dies with the program.
    Throwaway,
    /// `--sandbox <name>`: a persistent home shared by everything started into
    /// that sandbox.
    Named(OsString),
}

/// Everything that can be wrong with `vpn-zone run`'s arguments.
///
/// The texts are the shell's `${1:?…}` messages word for word — they are what
/// the user sees in a terminal, and translating them is a step of its own
/// (ROADMAP M6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    MissingZone,
    MissingProfile,
    MissingJoinDir,
    MissingSandbox,
    MissingContainer,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingZone => write!(f, "нужно имя"),
            Self::MissingProfile => write!(f, "нужно имя профиля"),
            Self::MissingJoinDir => write!(f, "нужен каталог временного контейнера"),
            Self::MissingSandbox => write!(f, "нужно имя песочницы"),
            Self::MissingContainer => write!(f, "нужно имя контейнера"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Selection {
    /// Parse `<zone> [--container C | --profile P | -p P | --tmp-profile
    /// [--join DIR]] [--fs-sandbox | --sandbox NAME] [--] cmd…`.
    ///
    /// Positional, exactly as the shell version: the container flag may only
    /// come first and the sandbox flag second, and everything after the
    /// optional `--` is the command even when it looks like a flag. The picker
    /// builds the line in that order, and a `-p` that arrives later belongs to
    /// the program, not to us.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let mut rest = argv.iter();
        let zone = rest
            .next()
            .filter(|z| !z.is_empty())
            .ok_or(ArgError::MissingZone)?;
        let zone = if zone == UNCONFINED_ALIAS {
            OsString::from(UNCONFINED)
        } else {
            zone.clone()
        };
        let mut rest: Vec<OsString> = rest.cloned().collect();

        let container = match rest.first().map(OsString::as_os_str) {
            Some(f) if f == "--container" => {
                let name = rest.get(1).filter(|n| !n.is_empty()).cloned();
                let name = name.ok_or(ArgError::MissingContainer)?;
                rest.drain(..2.min(rest.len()));
                Container::Named(name)
            }
            Some(f) if f == "--profile" || f == "-p" => {
                let name = rest.get(1).filter(|n| !n.is_empty()).cloned();
                let name = name.ok_or(ArgError::MissingProfile)?;
                rest.drain(..2.min(rest.len()));
                Container::Named(name)
            }
            Some(f) if f == "--tmp-profile" => {
                rest.remove(0);
                if rest.first().is_some_and(|f| f == "--join") {
                    let dir = rest.get(1).filter(|d| !d.is_empty()).cloned();
                    let dir = dir.ok_or(ArgError::MissingJoinDir)?;
                    rest.drain(..2.min(rest.len()));
                    Container::TmpJoin(PathBuf::from(dir))
                } else {
                    Container::TmpNew
                }
            }
            _ => Container::Main,
        };

        let sandbox = match rest.first().map(OsString::as_os_str) {
            Some(f) if f == "--fs-sandbox" => {
                rest.remove(0);
                Sandbox::Throwaway
            }
            Some(f) if f == "--sandbox" => {
                let name = rest.get(1).filter(|n| !n.is_empty()).cloned();
                let name = name.ok_or(ArgError::MissingSandbox)?;
                rest.drain(..2.min(rest.len()));
                Sandbox::Named(name)
            }
            _ => Sandbox::None,
        };

        if rest.first().is_some_and(|f| f == "--") {
            rest.remove(0);
        }

        Ok(Self {
            zone,
            container,
            sandbox,
            cmd: rest,
        })
    }
}

/// Drop the selection arguments of a `run` line and leave the command.
///
/// This is what a LOCKED zone does with a launch: we are already inside that
/// zone, entering it a second time is impossible, and mounting a container
/// layer from in here is impossible too (the capabilities are gone), so the
/// choice is simply thrown away and the command runs where it is.
///
/// The sandbox flags have to be dropped as well, and that is not cosmetic:
/// while they were left in the line, `--` was no longer found where it was
/// expected and the shell tried to execute the flag itself — "--sandbox: not
/// found". The program did not open at all, and the message went to a
/// shortcut's stderr, where nobody reads it.
pub fn strip_selection(argv: &[OsString]) -> Vec<OsString> {
    let mut rest: Vec<OsString> = argv.iter().skip(1).cloned().collect();
    match rest.first().map(OsString::as_os_str) {
        Some(f) if f == "--profile" || f == "-p" || f == "--container" => {
            rest.drain(..2.min(rest.len()));
        }
        Some(f) if f == "--tmp-profile" => {
            rest.remove(0);
            if rest.first().is_some_and(|f| f == "--join") {
                rest.drain(..2.min(rest.len()));
            }
        }
        _ => {}
    }
    match rest.first().map(OsString::as_os_str) {
        Some(f) if f == "--fs-sandbox" => {
            rest.remove(0);
        }
        Some(f) if f == "--sandbox" => {
            rest.drain(..2.min(rest.len()));
        }
        _ => {}
    }
    if rest.first().is_some_and(|f| f == "--") {
        rest.remove(0);
    }
    rest
}

/// The word of a command line that names the program.
///
/// Wrappers and variable assignments are skipped: for `env DESKTOPINTEGRATION=1
/// AyuGram` the answer is `AyuGram` and not `env`. Two traps here, both paid
/// for (`docs/GOTCHAS.md` §7):
///
/// * only a REAL assignment is skipped. The pattern used to be `*=*`, which
///   also threw away ordinary arguments with an equals sign in them — the
///   script text after `sh -c`, for instance — and the app-id came out empty;
/// * an argument with a space in it is taken as the program name (through
///   `basename`) rather than skipped, because that is the `sh -c '…'` case and
///   an empty app-id would mean no compositor restriction at all.
pub fn app_word(cmd: &[OsString]) -> Option<&OsStr> {
    for word in cmd {
        let bytes = word.as_bytes();
        if matches!(bytes, b"env" | b"sh" | b"bash" | b"setsid" | b"nohup")
            || bytes.starts_with(b"-")
        {
            continue;
        }
        if bytes.contains(&b' ') {
            return Some(basename(word));
        }
        if is_assignment(bytes) {
            continue;
        }
        return Some(basename(word));
    }
    None
}

/// Does this command hand a LINK to its program (`steam://rungameid/…`,
/// `tg://resolve?…`, `https://…`)?
///
/// Only the warning text depends on it, so a rough test is the right one: any
/// argument with `://` in it that is not the program itself.
pub fn hands_over_a_link(cmd: &[OsString]) -> bool {
    cmd.iter()
        .skip(1)
        .any(|arg| arg.as_bytes().windows(3).any(|w| w == b"://"))
}

/// `[A-Za-z_]*=*` as a shell glob: a name-looking word with an equals sign
/// somewhere after the first character.
///
/// Public because the picker derives its memory key the same way when a launch
/// did not come from a shortcut (`crate::picker::fallback_key`), and the two
/// must not drift apart.
pub fn is_assignment(word: &[u8]) -> bool {
    matches!(word.first(), Some(b) if b.is_ascii_alphabetic() || *b == b'_')
        && word[1..].contains(&b'=')
}

/// `basename`: the last path component, trailing slashes ignored.
pub fn basename(path: &OsStr) -> &OsStr {
    let bytes = path.as_bytes();
    let trimmed = bytes.trim_ascii_end_matches_slash();
    if trimmed.is_empty() {
        // "/" and "//" answer "/", "" answers "" — what basename(1) prints.
        return OsStr::from_bytes(&bytes[..bytes.len().min(1)]);
    }
    let start = trimmed
        .iter()
        .rposition(|b| *b == b'/')
        .map_or(0, |i| i + 1);
    OsStr::from_bytes(&trimmed[start..])
}

/// The private half of [`basename`]: `${x%%/}` for bytes.
trait TrimSlash {
    fn trim_ascii_end_matches_slash(&self) -> &Self;
}

impl TrimSlash for [u8] {
    fn trim_ascii_end_matches_slash(&self) -> &[u8] {
        let mut end = self.len();
        while end > 0 && self[end - 1] == b'/' {
            end -= 1;
        }
        &self[..end]
    }
}

/// Reduce an identifier to one word of `[A-Za-z0-9_.-]`, at most 64 bytes.
///
/// It goes into an argument of `wl-sandbox`, so it MUST be a single word: a
/// space split the argument in two and the wrong program was started (measured
/// on `sh -c 'echo …'`). Newlines are removed rather than replaced because the
/// first line of a multi-line command is empty — `cut` then returned nothing at
/// all and the launch died with "need an app-id".
///
/// Byte-wise on purpose, like the `tr` it replaces: a non-ASCII name becomes a
/// row of underscores, which is ugly and stable, and the shell version has been
/// answering that way for as long as the permission files have existed.
/// The registry's file name for a program: the picker's keys as they are
/// (`desktop::stable_key` makes them of these characters already), anything
/// else reduced to them — never a path, never `.` or `..`, never empty.
pub fn registry_key(raw: &OsStr) -> OsString {
    let kept: Vec<u8> = raw
        .as_bytes()
        .iter()
        .take(200)
        .map(|&b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-') {
                b
            } else {
                b'_'
            }
        })
        .collect();
    if kept.is_empty() || kept.iter().all(|&b| b == b'.') {
        return OsString::from("программа");
    }
    OsString::from_vec(kept)
}

pub fn sanitize_app_id(raw: &OsStr) -> OsString {
    let mut out: Vec<u8> = Vec::with_capacity(raw.as_bytes().len());
    for &b in raw.as_bytes() {
        if b == b'\n' {
            continue;
        }
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-') {
            out.push(b);
        } else {
            out.push(b'_');
        }
        if out.len() == 64 {
            break;
        }
    }
    OsString::from_vec(out)
}

/// `$VAR`, or `None` when it is unset or empty — the shell's `${VAR:-}` test.
fn env_nonempty(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// The human-readable name the picker remembered for this key
/// (`.labels/<key>`), if any.
///
/// Dialogs should say «Telegram», not "org.telegram.desktop": the raw id is
/// the PERMISSION KEY, not a name for humans. A launch that never went through
/// the picker has no label — callers fall back to the id, which is still
/// better than naming no program at all.
fn pretty_label(state: &Path, key: &OsStr) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let text = std::fs::read_to_string(state.join(".labels").join(key)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Is there a graphical session to show a dialog on?
///
/// Without one `kdialog` dies immediately, and treating that as "the user
/// cancelled" turned a launch from a terminal into silence. The picker and the
/// filesystem sandbox make the same test, and this is the one they make.
/// (`docs/GOTCHAS.md` §5, §6)
pub fn has_display() -> bool {
    env_nonempty("WAYLAND_DISPLAY").is_some() || env_nonempty("DISPLAY").is_some()
}

/// Run a program inside a zone. Returns only when something went wrong: the
/// successful path ends in `execvp`.
pub fn run(tools: &Tools, argv: &[OsString]) -> u8 {
    // The picker's pipe, when it watches this launch for a hand-over
    // (`crate::picker`): taken at once — nothing this starts on the way
    // (a dialog, systemctl) inherits it —, given on to `wl-sandbox` just
    // before its exec, and on every other way out told that no word will
    // come: a launch cancelled or only shown (`--dry-run`) that ends with
    // success is no hand-over.
    struct NoWord;
    impl Drop for NoWord {
        fn drop(&mut self) {
            crate::wl_sandbox::no_word();
        }
    }
    crate::wl_sandbox::take_opened();
    let _no_word = NoWord;
    // --- 1. FROM INSIDE A ZONE: DELEGATE OR STAY ---
    if let Some(current) = env_nonempty(ENV_CURRENT) {
        if env_nonempty(ENV_DELEGATED).is_none() {
            return if tools.state.join(&current).join(NO_ESCAPE).exists() {
                run_locked(&current, argv)
            } else {
                delegate(tools, argv)
            };
        }
    }
    // The guard has done its job for THIS launch and must not travel into the
    // program. It used to: a browser opened from a messenger inside a zone
    // carried `VPN_ZONE_DELEGATED=1` for the rest of its life, so a link
    // clicked in THAT browser skipped the delegation above and died in
    // `nsenter` with "reassociate to namespaces failed" — the very failure the
    // delegation exists to avoid. Whether it was there is kept for the
    // registry: a launch asked for from inside a zone is marked so.
    let from_zone = env_nonempty(ENV_DELEGATED).is_some();
    std::env::remove_var(ENV_DELEGATED);
    let unasked = env_nonempty(ENV_UNASKED).is_some();
    std::env::remove_var(ENV_UNASKED);
    let asked_from = env_nonempty(ENV_FROM).filter(|_| from_zone);
    std::env::remove_var(ENV_FROM);
    // A locked zone's own launches stay in it (`run_locked`), which the zone
    // can no longer see for itself: its lock is hidden from it with the rest
    // of the state. The name comes from the zone and may be a lie — a zone
    // with `systemd --user` has other ways out anyway, which is what the lock
    // of such a zone says of itself (`vpn-zone lock`); a hermetic zone has no
    // way here but the broker, which judges by the kernel.
    let argv: Vec<OsString> = match asked_from {
        Some(origin)
            if argv.first().map(OsString::as_os_str) != Some(origin.as_os_str())
                && !origin.is_empty()
                && !origin.to_string_lossy().contains('/')
                && tools.state.join(&origin).join(NO_ESCAPE).exists() =>
        {
            eprintln!(
                "зона {} заперта: запускаем в ней же",
                origin.to_string_lossy()
            );
            std::iter::once(origin)
                .chain(argv.iter().skip(1).cloned())
                .collect()
        }
        _ => argv.to_vec(),
    };
    let argv = argv.as_slice();

    let selection = match Selection::parse(argv) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    // One launch, one container, whatever words named it.
    let selection = match resolve_selection(tools, selection) {
        Ok(selection) => selection,
        Err(why) => {
            refuse(tools, &why);
            return 1;
        }
    };
    let zone = selection.zone.clone();
    let zone_name = zone.to_string_lossy().into_owned();

    // A zone that was called `unconfined` before the name meant the host's
    // network: a launch "into" it would now leave its VPN behind without a
    // word. Refused until the zone is renamed.
    if zone == UNCONFINED && tools.state.join(UNCONFINED).is_dir() {
        refuse(
            tools,
            &format!(
                "«{UNCONFINED}» теперь значит «без ограничений» (сеть хоста, без VPN и изоляции зоны), \
                 а у тебя есть зона с таким именем — запуск остановлен, чтобы не уйти мимо её VPN. \
                 Переименуй зону: cellward down {UNCONFINED}, переименуй каталог \
                 {} и снова cellward up",
                tools.state.join(UNCONFINED).display()
            ),
        );
        return 1;
    }

    // The zone with no network is created on demand, here as in the picker:
    // `vpn-zone run offline -- …` by hand used to find no zone at all when the
    // picker had never made one.
    if zone == OFFLINE {
        ensure_offline_zone(&tools.state);
    }

    // --- 1a. ONE IDENTITY, ONE NETWORK ---
    // Before anything is created: a container bound to a network runs in that
    // network only, and a container never runs in two networks at once
    // (`docs/CONTAINERS.md` I1, I2). The picker does not offer anything else;
    // this is where a command line, a stale shortcut or a script is stopped.
    if let Some(why) = identity_refusal(tools, &selection, &zone_name) {
        refuse(tools, &why);
        return 1;
    }
    // Only now anything is made or moved for it — never for a launch that is
    // refused, never in a dry run.
    if env_nonempty(ENV_DRYRUN).is_none() {
        if let Err(why) = prepare_selection(tools, &selection) {
            refuse(tools, &why);
            return 1;
        }
    }

    // --- 2. THE CONTAINER ---
    let Some(container) = resolve_container(tools, &selection) else {
        return 1;
    };

    // --- 3. THE WRAPPERS ---
    // The app-id is worked out BEFORE anything is prepended to the command:
    // afterwards the first word is `vpn-zone-core`, and taking the name from
    // there made the conflict warning name the wrapper, gave every sandboxed
    // program one shared "do not ask again" key, and merged them all into a
    // single registry entry. (`docs/GOTCHAS.md` §5, §6)
    let appid_env = env_nonempty(ENV_APPID);
    let appbin = sanitize_app_id(
        appid_env
            .as_deref()
            .or_else(|| app_word(&selection.cmd))
            .unwrap_or(OsStr::new("")),
    );
    // The human-readable name for every dialog below: the label the picker
    // remembered for this key, when there is one. Two programs starting at
    // once each ask their own questions, and a dialog that names its program
    // with a raw id (or not at all) is how the answers get swapped.
    // A file name, whoever set the variable (`registry_key`).
    let label = pretty_label(
        &tools.state,
        &registry_key(appid_env.as_deref().unwrap_or(appbin.as_os_str())),
    );
    let mut cmd = selection.cmd.clone();

    // --- THE CAMERAS ---
    // The host's cameras for this launch (`docs/PERMISSIONS.md` §11.10): the
    // zone's `/dev` has none, and a launch they are let gets them bound in,
    // in its own mount namespace (`profile::give_capture`)
    // — by its container's setting, the zone's for a launch with none.
    let camera = zone != UNCONFINED && {
        let zone_dir = tools.state.join(&zone_name);
        match container_name(&selection) {
            Some(name) => crate::container::camera_for(&zone_dir, &tools.config, &zone_name, &name),
            None => crate::hermetic::camera(&zone_dir, &tools.config, &zone_name).0,
        }
    };

    // --- THE DEVICES ---
    // The devices given to its container (`docs/PERMISSIONS.md` §11.12): the
    // zone's `/dev` has none, and this launch gets the given ones bound in,
    // in its own mount namespace (`profile-run --device`), checking each
    // once more there. None for a launch with no container.
    let devices: Vec<crate::devices::Pass> = match container_name(&selection) {
        Some(name) if zone != UNCONFINED => {
            let grants: Vec<crate::devices::Grant> = crate::container::load(tools, &name)
                .map(|c| {
                    c.devices
                        .iter()
                        .filter_map(|d| crate::devices::Grant::parse(&d.value))
                        .collect()
                })
                .unwrap_or_default();
            if grants.is_empty() {
                Vec::new()
            } else {
                let nodes = crate::devices::host_nodes();
                crate::devices::granted(&nodes, &grants)
                    .into_iter()
                    .map(crate::devices::Node::pass)
                    .collect()
            }
        }
        _ => Vec::new(),
    };
    let device_args: Vec<String> = devices.iter().map(crate::devices::Pass::arg).collect();

    // --- X11 (docs/HERMETICITY.md §7, A) ---
    // The host's X server is out of reach in a zone. A container with the x11
    // permission gets a satellite of its own, started INSIDE wl-sandbox (the
    // wrapping below goes around this one), so it speaks to the compositor
    // through the restricted socket like the program does. A sandbox starts
    // its own satellite and is told about the permission instead.
    // Or the zone itself has x11: for someone who runs zones without
    // containers, Steam in a zone must open all the same.
    let container_x11 = container_name(&selection)
        .and_then(|name| crate::container::load(tools, &name))
        .is_some_and(|c| c.x11.value)
        || (zone != UNCONFINED
            && crate::x11::zone_setting(&tools.state, &tools.config, &zone_name).0);
    if container_x11 && zone != UNCONFINED && selection.sandbox == Sandbox::None && !cmd.is_empty()
    {
        let mut wrapped: Vec<OsString> = vec![
            tools.core.clone().into(),
            "x11-run".into(),
            "--xwayland".into(),
            tools.xwayland.clone().into(),
            "--".into(),
        ];
        wrapped.extend(cmd);
        cmd = wrapped;
    }

    // --- THE COMPOSITOR (docs/LEAK-MODEL.md §13) ---
    // Around everything, on the host: a zone has no compositor socket of its
    // own to make the restricted one from, and a sandbox would otherwise be
    // handed the unrestricted one. Into a zone always — the allowlist and
    // `wayland-sandbox off` are for unconfined launches only, where the
    // compositor's own socket is there anyway.
    let compositor_wrap: Option<Vec<OsString>> =
        (zone != UNCONFINED || wayland_sandbox_wanted(tools, &appbin, unasked)).then(|| {
            let app = if appbin.is_empty() {
                OsString::from("shell")
            } else {
                appbin.clone()
            };
            let dir = if zone == UNCONFINED {
                crate::wl_sandbox::NO_ZONE.to_owned()
            } else {
                zone_name.clone()
            };
            let mut wrap: Vec<OsString> = vec![
                tools.core.clone().into(),
                "wl-sandbox".into(),
                app,
                "--zone".into(),
                dir.into(),
            ];
            if !wayland_proxy_wanted(tools, &appbin, unasked) {
                wrap.push("--no-proxy".into());
            } else if zone != UNCONFINED {
                // The zone's frame around its windows (docs/WINDOW-FRAME.md
                // §0а): the colour, width and title mode as they are now, and
                // the title's text — the zone and the container as this
                // launch knows them; the switch that hides it is read by the
                // supervisor for each connection.
                // The container's colour, the zone's when it has none.
                let color = container_name(&selection)
                    .and_then(|name| crate::container::load(tools, &name))
                    .and_then(|c| c.frame_color.map(|c| c.value));
                let frame = crate::frame::Frame::of_launch(
                    &tools.state,
                    &tools.config,
                    &zone_name,
                    color.as_deref(),
                );
                wrap.push("--frame".into());
                wrap.push(frame.to_arg().into());
                let selector = selector_of(&selection, &container.profile);
                let shown = if container.ephemeral && selection.sandbox == Sandbox::None {
                    // Its name is a random directory's: what it IS is what
                    // the owner needs to read.
                    "временный".to_owned()
                } else {
                    crate::picker::container_label_in(tools, &selector.to_string_lossy())
                };
                wrap.push("--frame-title".into());
                wrap.push(crate::frame::title_text(&zone_name, &shown).into());
                wrap.push("--frame-switch".into());
                wrap.push(tools.config.clone().into());
            }
            wrap.push("--".into());
            wrap
        });

    if selection.sandbox != Sandbox::None {
        // The permissions belong to the launcher's id when there is one: the
        // shortcut says "discord" while the binary is called "Discord", and two
        // independent permission sets for one program is what taking the binary
        // name gave us. (`docs/GOTCHAS.md` §6)
        // Cleaned (`appbin` is the variable's value, sanitized): it becomes a
        // directory of the sandbox's permissions and the portals' app id.
        let fsid = appbin.clone();
        // Asked here, on the host: in the zone the answers are read-only.
        if env_nonempty(ENV_DRYRUN).is_none() {
            let named = match &selection.sandbox {
                Sandbox::Named(name) => Some(name.to_string_lossy().into_owned()),
                _ => None,
            };
            crate::fs_sandbox::settle_permissions(
                &tools.home,
                &fsid.to_string_lossy(),
                named.as_deref(),
                label.as_deref(),
                &tools.kdialog,
            );
        }
        let mut wrapped: Vec<OsString> = vec![
            tools.core.clone().into(),
            "fs-sandbox".into(),
            "--bwrap".into(),
            tools.bwrap.clone().into(),
            "--dbus-proxy".into(),
            tools.dbus_proxy.clone().into(),
            "--kdialog".into(),
            tools.kdialog.clone().into(),
            "--xwayland".into(),
            tools.xwayland.clone().into(),
            "--opener".into(),
            tools.opener.clone().into(),
            fsid,
        ];
        if let Sandbox::Named(name) = &selection.sandbox {
            wrapped.push("--name".into());
            wrapped.push(name.clone());
            // Directories of the real home granted to this sandbox
            // (`docs/CONTAINERS.md` §3.5); fs-sandbox checks them once more.
            if let Some(container) = crate::container::load(tools, &name.to_string_lossy()) {
                for path in container.paths {
                    wrapped.push("--bind-path".into());
                    wrapped.push(path.value.into());
                }
            }
        }
        if let Some(label) = &label {
            wrapped.push("--label".into());
            wrapped.push(label.clone().into());
        }
        if container_x11 {
            wrapped.push("--x11".into());
            wrapped.push("on".into());
        }
        // The cameras into its own /dev, where they are let.
        if camera {
            wrapped.push("--camera".into());
            wrapped.push("on".into());
        }
        // And the devices its container is given.
        for pass in &devices {
            wrapped.push("--device".into());
            wrapped.push(pass.path.clone().into());
        }
        // The network it runs in: to the portal its programs are the zone
        // (LEAK-MODEL §23). None for an unconfined launch — the host's own.
        if zone != UNCONFINED {
            wrapped.push("--zone".into());
            wrapped.push(zone.clone());
        }
        wrapped.push("--".into());
        wrapped.extend(cmd);
        cmd = wrapped;
    }

    // --- 4. IS IT ALREADY RUNNING SOMEWHERE ELSE? ---
    // A file name in the registry, whoever set the variable: the broker
    // passes on what a zone asked for, and `/run/user/…` or `../..` would have
    // been a path to rewrite on the host.
    let appname = registry_key(appid_env.as_deref().unwrap_or(&appbin));
    let running = tools.state.join(".running");
    let regdir = running.join(container.key.as_os_str());
    let reg = regdir.join(&appname);
    // The same program under its BINARY name as well. The key above is the
    // launcher's id when there is one, and two ids for one single-instance
    // binary did not see each other: a Steam game's shortcut and Steam itself,
    // firefox and a firefox private-window entry, two Telegram variants. The
    // second launch handed its work to the process already up — in ITS network
    // — and the warning stayed silent. The binary index answers only "is it
    // running elsewhere"; which network a click on a running program goes to is
    // still decided by the id, because a multi-window program (a terminal) must
    // not be dragged into another's network by name. (`docs/GOTCHAS.md` §5)
    let binary = sanitize_app_id(app_word(&selection.cmd).unwrap_or(OsStr::new("")));
    let binreg = (!binary.is_empty() && binary != appname)
        .then(|| regdir.join(registry::BY_BINARY).join(&binary));
    let dryrun = env_nonempty(ENV_DRYRUN).is_some();

    let busy = match registry::lock(&regdir) {
        Ok(_guard) => {
            let live = |file: &Path| {
                registry::rewrite_live(file, &zone_name, |pid| registry::alive(&running, pid))
                    .unwrap_or_else(|e| {
                        eprintln!("реестр запусков {}: {e}", file.display());
                        None
                    })
            };
            let by_id = live(reg.as_path());
            let by_binary = binreg.as_deref().and_then(live);
            by_id.or(by_binary)
        }
        Err(e) => {
            eprintln!("реестр запусков {}: {e}", regdir.display());
            None
        }
    };

    if let Some(busy) = busy.filter(|_| !dryrun) {
        // Both `{busy}` and both `{zone}` get the same value, so a plain
        // replace does what the shell's five `%s` did.
        // The pretty label again: the warning is about a PROGRAM, and with two
        // of them launching the raw key does not say which one.
        let shown = label
            .clone()
            .unwrap_or_else(|| appname.to_string_lossy().into_owned());
        let template = if hands_over_a_link(&selection.cmd) {
            CONFLICT_URL_MESSAGE
        } else {
            CONFLICT_MESSAGE
        };
        let message = template
            .replace("{app}", &shown)
            .replace("{busy}", &busy)
            .replace("{zone}", &zone_name);
        if has_display() {
            let ok = Command::new(&tools.kdialog)
                .arg("--title")
                .arg("Программа уже запущена в другой сети")
                .arg("--dontagain")
                .arg(format!(
                    "vpn-zonesrc:conflict-{}",
                    appname.to_string_lossy()
                ))
                .arg("--warningcontinuecancel")
                .arg(&message)
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                // Cancelled — or kdialog is not there at all. Either way this
                // launch is over, and quietly: the user just said no.
                return 0;
            }
        } else {
            // No dialog to show from a terminal: warn and go on. Cancelling the
            // launch silently would be worse than warning about it.
            eprintln!("{message}");
        }
    }

    // --- 5. THE ZONE ITSELF ---
    let network = if zone == UNCONFINED {
        // Nothing to start and nothing to enter: the host's own network.
        Network::Unconfined
    } else {
        // Up and READY, not just up: a zone still being set up is not entered
        // (`cli::zone_up`).
        let mut pid = cli::zone_up(&tools.state, &zone);
        if pid.is_none() {
            // The shortcut may well have been clicked while the zone was down —
            // or while it was still coming up. Starting it is the expected
            // behaviour, not an error (a zone that is starting is left to it),
            // and a failure here is deliberately ignored, because the check
            // below says the same thing in words a user can act on.
            // Returns once the zone is ready or failed (`Type=notify`,
            // `cli::started_up`): no clock of ours — and says so while it
            // waits (`cli::start_zone`).
            let _ = cli::start_zone(tools, &zone, true);
            pid = cli::zone_up(&tools.state, &zone);
        }
        let Some(pid) = pid else {
            eprintln!("зона {zone_name} не поднимается");
            return 1;
        };
        Network::Zone(pid)
    };

    if dryrun {
        let shown: Vec<String> = compositor_wrap
            .iter()
            .flatten()
            .chain(cmd.iter())
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let profile = if container.profile.is_empty() {
            "основной".to_owned()
        } else {
            container.profile.to_string_lossy().into_owned()
        };
        println!("зона {zone_name}, профиль {profile}: {}", shown.join(" "));
        return 0;
    }

    // --- 6. INTO THE REGISTRY AND INTO THE ZONE ---
    let selector = selector_of(&selection, &container.profile);
    match registry::lock(&regdir) {
        Ok(_guard) => {
            for file in std::iter::once(&reg).chain(binreg.as_ref()) {
                if let Err(e) = registry::append(
                    file,
                    std::process::id() as i32,
                    &zone_name,
                    &selector.to_string_lossy(),
                ) {
                    eprintln!("реестр запусков {}: {e}", file.display());
                }
            }
            if let Err(e) = registry::note_start(&running, std::process::id() as i32, from_zone) {
                eprintln!("реестр запусков {}: {e}", running.display());
            }
        }
        Err(e) => eprintln!("реестр запусков {}: {e}", regdir.display()),
    }
    // The containers launched into a zone since it came up: what decides for
    // all its programs at once counts theirs after the launch is over — a
    // daemon outlives it (`origin::LAUNCHED`).
    if let (Network::Zone(_), Some(name)) = (network, container_name(&selection)) {
        if let Err(e) = crate::origin::note_launched(&tools.state, &zone_name, &name) {
            eprintln!("учёт контейнеров зоны {zone_name}: {e}");
        }
    }
    // Nothing of a zone around this one: on the record, with who and what.
    if network == Network::Unconfined {
        let program = selection
            .cmd
            .first()
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Err(e) = crate::journal::append(
            &tools.state,
            "launch-unconfined",
            &[
                ("app", &*appname.to_string_lossy()),
                ("container", &*selector.to_string_lossy()),
                ("program", program.as_str()),
                ("pid", std::process::id().to_string().as_str()),
            ],
        ) {
            eprintln!(
                "журнал {}: {e}",
                tools.state.join(crate::journal::FILE).display()
            );
        }
    }

    // The mark descendants are recognised by: a program started in a zone that
    // tries to open something else has that launch delegated outwards (step 1).
    //
    // An unconfined launch is marked only when it ends up in a namespace of its
    // own — a container's user namespace or a sandbox. From there `nsenter`
    // into a zone fails exactly as it does from inside a zone, so the
    // descendants have to delegate too. A plain unconfined launch is an ordinary
    // host process and must stay unmarked, or everything it starts would take
    // a detour through systemd for nothing.
    let namespaced = !container.dir.as_os_str().is_empty() || selection.sandbox != Sandbox::None;
    if network != Network::Unconfined || namespaced {
        std::env::set_var(ENV_CURRENT, &zone);
    }
    // No host X server in a zone, and no name of one either: toolkits that see
    // DISPLAY try X first and fail instead of using Wayland. A container with
    // the permission gets its own display from x11-run.
    if network != Network::Unconfined {
        std::env::remove_var("DISPLAY");
        std::env::remove_var("XAUTHORITY");
        // The compositors' IPC is not in a zone (LEAK-MODEL §13); its names
        // are not either.
        for var in COMPOSITOR_IPC_VARS {
            std::env::remove_var(var);
        }
        // Input methods through their portals only (review 2026-09-25): the
        // daemons' own interfaces run and fetch things on the host, and the
        // zone's bus and mount namespace keep them out
        // (`zone::SESSION_BUS_RULES`, `zone::hide_input_methods`). libibus
        // takes its portal only in Flatpak or when told so; fcitx5's clients
        // fall back to theirs by themselves.
        std::env::set_var("IBUS_USE_PORTAL", "1");
    }

    // The caller's working directory, which `nsenter` would otherwise lose. A
    // directory that has been removed under us is no reason not to start:
    // `profile-run` falls back to `$HOME` anyway.
    let cwd = std::env::current_dir().unwrap_or_else(|_| tools.home.clone());
    // No command at all is a shell inside the zone — what `nsenter` used to
    // start by itself, before `profile-run` stood between it and the program.
    let cmd = if cmd.is_empty() && network != Network::Unconfined {
        vec![std::env::var_os("SHELL")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| OsString::from("/bin/sh"))]
    } else {
        cmd
    };
    let (trust, nss_home, trust_extra) = trust_of(tools, &selection);
    // A layer container's grants: the paths it writes into the real home.
    let shares: Vec<PathBuf> = match (&selection.sandbox, &selection.container) {
        (Sandbox::None, Container::Named(name)) => {
            crate::container::load(tools, &name.to_string_lossy())
                .map(|c| c.paths.into_iter().map(|p| p.value).collect())
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };
    // Into a zone, the container's storage: the zone covers it, and
    // `profile-run` gives this one directory back in the launch's own mount
    // namespace. Made here first, on the host: a sandbox's before its first
    // launch, which the zone could not make.
    let storage_dir: Option<PathBuf> = match (&network, &selection.sandbox, &selection.container) {
        (Network::Zone(_), Sandbox::Named(name), _) => {
            Some(crate::container::data_dir(tools, &name.to_string_lossy()))
        }
        (Network::Zone(_), Sandbox::None, Container::Named(_)) if !container.ephemeral => {
            Some(container.dir.clone())
        }
        _ => None,
    };
    if let Some(dir) = &storage_dir {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("не создать хранилище контейнера {}: {e}", dir.display());
            return EXIT_NOT_STARTED;
        }
    }
    let exec = entry_argv(
        &Entry {
            nsenter: &tools.nsenter,
            unshare: &tools.unshare,
            core: &tools.core,
            zone: &zone,
            network,
            dir: &container.dir,
            ephemeral: container.ephemeral,
            regdir: &regdir,
            cwd: &cwd,
            trust: trust.as_deref(),
            nss_home: nss_home.as_deref(),
            trust_extra: &trust_extra,
            certutil: &tools.certutil,
            shares: &shares,
            own_mounts: matches!(
                (&selection.sandbox, &selection.container),
                (Sandbox::None, Container::MainNamed(_))
            ),
            camera,
            devices: &device_args,
            storage: storage_dir.as_deref(),
        },
        cmd,
    );
    // Only `direct` with no container can get here with nothing at all: into a
    // zone an empty command is `nsenter`'s own shell, which is a perfectly good
    // thing to want, but the host has no such fallback.
    if exec.is_empty() {
        eprintln!("нечего запускать");
        return 1;
    }
    let through_wl_sandbox = compositor_wrap.is_some();
    let exec = match compositor_wrap {
        Some(mut wrapped) => {
            wrapped.extend(exec);
            wrapped
        }
        None => {
            // No `wl-sandbox` on the way to say the program opened a window:
            // told that no word will come — the picker learns nothing.
            crate::wl_sandbox::no_word();
            exec
        }
    };

    // A zone is a network namespace of its own, and ours is the host's here: a
    // launch from inside a zone was handed outwards in step 1. A zone process
    // in OUR namespace is not the zone — `zone.pid` naming some other process
    // —, and entering it would start the program in the host's network under
    // the zone's name. Checked last, as close to the `exec` as it gets.
    if let Network::Zone(pid) = network {
        // What profile-run will check from inside: the zone's network as it is
        // now, not as a number will say later.
        match fs::read_link(format!("/proc/{pid}/ns/net")) {
            Ok(ns) => std::env::set_var(crate::profile::ENV_EXPECT_NETNS, ns),
            Err(e) => {
                eprintln!("зона {zone_name}: её процесс не прочитать ({e}) — запуск остановлен");
                return 1;
            }
        }
        if in_our_network(pid) {
            refuse(
                tools,
                &format!(
                    "Зона {zone_name} указывает на процесс в сети хоста — запуск остановлен. \
                     Перезапусти зону: cellward down {zone_name}, затем cellward up {zone_name}"
                ),
            );
            return 1;
        }
    }

    // The picker's pipe, given on to `wl-sandbox` alone, as the very last
    // thing before its exec (`wl_sandbox::pass_opened_on`): nothing this
    // process starts on the way has it.
    if through_wl_sandbox {
        crate::wl_sandbox::pass_opened_on();
    }
    let e = exec_command(&exec);
    eprintln!("не удалось запустить {}: {e}", exec[0].to_string_lossy());
    EXIT_NOT_STARTED
}

/// Where a launch runs, as far as its command line is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// A zone that is up; the pid of its APP namespace, the one `nsenter`
    /// targets.
    Zone(i32),
    /// The host's own network: there is no namespace to enter.
    Unconfined,
}

/// Everything the last command line of a launch depends on.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    pub nsenter: &'a Path,
    pub unshare: &'a Path,
    pub core: &'a Path,
    pub zone: &'a OsStr,
    pub network: Network,
    /// The container's layer directory; empty for the main profile.
    pub dir: &'a Path,
    pub ephemeral: bool,
    pub regdir: &'a Path,
    /// The directory the program is to start in: the caller's.
    pub cwd: &'a Path,
    /// The container's directory of trusted certificates, when it has one
    /// (`docs/CERTIFICATES.md`). Like a layer, it needs a mount namespace.
    pub trust: Option<&'a Path>,
    /// The home the program will see when that is not `$HOME`: a named
    /// sandbox's, on disk. Only meaningful together with `trust`.
    pub nss_home: Option<&'a Path>,
    /// Directories of certificates declared in Nix, besides `trust`.
    pub trust_extra: &'a [PathBuf],
    pub certutil: &'a Path,
    /// Paths of the real home granted to a layer container
    /// (`container grant`): written through its layer (`--share`).
    pub shares: &'a [PathBuf],
    /// The container's storage directory, for a launch into a zone: the zone
    /// covers container storage, and `profile-run --storage` gives this one
    /// directory back in the launch's own mount namespace, from the zone's
    /// keep (`home_layer::KEPT_STORAGE`).
    pub storage: Option<&'a Path>,
    /// A mount namespace of its own in a zone even with nothing to mount: a
    /// container of the main home. Its programs are told from the zone's own
    /// by it — one that leaves its launch (a daemon that forked twice) is
    /// then not taken for a program of the zone with no container, whose
    /// settings are not its container's (`crate::origin`).
    pub own_mounts: bool,
    /// The host's cameras let this launch in a zone: bound into its own
    /// mount namespace (`profile-run --camera`).
    pub camera: bool,
    /// The devices its container is given, as `profile-run --device` takes
    /// them (`devices::Pass::arg`): bound into its own mount namespace.
    pub devices: &'a [String],
}

/// The command line `run` finally `exec`s: the namespaces, the container, then
/// the (already wrapped) command.
///
/// A pure function, because every word of it was paid for:
///
/// * **into a zone**: `nsenter --preserve-credentials --keep-caps -U -n -m -t
///   <pid>` — without `--keep-caps` CapEff is zeroed on entering the zone's
///   user namespace, and there is nothing left to mount a layer with
///   (`docs/GOTCHAS.md` §1) nor to shed the session's groups with
///   (`profile::run`). A container then gets a mount namespace of its own
///   (`unshare --mount`), so its layers are seen by this launch only and not
///   by the whole zone — a slave of the zone's, which gets what the zone
///   binds into its runtime directory later; a container of the main home
///   too, with nothing mounted (`Entry::own_mounts`);
/// * **`direct` with a container**: there is no zone to borrow a user namespace
///   from, so `unshare` makes one — `--map-current-user` maps the user onto
///   itself (the program keeps its uid and sees `$HOME` as usual) and
///   `--keep-caps` carries the capabilities of that namespace across the exec,
///   for the same reason as above: `profile-run` needs CAP_SYS_ADMIN over the
///   new mount namespace to stack the layers, and drops it before the program
///   starts. No network namespace is created: `direct` IS the host's network;
/// * **`direct` without a container**: nothing at all. The program is a host
///   process like any other, and the command is exec'd as it is (still wrapped
///   in `wl-sandbox`/`fs-sandbox`, which are part of `cmd`).
///
/// **Everything that enters a namespace ends in `profile-run --cwd`**, the
/// main profile included (with an empty layer directory, which stacks
/// nothing). `nsenter` does `chdir("/")` when it joins a mount namespace — a
/// terminal started into a zone opened in `/` — and `--wd` is no cure: with a
/// container the overlay is mounted over `$HOME` after `nsenter`, so the chdir
/// has to come after the mounts, and even without one a directory that does
/// not exist in the zone's mount tree would make `nsenter` refuse to start the
/// program at all. `profile-run` makes the chdir after mounting and falls back
/// to `$HOME` and `/`. (`docs/GOTCHAS.md` §1)
pub fn entry_argv(entry: &Entry<'_>, cmd: Vec<OsString>) -> Vec<OsString> {
    // Something has to be mounted for this launch: a container's layer, or
    // the trust layer's bundle.
    let container =
        !entry.dir.as_os_str().is_empty() || entry.trust.is_some() || entry.storage.is_some();
    let mut exec: Vec<OsString> = Vec::new();
    // Does the program end up in a mount namespace other than ours?
    let entered = container || matches!(entry.network, Network::Zone(_));
    match entry.network {
        Network::Zone(pid) => {
            exec.push(entry.nsenter.into());
            exec.push("--preserve-credentials".into());
            // Always, a container or not: `profile-run` sheds the session's
            // groups with them before the program starts (`profile::run`).
            exec.push("--keep-caps".into());
            exec.extend(["-U".into(), "-n".into(), "-m".into(), "-t".into()]);
            exec.push(pid.to_string().into());
            exec.push("--".into());
            if container || entry.own_mounts || entry.camera || !entry.devices.is_empty() {
                // A slave of the zone's: what the zone binds into its
                // runtime directory later reaches this launch too (the one
                // shared mount of the zone, `zone::seal_runtime`), and
                // nothing this launch mounts goes back.
                exec.push(entry.unshare.into());
                exec.extend([
                    "--mount".into(),
                    "--propagation".into(),
                    "slave".into(),
                    "--".into(),
                ]);
            }
        }
        Network::Unconfined if container => {
            exec.push(entry.unshare.into());
            exec.extend([
                "--user".into(),
                "--map-current-user".into(),
                "--keep-caps".into(),
                "--mount".into(),
                "--propagation".into(),
                "private".into(),
                "--".into(),
            ]);
        }
        Network::Unconfined => {}
    }
    if entered {
        exec.push(entry.core.into());
        exec.push("profile-run".into());
        exec.push("--cwd".into());
        exec.push(entry.cwd.into());
        if entry.camera && matches!(entry.network, Network::Zone(_)) {
            exec.push("--camera".into());
        }
        if matches!(entry.network, Network::Zone(_)) {
            for device in entry.devices {
                exec.push("--device".into());
                exec.push(device.into());
            }
        }
        if let Some(path) = entry.storage {
            exec.push("--storage".into());
            exec.push(path.into());
        }
        if let Some(trust) = entry.trust {
            exec.push("--trust".into());
            exec.push(trust.into());
            exec.push("--certutil".into());
            exec.push(entry.certutil.into());
            if let Some(home) = entry.nss_home {
                exec.push("--nss-home".into());
                exec.push(home.into());
            }
            for extra in entry.trust_extra {
                exec.push("--trust-extra".into());
                exec.push(extra.into());
            }
        }
        // Only with a layer: the main profile has the real home anyway.
        if !entry.dir.as_os_str().is_empty() {
            for share in entry.shares {
                exec.push("--share".into());
                exec.push(share.into());
            }
        }
        exec.push(entry.dir.into());
        exec.push(entry.zone.into());
        exec.push(if entry.ephemeral { "1" } else { "0" }.into());
        exec.push(entry.regdir.into());
        exec.push("--".into());
    }
    exec.extend(cmd);
    exec
}

/// Why this launch may not use its container in `zone`, if it may not.
fn identity_refusal(tools: &Tools, selection: &Selection, zone: &str) -> Option<String> {
    let container = crate::container::load(tools, &container_name(selection)?)?;
    let running = crate::container::running_network(tools, &container);
    crate::container::refusal(&container, zone, running.as_deref())
}

/// The name of the container a resolved launch runs in, whatever its home;
/// `None` for the main profile, a throwaway one and a temporary one.
pub fn container_name(selection: &Selection) -> Option<String> {
    match (&selection.sandbox, &selection.container) {
        (Sandbox::Named(name), _)
        | (Sandbox::None, Container::Named(name) | Container::MainNamed(name)) => {
            Some(name.to_string_lossy().into_owned())
        }
        _ => None,
    }
}

/// One launch, one container (`docs/PERMISSIONS.md` §11.7): the name —
/// `--container`, and the words from before, `--profile` and `--sandbox` —
/// read as the container it is now, its kind of home deciding how it is
/// mounted. Nothing is made or moved here: that is [`prepare_selection`],
/// after the network is checked.
///
/// A layer and a home of its own together, or a named container with a
/// throwaway one, are two containers: refused. `--sandbox` (and `sb:`) asks
/// for a home of its own and gets nothing else: a name that is a layer or the
/// main home is refused, not given the real home without a word; a missing
/// one is made at the launch, as a sandbox always was. The others refuse a
/// container that is not there, and one whose move to this layout has not
/// finished (its data are not where the launch would look).
pub fn resolve_selection(tools: &Tools, selection: Selection) -> Result<Selection, String> {
    use crate::container::Home;
    let (asked, sandbox_asked) = match (&selection.container, &selection.sandbox) {
        (Container::Main, Sandbox::None | Sandbox::Throwaway)
        | (Container::TmpNew | Container::TmpJoin(_), Sandbox::None) => return Ok(selection),
        (Container::Named(name) | Container::MainNamed(name), Sandbox::None) => {
            (name.to_string_lossy().into_owned(), false)
        }
        (Container::Main, Sandbox::Named(name)) => {
            // A stale `--sandbox work` is the sandbox that became `work-sb`.
            let name = crate::container::sandbox_name(tools, &name.to_string_lossy())
                .unwrap_or_else(|| name.to_string_lossy().into_owned());
            (name, true)
        }
        _ => {
            return Err(
                "один запуск — один контейнер: слой (--profile, --tmp-profile) и песочница \
                 (--sandbox, --fs-sandbox) вместе больше не собираются"
                    .to_owned(),
            )
        }
    };
    let Some(name) = crate::container::canonical(tools, &asked) else {
        return Err(format!("«{asked}» не может быть именем контейнера"));
    };
    if crate::container::move_pending(tools, &name) {
        return Err(format!(
            "данные контейнера {name} ещё не перенесены в новый каталог (см. сообщение \
             переноса выше) — запуск остановлен, чтобы не открыть его с пустым домом"
        ));
    }
    let home = match crate::container::load(tools, &name) {
        Some(c) if sandbox_asked && c.home != Home::Private => {
            return Err(format!(
                "«{name}» — не песочница, а {}: запуск песочницы в нём остановлен. \
                 Запустить в нём: --container {name}",
                c.home.label()
            ))
        }
        Some(c) => c.home,
        None if sandbox_asked => Home::Private,
        None => {
            return Err(format!(
                "контейнера {name} нет — создай: cellward container create {name}"
            ))
        }
    };
    let name = OsString::from(&name);
    let (container_axis, sandbox) = match home {
        Home::Layer => (Container::Named(name), Sandbox::None),
        Home::Private => (Container::Main, Sandbox::Named(name)),
        Home::Main => (Container::MainNamed(name), Sandbox::None),
    };
    Ok(Selection {
        container: container_axis,
        sandbox,
        ..selection
    })
}

/// Make a resolved launch's container ready, once the launch may go: a home
/// of its own asked for and not there yet is made; the data are made the kind
/// the settings say, the other kind's set aside — never under programs of
/// the container that run, whose home would change under them (a change of
/// kind in Nix does not ask).
pub fn prepare_selection(tools: &Tools, selection: &Selection) -> Result<(), String> {
    let Some(name) = container_name(selection) else {
        return Ok(());
    };
    let container = match crate::container::load(tools, &name) {
        Some(c) => c,
        None => crate::container::create(tools, &name, crate::container::Home::Private)?,
    };
    if !crate::container::data_ready(&container) {
        if let Some(busy) = crate::container::running_network(tools, &container) {
            return Err(format!(
                "у контейнера {name} сменился вид дома, а его программы работают (в сети \
                 {busy}) — закрой их: дом сменится при следующем запуске"
            ));
        }
    }
    crate::container::prepare_data(&container)
}

/// Is the process `pid` in our network namespace?
fn in_our_network(pid: i32) -> bool {
    let ns = |p: &str| fs::read_link(format!("/proc/{p}/ns/net")).ok();
    ns(&pid.to_string()).is_some_and(|theirs| Some(theirs) == ns("self"))
}

/// Say no, where the person can see it: a dialog when there is a graphical
/// session (a launcher entry's stderr is read by nobody), and stderr always.
fn refuse(tools: &Tools, why: &str) {
    eprintln!("{why}");
    if has_display() {
        let _ = Command::new(&tools.kdialog)
            .arg("--title")
            .arg("Запуск остановлен")
            .arg("--sorry")
            .arg(why)
            .stderr(Stdio::null())
            .status();
    }
}

/// The trusted certificates of a launch: the container's own directory, the
/// directories declared in Nix, and the home they belong to.
///
/// They follow the home the program SEES (`docs/CERTIFICATES.md` §3.1): a
/// named sandbox's (its home on disk is where its NSS databases are), otherwise
/// the data container's. A throwaway sandbox has no identity to trust anything
/// with, and the main profile is the host's — neither ever gets a layer. The
/// layer is switched on by the directory existing, even empty: an emptied one
/// still takes stale entries out of the container's NSS databases.
fn trust_of(
    tools: &Tools,
    selection: &Selection,
) -> (Option<PathBuf>, Option<PathBuf>, Vec<PathBuf>) {
    let (selector, nss_home) = match (&selection.sandbox, &selection.container) {
        (Sandbox::Named(name), _) => {
            let name = name.to_string_lossy().into_owned();
            let home = crate::container::data_dir(tools, &name).join("home");
            (name, Some(home))
        }
        (Sandbox::Throwaway, _) => return (None, None, Vec::new()),
        (Sandbox::None, Container::Named(name)) => (name.to_string_lossy().into_owned(), None),
        // The main home's certificates are the host's: none of its own.
        (Sandbox::None, _) => return (None, None, Vec::new()),
    };
    let Some(container) = crate::container::load(tools, &selector) else {
        return (None, None, Vec::new());
    };
    let dir = container.trust_dir();
    if !container.declared_trust.is_empty() {
        // Declared certificates still need the container's own directory: the
        // bundle is written to a tmpfs laid over it.
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("не создать {}: {e}", dir.display());
        }
    }
    let active = dir.is_dir();
    (active.then_some(dir), nss_home, container.declared_trust)
}

/// A locked zone: run the command here, without the network the caller asked
/// for.
fn run_locked(current: &OsStr, argv: &[OsString]) -> u8 {
    let asked = argv
        .first()
        .map(|z| z.to_string_lossy().into_owned())
        .unwrap_or_else(|| "?".to_owned());
    eprintln!(
        "зона {} заперта: запускаем в ней же, а не в «{asked}»",
        current.to_string_lossy()
    );
    let cmd = strip_selection(argv);
    if cmd.is_empty() {
        eprintln!("нечего запускать");
        return 1;
    }
    let e = exec_command(&cmd);
    eprintln!("не удалось запустить {}: {e}", cmd[0].to_string_lossy());
    EXIT_NOT_STARTED
}

/// The zone with no network: a directory with the `offline` marker and nothing
/// else — there is no config to keep, it is an empty namespace
/// (`docs/GOTCHAS.md` §2).
pub fn ensure_offline_zone(state: &Path) {
    let dir = state.join(OFFLINE);
    if !dir.is_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join(OFFLINE), b"");
    }
}

/// Hand the launch to `systemd --user`, which lives outside every zone.
fn delegate(tools: &Tools, argv: &[OsString]) -> u8 {
    // The app-id is passed explicitly: systemd-run starts the unit with the
    // MANAGER's environment, not ours, and VPN_ZONE_APPID never reached it — so
    // a link opened from a messenger inside a zone built a separate set of file
    // permissions and a separate registry entry, and the same program stopped
    // being recognised as itself.
    let appid = env_nonempty(ENV_APPID).unwrap_or_default();

    // A hermetic zone has no systemd --user to reach, and the broker instead:
    // the door with a guard (`crate::broker`). Checked by the manager's socket
    // being gone rather than by a variable a program could set.
    let runtime = crate::broker::runtime_dir();
    if !runtime.join("systemd/private").exists() {
        if let Some(code) = crate::broker::request(appid.as_bytes(), argv) {
            return code;
        }
    }
    let mut setenv = OsString::from("--setenv=VPN_ZONE_APPID=");
    setenv.push(&appid);

    let mut exec: Vec<OsString> = vec![tools.systemd_run.clone().into()];
    exec.extend([
        "--user".into(),
        "--quiet".into(),
        "--collect".into(),
        "--setenv=VPN_ZONE_DELEGATED=1".into(),
    ]);
    exec.push(setenv);
    if let Some(current) = env_nonempty(ENV_CURRENT) {
        let mut from = OsString::from(format!("--setenv={ENV_FROM}="));
        from.push(&current);
        exec.push(from);
    }
    exec.push("--".into());
    exec.push(tools.runner.clone().into());
    exec.push("run".into());
    exec.extend(argv.iter().cloned());

    let e = exec_command(&exec);
    eprintln!("не удалось запустить {}: {e}", tools.systemd_run.display());
    EXIT_NOT_STARTED
}

/// What was chosen for the container, as the registry records it (the third
/// field): the container's name, `__fs__` for a throwaway sandbox, the
/// temporary container's directory name, empty for the main profile.
fn selector_of(selection: &Selection, profile: &OsStr) -> OsString {
    match (&selection.sandbox, &selection.container) {
        (Sandbox::Named(name), _) | (Sandbox::None, Container::MainNamed(name)) => name.clone(),
        (Sandbox::Throwaway, _) => OsString::from("__fs__"),
        (Sandbox::None, _) => profile.to_owned(),
    }
}

/// A container as the rest of `run` needs it.
struct ResolvedContainer {
    /// Name of the container, empty for the main profile. Also the third field
    /// of the registry record.
    profile: OsString,
    /// Where the layers live, empty for the main profile.
    dir: PathBuf,
    ephemeral: bool,
    /// Registry directory key: the container name, or `__main__`.
    key: OsString,
}

/// Where throwaway containers live, below the state directory.
pub const THROWAWAY_DIR: &str = ".throwaway";

/// Where a throwaway container named `name` is, if it still exists: below the
/// state directory, or in `/tmp`, where a launch from before the move put it.
pub fn throwaway_path(state: &Path, name: &OsStr) -> Option<PathBuf> {
    throwaway_bases(state)
        .into_iter()
        .map(|base| base.join(name))
        .find(|dir| dir.is_dir())
}

/// The directories throwaway containers are looked for in, the current one
/// first.
pub fn throwaway_bases(state: &Path) -> [PathBuf; 2] {
    [state.join(THROWAWAY_DIR), PathBuf::from("/tmp")]
}

/// Turn the parsed container into directories, creating a throwaway one.
///
/// `None` means the message has been printed and the launch is over.
fn resolve_container(tools: &Tools, selection: &Selection) -> Option<ResolvedContainer> {
    let (profile, dir, ephemeral) = match &selection.container {
        Container::Main | Container::MainNamed(_) => (OsString::new(), PathBuf::new(), false),
        Container::Named(name) => {
            let dir = crate::container::data_dir(tools, &name.to_string_lossy());
            if !dir.is_dir() {
                let name = name.to_string_lossy();
                eprintln!("контейнера {name} нет — создай: cellward container create {name}");
                return None;
            }
            (name.clone(), dir, false)
        }
        Container::TmpNew => {
            // On a disk rather than a tmpfs, so a browser cache does not eat the
            // RAM (`docs/GOTCHAS.md` §5) — and no longer in /tmp: a hermetic
            // zone has a /tmp of its own, where a layer made on the host would
            // not be (`docs/LEAK-MODEL.md` §15).
            let base = tools.state.join(THROWAWAY_DIR);
            let made = fs::create_dir_all(&base)
                .and_then(|()| fs::set_permissions(&base, fs::Permissions::from_mode(0o700)))
                .and_then(|()| mkdtemp(&format!("{}/vpn-profile-XXXXXXXX", base.display())));
            let dir = match made {
                Ok(dir) => dir,
                Err(e) => {
                    eprintln!("не создать временный контейнер в {}: {e}", base.display());
                    return None;
                }
            };
            (basename(dir.as_os_str()).to_owned(), dir, true)
        }
        Container::TmpJoin(dir) => {
            if !dir.is_dir() {
                eprintln!("временного контейнера {} уже нет", dir.display());
                return None;
            }
            // Only a throwaway container of ours: its layer is ERASED behind the
            // last tenant, and a directory named here — by a request that came
            // through the broker, or by a slip of the hand — would go with it.
            let real = fs::canonicalize(dir).ok()?;
            let ours = real
                .file_name()
                .is_some_and(|n| n.as_bytes().starts_with(b"vpn-profile-"))
                && throwaway_bases(&tools.state).iter().any(|base| {
                    fs::canonicalize(base).is_ok_and(|b| real.parent() == Some(b.as_path()))
                });
            if !ours {
                eprintln!(
                    "{} — не временный контейнер cellward: присоединиться нельзя",
                    dir.display()
                );
                return None;
            }
            (basename(real.as_os_str()).to_owned(), real, true)
        }
    };
    // Every named container has a registry directory of its own, whatever
    // its home: what runs in it is found there (`docs/PERMISSIONS.md` §11.8).
    let key = match container_name(selection) {
        Some(name) => OsString::from(name),
        None if profile.is_empty() => OsString::from(registry::MAIN),
        None => profile.clone(),
    };
    Some(ResolvedContainer {
        profile,
        dir,
        ephemeral,
        key,
    })
}

/// `mktemp -d <template>`.
fn mkdtemp(template: &str) -> std::io::Result<PathBuf> {
    let mut buf = template.as_bytes().to_vec();
    buf.push(0);
    // SAFETY: a NUL-terminated, writable buffer that outlives the call; mkdtemp
    // edits the six trailing X's in place.
    let ptr = unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) };
    if ptr.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    buf.pop();
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Should this program be put on a restricted Wayland socket? Reads the two
/// files the answer depends on and asks [`restrict_compositor`].
/// `unasked` ([`ENV_UNASKED`]): the list by program is not read.
fn wayland_sandbox_wanted(tools: &Tools, appbin: &OsStr, unasked: bool) -> bool {
    let mode = cli::setting(tools, "wayland-sandbox").map(|(value, _)| value);
    let allowlist = std::fs::read_to_string(tools.config.join("wayland-allow"))
        .ok()
        .filter(|_| !unasked);
    restrict_compositor(mode.as_deref(), appbin, allowlist.as_deref())
}

/// Whether the Wayland proxy stands between this program and the compositor
/// (`crate::wl_proxy`): on unless switched off — for all programs
/// (`vpn-zone wayland-proxy off`, `programs.cellward.waylandProxy.enable`)
/// or for this one (`~/.config/vpn-zones/wayland-no-proxy`, one program per
/// line, and its declared twin). Off, the compositor listens on the zone's
/// path itself, as before there was a proxy: still the restricted socket.
/// `unasked` ([`ENV_UNASKED`]): the lists by program are not read.
fn wayland_proxy_wanted(tools: &Tools, appbin: &OsStr, unasked: bool) -> bool {
    let mode = cli::setting(tools, "wayland-proxy").map(|(value, _)| value);
    let lists = [
        tools.config.join("wayland-no-proxy"),
        tools
            .config
            .join(cli::DECLARED_DIR)
            .join("wayland-no-proxy"),
    ];
    let listed = !unasked
        && appbin.to_str().is_some_and(|name| {
            lists.iter().any(|path| {
                std::fs::read_to_string(path)
                    .is_ok_and(|text| text.lines().map(str::trim).any(|line| line == name))
            })
        });
    proxy_wanted(mode.as_deref(), listed)
}

/// The decision itself: no setting means on, and only `off` switches it off.
pub fn proxy_wanted(mode: Option<&str>, listed: bool) -> bool {
    mode.map(str::trim) != Some("off") && !listed
}

/// The decision itself, without the filesystem.
///
/// **No setting file means ON.** That is the default the project promises, and
/// getting it wrong is invisible: the program starts, everything works, and the
/// screen capture, the background clipboard reads and the input emulation are
/// all quietly back. The shell version said `cat … || echo on` for exactly this
/// reason. (`docs/GOTCHAS.md` §7)
///
/// Two ways out of the restriction: the built-in [`WAYLAND_ALLOWED`] list, and
/// `~/.config/vpn-zones/wayland-allow`, one program per line and matched whole
/// (the shell's `grep -qxF`).
pub fn restrict_compositor(mode: Option<&str>, appbin: &OsStr, allowlist: Option<&str>) -> bool {
    if appbin.is_empty() {
        return false;
    }
    if mode.unwrap_or("on") != "on" {
        return false;
    }
    let Some(name) = appbin.to_str() else {
        // Sanitisation leaves only ASCII, so this cannot happen — and if it ever
        // does, restricting is the safe answer.
        return true;
    };
    if WAYLAND_ALLOWED.contains(&name) {
        return false;
    }
    !allowlist.is_some_and(|text| text.lines().any(|line| line == name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest whose home, state, containers and config are below `base`.
    fn tools_in(base: &Path) -> Tools {
        let entries: std::collections::BTreeMap<String, String> = Tools::keys()
            .iter()
            .map(|k| {
                let dir = match *k {
                    "home" => base.join("home"),
                    "state" => base.join("state"),
                    "profiles" => base.join("profiles"),
                    "sandboxes" => base.join("sandboxes"),
                    "config" => base.join("config"),
                    other => PathBuf::from(format!("/p/{other}")),
                };
                ((*k).to_owned(), dir.to_string_lossy().into_owned())
            })
            .collect();
        Tools::from_entries(Path::new("/m.json"), &entries).unwrap()
    }

    /// One launch, one container (`docs/PERMISSIONS.md` §11.7): the name,
    /// whichever word carries it, is the container, and its home decides how
    /// it is mounted; two containers at once are refused; `--sandbox` makes a
    /// missing one with a home of its own, as it always made a sandbox.
    #[test]
    fn one_launch_is_one_container_by_its_name() {
        use crate::container::{self, Home};
        let base = std::env::temp_dir().join(format!("vz-one-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let tools = tools_in(&base);
        container::create(&tools, "work", Home::Layer).unwrap();
        container::create(&tools, "dev", Home::Private).unwrap();
        container::create(&tools, "files", Home::Main).unwrap();
        let resolve = |line: &[&str]| {
            let argv: Vec<OsString> = line.iter().map(OsString::from).collect();
            resolve_selection(&tools, Selection::parse(&argv).unwrap())
                .map(|s| (s.container, s.sandbox))
        };
        let name = |n: &str| OsString::from(n);

        assert_eq!(
            resolve(&["nl", "--container", "work", "--", "x"]),
            Ok((Container::Named(name("work")), Sandbox::None))
        );
        for flag in ["--container", "--profile"] {
            assert_eq!(
                resolve(&["nl", flag, "dev", "--", "x"]),
                Ok((Container::Main, Sandbox::Named(name("dev")))),
                "{flag}"
            );
        }
        // A sandbox asked for gets a home of its own or nothing: never the
        // real home through a layer or the main home by that name.
        for layer_or_main in ["work", "files"] {
            assert!(resolve(&["nl", "--sandbox", layer_or_main, "--", "x"])
                .unwrap_err()
                .contains("не песочница"));
        }
        assert_eq!(
            resolve(&["nl", "--container", "files", "--", "x"]),
            Ok((Container::MainNamed(name("files")), Sandbox::None))
        );
        // A missing one is made — at the launch, after its network is
        // checked, not while it is resolved.
        let new = Selection::parse(&[
            OsString::from("nl"),
            OsString::from("--sandbox"),
            OsString::from("new"),
            OsString::from("x"),
        ])
        .unwrap();
        let new = resolve_selection(&tools, new).unwrap();
        assert_eq!(
            (&new.container, &new.sandbox),
            (&Container::Main, &Sandbox::Named(name("new")))
        );
        assert!(container::load(&tools, "new").is_none());
        prepare_selection(&tools, &new).unwrap();
        assert_eq!(
            container::load(&tools, "new").map(|c| c.home),
            Some(Home::Private)
        );
        assert!(resolve(&["nl", "--container", "gone", "--", "x"])
            .unwrap_err()
            .contains("нет"));
        assert!(resolve(&["nl", "--container", "main", "--", "x"]).is_err());
        for two in [
            &["nl", "--profile", "work", "--sandbox", "dev", "--", "x"][..],
            &["nl", "--profile", "work", "--fs-sandbox", "--", "x"],
            &["nl", "--tmp-profile", "--fs-sandbox", "--", "x"],
        ] {
            assert!(
                resolve(two).unwrap_err().contains("один контейнер"),
                "{two:?}"
            );
        }
        // A sandbox of that very name is itself; one the move renamed (a
        // layer had the name) is found by its old one.
        container::create(&tools, "a-sb", Home::Private).unwrap();
        container::create(&tools, "a-sb2", Home::Private).unwrap();
        fs::write(base.join("config/containers/.renamed"), "sb:a\ta-sb2\n").unwrap();
        assert_eq!(
            resolve(&["nl", "--sandbox", "a", "--", "x"]),
            Ok((Container::Main, Sandbox::Named(name("a-sb2"))))
        );
        assert_eq!(
            resolve(&["nl", "--sandbox", "a-sb", "--", "x"]),
            Ok((Container::Main, Sandbox::Named(name("a-sb"))))
        );
        container::create(&tools, "a", Home::Private).unwrap();
        assert_eq!(
            resolve(&["nl", "--sandbox", "a", "--", "x"]),
            Ok((Container::Main, Sandbox::Named(name("a"))))
        );
        // Nothing named: nothing to resolve.
        assert_eq!(
            resolve(&["nl", "--fs-sandbox", "--", "x"]),
            Ok((Container::Main, Sandbox::Throwaway))
        );
        assert_eq!(
            resolve(&["nl", "--", "x"]),
            Ok((Container::Main, Sandbox::None))
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// The proxy is on unless said off, for all or for one program.
    #[test]
    fn the_wayland_proxy_is_on_unless_said_off() {
        assert!(proxy_wanted(None, false));
        assert!(proxy_wanted(Some("on"), false));
        assert!(proxy_wanted(Some("whatever"), false));
        assert!(!proxy_wanted(Some("off"), false));
        assert!(!proxy_wanted(Some("off\n"), false));
        assert!(!proxy_wanted(None, true));
    }

    /// Throwaway containers live below the state directory, not in /tmp: a
    /// hermetic zone's /tmp is its own (`docs/LEAK-MODEL.md` §15). One from
    /// before the move is still found where it was.
    #[test]
    fn a_throwaway_container_is_found_in_the_state_directory_first() {
        let state = std::env::temp_dir().join(format!("vz-throwaway-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        let name = OsStr::new("vpn-profile-vzunit01");
        assert_eq!(throwaway_path(&state, name), None);
        let dir = state.join(THROWAWAY_DIR).join(name);
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(throwaway_path(&state, name), Some(dir));
        assert_eq!(throwaway_bases(&state)[1], Path::new("/tmp"));
        let _ = fs::remove_dir_all(&state);
    }

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn pretty_label_reads_trims_and_ignores_junk() {
        let state = mkdtemp("/tmp/vpn-launch-test-XXXXXXXX").unwrap();
        std::fs::create_dir_all(state.join(".labels")).unwrap();
        std::fs::write(state.join(".labels").join("app"), "Телеграм\n").unwrap();
        std::fs::write(state.join(".labels").join("blank"), "  \n").unwrap();
        assert_eq!(
            pretty_label(&state, OsStr::new("app")).as_deref(),
            Some("Телеграм")
        );
        // Whitespace-only, missing and empty keys are all "no label": the
        // dialog falls back to the id rather than showing «».
        assert_eq!(pretty_label(&state, OsStr::new("blank")), None);
        assert_eq!(pretty_label(&state, OsStr::new("missing")), None);
        assert_eq!(pretty_label(&state, OsStr::new("")), None);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn a_bare_zone_and_a_command() {
        let s = Selection::parse(&argv(&["nl", "--", "firefox", "--new-window"])).unwrap();
        assert_eq!(s.zone, os("nl"));
        assert_eq!(s.container, Container::Main);
        assert_eq!(s.sandbox, Sandbox::None);
        assert_eq!(s.cmd, argv(&["firefox", "--new-window"]));
    }

    #[test]
    fn the_old_name_of_unconfined_is_read_as_it() {
        let s = Selection::parse(&argv(&["direct", "--", "firefox"])).unwrap();
        assert_eq!(s.zone, os(UNCONFINED));
        assert_eq!(network_name("direct"), "unconfined");
        assert_eq!(network_name("nl"), "nl");
        assert!(is_unconfined_name("direct") && is_unconfined_name("unconfined"));
        assert!(!is_unconfined_name("offline"));
    }

    #[test]
    fn the_separator_is_optional_and_only_the_first_one_counts() {
        assert_eq!(
            Selection::parse(&argv(&["nl", "firefox"])).unwrap().cmd,
            argv(&["firefox"])
        );
        assert_eq!(
            Selection::parse(&argv(&["nl", "--", "sh", "-c", "echo -- hi"]))
                .unwrap()
                .cmd,
            argv(&["sh", "-c", "echo -- hi"])
        );
    }

    #[test]
    fn every_container_shape_is_recognised() {
        for flag in ["--profile", "-p"] {
            let s = Selection::parse(&argv(&["nl", flag, "work", "--", "x"])).unwrap();
            assert_eq!(s.container, Container::Named(os("work")));
            assert_eq!(s.cmd, argv(&["x"]));
        }
        let s = Selection::parse(&argv(&["nl", "--tmp-profile", "--", "x"])).unwrap();
        assert_eq!(s.container, Container::TmpNew);
        let s = Selection::parse(&argv(&[
            "nl",
            "--tmp-profile",
            "--join",
            "/tmp/p",
            "--",
            "x",
        ]))
        .unwrap();
        assert_eq!(s.container, Container::TmpJoin(PathBuf::from("/tmp/p")));
        assert_eq!(s.cmd, argv(&["x"]));
    }

    #[test]
    fn every_sandbox_shape_is_recognised() {
        let s = Selection::parse(&argv(&["nl", "--fs-sandbox", "--", "x"])).unwrap();
        assert_eq!(s.sandbox, Sandbox::Throwaway);
        let s = Selection::parse(&argv(&["nl", "--sandbox", "work", "--", "x"])).unwrap();
        assert_eq!(s.sandbox, Sandbox::Named(os("work")));
        assert_eq!(s.cmd, argv(&["x"]));
    }

    #[test]
    fn a_container_and_a_sandbox_together_the_way_the_picker_writes_them() {
        let s = Selection::parse(&argv(&[
            "nl",
            "--tmp-profile",
            "--join",
            "/tmp/vpn-profile-abc",
            "--sandbox",
            "work",
            "--",
            "firefox",
        ]))
        .unwrap();
        assert_eq!(
            s.container,
            Container::TmpJoin(PathBuf::from("/tmp/vpn-profile-abc"))
        );
        assert_eq!(s.sandbox, Sandbox::Named(os("work")));
        assert_eq!(s.cmd, argv(&["firefox"]));
    }

    #[test]
    fn flags_after_the_command_belong_to_the_program() {
        let s = Selection::parse(&argv(&["nl", "--", "code", "--profile", "mine"])).unwrap();
        assert_eq!(s.container, Container::Main);
        assert_eq!(s.cmd, argv(&["code", "--profile", "mine"]));
    }

    #[test]
    fn a_missing_value_is_the_shell_message() {
        assert_eq!(Selection::parse(&[]), Err(ArgError::MissingZone));
        assert_eq!(Selection::parse(&argv(&[""])), Err(ArgError::MissingZone));
        assert_eq!(
            Selection::parse(&argv(&["nl", "--profile"])),
            Err(ArgError::MissingProfile)
        );
        assert_eq!(
            Selection::parse(&argv(&["nl", "--tmp-profile", "--join"])),
            Err(ArgError::MissingJoinDir)
        );
        assert_eq!(
            Selection::parse(&argv(&["nl", "--sandbox"])),
            Err(ArgError::MissingSandbox)
        );
        assert_eq!(
            Selection::parse(&argv(&["nl", "--sandbox", ""])),
            Err(ArgError::MissingSandbox)
        );
    }

    #[test]
    fn a_locked_zone_drops_the_whole_selection() {
        assert_eq!(
            strip_selection(&argv(&["nl", "--", "firefox"])),
            argv(&["firefox"])
        );
        assert_eq!(
            strip_selection(&argv(&["nl", "firefox"])),
            argv(&["firefox"])
        );
        assert_eq!(
            strip_selection(&argv(&["nl", "--profile", "work", "--", "firefox"])),
            argv(&["firefox"])
        );
        assert_eq!(
            strip_selection(&argv(&["nl", "-p", "work", "--fs-sandbox", "--", "a", "b"])),
            argv(&["a", "b"])
        );
        assert_eq!(
            strip_selection(&argv(&["nl", "--tmp-profile", "--sandbox", "s", "--", "x"])),
            argv(&["x"])
        );
        assert_eq!(
            strip_selection(&argv(&[
                "nl",
                "--tmp-profile",
                "--join",
                "/tmp/p",
                "--sandbox",
                "s",
                "--",
                "x"
            ])),
            argv(&["x"])
        );
        // Nothing left to run: the caller says so instead of exec'ing a flag.
        assert!(strip_selection(&argv(&["nl"])).is_empty());
        assert!(strip_selection(&argv(&["nl", "--fs-sandbox", "--"])).is_empty());
    }

    #[test]
    fn the_program_name_survives_wrappers_and_assignments() {
        assert_eq!(
            app_word(&argv(&["env", "DESKTOPINTEGRATION=1", "AyuGram"])),
            Some(OsStr::new("AyuGram"))
        );
        assert_eq!(
            app_word(&argv(&["/nix/store/xxx/bin/firefox"])),
            Some(OsStr::new("firefox"))
        );
        assert_eq!(
            app_word(&argv(&["nohup", "setsid", "-f", "telegram-desktop"])),
            Some(OsStr::new("telegram-desktop"))
        );
        assert_eq!(app_word(&argv(&["env"])), None);
        assert_eq!(app_word(&[]), None);
    }

    #[test]
    fn an_argument_with_an_equals_sign_in_it_is_not_an_assignment() {
        // The `*=*` pattern threw this away and the app-id came out empty.
        // What comes back is `basename` of the whole word, exactly as the shell
        // took it — an odd name, but a non-empty one, and the sanitiser makes it
        // a single word afterwards.
        assert_eq!(
            app_word(&argv(&["sh", "-c", "exec foo --url=https://x"])),
            Some(OsStr::new("x"))
        );
        assert_eq!(
            app_word(&argv(&["sh", "-c", "echo hello=world"])),
            Some(OsStr::new("echo hello=world"))
        );
        // A real assignment still is one.
        assert_eq!(
            app_word(&argv(&["FOO=bar", "_X=1", "chromium"])),
            Some(OsStr::new("chromium"))
        );
    }

    #[test]
    fn an_app_id_is_one_word_of_at_most_sixty_four_bytes() {
        assert_eq!(sanitize_app_id(OsStr::new("firefox")), os("firefox"));
        assert_eq!(
            sanitize_app_id(OsStr::new("org.kde.dolphin")),
            os("org.kde.dolphin")
        );
        // Spaces used to split the wl-sandbox argument in two.
        assert_eq!(sanitize_app_id(OsStr::new("echo -- hi")), os("echo_--_hi"));
        // The first line of a multi-line command is empty: without dropping the
        // newlines the id came out empty and the launch died.
        assert_eq!(sanitize_app_id(OsStr::new("\necho hi")), os("echo_hi"));
        assert_eq!(sanitize_app_id(OsStr::new("")), os(""));
        let long = "a".repeat(100);
        assert_eq!(sanitize_app_id(OsStr::new(&long)).len(), 64);
        // Byte-wise, exactly as `tr -c` was: one underscore per byte.
        assert_eq!(sanitize_app_id(OsStr::new("зона")), os("________"));
    }

    #[test]
    fn basenames_match_the_tool_of_the_same_name() {
        assert_eq!(basename(OsStr::new("/a/b/c")), OsStr::new("c"));
        assert_eq!(basename(OsStr::new("c")), OsStr::new("c"));
        assert_eq!(basename(OsStr::new("/a/b/")), OsStr::new("b"));
        assert_eq!(
            basename(OsStr::new("/tmp/vpn-profile-abc")),
            OsStr::new("vpn-profile-abc")
        );
        assert_eq!(basename(OsStr::new("/")), OsStr::new("/"));
        assert_eq!(basename(OsStr::new("")), OsStr::new(""));
    }

    #[test]
    fn no_setting_file_means_the_compositor_restriction_is_on() {
        // The default the project promises. Getting it wrong is invisible from
        // the outside: the program starts and works, only the spying is back.
        assert!(restrict_compositor(None, OsStr::new("firefox"), None));
        assert!(restrict_compositor(Some("on"), OsStr::new("firefox"), None));
        assert!(!restrict_compositor(
            Some("off"),
            OsStr::new("firefox"),
            None
        ));
        // Anything that is not "on" is off, as the shell comparison was.
        assert!(!restrict_compositor(Some(""), OsStr::new("firefox"), None));
    }

    #[test]
    fn the_exceptions_are_the_built_in_list_and_the_allow_file() {
        assert!(!restrict_compositor(None, OsStr::new("grim"), None));
        assert!(!restrict_compositor(None, OsStr::new("flatpak"), None));
        // One program per line, matched whole — `grep -qxF`.
        let allow = "copyq\nmy-recorder\n";
        assert!(!restrict_compositor(
            None,
            OsStr::new("my-recorder"),
            Some(allow)
        ));
        assert!(restrict_compositor(
            None,
            OsStr::new("my-recorder-2"),
            Some(allow)
        ));
        assert!(restrict_compositor(None, OsStr::new("record"), Some(allow)));
        // No app-id at all: there is nothing to name the sandbox after, and the
        // shell version skipped the wrapper too.
        assert!(!restrict_compositor(None, OsStr::new(""), None));
    }

    #[test]
    fn the_exception_list_holds_the_tools_that_live_off_those_protocols() {
        for name in ["grim", "wl-paste", "copyq", "obs", "niri", "waybar"] {
            assert!(
                WAYLAND_ALLOWED.contains(&name),
                "{name} пропал из исключений"
            );
        }
        // Nested sandboxes: they build a security context themselves.
        for name in ["flatpak", "bwrap", "podman", "distrobox"] {
            assert!(
                WAYLAND_ALLOWED.contains(&name),
                "{name} пропал из исключений"
            );
        }
        assert!(!WAYLAND_ALLOWED.contains(&"firefox"));
    }

    #[test]
    fn a_link_is_told_apart_from_a_file_argument() {
        assert!(hands_over_a_link(&argv(&["steam", "steam://rungameid/1"])));
        assert!(hands_over_a_link(&argv(&[
            "firefox",
            "https://example.org"
        ])));
        assert!(!hands_over_a_link(&argv(&["firefox", "/home/u/page.html"])));
        assert!(!hands_over_a_link(&argv(&["firefox"])));
        // The program word itself does not count.
        assert!(!hands_over_a_link(&argv(&["x://odd"])));
    }

    fn entry<'a>(network: Network, dir: &'a Path, ephemeral: bool) -> Entry<'a> {
        Entry {
            nsenter: Path::new("/t/nsenter"),
            unshare: Path::new("/t/unshare"),
            core: Path::new("/t/core"),
            zone: OsStr::new(match network {
                Network::Zone(_) => "nl",
                Network::Unconfined => UNCONFINED,
            }),
            network,
            dir,
            ephemeral,
            regdir: Path::new("/r/.running/work"),
            cwd: Path::new("/home/u/src"),
            trust: None,
            nss_home: None,
            trust_extra: &[],
            certutil: Path::new("/t/certutil"),
            shares: &[],
            storage: None,
            own_mounts: false,
            camera: false,
            devices: &[],
        }
    }

    /// A container of the main home into a zone: nothing to mount, and a
    /// mount namespace of its own all the same — the zone's own is its
    /// programs' with no container (`crate::origin`). Outside a zone it
    /// takes none: there is no zone's own to be told from.
    #[test]
    fn a_container_of_the_main_home_takes_a_mount_namespace_in_a_zone() {
        let mut e = entry(Network::Zone(42), Path::new(""), false);
        e.own_mounts = true;
        let line = entry_argv(&e, argv(&["dolphin"]));
        let at = |w: &str| line.iter().position(|a| a == w).unwrap();
        assert!(at("/t/nsenter") < at("/t/unshare"), "{line:?}");
        assert!(at("/t/unshare") < at("profile-run"), "{line:?}");
        assert_eq!(line[at("/t/unshare") + 1], "--mount");
        let mut e = entry(Network::Unconfined, Path::new(""), false);
        e.own_mounts = true;
        assert_eq!(entry_argv(&e, argv(&["dolphin"])), argv(&["dolphin"]));
    }

    /// A sandbox into a zone: the zone covers container storage, and the
    /// launch gets its own directory back — in a mount namespace of its own,
    /// never in the zone's, where every other program would see it.
    #[test]
    fn a_containers_storage_comes_back_in_its_own_namespace() {
        let mut e = entry(Network::Zone(42), Path::new(""), false);
        e.storage = Some(Path::new("/home/u/.local/state/vpn-sandboxes/work"));
        let line = entry_argv(&e, argv(&["firefox"]));
        let at = |w: &str| line.iter().position(|a| a == w).unwrap();
        assert!(at("/t/unshare") < at("profile-run"), "{line:?}");
        let s = at("--storage");
        assert_eq!(line[s + 1], "/home/u/.local/state/vpn-sandboxes/work");
    }

    #[test]
    fn trust_alone_is_enough_to_take_a_mount_namespace() {
        // A named sandbox has no overlay directory, but its certificates still
        // need a bundle bound in a namespace of this launch's own — never in
        // the zone's, where the container next door would see it.
        let mut e = entry(Network::Zone(42), Path::new(""), false);
        e.trust = Some(Path::new("/s/sb/work/trust"));
        e.nss_home = Some(Path::new("/s/sb/work/home"));
        let line = entry_argv(&e, argv(&["firefox"]));
        assert_eq!(
            line,
            argv(&[
                "/t/nsenter",
                "--preserve-credentials",
                "--keep-caps",
                "-U",
                "-n",
                "-m",
                "-t",
                "42",
                "--",
                "/t/unshare",
                "--mount",
                "--propagation",
                "slave",
                "--",
                "/t/core",
                "profile-run",
                "--cwd",
                "/home/u/src",
                "--trust",
                "/s/sb/work/trust",
                "--certutil",
                "/t/certutil",
                "--nss-home",
                "/s/sb/work/home",
                "",
                "nl",
                "0",
                "/r/.running/work",
                "--",
                "firefox"
            ])
        );

        // In direct the same takes a user namespace of its own.
        let mut e = entry(Network::Unconfined, Path::new(""), false);
        e.trust = Some(Path::new("/p/work/trust"));
        let line = entry_argv(&e, argv(&["firefox"]));
        assert_eq!(line[0], os("/t/unshare"));
        assert!(line.contains(&os("--map-current-user")));
        assert!(line.contains(&os("--trust")));
        // The home is $HOME there: no --nss-home without one.
        assert!(!line.contains(&os("--nss-home")));
    }

    #[test]
    fn into_a_zone_without_a_container_still_restores_the_working_directory() {
        // No layer to stack, but `nsenter` has left us in `/`: `profile-run`
        // with an empty directory stacks nothing and makes the chdir.
        let line = entry_argv(
            &entry(Network::Zone(42), Path::new(""), false),
            argv(&["firefox", "%u"]),
        );
        assert_eq!(
            line,
            argv(&[
                "/t/nsenter",
                "--preserve-credentials",
                "--keep-caps",
                "-U",
                "-n",
                "-m",
                "-t",
                "42",
                "--",
                "/t/core",
                "profile-run",
                "--cwd",
                "/home/u/src",
                "",
                "nl",
                "0",
                "/r/.running/work",
                "--",
                "firefox",
                "%u"
            ])
        );
        // Not `nsenter --wd`: that chdir would come before the overlay, and a
        // directory missing from the zone's mount tree would stop the launch.
        assert!(!line.iter().any(|a| a.to_string_lossy().starts_with("--wd")));
    }

    #[test]
    fn into_a_zone_with_a_container_keeps_the_caps_and_takes_a_mount_namespace() {
        let line = entry_argv(
            &entry(Network::Zone(42), Path::new("/p/work"), false),
            argv(&["firefox"]),
        );
        assert_eq!(
            line,
            argv(&[
                "/t/nsenter",
                "--preserve-credentials",
                "--keep-caps",
                "-U",
                "-n",
                "-m",
                "-t",
                "42",
                "--",
                "/t/unshare",
                "--mount",
                "--propagation",
                "slave",
                "--",
                "/t/core",
                "profile-run",
                "--cwd",
                "/home/u/src",
                "/p/work",
                "nl",
                "0",
                "/r/.running/work",
                "--",
                "firefox"
            ])
        );
    }

    #[test]
    fn direct_without_a_container_is_the_command_itself() {
        // Still whatever wrappers `run` put in front of it — they are part of
        // the command by then — but no namespace of any kind, and no chdir:
        // the working directory survives an exec by itself.
        let cmd = argv(&["/t/core", "wl-sandbox", "firefox", "--", "firefox"]);
        assert_eq!(
            entry_argv(
                &entry(Network::Unconfined, Path::new(""), false),
                cmd.clone()
            ),
            cmd
        );
        assert!(entry_argv(
            &entry(Network::Unconfined, Path::new(""), false),
            Vec::new()
        )
        .is_empty());
    }

    #[test]
    fn direct_with_a_container_makes_its_own_user_namespace_and_no_network_one() {
        // The container must not be dropped just because there is no zone to
        // borrow a user namespace from — that was a silent loss of isolation.
        let line = entry_argv(
            &entry(Network::Unconfined, Path::new("/tmp/vpn-profile-x"), true),
            argv(&["firefox"]),
        );
        assert_eq!(
            line,
            argv(&[
                "/t/unshare",
                "--user",
                "--map-current-user",
                "--keep-caps",
                "--mount",
                "--propagation",
                "private",
                "--",
                "/t/core",
                "profile-run",
                "--cwd",
                "/home/u/src",
                "/tmp/vpn-profile-x",
                "unconfined",
                "1",
                "/r/.running/work",
                "--",
                "firefox"
            ])
        );
        assert!(
            !line.contains(&os("--net")),
            "unconfined is the host's network"
        );
        assert!(!line.contains(&os("/t/nsenter")));
    }

    /// What a zone asked the broker for is a file name in the registry, not
    /// a path on the host.
    #[test]
    fn a_registry_key_is_never_a_path() {
        for (raw, key) in [
            ("firefox", "firefox"),
            ("org.telegram.desktop", "org.telegram.desktop"),
            ("/run/user/1000/x", "_run_user_1000_x"),
            ("../../.bashrc", ".._.._.bashrc"),
            ("..", "программа"),
            (".", "программа"),
            ("", "программа"),
        ] {
            assert_eq!(registry_key(OsStr::new(raw)), OsString::from(key), "{raw}");
        }
    }

    /// Cameras let a launch into a zone: a mount namespace of its own, and
    /// `profile-run --camera` binds them in there. Outside a zone they are
    /// the host's anyway.
    #[test]
    fn a_launch_let_the_cameras_uncovers_them_in_its_own_namespace() {
        let mut e = entry(Network::Zone(42), Path::new(""), false);
        e.camera = true;
        let line = entry_argv(&e, argv(&["cheese"]));
        let at = |w: &str| line.iter().position(|a| a == w).unwrap();
        assert!(at("/t/unshare") < at("profile-run"), "{line:?}");
        assert!(at("profile-run") < at("--camera"), "{line:?}");
        let mut e = entry(Network::Unconfined, Path::new(""), false);
        e.camera = true;
        assert_eq!(entry_argv(&e, argv(&["cheese"])), argv(&["cheese"]));
    }
}
