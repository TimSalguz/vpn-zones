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
//! **The last step must be an `exec`.** The pid does not change, so the registry
//! record written just before it stays true for as long as the program runs —
//! the picker, the conflict warning and the throwaway-container cleanup all read
//! that pid. Anything that forked here instead would leave a record naming a
//! process that exits immediately. (`docs/GOTCHAS.md` §5)

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::{self, zone_pid};
use crate::profile::{exec_command, proc_is_alive, EXIT_NOT_STARTED};
use crate::registry;
use crate::tools::Tools;

/// Marks the descendants of a zone. Its presence is what step 1 keys on.
pub const ENV_CURRENT: &str = "VPN_ZONE_CURRENT";
/// Set on the delegated launch so that it does not delegate itself again.
pub const ENV_DELEGATED: &str = "VPN_ZONE_DELEGATED";
/// The launcher's stable key for the program, put there by the picker.
pub const ENV_APPID: &str = "VPN_ZONE_APPID";
/// Print the resulting command and start nothing.
pub const ENV_DRYRUN: &str = "VPN_ZONE_DRYRUN";

/// Marker file of a locked ("no escape") zone.
pub const NO_ESCAPE: &str = "no-escape";

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
    Named(OsString),
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
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingZone => write!(f, "нужно имя"),
            Self::MissingProfile => write!(f, "нужно имя профиля"),
            Self::MissingJoinDir => write!(f, "нужен каталог временного контейнера"),
            Self::MissingSandbox => write!(f, "нужно имя песочницы"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Selection {
    /// Parse `<zone> [--profile P | -p P | --tmp-profile [--join DIR]]
    /// [--fs-sandbox | --sandbox NAME] [--] cmd…`.
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
            .ok_or(ArgError::MissingZone)?
            .clone();
        let mut rest: Vec<OsString> = rest.cloned().collect();

        let container = match rest.first().map(OsString::as_os_str) {
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
        Some(f) if f == "--profile" || f == "-p" => {
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

    let selection = match Selection::parse(argv) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let zone = selection.zone.clone();
    let zone_name = zone.to_string_lossy().into_owned();

    // --- 2. THE CONTAINER ---
    let Some(container) = resolve_container(tools, &selection.container) else {
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
    let label = pretty_label(
        &tools.state,
        appid_env.as_deref().unwrap_or(appbin.as_os_str()),
    );
    let mut cmd = selection.cmd.clone();

    if wayland_sandbox_wanted(tools, &appbin) {
        let mut wrapped: Vec<OsString> = vec![
            tools.core.clone().into(),
            "wl-sandbox".into(),
            appbin.clone(),
            "--".into(),
        ];
        wrapped.extend(cmd);
        cmd = wrapped;
    }

    if selection.sandbox != Sandbox::None {
        // The permissions belong to the launcher's id when there is one: the
        // shortcut says "discord" while the binary is called "Discord", and two
        // independent permission sets for one program is what taking the binary
        // name gave us. (`docs/GOTCHAS.md` §6)
        let fsid = appid_env.clone().unwrap_or_else(|| appbin.clone());
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
            fsid,
        ];
        if let Sandbox::Named(name) = &selection.sandbox {
            wrapped.push("--name".into());
            wrapped.push(name.clone());
        }
        if let Some(label) = &label {
            wrapped.push("--label".into());
            wrapped.push(label.clone().into());
        }
        wrapped.push("--".into());
        wrapped.extend(cmd);
        cmd = wrapped;
    }

    // --- 4. IS IT ALREADY RUNNING SOMEWHERE ELSE? ---
    let appname = appid_env.clone().unwrap_or_else(|| {
        if appbin.is_empty() {
            OsString::from("программа")
        } else {
            appbin.clone()
        }
    });
    let regdir = tools.state.join(".running").join(container.key.as_os_str());
    let reg = regdir.join(&appname);
    let dryrun = env_nonempty(ENV_DRYRUN).is_some();

    let busy = match registry::lock(&regdir) {
        Ok(_guard) => registry::rewrite_live(&reg, &zone_name, proc_is_alive).unwrap_or_else(|e| {
            eprintln!("реестр запусков {}: {e}", reg.display());
            None
        }),
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
        let message = CONFLICT_MESSAGE
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
    let mut pid = zone_pid(&tools.state, &zone);
    if pid.is_none() {
        // The shortcut may well have been clicked while the zone was down.
        // Starting it is the expected behaviour, not an error — and a failure
        // here is deliberately ignored, because the check below says the same
        // thing in words a user can act on.
        let _ = cli::systemctl(tools, "start", &zone);
        cli::wait_ready(&tools.state, &zone);
        pid = zone_pid(&tools.state, &zone);
    }
    let Some(pid) = pid else {
        eprintln!("зона {zone_name} не поднимается");
        return 1;
    };

    if dryrun {
        let shown: Vec<String> = cmd
            .iter()
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
    let selector: OsString = match &selection.sandbox {
        Sandbox::Named(name) => {
            let mut s = OsString::from("sb:");
            s.push(name);
            s
        }
        Sandbox::Throwaway => OsString::from("__fs__"),
        Sandbox::None => container.profile.clone(),
    };
    match registry::lock(&regdir) {
        Ok(_guard) => {
            if let Err(e) = registry::append(
                &reg,
                std::process::id() as i32,
                &zone_name,
                &selector.to_string_lossy(),
            ) {
                eprintln!("реестр запусков {}: {e}", reg.display());
            }
        }
        Err(e) => eprintln!("реестр запусков {}: {e}", regdir.display()),
    }

    // The mark descendants are recognised by: a program started in a zone that
    // tries to open something else has that launch delegated outwards (step 1).
    std::env::set_var(ENV_CURRENT, &zone);

    let mut exec: Vec<OsString> = vec![tools.nsenter.clone().into()];
    exec.push("--preserve-credentials".into());
    if !container.dir.as_os_str().is_empty() {
        // Without --keep-caps CapEff is zeroed on entering the zone's user
        // namespace and there is nothing left to mount the layer with.
        // (`docs/GOTCHAS.md` §1)
        exec.push("--keep-caps".into());
    }
    exec.extend(["-U".into(), "-n".into(), "-m".into(), "-t".into()]);
    exec.push(pid.to_string().into());
    exec.push("--".into());
    if !container.dir.as_os_str().is_empty() {
        exec.push(tools.unshare.clone().into());
        exec.extend([
            "--mount".into(),
            "--propagation".into(),
            "private".into(),
            "--".into(),
        ]);
        exec.push(tools.core.clone().into());
        exec.push("profile-run".into());
        exec.push(container.dir.clone().into());
        exec.push(zone.clone());
        exec.push(if container.ephemeral { "1" } else { "0" }.into());
        exec.push(regdir.into());
        exec.push("--".into());
    }
    exec.extend(cmd);

    let e = exec_command(&exec);
    eprintln!("не удалось запустить {}: {e}", tools.nsenter.display());
    EXIT_NOT_STARTED
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

/// Hand the launch to `systemd --user`, which lives outside every zone.
fn delegate(tools: &Tools, argv: &[OsString]) -> u8 {
    // The app-id is passed explicitly: systemd-run starts the unit with the
    // MANAGER's environment, not ours, and VPN_ZONE_APPID never reached it — so
    // a link opened from a messenger inside a zone built a separate set of file
    // permissions and a separate registry entry, and the same program stopped
    // being recognised as itself.
    let appid = env_nonempty(ENV_APPID).unwrap_or_default();
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
    exec.push("--".into());
    exec.push(tools.runner.clone().into());
    exec.push("run".into());
    exec.extend(argv.iter().cloned());

    let e = exec_command(&exec);
    eprintln!("не удалось запустить {}: {e}", tools.systemd_run.display());
    EXIT_NOT_STARTED
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

/// Turn the parsed container into directories, creating a throwaway one.
///
/// `None` means the message has been printed and the launch is over.
fn resolve_container(tools: &Tools, container: &Container) -> Option<ResolvedContainer> {
    let (profile, dir, ephemeral) = match container {
        Container::Main => (OsString::new(), PathBuf::new(), false),
        Container::Named(name) => {
            let dir = tools.profiles.join(name);
            if !dir.is_dir() {
                let name = name.to_string_lossy();
                eprintln!("профиля {name} нет — создай: vpn-zone profile create {name}");
                return None;
            }
            (name.clone(), dir, false)
        }
        Container::TmpNew => {
            // A throwaway layer lives in /tmp deliberately: here that is btrfs
            // on a disk rather than a tmpfs, so a browser cache does not eat the
            // RAM. (`docs/GOTCHAS.md` §5)
            let dir = match mkdtemp("/tmp/vpn-profile-XXXXXXXX") {
                Ok(dir) => dir,
                Err(e) => {
                    eprintln!("не создать временный контейнер в /tmp: {e}");
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
            (basename(dir.as_os_str()).to_owned(), dir.clone(), true)
        }
    };
    let key = if profile.is_empty() {
        OsString::from(registry::MAIN)
    } else {
        profile.clone()
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
fn wayland_sandbox_wanted(tools: &Tools, appbin: &OsStr) -> bool {
    let mode = cli::read_setting(&tools.config.join("wayland-sandbox"));
    let allowlist = std::fs::read_to_string(tools.config.join("wayland-allow")).ok();
    restrict_compositor(mode.as_deref(), appbin, allowlist.as_deref())
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
}
