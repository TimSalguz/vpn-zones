//! `fs-sandbox` — the FILESYSTEM sandbox: a bwrap box where `$HOME` is gone.
//!
//! The third layer, on top of the network (a zone) and the data (a container).
//! Here the program loses `$HOME` altogether: a tmpfs takes its place and only
//! what the user allowed sticks out. Everything else it has to ask for through
//! the PORTALS — which are already installed and working on the desktop
//! (kde/gnome/gtk plus xdg-document-portal).
//!
//! **The key trick is `/.flatpak-info`.** An application only goes through the
//! portals when it believes itself to be sandboxed, and the way it checks is the
//! presence of that file (GTK, Qt, Chromium and Electron all do this). Put the
//! file there and the file dialog is suddenly drawn by another process, handing
//! the program exactly the one file that was picked (through document-portal),
//! while the camera and screen capture start asking for permission. The
//! "Android-style" prompts come for free; nobody has to write them.
//!
//! **What this is NOT.** It is not a replacement for flatpak: that has a runtime
//! of its own and a rule directory per application. Here the program comes from
//! nixpkgs and sees `/nix/store` (it would not start otherwise), so "swap a
//! library" is not something this sandbox prevents — it prevents reading YOUR
//! files.
//!
//! This was the `vpn-fs-sandbox` shell script of `module/default.nix` until it
//! moved here; the behaviour is the same, including every trap listed below.
//! Three things changed with the move, all of them written down in `CHANGELOG.md`:
//!
//! * the seccomp filter is built IN PROCESS (`crate::seccomp`) and handed to
//!   bwrap on an inherited descriptor, instead of running `vpn-zone-seccomp
//!   export` as a subprocess and redirecting a file into fd 34 from the shell;
//! * a D-Bus proxy that never came up no longer takes the program down with it.
//!   The shell version bound the proxy socket unconditionally, so a missing
//!   socket made bwrap fail with "Can't find source path" and nothing started at
//!   all — the exact opposite of the intended soft degradation;
//! * the proxy is killed even when this process is signalled. In the shell
//!   version the `trap` lived in a subshell that a TERM could take out on its
//!   own, leaving `xdg-dbus-proxy` behind.
//!
//! Traps carried over from the shell version, each of them load-bearing:
//!
//! * **The argument order of bwrap matters.** Operations are applied in the
//!   order they appear, so the tmpfs over `$HOME` has to come before the binds
//!   that poke through it, and the tmpfs over `XDG_RUNTIME_DIR` before the
//!   sockets. [`bwrap_args`] is a pure function precisely so that this order can
//!   be asserted in a test instead of hoped for.
//! * **The host's X socket is never passed in.** In a shared X server every
//!   client sees everybody's windows and input — a hole exactly the size of the
//!   one being closed. flatpak agrees: its `--socket=x11` is documented as
//!   unsafe. With the `x11` permission the sandbox runs an `xwayland-satellite`
//!   OF ITS OWN instead, on the already restricted Wayland socket, so X is no
//!   way around the security context either.
//! * **Without the x11 permission `DISPLAY` is unset**, or toolkits see the
//!   inherited `:0`, go to X and die instead of falling back to Wayland.
//!   Electron does not need X at all — `ELECTRON_OZONE_PLATFORM_HINT=auto` is
//!   enough (measured on Discord, which failed with "Missing X server or
//!   $DISPLAY" without it).
//! * **`/dev/dri` alone is not enough on NVIDIA.** The driver needs the
//!   `/dev/nvidia*` nodes too; without them EGL inside dies ("failed to create
//!   dri2 screen") and Electron hangs on its splash screen forever (measured on
//!   Discord).
//! * **`mimeapps.list` is passed in read-only.** `~/.config` is empty inside, so
//!   `xdg-open` picks a handler by itself: Discord's login link opened in Chrome
//!   although the default browser was zen. The file is tiny and holds no
//!   secrets.
//! * **Names do not resolve without `/run/systemd/resolve`.** `/etc/resolv.conf`
//!   is a symlink into it and `/run` itself is not passed in.
//! * **The permission dialog is not shown without a graphical session**: there
//!   would be nowhere to show it and nobody to answer, and the program would
//!   simply hang (measured). Then the answer is "nothing is allowed".
//! * **bwrap is NOT exec'd.** Somebody has to kill the bus proxy after the
//!   program exits, and the proxy's output goes to `/dev/null` or it keeps
//!   stdout open and the call looks like it is hanging long after the program
//!   has finished.
//!
//! Usage:
//! `vpn-zone-core fs-sandbox [--bwrap P] [--dbus-proxy P] [--kdialog P]
//! [--xwayland P] <app-id> [--name <sandbox>] [--label <text>] -- <command…>`.
//!
//! The tool paths are flags because Nix substitutes them: part of this runs
//! inside namespaces where `PATH` can be anything, the same reason the zone
//! holder takes `--ip`/`--pasta`.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, DirBuilder, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use crate::profile::{exit_code_of, home_dir, EXIT_NOT_STARTED};
use crate::seccomp::{Filter, FilterOptions};

/// Where the per-application permissions live, below `$HOME`. `vpn-zone perms`
/// reads the very same files, so this path is a contract.
const PERM_SUBDIR: &str = ".config/vpn-zones/fs-perms";
/// Where a NAMED sandbox keeps its home and its (shared) permissions.
/// `vpn-zone sandbox list/create/rm` is the other end of this contract.
const SANDBOX_SUBDIR: &str = ".local/state/vpn-sandboxes";
/// The one file passed in from `~/.config`, read-only.
const MIMEAPPS: &str = ".config/mimeapps.list";

/// The descriptor number bwrap reads the compiled filter from.
///
/// `bwrap --seccomp` takes a NUMBER, never a path, so the program has to be on
/// an inherited descriptor. The shell version opened one with `exec 34< file`
/// because a redirection cannot be put into an argument array; here the same
/// number is produced by a `dup2` in `pre_exec`, which also clears `FD_CLOEXEC`
/// as a side effect of duplicating. Any free number would do — bwrap reads the
/// descriptor and closes it itself.
const SECCOMP_FD: libc::c_int = 34;

/// Waiting for the proxy socket: 50 steps of 0.1 s, five seconds, as in bash.
const WAIT_STEPS: u32 = 50;
const WAIT_STEP: Duration = Duration::from_millis(100);

/// A second for the X server to come up. Without it the program starts before
/// the socket exists and dies with "cannot open display".
const X11_SETTLE: Duration = Duration::from_secs(1);

/// How long to wait for a TERM'd bus proxy before insisting with a KILL.
const PROXY_GRACE: Duration = Duration::from_millis(500);

/// What the sandboxed program is allowed to reach on the session bus.
///
/// Without a filter it reaches the Secret Service through the bus — that is
/// KWallet with every password in it — plus the window list and every other
/// application. Only the portals and notifications get through.
const BUS_TALK: [&str; 3] = [
    "--talk=org.freedesktop.portal.*",
    "--talk=org.freedesktop.Notifications",
    "--talk=org.kde.StatusNotifierWatcher",
];

/// The lowest and the number of X display numbers a satellite may take
/// (`:100`…`:499`, as the shell's `(RANDOM % 400) + 100`).
const DISPLAY_BASE: u64 = 100;
const DISPLAY_SPAN: u64 = 400;

// --- ARGUMENTS ---------------------------------------------------------------

/// Absolute paths of the tools the sandbox drives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tools {
    pub bwrap: PathBuf,
    pub dbus_proxy: PathBuf,
    pub kdialog: PathBuf,
    pub xwayland: PathBuf,
}

impl Default for Tools {
    /// Bare names, i.e. "find them on `PATH`". Only used when a flag was left
    /// out — running the sandbox by hand, out of a `nix-shell`.
    fn default() -> Self {
        Self {
            bwrap: PathBuf::from("bwrap"),
            dbus_proxy: PathBuf::from("xdg-dbus-proxy"),
            kdialog: PathBuf::from("kdialog"),
            xwayland: PathBuf::from("xwayland-satellite"),
        }
    }
}

/// What `fs-sandbox` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Identifier the permissions are remembered under. `vpn-zone run` passes
    /// the launcher's id (`VPN_ZONE_APPID`) and only falls back to the binary
    /// name, or the permissions would double up: Discord's desktop entry says
    /// "discord" while the binary is called "Discord", which used to produce two
    /// independent permission sets for one program.
    pub app_id: String,
    /// `--name <sandbox>`: a PERSISTENT sandbox with a shared home. Several
    /// programs can be started into it and they see each other's files but not
    /// yours. Without it the home is a tmpfs that dies with the program.
    pub sandbox: Option<String>,
    /// `--label <text>`: the human-readable program name for the dialogs. The
    /// app-id stays the KEY the permissions are remembered under; this is only
    /// what the user reads. Two programs starting at once each ask their
    /// question, and a dialog titled with a raw id is how the answers get
    /// swapped.
    pub label: Option<String>,
    pub tools: Tools,
    /// The program and its arguments.
    pub cmd: Vec<OsString>,
}

/// Everything that can be wrong with the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// No `--` separator, so where the command starts is anybody's guess.
    NoSeparator,
    /// No app-id, or an empty one.
    MissingAppId,
    /// `fs-sandbox-x11` without the display number to start the server on.
    MissingDisplay,
    /// `--` was there, but nothing followed it.
    EmptyCommand,
    /// A flag without its value.
    MissingValue(String),
    UnknownFlag(String),
    /// More than one positional argument. Almost always a quoting accident.
    ExtraArguments,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSeparator => write!(f, "no `--` before the command"),
            Self::MissingAppId => write!(f, "need a non-empty <app-id>"),
            Self::MissingDisplay => write!(f, "need a display number, e.g. :123"),
            Self::EmptyCommand => write!(f, "nothing to run after `--`"),
            Self::MissingValue(flag) => write!(f, "{flag} needs a value"),
            Self::UnknownFlag(flag) => write!(f, "unknown flag: {flag}"),
            Self::ExtraArguments => write!(f, "only <app-id> may precede `--`"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parse `[--tool P…] <app-id> [--name <sandbox>] -- cmd...`.
    ///
    /// Flags may come in any order and on either side of the app-id: Nix puts
    /// the tool paths first and `--name` after it, the way the shell version
    /// took them, but nothing here depends on that.
    ///
    /// The command keeps its `OsString`s — an argument can be a file name handed
    /// over by the launcher through a `%U` field code, and those are bytes, not
    /// necessarily UTF-8.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let split = argv
            .iter()
            .position(|a| a == "--")
            .ok_or(ArgError::NoSeparator)?;
        let cmd = argv[split + 1..].to_vec();
        if cmd.is_empty() {
            return Err(ArgError::EmptyCommand);
        }

        let mut tools = Tools::default();
        let mut sandbox: Option<String> = None;
        let mut label: Option<String> = None;
        let mut app_id: Option<OsString> = None;
        let mut rest = argv[..split].iter();
        while let Some(arg) = rest.next() {
            if !arg.as_bytes().starts_with(b"--") {
                if app_id.is_some() {
                    return Err(ArgError::ExtraArguments);
                }
                app_id = Some(arg.clone());
                continue;
            }
            let flag = arg.to_string_lossy().into_owned();
            let value = rest
                .next()
                .ok_or_else(|| ArgError::MissingValue(flag.clone()))?;
            match flag.as_str() {
                "--bwrap" => tools.bwrap = PathBuf::from(value),
                "--dbus-proxy" => tools.dbus_proxy = PathBuf::from(value),
                "--kdialog" => tools.kdialog = PathBuf::from(value),
                "--xwayland" => tools.xwayland = PathBuf::from(value),
                // An empty name is "no named sandbox", the way the shell's
                // `sbname=""` was: a launcher that lost the value must not end
                // up creating a sandbox directory called "".
                "--name" => {
                    sandbox = Some(value.to_string_lossy().into_owned()).filter(|n| !n.is_empty())
                }
                // Same shape as `--name`: an empty label is "no label", not a
                // dialog about a program called "".
                "--label" => {
                    label = Some(value.to_string_lossy().into_owned()).filter(|l| !l.is_empty())
                }
                _ => return Err(ArgError::UnknownFlag(flag)),
            }
        }

        let app_id = app_id
            .filter(|a| !a.is_empty())
            .ok_or(ArgError::MissingAppId)?;
        Ok(Self {
            // The id goes into a file name and into FLATPAK_ID, so it is
            // converted lossily rather than refused: an odd byte in a program
            // name must not cost the user the sandbox.
            app_id: app_id.to_string_lossy().into_owned(),
            sandbox,
            label,
            tools,
            cmd,
        })
    }
}

// --- PERMISSIONS -------------------------------------------------------------

/// The tokens of a permission file, in the order the dialog lists them.
pub const PERM_TOKENS: [&str; 5] = ["downloads", "documents", "pictures", "x11", "home"];

/// What the user allowed this program (or this named sandbox) to see.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Perms {
    pub downloads: bool,
    pub documents: bool,
    pub pictures: bool,
    pub x11: bool,
    /// The whole home directory, i.e. no filesystem isolation at all.
    pub home: bool,
}

impl Perms {
    /// Read a permission file.
    ///
    /// Tokens are matched as SUBSTRINGS of the whole text, which is exactly what
    /// the shell's `case "$perms" in *home*)` did, and the reason old files keep
    /// working: `kdialog --separate-output` writes one token per line, but a
    /// file written before that flag existed holds space-separated, quoted
    /// tokens (`"downloads" "home"`). No token is a substring of another, so
    /// there is nothing to confuse.
    pub fn parse(text: &str) -> Self {
        Self {
            downloads: text.contains("downloads"),
            documents: text.contains("documents"),
            pictures: text.contains("pictures"),
            x11: text.contains("x11"),
            home: text.contains("home"),
        }
    }

    /// The file contents: one token per line, in dialog order.
    ///
    /// An empty set is an EMPTY file. The shell wrote a lone newline here
    /// (`printf '%s\n' "$sel"`) while its own headless branch wrote nothing
    /// (`: > "$permfile"`); both parse to "nothing allowed", and the empty file
    /// is the one `vpn-zone perms list` renders as "ничего" instead of a blank.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (token, set) in PERM_TOKENS.iter().zip([
            self.downloads,
            self.documents,
            self.pictures,
            self.x11,
            self.home,
        ]) {
            if set {
                out.push_str(token);
                out.push('\n');
            }
        }
        out
    }
}

/// Ask the user, once per program (or once per named sandbox), what the sandbox
/// may show.
///
/// The dialog texts stay in Russian on purpose: they are read by the user at his
/// desktop, and this project's i18n (ROADMAP M6) has not happened yet. Cancelling
/// means "nothing allowed" — the safe answer.
fn ask_permissions(kdialog: &Path, shown: &str) -> Perms {
    // The program's name goes into the BODY, not only the title: with two
    // programs starting at once there are two of these dialogs on the screen,
    // and the body is what the user actually reads before answering.
    let question = format!(
        "Что показать программе «{shown}»? Ничего не отмечай — и она не увидит НИЧЕГО из твоих файлов: нужное сможет получить только через диалог выбора файла, по одному."
    );
    let out = Command::new(kdialog)
        .arg("--title")
        .arg(format!("Доступ к файлам: {shown}"))
        .arg("--separate-output")
        .args([
            "--checklist",
            question.as_str(),
            "downloads",
            "Загрузки (~/Downloads)",
            "off",
            "documents",
            "Документы (~/Documents)",
            "off",
            "pictures",
            "Изображения (~/Pictures)",
            "off",
            "x11",
            "Свой X-сервер (нужен Wine и старым программам)",
            "off",
            "home",
            "ВЕСЬ домашний каталог — файловой изоляции не будет",
            "off",
        ])
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(out) if out.status.success() => Perms::parse(&String::from_utf8_lossy(&out.stdout)),
        // Cancelled, or kdialog is not there at all: allow nothing.
        _ => Perms::default(),
    }
}

// --- THE ARGUMENT LIST -------------------------------------------------------

/// Everything the bwrap argument list depends on, gathered from the system by
/// the caller so that building the list itself stays a pure function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub app_id: String,
    pub home: PathBuf,
    pub runtime: PathBuf,
    pub perms: Perms,
    /// The persistent home of a named sandbox, bound over `$HOME`.
    pub sandbox_home: Option<PathBuf>,
    /// `~/.config/mimeapps.list`, when it exists.
    pub mimeapps: Option<PathBuf>,
    /// `/dev/dri` and the `/dev/nvidia*` nodes that exist.
    pub dev_nodes: Vec<PathBuf>,
    /// The compositor's socket — already the restricted one built by
    /// `wl-sandbox`, if there was one.
    pub wayland: Option<PathBuf>,
    pub pipewire: Option<PathBuf>,
    pub pulse: Option<PathBuf>,
    /// The filtered bus, or `None` when the proxy never came up.
    pub bus_proxy: Option<PathBuf>,
    pub flatpak_info: PathBuf,
    /// `:100`…`:499` with the x11 permission, `None` without it.
    pub display: Option<String>,
    pub seccomp_fd: Option<libc::c_int>,
}

fn push(v: &mut Vec<OsString>, s: &str) {
    v.push(OsString::from(s));
}

fn bind(v: &mut Vec<OsString>, kind: &str, src: &Path, dst: &Path) {
    push(v, kind);
    v.push(src.as_os_str().to_owned());
    v.push(dst.as_os_str().to_owned());
}

fn bind_same(v: &mut Vec<OsString>, kind: &str, path: &Path) {
    bind(v, kind, path, path);
}

/// The whole bwrap command line, in the order bwrap applies it.
///
/// A pure function of [`Layout`] and the command, and that is the point: the
/// ORDER of these operations is the sandbox. A tmpfs listed after the bind it is
/// supposed to hide would silently undo it, and there is no way to notice that
/// by reading a launched program — so the list is asserted in unit tests
/// instead.
pub fn bwrap_args(layout: &Layout, cmd: &[OsString]) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();

    bind_same(&mut a, "--ro-bind", Path::new("/nix/store"));
    // `-try` and not a plain `--ro-bind`: this path is NixOS-only, and a missing
    // source is a hard bwrap failure ("Can't find source path"). The sandbox has
    // to survive on a machine that has a nix store but no NixOS system profile —
    // the CI runner is exactly that, and so is a nix-on-Debian install.
    bind_same(&mut a, "--ro-bind-try", Path::new("/run/current-system"));
    bind_same(&mut a, "--ro-bind-try", Path::new("/run/opengl-driver"));
    bind_same(&mut a, "--ro-bind-try", Path::new("/run/opengl-driver-32"));
    bind_same(&mut a, "--ro-bind", Path::new("/etc"));
    bind_same(&mut a, "--ro-bind-try", Path::new("/sys"));
    // /etc/resolv.conf is a symlink into /run/systemd/resolve, and /run itself
    // is not passed in: without this line names do not resolve inside.
    bind_same(&mut a, "--ro-bind-try", Path::new("/run/systemd/resolve"));
    push(&mut a, "--dev");
    push(&mut a, "/dev");
    for node in &layout.dev_nodes {
        bind_same(&mut a, "--dev-bind-try", node);
    }
    push(&mut a, "--proc");
    push(&mut a, "/proc");
    push(&mut a, "--tmpfs");
    push(&mut a, "/tmp");

    // --- HOME ---
    if layout.perms.home {
        bind_same(&mut a, "--bind", &layout.home);
    } else {
        match &layout.sandbox_home {
            // The persistent home of a named sandbox: it outlives the program
            // and is shared by everything started into the same sandbox.
            Some(sb) => bind(&mut a, "--bind", sb, &layout.home),
            // A tmpfs instead of the home: the program gets an empty $HOME and
            // sees no keys, no documents and no other program's settings.
            None => {
                push(&mut a, "--tmpfs");
                a.push(layout.home.as_os_str().to_owned());
            }
        }
        // Plain `--bind`, not `--bind-try`, exactly as the shell had it: a
        // permission granted for a directory that does not exist is a bwrap
        // failure rather than a silently ignored tick. Worth knowing, since
        // ~/Pictures is not guaranteed to exist.
        for (allowed, name) in [
            (layout.perms.downloads, "Downloads"),
            (layout.perms.documents, "Documents"),
            (layout.perms.pictures, "Pictures"),
        ] {
            if allowed {
                bind_same(&mut a, "--bind", &layout.home.join(name));
            }
        }
    }

    // --- FILE AND LINK ASSOCIATIONS ---
    if let Some(mime) = &layout.mimeapps {
        bind_same(&mut a, "--ro-bind", mime);
    }

    // --- SOCKETS ---
    // A tmpfs over XDG_RUNTIME_DIR, then the sockets by name. Nothing else from
    // the runtime directory is visible to the program.
    push(&mut a, "--tmpfs");
    a.push(layout.runtime.as_os_str().to_owned());
    for path in [&layout.wayland, &layout.pipewire, &layout.pulse]
        .into_iter()
        .flatten()
    {
        bind_same(&mut a, "--ro-bind", path);
    }
    if let Some(proxy) = &layout.bus_proxy {
        bind(&mut a, "--bind", proxy, &layout.runtime.join("bus"));
    }

    bind(
        &mut a,
        "--ro-bind",
        &layout.flatpak_info,
        Path::new("/.flatpak-info"),
    );

    push(&mut a, "--setenv");
    push(&mut a, "HOME");
    a.push(layout.home.as_os_str().to_owned());
    push(&mut a, "--setenv");
    push(&mut a, "XDG_RUNTIME_DIR");
    a.push(layout.runtime.as_os_str().to_owned());
    push(&mut a, "--setenv");
    push(&mut a, "DBUS_SESSION_BUS_ADDRESS");
    // Kept pointing at the proxy even when the proxy is missing: the address
    // then names a path inside the runtime tmpfs, where there is nothing. The
    // program finds no bus, which is the intended degradation — the one thing it
    // must never do is find the REAL one.
    let mut addr = OsString::from("unix:path=");
    addr.push(layout.runtime.join("bus"));
    a.push(addr);
    push(&mut a, "--setenv");
    push(&mut a, "FLATPAK_ID");
    push(&mut a, &layout.app_id);
    push(&mut a, "--setenv");
    push(&mut a, "ELECTRON_OZONE_PLATFORM_HINT");
    push(&mut a, "auto");
    push(&mut a, "--setenv");
    push(&mut a, "NIXOS_OZONE_WL");
    push(&mut a, "1");
    push(&mut a, "--unsetenv");
    push(&mut a, "DBUS_SYSTEM_BUS_ADDRESS");

    match &layout.display {
        Some(display) => {
            push(&mut a, "--setenv");
            push(&mut a, "DISPLAY");
            push(&mut a, display);
        }
        // Without the x11 permission DISPLAY is dropped, or toolkits see the
        // inherited :0, go to X and die instead of falling back to Wayland.
        None => {
            push(&mut a, "--unsetenv");
            push(&mut a, "DISPLAY");
        }
    }

    if let Some(fd) = layout.seccomp_fd {
        push(&mut a, "--seccomp");
        push(&mut a, &fd.to_string());
    }

    push(&mut a, "--unshare-pid");
    push(&mut a, "--unshare-ipc");
    push(&mut a, "--unshare-uts");
    push(&mut a, "--unshare-cgroup-try");
    push(&mut a, "--die-with-parent");
    push(&mut a, "--");
    a.extend(cmd.iter().cloned());
    a
}

/// The `/.flatpak-info` a toolkit looks at to decide it is sandboxed.
///
/// The minimal `[Application]` section is enough to switch GTK, Qt, Chromium and
/// Electron over to the portals.
pub fn flatpak_info(app_id: &str, instance: u32) -> String {
    format!(
        "[Application]\n\
         name={app_id}\n\
         \n\
         [Instance]\n\
         instance-id={instance}\n\
         session-bus-proxy=true\n\
         system-bus-proxy=false\n"
    )
}

/// A display number for the sandbox's own X server, `:100`…`:499`.
///
/// The randomness is inherited from the shell version and costs nothing;
/// collisions are impossible anyway, because the satellite creates its socket in
/// the sandbox's own `/tmp`, which is a fresh tmpfs with nothing in it.
pub fn pick_display(seed: u64) -> String {
    format!(":{}", DISPLAY_BASE + seed % DISPLAY_SPAN)
}

/// `/dev/dri` and every `/dev/nvidia*` node, in that order.
///
/// One `/dev/dri` is not enough on NVIDIA: without the `/dev/nvidia*` nodes EGL
/// inside the sandbox fails with "failed to create dri2 screen" and Electron
/// hangs on its splash screen (measured on Discord).
///
/// The directory is a parameter so that a test can hand over one it built.
/// Sorted by bytes: `read_dir` has no order of its own, and a stable list is
/// what makes the argument list comparable.
pub fn dev_nodes(dev: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dri = dev.join("dri");
    if dri.symlink_metadata().is_ok() {
        out.push(dri);
    }
    let mut nvidia: Vec<PathBuf> = match fs::read_dir(dev) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| e.file_name().as_bytes().starts_with(b"nvidia"))
            .map(|e| e.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    nvidia.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
    out.extend(nvidia);
    out
}

// --- RUNNING -----------------------------------------------------------------

/// The bus proxy and the sandbox, so that a signal can be passed on to them.
static PROXY_PID: AtomicI32 = AtomicI32::new(0);
static BWRAP_PID: AtomicI32 = AtomicI32::new(0);
/// Were we asked to stop before the sandbox even started?
static ASKED_TO_STOP: AtomicBool = AtomicBool::new(false);

/// Pass a TERM/INT on to the sandbox and the proxy.
///
/// The shell version could not do this: its `trap` lived in a subshell, and a
/// signal that took the subshell out left `xdg-dbus-proxy` running with nobody
/// to collect it. bwrap's `--die-with-parent` covers the sandbox but not the
/// proxy, which is a process of ours and not of bwrap's.
extern "C" fn forward_stop(sig: libc::c_int) {
    ASKED_TO_STOP.store(true, Ordering::SeqCst);
    for slot in [&BWRAP_PID, &PROXY_PID] {
        let pid = slot.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: kill(2) is async-signal-safe and takes no pointers.
            unsafe { libc::kill(pid, sig) };
        }
    }
}

fn on_term_and_int(handler: extern "C" fn(libc::c_int)) {
    let handler = handler as libc::sighandler_t;
    // SAFETY: signal(2) with a plain function pointer; the handler only touches
    // atomics and calls kill(2).
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

/// The scratch directory and the bus proxy, removed and killed on the way out —
/// including the way out through a signal, because the handler above turns a
/// signal into an ordinary return from [`run`].
struct Cleanup {
    dir: PathBuf,
    proxy: Option<Child>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(mut proxy) = self.proxy.take() {
            PROXY_PID.store(0, Ordering::SeqCst);
            // TERM first, as the shell did; a KILL only for a proxy that will
            // not go, so that the sandbox cannot be outlived by its own bus.
            // SAFETY: kill(2) takes no pointers and the child has not been
            // waited for yet, so the pid is still ours.
            unsafe { libc::kill(proxy.id() as libc::pid_t, libc::SIGTERM) };
            let deadline = std::time::Instant::now() + PROXY_GRACE;
            loop {
                match proxy.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if std::time::Instant::now() >= deadline => {
                        let _ = proxy.kill();
                        let _ = proxy.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(WAIT_STEP),
                }
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    // SAFETY: getuid(2) cannot fail and takes no pointers.
    PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() }))
}

/// Is there a graphical session to show a dialog in?
///
/// Without one there is nowhere to show the permission dialog and nobody to
/// answer it — the program would simply hang (measured). The same test the
/// picker and the "already running elsewhere" warning use.
fn has_graphics() -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
}

/// The path, if there is a socket at it. `[ -S … ]`, symlinks followed.
fn socket_at(path: PathBuf) -> Option<PathBuf> {
    match fs::metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => Some(path),
        _ => None,
    }
}

/// A private scratch directory for `/.flatpak-info` and the proxy socket.
///
/// Mode 0700 and never anything else: the filtered bus lives in here, and a
/// world-writable path would let anybody on the machine hand the sandbox a bus
/// of their own.
fn scratch_dir() -> io::Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let path = std::env::temp_dir().join(format!("vpn-fs-sandbox-{}-{nanos}", std::process::id()));
    DirBuilder::new().mode(0o700).create(&path)?;
    // The mode above is still masked by the umask, so say it again outright.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

/// The compiled filter on a descriptor, or `None` with a word on stderr.
///
/// Soft degradation, as in every other layer: a filter that will not build must
/// not cost the user the program. This is where the shell called
/// `vpn-zone-seccomp export` as a subprocess and redirected its output into a
/// file; the filter is now built in this process, which removes both the fork
/// and the temporary file from the startup path of every sandboxed program.
fn seccomp_program() -> Option<File> {
    let filter = match Filter::build(FilterOptions::default()) {
        Ok(filter) => filter,
        Err(e) => {
            eprintln!("fs-sandbox: cannot build the seccomp filter ({e}) — running without it");
            return None;
        }
    };
    // Never fatal: a rule missing because this libseccomp does not know the
    // syscall still leaves a filter that is better than none. Saying nothing
    // about a filter with holes in it, on the other hand, would be wrong.
    let unknown = filter.unknown_syscalls();
    if !unknown.is_empty() {
        eprintln!("fs-sandbox: unknown to libseccomp, rules skipped: {unknown:?}");
    }
    let file = match filter.export_to_file() {
        Ok(file) => file,
        Err(e) => {
            eprintln!("fs-sandbox: cannot export the seccomp filter ({e}) — running without it");
            return None;
        }
    };
    // The shell version's `[ -s "$info/seccomp.bpf" ]`, and worth keeping: an
    // empty program is accepted by bwrap and filters absolutely nothing, which
    // is the one failure mode that would look like success.
    if file.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
        eprintln!("fs-sandbox: libseccomp produced an empty program — running without a filter");
        return None;
    }
    Some(file)
}

/// Start the filtered session bus and wait for its socket.
///
/// Returns the proxy (to be killed later, whether or not it worked) and the
/// socket — and a socket of `None` is the fix this port carries: the shell bound
/// it unconditionally, so a proxy that never came up made bwrap fail with
/// "Can't find source path" and the program did not start at all. The intent was
/// always the opposite: no bus is a degradation, no program is a bug.
fn start_bus_proxy(tool: &Path, socket: &Path, runtime: &Path) -> (Option<Child>, Option<PathBuf>) {
    let address = std::env::var_os("DBUS_SESSION_BUS_ADDRESS")
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| {
            let mut addr = OsString::from("unix:path=");
            addr.push(runtime.join("bus"));
            addr
        });
    // The output goes to /dev/null: an open stdout of the proxy makes the call
    // look like it is hanging long after the program has finished.
    let mut child = match Command::new(tool)
        .arg(address)
        .arg(socket)
        .arg("--filter")
        .args(BUS_TALK)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "fs-sandbox: cannot start {} ({e}) — the program gets no session bus",
                tool.display()
            );
            return (None, None);
        }
    };
    PROXY_PID.store(child.id() as i32, Ordering::SeqCst);

    for _ in 0..WAIT_STEPS {
        if let Some(path) = socket_at(socket.to_path_buf()) {
            return (Some(child), Some(path));
        }
        // A proxy that has already exited will never create the socket, and
        // waiting out the full five seconds for it would delay every launch on
        // a machine with no session bus at all (a CI runner, a tty login).
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(WAIT_STEP);
    }
    eprintln!("fs-sandbox: the D-Bus proxy did not come up — the program gets no session bus");
    (Some(child), None)
}

/// Everything `fs-sandbox` does, from the permissions to the exit code.
pub fn run(args: Args) -> u8 {
    let Some(home) = home_dir() else {
        eprintln!("fs-sandbox: no $HOME — there is nothing to sandbox");
        return EXIT_NOT_STARTED;
    };
    let runtime = runtime_dir();

    // --- PERMISSIONS ---
    // Asked once per program and remembered. Empty means "nothing beyond the
    // portal file exchange". A NAMED sandbox keeps them per sandbox, not per
    // program: its home is shared, so a second program would otherwise be asked
    // all over again about the very same directory.
    let perm_dir = home.join(PERM_SUBDIR);
    if let Err(e) = fs::create_dir_all(&perm_dir) {
        eprintln!("fs-sandbox: cannot create {}: {e}", perm_dir.display());
        return EXIT_NOT_STARTED;
    }
    let (perm_file, sandbox_home) = match &args.sandbox {
        Some(name) => {
            let dir = home.join(SANDBOX_SUBDIR).join(name);
            if let Err(e) = fs::create_dir_all(dir.join("home")) {
                eprintln!("fs-sandbox: cannot create {}: {e}", dir.display());
                return EXIT_NOT_STARTED;
            }
            (dir.join("perms"), Some(dir.join("home")))
        }
        None => (perm_dir.join(&args.app_id), None),
    };

    if !perm_file.is_file() {
        let perms = if has_graphics() {
            ask_permissions(
                &args.tools.kdialog,
                args.label.as_deref().unwrap_or(&args.app_id),
            )
        } else {
            Perms::default()
        };
        if let Err(e) = fs::write(&perm_file, perms.render()) {
            eprintln!(
                "fs-sandbox: cannot write {}: {e} — asking again next time",
                perm_file.display()
            );
        }
    }
    let perms = Perms::parse(&fs::read_to_string(&perm_file).unwrap_or_default());

    // --- SCRATCH: /.flatpak-info AND THE BUS SOCKET ---
    let dir = match scratch_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("fs-sandbox: cannot create a scratch directory: {e}");
            return EXIT_NOT_STARTED;
        }
    };
    // From here on everything leaves through this guard.
    let mut cleanup = Cleanup { dir, proxy: None };
    on_term_and_int(forward_stop);

    let info = cleanup.dir.join("flatpak-info");
    if let Err(e) = fs::write(&info, flatpak_info(&args.app_id, std::process::id())) {
        eprintln!("fs-sandbox: cannot write {}: {e}", info.display());
        return EXIT_NOT_STARTED;
    }

    // --- THE BUS THROUGH A FILTER ---
    let socket = cleanup.dir.join("bus");
    let (proxy, bus_proxy) = start_bus_proxy(&args.tools.dbus_proxy, &socket, &runtime);
    cleanup.proxy = proxy;

    if ASKED_TO_STOP.load(Ordering::SeqCst) {
        // Signalled while the proxy was coming up: do not start a sandbox that
        // is only going to be torn down.
        return 128 + libc::SIGTERM as u8;
    }

    // --- SECCOMP ---
    let program = seccomp_program();
    let seccomp_fd = program.as_ref().map(|_| SECCOMP_FD);

    // --- X11 ---
    // The host's X socket is never passed in. With the permission the sandbox
    // gets a satellite of ITS OWN instead, on the already restricted Wayland
    // socket, so X is no way around the security context either. The satellite
    // has to run INSIDE the sandbox: its socket lives in /tmp, and /tmp in there
    // is a fresh tmpfs the host cannot see into.
    let mut cmd = args.cmd.clone();
    let mut display = None;
    if perms.x11 {
        match std::env::current_exe() {
            Ok(exe) => {
                let seed = u64::from(std::process::id())
                    ^ u64::from(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| d.subsec_nanos()),
                    );
                let chosen = pick_display(seed);
                let mut wrapped: Vec<OsString> = vec![
                    exe.into_os_string(),
                    OsString::from("fs-sandbox-x11"),
                    OsString::from("--xwayland"),
                    args.tools.xwayland.as_os_str().to_owned(),
                    OsString::from(&chosen),
                    OsString::from("--"),
                ];
                wrapped.extend(cmd);
                cmd = wrapped;
                display = Some(chosen);
            }
            Err(e) => eprintln!(
                "fs-sandbox: cannot find my own path ({e}) — starting without an X server"
            ),
        }
    }

    let layout = Layout {
        app_id: args.app_id.clone(),
        home: home.clone(),
        runtime: runtime.clone(),
        perms,
        sandbox_home,
        mimeapps: home.join(MIMEAPPS).is_file().then(|| home.join(MIMEAPPS)),
        dev_nodes: dev_nodes(Path::new("/dev")),
        // An absolute WAYLAND_DISPLAY is legal (libwayland accepts one) and is
        // then bound at its own path; the shell glued it onto the runtime
        // directory and silently lost it.
        wayland: std::env::var_os("WAYLAND_DISPLAY")
            .filter(|d| !d.is_empty())
            .and_then(|d| socket_at(runtime.join(d))),
        pipewire: socket_at(runtime.join("pipewire-0")),
        pulse: socket_at(runtime.join("pulse/native")),
        bus_proxy,
        flatpak_info: info,
        display,
        seccomp_fd,
    };

    let mut command = Command::new(&args.tools.bwrap);
    command.args(bwrap_args(&layout, &cmd));
    if let Some(file) = &program {
        let raw = file.as_raw_fd();
        // SAFETY: the closure runs between fork and exec in the child. It calls
        // only dup2/fcntl, both async-signal-safe, and touches no allocator.
        unsafe {
            command.pre_exec(move || {
                if raw == SECCOMP_FD {
                    // dup2 onto itself is a no-op and would NOT clear
                    // FD_CLOEXEC, so the descriptor would be gone by the time
                    // bwrap looked at it.
                    if libc::fcntl(raw, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else if libc::dup2(raw, SECCOMP_FD) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    // NOT exec: the bus proxy has to be killed after the program exits, and
    // after an exec there would be nobody left to do it.
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "fs-sandbox: cannot start {} ({e})",
                args.tools.bwrap.display()
            );
            return EXIT_NOT_STARTED;
        }
    };
    BWRAP_PID.store(child.id() as i32, Ordering::SeqCst);
    // Our copy of the program is not needed any more: the child has fd 34.
    drop(program);

    let status = match child.wait() {
        Ok(status) => status,
        Err(e) => {
            eprintln!("fs-sandbox: cannot wait for the sandbox: {e}");
            return 1;
        }
    };
    BWRAP_PID.store(0, Ordering::SeqCst);
    // `cleanup` goes out of scope here: proxy killed, scratch directory gone.
    exit_code_of(status.into_raw())
}

// --- THE IN-SANDBOX X11 LAUNCHER ---------------------------------------------

/// What `fs-sandbox-x11` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X11Args {
    pub xwayland: PathBuf,
    pub display: String,
    pub cmd: Vec<OsString>,
}

impl X11Args {
    /// Parse `[--xwayland P] <:display> -- cmd...`.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let split = argv
            .iter()
            .position(|a| a == "--")
            .ok_or(ArgError::NoSeparator)?;
        let cmd = argv[split + 1..].to_vec();
        if cmd.is_empty() {
            return Err(ArgError::EmptyCommand);
        }
        let mut xwayland = Tools::default().xwayland;
        let mut display: Option<String> = None;
        let mut rest = argv[..split].iter();
        while let Some(arg) = rest.next() {
            if arg.as_bytes().starts_with(b"--") {
                let flag = arg.to_string_lossy().into_owned();
                let value = rest
                    .next()
                    .ok_or_else(|| ArgError::MissingValue(flag.clone()))?;
                match flag.as_str() {
                    "--xwayland" => xwayland = PathBuf::from(value),
                    _ => return Err(ArgError::UnknownFlag(flag)),
                }
                continue;
            }
            if display.is_some() {
                return Err(ArgError::ExtraArguments);
            }
            display = Some(arg.to_string_lossy().into_owned());
        }
        let display = display
            .filter(|d| !d.is_empty())
            .ok_or(ArgError::MissingDisplay)?;
        Ok(Self {
            xwayland,
            display,
            cmd,
        })
    }
}

/// Start the sandbox's own X server, then become the program.
///
/// Runs INSIDE the sandbox, started by [`run`] as the first element of the bwrap
/// command line. It exists because the satellite's socket has to appear in the
/// sandbox's `/tmp`, which is a tmpfs nobody outside can write to — the shell
/// version did the same thing with an inline `bash -c`, and this is that script
/// without a shell in the sandbox.
///
/// Nothing kills the satellite here, and nothing has to: `--unshare-pid` makes
/// bwrap pid 1 of a namespace of its own, and when the program (its only child
/// that matters) exits, the kernel takes the whole namespace down with it.
pub fn run_x11(args: X11Args) -> u8 {
    match Command::new(&args.xwayland)
        .arg(&args.display)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(_) => {
            // A second for the server to come up. Without it the program starts
            // before the socket exists and dies with "cannot open display".
            std::thread::sleep(X11_SETTLE);
        }
        Err(e) => eprintln!(
            "fs-sandbox: cannot start {} ({e}) — the program gets no X server",
            args.xwayland.display()
        ),
    }
    let e = crate::profile::exec_command(&args.cmd);
    eprintln!(
        "fs-sandbox: cannot start {}: {e}",
        args.cmd[0].to_string_lossy()
    );
    EXIT_NOT_STARTED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn strs(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    // --- ARGUMENTS ---

    #[test]
    fn the_shape_nix_generates_is_parsed() {
        let a = Args::parse(&argv(&[
            "--bwrap",
            "/store/bwrap",
            "--dbus-proxy",
            "/store/xdg-dbus-proxy",
            "--kdialog",
            "/store/kdialog",
            "--xwayland",
            "/store/xwayland-satellite",
            "discord",
            "--name",
            "work",
            "--",
            "discord",
            "--start-minimized",
        ]))
        .unwrap();
        assert_eq!(a.app_id, "discord");
        assert_eq!(a.sandbox.as_deref(), Some("work"));
        assert_eq!(a.tools.bwrap, PathBuf::from("/store/bwrap"));
        assert_eq!(a.tools.xwayland, PathBuf::from("/store/xwayland-satellite"));
        assert_eq!(a.cmd, argv(&["discord", "--start-minimized"]));
    }

    #[test]
    fn without_a_name_the_home_is_a_throwaway_one() {
        let a = Args::parse(&argv(&["--bwrap", "/b", "app", "--", "prog"])).unwrap();
        assert_eq!(a.sandbox, None);
        // Tools that were not given are looked up on PATH.
        assert_eq!(a.tools.kdialog, PathBuf::from("kdialog"));
    }

    #[test]
    fn only_the_first_separator_splits() {
        let a = Args::parse(&argv(&["app", "--", "sh", "-c", "echo -- hi"])).unwrap();
        assert_eq!(a.cmd, argv(&["sh", "-c", "echo -- hi"]));
    }

    #[test]
    fn an_empty_name_is_no_named_sandbox() {
        // A launcher that lost the value must not create a directory called "".
        let a = Args::parse(&argv(&["app", "--name", "", "--", "prog"])).unwrap();
        assert_eq!(a.sandbox, None);
    }

    #[test]
    fn a_label_is_kept_and_an_empty_one_is_none() {
        // The label only feeds the dialogs; the permission KEY stays the id.
        let a = Args::parse(&argv(&["app", "--label", "Телеграм", "--", "prog"])).unwrap();
        assert_eq!(a.app_id, "app");
        assert_eq!(a.label.as_deref(), Some("Телеграм"));
        let a = Args::parse(&argv(&["app", "--label", "", "--", "prog"])).unwrap();
        assert_eq!(a.label, None);
    }

    #[test]
    fn broken_command_lines_are_rejected() {
        assert_eq!(
            Args::parse(&argv(&["app", "prog"])),
            Err(ArgError::NoSeparator)
        );
        assert_eq!(
            Args::parse(&argv(&["app", "--"])),
            Err(ArgError::EmptyCommand)
        );
        assert_eq!(
            Args::parse(&argv(&["--", "prog"])),
            Err(ArgError::MissingAppId)
        );
        assert_eq!(
            Args::parse(&argv(&["", "--", "prog"])),
            Err(ArgError::MissingAppId)
        );
        assert_eq!(
            Args::parse(&argv(&["app", "other", "--", "prog"])),
            Err(ArgError::ExtraArguments)
        );
        assert_eq!(
            Args::parse(&argv(&["app", "--frob", "x", "--", "prog"])),
            Err(ArgError::UnknownFlag("--frob".to_string()))
        );
    }

    #[test]
    fn a_flag_at_the_end_of_the_positionals_is_missing_its_value() {
        // `--` ends the positionals, so the flag before it never got a value.
        // Saying so beats swallowing the separator and starting the wrong
        // program, which is what a shell `shift` would have done.
        assert_eq!(
            Args::parse(&argv(&["app", "--name", "--", "prog"])),
            Err(ArgError::MissingValue("--name".to_string()))
        );
        assert_eq!(
            Args::parse(&argv(&["app", "--bwrap", "--", "prog"])),
            Err(ArgError::MissingValue("--bwrap".to_string()))
        );
        assert_eq!(
            Args::parse(&argv(&["--kdialog"])),
            Err(ArgError::NoSeparator)
        );
    }

    // --- PERMISSIONS ---

    #[test]
    fn the_current_file_format_is_one_token_per_line() {
        let p = Perms::parse("downloads\nx11\n");
        assert_eq!(
            p,
            Perms {
                downloads: true,
                x11: true,
                ..Perms::default()
            }
        );
    }

    #[test]
    fn old_permission_files_still_work() {
        // Written before `--separate-output`: space separated and quoted.
        let old = Perms::parse("\"downloads\" \"home\"\n");
        assert!(old.downloads && old.home);
        assert!(!old.pictures && !old.x11 && !old.documents);
        // And the shape a shell `$(…)` left behind: no trailing newline.
        assert!(Perms::parse("pictures").pictures);
    }

    #[test]
    fn an_empty_or_missing_file_allows_nothing() {
        assert_eq!(Perms::parse(""), Perms::default());
        assert_eq!(Perms::parse("\n"), Perms::default());
        assert_eq!(Perms::parse("   \n\n"), Perms::default());
    }

    #[test]
    fn no_token_is_hidden_inside_another() {
        // The substring matching inherited from the shell is only safe as long
        // as this holds; a new token would have to be checked against it.
        for (i, a) in PERM_TOKENS.iter().enumerate() {
            for (j, b) in PERM_TOKENS.iter().enumerate() {
                assert!(i == j || !a.contains(b), "{a} contains {b}");
            }
        }
    }

    #[test]
    fn rendering_round_trips_and_an_empty_set_is_an_empty_file() {
        let all = Perms {
            downloads: true,
            documents: true,
            pictures: true,
            x11: true,
            home: true,
        };
        assert_eq!(all.render(), "downloads\ndocuments\npictures\nx11\nhome\n");
        assert_eq!(Perms::parse(&all.render()), all);
        assert_eq!(Perms::default().render(), "");
        let some = Perms {
            pictures: true,
            ..Perms::default()
        };
        assert_eq!(some.render(), "pictures\n");
        assert_eq!(Perms::parse(&some.render()), some);
    }

    // --- THE ARGUMENT LIST ---

    fn layout() -> Layout {
        Layout {
            app_id: "discord".to_string(),
            home: PathBuf::from("/home/u"),
            runtime: PathBuf::from("/run/user/1000"),
            perms: Perms::default(),
            sandbox_home: None,
            mimeapps: None,
            dev_nodes: Vec::new(),
            wayland: None,
            pipewire: None,
            pulse: None,
            bus_proxy: None,
            flatpak_info: PathBuf::from("/tmp/sb/flatpak-info"),
            display: None,
            seccomp_fd: None,
        }
    }

    /// The part of the list that never changes, up to the home.
    const PREFIX: [&str; 21] = [
        "--ro-bind",
        "/nix/store",
        "/nix/store",
        "--ro-bind-try",
        "/run/current-system",
        "/run/current-system",
        "--ro-bind-try",
        "/run/opengl-driver",
        "/run/opengl-driver",
        "--ro-bind-try",
        "/run/opengl-driver-32",
        "/run/opengl-driver-32",
        "--ro-bind",
        "/etc",
        "/etc",
        "--ro-bind-try",
        "/sys",
        "/sys",
        "--ro-bind-try",
        "/run/systemd/resolve",
        "/run/systemd/resolve",
    ];

    #[test]
    fn the_default_sandbox_shows_nothing_of_the_home() {
        let args = bwrap_args(&layout(), &argv(&["prog"]));
        let got = strs(&args);
        assert_eq!(got[..PREFIX.len()], PREFIX);
        let rest: Vec<&str> = got[PREFIX.len()..].iter().map(String::as_str).collect();
        assert_eq!(
            rest,
            [
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                // The home is a tmpfs and nothing pokes through it.
                "--tmpfs",
                "/home/u",
                "--tmpfs",
                "/run/user/1000",
                "--ro-bind",
                "/tmp/sb/flatpak-info",
                "/.flatpak-info",
                "--setenv",
                "HOME",
                "/home/u",
                "--setenv",
                "XDG_RUNTIME_DIR",
                "/run/user/1000",
                "--setenv",
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/run/user/1000/bus",
                "--setenv",
                "FLATPAK_ID",
                "discord",
                "--setenv",
                "ELECTRON_OZONE_PLATFORM_HINT",
                "auto",
                "--setenv",
                "NIXOS_OZONE_WL",
                "1",
                "--unsetenv",
                "DBUS_SYSTEM_BUS_ADDRESS",
                "--unsetenv",
                "DISPLAY",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--unshare-cgroup-try",
                "--die-with-parent",
                "--",
                "prog",
            ]
        );
    }

    #[test]
    fn the_home_permission_replaces_the_tmpfs_with_the_real_home() {
        let mut l = layout();
        l.perms.home = true;
        // The three directory permissions are meaningless next to it and must
        // not be added a second time.
        l.perms.downloads = true;
        l.perms.pictures = true;
        let got = strs(&bwrap_args(&l, &argv(&["prog"])));
        // Right after `--tmpfs /tmp`, where the home block lives.
        let start = got.iter().position(|a| a == "/tmp").unwrap();
        assert_eq!(
            got[start..start + 4],
            ["/tmp", "--bind", "/home/u", "/home/u"]
        );
        // Nothing is bound a second time, and the home is NOT a tmpfs: the only
        // two tmpfs left are /tmp and the runtime directory.
        assert!(!got.iter().any(|a| a == "/home/u/Downloads"));
        assert_eq!(got.iter().filter(|a| *a == "--tmpfs").count(), 2);
    }

    #[test]
    fn directory_permissions_poke_through_the_tmpfs_in_dialog_order() {
        let mut l = layout();
        l.perms.downloads = true;
        l.perms.documents = true;
        l.perms.pictures = true;
        let got = strs(&bwrap_args(&l, &argv(&["prog"])));
        let start = got.iter().position(|a| a == "/home/u").unwrap() - 1;
        let slice: Vec<&str> = got[start..start + 11].iter().map(String::as_str).collect();
        assert_eq!(
            slice,
            [
                // The tmpfs comes FIRST; a bind listed before it would be
                // covered up and the permission would silently do nothing.
                "--tmpfs",
                "/home/u",
                "--bind",
                "/home/u/Downloads",
                "/home/u/Downloads",
                "--bind",
                "/home/u/Documents",
                "/home/u/Documents",
                "--bind",
                "/home/u/Pictures",
                "/home/u/Pictures",
            ]
        );
    }

    #[test]
    fn a_named_sandbox_gets_its_own_persistent_home() {
        let mut l = layout();
        l.sandbox_home = Some(PathBuf::from(
            "/home/u/.local/state/vpn-sandboxes/work/home",
        ));
        let got = strs(&bwrap_args(&l, &argv(&["prog"])));
        let start = got.iter().position(|a| a == "--bind").unwrap();
        assert_eq!(
            got[start..start + 3],
            [
                "--bind",
                "/home/u/.local/state/vpn-sandboxes/work/home",
                "/home/u"
            ]
        );
        // The home is a bind of the sandbox's own directory, not a tmpfs: the
        // only two tmpfs left are /tmp and the runtime directory.
        assert_eq!(got.iter().filter(|a| *a == "--tmpfs").count(), 2);
    }

    #[test]
    fn the_sockets_come_after_the_runtime_tmpfs_and_only_when_they_exist() {
        let mut l = layout();
        l.wayland = Some(PathBuf::from("/run/user/1000/wl-sandbox-42"));
        l.pulse = Some(PathBuf::from("/run/user/1000/pulse/native"));
        l.bus_proxy = Some(PathBuf::from("/tmp/sb/bus"));
        let got = strs(&bwrap_args(&l, &argv(&["prog"])));
        let start = got.iter().position(|a| a == "/run/user/1000").unwrap() - 1;
        let slice: Vec<&str> = got[start..start + 11].iter().map(String::as_str).collect();
        assert_eq!(
            slice,
            [
                "--tmpfs",
                "/run/user/1000",
                "--ro-bind",
                "/run/user/1000/wl-sandbox-42",
                "/run/user/1000/wl-sandbox-42",
                // pipewire is absent here and simply does not appear.
                "--ro-bind",
                "/run/user/1000/pulse/native",
                "/run/user/1000/pulse/native",
                "--bind",
                "/tmp/sb/bus",
                "/run/user/1000/bus",
            ]
        );
    }

    #[test]
    fn a_dead_dbus_proxy_costs_the_bus_and_not_the_program() {
        // The regression this port fixes: the shell bound the socket
        // unconditionally, bwrap failed with "Can't find source path" and the
        // program never started.
        let l = layout();
        let got = strs(&bwrap_args(&l, &argv(&["prog"])));
        assert!(
            !got.iter().any(|a| a == "/run/user/1000/bus"),
            "a missing proxy must not be bound anywhere: {got:?}"
        );
        // …but the address still points into the runtime tmpfs, never at the
        // real session bus.
        let i = got
            .iter()
            .position(|a| a == "DBUS_SESSION_BUS_ADDRESS")
            .unwrap();
        assert_eq!(got[i + 1], "unix:path=/run/user/1000/bus");
    }

    #[test]
    fn the_gpu_nodes_are_dev_bind_try_right_after_dev() {
        let mut l = layout();
        l.dev_nodes = vec![
            PathBuf::from("/dev/dri"),
            PathBuf::from("/dev/nvidia0"),
            PathBuf::from("/dev/nvidiactl"),
        ];
        let got = strs(&bwrap_args(&l, &argv(&["prog"])));
        let start = got.iter().position(|a| a == "--dev").unwrap();
        let slice: Vec<&str> = got[start..start + 11].iter().map(String::as_str).collect();
        assert_eq!(
            slice,
            [
                "--dev",
                "/dev",
                "--dev-bind-try",
                "/dev/dri",
                "/dev/dri",
                "--dev-bind-try",
                "/dev/nvidia0",
                "/dev/nvidia0",
                "--dev-bind-try",
                "/dev/nvidiactl",
                "/dev/nvidiactl",
            ]
        );
    }

    #[test]
    fn mimeapps_is_read_only_and_lands_after_the_home() {
        let mut l = layout();
        l.mimeapps = Some(PathBuf::from("/home/u/.config/mimeapps.list"));
        let got = strs(&bwrap_args(&l, &argv(&["prog"])));
        let home = got.iter().position(|a| a == "--tmpfs").unwrap();
        let mime = got
            .iter()
            .position(|a| a == "/home/u/.config/mimeapps.list")
            .unwrap();
        assert!(mime > home, "the tmpfs would cover the file up");
        assert_eq!(got[mime - 1], "--ro-bind");
    }

    #[test]
    fn the_x11_permission_sets_display_and_the_filter_gets_a_number() {
        let mut l = layout();
        l.display = Some(":123".to_string());
        l.seccomp_fd = Some(34);
        let got = strs(&bwrap_args(&l, &argv(&["prog"])));
        let i = got.iter().position(|a| a == "DISPLAY").unwrap();
        assert_eq!(got[i - 1], "--setenv");
        assert_eq!(got[i + 1], ":123");
        let s = got.iter().position(|a| a == "--seccomp").unwrap();
        assert_eq!(got[s + 1], "34");
        // The filter must be in place before the namespaces are unshared, i.e.
        // before the trailing block bwrap applies last.
        assert!(s < got.iter().position(|a| a == "--unshare-pid").unwrap());
    }

    #[test]
    fn the_command_is_last_and_separated() {
        let got = strs(&bwrap_args(&layout(), &argv(&["sh", "-c", "echo -- hi"])));
        assert_eq!(got[got.len() - 4..], ["--", "sh", "-c", "echo -- hi"]);
    }

    // --- THE REST ---

    #[test]
    fn flatpak_info_says_what_toolkits_look_for() {
        let text = flatpak_info("discord", 4242);
        assert_eq!(
            text,
            "[Application]\nname=discord\n\n[Instance]\ninstance-id=4242\n\
             session-bus-proxy=true\nsystem-bus-proxy=false\n"
        );
        // The two things a toolkit actually reads.
        assert!(text.starts_with("[Application]\n"));
        assert!(text.contains("\nname=discord\n"));
    }

    #[test]
    fn display_numbers_stay_in_the_documented_range() {
        for seed in [0u64, 1, 399, 400, 12_345, u64::MAX] {
            let d = pick_display(seed);
            let n: u64 = d.strip_prefix(':').unwrap().parse().unwrap();
            assert!((100..500).contains(&n), "{d} is out of :100…:499");
        }
        assert_eq!(pick_display(0), ":100");
        assert_eq!(pick_display(399), ":499");
        assert_eq!(pick_display(400), ":100");
    }

    #[test]
    fn dev_nodes_are_dri_first_then_every_nvidia_node() {
        let dir = std::env::temp_dir().join(format!("vpn-zone-dev-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("dri")).unwrap();
        for name in ["nvidiactl", "nvidia0", "nvidia-modeset", "null", "shm"] {
            fs::write(dir.join(name), "").unwrap();
        }
        let got: Vec<String> = dev_nodes(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            got,
            ["dri", "nvidia-modeset", "nvidia0", "nvidiactl"],
            "dri first, then the nvidia nodes in a stable order"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_machine_without_a_gpu_gets_no_dev_binds() {
        let dir = std::env::temp_dir().join(format!("vpn-zone-nodev-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("null"), "").unwrap();
        assert!(dev_nodes(&dir).is_empty());
        assert!(dev_nodes(Path::new("/nonexistent/vpn-zone/dev")).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_x11_launcher_takes_the_display_and_the_command() {
        let a = X11Args::parse(&argv(&[
            "--xwayland",
            "/store/xwayland-satellite",
            ":123",
            "--",
            "wine",
            "notepad",
        ]))
        .unwrap();
        assert_eq!(a.xwayland, PathBuf::from("/store/xwayland-satellite"));
        assert_eq!(a.display, ":123");
        assert_eq!(a.cmd, argv(&["wine", "notepad"]));

        assert_eq!(
            X11Args::parse(&argv(&[":1", "wine"])),
            Err(ArgError::NoSeparator)
        );
        assert_eq!(
            X11Args::parse(&argv(&["--", "wine"])),
            Err(ArgError::MissingDisplay)
        );
        assert_eq!(
            X11Args::parse(&argv(&[":1", ":2", "--", "wine"])),
            Err(ArgError::ExtraArguments)
        );
    }
}
