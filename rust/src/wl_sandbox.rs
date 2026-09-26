//! `wl-sandbox` — run a program with RESTRICTED access to Wayland.
//!
//! **Why.** The compositor hands any client the protocols it needs to grab the
//! screen (wlr-screencopy), read the clipboard in the background
//! (data-control), type and move the pointer on the user's behalf
//! (virtual-keyboard, virtual-pointer) and see everybody else's windows
//! (foreign-toplevel). None of them asks for permission: the protocol has no
//! notion of a "trusted client", and they exist for perfectly good reasons —
//! screenshot tools, clipboard managers, automation.
//!
//! Telling clients apart is what `wp_security_context_v1` is for. The client
//! creates a SEPARATE unix socket, marks it as a sandbox and hands it to the
//! compositor. Everybody who connects through that socket counts as
//! restricted. niri (see `client_is_unrestricted` in its sources) and KWin do
//! not advertise those protocols to them at all — the program is not "refused",
//! it simply does not see them (measured: 47 protocols against 33).
//!
//! What the program KEEPS: its own windows, input into them, the clipboard
//! while focused (ordinary Ctrl+C/Ctrl+V), the GPU, sound. Only the spying is
//! taken away.
//!
//! **If the protocol is not there** (an older compositor, an X11 session) the
//! program is started as usual. Weakening the protection silently would be
//! wrong, so every such path prints a warning to stderr first — that is what
//! [`run_plain`] is, the shared "it did not work out" exit of this module.
//!
//! Usage: `vpn-zone-core wl-sandbox <app-id> [--zone <zone>] [--no-proxy]
//! [--frame <rrggbb>:<width>:<always|hover|off> --frame-title <text>
//! --frame-switch <settings dir>] -- <command> [args…]`.
//!
//! **Where it runs.** On the host, before the launch enters its zone
//! (`docs/LEAK-MODEL.md` §13): a zone does not have the compositor's own
//! socket at all — that one hands out the screen, the clipboard and a virtual
//! keyboard — so the restricted socket has to be made outside and handed in.
//! It is created in `$XDG_RUNTIME_DIR/vpn-zones/wayland/<zone>/`, the one
//! directory of this kind the zone's holder binds into that zone (and only
//! into that one: a program of another zone cannot replace the socket), and
//! `WAYLAND_DISPLAY` becomes that path relative to the runtime directory.
//!
//! **Who listens there.** A proxy of ours ([`crate::wl_proxy`], a confined
//! process of its own): the compositor listens on a socket in a private
//! directory outside every zone, and the proxy passes each connection of the
//! program on to it — the same globals minus the hidden ones, nothing added.
//! It is the base the window frame is built on (`docs/WINDOW-FRAME.md` §8),
//! and with `--frame` it draws the zone's border around the program's
//! windows (`crate::wl_frame`); `--frame-switch` names the directory whose
//! `frames` setting hides it, read for every connection (`crate::frame`).
//! When the proxy cannot start, the compositor listens on the zone's path
//! itself, as it did before there was a proxy (with a warning), and when that
//! cannot be registered either the program is not started at all — never
//! unrestricted once the compositor has shown it speaks the protocol;
//! `--no-proxy` asks for the compositor on the zone's path from the start.
//! The program is never given more than the restricted socket either way: a
//! proxy that dies takes its display along.
//!
//! This was a C program (`module/wl-sandbox.c`) until it moved here; there is
//! no C in this project any more. Two things changed with the move:
//!
//! * the command must now be separated by `--`, the same shape `profile-run`
//!   uses. The C version took `wl-sandbox <app-id> <command…>` with no
//!   separator;
//! * a child killed by a signal is reported as `128 + signal` instead of a flat
//!   `1` — see [`crate::profile::exit_code_of`].
//!
//! No libwayland is linked in: `wayland-client` speaks the wire protocol from
//! Rust unless `wayland-backend/client_system` is enabled, and it is not. The
//! derivation therefore needs no Wayland `buildInputs`.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::wl_registry;
use wayland_client::{delegate_noop, Connection, Dispatch, EventQueue, QueueHandle};
use wayland_protocols::wp::security_context::v1::client::{
    wp_security_context_manager_v1::WpSecurityContextManagerV1,
    wp_security_context_v1::WpSecurityContextV1,
};

use crate::profile::{exec_command, exit_code_of, EXIT_NOT_STARTED};
use crate::sys;
use crate::wl_proxy;

/// Sandbox engine name reported to the compositor. It is what a compositor
/// shows when it names the sandbox a window came from, so it names the project,
/// not the program.
const SANDBOX_ENGINE: &str = "vpn-zone";

/// Below the runtime directory: one directory per zone for the restricted
/// sockets of its launches.
pub const SOCKET_DIR: &str = "vpn-zones/wayland";
/// The directory for launches that enter no zone.
pub const NO_ZONE: &str = "unconfined";

/// The descriptor a launch may carry for whoever wants to hear of the
/// program's first window (`crate::picker`'s hand-over): its number, in this
/// variable, and [`OPENED_FD`] is the one the picker uses.
pub const ENV_OPENED_FD: &str = "CELLWARD_WINDOW_FD";
pub const OPENED_FD: RawFd = 9;

/// The words on the picker's pipe: the program opened a window
/// ([`crate::wl_proxy::window_opened`]), or no word will come — nothing on
/// the way to say it. The end of the pipe with neither is the launch's end.
pub const WORD_OPENED: u8 = b'w';
pub const WORD_NONE: u8 = b'n';

/// The pipe of [`ENV_OPENED_FD`], once taken ([`take_opened`]).
static OPENED: std::sync::Mutex<Option<OwnedFd>> = std::sync::Mutex::new(None);

/// Take the pipe of [`ENV_OPENED_FD`]: the variable gone, the descriptor
/// close-on-exec — the program never inherits it — and kept here, for this
/// process's life: the proxy gets a copy ([`opened_for_proxy`]) and says the
/// word; this one says that none will come ([`no_word`]) — without a proxy
/// that can, or when the proxy dies before it spoke. Only a pipe: a number
/// that names anything else is left alone.
pub fn take_opened() {
    if let Some(fd) = pipe_of_env() {
        *OPENED.lock().unwrap_or_else(|e| e.into_inner()) = Some(fd);
    }
}

/// The pipe put here as [`take_opened`] would (a test's).
#[cfg(test)]
pub(crate) fn put_opened(fd: OwnedFd) {
    *OPENED.lock().unwrap_or_else(|e| e.into_inner()) = Some(fd);
}

/// The pipe gone as with this process, without a word (a test's).
#[cfg(test)]
pub(crate) fn drop_opened() {
    OPENED.lock().unwrap_or_else(|e| e.into_inner()).take();
}

/// A copy of the pipe for the proxy, which says the word itself.
pub(crate) fn opened_for_proxy() -> Option<OwnedFd> {
    OPENED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|fd| fd.try_clone().ok())
}

/// Given on to the next program of the launch — `wl-sandbox`, which takes
/// it again ([`take_opened`]): close-on-exec off, [`ENV_OPENED_FD`] set to
/// its number, and no longer ours to speak on (`crate::launch`).
pub fn pass_opened_on() {
    if let Some(fd) = OPENED.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let fd = std::os::fd::IntoRawFd::into_raw_fd(fd);
        // SAFETY: our own descriptor; FD_CLOEXEC cleared.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } == 0 {
            std::env::set_var(ENV_OPENED_FD, fd.to_string());
        }
    }
}

/// Nothing on the way will say the word: said so ([`WORD_NONE`]) — the
/// picker leaves, and learns nothing — and the pipe gone.
pub fn no_word() {
    if let Some(fd) = OPENED.lock().unwrap_or_else(|e| e.into_inner()).take() {
        // SAFETY: our own descriptor, one byte from a constant.
        unsafe {
            libc::write(
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                [WORD_NONE].as_ptr().cast(),
                1,
            )
        };
    }
}

fn pipe_of_env() -> Option<OwnedFd> {
    let value = std::env::var(ENV_OPENED_FD).ok();
    std::env::remove_var(ENV_OPENED_FD);
    let fd: RawFd = value?.trim().parse().ok().filter(|fd| *fd > 2)?;
    // SAFETY: an all-zero stat is a valid one to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a descriptor number and a stat to fill; failing says it is not ours.
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return None;
    }
    // SAFETY: as above; FD_CLOEXEC on a descriptor of ours.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return None;
    }
    // SAFETY: the pipe the launch was given for this, and nobody else's here.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// What `wl-sandbox` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Identifier the compositor gets as the sandboxed application's app-id.
    /// The bash side has already reduced it to one word of
    /// `[A-Za-z0-9_.-]` — a space used to split the argument in two and the
    /// wrong program was started (`docs/GOTCHAS.md` §7).
    pub app_id: String,
    /// The zone the launch goes into, which names the socket's directory.
    pub zone: String,
    /// Put [`crate::wl_proxy`] between the program and the compositor. Off
    /// (`--no-proxy`): the compositor listens on the zone's path itself — for
    /// a program the proxy breaks, and for the test that compares the two.
    pub proxy: bool,
    /// The zone's frame the proxy draws (`--frame <rrggbb>:<width>:<title
    /// mode>`), the title strip's text (`--frame-title`, cleaned again here:
    /// no control or bidi characters, bounded) and the settings directory
    /// with the switch that hides it (`--frame-switch`; without one, nothing
    /// hides it).
    pub frame: Option<crate::frame::Setup>,
    /// The program and its arguments.
    pub cmd: Vec<OsString>,
}

/// Everything that can be wrong with the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgError {
    /// No `--` separator, so where the command starts is anybody's guess.
    NoSeparator,
    /// No app-id, or an empty one.
    MissingAppId,
    /// `--` was there, but nothing followed it.
    EmptyCommand,
    /// More than one positional argument before `--`. Almost always the old
    /// separator-less call shape, which would otherwise start the wrong
    /// program.
    TooManyArguments,
    /// `--zone` without a name, or with one that is not a single path
    /// component.
    BadZone,
    /// `--frame` without `<rrggbb>:<width>[:<mode>]`, `--frame-title`
    /// without a text, or `--frame-switch` without a directory.
    BadFrame,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSeparator => write!(f, "no `--` before the command"),
            Self::MissingAppId => write!(f, "need a non-empty <app-id>"),
            Self::EmptyCommand => write!(f, "nothing to run after `--`"),
            Self::TooManyArguments => write!(f, "only <app-id> may precede `--`"),
            Self::BadZone => write!(f, "--zone needs a zone name"),
            Self::BadFrame => write!(
                f,
                "--frame needs <rrggbb>:<width>[:always|hover|off], --frame-title a text, \
                 --frame-switch a directory"
            ),
        }
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parse `<app-id> [--zone <zone>] [--no-proxy] [--frame
    /// <rrggbb>:<w>[:<mode>]] [--frame-title <text>] [--frame-switch <dir>]
    /// -- cmd...`.
    ///
    /// The command keeps its `OsString`s: an argument can be a file name handed
    /// over by the launcher through a `%U` field code, and those are bytes, not
    /// necessarily UTF-8. The app-id, on the other hand, goes into a Wayland
    /// string argument, so it is converted lossily rather than refused — an odd
    /// byte in a program name must not cost the user the sandbox.
    pub fn parse(argv: &[OsString]) -> Result<Self, ArgError> {
        let split = argv
            .iter()
            .position(|a| a == "--")
            .ok_or(ArgError::NoSeparator)?;
        let cmd = argv[split + 1..].to_vec();
        if cmd.is_empty() {
            return Err(ArgError::EmptyCommand);
        }
        let mut positional = Vec::new();
        let mut zone = NO_ZONE.to_owned();
        let mut proxy = true;
        let mut frame = None;
        let mut title = String::new();
        let mut switch = None;
        let mut words = argv[..split].iter();
        while let Some(word) = words.next() {
            if word == "--no-proxy" {
                proxy = false;
            } else if word == "--frame" {
                let value = words.next().ok_or(ArgError::BadFrame)?.to_string_lossy();
                frame = Some(crate::frame::Frame::parse_arg(&value).ok_or(ArgError::BadFrame)?);
            } else if word == "--frame-title" {
                let text = words.next().ok_or(ArgError::BadFrame)?.to_string_lossy();
                title = crate::frame::clean_title(&text);
            } else if word == "--frame-switch" {
                let dir = words
                    .next()
                    .filter(|d| !d.is_empty())
                    .ok_or(ArgError::BadFrame)?;
                switch = Some(PathBuf::from(dir));
            } else if word == "--zone" {
                let name = words.next().ok_or(ArgError::BadZone)?.to_string_lossy();
                if !valid_zone_dir(&name) {
                    return Err(ArgError::BadZone);
                }
                zone = name.into_owned();
            } else {
                positional.push(word);
            }
        }
        if positional.len() > 1 {
            return Err(ArgError::TooManyArguments);
        }
        let app_id = positional.first().ok_or(ArgError::MissingAppId)?;
        if app_id.is_empty() {
            return Err(ArgError::MissingAppId);
        }
        // Without a switch nothing can hide the border: an empty path is a
        // directory with no settings in it.
        let frame = frame.map(|frame| crate::frame::Setup {
            frame,
            title,
            switch: switch.unwrap_or_default(),
        });
        Ok(Self {
            app_id: app_id.to_string_lossy().into_owned(),
            zone,
            proxy,
            frame,
            cmd,
        })
    }
}

/// A zone name that can be a directory: one component, nothing to climb with.
pub fn valid_zone_dir(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// Name of the socket this run registers with the compositor.
///
/// Unique by pid: two runs of the same program must not fight over one path.
pub fn socket_name(pid: u32) -> String {
    format!("wl-sandbox-{pid}")
}

/// The socket's path relative to the runtime directory — what
/// `WAYLAND_DISPLAY` is set to (libwayland joins a relative one onto
/// `XDG_RUNTIME_DIR`, slashes included).
pub fn socket_display(zone: &str, pid: u32) -> String {
    format!("{SOCKET_DIR}/{zone}/{}", socket_name(pid))
}

/// Run without restrictions — the shared path for everything that did not work
/// out.
///
/// `execvp`, so the program replaces this process, exactly as the C version
/// did: there is nothing left to supervise or clean up, and the caller gets the
/// program's own exit status without a middleman.
fn run_plain(cmd: &[OsString]) -> u8 {
    no_word();
    let e = exec_command(cmd);
    eprintln!("wl-sandbox: cannot start {}: {e}", cmd[0].to_string_lossy());
    EXIT_NOT_STARTED
}

/// Dispatch state of the Wayland connection.
///
/// Deliberately empty: the two security-context interfaces have no events at
/// all, and the registry is only ever read through [`GlobalListContents`], so
/// there is nothing to accumulate.
struct State;

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // Globals appearing or going away after the initial roundtrip are of no
        // interest: the manager was either there when we asked or it was not.
    }
}

delegate_noop!(State: WpSecurityContextManagerV1);
delegate_noop!(State: WpSecurityContextV1);

/// The compositor, reached through the UNRESTRICTED connection, with the
/// security-context manager bound: everything a registration takes. It lives
/// only until [`Compositor::register`], which closes it.
struct Compositor {
    conn: Connection,
    queue: EventQueue<State>,
    manager: WpSecurityContextManagerV1,
}

impl Compositor {
    /// Connect and find the manager. The error says what went wrong, not what
    /// comes of it: that is the caller's to say.
    fn connect() -> Result<Self, String> {
        // `connect_to_env` follows libwayland: WAYLAND_SOCKET (an inherited
        // descriptor, which it takes over and unsets) first, then
        // WAYLAND_DISPLAY inside XDG_RUNTIME_DIR, absolute paths included. The
        // one difference is that an unset WAYLAND_DISPLAY is "no compositor"
        // here, where libwayland would still try `wayland-0` — a session that
        // leaves the variable unset ends up unrestricted with a warning
        // instead of sandboxed silently.
        let conn = Connection::connect_to_env()
            .map_err(|e| format!("no connection to the compositor ({e})"))?;
        let (globals, queue) = registry_queue_init::<State>(&conn)
            .map_err(|e| format!("cannot read the compositor's globals ({e})"))?;
        let manager = globals
            .bind(&queue.handle(), 1..=1, ())
            .map_err(|e| format!("the compositor does not support security-context ({e})"))?;
        Ok(Self {
            conn,
            queue,
            manager,
        })
    }

    /// Hand `listener` to the compositor as a sandbox socket, switched off by
    /// closing the other end of `close_read`. Consumes the connection.
    fn register(
        mut self,
        listener: BorrowedFd<'_>,
        close_read: BorrowedFd<'_>,
        app_id: &str,
    ) -> Result<(), String> {
        let qh = self.queue.handle();
        let ctx: WpSecurityContextV1 = self.manager.create_listener(listener, close_read, &qh, ());
        ctx.set_sandbox_engine(SANDBOX_ENGINE.to_owned());
        ctx.set_app_id(app_id.to_owned());
        ctx.set_instance_id(std::process::id().to_string());
        ctx.commit();
        if let Err(e) = self.queue.roundtrip(&mut State) {
            // A compositor that refuses the context (nesting one sandbox
            // inside another is a protocol error) must not cost the user the
            // program: the socket we built is dropped and the program starts
            // as it would have without us.
            return Err(format!("the compositor refused the security context ({e})"));
        }
        ctx.destroy();
        let _ = self.conn.flush();
        // The connection goes here, before any fork, exactly as
        // `wl_display_disconnect` did: an UNRESTRICTED compositor connection
        // inherited by the sandboxed program (or the proxy) would be an open
        // back door, findable through /proc/self/fd even though WAYLAND_SOCKET
        // no longer names it. Both the queue and the connection hold the
        // backend; `self` is both, and it is dropped on return.
        Ok(())
    }
}

/// Register a sandboxed socket with the compositor, then run the program on it.
///
/// Returns the program's exit code, or falls back to [`run_plain`] (which never
/// returns unless the program itself could not be started) at every step that
/// did not work out.
pub fn run(args: Args) -> u8 {
    // Taken before anything is started: the program never inherits it. The
    // proxy says the word; every way without a proxy says that none will
    // come (`run_plain`, and below).
    take_opened();
    let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) else {
        eprintln!("wl-sandbox: no XDG_RUNTIME_DIR — running unrestricted");
        return run_plain(&args.cmd);
    };
    let runtime_dir = PathBuf::from(runtime_dir);

    let compositor = match Compositor::connect() {
        Ok(compositor) => compositor,
        Err(why) => {
            eprintln!(
                "wl-sandbox: {why} — running {} unrestricted",
                args.cmd[0].to_string_lossy()
            );
            return run_plain(&args.cmd);
        }
    };

    // A socket of this program's own, named by pid so that two runs of one
    // program do not fight over a single path, in the directory of its zone.
    let sock_name = socket_display(&args.zone, std::process::id());
    let sock_path = runtime_dir.join(&sock_name);
    if let Some(dir) = sock_path.parent() {
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
        {
            eprintln!(
                "wl-sandbox: cannot create {} ({e}) — running unrestricted",
                dir.display()
            );
            return run_plain(&args.cmd);
        }
    }
    // A leftover from an earlier run that happened to have this pid would make
    // bind(2) fail with EADDRINUSE.
    let _ = fs::remove_file(&sock_path);
    let listener = match UnixListener::bind(&sock_path) {
        Ok(listener) => listener,
        Err(e) => {
            // Includes the case libwayland silently truncated: sun_path is 108
            // bytes, and a longer XDG_RUNTIME_DIR is an error here, not a
            // half-working socket.
            eprintln!(
                "wl-sandbox: cannot create {} ({e}) — running unrestricted",
                sock_path.display()
            );
            return run_plain(&args.cmd);
        }
    };

    // With the proxy the compositor listens in a private directory instead,
    // and the zone's path is the proxy's. Not there: the first rung of the
    // fallback ladder — the compositor on the zone's path, as before.
    let upstream = if args.proxy {
        match wl_proxy::Upstream::bind(&runtime_dir, std::process::id()) {
            Ok(upstream) => Some(upstream),
            Err(e) => {
                eprintln!(
                    "wl-sandbox: cannot create the proxy's socket ({e}) — the compositor listens \
                     for the program itself"
                );
                None
            }
        }
    } else {
        None
    };
    let forget_upstream = |upstream: &Option<wl_proxy::Upstream>| {
        if let Some(up) = upstream {
            let _ = fs::remove_file(&up.path);
        }
    };

    // close_fd is the "switch". The compositor stops accepting connections on
    // the socket once this end of the pipe is closed; we hold it open for as
    // long as the program runs and let go after it exits.
    let (close_read, close_write) = match sys::pipe() {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("wl-sandbox: cannot create the close-fd pipe ({e}) — running unrestricted");
            let _ = fs::remove_file(&sock_path);
            forget_upstream(&upstream);
            return run_plain(&args.cmd);
        }
    };

    let target = upstream
        .as_ref()
        .map_or(listener.as_fd(), |up| up.listener.as_fd());
    if let Err(why) = compositor.register(target, close_read.as_fd(), &args.app_id) {
        eprintln!("wl-sandbox: {why} — running unrestricted");
        drop(close_write);
        let _ = fs::remove_file(&sock_path);
        forget_upstream(&upstream);
        return run_plain(&args.cmd);
    }
    // Our copies of the handed-over descriptors are not needed any more: the
    // compositor has its own. `close_write` is the exception — that is the
    // switch, and it stays.
    drop(close_read);

    let mut close_write = close_write;
    let mut proxy = None;
    // Whether the proxy has a copy of the picker's pipe to say the word on.
    let mut proxy_speaks = false;
    if let Some(up) = upstream {
        drop(up.listener);
        let word = opened_for_proxy();
        proxy_speaks = word.is_some();
        match wl_proxy::start(&listener, &up.path, args.frame.clone(), word) {
            Ok(started) => proxy = Some((started, up.path)),
            Err(e) => {
                // The second rung: the proxy did not start. The context made
                // for it is switched off, and the zone's path is registered
                // itself — exactly what happened before there was a proxy.
                // Should that fail, the program is NOT run unrestricted, as
                // the other fallbacks do: the compositor has just taken a
                // security context, so it speaks the protocol and a failure
                // now is no older compositor — and our first connection has
                // used up a WAYLAND_SOCKET, so without WAYLAND_DISPLAY the
                // program's libwayland would go looking for `wayland-0`
                // (review 2026-09-25).
                eprintln!(
                    "wl-sandbox: the Wayland proxy did not start ({e}) — the compositor listens \
                     for the program itself"
                );
                no_word();
                drop(close_write);
                let _ = fs::remove_file(&up.path);
                let registered = sys::pipe()
                    .map_err(|e| format!("cannot create the close-fd pipe ({e})"))
                    .and_then(|(close_read, switch)| {
                        Compositor::connect()?.register(
                            listener.as_fd(),
                            close_read.as_fd(),
                            &args.app_id,
                        )?;
                        Ok(switch)
                    });
                match registered {
                    Ok(switch) => close_write = switch,
                    Err(why) => {
                        eprintln!(
                            "wl-sandbox: {why} — the Wayland sandbox could not be set up a second \
                             time; {} is not started",
                            args.cmd[0].to_string_lossy()
                        );
                        let _ = fs::remove_file(&sock_path);
                        return EXIT_NOT_STARTED;
                    }
                }
            }
        }
    }
    // The compositor, or the proxy, has its own copy of the zone's socket.
    drop(listener);

    let previous_display = std::env::var_os("WAYLAND_DISPLAY");
    std::env::set_var("WAYLAND_DISPLAY", sock_name);
    // WAYLAND_SOCKET (an inherited descriptor) would override WAYLAND_DISPLAY,
    // and the program would go to the ordinary socket past the whole point.
    // This is a security invariant of the project, not a tidiness measure.
    std::env::remove_var("WAYLAND_SOCKET");

    if let Some((proxy, _)) = &mut proxy {
        proxy.take_over();
    }
    // Nobody on the way to say the program opened a window (no proxy —
    // `--no-proxy`, none started —, or no copy for it): said now. Our copy
    // stays until we go: the end of the pipe is then the launch's end.
    if proxy.is_none() || !proxy_speaks {
        no_word();
    }
    // NOT exec: after the program exits somebody has to close the switch and
    // unlink the socket, so it is started as a child.
    // SAFETY: single-threaded at this point, so the child may allocate and
    // print before it execs.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // The switch belongs to the parent. O_CLOEXEC would close this copy at
        // execve anyway; doing it here covers the case where the exec fails.
        drop(close_write);
        // The signals the supervisor took over are the program's again.
        if let Some((proxy, _)) = &proxy {
            proxy.in_program_child();
        }
        let e = exec_command(&args.cmd);
        eprintln!(
            "wl-sandbox: cannot start {}: {e}",
            args.cmd[0].to_string_lossy()
        );
        // _exit, not exit: the parent's atexit handlers and buffers are not
        // ours to run twice.
        unsafe { libc::_exit(EXIT_NOT_STARTED as libc::c_int) };
    }
    if pid < 0 {
        // Nobody can supervise the socket, and the switch would be closed by
        // the exec below (O_CLOEXEC) leaving the program with a dead
        // WAYLAND_DISPLAY — so put the environment back and run unrestricted.
        // WAYLAND_SOCKET is deliberately not restored: our own connection
        // consumed that descriptor and it is closed by now.
        eprintln!(
            "wl-sandbox: cannot fork ({}) — running unrestricted",
            io::Error::last_os_error()
        );
        match previous_display {
            Some(display) => std::env::set_var("WAYLAND_DISPLAY", display),
            None => std::env::remove_var("WAYLAND_DISPLAY"),
        }
        drop(close_write);
        let _ = fs::remove_file(&sock_path);
        if let Some((proxy, path)) = proxy {
            proxy.kill();
            let _ = fs::remove_file(path);
        }
        return run_plain(&args.cmd);
    }

    let status = match proxy {
        // The proxy outlives the program while a connection is open (a
        // terminal's child keeps its window); the switch and the sockets go
        // when the program does, as without it.
        Some((proxy, upstream_path)) => proxy.supervise(pid, move || {
            drop(close_write);
            let _ = fs::remove_file(&sock_path);
            let _ = fs::remove_file(upstream_path);
        }),
        None => {
            let mut status: libc::c_int = 0;
            loop {
                // SAFETY: `status` is a valid pointer for the duration of the call.
                let r = unsafe { libc::waitpid(pid, &mut status, 0) };
                if r == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            // The socket dies together with the program.
            drop(close_write);
            let _ = fs::remove_file(sock_path);
            status
        }
    };
    exit_code_of(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_command_is_taken_from_after_the_separator() {
        let a = Args::parse(&argv(&["firefox", "--", "firefox", "--new-window"])).unwrap();
        assert_eq!(a.app_id, "firefox");
        assert_eq!(a.cmd, argv(&["firefox", "--new-window"]));
    }

    #[test]
    fn only_the_first_separator_splits() {
        let a = Args::parse(&argv(&["sh", "--", "sh", "-c", "echo -- hi"])).unwrap();
        assert_eq!(a.cmd, argv(&["sh", "-c", "echo -- hi"]));
    }

    #[test]
    fn broken_command_lines_are_rejected() {
        // The old separator-less shape must not start the wrong program.
        assert_eq!(
            Args::parse(&argv(&["firefox", "firefox"])),
            Err(ArgError::NoSeparator)
        );
        assert_eq!(
            Args::parse(&argv(&["firefox", "firefox", "--", "firefox"])),
            Err(ArgError::TooManyArguments)
        );
        assert_eq!(
            Args::parse(&argv(&["firefox", "--"])),
            Err(ArgError::EmptyCommand)
        );
        assert_eq!(
            Args::parse(&argv(&["--", "firefox"])),
            Err(ArgError::MissingAppId)
        );
        assert_eq!(
            Args::parse(&argv(&["", "--", "firefox"])),
            Err(ArgError::MissingAppId)
        );
    }

    #[test]
    fn socket_names_are_unique_per_pid() {
        assert_eq!(socket_name(1234), "wl-sandbox-1234");
        assert_ne!(socket_name(1234), socket_name(1235));
        assert_eq!(
            socket_display("nl", 1234),
            "vpn-zones/wayland/nl/wl-sandbox-1234"
        );
    }

    #[test]
    fn the_zone_names_the_directory_and_nothing_else() {
        let a = Args::parse(&argv(&["firefox", "--zone", "nl", "--", "firefox"])).unwrap();
        assert_eq!((a.app_id.as_str(), a.zone.as_str()), ("firefox", "nl"));
        let a = Args::parse(&argv(&["--zone", "nl", "firefox", "--", "firefox"])).unwrap();
        assert_eq!(a.app_id, "firefox");
        let a = Args::parse(&argv(&["firefox", "--", "firefox"])).unwrap();
        assert_eq!(a.zone, NO_ZONE);
        assert!(a.proxy, "the proxy is the default");
        let a = Args::parse(&argv(&["firefox", "--no-proxy", "--zone", "nl", "--", "x"])).unwrap();
        assert_eq!(
            (a.proxy, a.zone.as_str(), a.app_id.as_str()),
            (false, "nl", "firefox")
        );
        // After the separator it is the program's own argument.
        let a = Args::parse(&argv(&["firefox", "--", "x", "--no-proxy"])).unwrap();
        assert!(a.proxy);
        assert_eq!(a.cmd, argv(&["x", "--no-proxy"]));
        for bad in [
            &["firefox", "--zone", "--", "x"][..],
            &["firefox", "--zone", "../x", "--", "x"],
            &["firefox", "--zone", "..", "--", "x"],
            &["firefox", "--zone", "", "--", "x"],
        ] {
            assert_eq!(Args::parse(&argv(bad)), Err(ArgError::BadZone), "{bad:?}");
        }
    }

    #[test]
    fn the_frame_is_a_colour_a_width_a_title_and_its_switch_a_directory() {
        use crate::frame::{Frame, Rgb, TitleMode};
        let a = Args::parse(&argv(&["foot", "--zone", "nl", "--", "foot"])).unwrap();
        assert_eq!(a.frame, None, "no border unless asked");
        let a = Args::parse(&argv(&[
            "foot",
            "--frame",
            "ff0080:6:hover",
            "--frame-title",
            "nl\u{202E} · банк\n",
            "--frame-switch",
            "/home/u/.config/vpn-zones",
            "--",
            "foot",
        ]))
        .unwrap();
        let setup = a.frame.unwrap();
        assert_eq!(
            setup.frame,
            Frame {
                color: Rgb(255, 0, 128),
                width: 6,
                title: TitleMode::Hover,
            }
        );
        assert_eq!(setup.title, "nl · банк", "cleaned again on the way in");
        assert_eq!(setup.switch, PathBuf::from("/home/u/.config/vpn-zones"));
        // Without a title, a strip without text.
        let a = Args::parse(&argv(&["foot", "--frame", "ff0080:6", "--", "x"])).unwrap();
        assert_eq!(a.frame.unwrap().title, "");
        for bad in [
            &["foot", "--frame", "--", "x"][..],
            &["foot", "--frame", "red:4", "--", "x"],
            &["foot", "--frame", "ff0080:0", "--", "x"],
            &["foot", "--frame", "ff0080:4:maybe", "--", "x"],
            &["foot", "--frame", "ff0080:4", "--frame-title", "--", "x"],
            &[
                "foot",
                "--frame",
                "ff0080:4",
                "--frame-switch",
                "",
                "--",
                "x",
            ],
        ] {
            assert_eq!(Args::parse(&argv(bad)), Err(ArgError::BadFrame), "{bad:?}");
        }
    }
}
