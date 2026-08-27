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
//! Usage: `vpn-zone-core wl-sandbox <app-id> -- <command> [args…]`.
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
use std::os::fd::AsFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::wl_registry;
use wayland_client::{delegate_noop, Connection, Dispatch, QueueHandle};
use wayland_protocols::wp::security_context::v1::client::{
    wp_security_context_manager_v1::WpSecurityContextManagerV1,
    wp_security_context_v1::WpSecurityContextV1,
};

use crate::profile::{exec_command, exit_code_of, EXIT_NOT_STARTED};
use crate::sys;

/// Sandbox engine name reported to the compositor. It is what a compositor
/// shows when it names the sandbox a window came from, so it names the project,
/// not the program.
const SANDBOX_ENGINE: &str = "vpn-zone";

/// What `wl-sandbox` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// Identifier the compositor gets as the sandboxed application's app-id.
    /// The bash side has already reduced it to one word of
    /// `[A-Za-z0-9_.-]` — a space used to split the argument in two and the
    /// wrong program was started (`docs/GOTCHAS.md` §7).
    pub app_id: String,
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
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSeparator => write!(f, "no `--` before the command"),
            Self::MissingAppId => write!(f, "need a non-empty <app-id>"),
            Self::EmptyCommand => write!(f, "nothing to run after `--`"),
            Self::TooManyArguments => write!(f, "only <app-id> may precede `--`"),
        }
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parse `<app-id> -- cmd...`.
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
        let positional = &argv[..split];
        let cmd = argv[split + 1..].to_vec();
        if cmd.is_empty() {
            return Err(ArgError::EmptyCommand);
        }
        if positional.len() > 1 {
            return Err(ArgError::TooManyArguments);
        }
        let app_id = positional.first().ok_or(ArgError::MissingAppId)?;
        if app_id.is_empty() {
            return Err(ArgError::MissingAppId);
        }
        Ok(Self {
            app_id: app_id.to_string_lossy().into_owned(),
            cmd,
        })
    }
}

/// Name of the socket this run registers with the compositor.
///
/// Unique by pid: two runs of the same program must not fight over one path.
pub fn socket_name(pid: u32) -> String {
    format!("wl-sandbox-{pid}")
}

/// Run without restrictions — the shared path for everything that did not work
/// out.
///
/// `execvp`, so the program replaces this process, exactly as the C version
/// did: there is nothing left to supervise or clean up, and the caller gets the
/// program's own exit status without a middleman.
fn run_plain(cmd: &[OsString]) -> u8 {
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

/// Register a sandboxed socket with the compositor, then run the program on it.
///
/// Returns the program's exit code, or falls back to [`run_plain`] (which never
/// returns unless the program itself could not be started) at every step that
/// did not work out.
pub fn run(args: Args) -> u8 {
    let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) else {
        eprintln!("wl-sandbox: no XDG_RUNTIME_DIR — running unrestricted");
        return run_plain(&args.cmd);
    };

    // `connect_to_env` follows libwayland: WAYLAND_SOCKET (an inherited
    // descriptor, which it takes over and unsets) first, then WAYLAND_DISPLAY
    // inside XDG_RUNTIME_DIR, absolute paths included. The one difference is
    // that an unset WAYLAND_DISPLAY is "no compositor" here, where libwayland
    // would still try `wayland-0` — a session that leaves the variable unset
    // ends up unrestricted with a warning instead of sandboxed silently.
    let conn = match Connection::connect_to_env() {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("wl-sandbox: no connection to the compositor ({e}) — running unrestricted");
            return run_plain(&args.cmd);
        }
    };

    let (globals, mut queue) = match registry_queue_init::<State>(&conn) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!(
                "wl-sandbox: cannot read the compositor's globals ({e}) — running unrestricted"
            );
            return run_plain(&args.cmd);
        }
    };
    let qh = queue.handle();
    let manager: WpSecurityContextManagerV1 = match globals.bind(&qh, 1..=1, ()) {
        Ok(manager) => manager,
        Err(e) => {
            eprintln!(
                "wl-sandbox: the compositor does not support security-context ({e}) — \
                 running {} unrestricted",
                args.cmd[0].to_string_lossy()
            );
            return run_plain(&args.cmd);
        }
    };

    // A socket of this program's own, named by pid so that two runs of one
    // program do not fight over a single path.
    let sock_name = socket_name(std::process::id());
    let sock_path = PathBuf::from(runtime_dir).join(&sock_name);
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

    // close_fd is the "switch". The compositor stops accepting connections on
    // the socket once this end of the pipe is closed; we hold it open for as
    // long as the program runs and let go after it exits.
    let (close_read, close_write) = match sys::pipe() {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("wl-sandbox: cannot create the close-fd pipe ({e}) — running unrestricted");
            let _ = fs::remove_file(&sock_path);
            return run_plain(&args.cmd);
        }
    };

    let ctx: WpSecurityContextV1 =
        manager.create_listener(listener.as_fd(), close_read.as_fd(), &qh, ());
    ctx.set_sandbox_engine(SANDBOX_ENGINE.to_owned());
    ctx.set_app_id(args.app_id);
    ctx.set_instance_id(std::process::id().to_string());
    ctx.commit();
    let mut state = State;
    if let Err(e) = queue.roundtrip(&mut state) {
        // A compositor that refuses the context (nesting one sandbox inside
        // another is a protocol error) must not cost the user the program: the
        // socket we built is dropped and the program starts as it would have
        // without us.
        eprintln!(
            "wl-sandbox: the compositor refused the security context ({e}) — running unrestricted"
        );
        drop(close_write);
        let _ = fs::remove_file(&sock_path);
        return run_plain(&args.cmd);
    }

    // Our copies of the handed-over descriptors are not needed any more: the
    // compositor has its own. `close_write` is the exception — that is the
    // switch, and it stays.
    //
    // The connection goes too, and before the fork, exactly as
    // `wl_display_disconnect` did: an UNRESTRICTED compositor connection
    // inherited by the sandboxed program would be an open back door, findable
    // through /proc/self/fd even though WAYLAND_SOCKET no longer names it.
    // Both the queue and the connection hold the backend, so both must go.
    ctx.destroy();
    let _ = conn.flush();
    drop(listener);
    drop(close_read);
    drop(queue);
    drop(conn);

    let previous_display = std::env::var_os("WAYLAND_DISPLAY");
    std::env::set_var("WAYLAND_DISPLAY", sock_name);
    // WAYLAND_SOCKET (an inherited descriptor) would override WAYLAND_DISPLAY,
    // and the program would go to the ordinary socket past the whole point.
    // This is a security invariant of the project, not a tidiness measure.
    std::env::remove_var("WAYLAND_SOCKET");

    // NOT exec: after the program exits somebody has to close the switch and
    // unlink the socket, so it is started as a child.
    // SAFETY: single-threaded at this point, so the child may allocate and
    // print before it execs.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // The switch belongs to the parent. O_CLOEXEC would close this copy at
        // execve anyway; doing it here covers the case where the exec fails.
        drop(close_write);
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
        return run_plain(&args.cmd);
    }

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
    }
}
