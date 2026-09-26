//! The Wayland proxy of `wl-sandbox`: a process of its own between a program
//! and the compositor (`docs/WINDOW-FRAME.md` §8, stage 1).
//!
//! **Why.** A frame the program cannot remove has to be drawn by someone who
//! sits on its connection, and a party that adds objects to a connection must
//! translate every object id in both directions — the compositor's table is
//! dense (§2). That needs the signature of every message of every protocol
//! passed on; `wl-proxy` has them and keeps the two id spaces apart (§3.2).
//! This stage is the TRANSPARENT proxy: the same connection the program had,
//! minus what is hidden below, nothing added. The frame comes on top of it.
//!
//! ```text
//!  wl-sandbox (supervisor, host)                                     zone
//!   │ listener of the security context: $XDG_RUNTIME_DIR/vpn-zones/wl-up/<pid>
//!   │   (0700, never bound into a zone; the compositor listens there)
//!   │ connects to it on request ──fd──┐
//!   └ fork ─► proxy (this, seccomp)   ▼
//!               accept() on vpn-zones/wayland/<zone>/wl-sandbox-<pid> ◄── program
//!               one wl-proxy State per accepted connection, upstream = the fd
//! ```
//!
//! **What the program sees.** Only the globals of the protocols compiled into
//! `wl-proxy` (`rust/Cargo.toml` names them — the list IS the policy), at most
//! at the versions of its pinned baseline. The rest is hidden: what the crate
//! does not know is dropped by the crate itself, and a bind to a name this
//! connection was never shown is refused here, so a hidden global cannot be
//! bound by guessing its number (the compositor would have taken it: a name is
//! just a number). [`HIDDEN`] lists what that means, and a test holds the build
//! to it. No global is ever added.
//!
//! **The proxy is hostile input's first reader**, so it is kept small in what
//! it can do (§10):
//!
//! * a process of its own, not dumpable — nobody of the same uid reads its
//!   memory or borrows its descriptors through `/proc`;
//! * an allow-list seccomp filter ([`filter`]): no `open`, no `socket`, no
//!   `connect`, no `exec`, no `fork`, no executable memory. It cannot reach the
//!   compositor's own socket or anything else by name: a connection upstream is
//!   made by the SUPERVISOR, which connects to the security context's listener
//!   and nothing else, and hands the descriptor over. A proxy taken over by its
//!   client gets what the client already had — restricted connections;
//! * only the launch's own processes: a connection is passed on when the
//!   process that made it is the supervisor's descendant, which the
//!   supervisor asks the kernel ([`of_this_launch`]). The zone's directory of
//!   sockets is shared by all its launches, and is read-only in the zone
//!   (`crate::zone`): a program of one launch can neither take another's
//!   socket nor be passed on through it;
//! * limits, so that a client cannot make it hold unbounded memory or
//!   descriptors: connections, connections waiting for their upstream, objects
//!   per connection, globals per registry, the bytes waiting for a client that
//!   does not read (its requests are not read meanwhile — back-pressure, as on
//!   a direct connection), and `RLIMIT_NOFILE`/`RLIMIT_DATA` for the process.
//!   `wl-proxy` bounds a message (4096 bytes) and the descriptors of one read
//!   (28, the rest the kernel closes); descriptors a client sends ahead and
//!   never uses stay queued until the process limit — which starves this
//!   launch's own connections only, since nobody else's are taken (§3.2);
//!   out of descriptors, accepting rests a while and is tried again;
//! * it dies with its supervisor (`PR_SET_PDEATHSIG`): a window's pid
//!   upstream is the supervisor's, and never a dead one's.
//!
//! **Fail-closed.** The proxy dying takes the program's display with it; the
//! program is never handed the compositor's socket instead. When it cannot
//! START, `wl-sandbox` falls back to exactly what it did before the proxy: the
//! compositor listens on the zone's path itself (§8, the fallback ladder) —
//! and if that cannot be set up either, the program is not started.
//!
//! **Lifetime.** Until the main program exits, the proxy accepts. Then the
//! supervisor closes the channel between them, and the proxy stops accepting —
//! a new connection after the program is gone is refused, as it was when the
//! compositor stopped listening — but serves the connections it has: a
//! terminal's child keeps its window. It exits with the last of them, and the
//! supervisor, which adopted the program's orphans (`PR_SET_CHILD_SUBREAPER`)
//! so that a window of one of them still leads to its launch
//! (`crate::focus`), exits after it. A SIGTERM, SIGINT or SIGHUP sent to the
//! supervisor is passed on to the program and those orphans ([`FORWARDED`]):
//! the launch's pid is the supervisor's, and "close" is sent to it.
//!
//! **Whose pid a window has.** The compositor takes a client's pid from the
//! connection (`SO_PEERCRED`: whoever called `connect`), and upstream it is the
//! supervisor that connects. Every window of the launch therefore has the
//! supervisor's pid — the very pid of the launch's registry record — whichever
//! process of the program opened it; the supervisor goes by
//! [`SUPERVISOR_NAME`] meanwhile, so that `crate::focus` knows to ask its
//! children for the network.
//!
//! **The zone's border** (stage 2, `crate::wl_frame`). With a frame the proxy
//! draws a border of the zone's colour around every toplevel: the colour is
//! one pixel in a sealed memfd made before the filter is loaded ([`pixel`])
//! — the filter still has no `memfd_create`, and the proxy never maps it —,
//! handed to the compositor with each connection's `wl_shm`. The supervisor
//! answers each connection with the border or without ([`UPSTREAM`],
//! [`UPSTREAM_BARE`]): it reads the switch that hides every border
//! (`crate::frame::hidden`) at that moment. Nothing is added to what the
//! program sees; what the proxy binds for the border is on a registry of its
//! own.
//!
//! **The title strip** (`crate::wl_title`): `<zone> · <container>` on the
//! zone's colour along the top. The supervisor reads the font — a file the
//! Nix package names by store path — before the fork; the proxy lays the
//! line out and makes the memfd its pixels go to before the filter, and
//! writes them there (`pwrite`, the only call the title added to the filter)
//! at whatever scale the compositor asks for.

use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
use wl_proxy::baseline::Baseline;
use wl_proxy::client::{Client, ClientHandler};
use wl_proxy::object::{Object, ObjectCoreApi, ObjectRcUtils};
use wl_proxy::protocols::wayland::wl_display::{WlDisplay, WlDisplayHandler};
use wl_proxy::protocols::wayland::wl_registry::{WlRegistry, WlRegistryHandler};
use wl_proxy::protocols::wayland::wl_surface::WlSurface;
use wl_proxy::protocols::xdg_shell::xdg_surface::{XdgSurface, XdgSurfaceHandler};
use wl_proxy::protocols::xdg_shell::xdg_toplevel::XdgToplevel;
use wl_proxy::protocols::xdg_shell::xdg_wm_base::{XdgWmBase, XdgWmBaseHandler};
use wl_proxy::protocols::ObjectInterface;
use wl_proxy::state::{State, StateHandler};

use crate::frame::{Frame, Rgb, Setup, TitleMode};
use crate::sys;
use crate::wl_frame::{Frames, MAX_FRAMED};
use crate::wl_title::{Prepared, Text};

/// The proxy's process name (`/proc/<pid>/comm`, 15 bytes at most).
pub const PROCESS_NAME: &str = "vz-wl-proxy";

/// The supervisor's process name while it runs a proxy. A window of a proxied
/// program has the SUPERVISOR's pid (it made the connection upstream), and
/// [`crate::focus`] knows it by this name: the network is not the
/// supervisor's own (the host's) but its children's.
pub const SUPERVISOR_NAME: &str = "vz-wl-sandbox";

/// Below the runtime directory: the listeners of the security contexts, one
/// per launch. `crate::zone` keeps nothing of `vpn-zones/` in a zone but the
/// zone's own `wayland/<zone>`, so this directory is never seen from one.
pub const UPSTREAM_DIR: &str = "vpn-zones/wl-up";

/// The baseline: the highest version of each interface the program is shown.
/// Pinned, like the crate: a newer one is a reviewed change.
const BASELINE: Baseline = Baseline::V5;

/// Globals a program behind the proxy never sees, though a compositor may
/// offer them to a restricted client: their protocols are left out of the
/// build (`rust/Cargo.toml`). `wp_drm_lease_device_v1` hands out a DRM
/// descriptor (§4.3, the decision of §11); the rest is what security-context
/// exists to hide — kept out here too, so that a compositor that forgets one
/// does not decide for us — and names the crate does not know at all
/// (NVIDIA's EGLStream, mutter's interop). Not exhaustive for the unknown:
/// anything not compiled in is hidden.
pub const HIDDEN: &[&str] = &[
    "wp_drm_lease_device_v1",
    "ext_data_control_manager_v1",
    "zwlr_data_control_manager_v1",
    "ext_foreign_toplevel_list_v1",
    "zwlr_foreign_toplevel_manager_v1",
    "ext_image_copy_capture_manager_v1",
    "ext_output_image_capture_source_manager_v1",
    "ext_foreign_toplevel_image_capture_source_manager_v1",
    "zwlr_screencopy_manager_v1",
    "zwlr_export_dmabuf_manager_v1",
    "ext_session_lock_manager_v1",
    "ext_idle_notifier_v1",
    "ext_transient_seat_manager_v1",
    "ext_workspace_manager_v1",
    "zwp_input_method_manager_v2",
    "zwp_input_method_v1",
    "zwp_input_panel_v1",
    "zwp_virtual_keyboard_manager_v1",
    "zwlr_virtual_pointer_manager_v1",
    "xwayland_shell_v1",
    "zwp_xwayland_keyboard_grab_manager_v1",
    "wp_security_context_manager_v1",
    "zwp_fullscreen_shell_v1",
    "zwlr_layer_shell_v1",
    "zwlr_output_manager_v1",
    "zwlr_output_power_manager_v1",
    "zwlr_gamma_control_manager_v1",
    "zwlr_input_inhibit_manager_v1",
    // Unknown to wl-proxy 0.1.4 altogether. xdg-foreign v1 is GTK3's: a
    // portal dialog of a GTK3 program comes up unparented (v2 passes).
    "zxdg_exporter_v1",
    "zxdg_importer_v1",
    "gtk_shell1",
    "wl_eglstream_display",
    "mutter_x11_interop",
];

// --- LIMITS -----------------------------------------------------------------

/// Connections of one launch at once. A browser opens a handful; a hundred is
/// a program trying something.
const MAX_CONNECTIONS: usize = 64;
/// Accepted connections still waiting for the supervisor to connect upstream.
const MAX_WAITING: usize = 16;
/// Objects of one connection. libwayland has no such limit, but a big program
/// holds a few thousand; the proxy's share of each is a few hundred bytes.
const MAX_OBJECTS: usize = 100_000;
/// How often (in dispatches of a connection) its objects are counted: the
/// count walks all of them. A dispatch reads the client's socket once
/// (wl-proxy's `may_read_from_socket`), into a buffer of 8 KiB, and that
/// creates at most ~700 — so the limit is overshot by 45 000 at the most.
const COUNT_OBJECTS_EVERY: u32 = 64;
/// Globals remembered per registry. The compositor's to fill, not the
/// program's, but an output plugged in and out forever must not grow it.
const MAX_GLOBALS: usize = 4096;
/// Bytes a client has not read yet (`TIOCOUTQ`) at which its requests stop
/// being read, and at which they are read again. The kernel's own buffer is
/// ~200 KiB; above the high mark the client is not keeping up.
const OUTQ_HIGH: libc::c_int = 128 * 1024;
const OUTQ_LOW: libc::c_int = 32 * 1024;
/// How often a stopped client is looked at again.
const RECHECK_MS: libc::c_int = 50;
/// The process limits.
const MAX_FDS: libc::rlim_t = 1024;
const MAX_DATA: libc::rlim_t = 512 << 20;
/// How long accepting rests after the process ran out of descriptors.
const ACCEPT_PAUSE: Duration = Duration::from_secs(1);
/// The longest compositor error text passed on to the program.
const MAX_ERROR_TEXT: usize = 1024;

// --- THE CHANNEL -------------------------------------------------------------
// One byte per message on a stream socketpair; the upstream descriptor rides
// on its byte. The supervisor closing its end is "the program has exited".

/// Proxy → supervisor: hardened, filter loaded, serving.
const READY: u8 = b'r';
/// Proxy → supervisor: one more connection upstream, please.
const CONNECT: u8 = b'c';
/// Supervisor → proxy: here it is (with the descriptor), with the zone's
/// border.
const UPSTREAM: u8 = b'u';
/// Supervisor → proxy: here it is, without the border — hidden for now
/// (`vpn-zone frame hide`), or the launch has none.
const UPSTREAM_BARE: u8 = b'b';
/// Supervisor → proxy: the security context no longer accepts.
const REFUSED: u8 = b'n';

/// `wl_display` error codes.
const INVALID_OBJECT: u32 = 0;
const NO_MEMORY: u32 = 2;

// --- THE SUPERVISOR'S SIDE ----------------------------------------------------

/// The security context's listener, before the proxy is started: made first,
/// because the compositor has to be listening on it when the program starts.
pub struct Upstream {
    pub listener: UnixListener,
    pub path: PathBuf,
}

impl Upstream {
    /// `$XDG_RUNTIME_DIR/vpn-zones/wl-up/<pid>`, in a directory only the user
    /// enters. A leftover of an earlier run with this pid is replaced.
    pub fn bind(runtime_dir: &Path, pid: u32) -> io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let dir = runtime_dir.join(UPSTREAM_DIR);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        // An existing directory keeps whatever mode it was made with.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let path = dir.join(pid.to_string());
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        Ok(Self { listener, path })
    }
}

/// A running proxy, as its supervisor holds it.
pub struct Proxy {
    pid: libc::pid_t,
    pidfd: Option<OwnedFd>,
    channel: Option<UnixStream>,
    upstream: PathBuf,
    adopting: bool,
    /// The signals taken over in [`Proxy::take_over`].
    signals: Option<Signals>,
    /// When the proxy draws the zone's border: the directory of the
    /// settings whose switch can hide it, read for each connection.
    frame: Option<PathBuf>,
}

/// The signals the supervisor passes on to its launch. The pid of the launch
/// — its registry record, and the pid of every window it opens through the
/// proxy — is the supervisor's, so "close it" reaches the supervisor: the
/// window menu's "close" and "restart" (`crate::focus`), a `kill` by hand.
/// Before the proxy it reached the program itself, which is why they are
/// passed on instead of ending the supervisor and leaving the program running,
/// its windows open and its record dead (review 2026-09-25).
const FORWARDED: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

/// [`FORWARDED`] and `SIGCHLD` (which only wakes the supervisor up to reap),
/// blocked and read from a signalfd in [`Proxy::supervise`].
struct Signals {
    fd: OwnedFd,
    /// The mask before, which the program is given back.
    old: libc::sigset_t,
}

impl Signals {
    fn take() -> io::Result<Self> {
        // SAFETY: sigset_t is plain data, filled by sigemptyset/sigaddset;
        // sigprocmask and signalfd read it and write `old`, all valid for the
        // calls. The descriptor signalfd returns is owned by nobody else.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for sig in FORWARDED.iter().chain(&[libc::SIGCHLD]) {
                libc::sigaddset(&mut set, *sig);
            }
            let mut old: libc::sigset_t = std::mem::zeroed();
            if libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old) != 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd < 0 {
                let e = io::Error::last_os_error();
                libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
                return Err(e);
            }
            Ok(Self {
                fd: OwnedFd::from_raw_fd(fd),
                old,
            })
        }
    }

    /// The mask as it was. In the program's child before its `execve` (the
    /// mask is inherited across both), and in the supervisor on a path that
    /// runs the program itself: a signal that came meanwhile is delivered
    /// then, as it would have been.
    fn restore(&self) {
        // SAFETY: a valid sigset_t; async-signal-safe, fit for a fresh child.
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) };
    }

    /// The signals that have come: each with whether a process sent it.
    fn read(&self) -> Vec<(libc::c_int, bool)> {
        let mut out = Vec::new();
        loop {
            // SAFETY: signalfd_siginfo is plain data.
            let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<libc::signalfd_siginfo>();
            // SAFETY: reads at most `size` bytes into `info`.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    (&mut info as *mut libc::signalfd_siginfo).cast(),
                    size,
                )
            };
            if n != size as isize {
                return out;
            }
            // SI_USER (kill, pidfd_send_signal), SI_QUEUE and SI_TKILL are
            // zero or below. A signal the kernel makes — SIGINT of a
            // terminal's Ctrl+C, SIGHUP of its hang-up — is SI_KERNEL, above
            // zero, and goes to the whole foreground process group, the
            // program included: passed on, it would come to it twice.
            out.push((info.ssi_signo as libc::c_int, info.ssi_code <= 0));
        }
    }
}

/// Start the proxy on `zone_listener`, the socket the program will be told
/// about. Returns once the proxy has confined itself; on any failure nothing
/// is left running and the caller falls back.
///
/// `frame`: the zone's frame and title, and the directory of the settings
/// with the switch that hides it (`crate::frame::hidden`), read again for
/// every connection.
///
/// Called with the compositor's (unrestricted) connection already closed: the
/// child inherits nothing of it. It closes every descriptor it did not ask for
/// all the same, first thing.
pub fn start(
    zone_listener: &UnixListener,
    upstream: &Path,
    frame: Option<Setup>,
    opened: Option<OwnedFd>,
) -> Result<Proxy, String> {
    let (ours, theirs) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    let listener = zone_listener.try_clone().map_err(|e| format!("dup: {e}"))?;
    // The font, read here: the proxy opens nothing. Only when there is a
    // title to draw.
    let drawing = frame.as_ref().map(|setup| Drawing {
        frame: setup.frame,
        font: (setup.frame.title != TitleMode::Off && !setup.title.is_empty())
            .then(read_font)
            .flatten(),
        title: setup.title.clone(),
    });
    // SAFETY: getpid takes nothing and cannot fail.
    let supervisor = unsafe { libc::getpid() };
    // SAFETY: single-threaded here (wl-sandbox has no threads), so the child
    // may allocate before it confines itself.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(ours);
        // A panic ends the proxy here: unwinding further would run the
        // supervisor's code (`wl_sandbox::run`) in this child.
        let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            child(listener, theirs, supervisor, drawing, opened)
        }))
        .unwrap_or(101);
        // _exit: the parent's atexit handlers and buffers are not ours.
        // SAFETY: always sound.
        unsafe { libc::_exit(code) };
    }
    drop(listener);
    drop(theirs);
    let proxy = Proxy {
        pid,
        pidfd: sys::pidfd_open(pid),
        channel: Some(ours),
        upstream: upstream.to_path_buf(),
        adopting: false,
        signals: None,
        frame: frame.map(|setup| setup.switch),
    };
    match proxy.await_ready() {
        Ok(()) => Ok(proxy),
        Err(e) => {
            proxy.kill();
            Err(e)
        }
    }
}

impl Proxy {
    /// Waited for as long as it takes — no clock: the proxy says it is
    /// ready, or its end of the channel closes when it dies. A loaded machine
    /// only makes it later, never a launch without the proxy.
    fn await_ready(&self) -> Result<(), String> {
        let channel = self.channel.as_ref().ok_or("no channel")?;
        let mut pfd = [pollfd(channel.as_raw_fd())];
        loop {
            match poll(&mut pfd, -1) {
                Ok(0) => continue,
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("poll: {e}")),
            }
        }
        let mut byte = [0u8; 1];
        match sys::recv_into_with_fds(channel.as_raw_fd(), &mut byte, 0) {
            Ok((1, _, _)) if byte[0] == READY => Ok(()),
            Ok(_) => Err("it exited before it was ready".to_owned()),
            Err(e) => Err(format!("recv: {e}")),
        }
    }

    /// Become the supervisor, just before the program is started: the name
    /// `crate::focus` knows the windows by ([`SUPERVISOR_NAME`]), and the
    /// program's orphans come here — a window of a process whose parent has
    /// gone still leads to its launch, and to its network. Only once the proxy
    /// is certainly running: the subreaper flag survives `execve`, and a
    /// fallback that runs the program in this very process must not keep it
    /// ([`Proxy::kill`] takes it back; the name goes with the `execve`).
    ///
    /// And the signals of [`FORWARDED`] are taken over from here on: one that
    /// comes before the program is started is passed on once it is. The
    /// program's child gives them back ([`Proxy::in_program_child`]). Without
    /// a signalfd (out of descriptors) the supervisor dies of them as it did
    /// before, with a warning, and the proxy with it.
    pub fn take_over(&mut self) {
        if let Ok(name) = std::ffi::CString::new(SUPERVISOR_NAME) {
            // SAFETY: PR_SET_NAME reads a NUL-terminated string that outlives
            // the call.
            unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0) };
        }
        // SAFETY: prctl with these arguments takes no pointers.
        self.adopting = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0;
        match Signals::take() {
            Ok(signals) => self.signals = Some(signals),
            Err(e) => eprintln!(
                "wl-sandbox: cannot take over the signals ({e}) — a signal to the launch ends the \
                 supervisor instead of reaching the program"
            ),
        }
    }

    /// In the program's child, between `fork` and `execve`: the signal mask
    /// the program would have had. Async-signal-safe.
    pub fn in_program_child(&self) {
        if let Some(signals) = &self.signals {
            signals.restore();
        }
    }

    /// Stop it at once, on a path that will not start the program behind it.
    pub fn kill(mut self) {
        if self.adopting {
            // SAFETY: as in `take_over`.
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) };
        }
        if let Some(signals) = self.signals.take() {
            signals.restore();
        }
        self.channel = None;
        match &self.pidfd {
            Some(fd) => {
                sys::pidfd_signal(fd, libc::SIGKILL);
            }
            // SAFETY: our own child, not reaped yet, so the pid is still ours.
            None => unsafe {
                libc::kill(self.pid, libc::SIGKILL);
            },
        }
        let mut status = 0;
        wait(self.pid, &mut status, 0);
    }

    /// Answer the proxy's requests until the program `main` exits, call
    /// `on_main_exit`, stop the proxy accepting and wait for it to finish
    /// with the connections it has. Returns `main`'s wait status.
    ///
    /// Meanwhile a signal of [`FORWARDED`] sent to this process is passed on
    /// to its children but the proxy: the program while it runs, and the
    /// orphans it left, which are adopted here. After a SIGTERM a child
    /// adopted later gets it too: a wrapper that dies of it (a throwaway
    /// container's `profile-run`, `x11-run`) leaves the program behind it to
    /// this process, and that program is what "close" was meant for.
    pub fn supervise(mut self, main: libc::pid_t, on_main_exit: impl FnOnce()) -> libc::c_int {
        let main_fd = sys::pidfd_open(main);
        let mut on_main_exit = Some(on_main_exit);
        let mut main_status = None;
        let mut proxy_alive = true;
        let mut terminating = false;
        // The children SIGTERM has been passed on to (and not reaped since).
        let mut told = HashSet::new();
        loop {
            self.reap(main, &mut main_status, &mut proxy_alive, &mut told);
            if main_status.is_some() {
                if let Some(on_main_exit) = on_main_exit.take() {
                    on_main_exit();
                    // The proxy stops accepting when this closes, and exits
                    // with its last connection.
                    self.channel = None;
                }
                if !proxy_alive {
                    break;
                }
            }
            if terminating {
                self.pass_on(libc::SIGTERM, &mut told);
            }
            let mut fds = Vec::with_capacity(4);
            if main_status.is_none() {
                if let Some(fd) = &main_fd {
                    fds.push(pollfd(fd.as_raw_fd()));
                }
            }
            let channel_at = self.channel.as_ref().map(|c| {
                fds.push(pollfd(c.as_raw_fd()));
                fds.len() - 1
            });
            if proxy_alive {
                if let Some(fd) = &self.pidfd {
                    fds.push(pollfd(fd.as_raw_fd()));
                }
            }
            let signals_at = self.signals.as_ref().map(|s| {
                fds.push(pollfd(s.fd.as_raw_fd()));
                fds.len() - 1
            });
            // Orphans are reaped on every wake-up (SIGCHLD is one); without
            // the pidfds an exit is only noticed on this timeout.
            let timeout = if main_fd.is_some() && self.pidfd.is_some() {
                2000
            } else {
                200
            };
            if let Err(e) = poll(&mut fds, timeout) {
                if e.kind() != io::ErrorKind::Interrupted {
                    eprintln!("wl-sandbox: poll: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
                continue;
            }
            if let Some(at) = channel_at {
                if fds[at].revents != 0 && !self.answer() {
                    self.channel = None;
                }
            }
            if let (Some(at), Some(signals)) = (signals_at, &self.signals) {
                if fds[at].revents != 0 {
                    for (sig, sent) in signals.read() {
                        if !sent || !FORWARDED.contains(&sig) {
                            continue;
                        }
                        if sig == libc::SIGTERM {
                            terminating = true;
                            self.pass_on(sig, &mut told);
                        } else {
                            self.pass_on(sig, &mut HashSet::new());
                        }
                    }
                }
            }
        }
        main_status.unwrap_or(0)
    }

    /// Send `sig` to every child of this process but the proxy that is not in
    /// `told`, and put it there. By number, and safely so: a child's number
    /// is not given to anybody else before it is reaped, and nothing is
    /// reaped between the listing and the signal.
    fn pass_on(&self, sig: libc::c_int, told: &mut HashSet<libc::pid_t>) {
        // SAFETY: getpid takes nothing and cannot fail.
        let me = unsafe { libc::getpid() };
        for child in sys::children_of(me) {
            if child == self.pid || !told.insert(child) {
                continue;
            }
            // SAFETY: kill(2) takes no pointers; the pid is our unreaped child.
            unsafe { libc::kill(child, sig) };
        }
    }

    /// Reap whatever has exited: the program, the proxy, adopted orphans.
    fn reap(
        &self,
        main: libc::pid_t,
        main_status: &mut Option<libc::c_int>,
        proxy_alive: &mut bool,
        told: &mut HashSet<libc::pid_t>,
    ) {
        loop {
            let mut status = 0;
            match wait(-1, &mut status, libc::WNOHANG) {
                Some(0) => return,
                // Nothing left to wait for at all (ECHILD).
                None => {
                    *proxy_alive = false;
                    main_status.get_or_insert(0);
                    return;
                }
                Some(pid) => {
                    told.remove(&pid);
                    if pid == main {
                        *main_status = Some(status);
                    } else if pid == self.pid {
                        *proxy_alive = false;
                        // Fail-closed: the program's connections died with
                        // the proxy, and it is not given another way to the
                        // compositor. (After the program, its exit is the
                        // ordinary end.)
                        if main_status.is_some() {
                            continue;
                        }
                        eprintln!(
                            "wl-sandbox: the Wayland proxy exited ({}) — the program has no \
                             display now",
                            describe(status)
                        );
                    }
                }
            }
        }
    }

    /// One request of the proxy. False when the channel is gone.
    fn answer(&self) -> bool {
        let Some(channel) = &self.channel else {
            return false;
        };
        let mut byte = [0u8; 1];
        // A request comes with the client's socket, for its peer to be looked
        // at; any other descriptor the proxy sends is closed by the kernel
        // (`MSG_CTRUNC`), and this one is closed here once looked at: the
        // supervisor only asks the kernel who connected, it never reads.
        let client = match sys::recv_into_with_fds(channel.as_raw_fd(), &mut byte, 1) {
            Ok((1, mut fds, _)) if byte[0] == CONNECT => fds.pop(),
            Ok((1, _, _)) => return true,
            Ok(_) => return false,
            Err(e) => return e.kind() == io::ErrorKind::Interrupted,
        };
        let peer = client.as_ref().and_then(|c| sys::peer_pid(c.as_raw_fd()));
        let ours = client
            .as_ref()
            .is_some_and(|c| of_this_launch(c.as_raw_fd()));
        drop(client);
        if !ours {
            eprintln!(
                "wl-sandbox: a Wayland connection from outside this launch (pid {}) — refused",
                peer.map_or("?".to_owned(), |p| p.to_string())
            );
            return sys::send_with_fds(channel.as_raw_fd(), &[REFUSED], &[]).is_ok();
        }
        // The one place a connection upstream is made: to the security
        // context's listener, never to anything the proxy names.
        // The switch, now: a window opened after `vpn-zone frame hide` comes
        // up without the border, also in a program started before.
        let answer = match &self.frame {
            Some(settings) if !crate::frame::hidden(settings) => UPSTREAM,
            _ => UPSTREAM_BARE,
        };
        let sent = match UnixStream::connect(&self.upstream) {
            Ok(up) => sys::send_with_fds(channel.as_raw_fd(), &[answer], &[up.as_raw_fd()]),
            Err(_) => sys::send_with_fds(channel.as_raw_fd(), &[REFUSED], &[]),
        };
        sent.is_ok()
    }
}

/// Whether the process that connected on `client` belongs to this launch:
/// this process or one below it (review 2026-09-25).
///
/// The zone's directory of sockets is every launch's of that zone, and it is
/// in the zone whole: a program of another launch can connect to this one's
/// socket. The compositor takes the pid of a window from the connection
/// upstream, which is this process's, so such a window would carry this
/// launch's pid — its container and program in `vpn-zone focused`, the target
/// of the window menu. Only the launch's own processes are passed on. That is
/// sound because this process is a subreaper ([`Proxy::take_over`]): an orphan
/// of the program is given to it, and nothing of the launch ever leaves its
/// subtree. The peer is held by a pidfd — the kernel's own (`SO_PEERPIDFD`)
/// where there is one — while its ancestry is read ([`sys::descends_from`]).
fn of_this_launch(client: RawFd) -> bool {
    // SAFETY: getpid takes nothing and cannot fail.
    let me = unsafe { libc::getpid() };
    let Some(pid) = sys::peer_pid(client) else {
        return false;
    };
    let Some(pidfd) = sys::peer_pidfd(client, pid) else {
        return false;
    };
    sys::descends_from(pid, &pidfd, me)
}

/// `waitpid`, retried on EINTR. `None` when there is nothing (left) to wait for.
fn wait(pid: libc::pid_t, status: &mut libc::c_int, flags: libc::c_int) -> Option<libc::pid_t> {
    loop {
        // SAFETY: `status` is a valid pointer for the duration of the call.
        let r = unsafe { libc::waitpid(pid, status, flags) };
        if r >= 0 {
            return Some(r);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return None;
        }
    }
}

fn describe(status: libc::c_int) -> String {
    if libc::WIFSIGNALED(status) {
        format!("signal {}", libc::WTERMSIG(status))
    } else {
        format!("code {}", libc::WEXITSTATUS(status))
    }
}

// --- THE PROXY'S SIDE -------------------------------------------------------

/// What the forked proxy is given to draw with: the frame, the title's text
/// and the font's bytes (read by the supervisor: none when the title is off
/// or the font cannot be read).
struct Drawing {
    frame: Frame,
    title: String,
    font: Option<Vec<u8>>,
}

/// The font the package was built with (`crate::wl_title::FONT`), read whole.
/// `None`, said once, when there is none: the title strip goes without its
/// text — the zone's colour is still there.
fn read_font() -> Option<Vec<u8>> {
    let read = || -> Result<Vec<u8>, String> {
        let path = crate::wl_title::FONT.ok_or("the build names no font")?;
        let size = fs::metadata(path)
            .map_err(|e| format!("{path}: {e}"))?
            .len();
        if size > crate::wl_title::MAX_FONT_BYTES {
            return Err(format!("{path}: {size} bytes"));
        }
        fs::read(path).map_err(|e| format!("{path}: {e}"))
    };
    read()
        .map_err(|e| eprintln!("wl-sandbox: no font for the window title ({e}) — the title strip goes without its text"))
        .ok()
}

/// Whoever asked to hear of the program's first window (the picker, through
/// `wl-sandbox`: `crate::picker`'s hand-over): the write end of its pipe, or
/// -1. One word, once, from whichever connection opens a window first.
static OPENED: AtomicI32 = AtomicI32::new(-1);

/// The program opened a window — an `xdg_toplevel`, framed or not: said,
/// once, to whoever asked (`OPENED`). A program that hands its launch over to
/// the copy that runs never does; one that opens its own always does — told
/// apart by the event, not by how long it took.
pub(crate) fn window_opened() {
    let fd = OPENED.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        // SAFETY: our own descriptor, one byte from a constant; closed after.
        unsafe {
            libc::write(fd, [crate::wl_sandbox::WORD_OPENED].as_ptr().cast(), 1);
            libc::close(fd);
        }
    }
}

/// A connection without a frame has no `crate::wl_frame` watching its
/// windows: this much does, for [`window_opened`].
struct OpeningWmBase;

impl XdgWmBaseHandler for OpeningWmBase {
    fn handle_get_xdg_surface(
        &mut self,
        slf: &Rc<XdgWmBase>,
        id: &Rc<XdgSurface>,
        surface: &Rc<WlSurface>,
    ) {
        slf.send_get_xdg_surface(id, surface);
        id.set_handler(OpeningSurface);
    }
}

struct OpeningSurface;

impl XdgSurfaceHandler for OpeningSurface {
    fn handle_get_toplevel(&mut self, slf: &Rc<XdgSurface>, id: &Rc<XdgToplevel>) {
        slf.send_get_toplevel(id);
        window_opened();
    }
}

/// The forked proxy: confine, report ready, serve.
fn child(
    listener: UnixListener,
    channel: UnixStream,
    supervisor: libc::pid_t,
    drawing: Option<Drawing>,
    opened: Option<OwnedFd>,
) -> libc::c_int {
    let opened = opened.map(IntoRawFd::into_raw_fd);
    let border = match confine(&listener, &channel, supervisor, drawing, opened) {
        Ok(border) => border,
        Err(e) => {
            eprintln!("wl-sandbox: the Wayland proxy cannot confine itself: {e}");
            return 1;
        }
    };
    if sys::send_with_fds(channel.as_raw_fd(), &[READY], &[]).is_err() {
        return 1;
    }
    serve(listener, channel, border)
}

/// The zone's frame as the proxy draws it: the border's width and the
/// colour's one pixel ([`pixel`]); the title's mode and, when there is a font
/// to draw it with, its text ([`title_memfd`]).
pub(crate) struct Border {
    pub width: i32,
    pub pixel: Rc<OwnedFd>,
    pub title: TitleMode,
    pub text: Option<Rc<Text>>,
}

/// Everything of the frame that has to be made before the filter: the
/// pixel, and the title's line and memfd. `None` when the pixel cannot be
/// made (no frame then, and it is said); a title that cannot be made is a
/// strip without its text.
fn prepare_border(drawing: Drawing) -> Option<Border> {
    let pixel = match pixel(drawing.frame.color) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("wl-sandbox: cannot make the border's colour ({e}) — windows go without it");
            return None;
        }
    };
    let text = drawing
        .font
        .filter(|_| drawing.frame.title != TitleMode::Off)
        .and_then(|font| Prepared::new(font, &drawing.title))
        .and_then(|prepared| match title_memfd(prepared.memfd_size()) {
            Ok((memfd, writer)) => Some(Rc::new(Text::new(
                prepared,
                drawing.frame.color,
                memfd,
                writer,
            ))),
            Err(e) => {
                eprintln!("wl-sandbox: cannot make the title's memory ({e}) — no text in it");
                None
            }
        });
    Some(Border {
        width: drawing.frame.width,
        pixel: Rc::new(pixel),
        title: drawing.frame.title,
        text,
    })
}

/// The title's pixels for the compositor (`crate::wl_title`): a memfd of
/// `size` bytes, sealed against shrinking and growing like [`pixel`]'s, and a
/// second descriptor of it the proxy writes with (`pwrite` — the filter has
/// no `fcntl(F_DUPFD)` to make one later). Never mapped here.
fn title_memfd(size: usize) -> io::Result<(OwnedFd, OwnedFd)> {
    let fd = sealed_memfd(c"vz-title", &[], size)?;
    let writer = fd.try_clone()?;
    Ok((fd, writer))
}

/// The border's colour for the compositor: a 3×3 square of XRGB8888 pixels
/// (`wl_frame::PIXEL_SIDE`: the strips show its middle one) in a memfd,
/// sealed against shrinking (a compositor maps it; a pool that shrank under
/// it would be a SIGBUS there) and growing, and the seals themselves sealed.
/// Not against writing: libwayland-server maps a pool writable, and a write
/// seal would make the compositor refuse it. Nobody but the proxy and the
/// compositor ever has it. Made before the filter is loaded — the filter has
/// no `memfd_create` — and never mapped here: written with `write`.
fn pixel(color: Rgb) -> io::Result<OwnedFd> {
    let bytes = color
        .xrgb8888()
        .repeat((crate::wl_frame::PIXEL_BYTES / 4) as usize);
    sealed_memfd(c"vz-frame", &bytes, bytes.len())
}

/// A memfd of `size` bytes beginning with `bytes`, sealed as [`pixel`] says.
fn sealed_memfd(name: &std::ffi::CStr, bytes: &[u8], size: usize) -> io::Result<OwnedFd> {
    // SAFETY: memfd_create reads a NUL-terminated name that outlives the
    // call; the descriptor it returns is owned by nobody else.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: just returned, ours alone.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: writes the bytes of a live slice to a descriptor we own.
    let n = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
    if n != bytes.len() as isize {
        return Err(io::Error::other("short write"));
    }
    let size = libc::off_t::try_from(size).map_err(|_| io::Error::other("too big"))?;
    // SAFETY: ftruncate with no pointer, on a descriptor we own.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    // SAFETY: fcntl with an int argument on a descriptor we own.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Everything that makes the process what [`filter`] assumes, in an order
/// that leaves it no moment to be anything else: a name, not dumpable, dying
/// with its supervisor, no descriptor but its own and the standard three, the
/// limits, the frame's pixel and title ([`prepare_border`]), the filter.
///
/// The frame is the only thing that may fail without failing the proxy: the
/// program is then served as in stage 1, without a border, and it is said.
fn confine(
    listener: &UnixListener,
    channel: &UnixStream,
    supervisor: libc::pid_t,
    drawing: Option<Drawing>,
    opened: Option<RawFd>,
) -> Result<Option<Border>, String> {
    let name = std::ffi::CString::new(PROCESS_NAME).map_err(|e| e.to_string())?;
    // SAFETY: PR_SET_NAME reads a NUL-terminated string that outlives the call.
    unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0) };
    // SAFETY: prctl with these arguments takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(format!("PR_SET_DUMPABLE: {}", io::Error::last_os_error()));
    }
    // The proxy does not outlive its supervisor (review 2026-09-25). A
    // window's pid upstream is the supervisor's; a proxy that went on
    // serving after it died would leave its windows with the number of a
    // dead process, which the next process to get it — a host one, say —
    // would lend its network in `vpn-zone focused`. A process of the zone
    // may kill the supervisor (kill(2) asks only for the uid, LEAK-MODEL
    // §16): then the display goes too. Fail-closed. Checked after it is set:
    // a supervisor that died before would not have been seen doing it.
    // SAFETY: prctl with these arguments takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(format!("PR_SET_PDEATHSIG: {}", io::Error::last_os_error()));
    }
    // SAFETY: getppid takes nothing and cannot fail.
    if unsafe { libc::getppid() } != supervisor {
        return Err("the supervisor is gone".to_owned());
    }
    let mut keep = vec![0, 1, 2, listener.as_raw_fd(), channel.as_raw_fd()];
    keep.extend(opened);
    close_all_but(&mut keep)?;
    if let Some(fd) = opened {
        OPENED.store(fd, Ordering::SeqCst);
    }
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("O_NONBLOCK: {e}"))?;
    limit(libc::RLIMIT_NOFILE, MAX_FDS)?;
    limit(libc::RLIMIT_DATA, MAX_DATA)?;
    let border = drawing.and_then(prepare_border);
    filter(ScmpAction::KillProcess, title_writer(border.as_ref()))
        .and_then(|f| f.load())
        .map_err(|e| format!("seccomp: {e}"))?;
    Ok(border)
}

/// Close every descriptor but `keep`. `close_range(2)`: one call per gap,
/// and nothing to enumerate — the proxy must not start with a descriptor it
/// does not know about (an inherited `WAYLAND_SOCKET` is the compositor's
/// unrestricted connection). Sorts `keep` in place and allocates nothing:
/// it runs in a fresh child.
fn close_all_but(keep: &mut [RawFd]) -> Result<(), String> {
    keep.sort_unstable();
    let mut from: libc::c_uint = 0;
    for &fd in keep.iter() {
        let Ok(fd) = libc::c_uint::try_from(fd) else {
            continue;
        };
        if fd > from {
            // SAFETY: close_range takes two numbers and flags; it closes
            // descriptors nobody in this (single-threaded) child still uses.
            if unsafe { libc::close_range(from, fd - 1, 0) } != 0 {
                return Err(format!("close_range: {}", io::Error::last_os_error()));
            }
        }
        from = from.max(fd.saturating_add(1));
    }
    // SAFETY: as above, to the end of the table.
    if unsafe { libc::close_range(from, libc::c_uint::MAX, 0) } != 0 {
        return Err(format!("close_range: {}", io::Error::last_os_error()));
    }
    Ok(())
}

/// Lower a resource limit (soft and hard) to `max`, never raise it.
fn limit(resource: libc::__rlimit_resource_t, max: libc::rlim_t) -> Result<(), String> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid pointer for the duration of each call.
    unsafe {
        if libc::getrlimit(resource, &mut lim) != 0 {
            return Err(format!("getrlimit: {}", io::Error::last_os_error()));
        }
        lim.rlim_max = lim.rlim_max.min(max);
        lim.rlim_cur = lim.rlim_max;
        if libc::setrlimit(resource, &lim) != 0 {
            return Err(format!("setrlimit: {}", io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// The proxy's seccomp filter: an ALLOW-list, `default` for everything else
/// (the proxy is started with `KillProcess`: a call outside this list means
/// it is broken or taken over, and neither should go on forwarding).
///
/// What it needs and nothing more: its descriptors (read, write, close,
/// recvmsg, sendmsg, accept4 on the listener it has), waiting (poll, epoll —
/// each wl-proxy State polls its own epoll), the eventfd and pipe a State
/// makes, memory (anonymous and never executable), futex, the clock and
/// random numbers the runtime reads, and leaving. `ioctl` only for
/// `TIOCOUTQ`. `pwrite64` for the title's pixels (`crate::wl_title`), and
/// only to `title` — the descriptor they are written with, made before the
/// filter (none: no `pwrite64` at all). Not to any descriptor (review
/// 2026-09-25): `write` only goes forward from where a file is, and there is
/// no `lseek`, but `pwrite64` rewrites any offset — of the border's pixel
/// memfd (its colour, for every window of the launch; a `write` there would
/// have to grow it, which its seal refuses), of a file the owner sent
/// stdout or stderr to. Not there: open*, socket, connect, bind, exec*,
/// clone/fork, ptrace, kill, prctl, setrlimit, mount, memfd_create,
/// ftruncate, lseek, anything with a path.
pub fn filter(
    default: ScmpAction,
    title: Option<RawFd>,
) -> Result<ScmpFilterContext, libseccomp::error::SeccompError> {
    let mut ctx = ScmpFilterContext::new(default)?;
    ctx.set_ctl_nnp(true)?;
    // A foreign architecture's table (int 0x80 on x86_64) is not in the
    // filter at all: whatever comes through it gets the same answer.
    ctx.set_act_badarch(default)?;
    let allow = [
        "read",
        "write",
        "close",
        "recvmsg",
        "sendmsg",
        "accept4",
        "poll",
        "ppoll",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        "epoll_pwait2",
        "eventfd2",
        "pipe2",
        "munmap",
        "mremap",
        "brk",
        "madvise",
        "futex",
        "getrandom",
        "clock_gettime",
        "gettimeofday",
        "sched_yield",
        "getpid",
        "gettid",
        "rt_sigreturn",
        "rt_sigprocmask",
        "sigaltstack",
        "restart_syscall",
        "exit",
        "exit_group",
    ];
    for name in allow {
        // A name this architecture does not have (`poll`, `epoll_wait` on
        // arm64) is simply not there to allow.
        if let Ok(call) = ScmpSyscall::from_name(name) {
            ctx.add_rule(ScmpAction::Allow, call)?;
        }
    }
    let exec = libc::PROT_EXEC as u64;
    let no_exec = ScmpArgCompare::new(2, ScmpCompareOp::MaskedEqual(exec), 0);
    // Anonymous memory only: the descriptor argument is -1. Masked to 32
    // bits: an `int` -1 may reach the register sign-extended or not.
    let anonymous = ScmpArgCompare::new(4, ScmpCompareOp::MaskedEqual(0xffff_ffff), 0xffff_ffff);
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("mmap")?,
        &[no_exec, anonymous],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("mprotect")?,
        &[no_exec],
    )?;
    // `F_GETFD` only: std asks it of every descriptor it closes when built
    // with debug assertions (an `OwnedFd` that is not open is a bug).
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("fcntl")?,
        &[ScmpArgCompare::new(
            1,
            ScmpCompareOp::MaskedEqual(0xffff_ffff),
            libc::F_GETFD as u64,
        )],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("ioctl")?,
        &[ScmpArgCompare::new(
            1,
            ScmpCompareOp::MaskedEqual(0xffff_ffff),
            libc::TIOCOUTQ,
        )],
    )?;
    // Masked to 32 bits, like the descriptor above: an `int`.
    if let Some(Ok(fd)) = title.map(u64::try_from) {
        ctx.add_rule_conditional(
            ScmpAction::Allow,
            ScmpSyscall::from_name("pwrite64")?,
            &[ScmpArgCompare::new(
                0,
                ScmpCompareOp::MaskedEqual(0xffff_ffff),
                fd,
            )],
        )?;
    }
    Ok(ctx)
}

/// The descriptor the title's pixels are written with, when the frame has a
/// title with text: the one [`filter`] lets `pwrite64` write to.
fn title_writer(border: Option<&Border>) -> Option<RawFd> {
    border.and_then(|b| b.text.as_ref()).map(|t| t.writer())
}

/// Serve until the supervisor has said the program is gone and the last
/// connection has closed. Runs confined; see [`filter`] for what it may call.
fn serve(listener: UnixListener, channel: UnixStream, border: Option<Border>) -> libc::c_int {
    // "Cannot draw" is said once for the launch, not once per connection.
    let warned = Rc::new(Cell::new(false));
    let mut listener = Some(listener);
    let mut channel = Some(channel);
    // Accepted, their upstream asked for, in the order asked.
    let mut waiting: VecDeque<OwnedFd> = VecDeque::new();
    let mut conns: Vec<Conn> = Vec::new();
    // Out of descriptors: accepting is paused until then.
    let mut paused: Option<Instant> = None;
    loop {
        if channel.is_none() && conns.is_empty() {
            return 0;
        }
        conns.retain_mut(Conn::flush);
        let now = Instant::now();
        if paused.is_some_and(|until| now >= until) {
            paused = None;
        }
        let accepting = listener.as_ref().filter(|_| paused.is_none());
        let mut fds = Vec::with_capacity(2 + conns.len());
        if let Some(l) = accepting {
            fds.push(pollfd(l.as_raw_fd()));
        }
        if let Some(c) = &channel {
            fds.push(pollfd(c.as_raw_fd()));
        }
        let first_conn = fds.len();
        fds.extend(conns.iter().map(|c| pollfd(c.state.poll_fd().as_raw_fd())));
        let mut timeout = if conns.iter().any(|c| c.stopped) {
            RECHECK_MS
        } else {
            -1
        };
        if let Some(until) = paused {
            let left = until.saturating_duration_since(now).as_millis();
            let left = libc::c_int::try_from(left)
                .unwrap_or(libc::c_int::MAX)
                .max(1);
            timeout = if timeout < 0 { left } else { timeout.min(left) };
        }
        match poll(&mut fds, timeout) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("wl-sandbox: the Wayland proxy cannot wait: {e}");
                return 1;
            }
        }
        let mut at = 0;
        if let Some(l) = accepting {
            if fds[at].revents != 0 {
                let busy = conns.len();
                if !accept(l, channel.as_ref(), &mut waiting, busy) {
                    // Out of descriptors: this launch holds too many (its
                    // own: nobody else is passed on). It keeps what it has;
                    // a new connection waits in the backlog, and accepting
                    // is tried again in a while — a descriptor freed by a
                    // connection that ended is one to take it with.
                    eprintln!(
                        "wl-sandbox: the Wayland proxy is out of descriptors — new connections wait"
                    );
                    paused = Some(Instant::now() + ACCEPT_PAUSE);
                }
            }
            at += 1;
        }
        if let Some(c) = &channel {
            if fds[at].revents != 0 {
                match answer(c) {
                    Answer::Upstream(up, framed) => {
                        if let Some(client) = waiting.pop_front() {
                            let border = border.as_ref().filter(|_| framed);
                            match Conn::open(client, up, border, &warned) {
                                Ok(conn) => conns.push(conn),
                                Err(e) => eprintln!("wl-sandbox: the Wayland proxy: {e}"),
                            }
                        }
                    }
                    Answer::Refused => {
                        waiting.pop_front();
                    }
                    Answer::Nothing => {}
                    Answer::Closed => {
                        // The program has exited: no new connections, those
                        // waiting are dropped. (A supervisor that died took
                        // this process with it: PR_SET_PDEATHSIG.)
                        channel = None;
                        listener = None;
                        waiting.clear();
                    }
                }
            }
        }
        // Those opened just now were not polled: their turn is the next round.
        let polled = &fds[first_conn..];
        for (conn, pfd) in conns.iter_mut().zip(polled) {
            if pfd.revents != 0 || conn.stopped {
                conn.dispatch();
            }
        }
        conns.retain(Conn::alive);
    }
}

/// Take what is waiting on the listener. False when out of descriptors.
fn accept(
    listener: &UnixListener,
    channel: Option<&UnixStream>,
    waiting: &mut VecDeque<OwnedFd>,
    busy: usize,
) -> bool {
    for _ in 0..MAX_WAITING {
        let sock = match accept_nonblocking(listener.as_raw_fd()) {
            Ok(sock) => sock,
            Err(e) => return !matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)),
        };
        // Over the limits, or nobody to ask for an upstream: closed at once,
        // so that the client fails now instead of hanging.
        let Some(channel) = channel else {
            continue;
        };
        if busy + waiting.len() >= MAX_CONNECTIONS || waiting.len() >= MAX_WAITING {
            continue;
        }
        // With the socket, for the supervisor to ask the kernel who is on its
        // other end: only this launch's own processes are passed on.
        if sys::send_with_fds(channel.as_raw_fd(), &[CONNECT], &[sock.as_raw_fd()]).is_ok() {
            waiting.push_back(sock);
        }
    }
    true
}

enum Answer {
    /// The connection upstream, and whether to draw the border on it.
    Upstream(OwnedFd, bool),
    Refused,
    Nothing,
    Closed,
}

fn answer(channel: &UnixStream) -> Answer {
    let mut byte = [0u8; 1];
    match sys::recv_into_with_fds(channel.as_raw_fd(), &mut byte, 1) {
        // Without its descriptor (out of descriptors here: the kernel closed
        // it) the answer is as good as a refusal — for this one client.
        Ok((1, mut fds, _)) if byte[0] == UPSTREAM || byte[0] == UPSTREAM_BARE => match fds.pop() {
            Some(up) => Answer::Upstream(up, byte[0] == UPSTREAM),
            None => Answer::Refused,
        },
        Ok((1, _, _)) if byte[0] == REFUSED => Answer::Refused,
        Ok((0, _, _)) => Answer::Closed,
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Answer::Nothing,
        // The supervisor never sends anything else: a broken channel.
        _ => Answer::Closed,
    }
}

/// One program connection and its own connection upstream.
struct Conn {
    state: Rc<State>,
    client: Rc<Client>,
    socket: Rc<OwnedFd>,
    /// Set by the handlers: the client is gone or refused.
    closing: Rc<Cell<bool>>,
    /// The zone's frame on it, when drawn: its windows are counted.
    frames: Option<Rc<Frames>>,
    /// Its requests are not being read: it is not reading its events.
    stopped: bool,
    dispatches: u32,
    scratch: Vec<Rc<dyn Object>>,
}

impl Conn {
    fn open(
        client: OwnedFd,
        upstream: OwnedFd,
        border: Option<&Border>,
        warned: &Rc<Cell<bool>>,
    ) -> Result<Self, String> {
        let upstream = Rc::new(upstream);
        let state = State::builder(BASELINE)
            .with_server_fd(&upstream)
            .build()
            .map_err(|e| format!("cannot start a connection: {e}"))?;
        let socket = Rc::new(client);
        let client = match state.add_client(&socket) {
            Ok(client) => client,
            Err(e) => {
                state.destroy();
                return Err(format!("cannot take a connection: {e}"));
            }
        };
        let closing = Rc::new(Cell::new(false));
        state.set_handler(Relay {
            socket: socket.clone(),
        });
        client.set_handler(Gone {
            closing: closing.clone(),
        });
        // Before any request of the program is read: the border's own
        // registry goes upstream first, so that its answer is in before the
        // compositor's first configure of any window (`crate::wl_frame`).
        let frames = border.map(|b| Frames::install(&client, b, warned.clone()));
        client.display().set_handler(Display {
            closing: closing.clone(),
            frames: frames.clone(),
        });
        Ok(Self {
            state,
            client,
            socket,
            closing,
            frames,
            stopped: false,
            dispatches: 0,
            scratch: Vec::new(),
        })
    }

    fn alive(&self) -> bool {
        !self.closing.get() && self.state.is_not_destroyed()
    }

    /// Write out what is queued, before going to sleep. False when dead.
    fn flush(&mut self) -> bool {
        self.alive() && self.state.before_poll().is_ok()
    }

    fn dispatch(&mut self) {
        if self.state.dispatch_available().is_err() {
            return;
        }
        self.dispatches = self.dispatches.wrapping_add(1);
        // Back-pressure: a client that does not read is not read either.
        let queued = outq(self.socket.as_raw_fd());
        if !self.stopped && queued >= OUTQ_HIGH {
            self.stopped = true;
            self.client.set_suspended(true);
        } else if self.stopped && queued <= OUTQ_LOW {
            self.stopped = false;
            self.client.set_suspended(false);
        }
        // The frame's own objects upstream are not in the program's table,
        // and a program makes ~20 of them per 3 of its own (a toplevel's
        // strips, title and text, `crate::wl_frame::Framed`): counted as
        // windows, at every dispatch — a Cell read, and one dispatch frames
        // at most ~170 new windows (48 bytes of requests each).
        if self
            .frames
            .as_ref()
            .is_some_and(|f| f.framed() > MAX_FRAMED)
        {
            refuse(&self.client, &self.closing, NO_MEMORY, "too many windows");
            let _ = self.state.before_poll();
            return;
        }
        if self.dispatches.is_multiple_of(COUNT_OBJECTS_EVERY) {
            self.scratch.clear();
            self.client.objects(&mut self.scratch);
            let count = self.scratch.len();
            self.scratch.clear();
            if count > MAX_OBJECTS {
                refuse(&self.client, &self.closing, NO_MEMORY, "too many objects");
                let _ = self.state.before_poll();
            }
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        // The State's objects and handlers point at each other: without this
        // the connection upstream would outlive the program's, and its
        // windows with it.
        self.state.destroy();
    }
}

/// Tell the client why, and end it. Like libwayland: an error event, then
/// the connection is closed (after this dispatch has written it out).
fn refuse(client: &Rc<Client>, closing: &Cell<bool>, code: u32, why: &str) {
    let display = client.display().clone();
    display.send_error(display.clone(), code, why);
    // Nothing more of it is read.
    client.set_suspended(true);
    closing.set(true);
}

struct Gone {
    closing: Rc<Cell<bool>>,
}

impl ClientHandler for Gone {
    fn disconnected(self: Box<Self>) {
        self.closing.set(true);
    }
}

/// A protocol error from the compositor ends the connection (wl-proxy
/// destroys the State at once); the program gets the error itself, written
/// straight to its socket, so that it can say what went wrong.
struct Relay {
    socket: Rc<OwnedFd>,
}

impl StateHandler for Relay {
    fn display_error(
        self: Box<Self>,
        object: Option<&Rc<dyn Object>>,
        _server_id: u32,
        error: u32,
        msg: &str,
    ) {
        let id = object.and_then(|o| o.client_id()).unwrap_or(1);
        // Non-blocking socket: a client that does not read loses the text,
        // not the proxy its time. If an earlier message was cut short, the
        // client reads garbage instead — it is being disconnected either way.
        let _ = sys::send_with_fds(
            self.socket.as_raw_fd(),
            &display_error_message(id, error, msg),
            &[],
        );
    }
}

struct Display {
    closing: Rc<Cell<bool>>,
    frames: Option<Rc<Frames>>,
}

impl WlDisplayHandler for Display {
    fn handle_get_registry(&mut self, slf: &Rc<WlDisplay>, registry: &Rc<WlRegistry>) {
        registry.set_handler(Registry {
            closing: self.closing.clone(),
            shown: HashMap::new(),
            frames: self.frames.clone(),
        });
        slf.send_get_registry(registry);
    }
}

/// A global this registry was shown.
struct Shown {
    interface: ObjectInterface,
    version: u32,
    removed: bool,
}

/// Every global wl-proxy passes (it has already dropped the ones it does not
/// know and capped the versions) is passed on and remembered; a bind must name
/// one of them, with its interface and at most its version. A global removed
/// stays bindable here: a bind racing the removal is the compositor's to
/// answer, as without the proxy.
struct Registry {
    closing: Rc<Cell<bool>>,
    shown: HashMap<u32, Shown>,
    /// The border, which watches some of what the program binds.
    frames: Option<Rc<Frames>>,
}

impl WlRegistryHandler for Registry {
    fn handle_global(
        &mut self,
        slf: &Rc<WlRegistry>,
        name: u32,
        interface: ObjectInterface,
        version: u32,
    ) {
        if self.shown.len() >= MAX_GLOBALS {
            self.shown.retain(|_, g| !g.removed);
            if self.shown.len() >= MAX_GLOBALS {
                return;
            }
        }
        self.shown.insert(
            name,
            Shown {
                interface,
                version,
                removed: false,
            },
        );
        slf.send_global(name, interface, version);
    }

    fn handle_global_remove(&mut self, slf: &Rc<WlRegistry>, name: u32) {
        if let Some(g) = self.shown.get_mut(&name) {
            if !g.removed {
                g.removed = true;
                slf.send_global_remove(name);
            }
        }
    }

    fn handle_bind(&mut self, slf: &Rc<WlRegistry>, name: u32, id: Rc<dyn Object>) {
        let fits = self
            .shown
            .get(&name)
            .is_some_and(|g| g.interface == id.interface() && id.version() <= g.version);
        if fits {
            if let Some(frames) = &self.frames {
                frames.watch(&id);
            } else if OPENED.load(Ordering::Relaxed) >= 0 {
                if let Some(o) = id.try_downcast::<XdgWmBase>() {
                    o.set_handler(OpeningWmBase);
                }
            }
            slf.send_bind(name, id);
            return;
        }
        // What libwayland answers a bind to a name it does not have.
        if let Some(client) = slf.client() {
            let why = format!("invalid global {} ({name})", id.interface().name());
            refuse(&client, &self.closing, INVALID_OBJECT, &why);
        } else {
            self.closing.set(true);
        }
    }
}

/// `wl_display.error(object, code, message)` on the wire (host byte order).
fn display_error_message(object: u32, code: u32, message: &str) -> Vec<u8> {
    let mut end = message.len().min(MAX_ERROR_TEXT);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let text = &message.as_bytes()[..end];
    let len = text.len() + 1;
    let padded = len.div_ceil(4) * 4;
    let size = 8 + 4 + 4 + 4 + padded;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&1u32.to_ne_bytes());
    out.extend_from_slice(&((size as u32) << 16).to_ne_bytes());
    out.extend_from_slice(&object.to_ne_bytes());
    out.extend_from_slice(&code.to_ne_bytes());
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(text);
    out.resize(size, 0);
    out
}

// --- SMALL SYSCALL HELPERS ----------------------------------------------------

fn pollfd(fd: RawFd) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// `poll(2)`: how many descriptors are ready.
fn poll(fds: &mut [libc::pollfd], timeout_ms: libc::c_int) -> io::Result<usize> {
    // SAFETY: `fds` is a valid, exclusively borrowed array of `fds.len()`
    // pollfds for the duration of the call.
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// `accept4(SOCK_NONBLOCK | SOCK_CLOEXEC)`: wl-proxy never blocks on a
/// client, and neither does the error relay.
fn accept_nonblocking(listener: RawFd) -> io::Result<OwnedFd> {
    loop {
        // SAFETY: no address is asked for, so both pointers may be null.
        let fd = unsafe {
            libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            )
        };
        if fd >= 0 {
            // SAFETY: accept4 has just returned this descriptor; nobody else
            // owns it.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = io::Error::last_os_error();
        if !matches!(e.raw_os_error(), Some(libc::EINTR | libc::ECONNABORTED)) {
            return Err(e);
        }
    }
}

/// Bytes sent on a socket that its peer has not read (`TIOCOUTQ`, which is
/// `SIOCOUTQ` for a socket). 0 when it cannot be told.
fn outq(fd: RawFd) -> libc::c_int {
    let mut n: libc::c_int = 0;
    // SAFETY: TIOCOUTQ writes one int through the pointer, valid for the call.
    let r = unsafe { libc::ioctl(fd, libc::TIOCOUTQ, &mut n) };
    if r == 0 {
        n
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    #[test]
    fn hidden_protocols_are_not_in_the_build() {
        for name in HIDDEN {
            assert!(
                ObjectInterface::from_str(name).is_none(),
                "{name} is compiled into wl-proxy, so it would be passed on"
            );
        }
        // And what an ordinary program needs is.
        for name in [
            "wl_compositor",
            "wl_subcompositor",
            "wl_shm",
            "wl_seat",
            "wl_output",
            "wl_data_device_manager",
            "xdg_wm_base",
            "zxdg_decoration_manager_v1",
            "org_kde_kwin_server_decoration_manager",
            "zwp_linux_dmabuf_v1",
            "wl_drm",
            "wp_viewporter",
            "wp_fractional_scale_manager_v1",
            "wp_cursor_shape_manager_v1",
            "zwp_primary_selection_device_manager_v1",
            "zwp_text_input_manager_v3",
            "xdg_activation_v1",
            "zxdg_output_manager_v1",
            "wp_presentation",
            "zwp_pointer_constraints_v1",
            "zwp_relative_pointer_manager_v1",
            "zwp_idle_inhibit_manager_v1",
            "wp_linux_drm_syncobj_manager_v1",
            "zwp_tablet_manager_v2",
            "zxdg_exporter_v2",
        ] {
            assert!(
                ObjectInterface::from_str(name).is_some(),
                "{name} is not compiled in"
            );
        }
    }

    #[test]
    fn the_filter_builds_and_its_default_is_kill() {
        let path = std::env::temp_dir().join(format!("vz-wl-proxy-bpf-{}", std::process::id()));
        let file = fs::File::create(&path).unwrap();
        filter(ScmpAction::KillProcess, Some(3))
            .unwrap()
            .export_bpf(&file)
            .unwrap();
        let bpf = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(!bpf.is_empty() && bpf.len().is_multiple_of(8));
        // SECCOMP_RET_KILL_PROCESS is 0x80000000: some return carries it.
        let kills = bpf.chunks(8).any(|insn| {
            u16::from_ne_bytes([insn[0], insn[1]]) & 0x07 == 0x06
                && u32::from_ne_bytes([insn[4], insn[5], insn[6], insn[7]]) == 0x8000_0000
        });
        assert!(kills, "no kill in the program");
    }

    #[test]
    fn the_error_message_is_a_wire_message() {
        let m = display_error_message(7, 2, "bad");
        let word = |i: usize| u32::from_ne_bytes(m[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!(m.len() % 4, 0);
        assert_eq!(word(0), 1, "sent by wl_display");
        assert_eq!(word(1) >> 16, m.len() as u32);
        assert_eq!(word(1) & 0xffff, 0, "opcode error");
        assert_eq!((word(2), word(3), word(4)), (7, 2, 4));
        assert_eq!(&m[20..24], b"bad\0");
        // Cut at a character, never in one, and never longer than allowed.
        let long = "й".repeat(MAX_ERROR_TEXT);
        let m = display_error_message(1, 0, &long);
        let len = u32::from_ne_bytes(m[16..20].try_into().unwrap()) as usize;
        assert!(len - 1 <= MAX_ERROR_TEXT);
        assert!(std::str::from_utf8(&m[20..20 + len - 1]).is_ok());
    }

    #[test]
    fn close_all_but_keeps_what_it_is_told() {
        // In a child: closing descriptors of the test harness is not ours to do.
        let (mut a, b) = UnixStream::pair().unwrap();
        let (c, _d) = UnixStream::pair().unwrap();
        // SAFETY: the child of this multi-threaded process allocates nothing:
        // close_range, fcntl, write, _exit.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let ok = close_all_but(&mut [2, b.as_raw_fd()]).is_ok();
            // SAFETY: fcntl on a number only asks.
            let c_open = unsafe { libc::fcntl(c.as_raw_fd(), libc::F_GETFD) } >= 0;
            let b_open = unsafe { libc::fcntl(b.as_raw_fd(), libc::F_GETFD) } >= 0;
            let byte = [u8::from(ok && b_open && !c_open)];
            // SAFETY: a valid descriptor and buffer.
            unsafe { libc::write(b.as_raw_fd(), byte.as_ptr().cast(), 1) };
            unsafe { libc::_exit(0) };
        }
        let mut got = [0u8];
        a.read_exact(&mut got).unwrap();
        let mut status = 0;
        wait(pid, &mut status, 0);
        assert_eq!(got[0], 1, "kept the wrong descriptors");
    }

    // --- a proxy between a real client and a fake compositor ----------------

    /// A compositor that knows two requests: `wl_display.get_registry` (it
    /// announces `globals` on the new registry) and `wl_display.sync` (done,
    /// then delete_id). Every bind is remembered.
    fn fake_compositor(
        mut sock: UnixStream,
        globals: &'static [(&'static str, u32)],
        binds: mpsc::Sender<u32>,
    ) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let word = |b: &[u8], i: usize| u32::from_ne_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        loop {
            let n = match sock.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            while buf.len() >= 8 {
                let size = (word(&buf, 1) >> 16) as usize;
                if buf.len() < size {
                    break;
                }
                let msg: Vec<u8> = buf.drain(..size).collect();
                let (object, opcode) = (word(&msg, 0), word(&msg, 1) & 0xffff);
                let mut out = Vec::new();
                match (object, opcode) {
                    (1, 1) => {
                        let registry = word(&msg, 2);
                        for (name, (iface, version)) in globals.iter().enumerate() {
                            event(&mut out, registry, 0, |a| {
                                a.extend_from_slice(&(name as u32 + 1).to_ne_bytes());
                                string(a, iface);
                                a.extend_from_slice(&version.to_ne_bytes());
                            });
                        }
                    }
                    (1, 0) => {
                        let callback = word(&msg, 2);
                        event(&mut out, callback, 0, |a| {
                            a.extend_from_slice(&7u32.to_ne_bytes())
                        });
                        event(&mut out, 1, 1, |a| {
                            a.extend_from_slice(&callback.to_ne_bytes())
                        });
                    }
                    (_, 0) if size > 12 => {
                        // wl_registry.bind(name, interface, version, id)
                        let _ = binds.send(word(&msg, 2));
                    }
                    _ => {}
                }
                if sock.write_all(&out).is_err() {
                    return;
                }
            }
        }
    }

    fn event(out: &mut Vec<u8>, object: u32, opcode: u32, args: impl FnOnce(&mut Vec<u8>)) {
        let mut a = Vec::new();
        args(&mut a);
        let size = 8 + a.len() as u32;
        out.extend_from_slice(&object.to_ne_bytes());
        out.extend_from_slice(&((size << 16) | opcode).to_ne_bytes());
        out.extend_from_slice(&a);
    }

    fn string(out: &mut Vec<u8>, s: &str) {
        let len = s.len() + 1;
        out.extend_from_slice(&(len as u32).to_ne_bytes());
        out.extend_from_slice(s.as_bytes());
        out.resize(out.len() + len.div_ceil(4) * 4 - s.len(), 0);
    }

    const GLOBALS: &[(&str, u32)] = &[
        ("wl_compositor", 6),
        ("wp_drm_lease_device_v1", 1),
        ("xdg_wm_base", 99),
        ("mutter_x11_interop", 1),
        ("zwlr_screencopy_manager_v1", 3),
        ("wl_shm", 1),
    ];

    /// The proxy's own loop, under its own filter (answering EPERM instead of
    /// killing, so that a missing call fails this test rather than the whole
    /// run), in a thread: the filter is loaded into that thread only. The
    /// test plays the supervisor and the compositor.
    struct Rig {
        dir: PathBuf,
        path: PathBuf,
        channel: Option<UnixStream>,
        proxy: Option<std::thread::JoinHandle<libc::c_int>>,
        binds: mpsc::Receiver<u32>,
        binds_tx: mpsc::Sender<u32>,
    }

    impl Rig {
        fn new(tag: &str) -> Self {
            Self::with_border(tag, None)
        }

        /// The proxy with the zone's border and no title: `(width, colour)`.
        fn with_border(tag: &str, border: Option<(i32, Rgb)>) -> Self {
            Self::with_drawing(
                tag,
                border.map(|(width, color)| Drawing {
                    frame: Frame {
                        color,
                        width,
                        title: TitleMode::Off,
                    },
                    title: String::new(),
                    font: None,
                }),
            )
        }

        /// The proxy with a frame. What the frame needs is made in the
        /// proxy's thread before its filter, as `confine` does.
        fn with_drawing(tag: &str, drawing: Option<Drawing>) -> Self {
            let dir =
                std::env::temp_dir().join(format!("vz-wl-proxy-test-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("sock");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let (ours, theirs) = UnixStream::pair().unwrap();
            let proxy = std::thread::spawn(move || {
                let border = drawing.map(|d| prepare_border(d).unwrap());
                filter(
                    ScmpAction::Errno(libc::EPERM),
                    title_writer(border.as_ref()),
                )
                .unwrap()
                .load()
                .unwrap();
                serve(listener, theirs, border)
            });
            let (binds_tx, binds) = mpsc::channel();
            Self {
                dir,
                path,
                channel: Some(ours),
                proxy: Some(proxy),
                binds,
                binds_tx,
            }
        }

        /// A client connects; the proxy asks for an upstream; the test hands
        /// it one to a fake compositor.
        fn connect(&self) -> UnixStream {
            let client = UnixStream::connect(&self.path).unwrap();
            let channel = self.channel.as_ref().unwrap();
            let mut byte = [0u8];
            (&*channel).read_exact(&mut byte).unwrap();
            assert_eq!(byte[0], CONNECT);
            let (up, compositor) = UnixStream::pair().unwrap();
            let binds = self.binds_tx.clone();
            std::thread::spawn(move || fake_compositor(compositor, GLOBALS, binds));
            sys::send_with_fds(channel.as_raw_fd(), &[UPSTREAM], &[up.as_raw_fd()]).unwrap();
            client
        }

        fn finish(mut self) -> libc::c_int {
            self.channel = None;
            let code = self.proxy.take().unwrap().join().unwrap();
            let _ = fs::remove_dir_all(&self.dir);
            code
        }
    }

    /// Globals the client sees through the proxy, by a real client library.
    fn globals_of(client: UnixStream) -> Vec<(String, u32)> {
        use wayland_client::globals::registry_queue_init;
        let conn = wayland_client::Connection::from_socket(client).unwrap();
        let (globals, _queue) = registry_queue_init::<NoState>(&conn).unwrap();
        globals
            .contents()
            .clone_list()
            .into_iter()
            .map(|g| (g.interface, g.version))
            .collect()
    }

    struct NoState;
    impl
        wayland_client::Dispatch<
            wayland_client::protocol::wl_registry::WlRegistry,
            wayland_client::globals::GlobalListContents,
        > for NoState
    {
        fn event(
            _: &mut Self,
            _: &wayland_client::protocol::wl_registry::WlRegistry,
            _: wayland_client::protocol::wl_registry::Event,
            _: &wayland_client::globals::GlobalListContents,
            _: &wayland_client::Connection,
            _: &wayland_client::QueueHandle<Self>,
        ) {
        }
    }

    #[test]
    fn a_client_sees_the_known_globals_and_nothing_else() {
        let rig = Rig::new("globals");
        let seen = globals_of(rig.connect());
        let names: Vec<&str> = seen.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["wl_compositor", "xdg_wm_base", "wl_shm"],
            "{seen:?}"
        );
        // Capped at the baseline, not the compositor's 99.
        let wm = seen.iter().find(|(n, _)| n == "xdg_wm_base").unwrap().1;
        assert!(wm < 99, "xdg_wm_base at {wm}");
        assert_eq!(rig.finish(), 0);
    }

    /// Raw requests, to bind what the library would not.
    fn request(sock: &mut UnixStream, object: u32, opcode: u32, args: &[u8]) {
        let mut out = Vec::new();
        event(&mut out, object, opcode, |a| a.extend_from_slice(args));
        sock.write_all(&out).unwrap();
    }

    fn bind_args(name: u32, iface: &str, version: u32, id: u32) -> Vec<u8> {
        let mut a = name.to_ne_bytes().to_vec();
        string(&mut a, iface);
        a.extend_from_slice(&version.to_ne_bytes());
        a.extend_from_slice(&id.to_ne_bytes());
        a
    }

    /// Read events until one for `object` has come.
    fn await_event(sock: &mut UnixStream, object: u32) {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = Vec::new();
        loop {
            while buf.len() >= 8 {
                let size = (u32::from_ne_bytes(buf[4..8].try_into().unwrap()) >> 16) as usize;
                if buf.len() < size {
                    break;
                }
                let msg: Vec<u8> = buf.drain(..size).collect();
                if u32::from_ne_bytes(msg[..4].try_into().unwrap()) == object {
                    return;
                }
            }
            let mut chunk = [0u8; 4096];
            let n = sock.read(&mut chunk).unwrap();
            assert!(n > 0, "closed before an event for {object}");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read until EOF; the bytes that came.
    fn drain(sock: &mut UnixStream) -> Vec<u8> {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut all = Vec::new();
        let _ = sock.read_to_end(&mut all);
        all
    }

    #[test]
    fn a_hidden_global_cannot_be_bound_by_its_number() {
        let rig = Rig::new("bind");
        let mut client = rig.connect();
        request(&mut client, 1, 1, &2u32.to_ne_bytes()); // get_registry → 2
                                                         // Name 2 is the DRM lease device: never shown. Asked for as a
                                                         // wl_compositor, the only way to name it at all.
        request(&mut client, 2, 0, &bind_args(2, "wl_compositor", 1, 3));
        let got = drain(&mut client);
        let text = String::from_utf8_lossy(&got);
        assert!(text.contains("invalid global"), "no error: {text:?}");
        // Name 1 is wl_compositor, shown: bound, and the compositor got it.
        let mut client = rig.connect();
        request(&mut client, 1, 1, &2u32.to_ne_bytes());
        request(&mut client, 1, 0, &3u32.to_ne_bytes());
        // As a real client does: bind once the globals are in, which the
        // sync's `done` says.
        await_event(&mut client, 3);
        request(&mut client, 2, 0, &bind_args(1, "wl_compositor", 4, 4));
        assert_eq!(rig.binds.recv_timeout(Duration::from_secs(10)), Ok(1));
        // A version above the one shown is refused too.
        request(&mut client, 2, 0, &bind_args(1, "wl_compositor", 7, 6));
        let text = String::from_utf8_lossy(&drain(&mut client)).into_owned();
        assert!(text.contains("invalid global"), "{text:?}");
        assert!(
            rig.binds.try_recv().is_err(),
            "a refused bind reached the compositor"
        );
        assert_eq!(rig.finish(), 0);
    }

    #[test]
    fn after_the_program_exits_nothing_new_is_accepted_but_old_connections_live() {
        let rig = Rig::new("life");
        let old = rig.connect();
        let path = rig.path.clone();
        let Rig {
            dir,
            channel,
            proxy,
            ..
        } = rig;
        drop(channel);
        // The listener is closed: a new connection is refused (the path is
        // the supervisor's to remove).
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match UnixStream::connect(&path) {
                Err(_) => break,
                Ok(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Ok(_) => panic!("still accepting"),
            }
        }
        // The old one still works.
        assert_eq!(globals_of(old).len(), 3);
        // And the proxy is done when the last connection is.
        assert_eq!(proxy.unwrap().join().unwrap(), 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn when_the_client_goes_its_upstream_goes_too() {
        let rig = Rig::new("updown");
        let client = UnixStream::connect(&rig.path).unwrap();
        let channel = rig.channel.as_ref().unwrap();
        let mut byte = [0u8];
        (&*channel).read_exact(&mut byte).unwrap();
        let (up, mut compositor) = UnixStream::pair().unwrap();
        sys::send_with_fds(channel.as_raw_fd(), &[UPSTREAM], &[up.as_raw_fd()]).unwrap();
        drop(up);
        drop(client);
        // The compositor sees its end close: no window outlives its program.
        compositor
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut rest = Vec::new();
        assert!(
            compositor.read_to_end(&mut rest).is_ok(),
            "upstream still open"
        );
        assert_eq!(rig.finish(), 0);
    }

    #[test]
    fn when_the_compositor_goes_the_client_loses_its_display() {
        let rig = Rig::new("down");
        let mut client = UnixStream::connect(&rig.path).unwrap();
        let channel = rig.channel.as_ref().unwrap();
        let mut byte = [0u8];
        (&*channel).read_exact(&mut byte).unwrap();
        let (up, compositor) = UnixStream::pair().unwrap();
        sys::send_with_fds(channel.as_raw_fd(), &[UPSTREAM], &[up.as_raw_fd()]).unwrap();
        drop(up);
        drop(compositor);
        // The proxy may have closed the client already — it is closing it —,
        // and a write to a closed socket is EPIPE: what is checked is only
        // that nothing comes back (on a loaded runner the close came first,
        // and the unwrap of this write failed the test).
        let mut sync = Vec::new();
        event(&mut sync, 1, 0, |a| {
            a.extend_from_slice(&2u32.to_ne_bytes())
        });
        let _ = client.write_all(&sync);
        assert!(drain(&mut client).is_empty());
        assert_eq!(rig.finish(), 0);
    }

    #[test]
    fn a_refused_upstream_closes_the_client() {
        let rig = Rig::new("refused");
        let mut client = UnixStream::connect(&rig.path).unwrap();
        let channel = rig.channel.as_ref().unwrap();
        let mut byte = [0u8];
        (&*channel).read_exact(&mut byte).unwrap();
        sys::send_with_fds(channel.as_raw_fd(), &[REFUSED], &[]).unwrap();
        assert!(drain(&mut client).is_empty());
        assert_eq!(rig.finish(), 0);
    }

    /// Where a test run alone ([`run_alone`]) and its foreign client meet.
    const TEST_DIR: &str = "VZ_WL_PROXY_TEST_DIR";

    /// One ignored test of this module in a process of its own, with `dir`
    /// for its directory. Whether it passed, and what it said.
    fn run_alone(test: &str, dir: &Path) -> (bool, String) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                test,
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(TEST_DIR, dir)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success() && text.contains("1 passed"), text)
    }

    /// `start` forks, and a fork of the multi-threaded test harness is no
    /// place to confine a process in: the test runs itself again, alone. A
    /// client from outside the launch is started beside it — a sibling of the
    /// supervisor, not a process below it.
    #[test]
    fn the_proxy_starts_confined_serves_and_ends_with_its_last_connection() {
        let dir = std::env::temp_dir().join(format!("vz-wl-proxy-sup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut foreign = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "wl_proxy::tests::foreign_client",
                "--ignored",
                "--test-threads=1",
            ])
            .env(TEST_DIR, &dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let (passed, text) = run_alone("wl_proxy::tests::supervised", &dir);
        let _ = foreign.kill();
        let _ = foreign.wait();
        let _ = fs::remove_dir_all(&dir);
        assert!(passed, "{text}");
    }

    /// Waits for `file` in `dir` to appear, up to 20 s; its text.
    fn await_file(dir: &Path, file: &str) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(text) = fs::read_to_string(dir.join(file)) {
                return text;
            }
            assert!(std::time::Instant::now() < deadline, "no {file}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A program of another launch: connects to the zone's socket of the one
    /// under test, asks for a roundtrip, and writes down whether it was
    /// served. The process under test waits for `connected` before it
    /// supervises, so the request is in while the proxy accepts.
    #[test]
    #[ignore = "run by the_proxy_starts_confined_serves_and_ends_with_its_last_connection"]
    fn foreign_client() {
        let Some(dir) = std::env::var_os(TEST_DIR).map(PathBuf::from) else {
            return;
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut client = loop {
            match UnixStream::connect(dir.join("zone-sock")) {
                Ok(client) => break client,
                Err(e) => {
                    assert!(std::time::Instant::now() < deadline, "{e}");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        };
        fs::write(dir.join("connected"), "").unwrap();
        let mut sync = Vec::new();
        event(&mut sync, 1, 0, |a| {
            a.extend_from_slice(&2u32.to_ne_bytes())
        });
        // Refused, the socket may be closed before this is written.
        let _ = client.write_all(&sync);
        let got = drain(&mut client);
        let verdict = if got.is_empty() { "refused" } else { "served" };
        fs::write(dir.join("foreign"), verdict).unwrap();
    }

    #[test]
    #[ignore = "run by the_proxy_starts_confined_serves_and_ends_with_its_last_connection"]
    fn supervised() {
        // Without the directory of the outer test: no foreign client either.
        let shared = std::env::var_os(TEST_DIR).map(PathBuf::from);
        let dir = shared.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("vz-wl-proxy-sup-{}", std::process::id()))
        });
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // The security context's listener, played by a fake compositor.
        let up = Upstream::bind(&dir, 42).unwrap();
        assert!(up.path.starts_with(dir.join(UPSTREAM_DIR)));
        let zone_path = dir.join("zone-sock");
        let zone = UnixListener::bind(&zone_path).unwrap();
        // Before any thread: the fork in `start` has to be the only thing.
        let mut proxy = start(&zone, &up.path, None, None).unwrap();
        drop(zone);
        if shared.is_some() {
            await_file(&dir, "connected");
        }
        let pid = proxy.pid;
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let field = |k: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(k))
                .map(str::trim)
                .unwrap_or("")
                .to_owned()
        };
        assert_eq!(field("Name:"), PROCESS_NAME);
        assert_eq!(field("Seccomp:"), "2", "no filter");
        assert_eq!(field("NoNewPrivs:"), "1");
        // Not dumpable: its descriptors are root's to look at.
        assert!(fs::read_dir(format!("/proc/{pid}/fd")).is_err());

        let (binds, _) = mpsc::channel();
        let (peers_tx, peers) = mpsc::channel();
        let listener = up.listener;
        std::thread::spawn(move || {
            for sock in listener.incoming().flatten() {
                // Whose pid the compositor sees: whoever connected.
                let mut cred = libc::ucred {
                    pid: 0,
                    uid: 0,
                    gid: 0,
                };
                let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
                // SAFETY: SO_PEERCRED fills one ucred, whose size is passed.
                unsafe {
                    libc::getsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_PEERCRED,
                        (&mut cred as *mut libc::ucred).cast(),
                        &mut len,
                    )
                };
                let _ = peers_tx.send(cred.pid);
                let binds = binds.clone();
                std::thread::spawn(move || fake_compositor(sock, GLOBALS, binds));
            }
        });
        // The "program": lives a second, and a client of it opens a
        // connection that outlives it by another. Reaped by `supervise`.
        #[allow(clippy::zombie_processes)]
        let main = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .unwrap();
        let (seen_tx, seen_rx) = mpsc::channel();
        let client_path = zone_path.clone();
        std::thread::spawn(move || {
            seen_tx
                .send(globals_of(UnixStream::connect(&client_path).unwrap()).len())
                .unwrap();
            let mut client = UnixStream::connect(&client_path).unwrap();
            request(&mut client, 1, 0, &2u32.to_ne_bytes());
            await_event(&mut client, 2);
            std::thread::sleep(Duration::from_secs(2));
            // Still served after the program is gone.
            request(&mut client, 1, 0, &3u32.to_ne_bytes());
            await_event(&mut client, 3);
            seen_tx.send(0).unwrap();
        });
        proxy.take_over();
        let exited = Rc::new(Cell::new(false));
        let flag = exited.clone();
        let started = std::time::Instant::now();
        let status = proxy.supervise(main.id() as libc::pid_t, move || flag.set(true));
        assert!(exited.get());
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert_eq!(seen_rx.recv().unwrap(), 3);
        // Every connection upstream is the supervisor's: its windows have the
        // pid of the launch's record (`crate::focus`).
        let me = std::process::id() as libc::pid_t;
        assert_eq!(peers.try_iter().collect::<Vec<_>>(), [me, me]);
        assert_eq!(
            seen_rx.recv().unwrap(),
            0,
            "the late connection was not served"
        );
        // Not before the connection that outlived the program was closed.
        assert!(
            started.elapsed() >= Duration::from_millis(1800),
            "{:?}",
            started.elapsed()
        );
        // And after the program, nothing new is taken.
        assert!(UnixStream::connect(&zone_path).is_err());
        // A process that is not below the supervisor — another launch's, in
        // the same zone — was not passed on: its window would have carried
        // this launch's pid (review 2026-09-25).
        if shared.is_some() {
            assert_eq!(await_file(&dir, "foreign"), "refused");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// A signal to the supervisor — the pid of the launch, the pid of its
    /// windows — reaches the program, and the program's orphans; it does not
    /// end the supervisor and leave them running (review 2026-09-25).
    #[test]
    fn a_signal_to_the_supervisor_reaches_the_program_and_its_orphans() {
        let dir = std::env::temp_dir().join(format!("vz-wl-proxy-sig-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (passed, text) = run_alone("wl_proxy::tests::supervised_signals", &dir);
        let _ = fs::remove_dir_all(&dir);
        assert!(passed, "{text}");
    }

    #[test]
    #[ignore = "run by a_signal_to_the_supervisor_reaches_the_program_and_its_orphans"]
    fn supervised_signals() {
        let Some(dir) = std::env::var_os(TEST_DIR).map(PathBuf::from) else {
            return;
        };
        let up = Upstream::bind(&dir, 43).unwrap();
        let zone = UnixListener::bind(dir.join("zone-sock")).unwrap();
        let mut proxy = start(&zone, &up.path, None, None).unwrap();
        drop(zone);
        drop(up.listener);
        proxy.take_over();
        // The program: a shell that leaves a `sleep` behind when it dies of
        // the signal — adopted here, and what "close" meant all the same.
        let orphan_file = dir.join("orphan");
        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", "sleep 60 & echo $! > \"$0\"; wait"])
            .arg(&orphan_file);
        // What `wl_sandbox::run` does in its child (`in_program_child`): the
        // mask is inherited, and std's spawn leaves it as it is.
        // SAFETY: sigprocmask is async-signal-safe; the set is plain data.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, || {
                let mut none: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut none);
                libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
                Ok(())
            });
        }
        #[allow(clippy::zombie_processes)]
        let main = command.spawn().unwrap();
        let orphan: i32 = loop {
            match fs::read_to_string(&orphan_file) {
                Ok(text) if text.ends_with('\n') => break text.trim().parse().unwrap(),
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        let orphan_fd = sys::pidfd_open(orphan).unwrap();
        // "Close" from the window menu: a SIGTERM to the supervisor. To this
        // thread, which holds it blocked; the harness's other threads do not.
        // SAFETY: tgkill takes numbers only.
        unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::gettid(),
                libc::SIGTERM,
            )
        };
        let started = std::time::Instant::now();
        let status = proxy.supervise(main.id() as libc::pid_t, || {});
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM,
            "the program was not ended by the signal: {status:#x}"
        );
        assert!(
            sys::pidfd_wait(&orphan_fd, Duration::from_secs(10)),
            "the orphan outlived the close"
        );
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    // --- the zone's border (crate::wl_frame) -----------------------------

    /// A message the fake compositor got, with the interface of its object.
    #[derive(Debug, Clone)]
    struct Msg {
        object: u32,
        iface: String,
        opcode: u32,
        args: Vec<u32>,
    }

    const FRAME_GLOBALS: &[(&str, u32)] = &[
        ("wl_compositor", 6),
        ("wl_subcompositor", 1),
        ("wl_shm", 1),
        ("wp_viewporter", 1),
        ("xdg_wm_base", 6),
        ("wl_seat", 7),
    ];

    /// A compositor that knows which interface every object is — of what
    /// the proxy and the client create — answers `get_registry` with
    /// [`FRAME_GLOBALS`] and `sync` with `done`, and logs every request.
    fn frame_compositor(
        mut sock: UnixStream,
        log: mpsc::Sender<Msg>,
        globals: &'static [(&'static str, u32)],
    ) {
        let mut ifaces: HashMap<u32, String> = HashMap::from([(1, "wl_display".to_owned())]);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let word = |b: &[u8], i: usize| u32::from_ne_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        loop {
            let n = match sock.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            while buf.len() >= 8 {
                let size = (word(&buf, 1) >> 16) as usize;
                if buf.len() < size {
                    break;
                }
                let msg: Vec<u8> = buf.drain(..size).collect();
                let (object, opcode) = (word(&msg, 0), word(&msg, 1) & 0xffff);
                let args: Vec<u32> = (2..size / 4).map(|i| word(&msg, i)).collect();
                let iface = ifaces.get(&object).cloned().unwrap_or_default();
                let mut out = Vec::new();
                let mut new = |id: u32, what: &str| {
                    ifaces.insert(id, what.to_owned());
                };
                match (iface.as_str(), opcode) {
                    ("wl_display", 1) => {
                        new(args[0], "wl_registry");
                        for (name, (global, version)) in globals.iter().enumerate() {
                            event(&mut out, args[0], 0, |a| {
                                a.extend_from_slice(&(name as u32 + 1).to_ne_bytes());
                                string(a, global);
                                a.extend_from_slice(&version.to_ne_bytes());
                            });
                        }
                    }
                    ("wl_display", 0) => {
                        event(&mut out, args[0], 0, |a| {
                            a.extend_from_slice(&7u32.to_ne_bytes())
                        });
                        event(&mut out, 1, 1, |a| {
                            a.extend_from_slice(&args[0].to_ne_bytes())
                        });
                    }
                    ("wl_registry", 0) => {
                        let len = args[1] as usize;
                        let bytes: Vec<u8> = msg[16..16 + len - 1].to_vec();
                        let id = *args.last().unwrap();
                        new(id, &String::from_utf8(bytes).unwrap());
                    }
                    ("wl_compositor", 0) => new(args[0], "wl_surface"),
                    ("wl_subcompositor", 1) => new(args[0], "wl_subsurface"),
                    ("wp_viewporter", 1) => new(args[0], "wp_viewport"),
                    ("wl_shm", 0) => new(args[0], "wl_shm_pool"),
                    ("wl_shm_pool", 0) => new(args[0], "wl_buffer"),
                    ("xdg_wm_base", 2) => new(args[0], "xdg_surface"),
                    ("xdg_surface", 1) => new(args[0], "xdg_toplevel"),
                    ("wl_seat", 0) => new(args[0], "wl_pointer"),
                    ("wp_fractional_scale_manager_v1", 1) => new(args[0], "wp_fractional_scale_v1"),
                    _ => {}
                }
                let _ = log.send(Msg {
                    object,
                    iface,
                    opcode,
                    args,
                });
                if sock.write_all(&out).is_err() {
                    return;
                }
            }
        }
    }

    impl Rig {
        /// A client connects and is answered `answer` (`UPSTREAM` or
        /// `UPSTREAM_BARE`) with an upstream to a [`frame_compositor`]; the
        /// client, a way to write events as the compositor, and its log.
        fn connect_framed(
            &self,
            answer: u8,
            globals: &'static [(&'static str, u32)],
        ) -> (UnixStream, UnixStream, mpsc::Receiver<Msg>) {
            let client = UnixStream::connect(&self.path).unwrap();
            let channel = self.channel.as_ref().unwrap();
            let mut byte = [0u8];
            (&*channel).read_exact(&mut byte).unwrap();
            assert_eq!(byte[0], CONNECT);
            let (up, compositor) = UnixStream::pair().unwrap();
            let writer = compositor.try_clone().unwrap();
            let (log_tx, log) = mpsc::channel();
            std::thread::spawn(move || frame_compositor(compositor, log_tx, globals));
            sys::send_with_fds(channel.as_raw_fd(), &[answer], &[up.as_raw_fd()]).unwrap();
            (client, writer, log)
        }
    }

    /// Messages from the log until one `pred` accepts, that one included.
    fn log_until(log: &mpsc::Receiver<Msg>, pred: impl Fn(&Msg) -> bool) -> Vec<Msg> {
        let mut got = Vec::new();
        loop {
            let m = log
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("not in the log: {got:#?}"));
            let done = pred(&m);
            got.push(m);
            if done {
                return got;
            }
        }
    }

    /// Events the client gets, `(object, opcode, args)`, until one `pred`
    /// accepts.
    fn events_until(
        sock: &mut UnixStream,
        pred: impl Fn(u32, u32, &[u32]) -> bool,
    ) -> Vec<(u32, u32, Vec<u32>)> {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut buf = Vec::new();
        let mut got = Vec::new();
        loop {
            while buf.len() >= 8 {
                let size = (u32::from_ne_bytes(buf[4..8].try_into().unwrap()) >> 16) as usize;
                if buf.len() < size {
                    break;
                }
                let msg: Vec<u8> = buf.drain(..size).collect();
                let w = |i: usize| u32::from_ne_bytes(msg[i * 4..i * 4 + 4].try_into().unwrap());
                let (object, opcode) = (w(0), w(1) & 0xffff);
                let args: Vec<u32> = (2..size / 4).map(w).collect();
                let done = pred(object, opcode, &args);
                got.push((object, opcode, args));
                if done {
                    return got;
                }
            }
            let mut chunk = [0u8; 4096];
            let n = sock
                .read(&mut chunk)
                .unwrap_or_else(|e| panic!("{e}: {got:?}"));
            assert!(n > 0, "closed: {got:?}");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn words(ws: &[i32]) -> Vec<u8> {
        ws.iter().flat_map(|w| w.to_ne_bytes()).collect()
    }

    /// The client's part up to its first commit of a toplevel with a
    /// geometry and a minimum size. Ids: registry 2, compositor 4,
    /// xdg_wm_base 5, seat 6, surface 7, xdg_surface 8, toplevel 9.
    fn a_window(client: &mut UnixStream) {
        request(client, 1, 1, &2u32.to_ne_bytes());
        request(client, 1, 0, &3u32.to_ne_bytes());
        await_event(client, 3);
        request(client, 2, 0, &bind_args(1, "wl_compositor", 4, 4));
        request(client, 2, 0, &bind_args(5, "xdg_wm_base", 1, 5));
        request(client, 2, 0, &bind_args(6, "wl_seat", 5, 6));
        request(client, 4, 0, &7u32.to_ne_bytes());
        request(client, 5, 2, &words(&[8, 7]));
        request(client, 8, 1, &9u32.to_ne_bytes());
        request(client, 8, 3, &words(&[10, 20, 300, 200]));
        request(client, 9, 8, &words(&[100, 50]));
        request(client, 7, 6, &[]);
    }

    /// The border's arithmetic on the wire (`crate::wl_frame`): the
    /// compositor is told a geometry grown by the border and a minimum grown
    /// by it, gets four strips on the program's surface around that
    /// geometry, laid before the program's commit; the program is told a
    /// configure less the border; input on a strip does not reach it.
    #[test]
    fn a_window_gets_the_border_inside_its_geometry_and_input_on_it_is_dropped() {
        let rig = Rig::with_border("border", Some((4, Rgb(0xff, 0, 0x80))));
        let (mut client, mut compositor, log) = rig.connect_framed(UPSTREAM, FRAME_GLOBALS);
        a_window(&mut client);
        // Up to the program's commit of its surface; the strips' own
        // commits come before it.
        let mut got = log_until(&log, |m| m.iface == "xdg_wm_base" && m.opcode == 2);
        let (xdg, root) = (got.last().unwrap().args[0], got.last().unwrap().args[1]);
        got.extend(log_until(&log, |m| {
            m.iface == "wl_surface" && m.opcode == 6 && m.object == root
        }));
        let find = |iface: &str, opcode: u32| -> Vec<&Msg> {
            got.iter()
                .filter(|m| m.iface == iface && m.opcode == opcode)
                .collect()
        };
        // The proxy's own: a pool of 36 bytes, a 3×3 XRGB8888 buffer.
        let pool = find("wl_shm", 0);
        assert_eq!(pool.len(), 1, "{got:#?}");
        assert_eq!(pool[0].args[1], 36);
        let buffer = find("wl_shm_pool", 0);
        assert_eq!(buffer[0].args[1..], [0, 3, 3, 12, 1]);
        // Each strip shows the square's middle pixel.
        let sources = find("wp_viewport", 1);
        assert_eq!(sources.len(), 4);
        assert!(
            sources.iter().all(|m| m.args == [256, 256, 256, 256]),
            "{sources:?}"
        );
        // The geometry and the minimum, grown by 4 on every side.
        let geometry = find("xdg_surface", 3);
        assert_eq!(geometry.len(), 1, "{got:#?}");
        assert_eq!(geometry[0].args, [6, 16, 308, 208]);
        assert_eq!(find("xdg_toplevel", 8)[0].args, [108, 58]);
        // Four strips on the program's surface, stretched and placed around
        // the geometry, and committed before it.
        let subs = find("wl_subcompositor", 1);
        assert_eq!(subs.len(), 4, "{got:#?}");
        assert!(subs.iter().all(|m| m.args[2] == root), "{subs:?}");
        let strips: Vec<u32> = subs.iter().map(|m| m.args[1]).collect();
        let sizes: Vec<(i32, i32)> = find("wp_viewport", 2)
            .iter()
            .map(|m| (m.args[0] as i32, m.args[1] as i32))
            .collect();
        assert_eq!(sizes, [(308, 4), (308, 4), (4, 200), (4, 200)]);
        let places: Vec<(i32, i32)> = find("wl_subsurface", 1)
            .iter()
            .map(|m| (m.args[0] as i32, m.args[1] as i32))
            .collect();
        assert_eq!(places, [(6, 16), (6, 220), (6, 20), (310, 20)]);
        let commits: Vec<u32> = find("wl_surface", 6).iter().map(|m| m.object).collect();
        assert_eq!(commits.len(), 5, "{commits:?}");
        assert_eq!(
            *commits.last().unwrap(),
            root,
            "the program's commit is the last"
        );
        for s in &strips {
            assert!(commits.contains(s), "strip {s} not committed");
        }

        // The compositor configures the window 800×600: the program is told
        // what is left inside the border.
        let toplevel = got
            .iter()
            .find(|m| m.iface == "xdg_surface" && m.opcode == 1)
            .map(|m| m.args[0])
            .unwrap();
        let mut out = Vec::new();
        event(&mut out, toplevel, 0, |a| {
            a.extend_from_slice(&words(&[800, 600, 0]))
        });
        event(&mut out, xdg, 0, |a| {
            a.extend_from_slice(&5u32.to_ne_bytes())
        });
        compositor.write_all(&out).unwrap();
        let events = events_until(&mut client, |o, op, _| o == 8 && op == 0);
        let configure = events
            .iter()
            .find(|(o, op, _)| *o == 9 && *op == 0)
            .expect("no configure");
        assert_eq!(configure.2[..2], [792, 592]);

        // The pointer: over a strip, nothing; over the program's surface,
        // its enter and its frame.
        request(&mut client, 6, 0, &10u32.to_ne_bytes());
        let pointer = log_until(&log, |m| m.iface == "wl_seat" && m.opcode == 0)
            .last()
            .unwrap()
            .args[0];
        let mut out = Vec::new();
        let fixed = |v: i32| v * 256;
        event(&mut out, pointer, 0, |a| {
            a.extend_from_slice(&words(&[11, strips[0] as i32, fixed(3), fixed(1)]))
        });
        event(&mut out, pointer, 5, |_| {});
        event(&mut out, pointer, 2, |a| {
            a.extend_from_slice(&words(&[1, fixed(5), fixed(2)]))
        });
        event(&mut out, pointer, 3, |a| {
            a.extend_from_slice(&words(&[12, 2, 0x110, 1]))
        });
        event(&mut out, pointer, 5, |_| {});
        event(&mut out, pointer, 1, |a| {
            a.extend_from_slice(&words(&[13, strips[0] as i32]))
        });
        event(&mut out, pointer, 0, |a| {
            a.extend_from_slice(&words(&[14, root as i32, fixed(7), fixed(9)]))
        });
        event(&mut out, pointer, 5, |_| {});
        compositor.write_all(&out).unwrap();
        let events = events_until(&mut client, |o, op, _| o == 10 && op == 5);
        let pointer_events: Vec<(u32, Vec<u32>)> = events
            .into_iter()
            .filter(|(o, _, _)| *o == 10)
            .map(|(_, op, args)| (op, args))
            .collect();
        assert_eq!(
            pointer_events,
            [(0, vec![14, 7, 7 * 256, 9 * 256]), (5, vec![])],
            "the program saw input on the border"
        );

        // A new subsurface of the program goes on top of its surface's
        // stack: the strips are put back above it (§5.9).
        let strip_subs: HashSet<u32> = subs.iter().map(|m| m.args[0]).collect();
        request(&mut client, 2, 0, &bind_args(2, "wl_subcompositor", 1, 11));
        request(&mut client, 4, 0, &12u32.to_ne_bytes());
        request(&mut client, 11, 1, &words(&[13, 12, 7]));
        let got = log_until(&log, |m| m.iface == "wl_subcompositor" && m.opcode == 1);
        let child = got.last().unwrap().args[1];
        let raised: HashSet<u32> = (0..4)
            .map(|_| {
                log_until(&log, |m| {
                    m.iface == "wl_subsurface" && m.opcode == 2 && m.args[0] == child
                })
                .last()
                .unwrap()
                .object
            })
            .collect();
        assert_eq!(raised, strip_subs);

        // The toplevel goes: its strips go with it, at once.
        request(&mut client, 9, 0, &[]);
        let gone: HashSet<u32> = (0..4)
            .map(|_| {
                log_until(&log, |m| {
                    m.iface == "wl_subsurface" && m.opcode == 0 && strip_subs.contains(&m.object)
                })
                .last()
                .unwrap()
                .object
            })
            .collect();
        assert_eq!(gone, strip_subs);
        drop(client);
        assert_eq!(rig.finish(), 0);
    }

    /// Hidden (`vpn-zone frame hide`), the connection is stage 1's: nothing
    /// translated, nothing drawn.
    #[test]
    fn a_connection_without_the_border_is_passed_on_as_it_is() {
        let rig = Rig::with_border("bare", Some((4, Rgb(0xff, 0, 0x80))));
        let (mut client, _compositor, log) = rig.connect_framed(UPSTREAM_BARE, FRAME_GLOBALS);
        a_window(&mut client);
        let got = log_until(&log, |m| m.iface == "wl_surface" && m.opcode == 6);
        assert!(
            got.iter()
                .all(|m| m.iface != "wl_subcompositor" && m.iface != "wl_shm"),
            "{got:#?}"
        );
        let geometry: Vec<&Msg> = got
            .iter()
            .filter(|m| m.iface == "xdg_surface" && m.opcode == 3)
            .collect();
        assert_eq!(geometry[0].args, [10, 20, 300, 200]);
        drop(client);
        assert_eq!(rig.finish(), 0);
    }

    /// A compositor without `wl_subcompositor` (in its place, at the same
    /// name, something else): the border cannot be drawn, and then nothing
    /// is translated either — the window is stage 1's, not a window with a
    /// gap where the border would be.
    #[test]
    fn without_a_subcompositor_a_window_goes_without_the_border() {
        const NO_SUBCOMPOSITOR: &[(&str, u32)] = &[
            ("wl_compositor", 6),
            ("wp_presentation", 1),
            ("wl_shm", 1),
            ("wp_viewporter", 1),
            ("xdg_wm_base", 6),
            ("wl_seat", 7),
        ];
        let rig = Rig::with_border("cannot", Some((4, Rgb(0xff, 0, 0x80))));
        let (mut client, mut compositor, log) = rig.connect_framed(UPSTREAM, NO_SUBCOMPOSITOR);
        a_window(&mut client);
        let mut got = log_until(&log, |m| m.iface == "xdg_wm_base" && m.opcode == 2);
        let (xdg, root) = (got.last().unwrap().args[0], got.last().unwrap().args[1]);
        got.extend(log_until(&log, |m| {
            m.iface == "wl_surface" && m.opcode == 6 && m.object == root
        }));
        let geometry: Vec<&Msg> = got
            .iter()
            .filter(|m| m.iface == "xdg_surface" && m.opcode == 3)
            .collect();
        assert_eq!(geometry[0].args, [10, 20, 300, 200]);
        assert!(
            got.iter().all(|m| m.iface != "wp_viewport"),
            "strips made: {got:#?}"
        );
        let toplevel = got
            .iter()
            .find(|m| m.iface == "xdg_surface" && m.opcode == 1)
            .map(|m| m.args[0])
            .unwrap();
        let mut out = Vec::new();
        event(&mut out, toplevel, 0, |a| {
            a.extend_from_slice(&words(&[800, 600, 0]))
        });
        event(&mut out, xdg, 0, |a| {
            a.extend_from_slice(&5u32.to_ne_bytes())
        });
        compositor.write_all(&out).unwrap();
        let events = events_until(&mut client, |o, op, _| o == 8 && op == 0);
        let configure = events
            .iter()
            .find(|(o, op, _)| *o == 9 && *op == 0)
            .expect("no configure");
        assert_eq!(configure.2[..2], [800, 600]);
        drop(client);
        assert_eq!(rig.finish(), 0);
    }

    /// Every toplevel makes the proxy make a frame of its own objects
    /// upstream, which the cap on the program's objects does not count: a
    /// program that makes toplevel after toplevel (each committed once,
    /// without a buffer — legal) is refused past [`MAX_FRAMED`] of them,
    /// with `no_memory`, like one with too many objects.
    #[test]
    fn a_program_with_too_many_framed_windows_is_refused() {
        let rig = Rig::with_border("many", Some((4, Rgb(0xff, 0, 0x80))));
        let (mut client, _compositor, _log) = rig.connect_framed(UPSTREAM, FRAME_GLOBALS);
        a_window(&mut client);
        let windows = u32::try_from(MAX_FRAMED).unwrap() + 400;
        'writing: for chunk in (0..windows).collect::<Vec<_>>().chunks(64) {
            let mut out = Vec::new();
            for &k in chunk {
                let surface = 100 + 3 * k;
                let (xdg, toplevel) = (surface + 1, surface + 2);
                event(&mut out, 4, 0, |a| {
                    a.extend_from_slice(&surface.to_ne_bytes())
                });
                event(&mut out, 5, 2, |a| {
                    a.extend_from_slice(&xdg.to_ne_bytes());
                    a.extend_from_slice(&surface.to_ne_bytes());
                });
                event(&mut out, xdg, 1, |a| {
                    a.extend_from_slice(&toplevel.to_ne_bytes())
                });
                event(&mut out, surface, 6, |_| {});
            }
            // Refused already: the rest is not read.
            if client.write_all(&out).is_err() {
                break 'writing;
            }
        }
        let events = events_until(&mut client, |o, op, _| o == 1 && op == 0);
        let error = &events.last().unwrap().2;
        assert_eq!(error[1], NO_MEMORY, "{error:?}");
        drop(client);
        assert_eq!(rig.finish(), 0);
    }

    // --- the title strip (crate::wl_title) ----------------------------------

    const TITLE_GLOBALS: &[(&str, u32)] = &[
        ("wl_compositor", 6),
        ("wl_subcompositor", 1),
        ("wl_shm", 1),
        ("wp_viewporter", 1),
        ("xdg_wm_base", 6),
        ("wl_seat", 7),
        ("wp_fractional_scale_manager_v1", 1),
    ];

    /// The package's font, when the build names one (the CI's shell does):
    /// without it the strip goes without text, which is checked too.
    fn test_font() -> Option<Vec<u8>> {
        let font = crate::wl_title::FONT.and_then(|path| fs::read(path).ok());
        if font.is_none() {
            eprintln!("VPN_ZONE_FRAME_FONT is not set at build time — the title without text");
        }
        font
    }

    fn titled(mode: TitleMode, font: Option<Vec<u8>>) -> Drawing {
        Drawing {
            frame: Frame {
                color: Rgb(0xff, 0, 0x80),
                width: 4,
                title: mode,
            },
            title: "nl · основной".to_owned(),
            font,
        }
    }

    fn signed(ws: &[u32]) -> Vec<i32> {
        ws.iter().map(|&w| w as i32).collect()
    }

    /// The title strip on the wire: the geometry grown by the border and
    /// the strip, the program told what is left, a strip of the colour
    /// under the top border and the text on it, all before the program's
    /// commit; the text drawn again at a new fractional scale and shown at
    /// once; input on the title and its text dropped, and the title raised
    /// above a new subsurface of the program; in fullscreen, no strip and no
    /// room for it — but out again as soon as the compositor ends
    /// fullscreen, acked or not.
    #[test]
    fn the_title_strip_takes_its_room_and_hides_in_fullscreen() {
        let font = test_font();
        let with_text = font.is_some();
        let rig = Rig::with_drawing("title", Some(titled(TitleMode::Always, font)));
        let (mut client, mut compositor, log) = rig.connect_framed(UPSTREAM, TITLE_GLOBALS);
        a_window(&mut client);
        let mut got = log_until(&log, |m| m.iface == "xdg_wm_base" && m.opcode == 2);
        let (xdg, root) = (got.last().unwrap().args[0], got.last().unwrap().args[1]);
        got.extend(log_until(&log, |m| {
            m.iface == "wl_surface" && m.opcode == 6 && m.object == root
        }));
        let find = |got: &[Msg], iface: &str, opcode: u32| -> Vec<Msg> {
            got.iter()
                .filter(|m| m.iface == iface && m.opcode == opcode)
                .cloned()
                .collect()
        };
        // The program's 300×200 at (10, 20): 4 on every side, 20 more on top.
        let geometry = find(&got, "xdg_surface", 3);
        assert_eq!(signed(&geometry[0].args), [6, -4, 308, 228], "{got:#?}");
        assert_eq!(find(&got, "xdg_toplevel", 8)[0].args, [108, 78]);
        // Four strips and the title on the program's surface; the text on
        // the title.
        let subs = find(&got, "wl_subcompositor", 1);
        let on_root: Vec<&Msg> = subs.iter().filter(|m| m.args[2] == root).collect();
        assert_eq!(on_root.len(), 5, "{subs:?}");
        let (title_sub, title) = (on_root[4].args[0], on_root[4].args[1]);
        let text = subs
            .iter()
            .find(|m| m.args[2] == title)
            .map(|m| (m.args[0], m.args[1]));
        assert_eq!(text.is_some(), with_text, "{subs:?}");
        // Where each is: the strips around the title and the program, the
        // title under the top border, the program's width, 20 high.
        let places: Vec<(u32, Vec<i32>)> = find(&got, "wl_subsurface", 1)
            .iter()
            .map(|m| (m.object, signed(&m.args)))
            .collect();
        let at = |sub: u32| {
            places
                .iter()
                .find(|(o, _)| *o == sub)
                .map(|(_, a)| a.clone())
        };
        let strips: Vec<Vec<i32>> = on_root[..4]
            .iter()
            .map(|m| at(m.args[0]).unwrap())
            .collect();
        assert_eq!(
            strips,
            [vec![6, -4], vec![6, 220], vec![6, 0], vec![310, 0]]
        );
        assert_eq!(at(title_sub), Some(vec![10, 0]));
        // The title shows the colour: the border's buffer, stretched.
        let attached: Vec<&Msg> = got
            .iter()
            .filter(|m| m.iface == "wl_surface" && m.opcode == 1 && m.object == title)
            .collect();
        assert_eq!(attached.len(), 1, "{got:#?}");
        let pixel = find(&got, "wl_shm_pool", 0)[0].args[0];
        assert_eq!(attached[0].args[0], pixel, "not the colour");
        let commits: Vec<u32> = find(&got, "wl_surface", 6)
            .iter()
            .map(|m| m.object)
            .collect();
        assert_eq!(
            *commits.last().unwrap(),
            root,
            "the program's commit is the last"
        );
        assert!(commits.contains(&title), "the title not committed");
        if let Some((text_sub, text)) = text {
            // Its own pool of the title's memfd, a buffer of the line at
            // scale 1, 20 high, shown whole after the pad.
            let pools = find(&got, "wl_shm", 0);
            assert_eq!(pools.len(), 2, "{pools:?}");
            let buffers = find(&got, "wl_shm_pool", 0);
            let line = buffers.last().unwrap();
            let (width, height) = (line.args[2] as i32, line.args[3] as i32);
            assert_eq!(height, 20);
            assert!((40..292).contains(&width), "{width}");
            assert_eq!(at(text_sub), Some(vec![8, 0]));
            let view = |got: &[Msg], opcode: u32| -> Vec<Vec<i32>> {
                got.iter()
                    .filter(|m| m.iface == "wp_viewport" && m.opcode == opcode)
                    .map(|m| signed(&m.args))
                    .collect()
            };
            assert!(
                view(&got, 2).contains(&vec![width, 20]),
                "{:?}",
                view(&got, 2)
            );
            assert!(commits.contains(&text), "the text not committed");

            // A fractional scale for the text: drawn again, 1.5 times the
            // pixels, and shown without waiting for the program.
            let fraction = find(&got, "wp_fractional_scale_manager_v1", 1)[0].args[0];
            let mut out = Vec::new();
            event(&mut out, fraction, 0, |a| {
                a.extend_from_slice(&180u32.to_ne_bytes())
            });
            compositor.write_all(&out).unwrap();
            let got = log_until(&log, |m| {
                m.iface == "wl_subsurface" && m.opcode == 4 && m.object == title_sub
            });
            let buffer = find(&got, "wl_shm_pool", 0);
            assert_eq!(buffer.len(), 1, "{got:#?}");
            assert_eq!(
                (buffer[0].args[2] as i32, buffer[0].args[3] as i32),
                (crate::wl_title::device(width, 180), 30)
            );
            let order: Vec<(String, u32, u32)> = got
                .iter()
                .filter(|m| m.object == title_sub || m.object == title || m.object == text)
                .map(|m| (m.iface.clone(), m.opcode, m.object))
                .collect();
            let text_commit = order
                .iter()
                .position(|o| *o == ("wl_surface".into(), 6, text));
            let desync = order
                .iter()
                .position(|o| *o == ("wl_subsurface".into(), 5, title_sub));
            let commit = order
                .iter()
                .position(|o| *o == ("wl_surface".into(), 6, title));
            assert!(
                text_commit < desync && desync < commit && commit.is_some(),
                "not shown at once: {order:?}"
            );
            // Still 300 logical pixels wide, the same text.
            assert!(view(&got, 2).contains(&vec![width, 20]), "{got:#?}");
        }

        // Input on the title or on its text is not the program's: the
        // pointer enters each, clicks, leaves, and the program hears nothing
        // until the pointer is on its own surface.
        request(&mut client, 6, 0, &10u32.to_ne_bytes());
        let pointer = log_until(&log, |m| m.iface == "wl_seat" && m.opcode == 0)
            .last()
            .unwrap()
            .args[0];
        let fixed = |v: i32| v * 256;
        let mut out = Vec::new();
        let own = [Some((11, title)), text.map(|(_, text)| (21, text))];
        for (serial, surface) in own.into_iter().flatten() {
            event(&mut out, pointer, 0, |a| {
                a.extend_from_slice(&words(&[serial, surface as i32, fixed(3), fixed(1)]))
            });
            event(&mut out, pointer, 5, |_| {});
            event(&mut out, pointer, 2, |a| {
                a.extend_from_slice(&words(&[1, fixed(5), fixed(2)]))
            });
            event(&mut out, pointer, 3, |a| {
                a.extend_from_slice(&words(&[serial + 1, 2, 0x110, 1]))
            });
            event(&mut out, pointer, 5, |_| {});
            event(&mut out, pointer, 1, |a| {
                a.extend_from_slice(&words(&[serial + 2, surface as i32]))
            });
        }
        event(&mut out, pointer, 0, |a| {
            a.extend_from_slice(&words(&[30, root as i32, fixed(7), fixed(40)]))
        });
        event(&mut out, pointer, 5, |_| {});
        compositor.write_all(&out).unwrap();
        let events = events_until(&mut client, |o, op, _| o == 10 && op == 5);
        let pointer_events: Vec<(u32, Vec<u32>)> = events
            .into_iter()
            .filter(|(o, _, _)| *o == 10)
            .map(|(_, op, args)| (op, args))
            .collect();
        assert_eq!(
            pointer_events,
            [(0, vec![30, 7, 7 * 256, 40 * 256]), (5, vec![])],
            "the program saw input on the title"
        );

        // A new subsurface of the program goes on top of its surface's
        // stack: the title is put back above it with the strips (§5.9).
        request(&mut client, 2, 0, &bind_args(2, "wl_subcompositor", 1, 11));
        request(&mut client, 4, 0, &12u32.to_ne_bytes());
        request(&mut client, 11, 1, &words(&[13, 12, 7]));
        let child = log_until(&log, |m| m.iface == "wl_subcompositor" && m.opcode == 1)
            .last()
            .unwrap()
            .args[1];
        let raised: HashSet<u32> = (0..5)
            .map(|_| {
                log_until(&log, |m| {
                    m.iface == "wl_subsurface" && m.opcode == 2 && m.args[0] == child
                })
                .last()
                .unwrap()
                .object
            })
            .collect();
        let frame_subs: HashSet<u32> = on_root.iter().map(|m| m.args[0]).collect();
        assert!(raised.contains(&title_sub), "the title not raised");
        assert_eq!(raised, frame_subs);

        // Fullscreen: the program is told the output less the border only,
        // and once it acks and commits, the geometry has no room for the
        // strip and the strip is gone.
        let toplevel = find(&got, "xdg_surface", 1)[0].args[0];
        let mut out = Vec::new();
        event(&mut out, toplevel, 0, |a| {
            a.extend_from_slice(&words(&[800, 600, 4, 2]))
        });
        event(&mut out, xdg, 0, |a| {
            a.extend_from_slice(&5u32.to_ne_bytes())
        });
        compositor.write_all(&out).unwrap();
        let events = events_until(&mut client, |o, op, _| o == 8 && op == 0);
        let configure = events
            .iter()
            .find(|(o, op, _)| *o == 9 && *op == 0)
            .unwrap();
        assert_eq!(configure.2[..2], [792, 592]);
        request(&mut client, 8, 4, &5u32.to_ne_bytes());
        request(&mut client, 8, 3, &words(&[0, 0, 792, 592]));
        request(&mut client, 7, 6, &[]);
        let got = log_until(&log, |m| {
            m.iface == "wl_surface" && m.opcode == 6 && m.object == root
        });
        let geometry: Vec<Vec<i32>> = got
            .iter()
            .filter(|m| m.iface == "xdg_surface" && m.opcode == 3)
            .map(|m| signed(&m.args))
            .collect();
        assert_eq!(geometry, [vec![-4, -4, 800, 600]]);
        let hidden = got.iter().any(|m| {
            m.iface == "wl_surface" && m.opcode == 1 && m.object == title && m.args[0] == 0
        });
        assert!(hidden, "the title still shown in fullscreen: {got:#?}");
        // Hidden over the top of the content, where it can come out.
        let title_at = |got: &[Msg]| -> Vec<Vec<i32>> {
            got.iter()
                .filter(|m| m.iface == "wl_subsurface" && m.opcode == 1 && m.object == title_sub)
                .map(|m| signed(&m.args))
                .collect()
        };
        assert_eq!(title_at(&got), [vec![0, 0]]);

        // The compositor ends fullscreen and the program never acks that
        // (review 2026-09-25): the strip comes out at once, without the
        // program's commit, over the content it still draws fullscreen...
        let mut out = Vec::new();
        event(&mut out, toplevel, 0, |a| {
            a.extend_from_slice(&words(&[800, 600, 0]))
        });
        event(&mut out, xdg, 0, |a| {
            a.extend_from_slice(&6u32.to_ne_bytes())
        });
        compositor.write_all(&out).unwrap();
        let got = log_until(&log, |m| {
            m.iface == "wl_subsurface" && m.opcode == 4 && m.object == title_sub
        });
        let shown = got.iter().any(|m| {
            m.iface == "wl_surface" && m.opcode == 1 && m.object == title && m.args[0] == pixel
        });
        assert!(shown, "the title not out when fullscreen ended: {got:#?}");
        let events = events_until(&mut client, |o, op, _| o == 8 && op == 0);
        let configure = events
            .iter()
            .find(|(o, op, _)| *o == 9 && *op == 0)
            .unwrap();
        assert_eq!(configure.2[..2], [792, 572]);
        // ...and stays out while the program commits without the ack.
        request(&mut client, 7, 6, &[]);
        let got = log_until(&log, |m| {
            m.iface == "wl_surface" && m.opcode == 6 && m.object == root
        });
        assert!(
            !got.iter()
                .any(|m| m.iface == "wl_surface" && m.opcode == 1 && m.object == title),
            "the title hidden by an un-acked fullscreen: {got:#?}"
        );
        // Acked: the room for it again, and the strip in it.
        request(&mut client, 8, 4, &6u32.to_ne_bytes());
        request(&mut client, 8, 3, &words(&[0, 0, 792, 572]));
        request(&mut client, 7, 6, &[]);
        let got = log_until(&log, |m| {
            m.iface == "wl_surface" && m.opcode == 6 && m.object == root
        });
        let geometry: Vec<Vec<i32>> = got
            .iter()
            .filter(|m| m.iface == "xdg_surface" && m.opcode == 3)
            .map(|m| signed(&m.args))
            .collect();
        assert_eq!(geometry, [vec![-4, -24, 800, 600]]);
        assert_eq!(title_at(&got), [vec![0, -20]]);
        assert!(
            !got.iter()
                .any(|m| m.iface == "wl_surface" && m.opcode == 1 && m.object == title),
            "{got:#?}"
        );
        drop(client);
        assert_eq!(rig.finish(), 0);
    }

    /// Hover: the strip takes no room and is not shown until the pointer is
    /// at the top of the window; it goes when the pointer goes down.
    #[test]
    fn a_hover_title_comes_out_at_the_top_edge_and_goes() {
        let rig = Rig::with_drawing("hover", Some(titled(TitleMode::Hover, test_font())));
        let (mut client, mut compositor, log) = rig.connect_framed(UPSTREAM, TITLE_GLOBALS);
        a_window(&mut client);
        let mut got = log_until(&log, |m| m.iface == "xdg_wm_base" && m.opcode == 2);
        let root = got.last().unwrap().args[1];
        got.extend(log_until(&log, |m| {
            m.iface == "wl_surface" && m.opcode == 6 && m.object == root
        }));
        let geometry: Vec<Vec<i32>> = got
            .iter()
            .filter(|m| m.iface == "xdg_surface" && m.opcode == 3)
            .map(|m| signed(&m.args))
            .collect();
        assert_eq!(
            geometry,
            [vec![6, 16, 308, 208]],
            "room taken for a hover title"
        );
        let subs: Vec<&Msg> = got
            .iter()
            .filter(|m| m.iface == "wl_subcompositor" && m.opcode == 1 && m.args[2] == root)
            .collect();
        assert_eq!(subs.len(), 5, "{subs:?}");
        let (title_sub, title) = (subs[4].args[0], subs[4].args[1]);
        let place = got
            .iter()
            .find(|m| m.iface == "wl_subsurface" && m.opcode == 1 && m.object == title_sub)
            .map(|m| signed(&m.args));
        assert_eq!(place, Some(vec![10, 20]), "over the top of the content");
        assert!(
            !got.iter()
                .any(|m| m.iface == "wl_surface" && m.opcode == 1 && m.object == title),
            "shown before the pointer came"
        );
        // The pointer comes to the window's top edge: out, at once.
        request(&mut client, 6, 0, &10u32.to_ne_bytes());
        let pointer = log_until(&log, |m| m.iface == "wl_seat" && m.opcode == 0)
            .last()
            .unwrap()
            .args[0];
        let fixed = |v: i32| v * 256;
        let mut out = Vec::new();
        event(&mut out, pointer, 0, |a| {
            a.extend_from_slice(&words(&[11, root as i32, fixed(50), fixed(20)]))
        });
        event(&mut out, pointer, 5, |_| {});
        compositor.write_all(&out).unwrap();
        let got = log_until(&log, |m| {
            m.iface == "wl_subsurface" && m.opcode == 4 && m.object == title_sub
        });
        let shown = got.iter().any(|m| {
            m.iface == "wl_surface" && m.opcode == 1 && m.object == title && m.args[0] != 0
        });
        assert!(shown, "{got:#?}");
        // The program still got its enter: the strip was not there yet.
        let events = events_until(&mut client, |o, op, _| o == 10 && op == 5);
        assert!(events.iter().any(|(o, op, _)| *o == 10 && *op == 0));
        // Down into the content: in again.
        let mut out = Vec::new();
        event(&mut out, pointer, 2, |a| {
            a.extend_from_slice(&words(&[1, fixed(50), fixed(120)]))
        });
        event(&mut out, pointer, 5, |_| {});
        compositor.write_all(&out).unwrap();
        let got = log_until(&log, |m| {
            m.iface == "wl_subsurface" && m.opcode == 4 && m.object == title_sub
        });
        let hidden = got.iter().any(|m| {
            m.iface == "wl_surface" && m.opcode == 1 && m.object == title && m.args[0] == 0
        });
        assert!(hidden, "{got:#?}");
        drop(client);
        assert_eq!(rig.finish(), 0);
    }

    #[test]
    fn the_border_pixel_is_sealed_and_says_the_colour() {
        let fd = pixel(Rgb(0x12, 0x34, 0x56)).unwrap();
        let mut bytes = [0u8; 64];
        // SAFETY: pread into a live buffer from a descriptor we own.
        let n = unsafe { libc::pread(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), 64, 0) };
        assert_eq!(n, 36, "a 3×3 square");
        for px in bytes[..36].chunks(4) {
            assert_eq!(u32::from_ne_bytes(px.try_into().unwrap()), 0xff12_3456);
        }
        // SAFETY: fcntl with no pointer.
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        let want = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        assert_eq!(seals & want, want);
        // SAFETY: ftruncate with no pointer.
        assert_ne!(
            unsafe { libc::ftruncate(fd.as_raw_fd(), 0) },
            0,
            "it shrank"
        );
    }

    #[test]
    fn the_filter_refuses_what_the_proxy_must_not_do() {
        let log = std::env::temp_dir().join(format!("vz-wl-proxy-pwrite-{}", std::process::id()));
        let file = fs::File::create(&log).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (a, _b) = UnixStream::pair().unwrap();
            let (memfd, writer) = title_memfd(64).unwrap();
            let colour = pixel(Rgb(0xff, 0, 0x80)).unwrap();
            filter(ScmpAction::Errno(libc::EPERM), Some(writer.as_raw_fd()))
                .unwrap()
                .load()
                .unwrap();
            let eperm = |r: libc::c_long| {
                r == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
            };
            let pwrite = |fd: RawFd| {
                // SAFETY: reads a live 4-byte buffer (when allowed at all).
                eperm(unsafe { libc::pwrite(fd, [0u8; 4].as_ptr().cast(), 4, 0) } as _)
            };
            // SAFETY: every call below either fails under the filter or acts
            // on memory/descriptors of this thread only.
            let mut results = unsafe {
                vec![
                    (
                        "socket",
                        eperm(libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as _),
                    ),
                    (
                        "openat",
                        eperm(libc::open(c"/etc/hostname".as_ptr(), libc::O_RDONLY) as _),
                    ),
                    (
                        "fcntl F_DUPFD",
                        eperm(libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 100) as _),
                    ),
                    (
                        "mmap exec",
                        libc::mmap(
                            std::ptr::null_mut(),
                            4096,
                            libc::PROT_READ | libc::PROT_EXEC,
                            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                            -1,
                            0,
                        ) == libc::MAP_FAILED,
                    ),
                    (
                        "mmap of a descriptor",
                        libc::mmap(
                            std::ptr::null_mut(),
                            4096,
                            libc::PROT_READ,
                            libc::MAP_PRIVATE,
                            0,
                            0,
                        ) == libc::MAP_FAILED,
                    ),
                    (
                        "ioctl other",
                        eperm(libc::ioctl(0, libc::FIONREAD, &mut 0i32) as _),
                    ),
                    ("kill", eperm(libc::kill(1, 0) as _)),
                    // The title's memory is made before the filter: none
                    // after it, and none resized.
                    (
                        "memfd_create",
                        eperm(libc::memfd_create(c"x".as_ptr(), libc::MFD_CLOEXEC) as _),
                    ),
                    ("ftruncate", eperm(libc::ftruncate(a.as_raw_fd(), 0) as _)),
                    (
                        "lseek",
                        eperm(libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) as _),
                    ),
                ]
            };
            // `pwrite64` to the title's writer only: not over the border's
            // colour, not over what a file holds already (stderr sent to
            // one), not through the title's other descriptor.
            results.extend([
                ("pwrite64 to the colour", pwrite(colour.as_raw_fd())),
                ("pwrite64 to a file", pwrite(file.as_raw_fd())),
                ("pwrite64 to the title's pool", pwrite(memfd.as_raw_fd())),
            ]);
            // And what it needs still works.
            let v: Vec<u8> = vec![1; 1 << 20];
            // The title's pixels are written into the memory made before.
            let title = {
                use std::os::unix::fs::FileExt;
                fs::File::from(writer).write_all_at(&[7; 8], 56).is_ok()
            };
            let fine = v.len() == 1 << 20 && outq(a.as_raw_fd()) == 0 && title;
            tx.send((results, fine)).unwrap();
        });
        let got = rx.recv_timeout(Duration::from_secs(10));
        let _ = fs::remove_file(&log);
        let (results, fine) = got.unwrap();
        for (what, refused) in results {
            assert!(refused, "{what} was allowed");
        }
        assert!(fine, "memory, TIOCOUTQ or the title's pwrite was refused");
    }
}
