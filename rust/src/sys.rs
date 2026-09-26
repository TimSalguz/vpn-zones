//! Thin wrappers over the syscalls this crate needs more than once.
//!
//! Nothing here is clever: it is the "build the C strings, check the return
//! value, turn `-1` into an `io::Error`" boilerplate that every caller would
//! otherwise repeat. The reason these two live together is that both the data
//! containers (`crate::profile`) and the zones (`crate::zone`) mount things,
//! and both the Wayland sandbox (`crate::wl_sandbox`) and the zone holder need
//! a pipe to synchronise a fork with.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// How many symlinks [`link_target`] follows before it gives up. The kernel's
/// own limit is 40; a resolv.conf hidden behind more than a handful of links is
/// a broken system, and any cap at all stops a symlink cycle from spinning here
/// forever.
const MAX_LINK_HOPS: usize = 8;

/// `mount(2)`.
///
/// An empty `source`, `fstype` or `data` is passed to the kernel as `NULL`, so
/// this one helper covers all three shapes the project uses: a filesystem mount
/// (tmpfs, overlay), a bind mount (`MS_BIND`, where the kernel ignores type and
/// data) and a propagation change (`MS_REC | MS_PRIVATE`, same).
///
/// **Why the syscall and not `mount(8)`.** The util-linux tool, started by a
/// non-root user, tries to drop privileges and dies with "drop permissions
/// failed" — even when the mount itself would be allowed. The raw syscall makes
/// no such check. (`docs/GOTCHAS.md` §1)
pub fn mount(
    source: &OsStr,
    target: &Path,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
) -> io::Result<()> {
    let source = cstring(source.as_bytes())?;
    let target = cstring(target.as_os_str().as_bytes())?;
    let fstype = cstring(fstype.as_bytes())?;
    let data = cstring(data.as_bytes())?;
    let or_null = |s: &CString| {
        if s.as_bytes().is_empty() {
            std::ptr::null()
        } else {
            s.as_ptr()
        }
    };
    // SAFETY: every pointer is either NULL or a valid NUL-terminated C string
    // owned by a local that outlives the call.
    let rc = unsafe {
        libc::mount(
            or_null(&source),
            target.as_ptr(),
            or_null(&fstype),
            flags,
            or_null(&data).cast(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A detached copy of the mount at `path` and every mount below it
/// (`open_tree(OPEN_TREE_CLONE | AT_RECURSIVE)`), to be attached elsewhere
/// with [`attach_tree`]. Recursive, because a mount whose children came from
/// a more privileged namespace (locked) cannot be copied without them: the
/// copy would bare what they cover.
pub fn clone_tree(path: &Path) -> io::Result<OwnedFd> {
    const OPEN_TREE_CLONE: libc::c_uint = 1;
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    let c = cstring(path.as_os_str().as_bytes())?;
    let flags = OPEN_TREE_CLONE | AT_RECURSIVE | libc::O_CLOEXEC as libc::c_uint;
    // SAFETY: open_tree(2) with a NUL-terminated path; a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just returned to us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// A detached bind of the one file `fd` names (`open_tree(fd, "",
/// OPEN_TREE_CLONE | AT_EMPTY_PATH)`): of what was opened and checked, not
/// of whatever a path names by the time it is bound.
pub fn clone_file(fd: &OwnedFd) -> io::Result<OwnedFd> {
    use std::os::fd::AsRawFd;
    const OPEN_TREE_CLONE: libc::c_uint = 1;
    const AT_EMPTY_PATH: libc::c_uint = 0x1000;
    let empty = cstring(b"")?;
    let flags = OPEN_TREE_CLONE | AT_EMPTY_PATH | libc::O_CLOEXEC as libc::c_uint;
    // SAFETY: open_tree(2) on a descriptor we hold, an empty NUL-terminated
    // path; a new descriptor or -1.
    let tree = unsafe { libc::syscall(libc::SYS_open_tree, fd.as_raw_fd(), empty.as_ptr(), flags) };
    if tree < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor was just returned to us.
    Ok(unsafe { OwnedFd::from_raw_fd(tree as i32) })
}

/// Attach a tree from [`clone_tree`] at `target` (`move_mount(2)`).
pub fn attach_tree(tree: &OwnedFd, target: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
    let c = cstring(target.as_os_str().as_bytes())?;
    let empty = cstring(b"")?;
    // SAFETY: move_mount(2) with a descriptor we hold and two NUL-terminated
    // paths.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_FDCWD,
            c.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A directory as a descriptor that only names it (`O_PATH`): what a process
/// keeps to reach a directory that is about to be covered by a mount, through
/// `/proc/self/fd/N`.
pub fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    let c = cstring(path.as_os_str().as_bytes())?;
    // SAFETY: a NUL-terminated path and constant flags.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor just opened and owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Make the mount at `path` read-only. In a user namespace the flags a mount
/// came with from the parent are locked (nosuid, nodev, noexec, the atime
/// ones), and a remount that leaves one out is refused: they are read back and
/// kept.
pub fn remount_read_only(path: &Path) -> io::Result<()> {
    let c = cstring(path.as_os_str().as_bytes())?;
    // SAFETY: statvfs is plain data; the call fills it or fails.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a statvfs to fill.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY;
    for (st_flag, ms_flag) in [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ] {
        if st.f_flag & st_flag != 0 {
            flags |= ms_flag;
        }
    }
    mount(OsStr::new(""), path, "", flags, "")
}

/// `pipe2(O_CLOEXEC)` as an owning pair (read end, write end).
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds: [libc::c_int; 2] = [0; 2];
    // SAFETY: `fds` is a valid array of two ints for the duration of the call.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 has just handed us these two descriptors and nothing else
    // owns them.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// An inotify watch on one directory for what appears in it.
pub struct Inotify {
    fd: OwnedFd,
    dir: PathBuf,
}

impl Inotify {
    /// Watch `dir` for entries created or moved into it.
    pub fn watch(dir: &Path) -> io::Result<Self> {
        Self::watch_for(dir, libc::IN_CREATE | libc::IN_MOVED_TO)
    }

    /// Watch `dir` for the events of `mask`.
    fn watch_for(dir: &Path, mask: u32) -> io::Result<Self> {
        // SAFETY: inotify_init1 takes flags and returns a new descriptor or -1.
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor was just returned to us and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let path = cstring(dir.as_os_str().as_bytes())?;
        // SAFETY: a valid inotify descriptor and a NUL-terminated path.
        let wd = unsafe {
            libc::inotify_add_watch(std::os::fd::AsRawFd::as_raw_fd(&fd), path.as_ptr(), mask)
        };
        if wd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            dir: dir.to_path_buf(),
        })
    }

    /// Block until something appears; the names that did. When the queue
    /// overflowed, every name in the directory — the caller cannot know what
    /// it missed. `Err` when the watch is gone for good.
    pub fn names(&self) -> io::Result<Vec<String>> {
        let mut buf = vec![0u8; 16 * 1024];
        // SAFETY: a valid descriptor and a buffer of the length passed.
        let n = unsafe {
            libc::read(
                std::os::fd::AsRawFd::as_raw_fd(&self.fd),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(Vec::new())
            } else {
                Err(e)
            };
        }
        let (names, overflow) = parse_inotify(&buf[..n as usize]);
        if overflow {
            return Ok(std::fs::read_dir(&self.dir)
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default());
        }
        Ok(names)
    }
}

/// How a [`wait_for_entry_or`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waited {
    /// `ready` held.
    There,
    /// The process it was waited on ended first.
    MakerGone,
    /// The one it was waited for hung up first.
    PeerGone,
}

/// Wait, as long as it takes, until `ready(path)` holds — looked at again
/// whenever something appears in its directory or is written there — or the
/// process of `pidfd` ends (`false`: it will not make it now). No clock
/// decides: a loaded machine makes it later, never "not there". Without a
/// watch on the directory (not there yet, no inotify instance left) it is
/// looked at every [`LOOK_AGAIN`] instead — which decides how soon, and
/// nothing else; a failed `poll` (no memory for it) is waited out the same
/// way, never taken for the maker's end.
pub fn wait_for_entry(path: &Path, pidfd: Option<&OwnedFd>, ready: impl Fn(&Path) -> bool) -> bool {
    wait_for_entry_or(path, pidfd, None, ready) == Waited::There
}

/// [`wait_for_entry`], and ended too by `peer` hanging up (`POLLRDHUP`): a
/// client the wait is for that went.
pub fn wait_for_entry_or(
    path: &Path,
    pidfd: Option<&OwnedFd>,
    peer: Option<RawFd>,
    ready: impl Fn(&Path) -> bool,
) -> Waited {
    use std::os::fd::AsRawFd;
    let watch = path.parent().and_then(|dir| {
        Inotify::watch_for(
            dir,
            libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_CLOSE_WRITE | libc::IN_MODIFY,
        )
        .ok()
    });
    let pollin = |fd: RawFd, events: libc::c_short| libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        if ready(path) {
            return Waited::There;
        }
        let mut fds: Vec<libc::pollfd> = Vec::with_capacity(3);
        if let Some(fd) = pidfd {
            fds.push(pollin(fd.as_raw_fd(), libc::POLLIN));
        }
        if let Some(fd) = peer {
            fds.push(pollin(fd, libc::POLLRDHUP));
        }
        if let Some(w) = &watch {
            fds.push(pollin(w.fd.as_raw_fd(), libc::POLLIN));
        }
        let ms = if watch.is_some() {
            -1
        } else {
            LOOK_AGAIN.as_millis() as libc::c_int
        };
        // SAFETY: a valid array of pollfd and its length.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
        if rc < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                std::thread::sleep(LOOK_AGAIN);
            }
            continue;
        }
        for pfd in fds.iter().filter(|p| p.revents != 0) {
            if pidfd.is_some_and(|fd| fd.as_raw_fd() == pfd.fd) {
                return Waited::MakerGone;
            }
            if peer == Some(pfd.fd) {
                return Waited::PeerGone;
            }
            if let Some(w) = &watch {
                let _ = w.names();
            }
        }
    }
}

/// [`wait_for_entry`] on a child just started: through its pidfd, or — none
/// to be had — by asking whether it ended every [`LOOK_AGAIN`]. Never a
/// failed `pidfd_open` taken for the child's end.
pub fn wait_for_child_entry(
    path: &Path,
    child: &mut std::process::Child,
    ready: impl Fn(&Path) -> bool,
) -> bool {
    if let Some(pidfd) = pidfd_open(child.id() as i32) {
        return wait_for_entry(path, Some(&pidfd), ready);
    }
    loop {
        if ready(path) {
            return true;
        }
        if matches!(child.try_wait(), Ok(Some(_))) {
            return false;
        }
        std::thread::sleep(LOOK_AGAIN);
    }
}

/// How often a wait looks without a watch.
pub const LOOK_AGAIN: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether a pid file has its pid: pasta opens it (and so makes it) as it
/// starts, and writes it "once initialisation is done" — its namespace
/// configured. That write is what a wait for pasta waits for.
pub fn written(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() > 0)
}

/// A pid file for a pasta that runs as `uid`/`gid` in a directory it cannot
/// write: made empty here, the last one gone, and handed to it.
pub fn pid_file_for(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    // SAFETY: a valid descriptor and two ids.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A pid file for a pasta about to run with the group `gid`, made by a
/// process that may not give files away (no `CAP_CHOWN`: the system-zone
/// service): created with that group as its filesystem group (`CAP_SETGID`),
/// root's and writable by the group (0620). Only this thread's filesystem
/// group changes, and back.
pub fn pid_file_for_group(path: &Path, gid: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    // SAFETY: setfsgid(2) takes an id and returns the previous one.
    let before = unsafe { libc::setfsgid(gid) };
    let made = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o620)
        .open(path);
    // SAFETY: as above, the one it had.
    unsafe { libc::setfsgid(before as libc::gid_t) };
    let file = made?;
    let meta = file.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if meta.gid() != gid {
        return Err(io::Error::other("the pid file did not get the group"));
    }
    // The umask took the group's write away: given back.
    // SAFETY: a valid descriptor and a mode.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o620) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What happened in a directory a [`DirWatch`] watches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirEvent {
    /// An entry appeared (created, or moved in).
    Appeared(PathBuf),
    /// An entry went (deleted, or moved out).
    Gone(PathBuf),
    /// The queue overflowed: what happened is not known.
    Overflow,
}

/// An inotify watch on several directories, for what appears in them and
/// what goes.
pub struct DirWatch {
    fd: OwnedFd,
    dirs: std::sync::Mutex<std::collections::HashMap<i32, PathBuf>>,
}

impl DirWatch {
    pub fn new() -> io::Result<Self> {
        // SAFETY: inotify_init1 takes flags and returns a new descriptor or -1.
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: the descriptor was just returned to us.
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            dirs: Default::default(),
        })
    }

    /// Watch `dir` too.
    pub fn add(&self, dir: &Path) -> io::Result<()> {
        let path = cstring(dir.as_os_str().as_bytes())?;
        // SAFETY: a valid inotify descriptor and a NUL-terminated path.
        let wd = unsafe {
            libc::inotify_add_watch(
                std::os::fd::AsRawFd::as_raw_fd(&self.fd),
                path.as_ptr(),
                libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_DELETE | libc::IN_MOVED_FROM,
            )
        };
        if wd < 0 {
            return Err(io::Error::last_os_error());
        }
        self.dirs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(wd, dir.to_path_buf());
        Ok(())
    }

    /// Block until something happens; what did.
    pub fn events(&self) -> io::Result<Vec<DirEvent>> {
        let mut buf = vec![0u8; 16 * 1024];
        // SAFETY: a valid descriptor and a buffer of the length passed.
        let n = unsafe {
            libc::read(
                std::os::fd::AsRawFd::as_raw_fd(&self.fd),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(Vec::new())
            } else {
                Err(e)
            };
        }
        let dirs = self.dirs.lock().unwrap_or_else(|e| e.into_inner());
        Ok(parse_dir_events(&buf[..n as usize])
            .into_iter()
            .filter_map(|(wd, mask, name)| {
                if mask & libc::IN_Q_OVERFLOW != 0 {
                    return Some(DirEvent::Overflow);
                }
                let path = dirs.get(&wd)?.join(name?);
                if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
                    Some(DirEvent::Appeared(path))
                } else if mask & (libc::IN_DELETE | libc::IN_MOVED_FROM) != 0 {
                    Some(DirEvent::Gone(path))
                } else {
                    None
                }
            })
            .collect())
    }
}

/// `(watch, mask, name)` of each `struct inotify_event` in a buffer.
pub fn parse_dir_events(mut buf: &[u8]) -> Vec<(i32, u32, Option<String>)> {
    const HEADER: usize = 16;
    let mut out = Vec::new();
    while buf.len() >= HEADER {
        let field =
            |at: usize| u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        let wd = field(0) as i32;
        let mask = field(4);
        let len = field(12) as usize;
        if buf.len() < HEADER + len {
            break;
        }
        let raw = &buf[HEADER..HEADER + len];
        let raw = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
        let name = (!raw.is_empty()).then(|| String::from_utf8_lossy(raw).into_owned());
        out.push((wd, mask, name));
        buf = &buf[HEADER + len..];
    }
    out
}

/// The names in a buffer of `struct inotify_event`s, and whether the queue
/// overflowed.
pub fn parse_inotify(mut buf: &[u8]) -> (Vec<String>, bool) {
    const HEADER: usize = 16;
    let mut names = Vec::new();
    let mut overflow = false;
    while buf.len() >= HEADER {
        let field =
            |at: usize| u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
        let mask = field(4);
        let len = field(12) as usize;
        if buf.len() < HEADER + len {
            break;
        }
        if mask & libc::IN_Q_OVERFLOW != 0 {
            overflow = true;
        }
        let name = &buf[HEADER..HEADER + len];
        let name = &name[..name.iter().position(|b| *b == 0).unwrap_or(name.len())];
        if !name.is_empty() {
            names.push(String::from_utf8_lossy(name).into_owned());
        }
        buf = &buf[HEADER + len..];
    }
    (names, overflow)
}

/// Make the mount at `path` and every mount below it read-only
/// (`mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY)`, Linux 5.12). On an older
/// kernel only the mount at `path` itself.
pub fn read_only_tree(path: &Path) -> io::Result<()> {
    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }
    const MOUNT_ATTR_RDONLY: u64 = 0x1;
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    let c = cstring(path.as_os_str().as_bytes())?;
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: a NUL-terminated path, a struct of the size given.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            c.as_ptr(),
            AT_RECURSIVE,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ENOSYS) {
        return remount_read_only(path);
    }
    Err(e)
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains a NUL byte"))
}

/// Where a path really ends once every symlink on the way has been followed.
///
/// Two callers need this and both need it for the same reason: `mount(2)`
/// resolves symlinks in its TARGET, and on NixOS `/etc/resolv.conf` is a chain
/// of them (`/etc/static/resolv.conf` → `/run/systemd/resolve/stub-resolv.conf`).
/// So the zone's bind mount does not land where it says it does, and the
/// filesystem sandbox has to pass in a file that is not where it looks like it
/// is. (`docs/GOTCHAS.md` §3)
///
/// `fs::canonicalize` cannot do this: it insists that every component exists,
/// and the interesting case is exactly the one where the last link dangles —
/// the zone has just covered the directory it points into with a tmpfs. A chain
/// that leads nowhere therefore comes back as the path it leads to, not as an
/// error; whether anything is there is the caller's question to ask.
///
/// The result carries no `..` left over from a relative link. The kernel would
/// have resolved those itself, but a CALLER cannot: `/etc/../run/systemd/…` —
/// which is what Ubuntu's `../run/systemd/resolve/stub-resolv.conf` expands to
/// — starts with `/etc` for anyone asking `starts_with`, and the sandbox asks
/// exactly that.
pub fn link_target(path: &Path) -> PathBuf {
    let mut current = path.to_path_buf();
    for _ in 0..MAX_LINK_HOPS {
        let Ok(next) = std::fs::read_link(&current) else {
            // Not a symlink, or not there at all: this is the end of the chain.
            break;
        };
        current = normalize(match current.parent() {
            // A relative link is relative to the directory the LINK is in.
            Some(dir) if next.is_relative() => dir.join(next),
            _ => next,
        });
    }
    current
}

/// Fold `.` and `..` away without touching the filesystem.
///
/// Lexical, and that is a deliberate simplification: it differs from the
/// kernel's answer only when the component before a `..` is itself a symlink to
/// somewhere else, and the paths this is used on (`/etc`, `/run`) are ordinary
/// directories on every system the project runs on.
fn normalize(path: PathBuf) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `rm -rf` that copes with what overlayfs leaves behind.
///
/// The kernel creates `work/work` inside every overlay workdir with mode 000.
/// GNU `rm -rf` (what the bash version called) handles that by falling back to
/// rmdir when a directory cannot be read; `std::fs::remove_dir_all` just gives
/// up with EACCES — which made `vpn-zone profile rm` fail on any profile that
/// had ever been mounted. Order of attempts: the fast path, then rmdir for an
/// unreadable-but-empty directory, then chmod u+rwx and recurse.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => remove_tree_fallback(path),
    }
}

fn remove_tree_fallback(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Every error names the path and the operation: an EACCES three levels
    // deep is undebuggable when the caller reports only the tree's root.
    let at =
        |op: &str, e: io::Error| io::Error::new(e.kind(), format!("{op} {}: {e}", path.display()));
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(at("stat", e)),
    };
    if !meta.is_dir() {
        return std::fs::remove_file(path).map_err(|e| at("unlink", e));
    }
    // Empty but unreadable (the overlay's work/work): rmdir needs no read
    // permission on the directory itself.
    if std::fs::remove_dir(path).is_ok() {
        return Ok(());
    }
    let mut perms = meta.permissions();
    perms.set_mode(perms.mode() | 0o700);
    if let Err(e) = std::fs::set_permissions(path, perms) {
        eprintln!("remove_tree: chmod {}: {e}", path.display());
    }
    for entry in std::fs::read_dir(path).map_err(|e| at("opendir", e))? {
        remove_tree_fallback(&entry.map_err(|e| at("readdir", e))?.path())?;
    }
    std::fs::remove_dir(path).map_err(|e| at("rmdir", e))
}

#[cfg(test)]
mod remove_tree_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn removes_a_mode_zero_overlay_work_dir() {
        let root = std::env::temp_dir().join(format!("vpn-rmtree-{}", std::process::id()));
        let work = root.join(".config").join("work").join("work");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(root.join(".config").join("upper"), b"x").unwrap();
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o000)).unwrap();
        remove_tree(&root).unwrap();
        assert!(!root.exists());
    }
}

#[cfg(test)]
mod link_target_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_chain_is_followed_to_the_end_even_when_the_end_is_missing() {
        let root = std::env::temp_dir().join(format!("vpn-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/static")).unwrap();
        std::fs::create_dir_all(root.join("run")).unwrap();
        // The NixOS shape, seen from inside a zone that has just hidden the
        // resolver's directory: a relative link, then an absolute one, then
        // nothing at all where the chain ends.
        symlink("static/resolv.conf", root.join("etc/resolv.conf")).unwrap();
        symlink(
            root.join("run/stub.conf"),
            root.join("etc/static/resolv.conf"),
        )
        .unwrap();
        assert_eq!(
            link_target(&root.join("etc/resolv.conf")),
            root.join("run/stub.conf")
        );
        // An ordinary file is its own target, and so is a path with nothing
        // behind it: neither is a link.
        std::fs::write(root.join("run/plain.conf"), b"nameserver 10.0.0.1\n").unwrap();
        assert_eq!(
            link_target(&root.join("run/plain.conf")),
            root.join("run/plain.conf")
        );
        assert_eq!(link_target(&root.join("run/none")), root.join("run/none"));
        // Ubuntu's shape: a link out of /etc and back down through `..`. The
        // `..` must not survive, or a caller asking "is this inside /etc?"
        // gets the wrong answer.
        symlink("../run/stub.conf", root.join("etc/up.conf")).unwrap();
        assert_eq!(
            link_target(&root.join("etc/up.conf")),
            root.join("run/stub.conf")
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(test)]
mod inotify_tests {
    use super::*;

    /// Waited for as long as it takes — and no longer than its maker lives.
    #[test]
    fn an_entry_is_waited_for_until_it_is_there_or_its_maker_is_gone() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("vz-wait-entry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let wait = |script: &str, path: &Path| {
            let mut maker = Command::new("sh")
                .args(["-c", script, "sh"])
                .arg(&dir)
                .spawn()
                .unwrap();
            let fd = pidfd_open(maker.id() as i32).unwrap();
            let there = wait_for_entry(path, Some(&fd), Path::exists);
            let _ = maker.kill();
            let _ = maker.wait();
            there
        };
        // Made a moment later, by a maker that goes on.
        assert!(wait(
            "sleep 0.3; touch \"$1/sock\"; sleep 30",
            &dir.join("sock")
        ));
        // Its maker gone without it.
        assert!(!wait("sleep 0.2", &dir.join("never")));
        // No directory to watch yet: looked at again until it is there.
        assert!(wait(
            "sleep 0.3; mkdir \"$1/later\"; touch \"$1/later/x\"; sleep 30",
            &dir.join("later/x")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inotify_events_are_read_past_their_padding() {
        let mut buf = Vec::new();
        for (mask, name) in [(libc::IN_CREATE, "pipewire-0"), (libc::IN_Q_OVERFLOW, "")] {
            let mut padded = name.as_bytes().to_vec();
            if !padded.is_empty() {
                padded.resize(16, 0);
            }
            buf.extend_from_slice(&1i32.to_ne_bytes());
            buf.extend_from_slice(&mask.to_ne_bytes());
            buf.extend_from_slice(&0u32.to_ne_bytes());
            buf.extend_from_slice(&(padded.len() as u32).to_ne_bytes());
            buf.extend_from_slice(&padded);
        }
        let (names, overflow) = parse_inotify(&buf);
        assert_eq!(names, ["pipewire-0"]);
        assert!(overflow);
    }
}

// --- DESCRIPTORS OVER A UNIX SOCKET -----------------------------------------

/// Room for `count` descriptors in a control message, in u64s so that the
/// buffer is aligned the way `cmsghdr` wants.
fn control_buffer(count: usize) -> (Vec<u64>, usize) {
    let payload = (count * std::mem::size_of::<libc::c_int>()) as libc::c_uint;
    // SAFETY: CMSG_SPACE is arithmetic.
    let space = unsafe { libc::CMSG_SPACE(payload) } as usize;
    (vec![0u64; space.div_ceil(8)], space)
}

pub fn send_with_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let (mut control, space) = control_buffer(fds.len());
    // SAFETY: msghdr is plain data; every pointer set below outlives sendmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let payload = std::mem::size_of_val(fds) as libc::c_uint;
        // SAFETY: the control buffer has room for one header and `fds`, and is
        // aligned for cmsghdr.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(payload) as _;
            let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
            for (i, fd) in fds.iter().enumerate() {
                data.add(i).write_unaligned(*fd);
            }
        }
    }
    // SAFETY: a valid descriptor and a filled msghdr.
    let sent = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent.unsigned_abs() != data.len() {
        return Err(io::Error::other("the request was cut short"));
    }
    Ok(())
}

pub fn recv_with_fds(
    sock: RawFd,
    max: usize,
    max_fds: usize,
) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut data = vec![0u8; max];
    let (n, fds, truncated) = recv_into_with_fds(sock, &mut data, max_fds)?;
    if truncated {
        return Err(io::Error::other("the request is too large"));
    }
    data.truncate(n);
    Ok((data, fds))
}

/// One `recvmsg` into `buf`: how many bytes, the descriptors that came with
/// them, and whether anything was cut off — the data (`MSG_TRUNC`, only on
/// datagram sockets) or descriptors that did not fit (`MSG_CTRUNC`: the kernel
/// closed them, and a stream that carries them is broken from here on).
pub fn recv_into_with_fds(
    sock: RawFd,
    buf: &mut [u8],
    max_fds: usize,
) -> io::Result<(usize, Vec<OwnedFd>, bool)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let (mut control, space) = control_buffer(max_fds);
    // SAFETY: msghdr is plain data; every pointer set below outlives recvmsg.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: a valid descriptor and a prepared msghdr.
    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fds = Vec::new();
    // SAFETY: walking the control messages the kernel wrote into our buffer;
    // every descriptor found is ours from here on.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let base = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                for i in 0..payload / std::mem::size_of::<libc::c_int>() {
                    fds.push(OwnedFd::from_raw_fd(base.add(i).read_unaligned()));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    let truncated = msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
    Ok((n.unsigned_abs(), fds, truncated))
}

/// When a process started, in clock ticks after boot: field 22 of
/// `/proc/<pid>/stat`. A pid is reused — at once after a reboot, after a while
/// in a long session —, a pid with its start time is not: together they name
/// one process for the life of the system. `None` when there is no such
/// process.
pub fn start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time(&stat)
}

/// A process's mark for the files that name it by pid: its start time and
/// this boot's id. The start time counts from boot, and the files outlive a
/// reboot; with the boot's id beside it a mark from before one matches nothing.
pub fn process_stamp(pid: i32) -> Option<String> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    Some(format!("{} {}", start_time(pid)?, boot.trim()))
}

/// The start time out of a `stat` line. The command name is in parentheses
/// and may hold anything, spaces and parentheses too, so the fields are counted
/// after the LAST `)`: the first one there is field 3, the start time field 22.
pub fn parse_start_time(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// A descriptor of the process `pid`: whatever happens to the number later, a
/// signal sent through it reaches this process or nobody.
pub fn pidfd_open(pid: i32) -> Option<OwnedFd> {
    // SAFETY: pidfd_open(2) takes a pid and flags and returns a new descriptor
    // or -1; the descriptor is owned by nobody else.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

/// Send `signal` through a pidfd. False when the process is gone.
pub fn pidfd_signal(fd: &OwnedFd, signal: i32) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: a valid pidfd, a signal number, no siginfo, no flags.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        ) == 0
    }
}

/// How a child of ours stands when [`pidfd_stopped_or_gone`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    /// Held by a signal (`SIGSTOP`) or a tracer.
    Stopped,
    /// Ended — or reaped already, or not ours.
    Gone,
}

/// Wait, as long as it takes, until the child of a pidfd stops or ends. It
/// is not reaped (`WNOWAIT`): whoever holds its `Child` still does that.
pub fn pidfd_stopped_or_gone(fd: &OwnedFd) -> ChildState {
    use std::os::fd::AsRawFd;
    const P_PIDFD: libc::idtype_t = 3;
    loop {
        // SAFETY: an all-zero siginfo_t is a valid one to be filled.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: a valid pidfd and a siginfo_t to fill.
        let rc = unsafe {
            libc::waitid(
                P_PIDFD,
                fd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WSTOPPED | libc::WNOWAIT,
            )
        };
        if rc != 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return ChildState::Gone;
        }
        return match info.si_code {
            libc::CLD_STOPPED | libc::CLD_TRAPPED => ChildState::Stopped,
            _ => ChildState::Gone,
        };
    }
}

/// Wait up to `timeout` for the process of a pidfd to exit. True when it has.
pub fn pidfd_wait(fd: &OwnedFd, timeout: std::time::Duration) -> bool {
    use std::os::fd::AsRawFd;
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: one valid pollfd for the duration of the call. A pidfd polls
    // readable when its process has exited.
    unsafe { libc::poll(&mut pfd, 1, ms) == 1 }
}

/// Wait, as long as it takes, for the process of a pidfd to exit.
pub fn pidfd_wait_end(fd: &OwnedFd) {
    use std::os::fd::AsRawFd;
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: one valid pollfd for the duration of the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, -1) };
        if rc >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return;
        }
    }
}

/// The pid of the process on the other end of a Unix socket (`SO_PEERCRED`):
/// the one that called `connect`, as this process's pid namespace numbers it.
pub fn peer_pid(sock: RawFd) -> Option<i32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a descriptor, a correctly sized buffer and its length.
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0 && cred.pid > 0).then_some(cred.pid)
}

/// The process on the other end of a Unix socket, held: the kernel's pidfd of
/// the very process that connected (`SO_PEERPIDFD`, Linux 6.5). Only a kernel
/// that does not know the option (`ENOPROTOOPT`) gets one opened by `pid`, its
/// [`peer_pid`], instead — a number that may have changed hands meanwhile, so a
/// caller checks the process is alive after it has looked. Any other failure
/// is `None`: `ESRCH` is the kernel saying the peer has exited, and opening
/// its number then would hold whoever took it next (review 2026-09-25).
pub fn peer_pidfd(sock: RawFd, pid: i32) -> Option<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: a descriptor, a buffer of one int and its length.
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc == 0 && fd >= 0 {
        // SAFETY: the kernel just gave us this descriptor to own.
        return Some(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    if rc != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOPROTOOPT) {
        return pidfd_open(pid);
    }
    None
}

/// The parent of a process, from `/proc/<pid>/status` (`PPid`: 0 for one
/// whose parent is outside this pid namespace, and for pid 1).
pub fn parent_of(pid: i32) -> Option<i32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// The children of `pid`, by the `PPid` of every process.
///
/// A number read here stays the child's for as long as `pid` has not reaped
/// it: a caller that is `pid` itself, and does not wait in between, may signal
/// what it finds by number.
pub fn children_of(pid: i32) -> Vec<i32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|&child| parent_of(child) == Some(pid))
        .collect()
}

/// The longest parent chain [`descends_from`] climbs. A process tree is not
/// that deep; one that is was built to make somebody climb.
const MAX_ANCESTRY: usize = 1024;

/// Whether the process held by `pidfd` (numbered `pid`) is `ancestor` or below
/// it: its chain of parents reaches `ancestor`.
///
/// Every step is read while both of its processes are held and alive, so that
/// no number in the chain can have gone to somebody else in between. A parent
/// number read from a live child is that child's parent's; the parent is held
/// by a pidfd opened afterwards, and the child — still alive, still naming the
/// same parent — proves that pidfd is of the right process: had the parent
/// died before it was opened, the child would have been given another parent
/// first, and its number freed only after that.
pub fn descends_from(pid: i32, pidfd: &OwnedFd, ancestor: i32) -> bool {
    let alive = |fd: &OwnedFd| !pidfd_wait(fd, std::time::Duration::ZERO);
    let mut at = pid;
    let mut held: Option<OwnedFd> = None;
    for _ in 0..MAX_ANCESTRY {
        let fd = held.as_ref().unwrap_or(pidfd);
        if !alive(fd) {
            return false;
        }
        if at == ancestor {
            return true;
        }
        let Some(up) = parent_of(at).filter(|&up| up > 0) else {
            return false;
        };
        let Some(up_fd) = pidfd_open(up) else {
            return false;
        };
        // Read again with the parent held, and the child still alive: the
        // number read first was the parent's, and this pidfd is of it.
        if parent_of(at) != Some(up) || !alive(fd) {
            return false;
        }
        at = up;
        held = Some(up_fd);
    }
    false
}

/// The process held by `pidfd` (numbered `pid`) and its parents, nearest
/// first, each step read the way [`descends_from`] reads it — a parent held
/// by a pidfd, and the child still alive and still naming it — so that no
/// number in the list went to somebody else while it was read. Ends where a
/// step cannot be read so, at the top, or at [`MAX_ANCESTRY`].
pub fn ancestors(pid: i32, pidfd: &OwnedFd) -> Vec<i32> {
    let alive = |fd: &OwnedFd| !pidfd_wait(fd, std::time::Duration::ZERO);
    let mut out = Vec::new();
    let mut at = pid;
    let mut held: Option<OwnedFd> = None;
    for _ in 0..MAX_ANCESTRY {
        let fd = held.as_ref().unwrap_or(pidfd);
        if !alive(fd) {
            break;
        }
        out.push(at);
        let Some(up) = parent_of(at).filter(|&up| up > 0) else {
            break;
        };
        let Some(up_fd) = pidfd_open(up) else {
            break;
        };
        if parent_of(at) != Some(up) || !alive(fd) {
            break;
        }
        at = up;
        held = Some(up_fd);
    }
    out
}

#[cfg(test)]
mod process_tree {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_child_descends_from_us_and_our_parent_and_an_orphan_do_not() {
        let me = std::process::id() as i32;
        let own = pidfd_open(me).unwrap();
        assert!(descends_from(me, &own, me), "we are our own subtree");
        let up = ancestors(me, &own);
        assert_eq!(up.first(), Some(&me));
        assert_eq!(up.get(1).copied(), parent_of(me));
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let fd = pidfd_open(pid).unwrap();
        assert!(descends_from(pid, &fd, me));
        assert!(children_of(me).contains(&pid));
        assert_eq!(parent_of(pid), Some(me));
        // Upwards is not downwards.
        let up = parent_of(me).unwrap();
        if let Some(up_fd) = pidfd_open(up) {
            assert!(!descends_from(up, &up_fd, me));
        }
        // An exited process is nobody's.
        let _ = child.kill();
        let _ = child.wait();
        assert!(!descends_from(pid, &fd, me));
        // Started by a shell that has exited: given to another parent,
        // no longer ours.
        let out = std::process::Command::new("sh")
            .args(["-c", "sleep 30 >/dev/null 2>&1 </dev/null & echo $!"])
            .output()
            .unwrap();
        let orphan: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        let orphan_fd = pidfd_open(orphan).unwrap();
        assert!(!descends_from(orphan, &orphan_fd, me));
        assert!(pidfd_signal(&orphan_fd, libc::SIGKILL));
    }

    #[test]
    fn the_peer_of_a_socket_is_the_process_that_made_it() {
        let (a, _b) = UnixStream::pair().unwrap();
        let me = std::process::id() as i32;
        let pid = peer_pid(a.as_raw_fd()).unwrap();
        assert_eq!(pid, me);
        let fd = peer_pidfd(a.as_raw_fd(), pid).unwrap();
        assert!(descends_from(pid, &fd, me));
    }
}

#[cfg(test)]
mod process_identity {
    use super::*;

    #[test]
    fn the_start_time_is_found_whatever_the_command_is_called() {
        // Field 22 of a real line, with a name that has ") (" in it.
        let line = "4242 (evil) (name x) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615";
        assert_eq!(parse_start_time(line), Some(987654));
        assert_eq!(parse_start_time("4242 (short) S 1"), None);
        assert_eq!(parse_start_time("no parenthesis"), None);
    }

    #[test]
    fn our_own_start_time_is_steady_and_a_pidfd_waits_for_its_process() {
        let me = std::process::id() as i32;
        assert!(start_time(me).is_some());
        assert_eq!(start_time(me), start_time(me));
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let fd = pidfd_open(pid).unwrap();
        assert!(!pidfd_wait(&fd, std::time::Duration::from_millis(50)));
        assert!(pidfd_signal(&fd, libc::SIGTERM));
        let _ = child.wait();
        assert!(pidfd_wait(&fd, std::time::Duration::from_millis(50)));
        assert!(!pidfd_signal(&fd, libc::SIGTERM));
    }
}
