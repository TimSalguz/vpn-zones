//! The unix sockets a zone can reach, as a checked invariant
//! (`docs/LEAK-MODEL.md` §15, §17, §18; ROADMAP: the ways out of a zone as an
//! invariant).
//!
//! A socket by path is not a network object. The zone's own network namespace
//! cuts every abstract socket of the host (`@name`), and none of these: what a
//! program connects to by path is a helper outside that acts for whoever
//! connects. An ssh ControlMaster runs a command on a remote machine, a root
//! daemon in `/run` (tailscaled, cups, docker, libvirt) does what its API
//! offers, the Nix daemon fetches in the host's network, an editor's server
//! runs a command on the host. The kernel stops none of it, because the
//! program itself goes nowhere: the helper does, outside the zone.
//!
//! So the probe (`doctor-probe`, INSIDE the zone) walks the places such a
//! socket lives — the runtime directory, `~/.ssh`, `/run`, `/var/lib`,
//! `/nix/var`, the home, the temporary directories — and lists every socket a
//! program of the zone could connect to; [`classify`] tells the zone's own
//! from the rest. The rules of the walk are the point of it:
//!
//! * the rights are the program's: the probe sheds the session's groups as
//!   `profile-run` does and holds no capability (`crate::doctor::probe_main`),
//!   and "may connect" is the kernel's own answer (`access(2)` for writing,
//!   ACLs included) — never a reading of mode bits;
//! * directories only are opened, each with `O_DIRECTORY | O_NOFOLLOW |
//!   O_NONBLOCK` from its parent's descriptor: a symlink a program planted
//!   takes the walk nowhere, and a FIFO is never opened, so it cannot hold it.
//!   A place itself, and a well-known name, is reached one component at a
//!   time ([`resolve_dir`]): a link is followed only when a program of the
//!   zone cannot have made it (`/var/run`, `/home` → `/var/home`);
//! * network and FUSE filesystems and automount points are not entered — a
//!   hung server would hang the probe (the document portal, gvfs, NFS, sshfs,
//!   9p). A directory is told by its device, asked with `AT_STATX_DONT_SYNC |
//!   AT_NO_AUTOMOUNT` BEFORE it is opened, whatever it is called; what was not
//!   entered is named;
//! * bounded, each place on its own: a depth, a number of entries, and a
//!   number of entries per directory — a program that fills
//!   a directory it may write spends that directory's budget, never another
//!   place's. What was not seen is said (`warn`), never taken for "nothing
//!   there".
//!
//! A socket in a directory a program may search but not read is found only
//! under a well-known name ([`KNOWN`]): a listing cannot see it, a program
//! that knows the name connects all the same.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::doctor::{Check, Level};

/// A device as `major:minor`, the way `/proc/self/mountinfo` writes it.
pub type Dev = (u32, u32);

/// A place the walk reads, and how many directories deep below it (the
/// entries of a directory that deep are still read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub path: PathBuf,
    pub depth: usize,
}

/// The system's places and their depths. `/run` to five: a daemon's socket
/// sits in a directory of its own, sometimes two. `/nix/var` only to three:
/// below that are the build logs, tens of thousands of them, and never a
/// socket.
pub const PLACES: [(&str, usize); 4] = [
    ("/run", 5),
    ("/var/run", 5),
    ("/nix/var", 3),
    ("/var/lib", 3),
];
/// The temporary directories, after the home.
pub const TMP_PLACES: [(&str, usize); 3] = [("/tmp", 3), ("/var/tmp", 3), ("/dev/shm", 2)];
/// How deep into the home: `~/.ssh/<master>` and
/// `~/.local/share/<program>/<dir>/<socket>` are in reach, a program's caches
/// three levels further are not — a real home has hundreds of thousands of
/// entries at six.
pub const HOME_DEPTH: usize = 3;
/// How deep into the runtime directory: `vpn-zones/wayland/<zone>/<socket>`.
pub const RUNTIME_DEPTH: usize = 3;

/// Sockets by their well-known names, looked at whether or not a listing
/// finds them: a daemon's directory is often `0711` or deeper than the walk
/// goes. The runtime directory's own are added by the probe.
pub const KNOWN: [&str; 16] = [
    "/run/docker.sock",
    "/run/podman/podman.sock",
    "/run/containerd/containerd.sock",
    "/run/libvirt/libvirt-sock",
    "/run/libvirt/virtqemud-sock",
    "/run/libvirt/virtnetworkd-sock",
    "/var/lib/incus/unix.socket",
    "/var/lib/lxd/unix.socket",
    "/run/cups/cups.sock",
    "/run/tailscale/tailscaled.sock",
    "/run/snapd.socket",
    "/run/pcscd/pcscd.comm",
    "/run/dbus/system_bus_socket",
    "/run/systemd/private",
    "/nix/var/nix/daemon-socket/socket",
    crate::sysrun::SOCKET,
];

/// How much the walk may cost. It runs on every `vpn-zone doctor`, and a
/// program of the zone can fill the places it may write: every place has a
/// budget of its own, so that filling `/tmp` costs `/tmp` and nothing else,
/// and a directory has one inside it, so that one full directory does not
/// cost its siblings. What is read is bounded, not how long it takes: no
/// clock, so a loaded machine reads as much as an idle one (slow filesystems
/// are not entered at all, see above); the doctor waits for the probe
/// however long it takes (`crate::doctor::run_bounded`).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub place_entries: usize,
    pub dir_entries: usize,
}

pub const LIMITS: Limits = Limits {
    place_entries: 100_000,
    dir_entries: 20_000,
};

/// At most this many foreign sockets are named line by line; the rest are
/// counted, and their level still counts. A program can make sockets by the
/// hundred thousand in its home — the report must stay a report.
pub const NAMED_MAX: usize = 200;
/// A path longer than this is cut in a report line.
pub const SHOWN_MAX: usize = 300;

/// A socket a program here may connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub path: Vec<u8>,
    pub dev: Dev,
    pub ino: u64,
}

/// What the walk saw.
#[derive(Debug, Default)]
pub struct Walk {
    /// Sorted by path, each socket once (by device and inode: `/var/run` is
    /// usually `/run`).
    pub found: Vec<Found>,
    pub entries: usize,
    /// What was not looked at, said in words; empty when nothing was left.
    pub incomplete: Vec<String>,
    /// Directories below a place that are mounts of a network or FUSE
    /// filesystem, or automount points: not entered, named. Not a gap of the
    /// walk in the same sense as [`Walk::incomplete`]: a socket there is a
    /// socket of that filesystem, which a program reaches only where the same
    /// mount has one bound — the document portal and gvfs make none.
    pub skipped: Vec<Vec<u8>>,
}

// --- MOUNTS ---------------------------------------------------------------------

/// One line of `/proc/self/mountinfo`, what the walk needs of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub dev: Dev,
    pub point: Vec<u8>,
    pub fstype: String,
}

/// The mounts of a `mountinfo`. The mount point comes octal-escaped (`\040`
/// for a blank), and is unescaped here.
pub fn mounts(mountinfo: &str) -> Vec<Mount> {
    mountinfo
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let dev = parse_dev(fields.get(2)?)?;
            let point = unescape(fields.get(4)?);
            let dash = fields.iter().position(|f| *f == "-")?;
            let fstype = (*fields.get(dash + 1)?).to_owned();
            Some(Mount { dev, point, fstype })
        })
        .collect()
}

/// `major:minor`.
pub fn parse_dev(text: &str) -> Option<Dev> {
    let (major, minor) = text.split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn unescape(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let octal = &bytes[i + 1..i + 4];
            if octal.iter().all(|b| (b'0'..=b'7').contains(b)) {
                let value = octal
                    .iter()
                    .fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// A filesystem the walk does not enter: a server that hangs would hang the
/// probe with it (FUSE — the document portal, gvfs, sshfs, virtiofs —, NFS,
/// SMB, 9p, Ceph, AFS), and an automount point mounts one when looked into.
pub fn slow_fs(fstype: &str) -> bool {
    fstype.starts_with("fuse")
        || fstype.starts_with("nfs")
        || matches!(
            fstype,
            "autofs"
                | "cifs"
                | "smb3"
                | "smbfs"
                | "9p"
                | "ceph"
                | "glusterfs"
                | "afs"
                | "davfs"
                | "sshfs"
                | "virtiofs"
                | "lustre"
                | "orangefs"
                | "gfs2"
                | "ocfs2"
                | "coda"
        )
}

/// The same, by the magic `statfs(2)` answers for an open directory: the
/// last guard, for a mount made after the table was read. virtiofs has no
/// magic of its own: it is FUSE, and answers FUSE's.
fn slow_magic(magic: i64) -> bool {
    const FUSE: i64 = 0x6573_5546;
    const NFS: i64 = 0x6969;
    const SMB: i64 = 0x517b;
    const CIFS: i64 = 0xff53_4d42;
    const SMB2: i64 = 0xfe53_4d42;
    const V9FS: i64 = 0x0102_1997;
    const CEPH: i64 = 0x00c3_6400;
    const AUTOFS: i64 = 0x0187;
    const AFS: i64 = 0x5346_414f;
    const CODA: i64 = 0x7375_7245;
    const GFS2: i64 = 0x0116_1970;
    const OCFS2: i64 = 0x7461_636f;
    const ORANGEFS: i64 = 0x2003_0528;
    const LUSTRE: i64 = 0x0bd0_0bd0;
    [
        FUSE, NFS, SMB, CIFS, SMB2, V9FS, CEPH, AUTOFS, AFS, CODA, GFS2, OCFS2, ORANGEFS, LUSTRE,
    ]
    .contains(&magic)
}

/// The mounts the walk must not enter, by their point and by their device.
/// The point catches a path spelled the way the table spells it before
/// anything is asked of it; the device catches the same mount under any
/// other spelling — through a link, a bind, a home reached as `/home` while
/// the table says `/var/home` —, asked of the directory's parent without
/// waking the server ([`meta_at`]).
#[derive(Debug, Clone, Default)]
pub struct Slow {
    points: Vec<Vec<u8>>,
    devs: HashSet<Dev>,
}

impl Slow {
    pub fn new(mountinfo: &str) -> Self {
        let mut slow = Self::default();
        for mount in mounts(mountinfo) {
            if slow_fs(&mount.fstype) {
                slow.devs.insert(mount.dev);
                slow.points.push(mount.point);
            }
        }
        slow
    }

    /// At or below one of the points, by spelling alone.
    pub fn below(&self, path: &[u8]) -> bool {
        self.points.iter().any(|point| {
            point.as_slice() == b"/"
                || path == point.as_slice()
                || (path.starts_with(point) && path.get(point.len()) == Some(&b'/'))
        })
    }

    pub fn dev(&self, dev: Dev) -> bool {
        self.devs.contains(&dev)
    }
}

/// Where a zone covers the host's directory with a tmpfs of its own, besides
/// its runtime directory: the temporary directories of a hermetic zone
/// (`zone::private_tmp`) and every zone's X11 directory (`zone::hide_x11`).
const OWN_PLACES: [&str; 4] = ["/tmp", "/var/tmp", "/dev/shm", crate::x11::X11_DIR];

/// The filesystems the zone made for itself: a tmpfs mounted at the runtime
/// directory or one of [`OWN_PLACES`] that the host does not have. A socket
/// on one of them was bound by a process of the zone — nobody outside can
/// reach that filesystem to listen there.
///
/// `host` is the host's own devices, from its `mountinfo` (the doctor passes
/// them). Without them nothing is the zone's own: a tmpfs is a tmpfs, and the
/// host's `/tmp` looks exactly like the zone's.
pub fn own_devs(mountinfo: &str, runtime: &Path, host: Option<&HashSet<Dev>>) -> HashSet<Dev> {
    let Some(host) = host else {
        return HashSet::new();
    };
    let runtime = runtime.as_os_str().as_bytes();
    mounts(mountinfo)
        .into_iter()
        .filter(|m| {
            m.fstype == "tmpfs"
                && (m.point == runtime || OWN_PLACES.iter().any(|p| m.point == p.as_bytes()))
                && !host.contains(&m.dev)
        })
        .map(|m| m.dev)
        .collect()
}

// --- THE WALK -------------------------------------------------------------------

/// A directory being read, from a descriptor of its own.
struct Dir(*mut libc::DIR);

impl Dir {
    fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let raw = fd.as_raw_fd();
        // SAFETY: a valid descriptor, whose ownership passes to the stream.
        let dir = unsafe { libc::fdopendir(raw) };
        if dir.is_null() {
            return Err(io::Error::last_os_error());
        }
        std::mem::forget(fd);
        Ok(Self(dir))
    }

    fn fd(&self) -> RawFd {
        // SAFETY: a stream opened by fdopendir and not closed yet.
        unsafe { libc::dirfd(self.0) }
    }

    /// The next entry but `.` and `..`, with its `d_type`. `None` at the end,
    /// and on an error: what could not be read is not there for a program
    /// either.
    fn next_entry(&mut self) -> Option<(CString, u8)> {
        loop {
            // SAFETY: a stream opened by fdopendir and not closed yet; the
            // entry is copied out before the next call can overwrite it.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                return None;
            }
            // SAFETY: readdir returned a valid entry with a NUL-terminated
            // name.
            let (name, kind) = unsafe {
                (
                    CStr::from_ptr((*entry).d_name.as_ptr()).to_owned(),
                    (*entry).d_type,
                )
            };
            if name.as_bytes() != b"." && name.as_bytes() != b".." {
                return Some((name, kind));
            }
        }
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: opened by fdopendir, closed once, here.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn open_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: a NUL-terminated name and constant flags.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor just opened and owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A directory below `parent`, for reading only, never through a link.
fn open_dir_at(parent: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_NOFOLLOW,
    )
}

/// `fstatat(2)` without following a link.
fn stat_at(dir: RawFd, name: &CStr) -> Option<libc::stat> {
    // SAFETY: stat is plain data filled in by the kernel.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor (or AT_FDCWD), a NUL-terminated name and a
    // stat to fill.
    let rc = unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    (rc == 0).then_some(st)
}

fn fd_stat(fd: RawFd) -> Option<libc::stat> {
    // SAFETY: as in stat_at.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and a stat to fill.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st)
}

fn dev_of(st: &libc::stat) -> Dev {
    (libc::major(st.st_dev), libc::minor(st.st_dev))
}

/// What the walk asks of an entry before it goes in.
#[derive(Debug, Clone, Copy)]
struct Meta {
    dev: Dev,
    ino: u64,
    mode: u32,
    uid: u32,
}

/// `statx(2)` of `name` below `dir`, never following it, never mounting an
/// automount point, and without asking a network or FUSE server
/// (`AT_STATX_DONT_SYNC`: what the client already has). This is how a
/// directory is told to be on such a filesystem BEFORE it is opened — opening
/// it would already be a request to its server.
fn meta_at(dir: RawFd, name: &CStr) -> Option<Meta> {
    // SAFETY: statx is plain data filled in by the kernel.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor, a NUL-terminated name, constant flags and a
    // statx to fill.
    let rc = unsafe {
        libc::statx(
            dir,
            name.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | libc::AT_STATX_DONT_SYNC,
            libc::STATX_TYPE | libc::STATX_MODE | libc::STATX_INO | libc::STATX_UID,
            &mut stx,
        )
    };
    (rc == 0).then(|| Meta {
        dev: (stx.stx_dev_major, stx.stx_dev_minor),
        ino: stx.stx_ino,
        mode: u32::from(stx.stx_mode),
        uid: stx.stx_uid,
    })
}

/// Is the directory behind `fd` on a filesystem the walk must not read?
fn fd_is_slow(fd: RawFd) -> bool {
    // SAFETY: statfs is plain data filled in by the kernel.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor and a statfs to fill.
    if unsafe { libc::fstatfs(fd, &mut st) } != 0 {
        return true;
    }
    #[allow(clippy::unnecessary_cast)]
    slow_magic(st.f_type as i64)
}

/// A socket at `name` below `dir` that this process may connect to: its
/// device and inode. Connecting to a unix socket by path takes write
/// permission on it; `faccessat` checks with the real ids and, for a user
/// other than root, without capabilities — the program's case. Neither call
/// follows `name`: a socket swapped for a link in between is judged as the
/// link, which never makes a socket reachable that is not.
fn reachable_socket(dir: RawFd, name: &CStr) -> Option<(Dev, u64)> {
    let st = stat_at(dir, name)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return None;
    }
    // SAFETY: a valid descriptor and a NUL-terminated name.
    let rc = unsafe { libc::faccessat(dir, name.as_ptr(), libc::W_OK, libc::AT_SYMLINK_NOFOLLOW) };
    let rc = if rc != 0
        && matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL)
        ) {
        // A kernel without faccessat2 (before 5.8): the plain call, on a name
        // just seen to be a socket and not a link.
        // SAFETY: as above.
        unsafe { libc::faccessat(dir, name.as_ptr(), libc::W_OK, 0) }
    } else {
        rc
    };
    (rc == 0).then(|| (dev_of(&st), st.st_ino))
}

fn joined(base: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = base.to_vec();
    if path.last() != Some(&b'/') {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    path
}

/// The components of an absolute path, `.` and `..` resolved by spelling. Only
/// ever used on a path whose resolved part has no link in it (see
/// [`resolve_dir`]), where that is what the kernel would do too.
fn lexical(path: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for part in path.split(|b| *b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                out.pop();
            }
            name => out.push(name.to_vec()),
        }
    }
    out
}

/// Why a path was not resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unseen {
    /// Not there, or not a directory, or not ours to search: a program does
    /// not get there either.
    Absent,
    /// A network or FUSE filesystem, or an automount point, at this path.
    Slow(Vec<u8>),
    /// A link a program of the zone may have made, at this path: not
    /// followed.
    Link(Vec<u8>),
}

/// Open the directory at the absolute `path` as an `O_PATH` descriptor, one
/// component at a time, and say where it really is.
///
/// Every component is looked at with [`meta_at`] before it is entered: a
/// network or FUSE filesystem or an automount point stops here, before a
/// request reaches its server, whatever the path is called. A link is
/// followed only when it is not the user's: the zone's programs are the
/// user, so a link of root's (`/var/run` → `/run`, `/home` → `/var/home`) is
/// the system's layout, and one of the user's may be a program's trap — a
/// `~/.ssh` or a runtime entry pointed into a FUSE mount whose server it
/// stopped.
pub fn resolve_dir(path: &[u8], slow: &Slow) -> Result<(OwnedFd, Vec<u8>), Unseen> {
    const HOPS: usize = 8;
    // SAFETY: getuid(2) takes no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    if !path.starts_with(b"/") || path.split(|b| *b == b'/').any(|p| p == b"..") {
        return Err(Unseen::Absent);
    }
    let path_flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let root = open_at(libc::AT_FDCWD, c"/", path_flags).map_err(|_| Unseen::Absent)?;
    let mut pending: VecDeque<Vec<u8>> = lexical(path).into();
    let mut fd = root.try_clone().map_err(|_| Unseen::Absent)?;
    let mut real: Vec<u8> = b"/".to_vec();
    let mut hops = 0;
    while let Some(name) = pending.pop_front() {
        let full = joined(&real, &name);
        if slow.below(&full) {
            return Err(Unseen::Slow(full));
        }
        let c = CString::new(name).map_err(|_| Unseen::Absent)?;
        let meta = meta_at(fd.as_raw_fd(), &c).ok_or(Unseen::Absent)?;
        match meta.mode & libc::S_IFMT {
            libc::S_IFLNK => {
                hops += 1;
                if meta.uid == uid || hops > HOPS {
                    return Err(Unseen::Link(full));
                }
                let target = read_link_at(fd.as_raw_fd(), &c).ok_or(Unseen::Absent)?;
                // Start again from the root with the link replaced: the part
                // before it is real, so `..` in the target is resolved by
                // spelling exactly as the kernel would resolve it.
                let mut respelled = if target.starts_with(b"/") {
                    Vec::new()
                } else {
                    real.clone()
                };
                respelled.push(b'/');
                respelled.extend_from_slice(&target);
                for rest in &pending {
                    respelled.push(b'/');
                    respelled.extend_from_slice(rest);
                }
                pending = lexical(&respelled).into();
                fd = root.try_clone().map_err(|_| Unseen::Absent)?;
                real = b"/".to_vec();
            }
            libc::S_IFDIR => {
                if slow.dev(meta.dev) {
                    return Err(Unseen::Slow(full));
                }
                let next = open_at(fd.as_raw_fd(), &c, path_flags).map_err(|_| Unseen::Absent)?;
                // Swapped between the look and the open: not what was judged.
                let st = fd_stat(next.as_raw_fd()).ok_or(Unseen::Absent)?;
                if dev_of(&st) != meta.dev || st.st_ino != meta.ino {
                    return Err(Unseen::Absent);
                }
                fd = next;
                real = full;
            }
            _ => return Err(Unseen::Absent),
        }
    }
    Ok((fd, real))
}

fn read_link_at(dir: RawFd, name: &CStr) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: a valid descriptor, a NUL-terminated name and a buffer of the
    // length given.
    let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    let n = usize::try_from(n).ok().filter(|n| *n < buf.len())?;
    buf.truncate(n);
    Some(buf)
}

/// The socket at the absolute `path`, reached as [`resolve_dir`] reaches its
/// directory, if a program here may connect to it: `(real path, dev, ino)`.
pub fn reachable_at(path: &[u8], slow: &Slow) -> Option<(Vec<u8>, Dev, u64)> {
    let cut = path.iter().rposition(|b| *b == b'/')?;
    let (dir, name) = (&path[..cut.max(1)], &path[cut + 1..]);
    let (fd, real) = resolve_dir(dir, slow).ok()?;
    let name = CString::new(name).ok()?;
    let (dev, ino) = reachable_socket(fd.as_raw_fd(), &name)?;
    Some((joined(&real, name.as_bytes()), dev, ino))
}

/// Is there anything at the absolute `path` — reached as [`resolve_dir`]
/// reaches it, never through a link a program may have made, never into a
/// network or FUSE filesystem? A directory counts only with an entry in it.
pub fn present_at(path: &[u8], slow: &Slow) -> bool {
    let Some(cut) = path.iter().rposition(|b| *b == b'/') else {
        return false;
    };
    let (dir, name) = (&path[..cut.max(1)], &path[cut + 1..]);
    let Ok((fd, _)) = resolve_dir(dir, slow) else {
        return false;
    };
    let Ok(name) = CString::new(name) else {
        return false;
    };
    let Some(meta) = meta_at(fd.as_raw_fd(), &name) else {
        return false;
    };
    if meta.mode & libc::S_IFMT != libc::S_IFDIR {
        return true;
    }
    if slow.dev(meta.dev) {
        return false;
    }
    let Ok(dir) = open_dir_at(fd.as_raw_fd(), &name) else {
        return false;
    };
    if fd_is_slow(dir.as_raw_fd()) {
        return false;
    }
    Dir::from_fd(dir).is_ok_and(|mut d| d.next_entry().is_some())
}

/// Open `rel` below `root`, one component at a time, never through a link.
fn open_below(root: &OwnedFd, rel: &[CString]) -> Option<OwnedFd> {
    let mut current: Option<OwnedFd> = None;
    for name in rel {
        let parent = current
            .as_ref()
            .map_or(root.as_raw_fd(), AsRawFd::as_raw_fd);
        current = Some(open_dir_at(parent, name).ok()?);
    }
    current
}

/// What the walk carries from place to place.
#[derive(Default)]
struct Seen {
    dirs: HashSet<(Dev, u64)>,
    sockets: HashSet<(Dev, u64)>,
}

/// Walk `places`, each on a budget of its own ([`Limits`]), then look at
/// `known` by name. `slow` are the mounts not to enter ([`Slow`]).
pub fn walk(places: &[Place], known: &[PathBuf], slow: &Slow, limits: Limits) -> Walk {
    let mut out = Walk::default();
    let mut seen = Seen::default();
    for place in places {
        walk_place(place, slow, limits, &mut seen, &mut out);
    }
    for path in known {
        if let Some((real, dev, ino)) = reachable_at(path.as_os_str().as_bytes(), slow) {
            if seen.sockets.insert((dev, ino)) {
                out.found.push(Found {
                    path: real,
                    dev,
                    ino,
                });
            }
        }
    }
    out.found.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn walk_place(place: &Place, slow: &Slow, limits: Limits, seen: &mut Seen, out: &mut Walk) {
    let spelled = place.path.as_os_str().as_bytes();
    let (at, base) = match resolve_dir(spelled, slow) {
        Ok(found) => found,
        // Absent or unreadable: a program finds nothing there by listing
        // either (and the known names are looked at after).
        Err(Unseen::Absent) => return,
        Err(Unseen::Slow(at)) => {
            out.incomplete.push(format!(
                "{} не просмотрен: {} — сетевая или FUSE ФС (или автомонтирование)",
                shown(spelled),
                shown(&at)
            ));
            return;
        }
        Err(Unseen::Link(at)) => {
            out.incomplete.push(format!(
                "{} не просмотрен: {} — ссылка пользователя, по таким обход не ходит",
                shown(spelled),
                shown(&at)
            ));
            return;
        }
    };
    let Ok(root) = open_dir_at(at.as_raw_fd(), c".") else {
        return;
    };
    if fd_is_slow(root.as_raw_fd()) {
        out.incomplete.push(format!(
            "{} не просмотрен: сетевая или FUSE ФС",
            shown(spelled)
        ));
        return;
    }
    let Some(st) = fd_stat(root.as_raw_fd()) else {
        return;
    };
    // Seen already: `/var/run` after `/run`, `/run/user/<uid>` after the
    // runtime directory was walked as a place of its own.
    if !seen.dirs.insert((dev_of(&st), st.st_ino)) {
        return;
    }
    let mut entries = 0usize;
    let mut queue: VecDeque<(Vec<CString>, usize)> = VecDeque::new();
    queue.push_back((Vec::new(), 0));
    'dirs: while let Some((rel, level)) = queue.pop_front() {
        let dir_path = rel
            .iter()
            .fold(base.clone(), |path, name| joined(&path, name.as_bytes()));
        let fd = if rel.is_empty() {
            match root.try_clone() {
                Ok(fd) => fd,
                Err(_) => continue,
            }
        } else {
            // Gone, replaced by a link, or not ours to read: skipped, as a
            // program's listing would skip it.
            let Some(fd) = open_below(&root, &rel) else {
                continue;
            };
            if fd_is_slow(fd.as_raw_fd()) {
                out.skipped.push(dir_path);
                continue;
            }
            let Some(st) = fd_stat(fd.as_raw_fd()) else {
                continue;
            };
            if !seen.dirs.insert((dev_of(&st), st.st_ino)) {
                continue;
            }
            fd
        };
        let Ok(mut dir) = Dir::from_fd(fd) else {
            continue;
        };
        let mut in_dir = 0usize;
        while let Some((name, kind)) = dir.next_entry() {
            entries += 1;
            in_dir += 1;
            out.entries += 1;
            if entries > limits.place_entries {
                out.incomplete.push(format!(
                    "{} просмотрен не весь: остановлено после {} записей, на {}",
                    shown(&base),
                    limits.place_entries,
                    shown(&dir_path)
                ));
                break 'dirs;
            }
            if in_dir > limits.dir_entries {
                out.incomplete.push(format!(
                    "{}: больше {} записей — дальше не прочитан (так забивают каталог нарочно)",
                    shown(&dir_path),
                    limits.dir_entries
                ));
                continue 'dirs;
            }
            let (is_socket, is_dir) = match kind {
                libc::DT_SOCK => (true, false),
                libc::DT_DIR => (false, level < place.depth),
                libc::DT_UNKNOWN => {
                    match stat_at(dir.fd(), &name).map(|s| s.st_mode & libc::S_IFMT) {
                        Some(libc::S_IFSOCK) => (true, false),
                        Some(libc::S_IFDIR) => (false, level < place.depth),
                        _ => (false, false),
                    }
                }
                _ => (false, false),
            };
            if is_socket {
                if let Some((dev, ino)) = reachable_socket(dir.fd(), &name) {
                    if seen.sockets.insert((dev, ino)) {
                        out.found.push(Found {
                            path: joined(&dir_path, name.as_bytes()),
                            dev,
                            ino,
                        });
                    }
                }
            } else if is_dir {
                // Its device, asked before it is opened: a mount of a network
                // or FUSE filesystem, or an automount point, is named and not
                // entered, whatever it is called.
                let Some(meta) = meta_at(dir.fd(), &name) else {
                    continue;
                };
                if meta.mode & libc::S_IFMT != libc::S_IFDIR {
                    continue;
                }
                let child = joined(&dir_path, name.as_bytes());
                if slow.below(&child) || slow.dev(meta.dev) {
                    out.skipped.push(child);
                } else {
                    let mut below = rel.clone();
                    below.push(name);
                    queue.push_back((below, level + 1));
                }
            }
        }
    }
}

// --- WHAT EACH ONE IS -----------------------------------------------------------

/// What a socket found in the zone is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The zone's own: bound by a process of the zone, or one of ours bound
    /// in (the filters, the broker, the restricted Wayland sockets).
    Own(&'static str),
    /// A service of the system that does nothing for the caller beyond
    /// taking what it is given: the journal, sd_notify, user lookups.
    System(&'static str),
    /// A helper outside, in reach: named every time (`warn`).
    Open(&'static str),
    /// In reach although the project promises it is not (`fail`).
    Closed(&'static str),
}

impl Verdict {
    pub fn level(self) -> Level {
        match self {
            Self::Own(_) | Self::System(_) => Level::Ok,
            Self::Open(_) => Level::Warn,
            Self::Closed(_) => Level::Fail,
        }
    }
}

/// A socket of the host the zone is promised out of reach of, as the doctor
/// names it to the probe by its identity (`--closed=`): found under any other
/// name — a hard link in a directory the zone reaches — it is still that
/// socket, and still a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostSocket {
    Resolver,
    SystemTier,
    NixDaemon,
    Compositor,
    PipewireManager,
    /// The host's raw `pipewire-0`, in a hermetic zone that is not an audio
    /// manager.
    Pipewire,
    Pulse,
    X11,
    SessionBus,
    SystemdUser,
}

impl HostSocket {
    const ALL: [Self; 10] = [
        Self::Resolver,
        Self::SystemTier,
        Self::NixDaemon,
        Self::Compositor,
        Self::PipewireManager,
        Self::Pipewire,
        Self::Pulse,
        Self::X11,
        Self::SessionBus,
        Self::SystemdUser,
    ];

    pub fn tag(self) -> &'static str {
        match self {
            Self::Resolver => "resolver",
            Self::SystemTier => "sysrun",
            Self::NixDaemon => "nix-daemon",
            Self::Compositor => "compositor",
            Self::PipewireManager => "pipewire-manager",
            Self::Pipewire => "pipewire",
            Self::Pulse => "pulse",
            Self::X11 => "x11",
            Self::SessionBus => "bus",
            Self::SystemdUser => "systemd",
        }
    }

    pub fn parse(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.tag() == tag)
    }

    fn verdict(self) -> Verdict {
        Verdict::Closed(match self {
            Self::Resolver => "резолвер хоста под другим именем (тот же сокет): имена мимо туннеля",
            Self::SystemTier => "посредник системного уровня под другим именем (тот же сокет, §14)",
            Self::NixDaemon => {
                "Nix-демон хоста под другим именем (тот же сокет); зоне он не разрешён"
            }
            Self::Compositor => "композитор хоста под другим именем (тот же сокет, §13)",
            Self::PipewireManager => {
                "PipeWire без ограничений под другим именем (тот же сокет, §17)"
            }
            Self::Pipewire => {
                "PipeWire хоста без ограничений в герметичной зоне под другим именем \
                 (тот же сокет, §17)"
            }
            Self::Pulse => {
                "звуковой сервер хоста без фильтра под другим именем (тот же сокет, §17)"
            }
            Self::X11 => "X-сервер хоста под другим именем (тот же сокет, §7)",
            Self::SessionBus => {
                "сессионная шина хоста в герметичной зоне под другим именем (тот же сокет, §1–2)"
            }
            Self::SystemdUser => {
                "systemd --user в герметичной зоне под другим именем (тот же сокет, §1)"
            }
        })
    }
}

/// `tag:major:minor:inode,…`, as the doctor writes it. An entry that does not
/// read (another build's tag) is left out: the list only ever adds failures.
pub fn parse_closed(list: &str) -> HashMap<(Dev, u64), HostSocket> {
    list.split(',')
        .filter_map(|entry| {
            let mut parts = entry.split(':');
            let kind = HostSocket::parse(parts.next()?)?;
            let major = parts.next()?.parse().ok()?;
            let minor = parts.next()?.parse().ok()?;
            let ino = parts.next()?.parse().ok()?;
            parts
                .next()
                .is_none()
                .then_some((((major, minor), ino), kind))
        })
        .collect()
}

/// What the classification needs to know about the zone.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// `/run/user/<uid>`.
    pub runtime: PathBuf,
    /// The zone's name, when the doctor said it: its own Wayland directory,
    /// told from every other zone's.
    pub zone: Option<String>,
    /// The zone is to be hermetic: the host's session bus and `systemd --user`
    /// are promised out of reach.
    pub hermetic: bool,
    /// The zone is let reach the Nix daemon.
    pub nix_daemon: bool,
    /// A hermetic zone let have the host's raw `pipewire-0`
    /// (`hermetic::audio_manager`).
    pub audio_manager: bool,
    /// The zone's `/proc/self/mountinfo`: which of our sockets is bound where.
    pub mountinfo: String,
    /// [`own_devs`].
    pub own_devs: HashSet<Dev>,
    /// [`parse_closed`].
    pub closed: HashMap<(Dev, u64), HostSocket>,
}

/// What `path`, a socket on `dev` with the inode `ino`, is to a zone
/// described by `ctx`.
pub fn classify(path: &[u8], dev: Dev, ino: u64, ctx: &Context) -> Verdict {
    // Made in the zone: a nested compositor's `wayland-1` in the zone's own
    // runtime directory, a tmux server in a hermetic zone's own /tmp, the
    // zone's own X server. Nobody outside listens on a filesystem only the
    // zone has (and no socket of the host is linked onto it: a hard link does
    // not cross filesystems).
    if ctx.own_devs.contains(&dev) {
        return Verdict::Own("сделан в зоне");
    }
    // By path first: its words are the more exact where both say "closed".
    // By identity after: a promised-closed socket under a name of its own
    // choosing is the same socket (it takes `fs.protected_hardlinks = 0`, or
    // the owner, to make one — the doctor warns of the first).
    let by_path = classify_path(path, ctx);
    match (by_path, ctx.closed.get(&(dev, ino))) {
        (Verdict::Closed(_), _) | (_, None) => by_path,
        (_, Some(host)) => host.verdict(),
    }
}

/// [`classify`] by the path alone.
fn classify_path(path: &[u8], ctx: &Context) -> Verdict {
    let p = Path::new(OsStr::from_bytes(path));
    if crate::doctor::RESOLVER_SOCKETS
        .iter()
        .any(|r| p == Path::new(r))
    {
        return Verdict::Closed("резолвер хоста — имена мимо туннеля");
    }
    if p.starts_with(crate::zone::SYSTEM_TIER_DIR) {
        return Verdict::Closed(
            "посредник системного уровня: запуск в системной зоне — мимо туннеля (§14)",
        );
    }
    if p.starts_with(crate::zone::NIX_DAEMON_DIR) {
        return if ctx.nix_daemon {
            Verdict::Open("Nix-демон хоста — зоне разрешён: сборка и загрузка идут в сети хоста")
        } else {
            Verdict::Closed(
                "Nix-демон хоста: производная с фиксированным хешем качает любой адрес \
                 в сети хоста (зоне он не разрешён)",
            )
        };
    }
    if p.starts_with(crate::x11::X11_DIR) {
        return Verdict::Closed("X-сервер хоста: окна, ввод и буфер обмена всей машины (§7)");
    }
    if let Ok(rest) = p.strip_prefix(&ctx.runtime) {
        if let Some(verdict) = runtime_verdict(rest, p, ctx) {
            return verdict;
        }
    }
    if p == Path::new(crate::zone::SYSTEM_BUS) {
        return if crate::doctor::mounted_at(&ctx.mountinfo, crate::zone::SYSTEM_BUS) {
            Verdict::Own("фильтр системной шины")
        } else {
            Verdict::Open("системная шина хоста без фильтра: NetworkManager, hostname1 (§3)")
        };
    }
    if p.starts_with("/run/systemd/journal") {
        return Verdict::System("журнал");
    }
    if p == Path::new("/run/systemd/notify") {
        return Verdict::System("sd_notify");
    }
    if p.starts_with("/run/systemd/userdb") {
        return Verdict::System("userdb");
    }
    if p.starts_with("/nix/var/nix/gc-socket") {
        return Verdict::System("сборщик мусора Nix");
    }
    Verdict::Open(describe(p))
}

/// The runtime directory's entries by name; `None` for what is not one of
/// them.
fn runtime_verdict(rest: &Path, full: &Path, ctx: &Context) -> Option<Verdict> {
    let first = rest
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .unwrap_or_default();
    if crate::zone::compositor_private(&first) {
        return Some(Verdict::Closed(
            "композитор хоста: экран, буфер обмена, ввод — или запуск процесса на хосте (§13)",
        ));
    }
    if first.starts_with("pipewire-") && first.ends_with("-manager") {
        return Some(Verdict::Closed(
            "PipeWire без ограничений: любой клиент и поток (§17)",
        ));
    }
    if rest == Path::new("bus") {
        // The filter, never the proxy behind it: bound alone, the proxy hands
        // the portal's links to the host (§2) — a zone brought up before the
        // filter existed, or a regression of `seal_runtime`.
        return Some(
            if crate::zone::bus_is_zones_bus_filter(&ctx.mountinfo, full) {
                Verdict::Own("фильтр сессионной шины")
            } else if crate::zone::bus_is_zones_filter(&ctx.mountinfo, full) {
                let what =
                    "прокси сессионной шины без фильтра: ссылки портала уходят хосту (§2) — \
                        перезапусти зону";
                if ctx.hermetic {
                    Verdict::Closed(what)
                } else {
                    Verdict::Open(what)
                }
            } else if ctx.hermetic {
                Verdict::Closed(
                    "сессионная шина хоста в герметичной зоне: systemd --user и порталы — \
                 запуск процесса вне зоны (§1–2)",
                )
            } else {
                Verdict::Open(
                    "сессионная шина хоста: порталы и systemd --user — запуск вне зоны (§1–2)",
                )
            },
        );
    }
    if first == "systemd" {
        return Some(if ctx.hermetic {
            Verdict::Closed("systemd --user в герметичной зоне: запуск процесса вне зоны (§1)")
        } else {
            Verdict::Open("systemd --user: запуск процесса вне зоны (§1)")
        });
    }
    if rest == Path::new("pulse/native") {
        return Some(
            if crate::zone::pulse_is_zones_filter(&ctx.mountinfo, full) {
                Verdict::Own("фильтр pulse")
            } else {
                Verdict::Closed(
                    "звуковой сервер хоста без фильтра: модуль, соединяющийся наружу (§17)",
                )
            },
        );
    }
    if rest == Path::new("pipewire-0") {
        // The security context's socket (`pw_context`): the zone's clients
        // see what WirePlumber's policy lets them. Anything else here is the
        // host's raw one — every stream, monitor and link of the host.
        return Some(
            if crate::zone::pipewire_is_zones_context(&ctx.mountinfo, full) {
                Verdict::Own("ограниченный PipeWire")
            } else if ctx.hermetic && !ctx.audio_manager {
                Verdict::Closed(
                    "PipeWire хоста без ограничений в герметичной зоне: запись того, что \
                     играет хост, чужие потоки и связи (§17)",
                )
            } else if ctx.hermetic {
                Verdict::Open(
                    "PipeWire хоста без ограничений — зона объявлена менеджером звука \
                     (cellward audio-manager): всё, что играет хост, чужие потоки и связи (§17)",
                )
            } else {
                Verdict::Open(
                    "PipeWire хоста без ограничений: всё, что играет хост, чужие потоки и \
                     связи — обычной зоне по замыслу, как и systemd --user (§17)",
                )
            },
        );
    }
    if rest == Path::new(crate::broker::SOCKET) {
        return Some(Verdict::Own("брокер"));
    }
    if let Ok(below) = rest.strip_prefix(crate::wl_sandbox::SOCKET_DIR) {
        // `seal_runtime` binds this zone's directory and no other: one zone
        // must not reach another zone's sockets (`zone::OURS`).
        let owner = below
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().into_owned());
        return Some(match (owner, ctx.zone.as_deref()) {
            (Some(owner), Some(zone)) if owner == zone => Verdict::Own("ограниченный Wayland"),
            (_, None) => Verdict::Open("ограниченный Wayland — какой зоны, проба не знает"),
            _ => Verdict::Closed(
                "ограниченный Wayland ДРУГОЙ зоны: окна от её имени — зоне биндится только \
                 свой каталог",
            ),
        });
    }
    if rest.starts_with(crate::fs_sandbox::SCRATCH_SUBDIR) {
        return Some(Verdict::Own("песочницы зоны"));
    }
    None
}

/// What a helper outside probably is, by its path — only words for the
/// report; the level does not depend on them.
fn describe(p: &Path) -> &'static str {
    let s = p.to_string_lossy().to_lowercase();
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let any = |words: &[&str]| words.iter().any(|w| s.contains(w));
    // The first that fits. Order matters where two could: an ssh agent in
    // `~/.ssh` is an agent, `S.gpg-agent.ssh` is one too.
    if name == "S.gpg-agent.ssh" || any(&["/keyring/ssh", "/ssh-agent", "/ssh-auth"]) {
        "ssh-агент: вход на машины вашими ключами"
    } else if s.contains("dhcpcd") {
        "dhcpcd: интерфейсы, адреса и аренды хоста (§3)"
    } else if s.starts_with("/run/ssh-unix-local/") {
        "sshd хоста по unix-сокету (systemd-ssh-generator): вход на хост, если есть ключ или \
         пароль"
    } else if s.contains("/.ssh/") {
        "ssh: мастер-соединение (ControlMaster) — команда на удалённой машине от вашего имени"
    } else if name.starts_with("S.gpg-agent") || name.starts_with("S.keyboxd") {
        "gpg: подпись и расшифровка вашими ключами"
    } else if s.contains("/tmux-") {
        "сервер tmux: `run-shell` исполняет команду на хосте, в его сети (§15)"
    } else if s.contains("vpn-fs-sandbox") {
        "фильтр шины чужой песочницы: шина от имени чужой программы (§15)"
    } else if any(&["docker", "podman", "containerd"]) {
        "контейнерный движок: контейнер в сети хоста"
    } else if any(&["libvirt", "virtqemud", "incus", "lxd"]) {
        "виртуальные машины: машина в сети хоста"
    } else if any(&[
        "tailscale",
        "amnezia",
        "openvpn",
        "mullvad",
        "nordvpn",
        "protonvpn",
    ]) {
        "клиент VPN хоста: включить, выключить, перенастроить VPN хоста (§15)"
    } else if s.contains("cups") {
        "CUPS: печать, в том числе на сетевые принтеры"
    } else if s.contains("/at-spi/") {
        "шина специальных возможностей: чтение и управление окнами других программ"
    } else if s.contains("polkit") {
        "polkit: помощник агента аутентификации"
    } else if name == "SingletonSocket" {
        "«единственный экземпляр» Chromium или Electron: окно в процессе вне зоны (§15)"
    } else if any(&["keepassxc", "bitwarden", "1password"]) {
        "менеджер паролей: интеграция с браузером"
    } else if any(&["emacs", "nvim", "/zed", "vscode"]) {
        "сервер редактора: файл или команда на хосте"
    } else if name == "io.systemd.Hostname" {
        "hostnamed по varlink: имя, модель и id машины — то, что системная шина зоне не \
         отдаёт (§3)"
    } else if name == "io.systemd.Network" {
        "networkd по varlink: интерфейсы и адреса хоста (§3)"
    } else if s.starts_with("/run/systemd/") {
        "служба systemd по varlink: что она сделает для подключившегося, решают она и polkit"
    } else {
        "помощник вне зоны: что он сделает для подключившегося, проверка не знает"
    }
}

/// A path for a report line: printable, a control character or a byte that is
/// not UTF-8 written out, so that no name a program chose can break the
/// probe's line, pass for another path or reach the owner's terminal as an
/// escape sequence. Cut at [`SHOWN_MAX`] characters: a program picks the
/// length of the names too.
pub fn shown(path: &[u8]) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut push = |out: &mut String, piece: &str| {
        count += 1;
        if count <= SHOWN_MAX {
            out.push_str(piece);
        } else if count == SHOWN_MAX + 1 {
            out.push('…');
        }
    };
    for chunk in path.utf8_chunks() {
        for c in chunk.valid().chars() {
            if unseen_char(c) || c == '\\' {
                push(&mut out, &c.escape_unicode().to_string());
            } else {
                push(&mut out, c.encode_utf8(&mut [0; 4]));
            }
        }
        for byte in chunk.invalid() {
            push(&mut out, &format!("\\x{byte:02x}"));
        }
    }
    out
}

/// A character a terminal does not show as itself: a control character (C0,
/// DEL, C1 — an escape sequence), or one that reorders or hides the text
/// around it (bidirectional overrides and isolates, zero-width marks) and so
/// makes one path read as another.
pub fn unseen_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// At most `max` of `items`, then how many more.
fn listed(items: &[String], max: usize) -> String {
    let mut text = items
        .iter()
        .take(max)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > max {
        text.push_str(&format!(" и ещё {}", items.len() - max));
    }
    text
}

/// The checks: `sockets`, the summary; `tmp-sockets`, what of it is in the
/// temporary directories (the check of `docs/LEAK-MODEL.md` §15, kept by its
/// name); one `socket` per socket that is not the zone's own or the system's,
/// `<path> — <what it is>`, at its level — the first [`NAMED_MAX`] of them,
/// failures first, the rest counted.
pub fn checks(walk: &Walk, ctx: &Context, groups_shed: bool) -> Vec<Check> {
    let mut own: BTreeMap<&str, usize> = BTreeMap::new();
    let mut system: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lines = Vec::new();
    let mut in_tmp = Vec::new();
    for found in &walk.found {
        let verdict = classify(&found.path, found.dev, found.ino, ctx);
        match verdict {
            Verdict::Own(label) => *own.entry(label).or_default() += 1,
            Verdict::System(label) => *system.entry(label).or_default() += 1,
            Verdict::Open(what) | Verdict::Closed(what) => {
                let path = Path::new(OsStr::from_bytes(&found.path));
                if crate::doctor::TMP_DIRS.iter().any(|d| path.starts_with(d))
                    && !path.starts_with(crate::x11::X11_DIR)
                {
                    in_tmp.push(shown(&found.path));
                }
                lines.push(Check::new(
                    "socket",
                    verdict.level(),
                    format!("{} — {what}", shown(&found.path)),
                ));
            }
        }
    }
    let foreign = lines.len();
    let level_of_lines = lines.iter().map(|c| c.level).max().unwrap_or(Level::Ok);
    // Failures first, then by path (the walk's order): cut, what is named is
    // what matters most, and the level is everyone's.
    lines.sort_by_key(|c| std::cmp::Reverse(c.level));
    lines.truncate(NAMED_MAX);
    let counted = |map: &BTreeMap<&str, usize>| {
        map.iter()
            .map(|(label, n)| {
                if *n > 1 {
                    format!("{label} ×{n}")
                } else {
                    (*label).to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let total = |map: &BTreeMap<&str, usize>| map.values().sum::<usize>();
    let mut detail = String::new();
    detail.push_str(&if foreign == 0 {
        "чужих сокетов в досягаемости нет".to_owned()
    } else if foreign > lines.len() {
        format!(
            "чужих сокетов в досягаемости: {foreign}, названы {} (строки socket), остальные \
             посчитаны",
            lines.len()
        )
    } else {
        format!("чужих сокетов в досягаемости: {foreign} (строки socket)")
    });
    if !own.is_empty() {
        detail.push_str(&format!("; своих {}: {}", total(&own), counted(&own)));
    }
    if !system.is_empty() {
        detail.push_str(&format!(
            "; системных {}: {}",
            total(&system),
            counted(&system)
        ));
    }
    detail.push_str(&format!("; просмотрено записей: {}", walk.entries));
    if !walk.skipped.is_empty() {
        let skipped: Vec<String> = walk.skipped.iter().map(|p| shown(p)).collect();
        detail.push_str(&format!(
            "; не входил (сетевые и FUSE ФС, автомонтирование): {}",
            listed(&skipped, 10)
        ));
    }
    if !walk.incomplete.is_empty() {
        detail.push_str(&format!(
            "; перечень НЕПОЛНЫЙ — {}",
            listed(&walk.incomplete, 10)
        ));
    }
    if !groups_shed {
        detail.push_str("; группы сеанса не сняты — доступ проверен шире, чем у программ зоны");
    }
    let mut level = level_of_lines;
    if !walk.incomplete.is_empty() {
        level = level.max(Level::Warn);
    }
    let mut out = vec![
        Check::new("sockets", level, detail),
        crate::doctor::listed_channel_check(
            "tmp-sockets",
            &in_tmp,
            "сокеты во временных каталогах — где /tmp общий с хостом, это сокеты хоста и \
             других зон: сервер tmux (`run-shell` — команда на хосте, в его сети), IPC \
             клиентов VPN (§15); у герметичной зоны /tmp свой",
        ),
    ];
    out.extend(lines);
    out
}

/// The places for a user whose runtime directory is `runtime` and home is
/// `home`, in the order they are walked. The runtime directory and `~/.ssh`
/// are places of their own, and first: `/run` and the home would reach them
/// too, but then on `/run`'s and the home's budget — which a program that
/// fills its home would spend. A directory is read once, by the first place
/// that reaches it.
pub fn places(runtime: &Path, home: Option<&Path>) -> Vec<Place> {
    let place = |path: PathBuf, depth: usize| Place { path, depth };
    let home = home.filter(|h| h.is_absolute());
    let mut out = vec![place(runtime.to_path_buf(), RUNTIME_DEPTH)];
    if let Some(home) = home {
        out.push(place(home.join(".ssh"), 0));
    }
    out.extend(PLACES.iter().map(|(p, d)| place(PathBuf::from(p), *d)));
    if let Some(home) = home {
        out.push(place(home.to_path_buf(), HOME_DEPTH));
    }
    out.extend(TMP_PLACES.iter().map(|(p, d)| place(PathBuf::from(p), *d)));
    out
}

/// The well-known names for a user whose runtime directory is `runtime`.
pub fn known(runtime: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = KNOWN.iter().map(PathBuf::from).collect();
    out.extend(crate::doctor::RESOLVER_SOCKETS.iter().map(PathBuf::from));
    // The broker too: in a zone its directory is the holder's, which a
    // program may pass through but not list (seen in the VM, 2026-09-25).
    for name in [
        "bus",
        "systemd/private",
        "pulse/native",
        crate::broker::SOCKET,
    ] {
        out.push(runtime.join(name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vz-sockinv-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn is_root() -> bool {
        // SAFETY: geteuid(2) takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    fn paths(walk: &Walk) -> Vec<String> {
        walk.found
            .iter()
            .map(|f| String::from_utf8_lossy(&f.path).into_owned())
            .collect()
    }

    fn place(path: &Path, depth: usize) -> Place {
        Place {
            path: path.to_path_buf(),
            depth,
        }
    }

    /// A table with a FUSE mount at `point` (by spelling; a test cannot
    /// mount one).
    fn fuse_at(point: &Path) -> Slow {
        Slow::new(&format!(
            "40 25 0:999 / {} rw - fuse.test test rw\n",
            point.display()
        ))
    }

    #[test]
    fn the_walk_finds_what_a_program_may_connect_to_and_nothing_else() {
        let dir = scratch("walk");
        let d = dir.display().to_string();
        for sub in ["a/b/c", "linked", "slow", "closed"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        let _top = UnixListener::bind(dir.join("top.sock")).unwrap();
        let _deep = UnixListener::bind(dir.join("a/b/in-reach")).unwrap();
        let _too_deep = UnixListener::bind(dir.join("a/b/c/too-deep")).unwrap();
        let _behind_link = UnixListener::bind(dir.join("linked/behind")).unwrap();
        let _slow = UnixListener::bind(dir.join("slow/hidden")).unwrap();
        let _mode0 = UnixListener::bind(dir.join("no-write")).unwrap();
        fs::set_permissions(dir.join("no-write"), fs::Permissions::from_mode(0o444)).unwrap();
        let _closed = UnixListener::bind(dir.join("closed/inside")).unwrap();
        fs::set_permissions(dir.join("closed"), fs::Permissions::from_mode(0o000)).unwrap();
        // A link to a directory with a socket, and a FIFO: neither followed
        // nor opened — the walk would hang on the FIFO if it opened it.
        std::os::unix::fs::symlink(dir.join("linked"), dir.join("a/link")).unwrap();
        let fifo = CString::new(dir.join("fifo").as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path and a mode.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        fs::write(dir.join("plain"), "").unwrap();

        let slow = fuse_at(&dir.join("slow"));
        // `linked` is walked where it is itself, never through `a/link`.
        let walk = super::walk(&[place(&dir, 2)], &[], &slow, LIMITS);
        let found = paths(&walk);
        assert!(found.contains(&format!("{d}/top.sock")), "{found:?}");
        assert!(found.contains(&format!("{d}/a/b/in-reach")), "{found:?}");
        assert!(found.contains(&format!("{d}/linked/behind")), "{found:?}");
        assert!(!found.iter().any(|p| p.ends_with("too-deep")), "{found:?}");
        assert!(!found.iter().any(|p| p.contains("/a/link/")), "{found:?}");
        assert!(!found.iter().any(|p| p.ends_with("hidden")), "{found:?}");
        if !is_root() {
            assert!(!found.iter().any(|p| p.ends_with("no-write")), "{found:?}");
            assert!(!found.iter().any(|p| p.ends_with("inside")), "{found:?}");
        }
        assert!(walk.incomplete.is_empty(), "{:?}", walk.incomplete);
        // Not entered, and named.
        assert_eq!(walk.skipped, [format!("{d}/slow").into_bytes()]);

        // The same place twice (as /var/run and /run) is walked once, and a
        // well-known name already found is not named again.
        let twice = super::walk(
            &[place(&dir, 0), place(&dir, 0)],
            &[dir.join("top.sock")],
            &Slow::default(),
            LIMITS,
        );
        assert_eq!(
            paths(&twice)
                .iter()
                .filter(|p| p.ends_with("top.sock"))
                .count(),
            1
        );
        // A well-known name the walk did not reach is found by name — but
        // never through a link the user (a program) may have made.
        let named = super::walk(
            &[],
            &[
                dir.join("a/b/c/too-deep"),
                dir.join("a/link/behind"),
                dir.join("slow/hidden"),
            ],
            &slow,
            LIMITS,
        );
        assert_eq!(paths(&named), [format!("{d}/a/b/c/too-deep")]);

        fs::set_permissions(dir.join("closed"), fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_program_that_fills_a_place_spends_that_place_and_nothing_else() {
        let dir = scratch("budget");
        let d = dir.display().to_string();
        for sub in ["filled/full", "filled/aside", "other"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        for i in 0..20 {
            fs::write(dir.join(format!("filled/full/f{i}")), "").unwrap();
        }
        let _aside = UnixListener::bind(dir.join("filled/aside/s")).unwrap();
        let _other = UnixListener::bind(dir.join("other/s")).unwrap();
        // One full directory costs itself: its sibling is still read.
        let per_dir = Limits {
            place_entries: 1000,
            dir_entries: 5,
        };
        let walk = super::walk(
            &[place(&dir.join("filled"), 2)],
            &[],
            &Slow::default(),
            per_dir,
        );
        assert!(paths(&walk).contains(&format!("{d}/filled/aside/s")));
        assert_eq!(walk.incomplete.len(), 1, "{:?}", walk.incomplete);
        assert!(
            walk.incomplete[0].starts_with(&format!("{d}/filled/full: ")),
            "{:?}",
            walk.incomplete
        );
        // One full place costs itself: the next place is still walked, and
        // where it stopped is said.
        let per_place = Limits {
            place_entries: 10,
            dir_entries: 1000,
        };
        let walk = super::walk(
            &[place(&dir.join("filled"), 2), place(&dir.join("other"), 1)],
            &[],
            &Slow::default(),
            per_place,
        );
        assert!(
            paths(&walk).contains(&format!("{d}/other/s")),
            "{:?}",
            paths(&walk)
        );
        assert_eq!(walk.incomplete.len(), 1, "{:?}", walk.incomplete);
        assert!(
            walk.incomplete[0].contains("остановлено после 10 записей"),
            "{:?}",
            walk.incomplete
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_place_not_seen_is_said_and_an_absent_one_is_not() {
        let dir = scratch("unseen");
        fs::create_dir_all(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("mine")).unwrap();
        let walk = super::walk(
            &[
                place(&dir.join("mine"), 1),
                place(&dir.join("real"), 1),
                place(Path::new("/nonexistent-vz"), 1),
            ],
            &[],
            &fuse_at(&dir.join("real")),
            LIMITS,
        );
        assert_eq!(walk.incomplete.len(), 2, "{:?}", walk.incomplete);
        // A link of the user's is not followed, a filesystem that may hang is
        // not entered — and both are said.
        assert!(
            walk.incomplete[0].contains("ссылка"),
            "{:?}",
            walk.incomplete
        );
        assert!(walk.incomplete[1].contains("FUSE"), "{:?}", walk.incomplete);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_link_of_the_system_is_followed_and_the_real_path_is_said() {
        // /proc/self: root's link, what `/var/run` is to `/run`.
        let (_, real) = resolve_dir(b"/proc/self", &Slow::default()).unwrap();
        assert_eq!(real, format!("/proc/{}", std::process::id()).into_bytes());
        assert_eq!(
            resolve_dir(b"/proc/../proc", &Slow::default()).err(),
            Some(Unseen::Absent)
        );
        assert_eq!(
            resolve_dir(b"relative", &Slow::default()).err(),
            Some(Unseen::Absent)
        );
        // Below a slow mount by spelling: stopped before anything is asked.
        let slow = Slow::new("1 0 0:77 / /proc rw - fuse.x x rw\n");
        assert_eq!(
            resolve_dir(b"/proc/self", &slow).err(),
            Some(Unseen::Slow(b"/proc".to_vec()))
        );
    }

    #[test]
    fn mountinfo_gives_devices_points_and_types() {
        let info = "36 25 0:32 / /run/user/1000 rw,nosuid - tmpfs tmpfs rw\n\
                    37 25 0:40 / /run/user/1000/doc rw shared:9 - fuse.portal portal rw\n\
                    38 25 0:41 / /mnt/with\\040blank rw - nfs4 srv:/x rw\n\
                    39 25 259:2 /@home /home rw - btrfs /dev/x rw\n";
        let all = mounts(info);
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].dev, (0, 32));
        assert_eq!(all[2].point, b"/mnt/with blank");
        assert_eq!(all[1].fstype, "fuse.portal");
        let slow = Slow::new(info);
        assert!(slow.below(b"/run/user/1000/doc"));
        assert!(slow.below(b"/run/user/1000/doc/x/y"));
        assert!(!slow.below(b"/run/user/1000/docs"));
        assert!(slow.below(b"/mnt/with blank"));
        assert!(!slow.below(b"/home"));
        assert!(slow.dev((0, 40)) && slow.dev((0, 41)) && !slow.dev((0, 32)));
        assert!(Slow::new("1 0 0:9 / / rw - nfs4 s:/ rw\n").below(b"/anything"));
        assert!(slow_fs("autofs") && slow_fs("fuse.sshfs") && slow_fs("9p"));
        assert!(slow_fs("virtiofs") && slow_magic(0x6573_5546));
        assert!(!slow_fs("tmpfs") && !slow_fs("btrfs") && !slow_fs("overlay"));
        assert_eq!(parse_dev("259:2"), Some((259, 2)));
        assert_eq!(parse_dev("x"), None);
    }

    #[test]
    fn only_a_tmpfs_the_host_does_not_have_is_the_zones_own() {
        let runtime = Path::new("/run/user/1000");
        let zone = "1 0 0:30 / /tmp rw - tmpfs tmpfs rw\n\
                    2 0 0:50 / /tmp rw - tmpfs tmpfs rw\n\
                    3 0 0:51 / /run/user/1000 rw - tmpfs tmpfs rw\n\
                    4 0 0:52 / /srv/other rw - tmpfs tmpfs rw\n\
                    5 0 0:31 / /run/user/1000 rw - tmpfs tmpfs rw\n\
                    6 0 0:53 / /tmp/.X11-unix rw - tmpfs tmpfs rw\n";
        let host: HashSet<Dev> = [(0, 30), (0, 31)].into();
        let own = own_devs(zone, runtime, Some(&host));
        assert_eq!(own, [(0, 50), (0, 51), (0, 53)].into());
        // Without the host's devices nothing is the zone's own.
        assert!(own_devs(zone, runtime, None).is_empty());
    }

    fn ctx() -> Context {
        Context {
            runtime: PathBuf::from("/run/user/1000"),
            zone: Some("nl".to_owned()),
            ..Context::default()
        }
    }

    fn level(path: &str, c: &Context) -> Level {
        classify(path.as_bytes(), (0, 31), 7, c).level()
    }

    #[test]
    fn the_zones_own_sockets_are_not_named() {
        let host = (0, 31);
        let mut c = ctx();
        c.mountinfo = "30 29 8:2 /h/.local/state/vpn-zones/nl/session-bus-filter /run/user/1000/bus rw - ext4 /dev/x rw\n\
                       31 29 8:2 /h/.local/state/vpn-zones/nl/pulse-filter /run/user/1000/pulse/native rw - ext4 /dev/x rw\n\
                       32 29 8:2 /h/.local/state/vpn-zones/nl/system-bus /run/dbus/system_bus_socket rw - ext4 /dev/x rw\n\
                       33 29 8:2 /h/.local/state/vpn-zones/nl/pipewire-context /run/user/1000/pipewire-0 rw - ext4 /dev/x rw\n"
            .to_owned();
        for path in [
            "/run/user/1000/bus",
            "/run/user/1000/pulse/native",
            "/run/user/1000/pipewire-0",
            "/run/user/1000/vpn-zones/broker",
            "/run/user/1000/vpn-zones/wayland/nl/wayland-0-17",
            "/run/user/1000/vpn-zones/sandbox/x/bus",
            "/run/dbus/system_bus_socket",
        ] {
            assert!(
                matches!(classify(path.as_bytes(), host, 7, &c), Verdict::Own(_)),
                "{path}"
            );
        }
        for path in [
            "/run/systemd/journal/socket",
            "/run/systemd/journal/stdout",
            "/run/systemd/notify",
            "/run/systemd/userdb/io.systemd.DynamicUser",
        ] {
            assert_eq!(level(path, &c), Level::Ok, "{path}");
        }
        // Made in the zone: its own, even under a name the host's would have.
        c.own_devs = [(0, 50)].into();
        assert!(matches!(
            classify(b"/run/user/1000/wayland-1", (0, 50), 7, &c),
            Verdict::Own(_)
        ));
        assert!(matches!(
            classify(b"/tmp/tmux-1000/default", (0, 50), 7, &c),
            Verdict::Own(_)
        ));
    }

    /// `pipewire-0`: the zone's restricted socket is its own; the host's raw
    /// one fails in a hermetic zone, is named in an audio manager and in an
    /// ordinary zone, and fails under any other name when promised closed.
    #[test]
    fn the_raw_pipewire_is_named_and_in_a_hermetic_zone_a_failure() {
        let mut c = ctx();
        let pw = "/run/user/1000/pipewire-0";
        assert_eq!(level(pw, &c), Level::Warn);
        c.hermetic = true;
        assert_eq!(level(pw, &c), Level::Fail);
        c.audio_manager = true;
        assert_eq!(level(pw, &c), Level::Warn);
        c.audio_manager = false;
        c.mountinfo = "33 29 8:2 /h/.local/state/vpn-zones/nl/pipewire-context /run/user/1000/pipewire-0 rw - ext4 /dev/x rw\n"
            .to_owned();
        assert_eq!(level(pw, &c), Level::Ok);
        // A socket named like ours elsewhere is not ours over pipewire-0.
        c.mountinfo =
            "33 29 8:2 /h/pipewire-context-evil /run/user/1000/pipewire-0 rw - ext4 /dev/x rw\n"
                .to_owned();
        assert_eq!(level(pw, &c), Level::Fail);
        c.closed = parse_closed("pipewire:0:31:7");
        assert!(matches!(
            classify(b"/home/alice/pw", (0, 31), 7, &c),
            Verdict::Closed(w) if w.contains("PipeWire")
        ));
    }

    #[test]
    fn what_the_project_promises_closed_fails_and_the_rest_warns() {
        let mut c = ctx();
        for path in [
            "/run/user/1000/wayland-1",
            "/run/user/1000/niri.wayland-1.42.sock",
            "/run/user/1000/pipewire-0-manager",
            "/run/user/1000/pulse/native",
            "/run/vpn-zones/sysrun.sock",
            "/nix/var/nix/daemon-socket/socket",
            "/run/systemd/resolve/io.systemd.Resolve",
            "/tmp/.X11-unix/X0",
            // Another zone's restricted Wayland: only this zone's is bound.
            "/run/user/1000/vpn-zones/wayland/other/wayland-0-3",
        ] {
            assert_eq!(level(path, &c), Level::Fail, "{path}");
        }
        // The session bus and systemd --user: open by design in an ordinary
        // zone, promised closed in a hermetic one.
        assert_eq!(level("/run/user/1000/bus", &c), Level::Warn);
        assert_eq!(level("/run/user/1000/systemd/private", &c), Level::Warn);
        c.hermetic = true;
        assert_eq!(level("/run/user/1000/bus", &c), Level::Fail);
        assert_eq!(level("/run/user/1000/systemd/private", &c), Level::Fail);
        // The proxy bound without the filter hands links to the host (§2):
        // not the zone's own, and in a hermetic zone a failure.
        c.mountinfo = "30 29 8:2 /h/.local/state/vpn-zones/nl/session-bus /run/user/1000/bus rw - ext4 /dev/x rw\n"
            .to_owned();
        assert_eq!(level("/run/user/1000/bus", &c), Level::Fail);
        c.hermetic = false;
        assert_eq!(level("/run/user/1000/bus", &c), Level::Warn);
        c.hermetic = true;
        // The Nix daemon, once the zone is let: named, not failed.
        c.nix_daemon = true;
        assert_eq!(level("/nix/var/nix/daemon-socket/socket", &c), Level::Warn);
        for path in [
            "/home/alice/.ssh/master-alice@host:22",
            "/run/tailscale/tailscaled.sock",
            "/run/docker.sock",
            "/run/user/1000/gnupg/S.gpg-agent",
            "/run/user/1000/at-spi/bus_0",
            "/run/systemd/io.systemd.Hostname",
            "/tmp/tmux-1000/default",
            "/var/lib/whatever/x.sock",
            "/run/dbus/system_bus_socket",
        ] {
            assert_eq!(level(path, &c), Level::Warn, "{path}");
        }
        // Which zone's Wayland, the probe does not know: named, not taken for
        // the zone's own.
        c.zone = None;
        assert_eq!(
            level("/run/user/1000/vpn-zones/wayland/nl/wayland-0-17", &c),
            Level::Warn
        );
    }

    #[test]
    fn a_closed_socket_under_another_name_is_still_closed() {
        let mut c = ctx();
        c.closed = parse_closed("nix-daemon:0:31:7,x11:0:31:8,junk,future:1:2:3,bus:1:2");
        assert_eq!(c.closed.len(), 2);
        // A hard link in the home, the same device and inode.
        assert_eq!(level("/home/alice/.cache/s", &c), Level::Fail);
        assert!(matches!(
            classify(b"/home/alice/.cache/s", (0, 31), 7, &c),
            Verdict::Closed(w) if w.contains("Nix")
        ));
        // Another inode: what its path says.
        assert_eq!(
            classify(b"/home/alice/.cache/s", (0, 31), 9, &c).level(),
            Level::Warn
        );
        // A closed path keeps its own words.
        assert!(matches!(
            classify(b"/tmp/.X11-unix/X0", (0, 31), 8, &c),
            Verdict::Closed(w) if w.contains("(§7)")
        ));
    }

    #[test]
    fn a_name_a_program_chose_cannot_forge_a_line() {
        assert_eq!(shown(b"/tmp/a b"), "/tmp/a b");
        let forged = shown(b"/tmp/x\tfail\tlinks\nlinks\tok\t\\\xff");
        assert!(!forged.contains('\t') && !forged.contains('\n'), "{forged}");
        assert!(
            forged.contains("\\u{9}") && forged.contains("\\xff"),
            "{forged}"
        );
        // Nor reach a terminal as an escape sequence, nor reorder itself.
        let terminal = shown("/run/user/1000/wayland-\u{1b}[3A\u{7}\u{9b}\u{202e}".as_bytes());
        assert!(!terminal.chars().any(unseen_char), "{terminal}");
        // Nor fill a screen.
        let long = shown(&[b'\x01'; 1000]);
        assert!(long.chars().count() < SHOWN_MAX * 8, "{}", long.len());
        assert!(long.ends_with('…'));
    }

    #[test]
    fn the_summary_and_the_lines_say_what_is_in_reach() {
        let mut c = ctx();
        c.mountinfo = "33 29 8:2 /h/.local/state/vpn-zones/nl/pipewire-context /run/user/1000/pipewire-0 rw - ext4 /dev/x rw\n"
            .to_owned();
        let found = |path: &[u8], dev: Dev| Found {
            path: path.to_vec(),
            dev,
            ino: 1,
        };
        let walk = Walk {
            found: vec![
                found(b"/run/user/1000/pipewire-0", (0, 31)),
                found(b"/run/systemd/journal/socket", (0, 25)),
                found(b"/tmp/evil.sock", (0, 30)),
                found(b"/run/user/1000/wayland-1", (0, 31)),
            ],
            entries: 10,
            ..Walk::default()
        };
        let checks = checks(&walk, &c, true);
        assert_eq!(checks[0].id, "sockets");
        assert_eq!(checks[0].level, Level::Fail);
        assert!(
            checks[0].detail.contains("ограниченный PipeWire"),
            "{}",
            checks[0].detail
        );
        assert!(checks[0].detail.contains("журнал"), "{}", checks[0].detail);
        assert_eq!(checks[1].id, "tmp-sockets");
        assert_eq!(checks[1].level, Level::Warn);
        assert!(checks[1].detail.contains("/tmp/evil.sock"));
        let lines: Vec<&Check> = checks.iter().filter(|c| c.id == "socket").collect();
        assert_eq!(lines.len(), 2);
        // Failures first.
        assert_eq!(lines[0].level, Level::Fail);
        assert!(
            lines[1].detail.starts_with("/tmp/evil.sock — "),
            "{}",
            lines[1].detail
        );

        // Nothing foreign, everything seen: ok. Something unseen: warn. A
        // FUSE mount not entered: named, and still ok.
        let clean = Walk {
            found: walk.found[..2].to_vec(),
            entries: 2,
            skipped: vec![b"/run/user/1000/doc".to_vec()],
            ..Walk::default()
        };
        let summary = &super::checks(&clean, &c, true)[0];
        assert_eq!(summary.level, Level::Ok);
        assert!(
            summary.detail.contains("/run/user/1000/doc"),
            "{}",
            summary.detail
        );
        let unseen = Walk {
            incomplete: vec!["/var/lib не просмотрен".to_owned()],
            ..clean
        };
        assert_eq!(super::checks(&unseen, &c, true)[0].level, Level::Warn);
    }

    #[test]
    fn a_flood_of_sockets_is_counted_not_listed() {
        let c = ctx();
        let mut found: Vec<Found> = (0..NAMED_MAX + 50)
            .map(|i| Found {
                path: format!("/home/alice/s{i:05}").into_bytes(),
                dev: (0, 40),
                ino: i as u64,
            })
            .collect();
        // The one failure, last by path: still named, still the level.
        found.push(Found {
            path: b"/tmp/.X11-unix/X0".to_vec(),
            dev: (0, 41),
            ino: 1,
        });
        let walk = Walk {
            found,
            ..Walk::default()
        };
        let checks = checks(&walk, &c, true);
        let lines: Vec<&Check> = checks.iter().filter(|c| c.id == "socket").collect();
        assert_eq!(lines.len(), NAMED_MAX);
        assert_eq!(lines[0].level, Level::Fail);
        assert_eq!(checks[0].level, Level::Fail);
        assert!(
            checks[0]
                .detail
                .contains(&format!("{}, названы {NAMED_MAX}", NAMED_MAX + 51)),
            "{}",
            checks[0].detail
        );
    }

    #[test]
    fn places_put_the_small_and_precious_first_each_on_its_own() {
        let all = places(Path::new("/run/user/1000"), Some(Path::new("/home/alice")));
        let names: Vec<String> = all.iter().map(|p| p.path.display().to_string()).collect();
        assert_eq!(
            names,
            [
                "/run/user/1000",
                "/home/alice/.ssh",
                "/run",
                "/var/run",
                "/nix/var",
                "/var/lib",
                "/home/alice",
                "/tmp",
                "/var/tmp",
                "/dev/shm"
            ]
        );
        assert_eq!(all[1].depth, 0);
        assert_eq!(
            places(Path::new("/run/user/1000"), Some(Path::new("relative"))).len(),
            1 + PLACES.len() + TMP_PLACES.len()
        );
        assert!(known(Path::new("/run/user/1000")).contains(&PathBuf::from("/run/user/1000/bus")));
    }
}
