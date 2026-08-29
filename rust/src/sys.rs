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
use std::os::fd::{FromRawFd, OwnedFd};
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
