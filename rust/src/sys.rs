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
use std::path::Path;

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
